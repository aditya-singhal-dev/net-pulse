"""Run at most one asynchronous diagnostic job for a dashboard database."""

import logging
import sqlite3
from dataclasses import dataclass
from threading import Event, Lock, Thread
from time import monotonic

from config.settings import Settings
from core.diagnostic_cycle import collect
from database.db import Database
from database.recording import record_cycle

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class MonitorStatus:
    state: str
    interval: int | None
    last_saved_id: int | None
    error: str | None


class MonitoringService:
    def __init__(self, database: Database) -> None:
        self.database = database
        self._lock = Lock()
        self._stop = Event()
        self._thread: Thread | None = None
        self._interval: int | None = None
        self._last_saved_id: int | None = None
        self._error: str | None = None

    def _active(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def snapshot(self) -> MonitorStatus:
        with self._lock:
            active = self._active()
            if not active:
                state = "idle"
            elif self._stop.is_set():
                state = "stopping"
            else:
                state = "monitoring" if self._interval is not None else "measuring"
            return MonitorStatus(
                state, self._interval if active else None, self._last_saved_id, self._error,
            )

    def start(self, settings: Settings) -> bool:
        """Start recurring measurements, returning False if a worker is already alive."""
        return self._launch(settings, settings.interval)

    def run_once(self, settings: Settings = Settings()) -> bool:
        """Use the same worker slot for a single manual diagnostic."""
        return self._launch(settings, None)

    def _launch(self, settings: Settings, interval: int | None) -> bool:
        with self._lock:
            if self._active():
                return False
            self._stop.clear()
            self._interval = interval
            self._error = None
            self._thread = Thread(
                target=self._run, args=(settings, interval), name="netpulse-monitor", daemon=True,
            )
            self._thread.start()
            return True

    def stop(self) -> bool:
        """Signal a recurring worker to stop without waiting on network operations."""
        with self._lock:
            if not self._active() or self._interval is None or self._stop.is_set():
                return False
            self._stop.set()
            return True

    def wait_until_stopped(self, timeout: float) -> bool:
        """Wait for the current worker to exit. Intended for shutdown and tests."""
        with self._lock:
            thread = self._thread
        if thread is None:
            return True
        thread.join(timeout)
        return not thread.is_alive()

    def _run(self, settings: Settings, interval: int | None) -> None:
        while True:
            with self._lock:
                if self._stop.is_set():
                    return
            started = monotonic()
            try:
                cycle_id, _, _ = record_cycle(
                    self.database, collect(settings), settings.score_thresholds, settings.diagnosis_thresholds,
                )
            except (OSError, sqlite3.Error) as exc:
                with self._lock:
                    self._error = str(exc) or type(exc).__name__
            except Exception as exc:
                LOGGER.exception("Diagnostic worker stopped unexpectedly")
                with self._lock:
                    self._error = str(exc) or type(exc).__name__
                return
            else:
                with self._lock:
                    self._last_saved_id = cycle_id
                    self._error = None
            if interval is None or self._stop.wait(max(0, interval - (monotonic() - started))):
                return
