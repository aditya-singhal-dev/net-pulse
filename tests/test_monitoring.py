"""Worker lifecycle, concurrent requests, and historical measurements."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Barrier, Event
from time import monotonic, sleep

from streamlit.testing.v1 import AppTest

from config.settings import Settings
from core.bandwidth_monitor import Bandwidth
from core.diagnostic_cycle import DiagnosticCycle
from core.dns_analyzer import DNSResult
from core.monitoring_service import MonitoringService
from core.network_info import NetworkInfo
from core.ping_monitor import PingResult
from core.tcp_checker import TCPResult
from database.db import Database

ENTRY_POINT = Path(__file__).resolve().parents[1] / "dashboard.py"


def _sample(timestamp: datetime) -> DiagnosticCycle:
    return DiagnosticCycle(
        timestamp.isoformat(), NetworkInfo("en0", None, (), True),
        Bandwidth(upload_mbps=0, download_mbps=2.5),
        (PingResult("192.0.2.1", "ok", avg_ms=20, loss_percent=0),
         PingResult("192.0.2.2", "partial_loss", avg_ms=30, loss_percent=50),
         PingResult("192.0.2.3", "error")),
        (DNSResult("example.com", "ok", 15), DNSResult("example.net", "timeout")),
        (TCPResult("example.com", 443, "ok", 10),),
    )


def _worker(tmp_path) -> MonitoringService:
    database = Database(tmp_path / "monitor.sqlite3")
    database.initialize()
    return MonitoringService(database)


def test_concurrent_starts_and_stop_during_a_measurement(tmp_path, monkeypatch):
    monitor = _worker(tmp_path)
    entered, finish = Event(), Event()
    sample = _sample(datetime.now(timezone.utc))
    calls = []

    def collect(settings):
        calls.append(settings)
        entered.set()
        assert finish.wait(10)
        return sample

    monkeypatch.setattr("core.monitoring_service.collect", collect)
    settings = Settings(interval=5)
    gate = Barrier(4, timeout=5)

    def start():
        gate.wait()
        return monitor.start(settings)

    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            assert sum(pool.map(lambda _: start(), range(4))) == 1
        assert entered.wait(5)
        assert monitor.snapshot().state == "monitoring"
        assert monitor.stop()
        assert monitor.snapshot().state == "stopping"
        assert not monitor.stop()
        assert not monitor.start(settings)
        assert not monitor.run_once()
        assert monitor.database.latest() is None
    finally:
        finish.set()
        monitor.stop()
        assert monitor.wait_until_stopped(5)

    assert calls == [settings]
    assert monitor.snapshot().state == "idle"
    cycle = Database(monitor.database.path).latest()
    assert cycle["id"] == monitor.snapshot().last_saved_id
    assert cycle["health_score"] is not None
    assert len(monitor.database.probes(cycle["id"])) == 6


def test_recurs_and_stop_interrupts_interval_wait(tmp_path, monkeypatch):
    monitor = _worker(tmp_path)
    second = Event()
    samples = []

    def collect(_settings):
        sample = _sample(datetime.now(timezone.utc))
        samples.append(sample)
        if len(samples) == 2:
            second.set()
        return sample

    monkeypatch.setattr("core.monitoring_service.collect", collect)
    try:
        assert monitor.start(Settings(interval=5))
        assert second.wait(9)
        deadline = monotonic() + 3
        while monitor.snapshot().last_saved_id != 2 and monotonic() < deadline:
            sleep(0.01)
        assert monitor.snapshot().last_saved_id == 2
        assert monitor.stop()
        assert monitor.wait_until_stopped(2)
    finally:
        monitor.stop()
        monitor.wait_until_stopped(5)
    rows = monitor.database.time_series(samples[0].timestamp, "9999")
    assert len(rows) == 2
    assert [row["timestamp"] for row in rows] == [sample.timestamp for sample in samples]
    assert rows[0]["latency_ms"] == 25
    assert rows[0]["packet_loss_percent"] == 25
    assert rows[0]["dns_response_ms"] == 15
    assert rows[0]["upload_mbps"] == 0
    assert rows[0]["download_mbps"] == 2.5
    assert monitor.database.time_series(rows[1]["timestamp"], "9999", limit=1)[0]["id"] == rows[1]["id"]


def test_live_page_shares_start_stop_and_renders_history(tmp_path, monkeypatch):
    path = tmp_path / "shared.sqlite3"
    monkeypatch.setenv("NETPULSE_DB", str(path))
    started, finish = Event(), Event()
    now = datetime.now(timezone.utc)

    def collect(_settings):
        started.set()
        if not finish.wait(15):
            raise TimeoutError("Test did not release the worker")
        return _sample(now)

    monkeypatch.setattr("core.monitoring_service.collect", collect)
    try:
        first = AppTest.from_file(str(ENTRY_POINT), default_timeout=30).run()
        first.radio[0].set_value("Live Monitoring").run()
        assert first.info[0].value == "No measurements in this time range."
        first.button[0].click().run()
        assert started.wait(5)
        assert first.button[0].disabled
        assert not first.button[1].disabled

        second = AppTest.from_file(str(ENTRY_POINT), default_timeout=30).run()
        assert second.button[0].disabled  # Manual diagnostics share the slot.
        second.radio[0].set_value("Live Monitoring").run()
        assert second.button[0].disabled
        second.button[1].click().run()
        assert "Stopping" in second.info[0].value
        finish.set()
        deadline = monotonic() + 5
        while Database(path).latest() is None and monotonic() < deadline:
            sleep(0.01)
        first.run()
        assert not first.exception
        assert len(first.get("plotly_chart")) == 5
        assert first.button[1].disabled
        assert not first.button[0].disabled
        assert Database(path).time_series((now - timedelta(minutes=1)).isoformat(), "9999")
    finally:
        finish.set()
