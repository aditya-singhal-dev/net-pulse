"""Store complete diagnostic cycles and indexed per-target measurements."""

import json
import sqlite3
from contextlib import closing
from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path

from core.bandwidth_monitor import Bandwidth
from core.diagnostic_cycle import DiagnosticCycle
from core.diagnosis_engine import Diagnosis
from core.health_score import HealthScore

SCHEMA = """
CREATE TABLE IF NOT EXISTS cycles (
    id INTEGER PRIMARY KEY,
    timestamp TEXT NOT NULL,
    interface TEXT,
    gateway TEXT,
    addresses TEXT NOT NULL,
    interface_up INTEGER,
    upload_mbps REAL,
    download_mbps REAL,
    total_sent INTEGER,
    total_received INTEGER,
    health_score INTEGER CHECK (health_score BETWEEN 0 AND 100),
    diagnostic_status TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS cycles_timestamp_idx ON cycles(timestamp);
CREATE TABLE IF NOT EXISTS probes (
    id INTEGER PRIMARY KEY,
    cycle_id INTEGER NOT NULL REFERENCES cycles(id) ON DELETE CASCADE,
    protocol TEXT NOT NULL CHECK (protocol IN ('icmp', 'dns', 'tcp')),
    target TEXT NOT NULL,
    port INTEGER,
    status TEXT NOT NULL,
    latency_ms REAL,
    packet_loss_percent REAL,
    jitter_ms REAL,
    dns_response_ms REAL,
    tcp_connect_ms REAL,
    details TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS probes_cycle_idx ON probes(cycle_id);
CREATE TABLE IF NOT EXISTS assessments (
    cycle_id INTEGER PRIMARY KEY REFERENCES cycles(id) ON DELETE CASCADE,
    health TEXT NOT NULL,
    diagnosis TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS extra_metrics (
    cycle_id INTEGER PRIMARY KEY REFERENCES cycles(id) ON DELETE CASCADE,
    link_capacity_mbps REAL,
    http_response_ms REAL,
    http_status INTEGER,
    tcp_retransmission_percent REAL,
    wifi_rssi_dbm INTEGER,
    dns_failure_percent REAL
);
CREATE TABLE IF NOT EXISTS dashboard_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    settings TEXT NOT NULL
);
"""


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(SCHEMA)

    def save(
        self, cycle: DiagnosticCycle, *, health_score: int | None = None,
        diagnostic_status: str | None = None,
        assessment: tuple[HealthScore, Diagnosis] | None = None,
    ) -> int:
        network, bandwidth = cycle.network, cycle.bandwidth
        if assessment is not None:
            health, diagnosis = assessment
            health_score, diagnostic_status = health.score, diagnosis.status
        with closing(self._connect()) as connection, connection:
            cursor = connection.execute(
                """INSERT INTO cycles (
                    timestamp, interface, gateway, addresses, interface_up, upload_mbps,
                    download_mbps, total_sent, total_received, health_score, diagnostic_status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (cycle.timestamp, network.interface, network.gateway, json.dumps(network.addresses),
                 network.interface_up, bandwidth.upload_mbps, bandwidth.download_mbps,
                 bandwidth.total_sent, bandwidth.total_received, health_score,
                 diagnostic_status if diagnostic_status is not None else cycle.status),
            )
            cycle_id = cursor.lastrowid
            records = [
                (cycle_id, "icmp", item.target, None, item.status, item.avg_ms, item.loss_percent,
                 item.jitter_ms, None, None, json.dumps(asdict(item)))
                for item in cycle.ping
            ]
            records.extend(
                (cycle_id, "dns", item.domain, None, item.status, None, None, None, item.elapsed_ms,
                 None, json.dumps(asdict(item)))
                for item in cycle.dns
            )
            records.extend(
                (cycle_id, "tcp", item.host, item.port, item.status, None, None, None, None,
                 item.elapsed_ms, json.dumps(asdict(item)))
                for item in cycle.tcp
            )
            connection.executemany(
                """INSERT INTO probes (
                    cycle_id, protocol, target, port, status, latency_ms, packet_loss_percent,
                    jitter_ms, dns_response_ms, tcp_connect_ms, details
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                records,
            )
            assert cycle_id is not None
            if cycle.extra is not None:
                connection.execute(
                    """INSERT INTO extra_metrics (
                       cycle_id, link_capacity_mbps, http_response_ms, http_status,
                       tcp_retransmission_percent, wifi_rssi_dbm, dns_failure_percent
                       ) VALUES (:cycle_id, :link_capacity_mbps, :http_response_ms, :http_status,
                                 :tcp_retransmission_percent, :wifi_rssi_dbm, :dns_failure_percent)""",
                    {"cycle_id": cycle_id, **asdict(cycle.extra)},
                )
            if assessment is not None:
                connection.execute(
                    "INSERT INTO assessments (cycle_id, health, diagnosis) VALUES (?, ?, ?)",
                    (cycle_id, json.dumps(asdict(health)), json.dumps(asdict(diagnosis))),
                )
            return cycle_id

    def latest(self) -> sqlite3.Row | None:
        with closing(self._connect()) as connection:
            return connection.execute(
                """SELECT cycles.*, assessments.health, assessments.diagnosis, extra_metrics.*
                   FROM cycles LEFT JOIN assessments ON assessments.cycle_id = cycles.id
                   LEFT JOIN extra_metrics ON extra_metrics.cycle_id = cycles.id
                   ORDER BY cycles.timestamp DESC, cycles.id DESC LIMIT 1"""
            ).fetchone()

    def get_dashboard_settings(self) -> str | None:
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT settings FROM dashboard_settings WHERE id = 1").fetchone()
        return row["settings"] if row else None

    def set_dashboard_settings(self, settings: str) -> None:
        with closing(self._connect()) as connection, connection:
            connection.execute(
                """INSERT INTO dashboard_settings (id, settings) VALUES (1, ?)
                   ON CONFLICT(id) DO UPDATE SET settings = excluded.settings""", (settings,),
            )

    def report_rows(
        self, start: str, end: str, limit: int,
    ) -> tuple[list[sqlite3.Row], list[sqlite3.Row], bool]:
        """Read a consistent snapshot of the latest matching cycles and their probes."""
        if not 1 <= limit <= 500:
            raise ValueError("Report limit must be between 1 and 500")
        with closing(self._connect()) as connection, connection:
            connection.execute("BEGIN")
            cycles = connection.execute(
                """SELECT cycles.*, assessments.health, assessments.diagnosis, extra_metrics.*
                   FROM cycles LEFT JOIN assessments ON assessments.cycle_id = cycles.id
                   LEFT JOIN extra_metrics ON extra_metrics.cycle_id = cycles.id
                   WHERE timestamp >= ? AND timestamp < ?
                   ORDER BY timestamp DESC, cycles.id DESC LIMIT ?""",
                (start, end, limit + 1),
            ).fetchall()
            if not cycles:
                return [], [], False
            truncated = len(cycles) > limit
            cycles = cycles[:limit]
            placeholders = ",".join("?" for _ in cycles)
            probes = connection.execute(
                f"SELECT * FROM probes WHERE cycle_id IN ({placeholders}) ORDER BY cycle_id, id",
                [cycle["id"] for cycle in cycles],
            ).fetchall()
            return cycles, probes, truncated

    def previous_bandwidth(
        self, cycle: DiagnosticCycle, max_age_seconds: float,
    ) -> Bandwidth | None:
        if cycle.network.interface is None:
            return None
        timestamp = datetime.fromisoformat(cycle.timestamp)
        earliest = datetime.min.replace(tzinfo=timestamp.tzinfo)
        start = earliest
        if max_age_seconds < (timestamp - earliest).total_seconds():
            start = timestamp - timedelta(seconds=max_age_seconds)
        with closing(self._connect()) as connection:
            row = connection.execute(
                """SELECT total_sent, total_received, upload_mbps, download_mbps FROM cycles
                   WHERE timestamp >= ? AND timestamp < ? AND interface = ?
                     AND (upload_mbps IS NOT NULL OR download_mbps IS NOT NULL)
                   ORDER BY timestamp DESC, id DESC LIMIT 1""",
                (start.isoformat(), cycle.timestamp, cycle.network.interface),
            ).fetchone()
        return Bandwidth(*row) if row is not None else None

    def history(self, start: str, end: str, limit: int = 1000) -> list[sqlite3.Row]:
        """Return newest cycles in a half-open range of UTC ISO timestamps."""
        if not 1 <= limit <= 10_000:
            raise ValueError("History limit must be between 1 and 10,000")
        with closing(self._connect()) as connection:
            return connection.execute(
                """SELECT * FROM cycles WHERE timestamp >= ? AND timestamp < ?
                   ORDER BY timestamp DESC, id DESC LIMIT ?""",
                (start, end, limit),
            ).fetchall()

    def probes(self, cycle_id: int) -> list[sqlite3.Row]:
        with closing(self._connect()) as connection:
            return connection.execute(
                "SELECT * FROM probes WHERE cycle_id = ? ORDER BY id", (cycle_id,)
            ).fetchall()

    def time_series(self, start: str, end: str, limit: int = 2000) -> list[sqlite3.Row]:
        """Return the newest matching samples in chronological order for charting."""
        if not 1 <= limit <= 10_000:
            raise ValueError("Time-series limit must be between 1 and 10,000")
        with closing(self._connect()) as connection:
            return connection.execute(
                """WITH recent AS (
                       SELECT id, timestamp, interface, upload_mbps, download_mbps, health_score
                       FROM cycles WHERE timestamp >= ? AND timestamp < ?
                       ORDER BY timestamp DESC, id DESC LIMIT ?
                   )
                   SELECT recent.*, AVG(probes.latency_ms) AS latency_ms,
                          AVG(probes.packet_loss_percent) AS packet_loss_percent,
                          AVG(probes.dns_response_ms) AS dns_response_ms
                   FROM recent LEFT JOIN probes ON probes.cycle_id = recent.id
                   GROUP BY recent.id ORDER BY recent.timestamp, recent.id""",
                (start, end, limit),
            ).fetchall()
