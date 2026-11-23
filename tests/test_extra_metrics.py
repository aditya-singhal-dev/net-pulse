from dataclasses import replace
from datetime import date

import pytest

from core import extra_metrics
from core.bandwidth_monitor import Bandwidth
from core.diagnostic_cycle import DiagnosticCycle
from core.dns_analyzer import DNSResult
from core.health_score import score_health
from core.network_info import NetworkInfo
from core.ping_monitor import PingResult
from core.tcp_checker import TCPResult
from database.db import Database
from database.recording import record_cycle
from utils.report_generator import load_report


def test_http_and_retransmissions(monkeypatch):
    monkeypatch.setattr(extra_metrics, "_command", lambda *_: "0.10 0.25 200")
    assert extra_metrics.http_response(2) == (150, 200)
    monkeypatch.setattr(extra_metrics, "_command", lambda *_: "0 0 000")
    assert extra_metrics.http_response(2) == (None, None)
    monkeypatch.setattr(extra_metrics, "_command", lambda *_:
                        "tcp:\n\t100 packets sent\n\t\t3 data packets (300 bytes) retransmitted\n")
    assert extra_metrics.tcp_counters() == (100, 3)
    assert extra_metrics.retransmission_percent((100, 3), (200, 7)) == 4
    assert extra_metrics.retransmission_percent((100, 3), (100, 3)) is None
    assert extra_metrics.retransmission_percent((100, 3), (50, 1)) is None


def test_link_signal_requires_matching_interface(monkeypatch):
    monkeypatch.setattr(extra_metrics, "_command", lambda *_: '["en0", 400, -65]')
    monkeypatch.setattr(extra_metrics.psutil, "net_if_stats", lambda: {})
    assert extra_metrics.link_metrics("en0") == (400, -65)
    assert extra_metrics.link_metrics("utun0") == (None, None)


def test_extended_score_and_persistence(tmp_path):
    cycle = DiagnosticCycle(
        "2026-11-23T00:00:00+00:00", NetworkInfo("en0", None, (), True), Bandwidth(),
        (PingResult("192.0.2.1", "ok", avg_ms=30, loss_percent=0, jitter_ms=5),),
        (DNSResult("example.com", "ok", 30), DNSResult("example.net", "timeout")),
        (TCPResult("example.com", 443, "ok", 10),),
        extra_metrics.ExtraMetrics(100, 150, 200, 0, -60, 50),
    )
    health = score_health(cycle)
    assert health.measured_weight == 100
    assert health.components["dns"] == 100
    assert health.components["dns_failure"] == 50
    assert health.score == 98
    weak = replace(cycle, extra=extra_metrics.ExtraMetrics(10, 1000, 200, 5, -85, 50))
    assert score_health(weak).score == 76
    assert score_health(replace(cycle, extra=extra_metrics.ExtraMetrics(dns_failure_percent=50))).score == 97

    database = Database(tmp_path / "extended.sqlite3")
    database.initialize()
    record_cycle(database, cycle)
    assert database.latest()["wifi_rssi_dbm"] == -60
    assert database.latest()["http_response_ms"] == pytest.approx(150)
    report = load_report(database, date(2026, 11, 23), date(2026, 11, 23))
    assert report.cycles.iloc[0]["dns_failure_percent"] == 50
