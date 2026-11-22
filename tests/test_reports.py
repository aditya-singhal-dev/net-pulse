from csv import DictReader
from dataclasses import replace
from datetime import date
from io import StringIO

import pytest

from core.bandwidth_monitor import Bandwidth
from core.diagnostic_cycle import DiagnosticCycle
from core.dns_analyzer import DNSResult
from core.network_info import NetworkInfo
from core.ping_monitor import PingResult
from core.tcp_checker import TCPResult
from database.db import Database
from database.recording import record_cycle
from utils.report_generator import export_csv, export_html, load_report

DAY = date(2026, 11, 19)


@pytest.fixture
def measured_database(tmp_path):
    database = Database(tmp_path / "measurements.sqlite3")
    database.initialize()
    cycle = DiagnosticCycle(
        "2026-11-19T12:00:00+00:00",
        NetworkInfo("en0", "192.0.2.1", ("192.0.2.2",), True),
        Bandwidth(upload_mbps=0, download_mbps=0.5),
        (PingResult("192.0.2.1", "partial_loss", 3, 2, 100 / 3, 175, 185, 180, 10),),
        (
            DNSResult("example.com", "ok", 250, ("192.0.2.3",)),
            DNSResult("example.net", "error", detail="<script>alert(1)</script>"),
        ),
        (TCPResult("192.0.2.1", 443, "error", detail="=1+1"),),
    )
    record_cycle(database, cycle)
    database.save(replace(cycle, timestamp="2026-11-20T00:00:00+00:00", ping=(), dns=(), tcp=()))
    return database


def test_exports_contain_same_report_and_preserve_missing_and_zero(measured_database):
    report = load_report(measured_database, DAY, DAY)
    rows = list(DictReader(StringIO(export_csv(report).decode("utf-8-sig"))))
    cycle = next(row for row in rows if row["record_type"] == "cycle")
    assert cycle["measured_at_utc"] == "2026-11-19T12:00:00+00:00"
    assert cycle["interface"] == "en0"
    assert float(cycle["upload_mbps"]) == 0
    assert cycle["health_score"]
    assert all(row["report_generated_at_utc"] == report.generated_at for row in rows)
    tcp = next(row for row in rows if row["protocol"] == "TCP")
    assert tcp["tcp_connect_ms"] == ""
    assert tcp["probe_detail"] == "'=1+1"
    dns_stats = next(row for row in rows if row["metric"] == "DNS lookup time per domain")
    assert dns_stats["sample_count"] == "1"
    assert float(dns_stats["mean"]) == 250
    assert {row["symptom"] for row in rows if row["record_type"] == "finding"} >= {
        "High latency", "Significant ICMP packet loss", "Slow DNS responses",
    }
    assert all(row["possible_causes"] and row["recommended_actions"]
               for row in rows if row["record_type"] == "finding")
    html = export_html(report).decode()
    assert "@media print" in html
    assert "save as a PDF" in html
    assert "High latency" in html
    assert "Recommended actions" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>" not in html
    assert report.generated_at in html


def test_legacy_and_empty_ranges(measured_database):
    following_day = date(2026, 11, 20)
    legacy = load_report(measured_database, following_day, following_day)
    assert legacy.cycles.iloc[0]["health_category"] == "Unavailable"
    assert legacy.probes.empty and legacy.findings.empty
    assert "Full assessment unavailable" in export_html(legacy).decode()
    empty = load_report(measured_database, date(2026, 11, 18), date(2026, 11, 18))
    assert empty.cycles.empty
    with pytest.raises(ValueError, match="date range"):
        load_report(measured_database, following_day, DAY)


def test_report_limit_and_demo_label(measured_database, monkeypatch):
    monkeypatch.setattr("utils.report_generator.REPORT_LIMIT", 1)
    report = load_report(measured_database, DAY, date(2026, 11, 20), demo=True)
    assert report.truncated
    assert len(report.cycles) == 1 and report.probes.empty
    assert "Offline demo (synthetic)" in export_html(report).decode()
    assert "Offline demo (synthetic)" in export_csv(report).decode("utf-8-sig")
