"""Exercise the dashboard without sending network probes."""

from pathlib import Path
from time import monotonic, sleep

from streamlit.testing.v1 import AppTest

from core.bandwidth_monitor import Bandwidth
from core.diagnostic_cycle import DiagnosticCycle
from core.dns_analyzer import DNSResult
from core.network_info import NetworkInfo
from core.ping_monitor import PingResult
from core.tcp_checker import TCPResult
from database.db import Database

ENTRY_POINT = Path(__file__).resolve().parents[1] / "dashboard.py"


def test_empty_database_does_not_start_probes(tmp_path, monkeypatch):
    def unexpected_probe(_settings):
        raise AssertionError("The dashboard must wait for an explicit run request")

    monkeypatch.setenv("NETPULSE_DB", str(tmp_path / "empty.sqlite3"))
    monkeypatch.setattr("core.monitoring_service.collect", unexpected_probe)
    dashboard = AppTest.from_file(str(ENTRY_POINT), default_timeout=30).run()
    assert not dashboard.exception
    assert dashboard.info[0].value == "No measurements available — start monitoring."
    assert not dashboard.metric


def test_diagnostic_button_saves_and_displays_results(tmp_path, monkeypatch):
    path = tmp_path / "diagnostics.sqlite3"
    monkeypatch.setenv("NETPULSE_DB", str(path))
    cycle = DiagnosticCycle(
        "2026-11-19T12:00:00+00:00", NetworkInfo("en0", "192.0.2.1", ("192.0.2.2",), True),
        Bandwidth(100, 200, 0.0, 1.25),
        (PingResult("192.0.2.1", "ok", 3, 3, 0, 10, 12, 11, 1),),
        (DNSResult("example.com", "ok", 15, ("192.0.2.3",)),),
        (TCPResult("example.com", 443, "ok", 20, "192.0.2.3"),),
    )
    monkeypatch.setattr("core.monitoring_service.collect", lambda settings: cycle)
    dashboard = AppTest.from_file(str(ENTRY_POINT), default_timeout=30).run()
    dashboard.button[0].click().run()
    deadline = monotonic() + 5
    while Database(path).latest() is None and monotonic() < deadline:
        sleep(0.01)
    dashboard.run()

    assert not dashboard.exception
    cards = {metric.label: metric.value for metric in dashboard.metric}
    assert cards == {
        "Health score": "100 / 100", "Latency": "11.0 ms", "ICMP loss": "0.0 %",
        "DNS lookup": "15.0 ms", "TCP connect": "20.0 ms",
        "Local upload": "0.0 Mbps", "Local download": "1.2 Mbps",
    }
    assert len(dashboard.get("plotly_chart")) == 2
    assert [table.value.iloc[0]["Target"] for table in dashboard.dataframe] == [
        "192.0.2.1", "example.com", "example.com:443",
    ]
    assert dashboard.success[0].value == "No configured thresholds were triggered."
    assert Database(path).latest()["health_score"] == 100

    fresh_view = AppTest.from_file(str(ENTRY_POINT), default_timeout=30).run()
    assert not fresh_view.exception
    assert fresh_view.metric[0].value == "100 / 100"
    assert len(Database(path).history("2026-11-19", "2026-11-20")) == 1


def test_phase_one_data_remains_readable(tmp_path, monkeypatch):
    path = tmp_path / "legacy.sqlite3"
    monkeypatch.setenv("NETPULSE_DB", str(path))
    database = Database(path)
    database.initialize()
    database.save(DiagnosticCycle(
        "2026-11-19T12:00:00+00:00", NetworkInfo(None, None, (), None), Bandwidth(),
        (PingResult("192.0.2.1", "no_reply", 3, 0, 100),), (), (),
    ))
    dashboard = AppTest.from_file(str(ENTRY_POINT), default_timeout=30).run()
    assert not dashboard.exception
    cards = {metric.label: metric.value for metric in dashboard.metric}
    assert cards["Health score"] == cards["Latency"] == "—"
    assert cards["ICMP loss"] == "100.0 %"
    assert any("Saved status: Inconclusive" in item.value for item in dashboard.info)
