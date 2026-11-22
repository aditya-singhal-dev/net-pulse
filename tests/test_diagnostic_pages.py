from pathlib import Path
from time import monotonic, sleep

import pytest
from streamlit.testing.v1 import AppTest

from core.dns_analyzer import DNSResult
from core.tcp_checker import TCPResult
from core.traceroute import Hop, TraceResult

ENTRY = Path(__file__).resolve().parents[1] / "dashboard.py"


@pytest.mark.parametrize(("page", "function", "response", "table_key", "expected"), [
    ("DNS Analysis", "ui.dns_tcp._query_dns", (DNSResult("example.com", "ok", 12),),
     "Domain", "example.com"),
    ("TCP Connectivity", "ui.dns_tcp._query_tcp", (TCPResult("example.com", 443, "ok", 9),),
     "Endpoint", "example.com:443"),
    ("Network Path", "ui.network_path.trace", TraceResult(
        "1.1.1.1", "1.1.1.1", "reached", (Hop(1, "1.1.1.1", 8, "Reply"),),
    ), "Router IP", "1.1.1.1"),
])
def test_tool_page_displays_background_result(page, function, response, table_key, expected, monkeypatch, tmp_path):
    monkeypatch.setenv("NETPULSE_DB", str(tmp_path / "test.sqlite3"))
    monkeypatch.setattr(function, lambda *_: response)
    app = AppTest.from_file(str(ENTRY), default_timeout=20).run()
    app.radio[0].set_value(page).run()
    app.button[0].click().run()
    deadline = monotonic() + 5
    while not app.dataframe and not app.exception and monotonic() < deadline:
        sleep(0.025)
        app.run()
    assert not app.exception
    assert app.dataframe[0].value.iloc[0][table_key] == expected


def test_no_scapy_keeps_dashboard_available(monkeypatch, tmp_path):
    monkeypatch.setenv("NETPULSE_DB", str(tmp_path / "test.sqlite3"))
    monkeypatch.setattr("ui.packets.find_spec", lambda _: None)
    app = AppTest.from_file(str(ENTRY), default_timeout=20).run()
    assert not app.exception
    app.radio[0].set_value("Packet Analysis").run()
    assert not app.exception
    assert "Packet analysis is optional" in app.info[0].value
    app.radio[0].set_value("Overview").run()
    assert not app.exception
    assert app.button[0].label == "Run diagnostics"


def test_packet_page_displays_imported_pcap_summary(monkeypatch, tmp_path):
    scapy = pytest.importorskip("scapy.all")
    monkeypatch.setenv("NETPULSE_DB", str(tmp_path / "test.sqlite3"))
    path = tmp_path / "packet.pcap"
    scapy.wrpcap(str(path), scapy.IP(src="192.0.2.1", dst="192.0.2.2") / scapy.UDP())
    data = path.read_bytes()

    class Upload:
        size = len(data)

        def getvalue(self):
            return data

    monkeypatch.setattr("ui.packets.st.file_uploader", lambda *args, **kwargs: Upload())
    app = AppTest.from_file(str(ENTRY), default_timeout=20).run()
    app.radio[0].set_value("Packet Analysis").run()
    app.button[0].click().run()
    deadline = monotonic() + 5
    while not app.dataframe and not app.exception and monotonic() < deadline:
        sleep(0.025)
        app.run()
    assert not app.exception
    row = app.dataframe[0].value.iloc[0]
    assert row["Source IP"] == "192.0.2.1"
    assert row["Destination IP"] == "192.0.2.2"
    assert row["Protocol"] == "UDP"
