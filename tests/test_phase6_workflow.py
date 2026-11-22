from pathlib import Path
from time import monotonic, sleep

from streamlit.testing.v1 import AppTest

from config.settings import Settings
from core.bandwidth_monitor import Bandwidth
from core.diagnostic_cycle import DiagnosticCycle
from core.network_info import NetworkInfo
from database.db import Database
from ui.settings import load_settings

ENTRY = Path(__file__).resolve().parents[1] / "dashboard.py"


def test_settings_persist_and_reach_the_worker(tmp_path, monkeypatch):
    path = tmp_path / "measurements.sqlite3"
    monkeypatch.setenv("NETPULSE_DB", str(path))
    calls = []

    def collect(settings):
        calls.append(settings)
        return DiagnosticCycle(
            "2026-11-19T12:00:00+00:00", NetworkInfo("en0", None, (), True),
            Bandwidth(), (), (), (),
        )

    monkeypatch.setattr("core.monitoring_service.collect", collect)
    app = AppTest.from_file(str(ENTRY), default_timeout=20).run()
    app.radio[0].set_value("Settings").run()
    app.text_area[0].set_value("192.0.2.8")
    app.text_area[3].set_value('{"diagnosis": {"latency_ms": 110}}')
    app.selectbox[0].set_value(30)
    app.button[0].click().run()
    assert not app.exception
    stored = load_settings(Database(path))
    assert isinstance(stored, Settings)
    assert stored.ping_targets == ("192.0.2.8",)
    assert stored.diagnosis_thresholds.latency_ms == 110
    assert stored.interval == 30
    app.radio[0].set_value("Overview").run()
    app.button[0].click().run()
    deadline = monotonic() + 5
    while Database(path).latest() is None and monotonic() < deadline:
        sleep(0.01)
    assert calls == [stored]
    assert Database(path).latest() is not None


def test_demo_has_no_live_controls_and_can_generate_reports(tmp_path, monkeypatch):
    real_path = tmp_path / "real.sqlite3"
    monkeypatch.setenv("NETPULSE_DB", str(real_path))
    monkeypatch.setenv("NETPULSE_DEMO", "1")

    def unexpected_probe(_):
        raise AssertionError("The demo must not call the live collector")

    monkeypatch.setattr("core.monitoring_service.collect", unexpected_probe)
    app = AppTest.from_file(str(ENTRY), default_timeout=20).run()
    assert not app.exception
    assert "Offline demo" in app.warning[0].value
    assert app.button[0].disabled
    assert "DNS Analysis" not in app.radio[0].options
    app.radio[0].set_value("Historical Reports").run()
    app.button[0].click().run()
    assert not app.exception
    assert app.metric[0].value == "5"
    assert len(app.get("download_button")) == 2
    assert not real_path.exists()
