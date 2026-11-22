from dataclasses import replace

import pytest

from config.analysis import ScoreThresholds
from core.bandwidth_monitor import Bandwidth
from core.diagnostic_cycle import DiagnosticCycle
from core.dns_analyzer import DNSResult
from core.health_score import score_health
from core.network_info import NetworkInfo
from core.ping_monitor import PingResult
from core.tcp_checker import TCPResult


@pytest.fixture
def healthy_cycle():
    return DiagnosticCycle(
        "2026-11-19T12:00:00+00:00", NetworkInfo("en0", None, (), True), Bandwidth(),
        (PingResult("1.1.1.1", "ok", 3, 3, 0, 20, 30, 25, 5),),
        (DNSResult("example.com", "ok", 25),),
        (TCPResult("example.com", 443, "ok", 10),),
    )


def test_excellent_score(healthy_cycle):
    health = score_health(healthy_cycle)
    assert (health.score, health.category, health.measured_weight) == (100, "Excellent", 100)


def test_weighted_penalties(healthy_cycle):
    cycle = replace(
        healthy_cycle,
        ping=(replace(healthy_cycle.ping[0], avg_ms=175, loss_percent=25, jitter_ms=45),),
        dns=(DNSResult("example.com", "timeout"),),
        tcp=healthy_cycle.tcp + (TCPResult("cloudflare.com", 443, "refused"),),
    )
    health = score_health(cycle)
    assert health.components == dict(latency=50, loss=50, jitter=50, dns=0, tcp=50)
    assert (health.score, health.category) == (40, "Poor")


def test_missing_icmp_is_excluded_when_dns_and_tcp_suffice(healthy_cycle):
    cycle = replace(healthy_cycle, ping=(PingResult("1.1.1.1", "error"),))
    health = score_health(cycle)
    assert health.score == 100
    assert health.measured_weight == 45
    assert health.components["loss"] is None


def test_one_protocol_cannot_produce_a_score(healthy_cycle):
    cycle = replace(healthy_cycle, dns=(), tcp=())
    health = score_health(cycle)
    assert health.measured_weight == 55
    assert (health.score, health.category) == (None, "Unavailable")


def test_dns_failure_is_not_counted_as_a_tcp_handshake(healthy_cycle):
    cycle = replace(healthy_cycle, tcp=(TCPResult("example.com", 443, "dns_failure"),))
    assert score_health(cycle).components["tcp"] is None


def test_confirmed_failures_can_score_zero(healthy_cycle):
    cycle = replace(
        healthy_cycle,
        ping=(PingResult("1.1.1.1", "no_reply", 3, 0, 100),),
        dns=(DNSResult("example.com", "timeout"),),
        tcp=(TCPResult("example.com", 443, "timeout"),),
    )
    health = score_health(cycle)
    assert (health.score, health.category) == (0, "Critical")
    assert health.components["latency"] is None


def test_custom_and_invalid_score_cutoffs(healthy_cycle):
    assert score_health(healthy_cycle, ScoreThresholds(latency_ms=(0, 25))).score == 80
    with pytest.raises(ValueError):
        ScoreThresholds(jitter_ms=(50, 10))


def test_cli_applies_threshold_file_and_persists_assessment(healthy_cycle, tmp_path, monkeypatch, capsys):
    import json
    import sys

    import app
    from database.db import Database

    thresholds = tmp_path / "thresholds.json"
    thresholds.write_text('{"score":{"latency_ms":[0,25]},"diagnosis":{"latency_ms":25}}')
    path = tmp_path / "netpulse.sqlite3"
    monkeypatch.setattr(app, "collect", lambda settings: healthy_cycle)
    monkeypatch.setattr(sys, "argv", ["app.py", "--db", str(path), "--thresholds", str(thresholds)])
    app.main()
    output = json.loads(capsys.readouterr().out)
    assert output["health"]["score"] == 80
    assert output["diagnosis"]["findings"][0]["title"] == "High latency"
    saved = Database(path).history("2026-11-19", "2026-11-20")[0]
    assert saved["health_score"] == 80
    assert saved["diagnostic_status"] == "issues_detected"
