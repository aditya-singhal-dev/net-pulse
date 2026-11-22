from dataclasses import replace

import pytest

from config.analysis import DiagnosisThresholds
from core.bandwidth_monitor import Bandwidth
from core.diagnosis_engine import diagnose
from core.diagnostic_cycle import DiagnosticCycle
from core.dns_analyzer import DNSResult
from core.network_info import NetworkInfo
from core.ping_monitor import PingResult
from core.tcp_checker import TCPResult


@pytest.fixture
def cycle():
    return DiagnosticCycle(
        "2026-11-19T12:00:00+00:00", NetworkInfo("en0", None, (), True),
        Bandwidth(upload_mbps=10, download_mbps=2),
        (PingResult("1.1.1.1", "partial_loss", 4, 3, 25, 120, 200, 150, 30),),
        (DNSResult("example.com", "ok", 200), DNSResult("cloudflare.com", "timeout")),
        (TCPResult("example.com", 443, "refused"),),
    )


def test_rules_include_evidence_causes_and_actions(cycle):
    result = diagnose(cycle, sufficient_evidence=True, previous_bandwidth=Bandwidth(upload_mbps=0))
    assert result.status == "issues_detected"
    assert {finding.title for finding in result.findings} == {
        "High latency", "Significant ICMP packet loss", "High jitter", "DNS resolution failed",
        "Slow DNS responses", "TCP connection failed", "Sudden change in local traffic",
    }
    assert all(f.evidence and f.possible_causes and f.recommended_actions for f in result.findings)
    assert "150.0 ms" in result.findings[0].evidence[0]


def test_custom_thresholds_and_small_change(cycle):
    thresholds = DiagnosisThresholds(latency_ms=151, loss_percent=26, jitter_ms=31, dns_ms=201)
    result = diagnose(cycle, sufficient_evidence=True, thresholds=thresholds,
                      previous_bandwidth=Bandwidth(upload_mbps=9))
    assert [f.title for f in result.findings] == ["DNS resolution failed", "TCP connection failed"]


def test_inconclusive_preserves_observed_issues(cycle):
    cycle = replace(cycle, dns=(), tcp=())
    result = diagnose(cycle, sufficient_evidence=False)
    assert result.status == "inconclusive"
    assert len(result.findings) == 3


@pytest.mark.parametrize(("link_up", "expected"), [(False, "issues_detected"), (None, "inconclusive")])
def test_confirmed_down_and_unknown_interfaces(cycle, link_up, expected):
    cycle = replace(cycle, network=replace(cycle.network, interface_up=link_up), ping=(), dns=(), tcp=())
    result = diagnose(cycle, sufficient_evidence=False)
    assert result.status == expected
    if link_up is False:
        assert result.findings[0].severity == "Critical"
    else:
        assert result.findings == ()


def test_dns_dependency_and_probe_errors(cycle):
    cycle = replace(
        cycle, ping=(PingResult("1.1.1.1", "error"),), dns=(),
        tcp=(TCPResult("example.com", 443, "dns_failure"), TCPResult("localhost", 443, "error")),
    )
    result = diagnose(cycle, sufficient_evidence=False)
    assert [f.title for f in result.findings] == ["DNS resolution failed"]


def test_no_findings_with_usable_evidence(cycle):
    result = diagnose(replace(
        cycle, ping=(), dns=(DNSResult("example.com", "ok", 10),),
        tcp=(TCPResult("example.com", 443, "ok", 11),),
    ), sufficient_evidence=True)
    assert result.status == "no_issues_detected"
    assert result.findings == ()
