import socket
import subprocess
from unittest.mock import Mock

import dns.exception
import dns.resolver
import pytest

from config.settings import Settings, parse_endpoint, validate_host
from core import bandwidth_monitor, dns_analyzer, network_info, ping_monitor, tcp_checker
from core.diagnostic_cycle import DiagnosticCycle
from database.db import Database


def test_target_validation():
    assert parse_endpoint("[2001:db8::1]:443") == ("2001:db8::1", 443)
    with pytest.raises(ValueError):
        validate_host("-c")
    with pytest.raises(ValueError):
        Settings(tcp_endpoints=(("example.com", 65536),))
    with pytest.raises(ValueError):
        Settings(interval=7)


def test_route(monkeypatch):
    monkeypatch.setattr(network_info.subprocess, "run", Mock(return_value=Mock(
        returncode=0, stdout="gateway: 192.0.2.1\ninterface: en0\n",
    )))
    address = Mock(family=socket.AF_INET, address="192.0.2.10")
    monkeypatch.setattr(network_info.psutil, "net_if_addrs", lambda: {"en0": [address]})
    monkeypatch.setattr(network_info.psutil, "net_if_stats", lambda: {"en0": Mock(isup=True)})
    info = network_info.get_network_info()
    assert info == network_info.NetworkInfo("en0", "192.0.2.1", ("192.0.2.10",), True)


def test_ping_loss_and_jitter():
    result = ping_monitor.parse_ping("example.com", """
64 bytes from 192.0.2.2: icmp_seq=0 ttl=55 time=10 ms
64 bytes from 192.0.2.2: icmp_seq=0 ttl=55 time=99 ms (DUP!)
64 bytes from 192.0.2.2: icmp_seq=2 ttl=55 time=14 ms
64 bytes from 192.0.2.2: icmp_seq=3 ttl=55 time=12 ms
4 packets transmitted, 3 packets received, 25.0% packet loss
""")
    assert result.status == "partial_loss"
    assert result.loss_percent == 25
    assert (result.min_ms, result.max_ms, result.avg_ms, result.jitter_ms) == (10, 14, 12, 3)


def test_ping_no_reply_keeps_latency_unknown():
    result = ping_monitor.parse_ping("example.com", "3 packets transmitted, 0 packets received")
    assert result.status == "no_reply"
    assert result.loss_percent == 100
    assert result.avg_ms is result.jitter_ms is None


def test_ping_permission_failure_is_not_packet_loss(monkeypatch):
    process = subprocess.CompletedProcess([], 2, "1 packets transmitted, 0 packets received",
                                          "ping: sendto: Operation not permitted")
    monkeypatch.setattr(ping_monitor.subprocess, "run", Mock(return_value=process))
    result = ping_monitor.ping("127.0.0.1", 1, 1)
    assert result.status == "error"
    assert result.loss_percent is None


def test_bandwidth_sample_delta():
    first = bandwidth_monitor.CounterSample("en0", 1, 1_000_000, 2_000_000)
    second = bandwidth_monitor.CounterSample("en0", 3, 2_000_000, 4_000_000)
    assert bandwidth_monitor.calculate(None, first).upload_mbps is None
    result = bandwidth_monitor.calculate(first, second)
    assert (result.upload_mbps, result.download_mbps) == (4, 8)
    assert result.total_received == 4_000_000
    reset = bandwidth_monitor.CounterSample("en0", 5, 0, 0)
    other = bandwidth_monitor.CounterSample("en1", 5, 3_000_000, 5_000_000)
    assert bandwidth_monitor.calculate(second, reset).download_mbps is None
    assert bandwidth_monitor.calculate(second, other).download_mbps is None


@pytest.mark.parametrize(("error", "status"), [
    (dns.resolver.NXDOMAIN(), "nxdomain"),
    (dns.resolver.NoAnswer(), "no_answer"),
    (dns.exception.Timeout(), "timeout"),
    (dns.resolver.NoNameservers(), "error"),
])
def test_dns_errors(monkeypatch, error, status):
    resolver = Mock()
    resolver.resolve_name.side_effect = error
    monkeypatch.setattr(dns_analyzer.dns.resolver, "Resolver", lambda: resolver)
    result = dns_analyzer.lookup("example.com", 2)
    assert result.status == status
    assert result.elapsed_ms is None
    resolver.resolve_name.assert_called_once_with("example.com", lifetime=2)


def test_tcp_timeout(monkeypatch):
    client = Mock()
    client.connect.side_effect = TimeoutError("timed out")
    context = Mock()
    context.__enter__ = Mock(return_value=client)
    context.__exit__ = Mock(return_value=False)
    monkeypatch.setattr(tcp_checker.socket, "socket", lambda *_: context)
    result = tcp_checker.connect("192.0.2.1", 443, 2)
    assert result.status == "timeout"
    assert result.elapsed_ms is None
    client.connect.assert_called_once_with(("192.0.2.1", 443))


def test_database_round_trip(tmp_path):
    cycle = DiagnosticCycle(
        "2026-11-19T12:00:00+00:00", network_info.NetworkInfo("en0", None, (), True),
        bandwidth_monitor.Bandwidth(100, 200, 1.2, 2.4),
        (ping_monitor.PingResult("192.0.2.1", "no_reply", 3, 0, 100),),
        (dns_analyzer.DNSResult("example.com", "ok", 3.1, ("192.0.2.1",)),),
        (tcp_checker.TCPResult("example.com", 443, "ok", 5.2),),
    )
    database = Database(tmp_path / "data" / "netpulse.sqlite3")
    database.initialize()
    database.initialize()
    cycle_id = database.save(cycle)
    rows = database.history("2026-11-19T00:00:00+00:00", "2026-11-20T00:00:00+00:00")
    assert len(rows) == 1
    assert rows[0]["id"] == cycle_id
    assert rows[0]["health_score"] is None
    assert rows[0]["diagnostic_status"] == "tcp_reachable"
    assert database.history("2026-11-18T00:00:00+00:00", cycle.timestamp) == []
    ping, dns, tcp = database.probes(cycle_id)
    assert ping["latency_ms"] is None and ping["packet_loss_percent"] == 100
    assert dns["dns_response_ms"] == 3.1
    assert tcp["tcp_connect_ms"] == 5.2


def test_analysis_storage_and_recent_same_interface_baseline(tmp_path):
    from dataclasses import replace

    database = Database(tmp_path / "netpulse.sqlite3")
    database.initialize()
    previous = DiagnosticCycle(
        "2026-11-19T12:00:00+00:00", network_info.NetworkInfo("en0", None, (), True),
        bandwidth_monitor.Bandwidth(100, 200, 0, 2.4), (), (), (),
    )
    database.save(previous)
    database.save(replace(
        previous, timestamp="2026-11-19T12:01:00+00:00",
        network=replace(previous.network, interface="en1"),
    ))
    current = replace(previous, timestamp="2026-11-19T12:02:00+00:00")
    assert database.previous_bandwidth(current, 300) == previous.bandwidth
    assert database.previous_bandwidth(current, 60) is None
    database.save(current, health_score=0, diagnostic_status="issues_detected")
    latest = database.history("2026-11-19T00:00:00+00:00", "2026-11-20T00:00:00+00:00")[0]
    assert latest["health_score"] == 0
    assert latest["diagnostic_status"] == "issues_detected"
