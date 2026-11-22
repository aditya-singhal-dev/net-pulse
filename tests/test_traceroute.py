import subprocess
from unittest.mock import Mock

import pytest

from core import traceroute


def test_parses_replies_timeouts_and_annotations():
    result = traceroute.parse_traceroute(
        "example.com",
        " 1  192.0.2.1  1.25 ms\n 2  *\n 3  198.51.100.1  2.0 ms !H\n",
        "traceroute to example.com (192.0.2.10), 3 hops max",
        3,
    )
    assert result.address == "192.0.2.10"
    assert result.status == "incomplete"
    assert [hop.status for hop in result.hops] == ["Reply", "No reply", "Annotated reply"]
    assert result.hops[2].annotation == "!H"
    assert result.hops[0].rtt_ms == 1.25


def test_ipv6_reaches_destination(monkeypatch):
    process = subprocess.CompletedProcess(
        [], 0, " 1  ::1  0.134 ms\n", "traceroute6 to ::1 (::1) from ::1, 1 hops max",
    )
    run = Mock(return_value=process)
    monkeypatch.setattr(traceroute.subprocess, "run", run)
    result = traceroute.trace("::1", 1)
    assert result.status == "reached"
    assert run.call_args.args[0] == ["/usr/sbin/traceroute6", "-n", "-m", "1", "-q", "1", "-w", "1", "::1"]
    assert run.call_args.kwargs["timeout"] == 4
    assert run.call_args.kwargs["shell"] is False


def test_timeout_retains_completed_hops(monkeypatch):
    run = Mock(side_effect=subprocess.TimeoutExpired([], 5, output=b" 1  192.0.2.1  2 ms\n 2  "))
    monkeypatch.setattr(traceroute.subprocess, "run", run)
    result = traceroute.trace("192.0.2.10", 2)
    assert result.status == "timeout"
    assert result.hops == (traceroute.Hop(1, "192.0.2.1", 2, "Reply"),)


@pytest.mark.parametrize(("host", "hops"), [("-I", 2), ("example.com", 21), ("example.com", 0)])
def test_invalid_values_do_not_run_subprocess(host, hops, monkeypatch):
    run = Mock()
    monkeypatch.setattr(traceroute.subprocess, "run", run)
    with pytest.raises(ValueError):
        traceroute.trace(host, hops)
    run.assert_not_called()


def test_missing_permissions_return_error(monkeypatch):
    run = Mock(side_effect=PermissionError("Operation not permitted"))
    monkeypatch.setattr(traceroute.subprocess, "run", run)
    result = traceroute.trace("192.0.2.10")
    assert result.status == "error"
    assert result.detail == "Operation not permitted"
