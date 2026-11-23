"""Measure link, HTTP, and system-wide TCP indicators on macOS."""

import json
import os
import re
import subprocess
from dataclasses import dataclass

import psutil

HTTP_URL = "https://example.com/"


@dataclass(frozen=True)
class ExtraMetrics:
    link_capacity_mbps: float | None = None
    http_response_ms: float | None = None
    http_status: int | None = None
    tcp_retransmission_percent: float | None = None
    wifi_rssi_dbm: int | None = None
    dns_failure_percent: float | None = None


def _command(args: list[str], timeout: float) -> str | None:
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout, check=False,
            env={**os.environ, "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout if result.returncode == 0 else None


def http_response(timeout: float) -> tuple[float | None, int | None]:
    output = _command([
        "/usr/bin/curl", "-q", "--silent", "--head", "--output", "/dev/null",
        "--max-time", str(timeout), "--write-out",
        "%{time_pretransfer} %{time_starttransfer} %{http_code}", HTTP_URL,
    ], timeout + 1)
    try:
        setup, first_byte, code = (output or "").split()
        elapsed = float(first_byte) - float(setup)
        status = int(code)
        if 100 <= status <= 599 and 0 <= elapsed <= timeout:
            return elapsed * 1000, status
    except ValueError:
        pass
    return None, None


def tcp_counters() -> tuple[int, int] | None:
    output = _command(["/usr/sbin/netstat", "-s", "-p", "tcp"], 1)
    total = re.search(r"(?m)^\s*(\d+) packets? sent\s*$", output or "")
    retransmitted = re.search(r"(?m)^\s*(\d+) data packets? \([^\n]*\) retransmitted\s*$", output or "")
    if total and retransmitted:
        return int(total[1]), int(retransmitted[1])
    return None


def retransmission_percent(
    before: tuple[int, int] | None, after: tuple[int, int] | None,
) -> float | None:
    if before is None or after is None:
        return None
    sent, retransmitted = after[0] - before[0], after[1] - before[1]
    if sent > 0 and 0 <= retransmitted <= sent:
        return 100 * retransmitted / sent
    return None


def link_metrics(interface: str | None) -> tuple[float | None, int | None]:
    if interface is None:
        return None, None
    script = """ObjC.import('CoreWLAN');
var wifi = $.CWWiFiClient.sharedWiFiClient.interface;
JSON.stringify([ObjC.unwrap(wifi.interfaceName), Number(wifi.transmitRate), Number(wifi.rssiValue)]);"""
    output = _command(["/usr/bin/osascript", "-l", "JavaScript", "-e", script], 2)
    rssi = None
    try:
        name, speed, signal = json.loads(output or "null")
        if name == interface:
            rssi = int(signal) if isinstance(signal, (int, float)) and -127 <= signal < 0 else None
            if isinstance(speed, (int, float)) and speed > 0:
                return speed, rssi
    except (TypeError, ValueError):
        pass
    try:
        stats = psutil.net_if_stats().get(interface)
    except (OSError, psutil.Error):
        return None, rssi
    return (stats.speed if stats and stats.isup and stats.speed > 0 else None), rssi
