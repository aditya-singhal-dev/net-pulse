"""Run and interpret limited macOS ICMP echo probes."""

import os
import re
import subprocess
from dataclasses import dataclass
from ipaddress import ip_address
from statistics import mean

from config.settings import validate_host


@dataclass(frozen=True)
class PingResult:
    target: str
    status: str
    sent: int | None = None
    received: int | None = None
    loss_percent: float | None = None
    min_ms: float | None = None
    max_ms: float | None = None
    avg_ms: float | None = None
    jitter_ms: float | None = None
    detail: str | None = None


def parse_ping(target: str, output: str) -> PingResult:
    counts = re.search(r"(\d+) packets transmitted, (\d+) (?:packets )?received", output)
    if not counts:
        return PingResult(target, "error", detail="Ping did not return probe statistics")
    sent, received = map(int, counts.groups())
    if not sent or received > sent:
        return PingResult(target, "error", detail="Invalid ICMP probe counts")
    samples = [
        float(value)
        for line in output.splitlines() if "DUP!" not in line
        for value in re.findall(r"\bicmp_seq[= ]\d+.*?\btime[= ]([\d.]+) ms", line)
    ]
    jitter = mean(abs(b - a) for a, b in zip(samples, samples[1:])) if len(samples) > 1 else None
    return PingResult(
        target, "ok" if sent == received else "partial_loss" if received else "no_reply",
        sent, received, 100 * (sent - received) / sent,
        min(samples, default=None), max(samples, default=None),
        mean(samples) if samples else None, jitter,
    )


def ping(target: str, count: int, timeout: float) -> PingResult:
    target = validate_host(target)
    if not 1 <= count <= 5 or not 0.5 <= timeout <= 5:
        raise ValueError("ICMP probe settings out of range")
    try:
        ipv6 = ip_address(target).version == 6
    except ValueError:
        ipv6 = False
    command = ["/sbin/ping6" if ipv6 else "/sbin/ping", "-n", "-c", str(count)]
    if not ipv6:
        command.extend(("-W", str(round(timeout * 1000))))
    command.append(target)
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, shell=False, check=False,
            timeout=count + timeout + 1, env={**os.environ, "LC_ALL": "C"},
        )
    except subprocess.TimeoutExpired:
        return PingResult(target, "timeout", detail="Ping exceeded its execution deadline")
    except OSError as exc:
        return PingResult(target, "error", detail=str(exc))
    if result.returncode not in (0, 2):
        return PingResult(target, "error", detail=result.stderr.strip() or
                          f"Ping exited with code {result.returncode}")
    parsed = parse_ping(target, result.stdout)
    if result.stderr.strip() and parsed.received in (0, None):
        return PingResult(target, "error", detail=result.stderr.strip())
    return parsed
