"""Bounded macOS UDP traceroute with numeric hops and partial results."""

import os
import re
import subprocess
from dataclasses import dataclass
from ipaddress import ip_address

from config.settings import validate_host

MAX_HOPS = 20
HEADER = re.compile(r"traceroute(?:6)? to .*?\(([^)]+)\)", re.IGNORECASE)
HOP = re.compile(r"^\s*(\d+)\s+(.+)$")
REPLY = re.compile(r"(\S+)\s+(\d+(?:\.\d+)?)\s*ms(?:\s*(!\S+))?")


@dataclass(frozen=True)
class Hop:
    number: int
    address: str | None = None
    rtt_ms: float | None = None
    status: str = "No reply"
    annotation: str | None = None


@dataclass(frozen=True)
class TraceResult:
    host: str
    address: str | None
    status: str
    hops: tuple[Hop, ...]
    detail: str | None = None


def _numeric(value: str) -> str | None:
    try:
        return str(ip_address(value.split("%", 1)[0]))
    except ValueError:
        return None


def parse_traceroute(
    host: str, output: str, stderr: str, max_hops: int, *, timed_out: bool = False,
    returncode: int = 0,
) -> TraceResult:
    header = HEADER.search(stderr) or HEADER.search(output)
    address = _numeric(header[1]) if header else _numeric(host)
    hops = []
    for line in output.splitlines():
        match = HOP.fullmatch(line)
        if not match or not 1 <= int(match[1]) <= max_hops:
            continue
        number = int(match[1])
        reply = REPLY.search(match[2])
        if reply and (router := _numeric(reply[1])):
            note = reply[3]
            hops.append(Hop(number, router, float(reply[2]), "Annotated reply" if note else "Reply", note))
        elif match[2].strip() == "*":
            hops.append(Hop(number))
    if timed_out:
        status, detail = "timeout", "Traceroute exceeded its execution deadline."
    elif returncode or not hops:
        messages = [line for line in stderr.splitlines() if not HEADER.search(line)]
        status, detail = "error", "\n".join(messages).strip() or "Traceroute returned no hop results."
    elif address is not None and any(hop.address == address and hop.annotation is None for hop in hops):
        status, detail = "reached", None
    else:
        status, detail = "incomplete", "The destination did not return a confirming probe reply."
    return TraceResult(host, address, status, tuple(hops), detail)


def trace(host: str, max_hops: int = 12) -> TraceResult:
    host = validate_host(host)
    if not isinstance(max_hops, int) or not 1 <= max_hops <= MAX_HOPS:
        raise ValueError(f"Maximum hop count must be between 1 and {MAX_HOPS}")
    executable = "/usr/sbin/traceroute6" if ":" in host else "/usr/sbin/traceroute"
    arguments = [executable, "-n", "-m", str(max_hops), "-q", "1", "-w", "1", host]
    try:
        result = subprocess.run(
            arguments, capture_output=True, text=True, timeout=max_hops + 3, check=False,
            shell=False, env={**os.environ, "LC_ALL": "C"},
        )
    except subprocess.TimeoutExpired as exc:
        # TimeoutExpired stores binary output even when text=True.
        output, stderr = ((value or b"").decode(errors="replace") for value in (exc.stdout, exc.stderr))
        return parse_traceroute(host, output, stderr, max_hops, timed_out=True)
    except OSError as exc:
        return TraceResult(host, None, "error", (), str(exc))
    return parse_traceroute(host, result.stdout, result.stderr, max_hops, returncode=result.returncode)
