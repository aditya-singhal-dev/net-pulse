"""Measure local interface traffic using cumulative OS counters."""

from dataclasses import dataclass
from time import monotonic

import psutil


@dataclass(frozen=True)
class CounterSample:
    interface: str
    timestamp: float
    sent: int
    received: int


@dataclass(frozen=True)
class Bandwidth:
    total_sent: int | None = None
    total_received: int | None = None
    upload_mbps: float | None = None
    download_mbps: float | None = None


def sample(interface: str | None) -> CounterSample | None:
    if not interface:
        return None
    counters = psutil.net_io_counters(pernic=True, nowrap=False).get(interface)
    if counters is None:
        return None
    return CounterSample(interface, monotonic(), counters.bytes_sent, counters.bytes_recv)


def calculate(previous: CounterSample | None, current: CounterSample | None) -> Bandwidth:
    if current is None:
        return Bandwidth()
    upload = download = None
    if previous and previous.interface == current.interface:
        elapsed = current.timestamp - previous.timestamp
        if elapsed > 0:
            sent = current.sent - previous.sent
            received = current.received - previous.received
            if sent >= 0:
                upload = sent * 8 / elapsed / 1_000_000
            if received >= 0:
                download = received * 8 / elapsed / 1_000_000
    return Bandwidth(current.sent, current.received, upload, download)
