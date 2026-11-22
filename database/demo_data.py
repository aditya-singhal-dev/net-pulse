"""Load the offline demo into a disposable database using the normal pipeline."""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core.bandwidth_monitor import Bandwidth
from core.diagnostic_cycle import DiagnosticCycle
from core.dns_analyzer import DNSResult
from core.network_info import NetworkInfo
from core.ping_monitor import PingResult
from core.tcp_checker import TCPResult
from database.db import Database
from database.recording import record_cycle

FIXTURE = Path(__file__).resolve().parents[1] / "demo" / "cycles.json"


def populate_demo(database: Database) -> None:
    now = datetime.now(timezone.utc)
    items = json.loads(FIXTURE.read_text(encoding="utf-8"))["cycles"]
    for item in items:
        stamp = (now - timedelta(seconds=item["seconds_ago"])).isoformat()
        loss, latency, jitter = item["loss_count"], item["latency_ms"], item["jitter_ms"]
        probes = (
            PingResult("198.51.100.10", "partial_loss" if loss else "ok",
                       3, 3 - loss, 100 * loss / 3, latency - jitter / 2,
                       latency + jitter / 2, latency, jitter),
            PingResult("203.0.113.20", "ok", 3, 3, 0, latency - 5 - jitter,
                       latency - 5 + jitter, latency - 5, jitter / 2),
        )
        cycle = DiagnosticCycle(
            stamp, NetworkInfo("demo0", "192.0.2.1", ("192.0.2.10",), True),
            Bandwidth(upload_mbps=item["upload_mbps"], download_mbps=item["download_mbps"]),
            probes, (DNSResult("example.com", "ok", item["dns_ms"], ("198.51.100.10",)),),
            (TCPResult("example.com", 443, "ok", item["tcp_ms"], "198.51.100.10"),),
        )
        record_cycle(database, cycle)
