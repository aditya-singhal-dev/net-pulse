"""Collect, assess, and save real network diagnostics."""

import argparse
import json
import sqlite3
from dataclasses import asdict
from pathlib import Path

from config.analysis import parse_thresholds
from config.settings import Settings, parse_endpoint
from core.diagnostic_cycle import collect
from database.db import Database
from database.recording import record_cycle


def main() -> None:
    defaults = Settings()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ping", action="append", metavar="HOST", help="Override ping targets")
    parser.add_argument("--dns", action="append", metavar="DOMAIN", help="Override DNS domains")
    parser.add_argument("--tcp", action="append", metavar="HOST:PORT", help="Override TCP endpoints")
    parser.add_argument("--count", type=int, default=defaults.ping_count, help="ICMP attempts")
    parser.add_argument("--timeout", type=float, default=defaults.timeout, help="Timeout in seconds")
    parser.add_argument("--db", type=Path, default=Path("data/netpulse.sqlite3"), help="SQLite path")
    parser.add_argument("--thresholds", type=Path, help="JSON file with scoring and diagnosis cutoffs")
    args = parser.parse_args()
    try:
        settings = Settings(
            ping_targets=tuple(args.ping) if args.ping else defaults.ping_targets,
            dns_domains=tuple(args.dns) if args.dns else defaults.dns_domains,
            tcp_endpoints=tuple(map(parse_endpoint, args.tcp)) if args.tcp else defaults.tcp_endpoints,
            ping_count=args.count,
            timeout=args.timeout,
        )
        overrides = json.loads(args.thresholds.read_text()) if args.thresholds else {}
        score_thresholds, diagnosis_thresholds = parse_thresholds(overrides)
    except (OSError, OverflowError, TypeError, ValueError) as exc:
        parser.error(str(exc))
    try:
        database = Database(args.db)
        database.initialize()
        cycle = collect(settings)
        cycle_id, health, diagnosis = record_cycle(
            database, cycle, score_thresholds, diagnosis_thresholds,
        )
    except (OSError, sqlite3.Error) as exc:
        parser.exit(1, f"NetPulse: {exc}\n")
    print(json.dumps({"cycle_id": cycle_id, "database": str(args.db),
                      "status": cycle.status, **asdict(cycle),
                      "health": asdict(health), "diagnosis": asdict(diagnosis)}, indent=2))


if __name__ == "__main__":
    main()
