"""Build printable reports and machine-readable CSV from a SQLite snapshot."""

import json
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone
from html import escape
from sqlite3 import Row

import pandas as pd

from core.extra_metrics import HTTP_URL
from core.health_score import score_category
from database.db import Database

REPORT_LIMIT = 500
EXTENDED_FIELDS = (
    "link_capacity_mbps", "http_response_ms", "http_status", "tcp_retransmission_percent",
    "wifi_rssi_dbm", "dns_failure_percent",
)
CYCLE_FIELDS = (
    "cycle_id", "measured_at_utc", "interface", "interface_state", "local_addresses", "gateway",
    "upload_mbps", "download_mbps", "total_sent_bytes", "total_received_bytes",
    "health_score", "health_category", "diagnostic_status", "diagnostic_summary",
    *EXTENDED_FIELDS, "http_target",
)
PROBE_FIELDS = (
    "cycle_id", "protocol", "target", "port", "probe_status", "latency_ms", "min_rtt_ms",
    "max_rtt_ms", "packet_loss_percent", "jitter_ms", "sent_probes", "received_probes",
    "dns_response_ms", "tcp_connect_ms", "addresses", "probe_detail",
)
FINDING_FIELDS = ("cycle_id", "symptom", "severity", "evidence", "possible_causes", "recommended_actions")
STAT_FIELDS = ("metric", "unit", "sample_count", "minimum", "mean", "maximum")
STAT_METRICS = (
    ("latency_ms", "ICMP mean RTT per target", "ms"),
    ("packet_loss_percent", "ICMP packet loss per target", "%"),
    ("jitter_ms", "ICMP jitter per target", "ms"),
    ("dns_response_ms", "DNS lookup time per domain", "ms"),
    ("tcp_connect_ms", "TCP handshake time per endpoint", "ms"),
    ("upload_mbps", "Local upload per cycle", "Mbps"),
    ("download_mbps", "Local download per cycle", "Mbps"),
    ("health_score", "Health score per cycle", "points"),
    ("link_capacity_mbps", "Local link capacity", "Mbps"),
    ("http_response_ms", "HTTP time to first byte", "ms"),
    ("tcp_retransmission_percent", "TCP retransmissions", "%"),
    ("wifi_rssi_dbm", "Wi-Fi signal strength", "dBm"),
    ("dns_failure_percent", "DNS failures", "%"),
)


@dataclass(frozen=True)
class Report:
    generated_at: str
    start: date
    end: date
    source: str
    truncated: bool
    cycles: pd.DataFrame
    probes: pd.DataFrame
    findings: pd.DataFrame
    statistics: pd.DataFrame


def _cycle_record(row: Row, diagnosis: dict) -> dict:
    return {
        **{key: row[key] for key in EXTENDED_FIELDS},
        "http_target": HTTP_URL if row["cycle_id"] is not None else None,
        "cycle_id": row["id"], "measured_at_utc": row["timestamp"], "interface": row["interface"],
        "interface_state": {0: "Down", 1: "Up"}.get(row["interface_up"], "Unknown"),
        "local_addresses": ", ".join(json.loads(row["addresses"])),
        "gateway": row["gateway"], "upload_mbps": row["upload_mbps"],
        "download_mbps": row["download_mbps"], "total_sent_bytes": row["total_sent"],
        "total_received_bytes": row["total_received"], "health_score": row["health_score"],
        "health_category": score_category(row["health_score"]),
        "diagnostic_status": row["diagnostic_status"],
        "diagnostic_summary": diagnosis.get("summary", "Full assessment unavailable for this record."),
    }


def _probe_record(row: Row) -> dict:
    details = json.loads(row["details"])
    return {
        "cycle_id": row["cycle_id"], "protocol": row["protocol"].upper(), "target": row["target"],
        "port": row["port"], "probe_status": row["status"], "latency_ms": row["latency_ms"],
        "min_rtt_ms": details.get("min_ms"), "max_rtt_ms": details.get("max_ms"),
        "packet_loss_percent": row["packet_loss_percent"], "jitter_ms": row["jitter_ms"],
        "sent_probes": details.get("sent"), "received_probes": details.get("received"),
        "dns_response_ms": row["dns_response_ms"], "tcp_connect_ms": row["tcp_connect_ms"],
        "addresses": ", ".join(details.get("addresses", ())) or details.get("address"),
        "probe_detail": details.get("detail"),
    }


def load_report(database: Database, start: date, end: date, *, demo: bool = False) -> Report:
    """Use inclusive UTC calendar dates and keep missing measurements blank."""
    if start > end or end == date.max:
        raise ValueError("Choose a valid date range with the start on or before the end.")
    lower = datetime.combine(start, time.min, timezone.utc).isoformat()
    upper = datetime.combine(end + timedelta(days=1), time.min, timezone.utc).isoformat()
    cycles, probes, truncated = database.report_rows(lower, upper, REPORT_LIMIT)
    cycle_records, findings = [], []
    for row in cycles:
        diagnosis = json.loads(row["diagnosis"]) if row["diagnosis"] else {}
        cycle_records.append(_cycle_record(row, diagnosis))
        findings.extend({
            "cycle_id": row["id"], "symptom": item["title"], "severity": item["severity"],
            "evidence": " | ".join(item["evidence"]),
            "possible_causes": " | ".join(item["possible_causes"]),
            "recommended_actions": " | ".join(item["recommended_actions"]),
        } for item in diagnosis.get("findings", ()))
    cycle_frame = pd.DataFrame(cycle_records, columns=CYCLE_FIELDS, dtype=object)
    probe_frame = pd.DataFrame([_probe_record(row) for row in probes], columns=PROBE_FIELDS, dtype=object)
    stats = []
    for key, label, unit in STAT_METRICS:
        frame = probe_frame if key in PROBE_FIELDS else cycle_frame
        values = frame[key].dropna()
        stats.append({
            "metric": label, "unit": unit, "sample_count": len(values),
            "minimum": round(values.min(), 3) if len(values) else None,
            "mean": round(values.mean(), 3) if len(values) else None,
            "maximum": round(values.max(), 3) if len(values) else None,
        })
    return Report(
        datetime.now(timezone.utc).isoformat(timespec="seconds"), start, end,
        "Offline demo (synthetic)" if demo else "Recorded measurements", truncated,
        cycle_frame, probe_frame, pd.DataFrame(findings, columns=FINDING_FIELDS, dtype=object),
        pd.DataFrame(stats, columns=STAT_FIELDS, dtype=object),
    )


def _csv_value(value: object) -> object:
    # Spreadsheet programs can evaluate a formula in a quoted CSV cell.
    if isinstance(value, str) and (value.startswith(("\t", "\r", "\n"))
                                   or value.lstrip().startswith(("=", "+", "-", "@", "＝", "＋", "－", "＠"))):
        return "'" + value
    return value


def export_csv(report: Report) -> bytes:
    metadata = {
        "report_generated_at_utc": report.generated_at, "range_start_utc": report.start.isoformat(),
        "range_end_utc": report.end.isoformat(), "data_source": report.source, "truncated": report.truncated,
    }
    columns = list(dict.fromkeys(("record_type", *metadata, *STAT_FIELDS, *CYCLE_FIELDS,
                                  *PROBE_FIELDS, *FINDING_FIELDS)))
    rows = [
        {**metadata, "record_type": kind, **row}
        for kind, table in (("summary", report.statistics), ("cycle", report.cycles),
                            ("probe", report.probes), ("finding", report.findings))
        for row in table.to_dict("records")
    ]
    cells = [{key: _csv_value(value) for key, value in row.items()} for row in rows]
    return pd.DataFrame(cells, columns=columns, dtype=object).to_csv(
        index=False, lineterminator="\r\n",
    ).encode("utf-8-sig")


def _html_table(frame: pd.DataFrame) -> str:
    if frame.empty:
        return "<p>No records in this section.</p>"
    abbreviations = {"id": "ID", "ip": "IP", "rtt": "RTT", "dns": "DNS", "tcp": "TCP",
                     "utc": "UTC", "mbps": "Mbps"}
    labels = {column: " ".join(abbreviations.get(word, word) for word in column.split("_"))
              for column in frame.columns}
    labels = {column: label[0].upper() + label[1:] for column, label in labels.items()}
    return frame.where(frame.notna(), "—").rename(columns=labels).to_html(
        index=False, escape=True, border=0, float_format=lambda value: f"{value:.3f}",
    )


def export_html(report: Report) -> bytes:
    # Smaller, repeated-header tables keep the report readable in landscape print.
    cycle_metrics = ("cycle_id", "measured_at_utc", "interface", "upload_mbps", "download_mbps",
                     "health_score", "health_category", "diagnostic_status")
    probe_timing = ("cycle_id", "protocol", "target", "port", "probe_status", "latency_ms",
                    "packet_loss_percent", "jitter_ms", "dns_response_ms", "tcp_connect_ms")
    note = (
        f"<p>The range contains more than {REPORT_LIMIT} cycles. This report uses the latest "
        f"{REPORT_LIMIT} cycles.</p>" if report.truncated else ""
    )
    sections = (
        ("Summary statistics", report.statistics),
        ("Diagnostic findings", report.findings),
        ("Recorded cycles", report.cycles[list(cycle_metrics)]),
        ("Additional measurements", report.cycles[["cycle_id", *EXTENDED_FIELDS, "http_target"]]),
        ("Interface details", report.cycles[["cycle_id", "interface", "interface_state",
                                            "local_addresses", "gateway", "total_sent_bytes",
                                            "total_received_bytes", "diagnostic_summary"]]),
        ("Test targets and measurements", report.probes[list(probe_timing)]),
        ("Probe details", report.probes[["cycle_id", "protocol", "target", "port", "min_rtt_ms",
                                         "max_rtt_ms", "sent_probes", "received_probes",
                                         "addresses", "probe_detail"]]),
    )
    body = "".join(f"<section><h2>{title}</h2>{_html_table(table)}</section>" for title, table in sections)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetPulse network diagnostic report</title>
<style>
  body {{ font: 15px/1.5 system-ui, sans-serif; color: #182437; margin: 2rem auto; max-width: 75rem; padding: 0 1rem; }}
  header {{ border-bottom: 3px solid #11958a; margin-bottom: 1.5rem; }}
  h1 {{ margin: 0 0 .35rem; font-size: 2rem; }}
  h2 {{ margin-top: 1.75rem; break-after: avoid; }}
  section {{ overflow-x: auto; }}
  table {{ border-collapse: collapse; text-align: left; width: 100%; font-size: .9em; }}
  th, td {{ border-bottom: 1px solid #d3dfeb; padding: .45em .55em; vertical-align: top; overflow-wrap: anywhere; }}
  th {{ background: #ebf4f8; text-align: left; }}
  .source {{ color: #11675f; font-weight: 700; }}
  @page {{ size: landscape; margin: 12mm; }}
  @media print {{
    body {{ margin: 0; padding: 0; font-size: 10pt; max-width: none; }}
    section {{ overflow: visible; }}
    thead {{ display: table-header-group; }}
    tr {{ break-inside: avoid; }}
    table {{ table-layout: fixed; }}
    .screen-only {{ display: none; }}
  }}
</style>
</head>
<body>
<header><h1>NetPulse network diagnostic report</h1>
<p class="source">{escape(report.source)}</p>
<p>Generated {escape(report.generated_at)} · UTC date range {report.start} through {report.end}</p>
<p>{len(report.cycles)} cycles · {len(report.probes)} probes · {len(report.findings)} findings</p>
{note}
</header>
<p>Missing measurements are shown as dashes. Local traffic reflects interface activity.
The health score is a diagnostic heuristic. Findings describe measured symptoms and possible causes.</p>
<p class="screen-only">Use your browser’s Print command to save as a PDF.</p>
{body}
</body>
</html>
""".encode("utf-8")
