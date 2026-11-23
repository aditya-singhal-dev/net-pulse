"""Render the latest recorded cycle and run a diagnostic on demand."""

import json
import sqlite3
from datetime import datetime
from statistics import mean

import plotly.graph_objects as go
import streamlit as st

from config.settings import Settings
from core.extra_metrics import HTTP_URL
from core.health_score import score_category
from core.monitoring_service import MonitoringService, MonitorStatus
from ui.monitoring import show_status

STATUS = {
    "ok": "Succeeded", "partial_loss": "Partial loss", "no_reply": "No reply",
    "timeout": "Timed out", "error": "Probe error", "nxdomain": "Domain not found",
    "no_answer": "No address answer", "refused": "Refused",
    "dns_failure": "DNS lookup failed", "unreachable": "Unreachable",
}

STYLE = """
<style>
.stMainBlockContainer { max-width: 1340px; padding-top: 2.5rem; }
.stAppDeployButton { display: none; }
[data-testid="stSidebar"] { border-right: 1px solid #223249; }
[data-testid="stSidebar"] [data-testid="stSidebarContent"] { padding-top: 0.7rem; }
[data-testid="stMetric"] {
    background: #121e2d;
    border-color: #26364c;
    border-radius: 0.75rem;
    min-height: 5.3rem;
}
[data-testid="stMetricLabel"] p { color: #b5c4d8; font-weight: 600; }
[data-testid="stMetricValue"] { font-size: clamp(1.15rem, 2.4vw, 1.9rem); }
.np-brand { color: #75e4dc; font-weight: 750; font-size: 1.3rem; letter-spacing: -0.03em; }
.np-status {
    display: inline-block; padding: .25rem .65rem; border-radius: 1rem;
    font-size: .78rem; font-weight: 700; margin-bottom: .35rem;
}
.np-ok { color: #91f1d5; background: #153c37; }
.np-warn { color: #ffcf87; background: #3c3023; }
.np-unknown { color: #c4d1e4; background: #253349; }
@media (max-width: 960px) {
    :is(.st-key-overview_metrics, .st-key-additional_metrics) [data-testid="stHorizontalBlock"] {
        display: grid; grid-template-columns: repeat(3, minmax(0, 1fr));
    }
    .st-key-performance [data-testid="stHorizontalBlock"] {
        display: grid; grid-template-columns: minmax(0, 1fr);
    }
    :is(.st-key-overview_metrics, .st-key-additional_metrics) [data-testid="stColumn"],
    .st-key-performance [data-testid="stColumn"] { width: 100%; min-width: 0; }
}
@media (max-width: 540px) {
    :is(.st-key-overview_metrics, .st-key-additional_metrics) [data-testid="stHorizontalBlock"] {
        grid-template-columns: repeat(2, minmax(0, 1fr));
    }
}
</style>
"""


def _format(value: float | None, unit: str) -> str:
    return "—" if value is None else f"{value:.1f} {unit}"


def _average(rows: list[sqlite3.Row], key: str) -> float | None:
    values = [row[key] for row in rows if row[key] is not None]
    return mean(values) if values else None


def _connection(cycle: sqlite3.Row | None, probes: list[sqlite3.Row]) -> tuple[str, str]:
    if cycle is None:
        return "Awaiting measurements", "unknown"
    if cycle["interface_up"] == 0:
        return "Interface down", "warn"
    if any(row["protocol"] == "tcp" and row["status"] == "ok" for row in probes):
        return "TCP reachable", "ok"
    if any((row["protocol"] == "icmp" and row["status"] in {"ok", "partial_loss"})
           or (row["protocol"] == "dns" and row["status"] == "ok") for row in probes):
        return "Partial reachability", "warn"
    return "Connectivity inconclusive", "unknown"


def _target(row: sqlite3.Row) -> str:
    if row["port"] is None:
        return row["target"]
    host = row["target"]
    return f"[{host}]:{row['port']}" if ":" in host else f"{host}:{row['port']}"


def _sidebar(cycle: sqlite3.Row | None) -> None:
    with st.sidebar:
        st.divider()
        if cycle is not None:
            st.markdown("**On this page**")
            st.markdown("[Probe performance](#probe-performance)")
            st.markdown("[Probe details](#probe-details)")
            st.markdown("[Diagnostic findings](#diagnostic-findings)")
            st.divider()
        st.markdown("**Network interface**")
        if cycle is None:
            st.caption("Interface details appear after a diagnostic run.")
            return
        state = {1: "Up", 0: "Down"}.get(cycle["interface_up"], "Unknown")
        st.text(f"{cycle['interface'] or 'Unavailable'} · {state}")
        st.caption("Local IP addresses")
        addresses = json.loads(cycle["addresses"])
        for address in addresses or ["Unavailable"]:
            st.text(address)
        st.caption("Default gateway")
        st.text(cycle["gateway"] or "Unavailable")


def _metrics(cycle: sqlite3.Row, probes: list[sqlite3.Row]) -> None:
    score = cycle["health_score"]
    labels = [
        ("Health score", f"{score} / 100" if score is not None else "—",
         "Project-defined heuristic from ping, DNS and TCP evidence."),
        ("Latency", _format(_average(probes, "latency_ms"), "ms"),
         "Mean of the available per-target ICMP round-trip averages."),
        ("ICMP loss", _format(_average(probes, "packet_loss_percent"), "%"),
         "Mean loss across measured targets. ICMP filtering can affect this result."),
        ("DNS lookup", _format(_average(probes, "dns_response_ms"), "ms"),
         "Mean duration of successful DNS lookups."),
        ("TCP connect", _format(_average(probes, "tcp_connect_ms"), "ms"),
         "Mean successful TCP handshake time, excluding DNS, TLS and HTTP."),
    ]
    with st.container(key="overview_metrics"):
        for column, (label, value, help_text) in zip(st.columns(len(labels)), labels):
            column.metric(label, value, help=help_text, border=True)
    coverage = ""
    if cycle["health"] is not None:
        measured = json.loads(cycle["health"])["measured_weight"]
        coverage = f" · {measured}% of score weight measured"
    st.caption(f"Health rating · {score_category(score)}{coverage}")

    upload, download = st.columns(2)
    upload.metric("Local upload", _format(cycle["upload_mbps"], "Mbps"), border=True)
    download.metric("Local download", _format(cycle["download_mbps"], "Mbps"), border=True)
    st.caption("Local interface traffic during the sample window. ISP line capacity is a separate measurement.")
    if cycle["cycle_id"] is not None:
        st.subheader("Additional measurements")
        metrics = (
            ("Link capacity", "link_capacity_mbps", "Mbps", "Reported link rate for the active local interface."),
            ("HTTP response", "http_response_ms", "ms", f"Time to first byte after connection setup for a HEAD request to {HTTP_URL}."),
            ("TCP retransmissions", "tcp_retransmission_percent", "%", "System-wide retransmitted TCP data packets as a share of all TCP packets sent during the cycle."),
            ("Wi-Fi RSSI", "wifi_rssi_dbm", "dBm", "Signal strength for the active Wi-Fi interface. Closer to zero is stronger."),
            ("DNS failures", "dns_failure_percent", "%", "Share of DNS probes that did not resolve successfully."),
        )
        with st.container(key="additional_metrics"):
            for column, (label, key, unit, explanation) in zip(st.columns(len(metrics)), metrics):
                column.metric(label, _format(cycle[key], unit), help=explanation, border=True)
        if cycle["http_status"] is not None:
            st.caption(f"HTTP probe · {HTTP_URL} · status {cycle['http_status']}")



def _timing_chart(rows: list[sqlite3.Row], protocol: str | None = None) -> None:
    palette = {
        "icmp": ("latency_ms", "ICMP RTT", "#55dacf"),
        "dns": ("dns_response_ms", "DNS lookup", "#61a8fa"),
        "tcp": ("tcp_connect_ms", "TCP connect", "#55dacf"),
    }
    figure = go.Figure()
    targets = []
    for kind, (key, label, color) in palette.items():
        if (protocol is None and kind == "icmp") or (protocol is not None and kind != protocol):
            continue
        measured = [(f"{_target(row)} · {kind.upper()}", row[key])
                    for row in rows if row["protocol"] == kind and row[key] is not None]
        if not measured:
            continue
        names, values = zip(*measured)
        targets.extend(names)
        figure.add_bar(
            x=values, y=names, name=label, orientation="h", marker_color=color,
            hovertemplate="%{y}<br>%{x:.1f} ms<extra></extra>",
        )
    if not targets:
        st.info("No timing measurements available for these probes.")
        return
    figure.update_layout(
        height=max(270, 120 + 30 * len(targets)), margin=dict(l=6, r=16, t=12, b=52),
        paper_bgcolor="#121e2d", plot_bgcolor="#121e2d",
        font=dict(color="#d7e4f6"),
        xaxis=dict(title="Milliseconds", gridcolor="#2a3b52", zerolinecolor="#2a3b52"),
        yaxis=dict(autorange="reversed", automargin=True),
        showlegend=False,
    )
    st.plotly_chart(figure, theme=None, width="stretch", config={"displayModeBar": False})


def _probe_details(probes: list[sqlite3.Row]) -> None:
    st.header("Probe details", anchor="probe-details")
    for tab, protocol in zip(st.tabs(["ICMP", "DNS", "TCP"]), ["icmp", "dns", "tcp"]):
        with tab:
            results = []
            for row in probes:
                if row["protocol"] != protocol:
                    continue
                details = json.loads(row["details"])
                item = {"Target": _target(row), "Status": STATUS.get(row["status"], row["status"])}
                if protocol == "icmp":
                    item.update({
                        "Average": _format(row["latency_ms"], "ms"),
                        "Min": _format(details.get("min_ms"), "ms"),
                        "Max": _format(details.get("max_ms"), "ms"),
                        "Loss": _format(row["packet_loss_percent"], "%"),
                        "Jitter": _format(row["jitter_ms"], "ms"),
                    })
                elif protocol == "dns":
                    item.update({"Lookup": _format(row["dns_response_ms"], "ms"),
                                 "Addresses": ", ".join(details.get("addresses", ())) or "—"})
                else:
                    item.update({"Handshake": _format(row["tcp_connect_ms"], "ms"),
                                 "Connected IP": details.get("address") or "—"})
                item["Detail"] = details.get("detail") or "—"
                results.append(item)
            if results:
                st.dataframe(results, hide_index=True, width="stretch")
            else:
                st.caption(f"No {protocol.upper()} probes recorded.")


def show_findings(cycle: sqlite3.Row) -> None:
    st.header("Diagnostic findings", anchor="diagnostic-findings")
    if cycle["diagnosis"] is None:
        status = cycle["diagnostic_status"].replace("_", " ").capitalize()
        st.info(f"Saved status: {status}. Run diagnostics to record a full assessment.")
        return
    diagnosis = json.loads(cycle["diagnosis"])
    if diagnosis["status"] == "no_issues_detected":
        st.success(diagnosis["summary"])
    elif diagnosis["status"] == "inconclusive":
        st.info(diagnosis["summary"])
    else:
        st.warning(diagnosis["summary"])
    for finding in diagnosis["findings"]:
        with st.expander(f"{finding['severity']} · {finding['title']}"):
            for title, key in (("Evidence", "evidence"), ("Possible causes", "possible_causes"),
                               ("Recommended actions", "recommended_actions")):
                st.markdown(f"**{title}**")
                for item in finding[key]:
                    st.text(item)


def render_dashboard(
    monitor: MonitoringService, worker_status: MonitorStatus, settings: Settings, *, demo: bool = False,
) -> None:
    database = monitor.database
    title, action = st.columns([3, 1], vertical_alignment="center")
    title.title("Network overview", anchor="network-overview")
    if action.button(
        "Run diagnostics", type="primary", width="stretch", disabled=demo or worker_status.state != "idle",
        help="Run one set of ICMP, DNS and TCP checks and save the results.",
    ):
        monitor.run_once(settings)
        st.rerun()
    if worker_status.state != "idle" or worker_status.error is not None:
        show_status(worker_status)
    try:
        cycle = database.latest()
        probes = database.probes(cycle["id"]) if cycle is not None else []
    except (OSError, sqlite3.Error) as exc:
        _sidebar(None)
        st.error("NetPulse could not load or save the diagnostic cycle.")
        st.caption(str(exc))
        return

    _sidebar(cycle)
    status, color = _connection(cycle, probes)
    st.html(f'<div class="np-status np-{color}" role="status">{status}</div>')
    if cycle is None:
        st.info("No measurements available — start monitoring.")
        st.caption("Run diagnostics to collect the first measurement.")
        return

    timestamp = datetime.fromisoformat(cycle["timestamp"]).astimezone()
    st.caption(f"Measured {timestamp:%d %b %Y · %H:%M:%S %Z}")
    _metrics(cycle, probes)
    st.divider()
    st.header("Probe performance", anchor="probe-performance")
    with st.container(key="performance"):
        icmp, services = st.columns(2)
        with icmp.container(border=True):
            st.subheader("ICMP round-trip time")
            _timing_chart(probes, "icmp")
        with services.container(border=True):
            st.subheader("DNS and TCP timings")
            _timing_chart(probes)
    _probe_details(probes)
    show_findings(cycle)
