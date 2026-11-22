"""Streamlit controls and charts for persisted live monitoring samples."""

import sqlite3
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import plotly.graph_objects as go
import streamlit as st
from pandas import to_datetime

from config.settings import INTERVALS, Settings
from core.monitoring_service import MonitoringService, MonitorStatus

WINDOWS = {
    "Last 15 minutes": timedelta(minutes=15),
    "Last hour": timedelta(hours=1),
    "Last 6 hours": timedelta(hours=6),
    "Last 24 hours": timedelta(days=1),
}
SAMPLE_LIMIT = 2000


@st.fragment(run_every=2)
def watch_monitor(service: MonitoringService, previous: MonitorStatus) -> None:
    """Poll shared metadata and refresh the page only when it changes."""
    if service.snapshot() != previous:
        st.rerun()


def show_status(status: MonitorStatus) -> None:
    if status.state == "monitoring":
        st.success(f"Monitoring · requested interval {status.interval} seconds")
    elif status.state == "measuring":
        st.info("Running a one-time diagnostic.")
    elif status.state == "stopping":
        st.info("Stopping after the current diagnostic finishes.")
    else:
        st.caption("Monitoring stopped.")
    if status.error is not None:
        st.error(f"A diagnostic cycle failed. {status.error}")


def _chart(
    rows: list[sqlite3.Row],
    timestamps: list[datetime],
    title: str,
    unit: str,
    series: tuple[tuple[str, str], ...],
    window: str,
    value_range: tuple[int, int] | None = None,
) -> None:
    with st.container(border=True):
        st.subheader(title)
        figure = go.Figure()
        for (key, label), color in zip(series, ("#55dacf", "#61a8fa")):
            values = [row[key] for row in rows]
            if not any(value is not None for value in values):
                continue
            figure.add_scatter(
                x=timestamps, y=values, name=label, mode="lines+markers", connectgaps=False,
                line=dict(color=color, width=2), marker=dict(size=4),
                hovertemplate=f"%{{x|%d %b %H:%M:%S}} UTC<br>%{{y:.2f}} {unit}<extra>{label}</extra>",
            )
        if not figure.data:
            st.caption("No usable measurements for this metric in the selected range.")
            return
        figure.update_layout(
            uirevision=window, height=230, margin=dict(l=12, r=18, t=10, b=50),
            plot_bgcolor="#121e2d", paper_bgcolor="#121e2d", font=dict(color="#d7e4f6"),
            xaxis=dict(title="Time (UTC)", gridcolor="#2a3b52", automargin=True),
            yaxis=dict(title=unit, range=value_range, gridcolor="#2a3b52", automargin=True),
            legend=dict(orientation="h"), showlegend=len(series) > 1,
        )
        st.plotly_chart(figure, key=f"history_{title}", theme=None, width="stretch",
                        config={"displayModeBar": False})


def render_monitoring(
    service: MonitoringService, status: MonitorStatus, settings: Settings, *, demo: bool = False,
) -> None:
    st.title("Live monitoring")
    interval_column, start_column, stop_column = st.columns([2, 1, 1], vertical_alignment="bottom")
    interval = interval_column.selectbox(
        "Measurement interval", INTERVALS, index=INTERVALS.index(settings.interval),
        format_func=lambda seconds: f"{seconds} seconds", disabled=demo or status.state != "idle",
        help="A cycle starts when the interval has elapsed and the previous cycle has finished.",
    )
    if start_column.button("Start monitoring", type="primary", width="stretch",
                           disabled=demo or status.state != "idle"):
        service.start(replace(settings, interval=interval))
        st.rerun()
    if stop_column.button("Stop monitoring", width="stretch",
                          disabled=demo or status.state != "monitoring"):
        service.stop()
        st.rerun()
    if demo:
        st.caption("The offline demo uses saved sample cycles.")
    else:
        show_status(status)

    st.divider()
    st.header("Measurement history")
    window = st.selectbox("Time range", list(WINDOWS), index=1, width=280)
    end = datetime.now(timezone.utc)
    try:
        rows = service.database.time_series(
            (end - WINDOWS[window]).isoformat(), end.isoformat(), limit=SAMPLE_LIMIT + 1,
        )
    except sqlite3.Error as exc:
        st.error(f"Could not read measurement history. {exc}")
        return
    if not rows:
        st.info("No measurements in this time range.")
        return
    if len(rows) > SAMPLE_LIMIT:
        rows = rows[-SAMPLE_LIMIT:]
        st.caption(f"Showing the latest {SAMPLE_LIMIT:,} cycles in this range.")
    else:
        st.caption(f"{len(rows):,} saved {'cycle' if len(rows) == 1 else 'cycles'}")
    timestamps = to_datetime(
        [row["timestamp"] for row in rows], format="ISO8601", utc=True,
    ).to_pydatetime().tolist()
    with st.container(key="performance"):
        latency, loss = st.columns(2)
        with latency:
            _chart(rows, timestamps, "Latency", "ms", (("latency_ms", "Mean RTT"),), window)
        with loss:
            _chart(rows, timestamps, "ICMP packet loss", "%", (("packet_loss_percent", "Mean loss"),),
                   window, (0, 100))
        traffic, dns = st.columns(2)
        with traffic:
            _chart(rows, timestamps, "Local interface traffic", "Mbps",
                   (("upload_mbps", "Upload"), ("download_mbps", "Download")), window)
        with dns:
            _chart(rows, timestamps, "DNS response time", "ms",
                   (("dns_response_ms", "Mean lookup"),), window)
    _chart(rows, timestamps, "Network health score", "Score", (("health_score", "Health score"),),
           window, (0, 100))
    st.caption("Latency, ICMP loss, and DNS time are means across measured targets in each cycle. "
               "Local traffic is measured at the interface.")
