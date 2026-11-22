"""Generate downloadable reports from a selected UTC date range."""

import sqlite3
from datetime import date, datetime, timedelta, timezone

import streamlit as st

from database.db import Database
from utils.report_generator import export_csv, export_html, load_report


def render_reports(database: Database, *, demo: bool = False) -> None:
    st.title("Historical reports")
    st.caption("Export stored diagnostic cycles, probe results, and troubleshooting findings.")
    try:
        latest = database.latest()
    except sqlite3.Error as exc:
        st.error(f"Could not open report history. {exc}")
        return
    if latest is None:
        st.info("No saved measurements. Run diagnostics from Overview to create the first report.")
        return
    latest_day = date.fromisoformat(latest["timestamp"][:10])
    latest_allowed = max(latest_day, datetime.now(timezone.utc).date())
    with st.form("report_range"):
        first, last = st.columns(2)
        start = first.date_input(
            "Start date (UTC)", latest_day - timedelta(days=6), max_value=latest_allowed,
        )
        end = last.date_input("End date (UTC)", latest_day, max_value=latest_allowed)
        generate = st.form_submit_button("Generate report", type="primary")
    if generate:
        st.session_state.pop("generated_report", None)
        try:
            report = load_report(database, start, end, demo=demo)
            if report.cycles.empty:
                st.info("No recorded cycles fall in that date range.")
                return
            st.session_state.generated_report = (
                report, export_csv(report), export_html(report),
            )
        except (OSError, sqlite3.Error, ValueError) as exc:
            st.error(f"Could not generate the report. {exc}")
            return
    generated = st.session_state.get("generated_report")
    if generated is None:
        return
    report, csv_data, html_data = generated
    st.subheader(f"{report.start:%d %b %Y} – {report.end:%d %b %Y} UTC")
    a, b, c = st.columns(3)
    a.metric("Diagnostic cycles", len(report.cycles), border=True)
    b.metric("Probe results", len(report.probes), border=True)
    c.metric("Findings", len(report.findings), border=True)
    if report.truncated:
        st.warning(f"This export includes the latest {len(report.cycles):,} cycles in the selected range.")
    st.dataframe(
        report.statistics.rename(columns={
            "metric": "Metric", "unit": "Unit", "sample_count": "Samples",
            "minimum": "Minimum", "mean": "Mean", "maximum": "Maximum",
        }), hide_index=True, width="stretch",
    )
    prefix = "netpulse-demo" if demo else "netpulse"
    filename = f"{prefix}-{report.start}-to-{report.end}"
    csv_column, html_column = st.columns(2)
    csv_column.download_button("Download CSV", csv_data, filename + ".csv", "text/csv",
                               width="stretch", on_click="ignore")
    html_column.download_button("Download HTML", html_data, filename + ".html", "text/html",
                                width="stretch", on_click="ignore")
    st.caption("Open the HTML report in a browser and choose Print → Save as PDF.")
