"""Streamlit entry point for the NetPulse dashboard."""

import os
import sqlite3
from pathlib import Path
from tempfile import TemporaryDirectory

import streamlit as st

from config.settings import Settings
from core.monitoring_service import MonitoringService
from database.db import Database
from database.demo_data import populate_demo
from ui.dashboard import STYLE, render_dashboard, show_findings
from ui.dns_tcp import render_dns, render_tcp
from ui.monitoring import render_monitoring, watch_monitor
from ui.network_path import render_network_path
from ui.packets import render_packets
from ui.reports import render_reports
from ui.settings import load_settings, render_settings

st.set_page_config(page_title="NetPulse | Network Health", page_icon="📶", layout="wide")


@st.cache_resource
def get_monitor(path: Path) -> MonitoringService:
    """Share one worker slot across sessions in this Streamlit server."""
    database = Database(path)
    database.initialize()
    return MonitoringService(database)


@st.cache_resource
def get_demo_monitor() -> tuple[MonitoringService, TemporaryDirectory]:
    directory = TemporaryDirectory(prefix="netpulse-demo-")
    database = Database(Path(directory.name) / "demo.sqlite3")
    database.initialize()
    populate_demo(database)
    return MonitoringService(database), directory


def main() -> None:
    demo = os.environ.get("NETPULSE_DEMO") == "1"
    tools = {
        "DNS Analysis": render_dns,
        "TCP Connectivity": render_tcp,
        "Network Path": render_network_path,
        "Packet Analysis": render_packets,
    }
    pages = ["Overview", "Live Monitoring", "Diagnostics"]
    if not demo:
        pages.extend(tools)
    pages.extend(["Historical Reports", "Settings"])
    st.html(STYLE)
    with st.sidebar:
        st.html('<div class="np-brand">◉ NetPulse</div>')
        st.caption("Network health monitor")
        st.divider()
        page = st.radio("Navigation", pages, label_visibility="collapsed")
    if demo:
        st.warning("Offline demo · synthetic measurements. Live probes and capture are disabled.")
    elif page in tools:
        tools[page]()
        return

    default_database = Path(__file__).resolve().parent / "data" / "netpulse.sqlite3"
    try:
        if demo:
            monitor, _directory = get_demo_monitor()
        else:
            path = Path(os.environ.get("NETPULSE_DB", default_database)).expanduser().resolve()
            monitor = get_monitor(path)
    except (OSError, sqlite3.Error, ValueError) as exc:
        st.error(f"NetPulse could not open its diagnostic database. {exc}")
        return

    database = monitor.database
    if page == "Historical Reports":
        render_reports(database, demo=demo)
        return

    status = monitor.snapshot()
    if page == "Diagnostics":
        st.title("Network diagnostics")
        try:
            cycle = database.latest()
        except sqlite3.Error as exc:
            st.error(f"Could not read diagnostic findings. {exc}")
        else:
            if cycle is None:
                st.info("No saved diagnostics. Run diagnostics from Overview to collect a measurement.")
            else:
                st.caption(f"Latest cycle · {cycle['timestamp']} UTC")
                show_findings(cycle)
        watch_monitor(monitor, status)
        return

    try:
        settings = load_settings(database)
    except (OSError, KeyError, OverflowError, sqlite3.Error, TypeError, ValueError) as exc:
        st.warning(f"Saved settings could not be loaded. Using defaults. {exc}")
        settings = Settings()
    if page == "Settings":
        render_settings(database, settings, demo=demo)
        return
    if page == "Live Monitoring":
        render_monitoring(monitor, status, settings, demo=demo)
    else:
        render_dashboard(monitor, status, settings, demo=demo)
    watch_monitor(monitor, status)


main()
