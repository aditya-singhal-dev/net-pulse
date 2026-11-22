"""Edit persisted dashboard probe settings and diagnosis thresholds."""

import json
import sqlite3
from dataclasses import asdict

import streamlit as st

from config.analysis import parse_thresholds
from config.settings import INTERVALS, Settings, parse_endpoint, validate_host
from database.db import Database


def load_settings(database: Database) -> Settings:
    saved = database.get_dashboard_settings()
    if saved is None:
        return Settings()
    options = json.loads(saved)
    score, diagnosis = parse_thresholds({
        "score": options.pop("score_thresholds"), "diagnosis": options.pop("diagnosis_thresholds"),
    })
    return Settings(
        ping_targets=tuple(options.pop("ping_targets")), dns_domains=tuple(options.pop("dns_domains")),
        tcp_endpoints=tuple(tuple(value) for value in options.pop("tcp_endpoints")),
        score_thresholds=score, diagnosis_thresholds=diagnosis, **options,
    )


def _lines(text: str) -> tuple[str, ...]:
    return tuple(line.strip() for line in text.splitlines() if line.strip())


def render_settings(database: Database, settings: Settings, *, demo: bool = False) -> None:
    st.title("Settings")
    if demo:
        st.info("Settings are read-only in the offline demo.")
        return
    st.caption("Settings apply to the next Overview diagnostic or monitoring start. "
               "A running session keeps the settings it started with.")
    thresholds = {
        "score": asdict(settings.score_thresholds), "diagnosis": asdict(settings.diagnosis_thresholds),
    }
    endpoints = "\n".join(
        f"[{host}]:{port}" if ":" in host else f"{host}:{port}" for host, port in settings.tcp_endpoints
    )
    if st.session_state.pop("settings_saved", False):
        st.success("Dashboard settings saved.")
    with st.form("dashboard_settings"):
        st.subheader("Probe targets")
        st.caption("Enter one to five targets per test, one per line.")
        left, middle, right = st.columns(3)
        ping = left.text_area("ICMP hosts", "\n".join(settings.ping_targets), max_chars=1300)
        dns = middle.text_area("DNS domains", "\n".join(settings.dns_domains), max_chars=1300)
        tcp = right.text_area("TCP endpoints", endpoints, max_chars=1320,
                              help="Use host:port or [IPv6]:port.")
        left, middle, right = st.columns(3)
        count = left.number_input("Pings per host", 1, 5, settings.ping_count)
        timeout = middle.number_input("Probe timeout (seconds)", 0.5, 5.0, settings.timeout, step=0.5)
        interval = right.selectbox("Default interval", INTERVALS, index=INTERVALS.index(settings.interval),
                                   format_func=lambda value: f"{value} seconds")
        with st.expander("Scoring and diagnosis thresholds"):
            text = st.text_area("Thresholds (JSON)", json.dumps(thresholds, indent=2),
                                height=250, max_chars=5000)
        save = st.form_submit_button("Save settings", type="primary")
    if save:
        try:
            score, diagnosis = parse_thresholds(json.loads(text))
            proposed = Settings(
                ping_targets=tuple(map(validate_host, _lines(ping))),
                dns_domains=tuple(map(validate_host, _lines(dns))),
                tcp_endpoints=tuple(map(parse_endpoint, _lines(tcp))),
                ping_count=count, timeout=timeout, interval=interval,
                score_thresholds=score, diagnosis_thresholds=diagnosis,
            )
            database.set_dashboard_settings(json.dumps(asdict(proposed)))
        except (OSError, OverflowError, sqlite3.Error, TypeError, ValueError) as exc:
            st.error(f"Could not save the dashboard settings. {exc}")
        else:
            st.session_state.settings_saved = True
            st.rerun()
