"""Focused DNS lookup and TCP handshake views."""

from collections.abc import Callable
from ipaddress import ip_address

import plotly.graph_objects as go
import streamlit as st

from config.settings import Settings, parse_endpoint, validate_host
from core.dns_analyzer import DNSResult, lookup
from core.tcp_checker import TCPResult, connect
from ui.dashboard import STATUS
from ui.on_demand import is_running, result, submit


def _targets(text: str, parser: Callable) -> tuple:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not 1 <= len(lines) <= 5:
        raise ValueError("Enter one to five targets, one per line.")
    return tuple(dict.fromkeys(map(parser, lines)))


def _domain(value: str) -> str:
    host = validate_host(value)
    try:
        ip_address(host)
    except ValueError:
        return host
    raise ValueError("Enter a DNS domain name, such as example.com.")


def _query_dns(domains: tuple[str, ...], timeout: float) -> tuple[DNSResult, ...]:
    return tuple(lookup(domain, timeout) for domain in domains)


def _query_tcp(endpoints: tuple[tuple[str, int], ...], timeout: float) -> tuple[TCPResult, ...]:
    return tuple(connect(host, port, timeout) for host, port in endpoints)


def _endpoint_label(endpoint: tuple[str, int]) -> str:
    host, port = endpoint
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _timings(names: list[str], timings: list[float | None], x_label: str) -> None:
    measured = [(name, timing) for name, timing in zip(names, timings) if timing is not None]
    if not measured:
        st.info("There were no successful timings to compare.")
        return
    labels, durations = zip(*measured)
    figure = go.Figure(go.Bar(
        x=durations, y=labels, orientation="h", marker_color="#55dacf",
        hovertemplate="%{y}<br>%{x:.2f} ms<extra></extra>",
    ))
    figure.update_layout(
        height=max(225, 100 + len(labels) * 36), margin=dict(l=12, r=16, t=16, b=55),
        xaxis_title=x_label, yaxis=dict(autorange="reversed", automargin=True),
    )
    st.plotly_chart(figure, width="stretch", config={"displayModeBar": False})


def render_dns() -> None:
    st.title("DNS analysis")
    st.caption("Compare address lookup times through the configured DNS resolver.")
    defaults = Settings()
    with st.form("dns_targets"):
        text = st.text_area("Domains (one per line)", "\n".join(defaults.dns_domains), max_chars=1_300)
        timeout = st.slider("Timeout per domain (seconds)", 0.5, 5.0, defaults.timeout, step=0.5)
        submitted = st.form_submit_button("Test DNS", type="primary", disabled=is_running("dns"))
    if submitted:
        try:
            domains = _targets(text, _domain)
        except ValueError as exc:
            st.error(str(exc))
        else:
            submit("dns", _query_dns, domains, timeout)
    measured = result("dns")
    if measured is None:
        return
    st.subheader("Lookup results")
    st.dataframe([{
        "Domain": item.domain, "Status": STATUS.get(item.status, item.status),
        "Lookup (ms)": item.elapsed_ms,
        "Addresses": ", ".join(item.addresses), "Detail": item.detail,
    } for item in measured], hide_index=True, width="stretch")
    _timings([item.domain for item in measured], [item.elapsed_ms for item in measured], "DNS lookup (ms)")


def render_tcp() -> None:
    st.title("TCP connectivity")
    st.caption("Measure the TCP handshake. Timings exclude DNS, TLS, and HTTP.")
    defaults = Settings()
    with st.form("tcp_targets"):
        text = st.text_area(
            "Endpoints (one host:port per line)", "\n".join(map(_endpoint_label, defaults.tcp_endpoints)),
            max_chars=1_320, help="Use brackets around IPv6 addresses, for example [::1]:443.",
        )
        timeout = st.slider("Timeout per endpoint (seconds)", 0.5, 5.0, defaults.timeout, step=0.5)
        submitted = st.form_submit_button("Test TCP", type="primary", disabled=is_running("tcp"))
    if submitted:
        try:
            endpoints = _targets(text, parse_endpoint)
            Settings(tcp_endpoints=endpoints)
        except ValueError as exc:
            st.error(str(exc))
        else:
            submit("tcp", _query_tcp, endpoints, timeout)
    measured = result("tcp")
    if measured is None:
        return
    labels = [_endpoint_label((item.host, item.port)) for item in measured]
    st.subheader("Connection results")
    st.dataframe([{
        "Endpoint": label, "Status": STATUS.get(item.status, item.status),
        "Handshake (ms)": item.elapsed_ms, "Connected IP": item.address, "Detail": item.detail,
    } for label, item in zip(labels, measured)], hide_index=True, width="stretch")
    _timings(labels, [item.elapsed_ms for item in measured], "TCP handshake (ms)")
