"""Run one bounded traceroute and display the replies that came back."""

import streamlit as st

from config.settings import validate_host
from core.traceroute import MAX_HOPS, trace
from ui.on_demand import is_running, result, submit


def render_network_path() -> None:
    st.title("Network path")
    st.caption("Trace one destination using a single UDP probe per hop.")
    with st.form("traceroute_target"):
        host = st.text_input("Destination host or IP", "1.1.1.1", max_chars=253)
        hops = st.slider("Maximum hops", 1, MAX_HOPS, 12)
        submitted = st.form_submit_button("Run traceroute", type="primary", disabled=is_running("trace"))
    st.caption("Routers can ignore or rate-limit probes. An intermediate timeout does not establish a broken route.")
    if submitted:
        try:
            target = validate_host(host.strip())
        except ValueError as exc:
            st.error(str(exc))
        else:
            submit("trace", trace, target, hops)
    measurement = result("trace")
    if measurement is None:
        return
    st.subheader("Hop results")
    destination = measurement.host
    if measurement.address and measurement.address != measurement.host:
        destination += f" ({measurement.address})"
    st.text(f"Destination: {destination}")
    if measurement.status == "reached":
        st.success("Destination replied.")
    elif measurement.status == "error":
        st.error(measurement.detail)
    else:
        st.warning(measurement.detail)
    if measurement.hops:
        st.dataframe([{
            "Hop": hop.number, "Router IP": hop.address, "RTT (ms)": hop.rtt_ms,
            "Status": hop.status, "Annotation": hop.annotation,
        } for hop in measurement.hops], hide_index=True, width="stretch")
