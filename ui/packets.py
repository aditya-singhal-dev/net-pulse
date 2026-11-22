"""Optional metadata-only live capture and offline capture import."""

from importlib.util import find_spec

import plotly.graph_objects as go
import streamlit as st

from core.packet_analyzer import (
    MAX_CAPTURE_SECONDS,
    MAX_FILE_BYTES,
    MAX_FLOWS,
    MAX_IMPORT_PACKETS,
    MAX_LIVE_PACKETS,
    PacketSummary,
    capture_local,
    inspect_pcap,
    local_interfaces,
)
from ui.on_demand import is_running, result, submit


def _show_summary(summary: PacketSummary, limit: int) -> None:
    if summary.limit_reached:
        st.info(f"Analysis reached the {limit:,}-packet limit.")
    if not summary.total:
        st.info("No packets were available in this capture window or file.")
        return
    packets, flows = st.columns(2)
    packets.metric("Packets analyzed", f"{summary.total:,}", border=True)
    flows.metric("IP address pairs by protocol", f"{summary.unique_flows:,}", border=True)

    st.subheader("Protocol distribution")
    figure = go.Figure(go.Bar(
        x=list(summary.protocols), y=list(summary.protocols.values()), marker_color="#55dacf",
        hovertemplate="%{x}<br>%{y} packets<extra></extra>",
    ))
    figure.update_layout(height=240, margin=dict(l=14, r=12, t=12, b=45),
                         yaxis=dict(title="Packets", automargin=True))
    st.plotly_chart(figure, width="stretch", config={"displayModeBar": False})
    if summary.flows:
        st.subheader("Source and destination addresses")
        if summary.unique_flows > MAX_FLOWS:
            st.caption(f"Showing the {MAX_FLOWS} busiest address pairs by protocol.")
        st.dataframe([{
            "Protocol": flow.protocol, "Source IP": flow.source,
            "Destination IP": flow.destination, "Packets": flow.count,
        } for flow in summary.flows], hide_index=True, width="stretch")


def render_packets() -> None:
    st.title("Packet analysis")
    if find_spec("scapy") is None:
        st.info("Packet analysis is optional. Install Scapy in the NetPulse virtual environment to use it.")
        st.code("python -m pip install -r requirements-packets.txt", language="sh")
        return
    mode = st.radio("Packet source", ["Import PCAP", "Live capture"], horizontal=True)
    if mode == "Import PCAP":
        st.caption("Analyze an uncompressed PCAP or PCAPNG file up to 16 MiB without administrator access.")
        uploaded = st.file_uploader("Capture file", type=["pcap", "pcapng"])
        if st.button("Analyze capture", type="primary", disabled=uploaded is None or is_running("pcap")):
            if uploaded.size > MAX_FILE_BYTES:
                st.error("Capture files must be 16 MiB or smaller.")
            else:
                submit("pcap", inspect_pcap, uploaded.getvalue())
        summary = result("pcap")
        if summary is not None:
            _show_summary(summary, MAX_IMPORT_PACKETS)
        return

    st.warning("Capture only on an interface you are authorized to monitor. "
               "macOS may require administrator-granted capture permissions.")
    st.caption("Live capture reads base IP headers on supported local interfaces. "
               "Only counts and addresses are shown.")
    interfaces = local_interfaces()
    if not interfaces:
        st.info("No active local interfaces are available.")
        return
    with st.form("live_packet_capture"):
        interface = st.selectbox("Active local interface", interfaces, index=None)
        seconds = st.slider("Capture duration (seconds)", 1, MAX_CAPTURE_SECONDS, 5)
        authorized = st.checkbox("I am authorized to capture on this interface.")
        submitted = st.form_submit_button(
            "Capture packet headers", type="primary", disabled=is_running("capture"),
        )
    if submitted:
        if interface is None or not authorized:
            st.error("Select a local interface and confirm you are authorized to capture on it.")
        else:
            submit("capture", capture_local, interface, seconds, authorized=authorized)
    summary = result("capture")
    if summary is not None:
        _show_summary(summary, MAX_LIVE_PACKETS)
