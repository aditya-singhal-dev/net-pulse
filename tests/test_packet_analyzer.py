from unittest.mock import Mock

import pytest

from core import packet_analyzer as packets


def test_rejects_unsupported_and_oversized_files(monkeypatch):
    with pytest.raises(ValueError, match="uncompressed"):
        packets.inspect_pcap(b"\x1f\x8b\x08\x00")
    monkeypatch.setattr(packets, "MAX_FILE_BYTES", 4)
    with pytest.raises(ValueError, match="16 MiB"):
        packets.inspect_pcap(b"12345")


def test_live_capture_requires_authorization_and_valid_local_selection(monkeypatch):
    interfaces = Mock(return_value=("lo0",))
    monkeypatch.setattr(packets, "local_interfaces", interfaces)
    with pytest.raises(ValueError, match="authorized"):
        packets.capture_local("lo0", 1, authorized=False)
    interfaces.assert_not_called()
    with pytest.raises(ValueError, match="active local"):
        packets.capture_local("unknown", 1, authorized=True)
    with pytest.raises(ValueError, match="duration"):
        packets.capture_local("lo0", 11, authorized=True)


@pytest.mark.parametrize("file_type", ["pcap", "pcapng"])
def test_import_summarizes_addresses_without_retaining_payload(tmp_path, file_type):
    scapy = pytest.importorskip("scapy.all")
    ip = scapy.IP(src="192.0.2.1", dst="192.0.2.2")
    ipv6 = scapy.IPv6(src="2001:db8::1", dst="2001:db8::2")
    ethernet = scapy.Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    frames = [
        ethernet / ip / scapy.TCP() / b"fixture payload",
        ethernet / ip / scapy.UDP(),
        ethernet / ip / scapy.ICMP(type=3, code=3) / ip / scapy.UDP(),
        ethernet / ipv6 / scapy.IPv6ExtHdrHopByHop() / scapy.UDP(),
        ethernet / ipv6 / scapy.ICMPv6EchoRequest(),
    ]
    path = tmp_path / f"sample.{file_type}"
    writer = scapy.wrpcap if file_type == "pcap" else scapy.wrpcapng
    writer(str(path), frames)
    summary = packets.inspect_pcap(path.read_bytes())
    assert summary.total == 5
    assert summary.protocols == {"TCP": 1, "UDP": 2, "ICMP": 1, "ICMPv6": 1}
    assert packets.PacketFlow("TCP", "192.0.2.1", "192.0.2.2", 1) in summary.flows
    assert packets.PacketFlow("UDP", "2001:db8::1", "2001:db8::2", 1) in summary.flows
    assert "fixture payload" not in repr(summary)
    assert not summary.limit_reached


def test_import_stops_at_packet_limit(tmp_path, monkeypatch):
    scapy = pytest.importorskip("scapy.all")
    monkeypatch.setattr(packets, "MAX_IMPORT_PACKETS", 1)
    path = tmp_path / "sample.pcap"
    scapy.wrpcap(str(path), [scapy.IP() / scapy.TCP(), scapy.IP() / scapy.UDP()])
    summary = packets.inspect_pcap(path.read_bytes())
    assert summary.total == 1
    assert summary.limit_reached


def test_live_uses_per_family_ip_header_lengths(monkeypatch):
    scapy = pytest.importorskip("scapy.all")
    monkeypatch.setattr(packets, "local_interfaces", lambda: ("en0",))
    monkeypatch.setattr(scapy.conf, "use_pcap", True)
    from scapy.arch import libpcap
    from scapy.libs import winpcapy

    lookup_handle, ipv4_handle, ipv6_handle = [Mock() for _ in range(3)]
    for handle in (lookup_handle, ipv4_handle, ipv6_handle):
        handle.datalink.return_value = 1
    handles = Mock(side_effect=[lookup_handle, ipv4_handle, ipv6_handle])
    monkeypatch.setattr(libpcap, "open_pcap", handles)
    monkeypatch.setattr(winpcapy, "pcap_getnonblock", lambda *_: 1)
    ethernet = scapy.Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    ipv4_handle.next.return_value = (1, bytes(ethernet / scapy.IP() / scapy.TCP())[:34])
    ipv6_handle.next.return_value = (1, bytes(ethernet / scapy.IPv6() / scapy.UDP())[:54])
    monkeypatch.setattr(packets, "MAX_LIVE_PACKETS", 2)
    summary = packets.capture_local("en0", 1, authorized=True)
    assert summary.protocols == {"TCP": 1, "UDP": 1}
    assert [call.kwargs["snaplen"] for call in handles.call_args_list] == [1, 34, 54]
    assert all(not call.kwargs["promisc"] for call in handles.call_args_list)
    ipv4_handle.setfilter.assert_called_once_with("ip")
    ipv6_handle.setfilter.assert_called_once_with("ip6")
    for handle in (lookup_handle, ipv4_handle, ipv6_handle):
        handle.close.assert_called_once()
