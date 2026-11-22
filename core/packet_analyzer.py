"""Summarize authorized capture data without retaining individual frames."""

from collections import Counter
from contextlib import ExitStack, closing
from dataclasses import dataclass
from io import BytesIO
from time import monotonic, sleep
from typing import TYPE_CHECKING

import psutil

if TYPE_CHECKING:
    from scapy.packet import Packet

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_IMPORT_PACKETS = 5_000
MAX_LIVE_PACKETS = 500
MAX_CAPTURE_SECONDS = 10
MAX_FLOWS = 100
IMPORT_PREFIX = 256
PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
               b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}
PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
IPV6_EXTENSIONS = {0, 43, 44, 51, 60, 135}

# Ethernet, BSD loopback/null, and raw IP each have a fixed prefix for
# untagged IP. Skip unsupported link types rather than capturing extra bytes.
LINK_PREFIX = {0: 4, 1: 14, 12: 0, 101: 0, 108: 4}


@dataclass(frozen=True)
class PacketFlow:
    protocol: str
    source: str
    destination: str
    count: int


@dataclass(frozen=True)
class PacketSummary:
    total: int
    protocols: dict[str, int]
    flows: tuple[PacketFlow, ...]
    unique_flows: int
    limit_reached: bool


class _Accumulator:
    def __init__(self) -> None:
        self.protocols: Counter[str] = Counter()
        self.flows: Counter[tuple[str, str, str]] = Counter()

    def add(self, packet: "Packet") -> None:
        from scapy.layers.inet import IP
        from scapy.layers.inet6 import IPv6

        layer = packet.firstlayer()
        while not isinstance(layer, (IP, IPv6)) and layer:
            layer = layer.payload

        if isinstance(layer, IP):
            protocol = PROTOCOLS.get(layer.proto, "Other IP")
        elif isinstance(layer, IPv6):
            next_header = layer.nh
            extension = layer.payload
            while next_header in IPV6_EXTENSIONS and hasattr(extension, "nh"):
                next_header = extension.nh
                extension = extension.payload
            protocol = PROTOCOLS.get(next_header, "Other IP")
        else:
            self.protocols["Non-IP or unparsed"] += 1
            return
        self.protocols[protocol] += 1
        self.flows[protocol, layer.src, layer.dst] += 1

    def result(self, limit_reached: bool) -> PacketSummary:
        return PacketSummary(
            sum(self.protocols.values()), dict(self.protocols.most_common()),
            tuple(PacketFlow(*key, count) for key, count in self.flows.most_common(MAX_FLOWS)),
            len(self.flows), limit_reached,
        )


def inspect_pcap(data: bytes) -> PacketSummary:
    if len(data) > MAX_FILE_BYTES:
        raise ValueError("Capture files must be 16 MiB or smaller.")
    if data[:4] not in PCAP_MAGICS:
        raise ValueError("Select an uncompressed PCAP or PCAPNG file.")
    from scapy.all import PcapReader, Scapy_Exception

    accumulator = _Accumulator()
    try:
        with PcapReader(BytesIO(data)) as reader:
            for _ in range(MAX_IMPORT_PACKETS):
                try:
                    packet = reader.read_packet(size=IMPORT_PREFIX)
                except EOFError:
                    return accumulator.result(False)
                accumulator.add(packet)
    except (OSError, ValueError, Scapy_Exception) as exc:
        raise ValueError(f"Could not read the capture file: {exc}") from exc
    return accumulator.result(True)


def local_interfaces() -> tuple[str, ...]:
    return tuple(sorted(name for name, stats in psutil.net_if_stats().items() if stats.isup))


def capture_local(interface: str, seconds: int, *, authorized: bool) -> PacketSummary:
    if not authorized:
        raise ValueError("Confirm you are authorized to capture on the selected interface.")
    if interface not in local_interfaces():
        raise ValueError("Select an active local interface.")
    if not isinstance(seconds, int) or not 1 <= seconds <= MAX_CAPTURE_SECONDS:
        raise ValueError(f"Capture duration must be between 1 and {MAX_CAPTURE_SECONDS} seconds.")

    from scapy.all import conf
    from scapy.libs.winpcapy import pcap_getnonblock

    if not conf.use_pcap:
        conf.use_pcap = True
    if not conf.use_pcap:
        raise OSError("Scapy could not enable macOS libpcap support.")
    from scapy.arch.libpcap import open_pcap

    accumulator = _Accumulator()
    count = 0
    with closing(open_pcap(interface, snaplen=1, promisc=False)) as handle:
        link_type = handle.datalink()
    if link_type not in LINK_PREFIX or (decoder := conf.l2types.get(link_type)) is None:
        raise ValueError("This interface does not expose a supported fixed IP header format.")
    with ExitStack() as stack:
        handles = []
        for family, length in (("ip", 20), ("ip6", 40)):
            handle = stack.enter_context(closing(open_pcap(
                interface, snaplen=LINK_PREFIX[link_type] + length, promisc=False, to_ms=50,
            )))
            if handle.datalink() != link_type:
                raise OSError("The interface changed link type during capture setup.")
            handle.setfilter(family)
            handle.setnonblock(True)
            if pcap_getnonblock(handle.pcap, handle.errbuf) != 1:
                raise OSError("Could not open a nonblocking capture.")
            handles.append(handle)
        deadline = monotonic() + seconds
        while monotonic() < deadline and count < MAX_LIVE_PACKETS:
            received = False
            for handle in handles:
                _, frame = handle.next()
                if frame:
                    accumulator.add(decoder(frame))
                    count += 1
                    received = True
                    if count >= MAX_LIVE_PACKETS:
                        break
            if not received:
                sleep(0.02)
    return accumulator.result(count == MAX_LIVE_PACKETS)
