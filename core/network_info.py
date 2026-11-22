"""Discover the default route and local interface addresses on macOS."""

import socket
import subprocess
from dataclasses import dataclass

import psutil

ADDRESS_FAMILIES = (socket.AF_INET, socket.AF_INET6)


@dataclass(frozen=True)
class NetworkInfo:
    interface: str | None
    gateway: str | None
    addresses: tuple[str, ...]
    interface_up: bool | None


def get_network_info() -> NetworkInfo:
    for family in ("-inet", "-inet6"):
        try:
            route = subprocess.run(
                ["/sbin/route", "-n", "get", family, "default"],
                capture_output=True, text=True, timeout=2, shell=False, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if route.returncode:
            continue
        fields = dict(line.strip().split(":", 1) for line in route.stdout.splitlines()
                      if ":" in line)
        interface = fields.get("interface", "").strip()
        if interface:
            addresses = tuple(
                entry.address for entry in psutil.net_if_addrs().get(interface, [])
                if entry.family in ADDRESS_FAMILIES
            )
            stats = psutil.net_if_stats().get(interface)
            return NetworkInfo(interface, fields.get("gateway", "").strip() or None,
                               addresses, stats.isup if stats else None)
    return NetworkInfo(None, None, (), None)
