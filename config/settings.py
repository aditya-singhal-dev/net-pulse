"""Validated configuration for a bounded diagnostic cycle."""

import ipaddress
import re
from dataclasses import dataclass

from config.analysis import DiagnosisThresholds, ScoreThresholds

INTERVALS = (5, 10, 30, 60)


def validate_host(host: str) -> str:
    if not host or len(host) > 253 or "%" in host:
        raise ValueError("Expected an IP address or a DNS hostname")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        labels = host.removesuffix(".").split(".")
        if not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                   for label in labels):
            raise ValueError("Expected an IP address or a DNS hostname") from None
        return host.lower()


def parse_endpoint(value: str) -> tuple[str, int]:
    host, sep, port = value.rpartition(":")
    if not sep or not re.fullmatch(r"[0-9]{1,5}", port):
        raise ValueError("Expected HOST:PORT or [IPv6]:PORT")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    elif ":" in host:
        raise ValueError("Put IPv6 addresses in brackets")
    return validate_host(host), int(port)


@dataclass(frozen=True)
class Settings:
    ping_targets: tuple[str, ...] = ("1.1.1.1", "8.8.8.8")
    dns_domains: tuple[str, ...] = ("example.com", "cloudflare.com", "google.com")
    tcp_endpoints: tuple[tuple[str, int], ...] = (
        ("example.com", 443), ("cloudflare.com", 443),
    )
    ping_count: int = 3
    timeout: float = 2.0
    interval: int = 10
    score_thresholds: ScoreThresholds = ScoreThresholds()
    diagnosis_thresholds: DiagnosisThresholds = DiagnosisThresholds()

    def __post_init__(self) -> None:
        for targets in (self.ping_targets, self.dns_domains, self.tcp_endpoints):
            if not 1 <= len(targets) <= 5:
                raise ValueError("Provide between one and five targets per test")
        for host in (*self.ping_targets, *self.dns_domains):
            validate_host(host)
        for host, port in self.tcp_endpoints:
            validate_host(host)
            if not 1 <= port <= 65535:
                raise ValueError("TCP ports must be in 1–65535")
        if not 1 <= self.ping_count <= 5 or not 0.5 <= self.timeout <= 5:
            raise ValueError("Use 1–5 ICMP attempts and a timeout of 0.5–5 seconds")
        if self.interval not in INTERVALS:
            raise ValueError(f"Monitoring interval must be one of {INTERVALS}")
