"""Identify measured symptoms and attach plausible causes and actions."""

from dataclasses import dataclass

from config.analysis import DiagnosisThresholds
from core.bandwidth_monitor import Bandwidth
from core.diagnostic_cycle import DiagnosticCycle
from core.health_score import DNS_FAILURES, TCP_FAILURES


@dataclass(frozen=True)
class Finding:
    title: str
    severity: str
    evidence: tuple[str, ...]
    possible_causes: tuple[str, ...]
    recommended_actions: tuple[str, ...]


@dataclass(frozen=True)
class Diagnosis:
    status: str
    findings: tuple[Finding, ...]
    summary: str


def _exceeds(samples: list[tuple[str, float | None]], cutoff: float, unit: str) -> tuple[str, ...]:
    return tuple(
        f"{target}: {value:.1f} {unit} (threshold {cutoff:g} {unit})"
        for target, value in samples if value is not None and value >= cutoff
    )


def _traffic_changes(
    current: Bandwidth, previous: Bandwidth | None, thresholds: DiagnosisThresholds,
) -> tuple[str, ...]:
    if previous is None:
        return ()
    evidence = []
    for direction in ("upload", "download"):
        before = getattr(previous, f"{direction}_mbps")
        after = getattr(current, f"{direction}_mbps")
        if before is None or after is None:
            continue
        delta = abs(after - before)
        if (delta >= thresholds.traffic_change_mbps
                and delta >= before * thresholds.traffic_change_percent / 100):
            evidence.append(f"{direction.capitalize()}: {before:.2f} to {after:.2f} Mbps")
    return tuple(evidence)


def diagnose(
    cycle: DiagnosticCycle,
    *,
    sufficient_evidence: bool,
    previous_bandwidth: Bandwidth | None = None,
    thresholds: DiagnosisThresholds = DiagnosisThresholds(),
) -> Diagnosis:
    findings: list[Finding] = []

    def add(title: str, severity: str, evidence: tuple[str, ...],
            causes: tuple[str, ...], actions: tuple[str, ...]) -> None:
        if evidence:
            findings.append(Finding(title, severity, evidence, causes, actions))

    interface_down = cycle.network.interface_up is False
    if interface_down:
        add(
            "Network interface is down", "Critical",
            (f"macOS reports {cycle.network.interface or 'the selected interface'} as down.",),
            ("Wi-Fi may be disabled or disconnected.", "An Ethernet cable may be unplugged."),
            ("Check the active connection in macOS Network settings.",
             "Reconnect Wi-Fi or reseat the Ethernet cable, then rerun the tests."),
        )

    add(
        "High latency", "Medium",
        _exceeds([(p.target, p.avg_ms) for p in cycle.ping], thresholds.latency_ms, "ms"),
        ("Wi-Fi interference, congestion, or a longer upstream route may increase RTT.",),
        ("Pause large transfers and compare results near the router or over Ethernet.",),
    )
    add(
        "Significant ICMP packet loss", "High",
        _exceeds([(p.target, p.loss_percent) for p in cycle.ping], thresholds.loss_percent, "%"),
        ("Congestion or a weak connection may drop packets.",
         "The destination or a network device may filter or rate-limit ICMP."),
        ("Compare results across targets and check whether DNS and TCP probes still succeed.",),
    )
    add(
        "High jitter", "Medium",
        _exceeds([(p.target, p.jitter_ms) for p in cycle.ping], thresholds.jitter_ms, "ms"),
        ("Variable queueing under load or Wi-Fi retransmissions may cause inconsistent RTTs.",),
        ("Repeat the test with background transfers paused and compare with a wired connection.",),
    )
    dns_failures = tuple(
        f"{p.domain}: {p.status}" for p in cycle.dns
        if p.status in DNS_FAILURES or p.status == "error"
    ) + tuple(f"{p.host}:{p.port}: {p.detail or 'DNS lookup failed'}"
              for p in cycle.tcp if p.status == "dns_failure")
    add(
        "DNS resolution failed", "High", dns_failures,
        ("A name may be misspelled or lack address records.",
         "The configured resolver or its network path may be unavailable."),
        ("Verify the domain spelling and retry with a known domain.",
         "Check the configured resolver and compare with a direct-IP connectivity test."),
    )
    add(
        "Slow DNS responses", "Medium",
        _exceeds([(p.domain, p.elapsed_ms) for p in cycle.dns if p.status == "ok"],
                 thresholds.dns_ms, "ms"),
        ("Cache misses, resolver load, or network delays may extend lookups.",),
        ("Repeat several lookups and compare with another resolver permitted on this network.",),
    )
    add(
        "TCP connection failed", "High",
        tuple(f"{p.host}:{p.port}: {p.status}" for p in cycle.tcp if p.status in TCP_FAILURES),
        ("The service may be unavailable, the port may be closed, or a firewall may block it.",),
        ("Verify the host and port and compare results with another known service.",
         "Check local firewall or VPN settings if multiple endpoints fail."),
    )
    add(
        "Sudden change in local traffic", "Low",
        _traffic_changes(cycle.bandwidth, previous_bandwidth, thresholds),
        ("An app may have started or finished a download, sync, or backup.",),
        ("Check the Network tab in Activity Monitor for applications using the interface.",),
    )

    if interface_down:
        return Diagnosis("issues_detected", tuple(findings), "The local interface is confirmed down.")
    if not sufficient_evidence:
        return Diagnosis("inconclusive", tuple(findings),
                         "There are too few usable measurements for an overall assessment.")
    if findings:
        return Diagnosis("issues_detected", tuple(findings), "One or more symptoms were observed.")
    return Diagnosis("no_issues_detected", (), "No configured thresholds were triggered.")
