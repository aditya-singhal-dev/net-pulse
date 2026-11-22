"""Calculate a weighted health score from available protocol measurements."""

from dataclasses import dataclass
from statistics import mean

from config.analysis import ScoreThresholds
from core.diagnostic_cycle import DiagnosticCycle

DNS_FAILURES = frozenset({"nxdomain", "no_answer", "timeout"})
TCP_FAILURES = frozenset({"refused", "timeout", "unreachable"})
PROTOCOLS = {"latency": "icmp", "loss": "icmp", "jitter": "icmp", "dns": "dns", "tcp": "tcp"}
WEIGHTS = {"latency": 20, "loss": 25, "jitter": 10, "dns": 20, "tcp": 25}
MIN_WEIGHT = 45


@dataclass(frozen=True)
class HealthScore:
    score: int | None
    category: str
    measured_weight: int
    components: dict[str, float | None]


def _quality(value: float, cutoffs: tuple[float, float]) -> float:
    good, poor = cutoffs
    return max(0.0, min(100.0, 100 * (poor - value) / (poor - good)))


def _average(values: list[float]) -> float | None:
    return mean(values) if values else None


def score_category(score: int | None) -> str:
    if score is None:
        return "Unavailable"
    for cutoff, category in ((90, "Excellent"), (75, "Good"), (50, "Fair"), (25, "Poor")):
        if score >= cutoff:
            return category
    return "Critical"


def score_health(
    cycle: DiagnosticCycle, thresholds: ScoreThresholds = ScoreThresholds(),
) -> HealthScore:
    dns_scores = []
    for probe in cycle.dns:
        if probe.status == "ok" and probe.elapsed_ms is not None:
            dns_scores.append(_quality(probe.elapsed_ms, thresholds.dns_ms))
        elif probe.status in DNS_FAILURES:
            dns_scores.append(0.0)
    tcp_scores = [
        100.0 if probe.status == "ok" else 0.0
        for probe in cycle.tcp if probe.status == "ok" or probe.status in TCP_FAILURES
    ]
    components = {
        "latency": _average([_quality(p.avg_ms, thresholds.latency_ms) for p in cycle.ping
                             if p.avg_ms is not None]),
        "loss": _average([_quality(p.loss_percent, thresholds.loss_percent) for p in cycle.ping
                          if p.loss_percent is not None]),
        "jitter": _average([_quality(p.jitter_ms, thresholds.jitter_ms) for p in cycle.ping
                            if p.jitter_ms is not None]),
        "dns": _average(dns_scores),
        "tcp": _average(tcp_scores),
    }
    available = {name: value for name, value in components.items() if value is not None}
    measured_weight = sum(WEIGHTS[name] for name in available)
    families = {PROTOCOLS[name] for name in available}
    if measured_weight < MIN_WEIGHT or len(families) < 2:
        return HealthScore(None, "Unavailable", measured_weight, components)
    score = round(sum(value * WEIGHTS[name] for name, value in available.items()) / measured_weight)
    return HealthScore(score, score_category(score), measured_weight, components)
