"""Configurable cutoffs for network scoring and troubleshooting."""

from dataclasses import astuple, dataclass
from math import isfinite


@dataclass(frozen=True)
class ScoreThresholds:
    latency_ms: tuple[float, float] = (50, 300)
    loss_percent: tuple[float, float] = (0, 50)
    jitter_ms: tuple[float, float] = (10, 80)
    dns_ms: tuple[float, float] = (50, 500)

    def __post_init__(self) -> None:
        for good, poor in astuple(self):
            if not 0 <= good < poor or not isfinite(poor):
                raise ValueError("Score cutoffs must be finite and satisfy 0 <= good < poor")
        if self.loss_percent[1] > 100:
            raise ValueError("Packet loss cutoffs cannot exceed 100 percent")


@dataclass(frozen=True)
class DiagnosisThresholds:
    latency_ms: float = 150
    loss_percent: float = 10
    jitter_ms: float = 30
    dns_ms: float = 200
    traffic_change_mbps: float = 5
    traffic_change_percent: float = 50
    traffic_baseline_max_age_seconds: float = 300

    def __post_init__(self) -> None:
        if any(not isfinite(value) or value <= 0 for value in astuple(self)):
            raise ValueError("Diagnosis cutoffs must be positive and finite")
        if self.loss_percent > 100:
            raise ValueError("Packet loss cutoffs cannot exceed 100 percent")


def parse_thresholds(overrides: object) -> tuple[ScoreThresholds, DiagnosisThresholds]:
    if not isinstance(overrides, dict) or overrides.keys() - {"score", "diagnosis"}:
        raise ValueError("Threshold configuration must contain only score and diagnosis sections")
    score = overrides.get("score", {})
    diagnosis = overrides.get("diagnosis", {})
    if not isinstance(score, dict) or not isinstance(diagnosis, dict):
        raise ValueError("Score and diagnosis threshold sections must be JSON objects")
    if any(not isinstance(value, (tuple, list)) for value in score.values()):
        raise ValueError("Each scoring threshold must be a pair of cutoffs")
    return ScoreThresholds(**{key: tuple(value) for key, value in score.items()}), DiagnosisThresholds(**diagnosis)
