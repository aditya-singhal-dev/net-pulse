"""Assess and store the same measurements for each application entry point."""

from config.analysis import DiagnosisThresholds, ScoreThresholds
from core.diagnostic_cycle import DiagnosticCycle
from core.diagnosis_engine import Diagnosis, diagnose
from core.health_score import HealthScore, score_health
from database.db import Database


def record_cycle(
    database: Database,
    cycle: DiagnosticCycle,
    score_thresholds: ScoreThresholds = ScoreThresholds(),
    diagnosis_thresholds: DiagnosisThresholds = DiagnosisThresholds(),
) -> tuple[int, HealthScore, Diagnosis]:
    health = score_health(cycle, score_thresholds)
    diagnosis = diagnose(
        cycle,
        sufficient_evidence=health.score is not None,
        previous_bandwidth=database.previous_bandwidth(
            cycle, diagnosis_thresholds.traffic_baseline_max_age_seconds,
        ),
        thresholds=diagnosis_thresholds,
    )
    return database.save(cycle, assessment=(health, diagnosis)), health, diagnosis
