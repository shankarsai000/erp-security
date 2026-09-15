from dataclasses import dataclass
from typing import Dict, Any, List, Tuple

BASELINE_GATES_CRITERIA = {
    "minimum_days": 30,             # At least 30 days of data
    "minimum_events": 100000,       # Statistically meaningful volume
    "minimum_users": 100,           # Broad demographic coverage
    "analyst_review_samples": 500,  # 500+ events manually validated
    "analyst_agreement_rate": 0.97, # 97%+ analyst consensus
    "false_positive_rate": 0.02,    # FP < 2% on analyst labels
    "endpoint_coverage": 0.95,      # 95%+ endpoints represented
    "weekly_drift_max": 0.05,       # Drift < 5% week-to-week
}

@dataclass
class BaselineEvaluationResult:
    is_ready_for_ml: bool
    passed_gates: List[str]
    failed_gates: List[str]
    metrics: Dict[str, Any]

def evaluate_baseline_trustworthiness(current_metrics: Dict[str, Any]) -> BaselineEvaluationResult:
    """
    Evaluates whether the telemetry dataset is statistically sufficient and
    trustworthy before permitting machine learning deployment (Critical Improvement #2).
    """
    passed = []
    failed = []

    # 1. Volume & Temporal Duration
    days = current_metrics.get("days_collected", 0)
    if days >= BASELINE_GATES_CRITERIA["minimum_days"]:
        passed.append(f"Days collected: {days} >= 30")
    else:
        failed.append(f"Days collected: {days} < 30")

    events = current_metrics.get("total_events", 0)
    if events >= BASELINE_GATES_CRITERIA["minimum_events"]:
        passed.append(f"Total events: {events} >= 100,000")
    else:
        failed.append(f"Total events: {events} < 100,000")

    # 2. Analyst Ground Truth Quality
    analyst_reviews = current_metrics.get("analyst_reviews", 0)
    if analyst_reviews >= BASELINE_GATES_CRITERIA["analyst_review_samples"]:
        passed.append(f"Analyst reviews: {analyst_reviews} >= 500")
    else:
        failed.append(f"Analyst reviews: {analyst_reviews} < 500")

    fp_rate = current_metrics.get("false_positive_rate", 1.0)
    if fp_rate <= BASELINE_GATES_CRITERIA["false_positive_rate"]:
        passed.append(f"False positive rate: {fp_rate:.1%} <= 2.0%")
    else:
        failed.append(f"False positive rate: {fp_rate:.1%} > 2.0%")

    # 3. Endpoint Coverage
    coverage = current_metrics.get("endpoint_coverage", 0.0)
    if coverage >= BASELINE_GATES_CRITERIA["endpoint_coverage"]:
        passed.append(f"Endpoint coverage: {coverage:.1%} >= 95.0%")
    else:
        failed.append(f"Endpoint coverage: {coverage:.1%} < 95.0%")

    is_ready = len(failed) == 0
    return BaselineEvaluationResult(
        is_ready_for_ml=is_ready,
        passed_gates=passed,
        failed_gates=failed,
        metrics=current_metrics
    )
