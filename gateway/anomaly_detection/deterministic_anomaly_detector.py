"""
Deterministic Anomaly Detection
Identifies behavioral deviations from statistical baselines using ONLY explicit mathematical thresholds.
Zero black-box ML models. Purely explainable and deterministic.
"""

import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone

from gateway.baselines.baseline_engine import BaselineEngine, baseline_engine

logger = logging.getLogger("gateway.anomaly_detection")

@dataclass
class AnomalyScore:
    """Result of deterministic statistical anomaly evaluation."""
    is_anomalous: bool
    score: float  # Bounded 0.0 to 100.0
    reasons: List[str]
    severity: str  # "LOW", "MEDIUM", "HIGH"

class DeterministicAnomalyDetector:
    """
    Evaluates incoming request telemetry against established statistical baselines.
    Flags anomalies using explicit multiplier thresholds on size, latency, temporal patterns, and rates.
    """
    
    def __init__(self, engine: Optional[BaselineEngine] = None):
        self.baseline_engine = engine or baseline_engine

    def detect_anomalies(self, request_data: Dict[str, Any]) -> AnomalyScore:
        """
        Evaluates a request against the user/endpoint baseline.
        Returns explainable AnomalyScore (0-100).
        """
        user_id = (
            request_data.get("user_id")
            or request_data.get("principal_ref")
            or "unknown"
        )
        endpoint = request_data.get("path") or request_data.get("endpoint") or "unknown"
        request_size = int(request_data.get("request_size_bytes", 0) or len(str(request_data.get("body", ""))))
        response_time = float(request_data.get("latency_ms", 0.0) or request_data.get("response_time_ms", 0.0))
        
        # Determine request hour (0-23)
        request_hour = request_data.get("request_hour")
        if request_hour is None:
            ts_str = request_data.get("timestamp")
            if ts_str:
                try:
                    request_hour = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).hour
                except Exception:
                    request_hour = datetime.now(timezone.utc).hour
            else:
                request_hour = datetime.now(timezone.utc).hour

        baseline = self.baseline_engine.get_baseline(user_id, endpoint)
        
        # If no baseline established yet for this pair, conservatively allow without flagging
        if not baseline:
            return AnomalyScore(
                is_anomalous=False,
                score=0.0,
                reasons=[],
                severity="LOW"
            )

        anomaly_score = 0.0
        reasons: List[str] = []

        # Check 1: Request size anomaly (> 2x baseline p95)
        if baseline.request_size_p95 > 0 and request_size > (baseline.request_size_p95 * 2):
            anomaly_score += 25.0
            reasons.append(
                f"Payload size anomaly: {request_size} bytes exceeds 2x baseline p95 ({baseline.request_size_p95} bytes)"
            )

        # Check 2: Response time / execution latency anomaly (> 3x baseline p95)
        if baseline.response_time_p95 > 0 and response_time > (baseline.response_time_p95 * 3):
            anomaly_score += 20.0
            reasons.append(
                f"Latency anomaly: {response_time:.1f}ms exceeds 3x baseline p95 ({baseline.response_time_p95:.1f}ms)"
            )

        # Check 3: Time-of-day / operational schedule anomaly
        if baseline.peak_hours and (request_hour not in baseline.peak_hours):
            anomaly_score += 15.0
            reasons.append(
                f"Temporal anomaly: Request at hour {request_hour}:00 outside typical peak hours {baseline.peak_hours}"
            )

        # Check 4: Request burst rate anomaly
        current_rate = request_data.get("current_rate_per_hour", 0.0)
        if baseline.call_rate_p95 > 0 and current_rate > (baseline.call_rate_p95 * 2.5):
            anomaly_score += 20.0
            reasons.append(
                f"Velocity anomaly: Request rate {current_rate:.1f}/h exceeds 2.5x baseline p95 ({baseline.call_rate_p95:.1f}/h)"
            )

        bounded_score = max(0.0, min(100.0, anomaly_score))

        # Severity categorization
        if bounded_score == 0.0 or bounded_score < 25.0:
            severity = "LOW"
            is_anomalous = False
        elif bounded_score < 50.0:
            severity = "MEDIUM"
            is_anomalous = True
        else:
            severity = "HIGH"
            is_anomalous = True

        if is_anomalous:
            logger.warning(
                "Deterministic Anomaly Detected: user=%s, path=%s, score=%.1f (%s) - %s",
                user_id, endpoint, bounded_score, severity, "; ".join(reasons)
            )

        return AnomalyScore(
            is_anomalous=is_anomalous,
            score=bounded_score,
            reasons=reasons,
            severity=severity
        )

anomaly_detector = DeterministicAnomalyDetector()
