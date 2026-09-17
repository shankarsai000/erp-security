"""
Advisory ML Model Service
Provides sub-50ms advisory anomaly scoring, canary percentage evaluation,
and instant (<30 seconds) rollback to deterministic baseline.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import logging
import os
from pathlib import Path
import time
from typing import Dict, List, Optional, Any

import joblib
import numpy as np

from ml.feature_engineering import Features

logger = logging.getLogger(__name__)


@dataclass
class MLInferenceResult:
    """Advisory ML inference result (NEVER directly blocks)."""
    ml_score: float  # Bounded 0-100
    ml_confidence: float  # Bounded 0.0 - 1.0
    ml_anomalous: bool
    ml_advisory: bool = True
    latency_ms: float = 0.0
    reasons: List[str] = field(default_factory=list)


class MLModelService:
    """
    Production-grade Advisory ML Model Service.
    Loads Isolation Forest and StandardScaler, performs fast bounded inference,
    and supports canary rollout and immediate operational rollback.
    """

    def __init__(
        self,
        model_dir: str = "ml/models",
        canary_percentage: float = 100.0,
        enabled: bool = True
    ):
        self.model_dir = Path(model_dir)
        self.canary_percentage = float(canary_percentage)
        self.enabled = enabled
        self.is_rolled_back = False
        self.rollback_reason: Optional[str] = None
        self.rolled_back_at: Optional[str] = None

        self.model: Optional[Any] = None
        self.scaler: Optional[Any] = None
        self.metadata: Dict[str, Any] = {}

        # Performance and monitoring metrics
        self.total_inferences = 0
        self.total_anomalies = 0
        self.total_latency_ms = 0.0

        # Attempt immediate load
        self.load_models()

    def load_models(self) -> bool:
        """Load trained model and scaler from model_dir."""
        model_path = self.model_dir / "isolation_forest.joblib"
        scaler_path = self.model_dir / "scaler.joblib"
        meta_path = self.model_dir / "metadata.json"

        if not model_path.exists() or not scaler_path.exists():
            logger.info(f"ML models not found in {self.model_dir}. Operating in standby mode.")
            return False

        try:
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            if meta_path.exists():
                import json
                with open(meta_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
            logger.info(f"Successfully loaded ML models from {self.model_dir}")
            return True
        except Exception as exc:
            logger.error(f"Failed to load ML models from {self.model_dir}: {exc}")
            return False

    def should_evaluate_ml(self, request_id: str, canary_pct: Optional[float] = None) -> bool:
        """
        Deterministic canary evaluation based on stable hash of request_id.
        Allows gradual rollout: 1% -> 10% -> 50% -> 100%.
        """
        if not self.enabled or self.is_rolled_back or self.model is None or self.scaler is None:
            return False

        pct = self.canary_percentage if canary_pct is None else canary_pct
        if pct <= 0.0:
            return False
        if pct >= 100.0:
            return True

        # Hash request_id to integer [0, 9999] for smooth 0.01% resolution
        digest = hashlib.sha256(request_id.encode("utf-8")).hexdigest()
        hash_val = int(digest[:8], 16) % 10000
        return hash_val < (pct * 100.0)

    def score_request(self, features: Features) -> MLInferenceResult:
        """
        Score a request using Isolation Forest.
        Returns advisory score bounded between 0 and 100.
        SLA: < 50ms p95.
        """
        t0 = time.perf_counter()

        # 1. Check if ML is operational
        if not self.enabled or self.is_rolled_back or self.model is None or self.scaler is None:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            reasons = ["ML model service not active or rolled back"]
            if self.is_rolled_back:
                reasons.append(f"Rollback active: {self.rollback_reason}")
            return MLInferenceResult(
                ml_score=0.0,
                ml_confidence=0.0,
                ml_anomalous=False,
                ml_advisory=True,
                latency_ms=elapsed_ms,
                reasons=reasons
            )

        try:
            # 2. Extract and scale vector
            vector = np.array([features.to_vector()], dtype=float)
            scaled = self.scaler.transform(vector)

            # 3. Model inference: single-pass decision_function
            dec_func = float(self.model.decision_function(scaled)[0])
            pred = -1 if dec_func < 0.0 else 1
            # dec_func: positive for inliers (~ +0.1 to +0.3), negative for outliers (~ -0.1 to -0.4)

            # 4. Map decision function to bounded 0-100 anomaly score
            # A normal request with dec_func >= 0.15 gives score ~ 0-10
            # A borderline request with dec_func ~ 0.0 gives score ~ 50
            # A strong anomaly with dec_func <= -0.15 gives score ~ 80-100
            raw_score = (0.15 - dec_func) / 0.30 * 100.0
            ml_score = float(round(min(100.0, max(0.0, raw_score)), 2))

            # Confidence increases with absolute distance from decision boundary
            confidence = float(round(min(1.0, max(0.20, abs(dec_func) * 3.5)), 2))
            is_anomalous = bool(pred == -1 or ml_score >= 50.0)

            elapsed_ms = (time.perf_counter() - t0) * 1000.0

            reasons = []
            if is_anomalous:
                reasons.append(
                    f"ML Isolation Forest detected behavioral outlier (score: {ml_score}, confidence: {confidence})"
                )
                if features.request_size_deviation > 1.5:
                    reasons.append(f"Payload size deviation: {features.request_size_deviation:.1f}x vs median")
                if not features.is_peak_hour:
                    reasons.append(f"Off-peak execution at hour {features.hour_of_day}")
                if features.endpoint_entropy > 2.5:
                    reasons.append(f"High endpoint entropy: {features.endpoint_entropy:.2f}")

            # Update operational counters
            self.total_inferences += 1
            if is_anomalous:
                self.total_anomalies += 1
            self.total_latency_ms += elapsed_ms

            return MLInferenceResult(
                ml_score=ml_score,
                ml_confidence=confidence,
                ml_anomalous=is_anomalous,
                ml_advisory=True,
                latency_ms=round(elapsed_ms, 3),
                reasons=reasons
            )

        except Exception as exc:
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            logger.error(f"Inference exception in MLModelService: {exc}")
            return MLInferenceResult(
                ml_score=0.0,
                ml_confidence=0.0,
                ml_anomalous=False,
                ml_advisory=True,
                latency_ms=round(elapsed_ms, 3),
                reasons=[f"ML inference error: {str(exc)}"]
            )

    def rollback(self, reason: str = "High false positive rate or anomaly spike") -> None:
        """
        Instant rollback procedure (< 30 seconds SLA).
        Instantly halts ML scoring across all requests and falls back to statistical baseline.
        """
        self.is_rolled_back = True
        self.rollback_reason = reason
        self.rolled_back_at = datetime.now(timezone.utc).isoformat()
        logger.warning(f"CRITICAL: ML Model Rollback triggered: '{reason}' at {self.rolled_back_at}")

    def recover(self) -> None:
        """Recover from rollback state back to normal canary operation."""
        self.is_rolled_back = False
        self.rollback_reason = None
        self.rolled_back_at = None
        logger.info("ML Model Service recovered from rollback state.")

    def set_canary_percentage(self, percentage: float) -> None:
        """Dynamically update canary percentage (e.g. 1%, 10%, 50%, 100%)."""
        self.canary_percentage = float(max(0.0, min(100.0, percentage)))
        logger.info(f"Updated ML canary percentage to {self.canary_percentage}%")

    def get_health(self) -> Dict[str, Any]:
        """Return diagnostic health and performance telemetry."""
        avg_latency = (
            (self.total_latency_ms / self.total_inferences)
            if self.total_inferences > 0
            else 0.0
        )
        return {
            "status": "rolled_back" if self.is_rolled_back else ("healthy" if self.model else "standby"),
            "enabled": self.enabled,
            "is_rolled_back": self.is_rolled_back,
            "rollback_reason": self.rollback_reason,
            "canary_percentage": self.canary_percentage,
            "model_loaded": self.model is not None,
            "total_inferences": self.total_inferences,
            "total_anomalies": self.total_anomalies,
            "avg_latency_ms": round(avg_latency, 3),
            "metadata": self.metadata
        }
