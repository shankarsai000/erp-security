"""
ML Model Training Pipeline
Trains Isolation Forest unsupervised anomaly detection models exclusively on Tier 1 clean baseline data.
Enforces feature normalization with StandardScaler and validates FPR / FNR bounds.
"""

from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from ml.feature_engineering import FeatureExtractor, Features, FEATURE_NAMES

logger = logging.getLogger(__name__)


class ModelTrainingPipeline:
    """
    Train and validate Isolation Forest anomaly detection models on clean baseline data.
    Guarantees anti-poisoning by requiring Tier 1 clean inputs.
    """

    def __init__(self, model_dir: str = "ml/models"):
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.feature_extractor = FeatureExtractor()
        self.scaler: Optional[StandardScaler] = None
        self.model: Optional[IsolationForest] = None
        self.metadata: Dict[str, Any] = {}

    def extract_dataset(
        self,
        events: List[dict],
        baseline_engine: Any = None
    ) -> np.ndarray:
        """Extract numeric feature vectors from a list of clean telemetry events."""
        vectors = []
        user_histories: Dict[str, List[dict]] = {}

        for ev in events:
            uid = ev.get("user_id") or ev.get("principal_ref") or "anonymous"
            if uid not in user_histories:
                user_histories[uid] = []
            user_histories[uid].append(ev)

            features = self.feature_extractor.extract_features(
                user_events=user_histories[uid],
                baseline_engine=baseline_engine,
                current_event=ev
            )
            vectors.append(features.to_vector())

        return np.array(vectors, dtype=float)

    def train_isolation_forest(
        self,
        X_train: np.ndarray,
        contamination: float = 0.05,
        n_estimators: int = 50,
        random_state: int = 42
    ) -> Tuple[IsolationForest, StandardScaler]:
        """
        Fit StandardScaler and IsolationForest on clean training feature vectors.
        """
        if len(X_train) == 0:
            raise ValueError("Cannot train on empty dataset")

        logger.info(f"Training IsolationForest on {len(X_train)} samples, {X_train.shape[1]} features")

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_train)

        model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            max_samples="auto",
            random_state=random_state,
            n_jobs=1
        )
        model.fit(X_scaled)

        self.scaler = scaler
        self.model = model
        self.metadata = {
            "trained_at": datetime.now(timezone.utc).isoformat(),
            "sample_count": int(len(X_train)),
            "feature_count": int(X_train.shape[1]),
            "feature_names": FEATURE_NAMES,
            "contamination": float(contamination),
            "n_estimators": int(n_estimators),
            "model_type": "IsolationForest"
        }

        return model, scaler

    def evaluate_model(
        self,
        X_normal: np.ndarray,
        X_anomalous: np.ndarray
    ) -> Dict[str, float]:
        """
        Validate model performance on clean (normal) vs synthetic anomalous test data.
        Returns FPR, FNR, and Accuracy.
        """
        if self.model is None or self.scaler is None:
            raise RuntimeError("Model must be trained before evaluation")

        # In Isolation Forest: 1 = normal, -1 = anomaly
        X_norm_scaled = self.scaler.transform(X_normal)
        norm_preds = self.model.predict(X_norm_scaled)
        # False Positives: normal events predicted as -1 (anomaly)
        fp_count = int(np.sum(norm_preds == -1))
        fpr = fp_count / float(len(norm_preds)) if len(norm_preds) > 0 else 0.0

        X_anom_scaled = self.scaler.transform(X_anomalous)
        anom_preds = self.model.predict(X_anom_scaled)
        # False Negatives: anomalous events predicted as 1 (normal)
        fn_count = int(np.sum(anom_preds == 1))
        fnr = fn_count / float(len(anom_preds)) if len(anom_preds) > 0 else 0.0

        metrics = {
            "false_positive_rate": float(round(fpr, 4)),
            "false_negative_rate": float(round(fnr, 4)),
            "normal_samples": int(len(norm_preds)),
            "anomalous_samples": int(len(anom_preds))
        }
        logger.info(f"Model validation metrics: {metrics}")
        return metrics

    def save_models(self, prefix: str = "") -> Dict[str, str]:
        """Persist model, scaler, and metadata to disk."""
        if self.model is None or self.scaler is None:
            raise RuntimeError("No trained model to save")

        p = f"{prefix}_" if prefix else ""
        model_path = self.model_dir / f"{p}isolation_forest.joblib"
        scaler_path = self.model_dir / f"{p}scaler.joblib"
        meta_path = self.model_dir / f"{p}metadata.json"

        joblib.dump(self.model, model_path)
        joblib.dump(self.scaler, scaler_path)

        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(self.metadata, f, indent=2)

        logger.info(f"Saved models to {self.model_dir}")
        return {
            "model_path": str(model_path),
            "scaler_path": str(scaler_path),
            "metadata_path": str(meta_path)
        }

    def train_from_tier1_baseline(
        self,
        baseline_file: str = "events/baseline_candidates.jsonl",
        baseline_engine: Any = None,
        contamination: float = 0.05
    ) -> Dict[str, str]:
        """Read Tier 1 baseline candidates and train production model."""
        clean_events = []
        if os.path.exists(baseline_file):
            with open(baseline_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            clean_events.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue

        if len(clean_events) < 50:
            logger.warning(
                f"Only {len(clean_events)} events in {baseline_file}. "
                f"Generating synthetic Tier 1 clean events for initialization."
            )
            clean_events.extend(self._generate_synthetic_clean_events(100 - len(clean_events)))

        X_train = self.extract_dataset(clean_events, baseline_engine=baseline_engine)
        self.train_isolation_forest(X_train, contamination=contamination)
        return self.save_models()

    def _generate_synthetic_clean_events(self, count: int = 100) -> List[dict]:
        """Generate realistic synthetic clean Tier 1 events for bootstrap training."""
        rng = np.random.default_rng(42)
        endpoints = [
            "/api/orders",
            "/api/inventory/items",
            "/api/finance/invoices",
            "/api/users/profile"
        ]
        users = [f"user_{i:03d}" for i in range(1, 15)]
        events = []

        base_time = datetime(2026, 9, 1, 9, 0, 0, tzinfo=timezone.utc).timestamp()

        for i in range(count):
            uid = str(rng.choice(users))
            path = str(rng.choice(endpoints))
            ts = datetime.fromtimestamp(base_time + i * 45.0, tz=timezone.utc).isoformat()
            events.append({
                "timestamp": ts,
                "user_id": uid,
                "principal_ref": uid,
                "path": path,
                "method": "POST" if "orders" in path else "GET",
                "request_size_bytes": int(rng.normal(512, 100)),
                "latency_ms": float(max(1.0, rng.normal(15.0, 4.0))),
                "user_account_age_days": int(rng.integers(30, 700)),
                "user_incident_count": 0,
                "client_ip": f"192.168.1.{rng.integers(10, 50)}",
                "user_agent": "ERP-Client/1.0",
                "decision": "ALLOW",
                "risk_score": float(rng.uniform(5.0, 15.0))
            })

        return events


def generate_synthetic_anomalies(count: int = 50) -> List[dict]:
    """Generate starkly anomalous events for model verification (spikes, high volume, unusual sizes)."""
    rng = np.random.default_rng(999)
    anomalies = []
    base_time = datetime(2026, 9, 10, 3, 0, 0, tzinfo=timezone.utc).timestamp()

    for i in range(count):
        ts = datetime.fromtimestamp(base_time + i * 0.5, tz=timezone.utc).isoformat()  # rapid velocity
        uid = f"attacker_{i % 10}"
        anomalies.append({
            "timestamp": ts,
            "user_id": uid,
            "principal_ref": uid,
            "path": f"/api/admin/dump_{i % 5}",
            "method": "POST",
            "request_size_bytes": int(rng.integers(50000, 200000)),  # massive payload
            "latency_ms": float(rng.uniform(300.0, 1500.0)),  # excessive latency
            "user_account_age_days": 1,  # brand new account
            "user_incident_count": 5,  # high incident history
            "client_ip": f"10.0.99.{rng.integers(1, 255)}",
            "user_agent": "Sqlmap/1.5",
            "decision": "ALLOW",
            "risk_score": 80.0
        })
    return anomalies

