"""
Phase 6 Automated Test Suite: Machine Learning Anomaly Detection (Advisory Only)
Verifies feature engineering, model training, evaluation bounds, inference latency (<50ms SLA),
canary rollout, fast rollback (<30s SLA), and gateway telemetry integration.
"""

import math
import tempfile
import time
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient
import numpy as np

from ml.feature_engineering import FeatureExtractor, Features, FEATURE_NAMES
from ml.train_models import ModelTrainingPipeline, generate_synthetic_anomalies
from ml.model_service import MLModelService
from gateway.app import app, ml_service
from gateway.baselines.baseline_engine import BaselineEngine, BaselineStats


@pytest.fixture
def mock_baseline_engine():
    """Mock baseline engine populated with statistical baselines."""
    engine = BaselineEngine()
    engine.baselines["test_user:/api/orders"] = BaselineStats(
        user_id="test_user",
        endpoint="/api/orders",
        call_count=500,
        call_rate_per_hour=25.0,
        call_rate_p95=40.0,
        request_size_median=500,
        request_size_p95=1000,
        response_time_median=20.0,
        response_time_p95=50.0,
        peak_hours=[9, 10, 11, 14, 15, 16],
        updated_at=datetime.now(timezone.utc).isoformat(),
        data_points=500
    )
    return engine


class TestMLFeatureEngineering:
    """Test feature extraction, entropy calculation, and vector conversion."""

    def test_feature_extractor_all_features_computed(self, mock_baseline_engine):
        extractor = FeatureExtractor()
        current_event = {
            "timestamp": "2026-09-15T10:30:00+00:00",
            "user_id": "test_user",
            "principal_ref": "test_user",
            "path": "/api/orders",
            "method": "POST",
            "request_size_bytes": 1000,
            "latency_ms": 30.0,
            "client_ip": "10.0.0.1",
            "user_agent": "Mozilla/5.0",
            "user_account_age_days": 180,
            "user_incident_count": 0
        }

        user_events = [
            {
                "timestamp": "2026-09-15T10:00:00+00:00",
                "path": "/api/orders",
                "client_ip": "10.0.0.1",
                "user_agent": "Mozilla/5.0"
            },
            {
                "timestamp": "2026-09-15T10:15:00+00:00",
                "path": "/api/inventory/items",
                "client_ip": "10.0.0.2",
                "user_agent": "Mozilla/5.0"
            }
        ]

        features = extractor.extract_features(
            user_events=user_events,
            baseline_engine=mock_baseline_engine,
            current_event=current_event
        )

        assert isinstance(features, Features)
        assert features.request_count_1h == 3
        assert features.unique_endpoints_1h == 2
        assert features.device_diversity == 2
        assert features.is_peak_hour is True  # Hour 10 is in peak_hours
        assert features.request_size_deviation == 1.0  # (1000 - 500) / 500 = 1.0
        assert features.response_time_deviation == 0.5  # (30 - 20) / 20 = 0.5
        assert features.method_is_mutation == 1.0
        assert features.endpoint_entropy > 0.0

        vec = features.to_vector()
        assert len(vec) == len(FEATURE_NAMES)
        assert all(isinstance(v, float) for v in vec)

    def test_shannon_entropy_bounds(self):
        extractor = FeatureExtractor()
        # Single endpoint -> 0 entropy
        assert extractor._compute_entropy(["/api/orders"] * 10) == 0.0

        # Uniform 4 distinct endpoints -> log2(4) = 2.0
        uniform_4 = ["/api/a", "/api/b", "/api/c", "/api/d"]
        entropy = extractor._compute_entropy(uniform_4)
        assert pytest.approx(entropy, 0.01) == 2.0

        # Empty list -> 0.0
        assert extractor._compute_entropy([]) == 0.0

    def test_default_features_on_empty(self):
        extractor = FeatureExtractor()
        defaults = extractor.extract_features(user_events=[], current_event=None)
        assert defaults.request_count_1h == 1
        assert defaults.account_age_days == 365
        assert defaults.endpoint_entropy == 0.0


class TestMLModelTrainingAndEvaluation:
    """Test model training pipeline, validation metrics, and persistence."""

    def test_train_and_serialize_models(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            pipeline = ModelTrainingPipeline(model_dir=tmp_dir)
            synthetic_events = pipeline._generate_synthetic_clean_events(120)
            X = pipeline.extract_dataset(synthetic_events)

            assert X.shape[0] == 120
            assert X.shape[1] == len(FEATURE_NAMES)

            model, scaler = pipeline.train_isolation_forest(X, contamination=0.05)
            assert model is not None
            assert scaler is not None

            saved = pipeline.save_models()
            assert "isolation_forest.joblib" in saved["model_path"]
            assert "scaler.joblib" in saved["scaler_path"]

            # Load into MLModelService and verify
            service = MLModelService(model_dir=tmp_dir)
            assert service.model is not None
            assert service.scaler is not None

    def test_model_evaluation_metrics_fpr_fnr(self):
        pipeline = ModelTrainingPipeline()
        clean_train = pipeline._generate_synthetic_clean_events(200)
        X_train = pipeline.extract_dataset(clean_train)
        pipeline.train_isolation_forest(X_train, contamination=0.05)

        # Validation sets
        clean_test = pipeline._generate_synthetic_clean_events(100)
        X_test_clean = pipeline.extract_dataset(clean_test)

        anom_test = generate_synthetic_anomalies(50)
        X_test_anom = pipeline.extract_dataset(anom_test)

        metrics = pipeline.evaluate_model(X_test_clean, X_test_anom)
        # Isolation Forest with 0.05 contamination: expect FPR <= 0.10 and FNR <= 0.15
        assert metrics["false_positive_rate"] <= 0.10
        assert metrics["false_negative_rate"] <= 0.15


class TestMLModelServiceAndSLA:
    """Test sub-50ms inference SLA, canary rollout, and instant rollback."""

    def test_inference_latency_budget(self):
        """Verify that ML inference p95 latency is strictly < 50ms (target < 10ms)."""
        service = MLModelService()
        service.load_models()
        if service.model is None:
            pytest.skip("Models not yet loaded in default path")

        features = FeatureExtractor()._default_features()
        latencies = []

        # Run 100 inference evaluations
        for _ in range(100):
            res = service.score_request(features)
            latencies.append(res.latency_ms)

        p95_latency = float(np.percentile(latencies, 95))
        assert p95_latency < 50.0, f"p95 latency {p95_latency}ms violated 50ms budget"

    def test_canary_allocation_hashing(self):
        service = MLModelService(canary_percentage=0.0)
        req_id = "req-canary-test-123"
        assert service.should_evaluate_ml(req_id) is False

        service.set_canary_percentage(100.0)
        assert service.should_evaluate_ml(req_id) is True

        # At 50%, roughly 50% of distinct UUIDs should trigger ML
        service.set_canary_percentage(50.0)
        evaluated = sum(1 for i in range(200) if service.should_evaluate_ml(f"uuid-{i}"))
        # 200 samples at 50%: expect between 70 and 130
        assert 70 <= evaluated <= 130

    def test_instant_rollback_and_recovery(self):
        service = MLModelService()
        if service.model is None:
            pytest.skip("Models not yet loaded")

        features = FeatureExtractor()._default_features()

        # Before rollback: active scoring
        res_before = service.score_request(features)
        assert res_before.reasons != ["ML model service not active or rolled back"]

        # Trigger rollback (< 30s SLA)
        t0 = time.perf_counter()
        service.rollback(reason="Test emergency rollback")
        rollback_time_ms = (time.perf_counter() - t0) * 1000.0
        assert rollback_time_ms < 5.0, "Rollback must execute in milliseconds"
        assert service.is_rolled_back is True

        # After rollback: instantly bypassed
        res_after = service.score_request(features)
        assert res_after.ml_score == 0.0
        assert res_after.ml_anomalous is False
        assert any("Rollback active" in r for r in res_after.reasons)

        # Recover
        service.recover()
        assert service.is_rolled_back is False
        res_recovered = service.score_request(features)
        assert "Rollback active" not in str(res_recovered.reasons)


class TestGatewayAdvisoryMLIntegration:
    """Test that ML scores are tagged into audit events and NEVER block requests directly."""

    @pytest.fixture
    def client(self):
        return TestClient(app, raise_server_exceptions=False)

    def test_ml_health_endpoint(self, client):
        resp = client.get("/api/ml/health")
        assert resp.status_code == 200
        data = resp.json()
        assert "status" in data
        assert "canary_percentage" in data
        assert "enabled" in data

    def test_ml_rollback_endpoint(self, client):
        resp = client.post("/api/ml/rollback?reason=Automated+test+rollback")
        assert resp.status_code == 200
        assert resp.json()["status"] == "rolled_back"

        health = client.get("/api/ml/health").json()
        assert health["is_rolled_back"] is True

        # Recover
        rec = client.post("/api/ml/recover")
        assert rec.status_code == 200
        assert rec.json()["status"] == "recovered"

    def test_advisory_ml_does_not_block_legitimate_traffic(self, client):
        """
        Critical guarantee: ML anomaly detection is strictly ADVISORY.
        Even if an event has anomalous characteristics, it is not blocked unless
        deterministic controls (WAF, rules, auth, replay) trigger.
        """
        # A legitimate user login with valid credentials
        login_resp = client.post(
            "/api/auth/login",
            json={"username": "sales_john", "password": "password123"}
        )
        assert login_resp.status_code == 200
        token = login_resp.json().get("access_token")
        assert token is not None

        # Legitimate query with token passes through gateway
        resp = client.get(
            "/api/orders",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Request-ID": "req-advisory-ml-test"
            }
        )
        assert resp.status_code == 200
        assert resp.headers.get("X-Decision") == "ALLOW"
