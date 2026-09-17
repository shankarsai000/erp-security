"""Phase 9: Continuous Improvement & SOC Feedback Loop Test Suite.

Verifies:
1. SOC Analyst Feedback recording, persistence, and rule accuracy/precision calculations.
2. Automated rule tuning recommendations on recurring false positives.
3. Concept drift detection across telemetry feature distributions.
4. Model retraining pipeline with strict FPR (<=2%) and FNR (<=5%) promotion gates.
5. Enterprise MTTD, MTTR, and security KPI tracking.
6. Gateway SOC and Continuous Improvement API endpoints.
"""

from pathlib import Path
import numpy as np
import pytest
from fastapi.testclient import TestClient

from gateway.app import app
from gateway.security_metrics import SecurityMetricsTracker, security_metrics_tracker
from gateway.soc_feedback import (
    FeedbackTag,
    SOCFeedbackEngine,
    SOCFeedbackRecord,
    soc_feedback_engine
)
from ml.retraining_pipeline import (
    ConceptDriftDetector,
    DriftReport,
    ModelRetrainingPipeline,
    RetrainingResult
)


@pytest.fixture
def temp_feedback_file(tmp_path):
    """Provides a dedicated temporary feedback file for isolated unit testing."""
    return str(tmp_path / "test_soc_feedback.jsonl")


@pytest.fixture
def isolated_feedback_engine(temp_feedback_file):
    """Provides a fresh, isolated SOCFeedbackEngine instance."""
    return SOCFeedbackEngine(feedback_file=temp_feedback_file)


class TestSOCFeedbackEngine:
    """Unit tests for analyst feedback ingestion and rule precision analytics."""

    def test_feedback_submission_and_persistence(self, isolated_feedback_engine, temp_feedback_file):
        rec = isolated_feedback_engine.submit_feedback(
            tag=FeedbackTag.CONFIRMED_ATTACK,
            analyst_id="analyst_alice",
            request_id="req-test-100",
            alert_id="alt-test-100",
            rule_id="R001",
            notes="Confirmed negative price tampering attack",
            target_entity="attacker_ip_1"
        )

        assert rec.feedback_id.startswith("fb-")
        assert rec.tag == FeedbackTag.CONFIRMED_ATTACK
        assert rec.analyst_id == "analyst_alice"
        assert len(isolated_feedback_engine.records) == 1

        # Check persistence to disk
        assert Path(temp_feedback_file).exists()
        reloaded_engine = SOCFeedbackEngine(feedback_file=temp_feedback_file)
        assert len(reloaded_engine.records) == 1
        assert reloaded_engine.records[0].feedback_id == rec.feedback_id

    def test_accuracy_metrics_precision_calculation(self, isolated_feedback_engine):
        # 3 confirmed attacks and 1 false positive on rule R001 -> precision = 3/4 = 0.75
        for _ in range(3):
            isolated_feedback_engine.submit_feedback(
                tag=FeedbackTag.CONFIRMED_ATTACK,
                rule_id="R001"
            )
        isolated_feedback_engine.submit_feedback(
            tag=FeedbackTag.FALSE_POSITIVE,
            rule_id="R001"
        )

        # 2 confirmed attacks on R004 -> precision = 1.0
        for _ in range(2):
            isolated_feedback_engine.submit_feedback(
                tag=FeedbackTag.CONFIRMED_ATTACK,
                rule_id="R004"
            )

        metrics = isolated_feedback_engine.get_accuracy_metrics()
        assert metrics["total_feedbacks"] == 6
        assert metrics["rule_precision"]["R001"]["precision"] == 0.75
        assert metrics["rule_precision"]["R001"]["false_positive_count"] == 1
        assert metrics["rule_precision"]["R004"]["precision"] == 1.0
        assert metrics["overall_precision"] == round(5 / 6, 3)

    def test_rule_tuning_recommendations_triggered_on_recurring_fp(self, isolated_feedback_engine):
        # Submit recurring false positives for R006 (mass scraping)
        for _ in range(3):
            isolated_feedback_engine.submit_feedback(
                tag=FeedbackTag.FALSE_POSITIVE,
                rule_id="R006",
                notes="Legitimate ETL bulk inventory synchronizer triggered scraping alarm"
            )

        recommendations = isolated_feedback_engine.generate_tuning_recommendations()
        assert len(recommendations) >= 1
        rec = next(r for r in recommendations if r["rule_id"] == "R006")
        assert rec["type"] == "THRESHOLD_INCREASE"
        assert "Increase mass scraping threshold" in rec["recommendation"]
        assert "safety_guard" in rec

    def test_export_labeled_events(self, isolated_feedback_engine):
        isolated_feedback_engine.submit_feedback(
            tag=FeedbackTag.CONFIRMED_ATTACK,
            request_id="req-attack-1",
            rule_id="R001"
        )
        isolated_feedback_engine.submit_feedback(
            tag=FeedbackTag.FALSE_POSITIVE,
            request_id="req-fp-1",
            rule_id="R006"
        )

        labeled = isolated_feedback_engine.export_labeled_events()
        assert len(labeled) == 2
        attack_sample = next(item for item in labeled if item["request_id"] == "req-attack-1")
        fp_sample = next(item for item in labeled if item["request_id"] == "req-fp-1")
        assert attack_sample["ground_truth_label"] == 1
        assert fp_sample["ground_truth_label"] == 0


class TestConceptDriftDetector:
    """Unit tests for feature distribution drift detection."""

    def test_no_drift_on_identical_distributions(self):
        detector = ConceptDriftDetector()
        rng = np.random.default_rng(42)
        X_base = rng.normal(loc=0.0, scale=1.0, size=(100, 16))
        X_curr = rng.normal(loc=0.0, scale=1.0, size=(100, 16))

        report = detector.evaluate_drift(X_base, X_curr)
        assert isinstance(report, DriftReport)
        assert report.is_drift_detected is False
        assert report.overall_drift_score < 0.25
        assert len(report.drifted_features) == 0

    def test_drift_detected_on_distribution_shift(self):
        detector = ConceptDriftDetector(drift_threshold=0.25, feature_drift_threshold=0.35)
        rng = np.random.default_rng(42)
        X_base = rng.normal(loc=0.0, scale=1.0, size=(100, 16))
        # Shift several features significantly (simulating change in attacker tools or API traffic)
        X_curr = rng.normal(loc=0.0, scale=1.0, size=(100, 16))
        X_curr[:, 0] += 2.5  # Feature 0 shifted
        X_curr[:, 2] += 3.0  # Feature 2 shifted
        X_curr[:, 5] += 2.0  # Feature 5 shifted

        report = detector.evaluate_drift(X_base, X_curr)
        assert report.is_drift_detected is True
        assert len(report.drifted_features) >= 3
        assert report.overall_drift_score > 0.25


class TestModelRetrainingPipeline:
    """Unit tests for model retraining and promotion gating (FPR <= 2%, FNR <= 5%)."""

    def test_retraining_promotion_gate_passed(self, tmp_path):
        pipeline = ModelRetrainingPipeline(model_dir=str(tmp_path))
        rng = np.random.default_rng(42)

        # Well-separated training and test distributions
        X_train = rng.normal(loc=0.0, scale=0.8, size=(250, 16))
        X_val_norm = rng.normal(loc=0.0, scale=0.8, size=(150, 16))
        X_val_anom = rng.normal(loc=5.0, scale=1.0, size=(30, 16))

        result = pipeline.run_retraining_cycle(
            X_clean_train=X_train,
            X_validation_normal=X_val_norm,
            X_validation_anomalous=X_val_anom,
            X_reference_baseline=X_val_norm
        )

        assert isinstance(result, RetrainingResult)
        assert result.success is True
        assert result.promotion_granted is True
        assert result.fpr <= pipeline.MAX_PERMITTED_FPR
        assert result.fnr <= pipeline.MAX_PERMITTED_FNR
        assert result.candidate_model_path is not None
        assert Path(result.candidate_model_path).exists()
        assert "PASSED promotion gates" in result.message

    def test_retraining_promotion_gate_rejected_on_high_fpr(self, tmp_path):
        pipeline = ModelRetrainingPipeline(model_dir=str(tmp_path))
        rng = np.random.default_rng(42)

        # Training set is compact
        X_train = rng.normal(loc=0.0, scale=0.2, size=(200, 16))
        # Validation normal has wide variance -> causes many normal points to be flagged as anomalies (high FPR)
        X_val_norm = rng.normal(loc=0.0, scale=3.0, size=(150, 16))
        X_val_anom = rng.normal(loc=5.0, scale=1.0, size=(30, 16))

        result = pipeline.run_retraining_cycle(
            X_clean_train=X_train,
            X_validation_normal=X_val_norm,
            X_validation_anomalous=X_val_anom
        )

        assert result.success is True
        assert result.promotion_granted is False
        assert result.fpr > pipeline.MAX_PERMITTED_FPR
        assert "Model candidate REJECTED" in result.message


class TestSecurityMetricsTracker:
    """Unit tests for enterprise security KPIs (MTTD, MTTR, traffic analytics)."""

    def test_mttd_mttr_kpi_computation(self):
        tracker = SecurityMetricsTracker()

        # Incident 1: Event at T=100, Alert at T=102 (TTD=2s), Containment at T=105 (TTR=3s)
        tracker.record_incident_lifecycle(
            incident_id="inc-1",
            event_time_epoch=100.0,
            alert_time_epoch=102.0,
            containment_time_epoch=105.0,
            automated=True
        )

        # Incident 2: Event at T=200, Alert at T=204 (TTD=4s), Containment at T=209 (TTR=5s)
        tracker.record_incident_lifecycle(
            incident_id="inc-2",
            event_time_epoch=200.0,
            alert_time_epoch=204.0,
            containment_time_epoch=209.0,
            automated=True
        )

        kpis = tracker.get_kpis()
        incident_kpis = kpis["incident_kpis"]
        assert incident_kpis["total_incidents_tracked"] == 2
        # Avg MTTD = (2 + 4) / 2 = 3.0s
        assert incident_kpis["mttd_mean_seconds"] == 3.0
        # Avg MTTR = (3 + 5) / 2 = 4.0s
        assert incident_kpis["mttr_mean_seconds"] == 4.0
        assert incident_kpis["automated_containment_rate_pct"] == 100.0

    def test_traffic_decision_breakdown(self):
        tracker = SecurityMetricsTracker()
        for _ in range(80):
            tracker.record_request_decision("ALLOW")
        for _ in range(15):
            tracker.record_request_decision("BLOCK")
        for _ in range(5):
            tracker.record_request_decision("CHALLENGE")

        kpis = tracker.get_kpis()
        assert kpis["total_requests_processed"] == 100
        assert kpis["traffic_breakdown"]["ALLOW"] == 80
        assert kpis["traffic_breakdown"]["BLOCK"] == 15
        assert kpis["threat_mitigation_rate_pct"] == 15.0


class TestGatewaySOCEndpoints:
    """Live Gateway API tests for Phase 9 continuous improvement endpoints."""

    def test_soc_feedback_api_flow(self):
        client = TestClient(app)

        # Submit feedback
        payload = {
            "tag": "CONFIRMED_ATTACK",
            "analyst_id": "soc_senior_analyst",
            "request_id": "req-live-001",
            "alert_id": "alt-live-001",
            "rule_id": "R001",
            "notes": "Verified SQLi injection attack payload"
        }
        res = client.post("/api/soc/feedback", json=payload)
        assert res.status_code == 200
        data = res.json()
        assert data["tag"] == "CONFIRMED_ATTACK"
        assert data["analyst_id"] == "soc_senior_analyst"

        # Retrieve feedback and accuracy metrics
        get_res = client.get("/api/soc/feedback")
        assert get_res.status_code == 200
        feed_data = get_res.json()
        assert "metrics" in feed_data
        assert "recent_records" in feed_data
        assert feed_data["metrics"]["total_feedbacks"] >= 1

    def test_soc_tuning_recommendations_api(self):
        client = TestClient(app)
        res = client.get("/api/soc/tuning-recommendations")
        assert res.status_code == 200
        data = res.json()
        assert "recommendations" in data

    def test_ml_retraining_trigger_api(self):
        client = TestClient(app)
        res = client.post("/api/ml/retrain")
        assert res.status_code == 200
        data = res.json()
        assert "success" in data
        assert "promotion_granted" in data
        assert "fpr" in data
        assert "fnr" in data

    def test_security_metrics_api(self):
        client = TestClient(app)
        res = client.get("/api/metrics/security")
        assert res.status_code == 200
        data = res.json()
        assert "incident_kpis" in data
        assert "traffic_breakdown" in data
        assert "mttd_mean_seconds" in data["incident_kpis"]
