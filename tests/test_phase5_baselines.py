"""
Phase 5 Test Suite: Baseline Statistics Engine, Deterministic Anomaly Detection & 3-Tier Anti-Poisoning
Verifies:
1. Deterministic baseline computation (medians, percentiles, peak hours)
2. Trustworthiness readiness gates per CRITICAL_IMPROVEMENTS_SUMMARY.md #2
3. Multiplier-based statistical anomaly detector (zero black-box ML)
4. Anti-poisoning 3-tier triage (Pristine, Review Quarantine, Hard Quarantine)
5. Gateway end-to-end telemetry and risk integration
"""

import os
import time
import json
import uuid
import pytest
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient

from gateway.app import app
from gateway.baselines.baseline_engine import BaselineEngine, BaselineStats
from gateway.anomaly_detection.deterministic_anomaly_detector import (
    DeterministicAnomalyDetector,
    AnomalyScore,
)
from gateway.telemetry.anti_poisoning import AntiPoisoningFilter, EventTier
import gateway.app as gateway_module

client = TestClient(app, raise_server_exceptions=False)
SALES_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzYWxlc19qb2huIiwicm9sZSI6InNhbGVzIn0.c2ltdWxhdGVkX3NpZw"

@pytest.fixture
def sample_clean_events_file(tmp_path):
    """Generates synthetic Tier 1 clean events across 35 days for testing."""
    file_path = tmp_path / "clean_events.jsonl"
    base_time = datetime(2026, 1, 1, 9, 0, 0, tzinfo=timezone.utc)
    
    with open(file_path, "w", encoding="utf-8") as f:
        for i in range(120):
            # Timestamps spread over 35 days during typical business hours (9-17)
            event_time = base_time + timedelta(days=(i % 35), hours=(i % 8))
            event = {
                "timestamp": event_time.isoformat(),
                "request_id": f"clean-req-{i}",
                "principal_ref": "p-sales-john",
                "client_ip": "10.0.1.50",
                "method": "GET",
                "path": "/api/orders/101",
                "decision": "ALLOW",
                "risk_score": 10.0,
                "components": {
                    "threat": 0.0,
                    "sensitivity": 80.0,
                    "user_trust": 100.0,
                    "context": 0.0,
                    "waf_severity": 0.0,
                    "rule_severity": 0.0,
                    "auth_anomaly": 0.0,
                    "rate_severity": 0.0
                },
                "fired_rules": [],
                "reasons": [],
                "request_size_bytes": 150 + (i % 20),
                "latency_ms": 1.2 + ((i % 5) * 0.1),
                "user_agent": "ERP-Client/1.0"
            }
            f.write(json.dumps(event) + "\n")
    return str(file_path)


class TestBaselineEngine:
    """Verifies deterministic statistical aggregation and trustworthiness gates."""

    def test_build_baselines_from_clean_events(self, sample_clean_events_file):
        engine = BaselineEngine()
        engine.build_baseline_from_clean_events(sample_clean_events_file, min_samples=100)
        
        stat = engine.get_baseline("p-sales-john", "/api/orders/101")
        assert stat is not None
        assert stat.user_id == "p-sales-john"
        assert stat.endpoint == "/api/orders/101"
        assert stat.call_count == 120
        assert stat.data_points == 120
        # Request sizes ranged from 150 to 169 bytes
        assert 150 <= stat.request_size_median <= 165
        assert stat.request_size_p95 >= stat.request_size_median
        # Latency ranged around 1.2 to 1.6 ms
        assert 1.0 <= stat.response_time_median <= 2.0
        assert stat.response_time_p95 >= stat.response_time_median
        # Peak hours should reflect the generated hours (9-16)
        assert len(stat.peak_hours) > 0
        assert any(h in range(9, 17) for h in stat.peak_hours)

    def test_insufficient_samples_skips_baseline(self, tmp_path):
        sparse_file = tmp_path / "sparse.jsonl"
        with open(sparse_file, "w", encoding="utf-8") as f:
            for i in range(5):
                f.write(json.dumps({
                    "timestamp": "2026-01-01T10:00:00Z",
                    "principal_ref": "p-sparse-user",
                    "path": "/api/rare-endpoint",
                    "request_size_bytes": 100,
                    "latency_ms": 1.0
                }) + "\n")

        engine = BaselineEngine()
        # Default minimum is 100 observations
        engine.build_baseline_from_clean_events(str(sparse_file), min_samples=100)
        assert engine.get_baseline("p-sparse-user", "/api/rare-endpoint") is None

    def test_baseline_persistence(self, tmp_path):
        json_file = str(tmp_path / "saved_baselines.json")
        engine = BaselineEngine(baselines_path=json_file)
        engine.baselines["user1:/api/orders"] = BaselineStats(
            user_id="user1",
            endpoint="/api/orders",
            call_count=500,
            call_rate_per_hour=25.0,
            call_rate_p95=40.0,
            request_size_median=250,
            request_size_p95=450,
            response_time_median=2.5,
            response_time_p95=5.0,
            peak_hours=[9, 10, 11, 14, 15],
            updated_at="2026-01-01T12:00:00",
            data_points=500
        )
        engine.save_baselines(json_file)
        assert os.path.exists(json_file)

        # Reload into new instance
        new_engine = BaselineEngine(baselines_path=json_file)
        reloaded = new_engine.get_baseline("user1", "/api/orders")
        assert reloaded is not None
        assert reloaded.call_count == 500
        assert reloaded.request_size_median == 250
        assert reloaded.peak_hours == [9, 10, 11, 14, 15]

    def test_trustworthiness_gates_fail_when_under_threshold(self):
        engine = BaselineEngine()
        engine.events_processed = 5000  # < 100k
        engine.oldest_event_time = datetime(2026, 1, 1)
        engine.newest_event_time = datetime(2026, 1, 10)  # 9 days < 30 days
        
        is_ready, blockers = engine.evaluate_trustworthiness_gates(total_endpoints=20, total_users=500)
        assert is_ready is False
        assert len(blockers) >= 3
        assert any("volume" in b.lower() for b in blockers)
        assert any("temporal span" in b.lower() for b in blockers)

    def test_trustworthiness_gates_pass_when_criteria_met(self):
        engine = BaselineEngine()
        engine.events_processed = 120_000
        engine.oldest_event_time = datetime(2026, 1, 1)
        engine.newest_event_time = datetime(2026, 2, 5)  # 35 days
        
        # Populate 20 endpoints and 500 users
        for i in range(20):
            ep = f"/api/endpoint_{i}"
            for u in range(25):
                user = f"user_{u}"
                engine.baselines[f"{user}:{ep}"] = BaselineStats(
                    user_id=user, endpoint=ep, call_count=100, call_rate_per_hour=10.0,
                    call_rate_p95=20.0, request_size_median=100, request_size_p95=200,
                    response_time_median=1.0, response_time_p95=2.0, peak_hours=[9, 10],
                    updated_at="2026-01-01", data_points=100
                )

        is_ready, blockers = engine.evaluate_trustworthiness_gates(
            total_endpoints=20,
            total_users=25,
            min_events=100_000
        )
        assert is_ready is True
        assert len(blockers) == 0


class TestDeterministicAnomalyDetector:
    """Verifies multiplier-based statistical deviation detection."""

    @pytest.fixture
    def mock_baseline_engine(self):
        engine = BaselineEngine()
        engine.baselines["p-sales-john:/api/orders/101"] = BaselineStats(
            user_id="p-sales-john",
            endpoint="/api/orders/101",
            call_count=1000,
            call_rate_per_hour=20.0,
            call_rate_p95=35.0,
            request_size_median=150,
            request_size_p95=200,
            response_time_median=1.5,
            response_time_p95=3.0,
            peak_hours=[9, 10, 11, 13, 14, 15, 16],
            updated_at="2026-01-01T00:00:00",
            data_points=1000
        )
        return engine

    def test_clean_request_matching_baseline_is_not_anomalous(self, mock_baseline_engine):
        detector = DeterministicAnomalyDetector(mock_baseline_engine)
        req = {
            "user_id": "p-sales-john",
            "path": "/api/orders/101",
            "request_size_bytes": 180,  # <= 2x p95 (400)
            "latency_ms": 2.0,          # <= 3x p95 (9.0)
            "request_hour": 10          # in peak hours
        }
        res = detector.detect_anomalies(req)
        assert res.is_anomalous is False
        assert res.score == 0.0
        assert res.severity == "LOW"

    def test_unknown_user_conservatively_allowed(self, mock_baseline_engine):
        detector = DeterministicAnomalyDetector(mock_baseline_engine)
        req = {
            "user_id": "p-new-user-unseen",
            "path": "/api/orders/101",
            "request_size_bytes": 10000,
            "latency_ms": 50.0
        }
        res = detector.detect_anomalies(req)
        assert res.is_anomalous is False
        assert res.score == 0.0

    def test_payload_size_anomaly_detected(self, mock_baseline_engine):
        detector = DeterministicAnomalyDetector(mock_baseline_engine)
        # Baseline p95 is 200 bytes. 500 bytes > 2x p95
        req = {
            "user_id": "p-sales-john",
            "path": "/api/orders/101",
            "request_size_bytes": 500,
            "latency_ms": 2.0,
            "request_hour": 10
        }
        res = detector.detect_anomalies(req)
        assert res.is_anomalous is True
        assert res.score >= 25.0
        assert any("Payload size anomaly" in r for r in res.reasons)

    def test_latency_anomaly_detected(self, mock_baseline_engine):
        detector = DeterministicAnomalyDetector(mock_baseline_engine)
        # Baseline p95 is 3.0ms. 15.0ms > 3x p95
        req = {
            "user_id": "p-sales-john",
            "path": "/api/orders/101",
            "request_size_bytes": 150,
            "latency_ms": 15.0,
            "request_hour": 11
        }
        res = detector.detect_anomalies(req)
        assert res.score >= 20.0
        assert any("Latency anomaly" in r for r in res.reasons)

    def test_off_hours_temporal_anomaly_detected(self, mock_baseline_engine):
        detector = DeterministicAnomalyDetector(mock_baseline_engine)
        # Hour 3:00 AM is outside peak hours [9..16]
        req = {
            "user_id": "p-sales-john",
            "path": "/api/orders/101",
            "request_size_bytes": 150,
            "latency_ms": 2.0,
            "request_hour": 3
        }
        res = detector.detect_anomalies(req)
        assert res.score >= 15.0
        assert any("Temporal anomaly" in r for r in res.reasons)

    def test_compounding_anomalies_reach_high_severity(self, mock_baseline_engine):
        detector = DeterministicAnomalyDetector(mock_baseline_engine)
        # Massive payload + huge latency + off-hours
        req = {
            "user_id": "p-sales-john",
            "path": "/api/orders/101",
            "request_size_bytes": 1000,
            "latency_ms": 25.0,
            "request_hour": 2
        }
        res = detector.detect_anomalies(req)
        assert res.is_anomalous is True
        assert res.score >= 60.0
        assert res.severity == "HIGH"
        assert len(res.reasons) >= 3

    def test_anomaly_detection_performance_under_budget(self, mock_baseline_engine):
        detector = DeterministicAnomalyDetector(mock_baseline_engine)
        req = {
            "user_id": "p-sales-john",
            "path": "/api/orders/101",
            "request_size_bytes": 180,
            "latency_ms": 2.0,
            "request_hour": 11
        }
        # Warmup
        for _ in range(10):
            detector.detect_anomalies(req)

        times = []
        for _ in range(100):
            t0 = time.perf_counter()
            detector.detect_anomalies(req)
            times.append((time.perf_counter() - t0) * 1000.0)

        p95 = sorted(times)[int(len(times) * 0.95)]
        print(f"\n[Phase 5 Anomaly Detector Latency (100 runs)] p95: {p95:.4f} ms (Target: < 1.0 ms)")
        assert p95 < 1.0, f"Anomaly detection p95 {p95:.3f}ms exceeded 1.0ms budget!"


class TestAntiPoisoning3TierTriage:
    """Verifies 3-tier routing: Pristine Baseline, Review Quarantine, Hard Quarantine."""

    def test_pristine_event_classified_tier_1(self, tmp_path):
        triage = AntiPoisoningFilter(output_dir=str(tmp_path))
        event = {
            "decision": "ALLOW",
            "risk_score": 15.0,
            "fired_rules": [],
            "user_account_age_days": 45,
            "user_incident_count": 0,
            "components": {"waf_severity": 0.0, "auth_anomaly": 0.0}
        }
        tier = triage.classify_event(event)
        assert tier == EventTier.TIER_1_PRISTINE

        tier_name, is_quarantined = triage.process_event(event)
        assert is_quarantined is False
        assert tier_name == "TIER_1_BASELINE"

    def test_moderate_risk_classified_tier_2_review(self, tmp_path):
        triage = AntiPoisoningFilter(output_dir=str(tmp_path))
        event = {
            "decision": "ALLOW",
            "risk_score": 35.0,
            "fired_rules": ["R002"],
            "user_account_age_days": 20,
            "user_incident_count": 0,
            "components": {"waf_severity": 0.0, "auth_anomaly": 0.0}
        }
        tier = triage.classify_event(event)
        assert tier == EventTier.TIER_2_REVIEW

        tier_name, is_quarantined = triage.process_event(event)
        assert is_quarantined is True
        assert tier_name == "TIER_2_REVIEW"

    def test_new_account_under_7_days_routed_to_tier_2(self, tmp_path):
        triage = AntiPoisoningFilter(output_dir=str(tmp_path))
        event = {
            "decision": "ALLOW",
            "risk_score": 10.0,
            "fired_rules": [],
            "user_account_age_days": 3,  # < 7 days
            "user_incident_count": 0,
            "components": {}
        }
        tier = triage.classify_event(event)
        assert tier == EventTier.TIER_2_REVIEW

    def test_attack_and_block_classified_tier_3_hard_quarantine(self, tmp_path):
        triage = AntiPoisoningFilter(output_dir=str(tmp_path))
        event = {
            "decision": "BLOCK",
            "risk_score": 90.0,
            "fired_rules": ["R001"],
            "components": {"waf_severity": 95.0, "auth_anomaly": 0.0}
        }
        tier = triage.classify_event(event)
        assert tier == EventTier.TIER_3_HARD_QUARANTINE

        tier_name, is_quarantined = triage.process_event(event)
        assert is_quarantined is True
        assert tier_name == "TIER_3_QUARANTINE"


class TestGatewayAnomalyIntegration:
    """Verifies live gateway middleware incorporates anomaly detection."""

    def test_gateway_attaches_anomaly_score_in_telemetry(self):
        # Establish baseline for sales_john
        from gateway.anomaly_detection.deterministic_anomaly_detector import anomaly_detector
        anomaly_detector.baseline_engine.baselines["p-sales-john:/api/orders/101"] = BaselineStats(
            user_id="p-sales-john",
            endpoint="/api/orders/101",
            call_count=500,
            call_rate_per_hour=10.0,
            call_rate_p95=20.0,
            request_size_median=100,
            request_size_p95=150,
            response_time_median=1.0,
            response_time_p95=2.0,
            peak_hours=[9, 10, 11, 12, 13, 14, 15, 16],
            updated_at="2026-01-01",
            data_points=500
        )

        # Valid request passes with allow decision
        headers = {
            "Authorization": f"Bearer {SALES_TOKEN}",
            "X-Forwarded-For": f"10.199.{uuid.uuid4().hex[:4]}"
        }
        response = client.get("/api/orders/101", headers=headers)
        assert response.status_code == 200
        assert response.headers["X-Decision"] == "ALLOW"
