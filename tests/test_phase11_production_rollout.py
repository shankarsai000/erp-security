"""
Phase 11: Production Rollout, Canary Deployment & Enterprise Runbooks Tests.
"""

import pytest
from fastapi.testclient import TestClient

from gateway.app import app, canary_router
from gateway.canary_router import CanaryRouter, CanaryStage, TrafficMetrics


class TestCanaryRouterUnit:
    """Unit tests for the Canary Router core logic."""

    def test_stage_progression_weights(self):
        router = CanaryRouter()
        assert router.stage == CanaryStage.DISABLED
        assert router.weight == 0.0

        router.promote(CanaryStage.CANARY_1)
        assert router.stage == CanaryStage.CANARY_1
        assert router.weight == 0.01

        router.promote(CanaryStage.CANARY_10)
        assert router.stage == CanaryStage.CANARY_10
        assert router.weight == 0.10

        router.promote(CanaryStage.CANARY_50)
        assert router.stage == CanaryStage.CANARY_50
        assert router.weight == 0.50

        router.promote(CanaryStage.FULL_ROLLOUT)
        assert router.stage == CanaryStage.FULL_ROLLOUT
        assert router.weight == 1.00

    def test_custom_weight_setting_and_clamping(self):
        router = CanaryRouter()
        router.set_weight(0.25)
        assert router.weight == 0.25
        assert router.stage == CanaryStage.CANARY_50

        router.set_weight(-0.5)
        assert router.weight == 0.0
        assert router.stage == CanaryStage.DISABLED

        router.set_weight(1.5)
        assert router.weight == 1.0
        assert router.stage == CanaryStage.FULL_ROLLOUT

    def test_header_override_routing(self):
        router = CanaryRouter()
        router.promote(CanaryStage.DISABLED)  # 0% traffic

        # Explicit header forces canary
        assert router.should_route_to_canary(headers={"x-canary-target": "canary"}) is True

        router.promote(CanaryStage.FULL_ROLLOUT)  # 100% traffic
        # Explicit header forces stable
        assert router.should_route_to_canary(headers={"x-canary-target": "stable"}) is False

    def test_sticky_session_deterministic_routing(self):
        router = CanaryRouter()
        router.promote(CanaryStage.CANARY_50)  # 50%

        user_a = "user_alpha_123"
        user_b = "user_bravo_456"

        decision_a_1 = router.should_route_to_canary(user_id=user_a)
        decision_a_2 = router.should_route_to_canary(user_id=user_a)
        assert decision_a_1 == decision_a_2, "Same user ID must produce deterministic sticky decision"

        decision_b_1 = router.should_route_to_canary(user_id=user_b)
        decision_b_2 = router.should_route_to_canary(user_id=user_b)
        assert decision_b_1 == decision_b_2

    def test_traffic_metrics_percentiles_calculation(self):
        metrics = TrafficMetrics(window_size=100)
        # Record 100 latencies: 1ms to 100ms
        for i in range(1, 101):
            metrics.record(latency_ms=float(i), is_error=(i > 95))

        stats = metrics.get_stats()
        assert stats["total_requests"] == 100
        assert stats["window_samples"] == 100
        assert stats["error_rate"] == 0.05  # 5 errors out of 100
        assert stats["p50_latency_ms"] == pytest.approx(50.0, abs=1.0)
        assert stats["p95_latency_ms"] == pytest.approx(95.0, abs=1.0)
        assert stats["p99_latency_ms"] == pytest.approx(99.0, abs=1.0)

    def test_automatic_rollback_on_canary_error_rate_breach(self):
        router = CanaryRouter(
            initial_stage=CanaryStage.CANARY_10,
            max_error_rate=0.05,  # 5% max
            min_eval_samples=20,
            auto_rollback_enabled=True
        )
        assert router.weight == 0.10

        # Send 15 successful requests (under min_eval_samples)
        for _ in range(15):
            router.record_metric(is_canary=True, latency_ms=10.0, status_code=200)
        assert router.stage == CanaryStage.CANARY_10

        # Send 10 failing requests (40% error rate total, well over 5%)
        for _ in range(10):
            router.record_metric(is_canary=True, latency_ms=10.0, status_code=500)

        # Should have automatically rolled back!
        assert router.stage == CanaryStage.ROLLED_BACK
        assert router.weight == 0.0
        assert router.last_rollback_reason is not None
        assert "error rate" in router.last_rollback_reason.lower()

    def test_automatic_rollback_on_canary_p95_latency_breach(self):
        router = CanaryRouter(
            initial_stage=CanaryStage.CANARY_10,
            max_p95_latency_ms=50.0,  # 50ms SLA
            min_eval_samples=20,
            auto_rollback_enabled=True
        )

        # Send 25 canary requests with high latency (120ms)
        for _ in range(25):
            router.record_metric(is_canary=True, latency_ms=120.0, status_code=200)

        assert router.stage == CanaryStage.ROLLED_BACK
        assert router.weight == 0.0
        assert router.last_rollback_reason is not None
        assert "p95 latency" in router.last_rollback_reason.lower()

    def test_manual_rollback_and_promotion_recovery(self):
        router = CanaryRouter(initial_stage=CanaryStage.CANARY_50)
        res = router.rollback(reason="Operator noticed anomaly in downstream logs")

        assert res["status"] == "ROLLED_BACK"
        assert router.stage == CanaryStage.ROLLED_BACK
        assert router.weight == 0.0

        # Recovery promotion
        res2 = router.promote(CanaryStage.CANARY_1)
        assert res2["status"] == "PROMOTED"
        assert router.stage == CanaryStage.CANARY_1
        assert router.weight == 0.01


class TestGatewayCanaryEndpoints:
    """Integration tests for Canary Gateway HTTP Endpoints."""

    @pytest.fixture(autouse=True)
    def reset_canary(self):
        canary_router.promote(CanaryStage.DISABLED)
        yield
        canary_router.promote(CanaryStage.DISABLED)

    def test_canary_status_endpoint(self):
        with TestClient(app) as client:
            resp = client.get("/api/canary/status")
            assert resp.status_code == 200
            data = resp.json()
            assert "stage" in data
            assert "weight" in data
            assert "canary_metrics" in data
            assert "stable_metrics" in data
            assert "slo_limits" in data

    def test_canary_promote_by_stage_and_weight(self):
        with TestClient(app) as client:
            # Promote by stage
            resp = client.post("/api/canary/promote", json={"stage": "CANARY_10%"})
            assert resp.status_code == 200
            assert resp.json()["stage"] == "CANARY_10%"
            assert resp.json()["weight"] == 0.10

            # Promote by custom weight
            resp2 = client.post("/api/canary/promote", json={"weight": 0.35})
            assert resp2.status_code == 200
            assert resp2.json()["weight"] == 0.35

            # Invalid stage returns 400
            resp_err = client.post("/api/canary/promote", json={"stage": "INVALID_STAGE"})
            assert resp_err.status_code == 400

    def test_canary_rollback_endpoint(self):
        with TestClient(app) as client:
            # Promote first
            client.post("/api/canary/promote", json={"stage": "CANARY_50%"})

            # Rollback
            resp = client.post("/api/canary/rollback", json={"reason": "Security Alert triggered"})
            assert resp.status_code == 200
            data = resp.json()
            assert data["status"] == "ROLLED_BACK"
            assert data["current_weight"] == 0.0

            # Verify status is rolled back
            status_resp = client.get("/api/canary/status")
            assert status_resp.json()["stage"] == "ROLLED_BACK"
            assert status_resp.json()["weight"] == 0.0

    def test_gateway_route_header_attachment(self):
        with TestClient(app) as client:
            # Bypass health check to test route tagging
            # Send request with X-Canary-Target header
            resp = client.get("/health/live", headers={"x-canary-target": "canary"})
            assert resp.status_code == 200


class TestProductionReadinessAuditor:
    """Validates that the automated enterprise production readiness audit executes cleanly."""

    def test_production_readiness_audit_100_percent_pass(self):
        from scripts.verify_production_readiness import ProductionAuditor

        auditor = ProductionAuditor()
        passed = auditor.run_all_audits()
        assert passed is True
        assert auditor.passed_phases == 12
        assert auditor.total_phases == 12

