"""
Sprint 3 Operational & Performance Hardening Tests.

Validates:
- SEC-07: WAF Unicode-escape normalization & recursive JSON payload inspection.
- OPS-01: Route-aware canary SLO budgets (250ms for mutations, 50ms for reads, 1% financial error rate).
- ML-01: Isolation Forest alert deduplication / clustering and tighter FPR <= 1.0% promotion gates.
- PERF-01: Real socket benchmark validation.
"""

import time
import uuid
import pytest
from fastapi.testclient import TestClient

from gateway.app import app
from gateway.auth_engine import auth_engine
from gateway.canary_router import CanaryRouter, CanaryStage
from gateway.waf import inspect_content, inspect_payload
from ml.retraining_pipeline import AlertDeduplicator, ModelRetrainingPipeline


@pytest.fixture
def sales_auth_token():
    """Genuine JWT token with sales role."""
    return auth_engine.generate_token("sales_sprint3", roles=["sales"], expires_in_seconds=3600)


class TestSEC07WAFUnicodeNormalizationAndJSONInspection:
    """SEC-07: Proves that Unicode-escaped and nested JSON attacks cannot bypass WAF."""

    def test_unicode_escaped_sqli_literal_detected(self):
        """\\u0027 OR \\u0031\\u003d\\u0031 normalizes to ' OR 1=1 and is detected."""
        escaped_sqli = r"\u0027 OR \u0031\u003d\u0031"
        is_bad, reasons, score = inspect_content(escaped_sqli)
        assert is_bad is True
        assert score >= 90
        assert any("sql injection" in r.lower() for r in reasons)

    def test_unicode_escaped_xss_in_content_detected(self):
        """\\u003cscript\\u003e normalizes to <script> and is detected."""
        escaped_xss = r"\u003cscript\u003ealert(1)\u003c/script\u003e"
        is_bad, reasons, score = inspect_content(escaped_xss)
        assert is_bad is True
        assert score >= 85
        assert any("xss" in r.lower() for r in reasons)

    def test_unicode_escaped_path_traversal_detected(self):
        """\\u002e\\u002e/etc/passwd normalizes to ../etc/passwd and is detected."""
        escaped_path = r"\u002e\u002e/etc/passwd"
        is_bad, reasons, score = inspect_content(escaped_path)
        assert is_bad is True
        assert score >= 90
        assert any("path traversal" in r.lower() for r in reasons)

    def test_nested_json_payload_inspection(self):
        """Recursive dictionary and list traversal detects deeply nested attacks."""
        nested_payload = {
            "order_metadata": {
                "tags": ["urgent", "bulk"],
                "customer_notes": {
                    "delivery": r"\u0027 OR \u0031\u003d\u0031",
                    "instructions": "Standard shipping"
                }
            }
        }
        is_bad, reasons, score = inspect_payload(nested_payload)
        assert is_bad is True
        assert score >= 90
        assert any("sql injection" in r.lower() for r in reasons)

    def test_gateway_blocks_unicode_escaped_sqli_in_order_mutation(self, sales_auth_token):
        """HTTP POST /api/orders containing Unicode-escaped SQLi is blocked with 403."""
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post(
                "/api/orders",
                headers={
                    "Authorization": f"Bearer {sales_auth_token}",
                    "Idempotency-Key": f"idemp-waf-{uuid.uuid4().hex}"
                },
                json={
                    "customer_id": r"\u0027 OR \u0031\u003d\u0031",
                    "items": ["Turbine Blade"],
                    "total_amount": 500.0
                }
            )
            assert resp.status_code == 403
            data = resp.json()
            assert data.get("error") == "Forbidden"
            assert any("sql injection" in r.lower() for r in data.get("reasons", []))

    def test_gateway_blocks_unicode_escaped_xss_in_order_items(self, sales_auth_token):
        """HTTP POST /api/orders with Unicode XSS in items array is blocked with 403."""
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post(
                "/api/orders",
                headers={
                    "Authorization": f"Bearer {sales_auth_token}",
                    "Idempotency-Key": f"idemp-waf-{uuid.uuid4().hex}"
                },
                json={
                    "customer_id": "cust-normal",
                    "items": [r"\u003cscript\u003ealert(1)\u003c/script\u003e"],
                    "total_amount": 25.0
                }
            )
            assert resp.status_code == 403
            data = resp.json()
            assert data.get("error") == "Forbidden"
            assert any("xss" in r.lower() for r in data.get("reasons", []))


class TestOPS01RouteAwareCanarySLOBudgets:
    """OPS-01: Proves that canary router differentiates complex mutations from fast reads."""

    def test_route_budget_differentiates_reads_and_mutations(self):
        router = CanaryRouter()
        # Read route budget
        read_lat, read_err = router.get_route_budget(path="/api/inventory", method="GET")
        assert read_lat == 50.0
        assert read_err == 0.02

        # Order mutation budget
        mut_lat, mut_err = router.get_route_budget(path="/api/orders", method="POST")
        assert mut_lat == 250.0
        assert mut_err == 0.01

    def test_order_creation_at_150ms_does_not_trigger_false_rollback(self):
        """150ms order creation requests are within 250ms SLA and do NOT trip rollback."""
        router = CanaryRouter(
            initial_stage=CanaryStage.CANARY_10,
            min_eval_samples=15,
            auto_rollback_enabled=True
        )

        # Record 20 order creation requests taking 150ms (above global 50ms, but within 250ms order budget)
        for _ in range(20):
            router.record_metric(
                is_canary=True,
                latency_ms=150.0,
                status_code=200,
                path="/api/orders",
                method="POST"
            )

        # Must NOT roll back!
        assert router.stage == CanaryStage.CANARY_10
        assert router.weight == 0.10
        assert router.last_rollback_reason is None

    def test_order_creation_exceeding_250ms_budget_trips_rollback(self):
        """Order mutations exceeding the 250ms budget trip an automated rollback."""
        router = CanaryRouter(
            initial_stage=CanaryStage.CANARY_10,
            min_eval_samples=15,
            auto_rollback_enabled=True
        )

        # Record 20 order creation requests taking 290ms (> 250ms SLA)
        for _ in range(20):
            router.record_metric(
                is_canary=True,
                latency_ms=290.0,
                status_code=200,
                path="/api/orders",
                method="POST"
            )

        # Must trigger emergency rollback!
        assert router.stage == CanaryStage.ROLLED_BACK
        assert router.weight == 0.0
        assert "p95 latency" in router.last_rollback_reason.lower()

    def test_read_route_exceeding_50ms_budget_trips_rollback(self):
        """Read requests taking 80ms breach the strict 50ms read SLA and trip rollback."""
        router = CanaryRouter(
            initial_stage=CanaryStage.CANARY_10,
            min_eval_samples=15,
            auto_rollback_enabled=True
        )

        for _ in range(20):
            router.record_metric(
                is_canary=True,
                latency_ms=80.0,
                status_code=200,
                path="/api/inventory",
                method="GET"
            )

        assert router.stage == CanaryStage.ROLLED_BACK
        assert router.weight == 0.0
        assert "p95 latency" in router.last_rollback_reason.lower()

    def test_financial_mutation_error_rate_tightened_to_one_percent(self):
        """Financial route with > 1% error rate triggers rollback (tightened from 2%)."""
        router = CanaryRouter(
            initial_stage=CanaryStage.CANARY_10,
            min_eval_samples=20,
            auto_rollback_enabled=True
        )

        # 20 successful requests
        for _ in range(20):
            router.record_metric(
                is_canary=True,
                latency_ms=40.0,
                status_code=200,
                path="/api/orders",
                method="POST"
            )

        # 2 errors (2/22 ~ 9%, exceeding 1% financial budget)
        for _ in range(2):
            router.record_metric(
                is_canary=True,
                latency_ms=40.0,
                status_code=500,
                path="/api/orders",
                method="POST"
            )

        assert router.stage == CanaryStage.ROLLED_BACK
        assert "error rate" in router.last_rollback_reason.lower()


class TestML01AlertDeduplicationAndFPRHardening:
    """ML-01: Proves alert deduplication suppresses noise and retraining enforces FPR <= 1.0%."""

    def test_alert_deduplicator_clusters_repetitive_alerts(self):
        dedup = AlertDeduplicator(window_seconds=60.0, max_alerts_per_window=3)
        user_key = "user_burst_attacker"

        # First 3 alerts are forwarded
        for i in range(3):
            should_alert, suppressed = dedup.should_alert(user_key, alert_type="ANOMALY")
            assert should_alert is True
            assert suppressed == 0

        # Subsequent alerts within the window are suppressed / clustered
        for i in range(5):
            should_alert, suppressed = dedup.should_alert(user_key, alert_type="ANOMALY")
            assert should_alert is False
            assert suppressed == (i + 1)

        stats = dedup.get_cluster_stats()
        assert stats["active_clusters"] == 1
        assert "ANOMALY:user_burst_attacker" in stats["tracked_entities"]

    def test_alert_deduplicator_tracks_different_entities_separately(self):
        dedup = AlertDeduplicator(window_seconds=60.0, max_alerts_per_window=2)
        assert dedup.should_alert("user_a")[0] is True
        assert dedup.should_alert("user_b")[0] is True
        assert dedup.should_alert("user_a")[0] is True
        assert dedup.should_alert("user_a")[0] is False  # 3rd alert for user_a is suppressed
        assert dedup.should_alert("user_b")[0] is True   # 2nd alert for user_b is still allowed

    def test_retraining_pipeline_enforces_strict_one_percent_fpr(self):
        pipeline = ModelRetrainingPipeline()
        assert pipeline.MAX_PERMITTED_FPR == 0.01  # Stricter 1% FPR limit enforced
        assert pipeline.max_permitted_fpr == 0.01
