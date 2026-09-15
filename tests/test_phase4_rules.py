import time
import uuid
import json
import base64
import statistics
import pytest
from fastapi.testclient import TestClient
from gateway.app import app
from gateway.rules_engine import RulesEngine, rules_engine

client = TestClient(app, raise_server_exceptions=False)

def make_jwt(sub: str, role: str, exp_offset: int = 3600) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({
        "sub": sub,
        "role": role,
        "exp": int(time.time()) + exp_offset
    }).encode()).decode().rstrip("=")
    sig = base64.urlsafe_b64encode(b"simulated_mock_cryptographic_signature").decode().rstrip("=")
    return f"{header}.{payload}.{sig}"

SALES_TOKEN = make_jwt("sales_john", "sales")
ADMIN_TOKEN = make_jwt("admin", "admin")

class TestDeterministicRulesUnit:
    """Unit tests for explicit business logic rules."""

    def test_negative_price_blocked(self):
        """Negative price should trigger R001."""
        engine = RulesEngine()
        request_data = {
            "method": "POST",
            "path": "/api/orders",
            "body": {
                "customer_id": "cust-123",
                "items": [
                    {"product_id": 1, "name": "Industrial Widget A", "quantity": 5, "price": -100.0}
                ],
                "total_amount": 100.0
            }
        }
        severity, fired_rules = engine.evaluate(request_data)
        assert "R001" in fired_rules
        assert severity >= 80

    def test_negative_total_amount_blocked(self):
        """Negative total amount should trigger R001."""
        engine = RulesEngine()
        request_data = {
            "method": "POST",
            "path": "/api/orders",
            "body": {
                "customer_id": "cust-123",
                "items": ["Industrial Widget A"],
                "total_amount": -50.0
            }
        }
        severity, fired_rules = engine.evaluate(request_data)
        assert "R001" in fired_rules
        assert severity == 100

    def test_role_escalation_blocked(self):
        """Non-admin cannot grant themselves admin role (R004)."""
        engine = RulesEngine()
        request_data = {
            "method": "POST",
            "path": "/api/users/456",
            "body": {"role": "admin"},
            "user_id": "456",
            "current_role": "sales"
        }
        severity, fired_rules = engine.evaluate(request_data)
        assert "R004" in fired_rules
        assert severity == 100

    def test_duplicate_order_detected(self):
        """Submitting identical order twice within 5 seconds triggers R002."""
        engine = RulesEngine()
        engine.reset_state()
        
        request_data = {
            "method": "POST",
            "path": "/api/orders",
            "user_id": "client-user-999",
            "is_authenticated": True,
            "body": {
                "customer_id": "cust-999",
                "items": ["Bearing Assembly"],
                "total_amount": 250.0
            }
        }

        # First execution: clean
        sev1, fired1 = engine.evaluate(request_data)
        assert "R002" not in fired1
        assert sev1 == 0

        # Immediate duplicate execution: triggers R002
        sev2, fired2 = engine.evaluate(request_data)
        assert "R002" in fired2
        assert sev2 == 60

    def test_inventory_depletion_blocked(self):
        """Ordering quantity in excess of warehouse inventory triggers R003."""
        engine = RulesEngine()
        # "Industrial Widget A" has 420 units in stock
        request_data = {
            "method": "POST",
            "path": "/api/orders",
            "body": {
                "customer_id": "cust-456",
                "items": [
                    {"name": "Industrial Widget A", "quantity": 500, "price": 10.0}
                ],
                "total_amount": 5000.0
            }
        }
        severity, fired_rules = engine.evaluate(request_data)
        assert "R003" in fired_rules
        assert severity >= 80

    def test_sequence_violation_unauthenticated_order(self):
        """POST /api/orders without authentication triggers R005."""
        engine = RulesEngine()
        request_data = {
            "method": "POST",
            "path": "/api/orders",
            "body": {"customer_id": "cust-1", "items": ["Item A"], "total_amount": 50.0},
            "is_authenticated": False,
            "user_id": None
        }
        severity, fired_rules = engine.evaluate(request_data)
        assert "R005" in fired_rules
        assert severity == 75

    def test_legitimate_order_passes_cleanly(self):
        """Normal valid order does not trigger any deterministic rules."""
        engine = RulesEngine()
        engine.reset_state()
        request_data = {
            "method": "POST",
            "path": "/api/orders",
            "user_id": "sales_john",
            "current_role": "sales",
            "is_authenticated": True,
            "body": {
                "customer_id": "cust-123",
                "items": [
                    {"name": "Industrial Widget A", "quantity": 5, "price": 99.99}
                ],
                "total_amount": 499.95
            }
        }
        severity, fired_rules = engine.evaluate(request_data)
        assert len(fired_rules) == 0
        assert severity == 0

class TestConfigDrivenHotReload:
    """Verifies that rules are loaded from YAML config and support hot-reloading."""

    def test_rules_loaded_from_yaml(self):
        engine = RulesEngine("config/rules.yaml")
        assert len(engine.rules) >= 6
        rule_ids = [r.rule_id for r in engine.rules]
        assert "R001" in rule_ids
        assert "R002" in rule_ids
        assert "R003" in rule_ids
        assert "R004" in rule_ids
        assert "R005" in rule_ids
        assert "R006" in rule_ids

    def test_hot_reload_functionality(self, tmp_path):
        custom_yaml = tmp_path / "custom_rules.yaml"
        custom_yaml.write_text("""
rules:
  - rule_id: "R999"
    category: "business_logic"
    description: "Custom test rule"
    severity: 88
    check_type: "negative_price"
    remediation: "block"
""", encoding="utf-8")

        engine = RulesEngine(str(custom_yaml))
        assert len(engine.rules) == 1
        assert engine.rules[0].rule_id == "R999"
        assert engine.rules[0].severity == 88

class TestGatewayRulesIntegration:
    """Verifies end-to-end enforcement through the FastAPI Gateway middleware."""

    def test_gateway_blocks_negative_amount_order(self):
        # Order with negative amount is blocked by rules engine and schema validation
        response = client.post(
            "/api/orders",
            headers={"Authorization": f"Bearer {SALES_TOKEN}"},
            json={
                "customer_id": "cust-888",
                "items": ["Industrial Widget A"],
                "total_amount": -150.0
            }
        )
        assert response.status_code in [403, 422]
        assert response.headers["X-Decision"] == "BLOCK"

    def test_gateway_blocks_inventory_depletion_order(self):
        rules_engine.reset_state()
        # Item format "SKU-9901:500" exceeds available stock of 420
        response = client.post(
            "/api/orders",
            headers={"Authorization": f"Bearer {SALES_TOKEN}"},
            json={
                "customer_id": "cust-888",
                "items": ["SKU-9901:500"],
                "total_amount": 5000.0
            }
        )
        assert response.status_code == 403
        data = response.json()
        assert data["error"] == "Forbidden"
        assert any("exceeds available warehouse stock" in r for r in data["reasons"])

    def test_gateway_challenges_or_blocks_duplicate_order(self):
        rules_engine.reset_state()
        order_payload = {
            "customer_id": "cust-dupe-test",
            "items": ["Industrial Widget A"],
            "total_amount": 120.0
        }
        headers = {"Authorization": f"Bearer {SALES_TOKEN}"}

        # First request succeeds
        resp1 = client.post("/api/orders", headers=headers, json=order_payload)
        assert resp1.status_code == 200

        # Duplicate immediate request triggers R002 (elevates risk score)
        resp2 = client.post("/api/orders", headers=headers, json=order_payload)
        assert resp2.headers["X-Decision"] in ["CHALLENGE", "LIMIT", "BLOCK"]
        data = resp2.json()
        if "reasons" in data:
            assert any("Duplicate order" in r for r in data["reasons"])

    def test_gateway_allows_valid_order(self):
        rules_engine.reset_state()
        order_payload = {
            "customer_id": f"cust-clean-{uuid.uuid4().hex[:6]}",
            "items": ["Industrial Widget A"],
            "total_amount": 95.50
        }
        headers = {
            "Authorization": f"Bearer {SALES_TOKEN}",
            "X-Forwarded-For": f"10.201.{uuid.uuid4().hex[:4]}"
        }

        response = client.post("/api/orders", headers=headers, json=order_payload)
        assert response.status_code == 200
        assert response.headers["X-Decision"] == "ALLOW"


class TestRulesLatencyImpact:
    """Benchmark verifying deterministic rule engine adds < 2ms overhead."""

    def test_rule_evaluation_latency_under_budget(self):
        engine = RulesEngine()
        sample_request = {
            "method": "POST",
            "path": "/api/orders",
            "user_id": "sales_john",
            "current_role": "sales",
            "is_authenticated": True,
            "body": {
                "customer_id": "cust-perf-1",
                "items": [
                    {"name": "Industrial Widget A", "quantity": 2, "price": 45.0}
                ],
                "total_amount": 90.0
            }
        }

        # Warm-up
        for _ in range(10):
            engine.evaluate(sample_request)

        latencies = []
        for _ in range(100):
            t0 = time.perf_counter()
            engine.evaluate(sample_request)
            latencies.append((time.perf_counter() - t0) * 1000.0)

        p50 = statistics.median(latencies)
        p95 = sorted(latencies)[int(len(latencies) * 0.95)]
        
        print(f"\n[Phase 4 Rule Engine Latency Benchmark (100 runs)]")
        print(f"  p50: {p50:.4f} ms")
        print(f"  p95: {p95:.4f} ms (Target: < 2.0 ms)")

        assert p95 < 2.0, f"Rule engine p95 latency {p95:.3f}ms exceeded 2.0ms budget!"
