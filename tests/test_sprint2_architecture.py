"""
Sprint 2 Architecture, Scalability & Object-Level Authorization Tests.

Validates:
- ARCH-01: Ephemeral in-memory state to shared storage / distributed readiness.
- SEC-06: Broken Object-Level Authorization (BOLA/IDOR) on order reading and creation.
- COMP-01: Accurate compliance terminology and third-party audit disclaimers.
"""

import time
import uuid
import pytest
from fastapi.testclient import TestClient

from agents.base import ActionType, AgentAction, ApprovalStatus
from gateway.app import app
from gateway.auth_engine import auth_engine
from gateway.compliance import compliance_reporter, tamper_evident_audit_chain
from gateway.mitigation_engine import MitigationEngine
from gateway.replay_guard import ReplayGuard
from gateway.state_store import DistributedStateStore, InMemoryStateStore, state_store


@pytest.fixture
def customer_token_cust882():
    return auth_engine.generate_token(principal_id="cust-882", roles=["customer"], expires_in_seconds=3600)


@pytest.fixture
def customer_token_cust941():
    return auth_engine.generate_token(principal_id="cust-941", roles=["customer"], expires_in_seconds=3600)


@pytest.fixture
def sales_token():
    return auth_engine.generate_token(principal_id="sales_john", roles=["sales"], expires_in_seconds=3600)


@pytest.fixture
def admin_token():
    return auth_engine.generate_token(principal_id="admin", roles=["admin"], expires_in_seconds=3600)


class TestARCH01DistributedStateStore:
    """ARCH-01: Proves distributed state synchronization and graceful fallback."""

    def test_atomic_nonce_prevents_replays(self):
        store = DistributedStateStore()
        nonce = f"test-nonce-{uuid.uuid4().hex}"

        # First attempt must succeed
        assert store.set_nonce_nx(nonce, ttl_seconds=60) is True

        # Second attempt with same nonce must fail (replay blocked)
        assert store.set_nonce_nx(nonce, ttl_seconds=60) is False

    def test_shared_state_synchronization_across_instances(self):
        """Simulates two distinct gateway pod instances backed by a shared state store."""
        shared_backend = InMemoryStateStore()
        pod1_store = DistributedStateStore()
        pod1_store.fallback = shared_backend

        pod2_store = DistributedStateStore()
        pod2_store.fallback = shared_backend

        # Pod 1 revokes a compromised session token
        compromised_token = f"comp-tok-{uuid.uuid4().hex}"
        engine_pod1 = MitigationEngine(state_store=pod1_store)
        action = AgentAction(
            action_id=f"act-rev-{uuid.uuid4().hex[:6]}",
            action_type=ActionType.REVOKE_SESSION,
            target_entity=compromised_token,
            justification="Credential leak detected",
            approval_status=ApprovalStatus.APPROVED
        )
        engine_pod1.apply_action(action)

        # Pod 2 must immediately recognize the revocation
        engine_pod2 = MitigationEngine(state_store=pod2_store)
        decision = engine_pod2.evaluate_request(
            client_ip="192.168.1.100",
            auth_token=f"Bearer {compromised_token}"
        )
        assert decision.is_mitigated is True
        assert decision.http_status == 401
        assert "revoked" in decision.reason.lower()

    def test_in_memory_graceful_fallback_when_redis_unavailable(self):
        """When Redis host is unreachable, gateway operates with zero downtime using local fallback."""
        # Non-routable dummy IP
        offline_store = DistributedStateStore(redis_host="192.0.2.1", redis_timeout=0.01)
        nonce = f"offline-nonce-{uuid.uuid4().hex}"

        # Must succeed via fallback without raising exception
        assert offline_store.set_nonce_nx(nonce, ttl_seconds=60) is True
        assert offline_store.set_nonce_nx(nonce, ttl_seconds=60) is False

    def test_replay_guard_uses_state_store(self):
        shared_store = DistributedStateStore()
        guard = ReplayGuard(max_skew_seconds=300, state_store=shared_store)
        key = f"idemp-guard-{uuid.uuid4().hex}"

        is_rep1, score1, reasons1 = guard.validate_request(idempotency_key=key)
        assert is_rep1 is False
        assert score1 == 0

        # Duplicate replay attempt
        is_rep2, score2, reasons2 = guard.validate_request(idempotency_key=key)
        assert is_rep2 is True
        assert score2 == 95
        assert "replay detected" in reasons2[0].lower()


class TestSEC06ObjectLevelAuthorization:
    """SEC-06: Proves BOLA/IDOR protection on /api/orders/{id} and /api/orders."""

    def test_customer_cannot_read_another_customer_order(self, customer_token_cust941):
        """Customer 'cust-941' attempting to view order 101 (owned by 'cust-882') is blocked."""
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get(
                "/api/orders/101",
                headers={"Authorization": f"Bearer {customer_token_cust941}"}
            )
            assert resp.status_code == 403
            data = resp.json()
            assert data.get("error") == "Forbidden"
            assert any("BOLA violation" in r for r in data.get("reasons", []))

    def test_customer_can_read_own_order(self, customer_token_cust941):
        """Customer 'cust-941' viewing order 102 (owned by 'cust-941') is permitted."""
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get(
                "/api/orders/102",
                headers={"Authorization": f"Bearer {customer_token_cust941}"}
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["order"]["order_id"] == 102
            assert data["order"]["customer_id"] == "cust-941"

    def test_customer_cannot_create_order_for_another_customer(self, customer_token_cust941):
        """Customer 'cust-941' submitting an order billed to 'cust-882' is rejected with 403."""
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post(
                "/api/orders",
                headers={
                    "Authorization": f"Bearer {customer_token_cust941}",
                    "Idempotency-Key": f"idemp-idor-{uuid.uuid4().hex}"
                },
                json={
                    "customer_id": "cust-882",  # Spoofed victim customer ID
                    "items": ["Bearing Assembly"],
                    "total_amount": 350.0
                }
            )
            assert resp.status_code == 403
            data = resp.json()
            assert any("BOLA violation" in r for r in data.get("reasons", []))

    def test_customer_can_create_order_for_self(self, customer_token_cust941):
        """Customer 'cust-941' submitting an order with their own customer ID succeeds."""
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post(
                "/api/orders",
                headers={
                    "Authorization": f"Bearer {customer_token_cust941}",
                    "Idempotency-Key": f"idemp-legit-{uuid.uuid4().hex}"
                },
                json={
                    "customer_id": "cust-941",
                    "items": ["Hydraulic Pump v2"],
                    "total_amount": 5890.0
                }
            )
            assert resp.status_code == 200

    def test_staff_and_admin_have_cross_tenant_access(self, sales_token, admin_token):
        """Sales and Admin users can view any order for operational fulfillments."""
        with TestClient(app, raise_server_exceptions=False) as client:
            # Sales viewing order 101
            resp_sales = client.get("/api/orders/101", headers={"Authorization": f"Bearer {sales_token}"})
            assert resp_sales.status_code == 200

            # Admin viewing order 102
            resp_admin = client.get("/api/orders/102", headers={"Authorization": f"Bearer {admin_token}"})
            assert resp_admin.status_code == 200


class TestCOMP01AccurateComplianceReporting:
    """COMP-01: Proves compliance reports use precise cryptographic and legal terminology."""

    def test_compliance_report_terminology_and_disclaimer(self):
        report = compliance_reporter.generate_full_compliance_report()

        # 1. Cryptographic algorithm must not falsely claim RFC 6962 Merkle tree
        algo = report["audit_trail_integrity"]["cryptographic_algorithm"]
        assert "RFC 6962" not in algo
        assert algo == "Sequential HMAC-SHA256 Block Chaining"

        # 2. Framework status must state evidence collection rather than formal legal attestation
        for fw_key, fw_data in report["frameworks"].items():
            status = fw_data["status"]
            assert status == "EVIDENCE_COLLECTED_CONTROLS_ACTIVE"
            assert "ATTESTED" not in status

        # 3. Third-party auditor disclaimer must be explicitly present
        assert "audit_disclaimer" in report
        assert "independent third-party auditor" in report["audit_disclaimer"]
