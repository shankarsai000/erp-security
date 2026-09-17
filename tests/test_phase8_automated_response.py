"""Phase 8: Automated Response & Active Mitigation Engine Test Suite.

Verifies:
1. Automated safe, reversible containment (Rate limiting, MFA challenges, session revocation, temporary IP quarantine < 1hr).
2. Strict Human Approval Gates: High-impact actions (account suspension) CANNOT be autonomously applied.
3. Clean TTL auto-expiry for temporary mitigations.
4. Sub-second programmatic rollback (< 30 seconds SLA).
5. Gateway middleware live enforcement and low-latency execution (< 0.5ms per evaluation).
"""

import datetime
import time
import pytest
from fastapi.testclient import TestClient

from agents.base import ActionType, AgentAction, ApprovalStatus
from agents.detection_agent import SecurityAlert
from agents.investigation_agent import InvestigationReport
from agents.orchestrator import SecurityOrchestrator
from gateway.app import app, mitigation_engine, security_orchestrator
from gateway.auth_engine import auth_engine
from gateway.mitigation_engine import (
    MitigationDecision,
    MitigationEngine,
    UnauthorizedMitigationError
)


@pytest.fixture
def clean_engine():
    """Provides a fresh, isolated MitigationEngine."""
    return MitigationEngine()


@pytest.fixture
def test_jwt():
    """Generates a valid JWT token for authenticated gateway testing."""
    return auth_engine.generate_token(
        principal_id="analyst_test_user",
        roles=["analyst"],
        expires_in_seconds=3600
    )


class TestMitigationEngineUnit:
    """Unit tests for the active mitigation registry, policies, and invariants."""

    def test_automated_ip_quarantine_application_and_evaluation(self, clean_engine):
        action = AgentAction(
            action_id="act-quarantine-01",
            action_type=ActionType.QUARANTINE_IP_TEMP,
            target_entity="198.51.100.44",
            duration_seconds=1800,
            justification="Automated threat containment for scanner probe",
            approval_status=ApprovalStatus.AUTO_APPROVED,
            reversible=True
        )

        applied = clean_engine.apply_action(action)
        assert applied is True
        assert "198.51.100.44" in clean_engine.quarantined_ips

        # Evaluate incoming request from quarantined IP
        decision = clean_engine.evaluate_request(client_ip="198.51.100.44")
        assert decision.is_mitigated is True
        assert decision.action == ActionType.QUARANTINE_IP_TEMP
        assert decision.http_status == 403
        assert "Retry-After" in decision.headers
        assert int(decision.headers["Retry-After"]) > 0

        # Non-quarantined IP is allowed
        clean_decision = clean_engine.evaluate_request(client_ip="10.0.0.5")
        assert clean_decision.is_mitigated is False

    def test_automated_ip_quarantine_enforces_max_duration_cap(self, clean_engine):
        # Even if an agent requests 24 hours, engine must cap to MAX_AUTO_QUARANTINE_SECONDS (1 hour)
        action = AgentAction(
            action_id="act-quarantine-oversized",
            action_type=ActionType.QUARANTINE_IP_TEMP,
            target_entity="198.51.100.55",
            duration_seconds=86400,  # 24 hours requested
            justification="Aggressive containment",
            approval_status=ApprovalStatus.AUTO_APPROVED
        )

        clean_engine.apply_action(action)
        quarantine_info = clean_engine.quarantined_ips["198.51.100.55"]
        now = datetime.datetime.now(datetime.timezone.utc)
        diff_seconds = (quarantine_info["until"] - now).total_seconds()
        assert diff_seconds <= clean_engine.MAX_AUTO_QUARANTINE_SECONDS + 5

    def test_token_and_session_revocation(self, clean_engine):
        action = AgentAction(
            action_id="act-revoke-token-01",
            action_type=ActionType.REVOKE_SESSION,
            target_entity="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token_payload_xyz",
            justification="Compromised credential revocation",
            approval_status=ApprovalStatus.AUTO_APPROVED
        )

        clean_engine.apply_action(action)
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token_payload_xyz" in clean_engine.revoked_tokens

        decision = clean_engine.evaluate_request(
            client_ip="10.0.0.1",
            auth_token="Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.token_payload_xyz"
        )
        assert decision.is_mitigated is True
        assert decision.action == ActionType.REVOKE_SESSION
        assert decision.http_status == 401
        assert "WWW-Authenticate" in decision.headers

    def test_mfa_challenge_enforcement(self, clean_engine):
        action = AgentAction(
            action_id="act-mfa-01",
            action_type=ActionType.CHALLENGE_MFA,
            target_entity="suspect_user_01",
            duration_seconds=600,
            justification="Step-up authentication required",
            approval_status=ApprovalStatus.AUTO_APPROVED
        )

        clean_engine.apply_action(action)
        decision = clean_engine.evaluate_request(
            client_ip="10.0.0.1",
            principal_ref="suspect_user_01"
        )
        assert decision.is_mitigated is True
        assert decision.action == ActionType.CHALLENGE_MFA
        assert decision.http_status == 403
        assert decision.headers.get("X-MFA-Required") == "true"

    def test_high_risk_action_blocks_unauthorized_autonomous_execution(self, clean_engine):
        # Autonomous agent attempts to suspend account without human approval
        unapproved_action = AgentAction(
            action_id="act-unauth-suspend",
            action_type=ActionType.SUSPEND_ACCOUNT,
            target_entity="vip_customer",
            justification="Autonomous suspension attempt",
            approval_status=ApprovalStatus.PENDING_HUMAN_APPROVAL
        )

        with pytest.raises(UnauthorizedMitigationError) as exc_info:
            clean_engine.apply_action(unapproved_action)

        assert "requires explicit human approval" in str(exc_info.value)
        assert "vip_customer" not in clean_engine.suspended_accounts

    def test_human_approved_account_suspension(self, clean_engine):
        approved_action = AgentAction(
            action_id="act-auth-suspend-01",
            action_type=ActionType.SUSPEND_ACCOUNT,
            target_entity="rogue_contractor",
            justification="Confirmed data exfiltration incident",
            approval_status=ApprovalStatus.APPROVED,
            approved_by="senior_soc_lead"
        )

        applied = clean_engine.apply_action(approved_action)
        assert applied is True
        assert "rogue_contractor" in clean_engine.suspended_accounts

        decision = clean_engine.evaluate_request(
            client_ip="10.0.0.99",
            principal_ref="rogue_contractor"
        )
        assert decision.is_mitigated is True
        assert decision.action == ActionType.SUSPEND_ACCOUNT
        assert decision.http_status == 403
        assert "suspended by security policy" in decision.reason

    def test_ttl_auto_expiry(self, clean_engine):
        # Manually create an expired mitigation entry
        expired_time = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=10)
        clean_engine.quarantined_ips["198.51.100.9"] = {
            "until": expired_time,
            "reason": "Old quarantine",
            "action_id": "act-expired-1"
        }

        # Evaluating request should detect expiration, purge entry, and allow traffic
        decision = clean_engine.evaluate_request(client_ip="198.51.100.9")
        assert decision.is_mitigated is False
        assert "198.51.100.9" not in clean_engine.quarantined_ips

    def test_instant_programmatic_rollback(self, clean_engine):
        action = AgentAction(
            action_id="act-rollback-test",
            action_type=ActionType.QUARANTINE_IP_TEMP,
            target_entity="198.51.100.77",
            duration_seconds=900,
            justification="Containment testing",
            approval_status=ApprovalStatus.AUTO_APPROVED
        )

        clean_engine.apply_action(action)
        assert clean_engine.evaluate_request("198.51.100.77").is_mitigated is True

        # Perform instant rollback
        start = time.perf_counter()
        revoked = clean_engine.rollback_action("act-rollback-test")
        rollback_elapsed_ms = (time.perf_counter() - start) * 1000

        assert revoked is True
        assert rollback_elapsed_ms < 10.0  # Must be sub-millisecond, SLA is < 30 seconds
        assert clean_engine.evaluate_request("198.51.100.77").is_mitigated is False

    def test_evaluation_performance_under_budget(self, clean_engine):
        # Warm up engine with 100 active mitigations
        for i in range(100):
            clean_engine.quarantined_ips[f"198.51.100.{i}"] = {
                "until": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=30),
                "reason": "Test load",
                "action_id": f"act-load-{i}"
            }

        # Run 5,000 evaluations
        start = time.perf_counter()
        for i in range(5000):
            clean_engine.evaluate_request(f"198.51.100.{i % 150}", principal_ref=f"user_{i % 50}")
        elapsed_sec = time.perf_counter() - start
        avg_eval_micros = (elapsed_sec / 5000) * 1_000_000

        # Latency budget: < 500 microseconds (0.5ms) per evaluation
        assert avg_eval_micros < 500.0


class TestOrchestratorMitigationIntegration:
    """Tests end-to-end coordination between SecurityOrchestrator and MitigationEngine."""

    def test_orchestrator_applies_auto_containment_to_mitigation_engine(self, clean_engine):
        orchestrator = SecurityOrchestrator(
            audit_file="events/agent_audit.jsonl",
            mitigation_engine=clean_engine
        )

        # Feed mass scraping pattern to trigger auto-quarantine
        history = [
            {"path": f"/api/orders/{i}", "method": "GET", "timestamp": "2026-09-17T12:00:00+00:00"}
            for i in range(10)
        ]
        curr = {
            "request_id": "req-scraping-trigger",
            "timestamp": "2026-09-17T12:00:05+00:00",
            "client_ip": "203.0.113.88",
            "principal_ref": "crawler_bot",
            "path": "/api/orders/11",
            "method": "GET",
            "decision": "ALLOW",
            "risk_score": 60.0
        }

        plan = orchestrator.process_security_event(curr, history)
        assert plan is not None
        assert len(plan.auto_executed_actions) > 0

        # Verify mitigation engine immediately received active quarantine
        assert ("203.0.113.88" in clean_engine.quarantined_ips) or ("crawler_bot" in clean_engine.quarantined_ips)
        decision = clean_engine.evaluate_request("203.0.113.88", principal_ref="crawler_bot")
        assert decision.is_mitigated is True

    def test_orchestrator_human_approval_promotes_to_active_mitigation(self, clean_engine):
        orchestrator = SecurityOrchestrator(
            audit_file="events/agent_audit.jsonl",
            mitigation_engine=clean_engine
        )

        # Trigger privilege escalation alert requiring human approval
        curr = {
            "request_id": "req-priv-esc",
            "timestamp": "2026-09-17T12:00:00+00:00",
            "client_ip": "10.0.1.50",
            "principal_ref": "insider_threat_user",
            "path": "/api/users/1",
            "method": "POST",
            "fired_rules": ["R004"],
            "decision": "BLOCK",
            "risk_score": 100.0
        }

        plan = orchestrator.process_security_event(curr, [])
        assert plan is not None
        assert len(plan.pending_human_actions) > 0

        pending_action = plan.pending_human_actions[0]
        assert pending_action.action_type == ActionType.SUSPEND_ACCOUNT

        # Account is NOT yet suspended in mitigation engine
        assert "insider_threat_user" not in clean_engine.suspended_accounts

        # Human Analyst approves the action
        approved_result = orchestrator.approve_action(pending_action.action_id, analyst_id="senior_soc_analyst")
        assert approved_result["approval_status"] in ("approved", "executed")

        # Now active in mitigation engine
        assert "insider_threat_user" in clean_engine.suspended_accounts
        decision = clean_engine.evaluate_request("10.0.1.50", principal_ref="insider_threat_user")
        assert decision.is_mitigated is True
        assert decision.action == ActionType.SUSPEND_ACCOUNT

        # Analyst revokes account suspension -> instantly removed from mitigation engine
        revoked_result = orchestrator.revoke_action(pending_action.action_id, analyst_id="senior_soc_analyst")
        assert revoked_result["approval_status"].lower() == "revoked"
        assert "insider_threat_user" not in clean_engine.suspended_accounts

        # Analyst also revokes the auto-executed temporary quarantine to completely restore user
        for auto_act in plan.auto_executed_actions:
            orchestrator.revoke_action(auto_act.action_id, analyst_id="senior_soc_analyst")

        assert clean_engine.evaluate_request("10.0.1.50", principal_ref="insider_threat_user").is_mitigated is False


class TestGatewayActiveMitigationEnforcement:
    """Tests live Gateway HTTP enforcement via TestClient."""

    @pytest.fixture(autouse=True)
    def reset_gateway_mitigations(self):
        """Cleans up global mitigation engine before each test."""
        mitigation_engine.quarantined_ips.clear()
        mitigation_engine.revoked_tokens.clear()
        mitigation_engine.revoked_principals.clear()
        mitigation_engine.mfa_enforced_principals.clear()
        mitigation_engine.dynamic_rate_limits.clear()
        mitigation_engine.suspended_accounts.clear()
        mitigation_engine._action_registry.clear()
        yield
        mitigation_engine.quarantined_ips.clear()
        mitigation_engine.suspended_accounts.clear()

    def test_gateway_mitigations_status_endpoint(self):
        client = TestClient(app)
        res = client.get("/api/mitigations/status")
        assert res.status_code == 200
        data = res.json()
        assert "active_quarantined_ips" in data
        assert "total_mitigations_enforced" in data

    def test_live_gateway_blocks_quarantined_ip(self, test_jwt):
        client = TestClient(app)

        # Pre-quarantine an IP
        action = AgentAction(
            action_id="act-live-ip-01",
            action_type=ActionType.QUARANTINE_IP_TEMP,
            target_entity="198.51.100.123",
            duration_seconds=600,
            justification="Automated quarantine for malicious probing",
            approval_status=ApprovalStatus.AUTO_APPROVED
        )
        mitigation_engine.apply_action(action)

        # Send request from quarantined IP
        res = client.get(
            "/api/orders",
            headers={
                "X-Forwarded-For": "198.51.100.123",
                "Authorization": f"Bearer {test_jwt}"
            }
        )
        assert res.status_code == 403
        data = res.json()
        assert data["mitigation_action"] == "QUARANTINE_IP_TEMP"
        assert "quarantined due to automated threat containment" in data["message"]
        assert "Retry-After" in res.headers

    def test_live_gateway_rejects_revoked_session_token(self, test_jwt):
        client = TestClient(app)

        # Revoke the specific JWT token
        action = AgentAction(
            action_id="act-live-token-01",
            action_type=ActionType.REVOKE_SESSION,
            target_entity=test_jwt,
            justification="Session invalidated due to suspicious activity",
            approval_status=ApprovalStatus.AUTO_APPROVED
        )
        mitigation_engine.apply_action(action)

        # Attempt to access protected ERP API with revoked token
        res = client.get(
            "/api/orders",
            headers={"Authorization": f"Bearer {test_jwt}"}
        )
        assert res.status_code == 401
        data = res.json()
        assert data["mitigation_action"] == "REVOKE_SESSION"
        assert "revoked by security response" in data["message"]

    def test_live_gateway_enforces_human_approved_suspension(self):
        client = TestClient(app)

        # Generate token for suspended user
        suspended_jwt = auth_engine.generate_token(
            principal_id="compromised_worker_7",
            roles=["warehouse_staff"],
            expires_in_seconds=3600
        )

        # Stage human-approved suspension
        action = AgentAction(
            action_id="act-live-suspend-01",
            action_type=ActionType.SUSPEND_ACCOUNT,
            target_entity="compromised_worker_7",
            justification="Exfiltration detected by SOC",
            approval_status=ApprovalStatus.APPROVED,
            approved_by="soc_lead_01"
        )
        mitigation_engine.apply_action(action)

        # Attempt to access API with suspended principal's token
        res = client.get(
            "/api/inventory",
            headers={"Authorization": f"Bearer {suspended_jwt}"}
        )
        assert res.status_code == 403
        data = res.json()
        assert data["mitigation_action"] == "SUSPEND_ACCOUNT"
        assert "suspended by security policy" in data["message"]

        # Instant rollback via API endpoint
        mitigation_engine.rollback_action("act-live-suspend-01")

        # After rollback, access should no longer be blocked by suspension
        res_after = client.get(
            "/api/inventory",
            headers={"Authorization": f"Bearer {suspended_jwt}"}
        )
        # Should now proceed beyond the suspension check
        assert res_after.status_code in (200, 404, 502)  # May hit mock backend or succeed
