"""
Phase 7 Automated Test Suite: Security Agents
Tests specialized Detection, Threat Intel, Investigation, and Response agents,
enforcing least-privilege roles, strict Human Approval Gates, programmatic rollback,
and audit trails.
"""

from datetime import datetime, timezone
import json
import os
import tempfile
import time
import pytest
from fastapi.testclient import TestClient

from agents.base import (
    AgentRole,
    ActionType,
    ApprovalStatus,
    AgentAction,
    HUMAN_APPROVAL_REQUIRED_ACTIONS
)
from agents.detection_agent import DetectionAgent, SecurityAlert
from agents.threat_intel_agent import ThreatIntelAgent, ThreatIntelEnrichment
from agents.investigation_agent import InvestigationAgent, InvestigationReport, TimelineEvent
from agents.response_agent import ResponseAgent, ResponsePlan
from agents.orchestrator import SecurityOrchestrator
from gateway.app import app


class TestDetectionAgent:
    """Test correlation logic and threat pattern detection in DetectionAgent."""

    def test_detection_agent_credential_stuffing(self):
        agent = DetectionAgent()
        ip = "198.51.100.77"

        # Simulate 5 rapid login attempts with failures
        history = []
        for i in range(5):
            history.append({
                "request_id": f"req-login-{i}",
                "timestamp": f"2026-09-17T10:0{i}:00+00:00",
                "client_ip": ip,
                "path": "/api/auth/login",
                "method": "POST",
                "decision": "BLOCK",
                "status_code": 401
            })

        curr = {
            "request_id": "req-login-final",
            "timestamp": "2026-09-17T10:06:00+00:00",
            "client_ip": ip,
            "path": "/api/auth/login",
            "method": "POST",
            "decision": "BLOCK"
        }

        alert = agent.analyze_event(curr, history)
        assert alert is not None
        assert alert.threat_category == "CREDENTIAL_STUFFING"
        assert alert.severity == "HIGH"
        assert alert.score >= 80.0
        assert alert.target_entity == ip
        assert any("Rapid login velocity" in ev for ev in alert.evidence)

    def test_detection_agent_mass_scraping(self):
        agent = DetectionAgent()
        user = "scraping_bot"

        history = [
            {
                "request_id": f"req-scrape-{i}",
                "timestamp": f"2026-09-17T11:00:{i:02d}+00:00",
                "principal_ref": user,
                "path": f"/api/orders/{100 + i}",
                "method": "GET",
                "decision": "ALLOW"
            }
            for i in range(10)
        ]

        curr = {
            "request_id": "req-scrape-now",
            "timestamp": "2026-09-17T11:00:15+00:00",
            "principal_ref": user,
            "path": "/api/inventory/items",
            "method": "GET",
            "decision": "ALLOW"
        }

        alert = agent.analyze_event(curr, history)
        assert alert is not None
        assert alert.threat_category == "MASS_SCRAPING"
        assert alert.severity == "HIGH"
        assert alert.score >= 70.0

    def test_detection_agent_privilege_escalation(self):
        agent = DetectionAgent()
        user = "sales_user_1"

        curr = {
            "request_id": "req-priv-esc",
            "timestamp": "2026-09-17T12:00:00+00:00",
            "principal_ref": user,
            "path": "/api/users/99",
            "method": "POST",
            "fired_rules": ["R004"],
            "decision": "BLOCK",
            "risk_score": 100.0
        }

        alert = agent.analyze_event(curr, [])
        assert alert is not None
        assert alert.threat_category == "PRIVILEGE_ESCALATION"
        assert alert.severity == "CRITICAL"
        assert alert.score >= 90.0

    def test_detection_agent_compound_anomaly(self):
        agent = DetectionAgent()
        user = "compromised_alice"

        curr = {
            "request_id": "req-compound",
            "timestamp": "2026-09-17T14:00:00+00:00",
            "principal_ref": user,
            "path": "/api/orders",
            "method": "POST",
            "ml_score": 65.5,
            "fired_rules": ["R001"],
            "risk_score": 55.0,
            "decision": "BLOCK"
        }

        alert = agent.analyze_event(curr, [])
        assert alert is not None
        assert alert.threat_category == "COMPOUND_ANOMALY"
        assert alert.score >= 60.0

    def test_clean_traffic_produces_no_alert(self):
        agent = DetectionAgent()
        curr = {
            "request_id": "req-normal",
            "timestamp": "2026-09-17T09:00:00+00:00",
            "principal_ref": "normal_user",
            "path": "/api/orders/101",
            "method": "GET",
            "risk_score": 10.0,
            "decision": "ALLOW"
        }
        alert = agent.analyze_event(curr, [])
        assert alert is None


class TestThreatIntelAgent:
    """Test indicator enrichment in ThreatIntelAgent."""

    def test_enrich_known_botnet_ip(self):
        agent = ThreatIntelAgent()
        enrichment = agent.enrich_indicator("198.51.100.200", user_agent="Mozilla/5.0")
        assert enrichment.is_known_botnet is True
        assert enrichment.ip_reputation_score == 100.0
        assert enrichment.reputation_category == "MALICIOUS"
        assert "KNOWN_BOTNET_C2" in enrichment.tags

    def test_enrich_tor_exit_node(self):
        agent = ThreatIntelAgent()
        enrichment = agent.enrich_indicator("198.51.100.250")
        assert enrichment.is_tor_exit_node is True
        assert enrichment.ip_reputation_score >= 80.0
        assert "TOR_EXIT_NODE" in enrichment.tags

    def test_enrich_scanner_user_agent(self):
        agent = ThreatIntelAgent()
        enrichment = agent.enrich_indicator("192.168.1.50", user_agent="sqlmap/1.5.2#stable")
        assert enrichment.is_scanner_tool is True
        assert enrichment.user_agent_risk >= 90.0
        assert enrichment.reputation_category == "MALICIOUS"
        assert any("SCANNER_SIGNATURE" in t for t in enrichment.tags)

    def test_enrich_clean_corporate_client(self):
        agent = ThreatIntelAgent()
        enrichment = agent.enrich_indicator("10.0.1.15", user_agent="ERP-WebClient/2.0")
        assert enrichment.reputation_category == "CLEAN"
        assert enrichment.is_known_botnet is False
        assert enrichment.is_scanner_tool is False


class TestInvestigationAgent:
    """Test incident timeline and blast radius investigation in InvestigationAgent."""

    def test_investigation_report_and_timeline(self):
        agent = InvestigationAgent()
        alert = SecurityAlert(
            alert_id="alt-test-01",
            severity="HIGH",
            threat_category="MASS_SCRAPING",
            target_entity="attacker_ref",
            score=80.0,
            description="Mass scraping alert",
            evidence=["High call rate across business APIs"]
        )

        events = [
            {
                "timestamp": "2026-09-17T12:00:00+00:00",
                "request_id": "req-1",
                "path": "/api/orders/101",
                "method": "GET",
                "decision": "ALLOW",
                "risk_score": 15.0
            },
            {
                "timestamp": "2026-09-17T12:00:05+00:00",
                "request_id": "req-2",
                "path": "/api/orders/102",
                "method": "GET",
                "decision": "ALLOW",
                "risk_score": 20.0
            },
            {
                "timestamp": "2026-09-17T12:00:10+00:00",
                "request_id": "req-3",
                "path": "/api/finance/invoices",
                "method": "GET",
                "decision": "BLOCK",
                "risk_score": 85.0,
                "fired_rules": ["R006"]
            }
        ]

        report = agent.investigate(alert, events)
        assert isinstance(report, InvestigationReport)
        assert report.target_entity == "attacker_ref"
        assert len(report.timeline) == 3
        assert report.timeline[0].request_id == "req-1"
        assert report.timeline[2].decision == "BLOCK"
        assert report.blast_radius["total_requests_analyzed"] == 3
        assert report.blast_radius["distinct_endpoints_accessed"] == 3
        assert "root_cause_hypothesis" in report.to_dict()


class TestResponseAgentAndApprovalGates:
    """Test pre-approved containment, strict Human Approval Gates, and programmatic rollback."""

    def test_auto_executed_safe_containment(self):
        agent = ResponseAgent()
        alert = SecurityAlert(
            alert_id="alt-safe-01",
            severity="HIGH",
            threat_category="MASS_SCRAPING",
            target_entity="198.51.100.99",
            score=75.0,
            description="Scraping alert",
            evidence=["15 calls in 5 seconds"]
        )
        report = InvestigationReport(
            incident_id="inc-safe-01",
            target_entity="198.51.100.99",
            alert_ref=alert.alert_id,
            timeline=[],
            blast_radius={},
            user_profile={},
            threat_intel=None,
            root_cause_hypothesis="Scraping bot",
            risk_level="HIGH"
        )

        plan = agent.formulate_response_plan(alert, report)
        # Safe reversible actions should be auto-executed
        assert len(plan.auto_executed_actions) >= 1
        act_types = [a.action_type for a in plan.auto_executed_actions]
        assert ActionType.RATE_LIMIT in act_types
        assert ActionType.QUARANTINE_IP_TEMP in act_types
        for act in plan.auto_executed_actions:
            assert act.approval_status == ApprovalStatus.EXECUTED
            assert act.executed_at is not None

        # Verify active containment applied
        assert "198.51.100.99" in agent.active_rate_limits
        assert "198.51.100.99" in agent.active_quarantined_ips

    def test_human_approval_gate_for_account_suspension(self):
        agent = ResponseAgent()
        alert = SecurityAlert(
            alert_id="alt-crit-01",
            severity="CRITICAL",
            threat_category="PRIVILEGE_ESCALATION",
            target_entity="user_evil_admin",
            score=95.0,
            description="Attempted admin promotion",
            evidence=["R004 triggered"]
        )
        report = InvestigationReport(
            incident_id="inc-crit-01",
            target_entity="user_evil_admin",
            alert_ref=alert.alert_id,
            timeline=[],
            blast_radius={},
            user_profile={},
            threat_intel=None,
            root_cause_hypothesis="Privilege escalation attack",
            risk_level="CRITICAL"
        )

        plan = agent.formulate_response_plan(alert, report)

        # High-impact action (SUSPEND_ACCOUNT) MUST be in pending_human_actions
        assert len(plan.pending_human_actions) >= 1
        suspension_act = next(
            a for a in plan.pending_human_actions
            if a.action_type == ActionType.SUSPEND_ACCOUNT
        )
        assert suspension_act.requires_human_approval is True
        assert suspension_act.approval_status == ApprovalStatus.PENDING_HUMAN_APPROVAL

        # Crucial security guarantee: Account is NOT suspended before human approval!
        assert agent.active_challenges.get("user_evil_admin") != "SUSPENDED"

        # Analyst reviews and approves
        approved_act = agent.approve_action(suspension_act.action_id, analyst_id="analyst_bob")
        assert approved_act.approval_status == ApprovalStatus.EXECUTED
        assert approved_act.approved_by == "analyst_bob"
        assert agent.active_challenges.get("user_evil_admin") == "SUSPENDED"

    def test_human_rejection_flow(self):
        agent = ResponseAgent()
        action = AgentAction(
            action_type=ActionType.SUSPEND_ACCOUNT,
            target_entity="innocent_user",
            justification="Suspicious activity flag"
        )
        agent.actions_registry[action.action_id] = action

        rejected = agent.reject_action(
            action.action_id,
            analyst_id="analyst_alice",
            reason="Confirmed false positive during billing maintenance"
        )
        assert rejected.approval_status == ApprovalStatus.REJECTED
        assert rejected.approved_by == "analyst_alice"
        assert "Confirmed false positive" in rejected.parameters["rejection_reason"]
        assert agent.active_challenges.get("innocent_user") != "SUSPENDED"

    def test_instant_programmatic_containment_rollback(self):
        agent = ResponseAgent()
        action = AgentAction(
            action_type=ActionType.RATE_LIMIT,
            target_entity="192.168.1.200",
            justification="Automated rate limiting"
        )
        agent.actions_registry[action.action_id] = action
        agent._apply_containment(action)
        action.approval_status = ApprovalStatus.EXECUTED

        assert "192.168.1.200" in agent.active_rate_limits

        # Execute instant rollback (< 30s SLA)
        t0 = time.perf_counter()
        revoked = agent.revoke_action(action.action_id, analyst_id="oncall_engineer")
        elapsed_ms = (time.perf_counter() - t0) * 1000.0

        assert elapsed_ms < 5.0, "Rollback must execute in milliseconds"
        assert revoked.approval_status == ApprovalStatus.REVOKED
        assert "192.168.1.200" not in agent.active_rate_limits


class TestSecurityOrchestrator:
    """Test end-to-end multi-agent pipeline and audit trail persistence."""

    def test_orchestrator_end_to_end_workflow(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            audit_file = os.path.join(tmp_dir, "agent_audit.jsonl")
            orchestrator = SecurityOrchestrator(audit_file=audit_file)

            # High-risk trigger event
            trigger_event = {
                "request_id": "req-orch-01",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "client_ip": "198.51.100.200",  # Known botnet IP in mock intel
                "path": "/api/users/profile",
                "method": "POST",
                "fired_rules": ["R004"],
                "risk_score": 85.0,
                "ml_score": 60.0,
                "user_agent": "sqlmap/1.5"
            }

            plan = orchestrator.process_security_event(trigger_event)
            assert plan is not None
            assert plan.target_entity == "198.51.100.200"

            # Verify alert and incident created in registries
            assert len(orchestrator.alerts) >= 1
            assert len(orchestrator.incidents) >= 1

            # Verify audit trail written to disk
            assert os.path.exists(audit_file)
            with open(audit_file, "r", encoding="utf-8") as f:
                lines = [json.loads(line) for line in f if line.strip()]
            assert len(lines) >= 3  # Detection, Threat Intel, Investigation, Response audits
            roles = [r["agent_role"] for r in lines]
            assert "detection" in roles
            assert "threat_intel" in roles
            assert "investigation" in roles
            assert "response" in roles


class TestGatewayAgentEndpoints:
    """Test Analyst API management endpoints in Gateway."""

    @pytest.fixture
    def client(self):
        return TestClient(app, raise_server_exceptions=False)

    def test_agents_status_endpoint(self, client):
        resp = client.get("/api/agents/status")
        assert resp.status_code == 200
        data = resp.json()
        assert data["enabled"] is True
        assert "agents" in data
        assert "detection" in data["agents"]
        assert "response" in data["agents"]

    def test_agents_pending_and_approval_api_flow(self, client):
        # Trigger an alert through orchestrator
        from gateway.app import security_orchestrator

        event = {
            "request_id": "req-api-esc",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "principal_ref": "attacker_user_api",
            "client_ip": "10.0.0.88",
            "path": "/api/users/role",
            "method": "POST",
            "fired_rules": ["R004"],
            "decision": "BLOCK",
            "risk_score": 95.0
        }
        security_orchestrator.process_security_event(event)

        # 1. Query pending actions
        pending_resp = client.get("/api/agents/actions/pending")
        assert pending_resp.status_code == 200
        pending_actions = pending_resp.json()
        assert len(pending_actions) >= 1
        act = pending_actions[0]
        act_id = act["action_id"]

        # 2. Approve action via API
        approve_resp = client.post(f"/api/agents/actions/{act_id}/approve?analyst_id=analyst_lead")
        assert approve_resp.status_code == 200
        assert approve_resp.json()["approval_status"] == "executed"
        assert approve_resp.json()["approved_by"] == "analyst_lead"

        # 3. Rollback / Revoke action via API (<30s SLA)
        revoke_resp = client.post(f"/api/agents/actions/{act_id}/revoke?analyst_id=analyst_lead")
        assert revoke_resp.status_code == 200
        assert revoke_resp.json()["approval_status"] == "revoked"
