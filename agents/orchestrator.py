"""
Security Multi-Agent Orchestrator (Phase 7)
Coordinates Detection, Threat Intel, Investigation, and Response agents.
Maintains an immutable audit trail in events/agent_audit.jsonl and provides analyst operational endpoints.
"""

from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import time
from typing import Dict, List, Optional, Any

from agents.detection_agent import DetectionAgent, SecurityAlert
from agents.threat_intel_agent import ThreatIntelAgent, ThreatIntelEnrichment
from agents.investigation_agent import InvestigationAgent, InvestigationReport
from agents.response_agent import ResponseAgent, ResponsePlan
from agents.base import AgentAction, ApprovalStatus

logger = logging.getLogger(__name__)


class SecurityOrchestrator:
    """
    Security Orchestrator coordinates the lifecycle of specialized agents:
    Event -> Detection -> Threat Intel -> Investigation -> Response (with Human Approval Gates).
    """

    def __init__(
        self,
        audit_file: str = "events/agent_audit.jsonl",
        enabled: bool = True,
        mitigation_engine: Optional[Any] = None
    ):
        self.enabled = enabled
        self.audit_file = Path(audit_file)
        self.audit_file.parent.mkdir(parents=True, exist_ok=True)
        self.mitigation_engine = mitigation_engine

        # Initialize the 4 specialized agents
        self.detection_agent = DetectionAgent()
        self.threat_intel_agent = ThreatIntelAgent()
        self.investigation_agent = InvestigationAgent()
        self.response_agent = ResponseAgent()

        # Operational Registries
        self.alerts: Dict[str, SecurityAlert] = {}
        self.incidents: Dict[str, InvestigationReport] = {}
        self.plans: Dict[str, ResponsePlan] = {}

    def process_security_event(
        self,
        event: dict,
        history: Optional[List[dict]] = None
    ) -> Optional[ResponsePlan]:
        """
        Execute multi-agent workflow for a telemetry event:
        1. Detection Agent: Correlate signals and identify threats.
        2. Threat Intel Agent: Enrich network and client indicators.
        3. Investigation Agent: Reconstruct timeline and assess blast radius.
        4. Response Agent: Formulate containment plan (auto-execute safe actions, queue high-impact actions for human approval).
        """
        if not self.enabled:
            return None

        # 1. Detection Phase
        alert = self.detection_agent.analyze_event(event, history)
        if not alert:
            return None

        self.alerts[alert.alert_id] = alert
        logger.warning(
            f"SECURITY AGENT ALERT: {alert.alert_id} - {alert.threat_category} "
            f"(Severity: {alert.severity}, Score: {alert.score}) for {alert.target_entity}"
        )

        # 2. Threat Intel Phase
        client_ip = event.get("client_ip", alert.target_entity)
        ua = event.get("user_agent", "")
        enrichment = self.threat_intel_agent.enrich_indicator(ip=client_ip, user_agent=ua)

        # 3. Investigation Phase
        context_events = history if history else [event]
        report = self.investigation_agent.investigate(
            alert=alert,
            events=context_events,
            threat_intel=enrichment
        )
        self.incidents[report.incident_id] = report

        # 4. Response Phase
        plan = self.response_agent.formulate_response_plan(alert=alert, report=report)
        self.plans[report.incident_id] = plan

        # Phase 8: Apply automatically executed safe mitigations directly to mitigation engine
        if self.mitigation_engine and plan.auto_executed_actions:
            for action in plan.auto_executed_actions:
                try:
                    self.mitigation_engine.apply_action(action)
                except Exception as exc:
                    logger.error(f"Failed to apply auto mitigation {action.action_id}: {exc}")

        # 5. Persist Agent Audit Trail
        self._flush_audit_records()

        return plan

    def _flush_audit_records(self) -> None:
        """Write all pending agent audit records to events/agent_audit.jsonl."""
        agents = [
            self.detection_agent,
            self.threat_intel_agent,
            self.investigation_agent,
            self.response_agent
        ]
        records = []
        for agent in agents:
            while agent.audit_records:
                records.append(agent.audit_records.pop(0).to_dict())

        if records:
            try:
                with open(self.audit_file, "a", encoding="utf-8") as f:
                    for r in records:
                        f.write(json.dumps(r) + "\n")
            except Exception as exc:
                logger.error(f"Failed to append agent audit records to {self.audit_file}: {exc}")

    # Analyst Operations & Management API

    def get_status(self) -> Dict[str, Any]:
        """Status summary of all security agents and active containment."""
        return {
            "enabled": self.enabled,
            "total_alerts": len(self.alerts),
            "total_incidents": len(self.incidents),
            "pending_approval_count": len(self.get_pending_actions()),
            "active_containment": {
                "rate_limits": len(self.response_agent.active_rate_limits),
                "quarantined_ips": len(self.response_agent.active_quarantined_ips),
                "active_challenges": len(self.response_agent.active_challenges)
            },
            "agents": {
                "detection": {"role": self.detection_agent.role.value, "status": "active"},
                "threat_intel": {"role": self.threat_intel_agent.role.value, "status": "active"},
                "investigation": {"role": self.investigation_agent.role.value, "status": "active"},
                "response": {"role": self.response_agent.role.value, "status": "active"}
            }
        }

    def get_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Retrieve recent security alerts."""
        alerts_list = sorted(
            self.alerts.values(),
            key=lambda a: a.created_at,
            reverse=True
        )
        return [a.to_dict() for a in alerts_list[:limit]]

    def get_incident(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve incident report and investigation timeline."""
        incident = self.incidents.get(incident_id)
        return incident.to_dict() if incident else None

    def get_pending_actions(self) -> List[Dict[str, Any]]:
        """Retrieve all actions currently awaiting human analyst review and approval."""
        pending = [
            act.to_dict() for act in self.response_agent.actions_registry.values()
            if act.approval_status == ApprovalStatus.PENDING_HUMAN_APPROVAL
        ]
        return pending

    def approve_action(self, action_id: str, analyst_id: str) -> Dict[str, Any]:
        """Analyst authorizes high-impact containment action."""
        action = self.response_agent.approve_action(action_id, analyst_id)
        # Phase 8: Once approved by human analyst, immediately enforce in mitigation engine
        if self.mitigation_engine and action.approval_status in (ApprovalStatus.APPROVED, ApprovalStatus.EXECUTED):
            try:
                self.mitigation_engine.apply_action(action)
            except Exception as exc:
                logger.error(f"Failed to enforce approved mitigation {action_id}: {exc}")
        self._flush_audit_records()
        return action.to_dict()

    def reject_action(self, action_id: str, analyst_id: str, reason: str = "") -> Dict[str, Any]:
        """Analyst rejects high-impact containment action."""
        action = self.response_agent.reject_action(action_id, analyst_id, reason)
        self._flush_audit_records()
        return action.to_dict()

    def revoke_action(self, action_id: str, analyst_id: Optional[str] = None) -> Dict[str, Any]:
        """Revert / rollback previously executed containment action (<30s SLA)."""
        action = self.response_agent.revoke_action(action_id, analyst_id)
        # Phase 8: Instantly rollback from active mitigation engine
        if self.mitigation_engine:
            self.mitigation_engine.rollback_action(action_id)
        self._flush_audit_records()
        return action.to_dict()


# Global Singleton Orchestrator Instance
security_orchestrator = SecurityOrchestrator()
