"""
Response Agent (Phase 7)
Autonomy: Pre-approved/reversible containment only.
Enforces strict Human Approval Gates for high-impact actions, and supports 100% reversible rollback.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import time
from typing import Dict, List, Optional, Any
import logging

from agents.base import (
    AgentRole,
    BaseSecurityAgent,
    AgentAction,
    ActionType,
    ApprovalStatus,
    HUMAN_APPROVAL_REQUIRED_ACTIONS
)
from agents.detection_agent import SecurityAlert
from agents.investigation_agent import InvestigationReport

logger = logging.getLogger(__name__)


@dataclass
class ResponsePlan:
    """Containment and response plan formulated for an incident."""
    incident_id: str
    target_entity: str
    actions: List[AgentAction]
    auto_executed_actions: List[AgentAction] = field(default_factory=list)
    pending_human_actions: List[AgentAction] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "target_entity": self.target_entity,
            "actions": [a.to_dict() for a in self.actions],
            "auto_executed_actions": [a.to_dict() for a in self.auto_executed_actions],
            "pending_human_actions": [a.to_dict() for a in self.pending_human_actions],
            "created_at": self.created_at
        }


class ResponseAgent(BaseSecurityAgent):
    """
    Response Agent enforces approved containment actions.
    - Safely auto-executes pre-approved, reversible actions.
    - Strictly blocks high-impact actions until explicit human authorization is granted.
    - Supports programmatic reversal/rollback (<30s SLA).
    """

    def __init__(self, name: str = "response_agent_v1"):
        super().__init__(role=AgentRole.RESPONSE, name=name)
        # Registry of all formulated actions: action_id -> AgentAction
        self.actions_registry: Dict[str, AgentAction] = {}
        # Active containment state
        self.active_rate_limits: Dict[str, int] = {}  # target -> limit
        self.active_quarantined_ips: Dict[str, str] = {}  # ip -> reason
        self.active_challenges: Dict[str, str] = {}  # user/session -> reason
        self.revoked_tokens: Set_Token = set()

    def formulate_response_plan(
        self,
        alert: SecurityAlert,
        report: InvestigationReport
    ) -> ResponsePlan:
        """
        Formulate appropriate containment actions based on threat severity and blast radius.
        """
        t0 = time.perf_counter()
        target = alert.target_entity
        proposed_actions: List[AgentAction] = []

        # 1. Evaluate Pre-Approved Safe Containment (Auto-executed)
        if alert.severity in ("MEDIUM", "HIGH", "CRITICAL"):
            # Reversible rate limit
            proposed_actions.append(AgentAction(
                action_type=ActionType.RATE_LIMIT,
                target_entity=target,
                justification=f"Automated containment: throttle abusive entity '{target}' due to {alert.threat_category}",
                reversible=True,
                duration_seconds=3600,
                parameters={"rate_limit": 5, "window_seconds": 60}
            ))

        if alert.threat_category in ("CREDENTIAL_STUFFING", "COMPOUND_ANOMALY"):
            # Reversible session/MFA challenge
            proposed_actions.append(AgentAction(
                action_type=ActionType.CHALLENGE_MFA,
                target_entity=target,
                justification=f"Require MFA re-authentication for '{target}' following suspicious velocity/anomaly",
                reversible=True,
                duration_seconds=1800
            ))

        if alert.severity in ("HIGH", "CRITICAL"):
            # Temporary IP quarantine (< 1 hour)
            proposed_actions.append(AgentAction(
                action_type=ActionType.QUARANTINE_IP_TEMP,
                target_entity=target,
                justification=f"Temporary 1-hour IP quarantine for '{target}' pending investigation",
                reversible=True,
                duration_seconds=3600
            ))

        # 2. Evaluate High-Impact Actions (Strict Human-in-the-Loop Required)
        if alert.severity == "CRITICAL" or alert.threat_category == "PRIVILEGE_ESCALATION":
            proposed_actions.append(AgentAction(
                action_type=ActionType.SUSPEND_ACCOUNT,
                target_entity=target,
                justification=f"CRITICAL privilege abuse by '{target}'. Human analyst approval required to suspend account.",
                reversible=True,
                requires_human_approval=True,
                approval_status=ApprovalStatus.PENDING_HUMAN_APPROVAL
            ))

        # Register and partition actions
        auto_executed: List[AgentAction] = []
        pending_human: List[AgentAction] = []

        for act in proposed_actions:
            self.actions_registry[act.action_id] = act
            if act.requires_human_approval:
                pending_human.append(act)
            else:
                # Auto-execute safe action
                self._apply_containment(act)
                act.approval_status = ApprovalStatus.EXECUTED
                act.executed_at = datetime.now(timezone.utc).isoformat()
                auto_executed.append(act)

        plan = ResponsePlan(
            incident_id=report.incident_id,
            target_entity=target,
            actions=proposed_actions,
            auto_executed_actions=auto_executed,
            pending_human_actions=pending_human
        )

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        self._record_audit(
            target_ref=target,
            input_summary={"alert_id": alert.alert_id, "incident_id": report.incident_id},
            findings=plan.to_dict(),
            actions_proposed=proposed_actions,
            execution_status="COMPLETED",
            latency_ms=elapsed_ms,
            trigger_event_id=alert.alert_id
        )

        return plan

    def approve_action(self, action_id: str, analyst_id: str) -> AgentAction:
        """Human analyst approval gate: approves and executes a pending action."""
        action = self.actions_registry.get(action_id)
        if not action:
            raise KeyError(f"Action '{action_id}' not found in registry")

        if action.approval_status != ApprovalStatus.PENDING_HUMAN_APPROVAL:
            raise ValueError(
                f"Action '{action_id}' is in status '{action.approval_status.value}', cannot approve"
            )

        action.approved_by = analyst_id
        action.approved_at = datetime.now(timezone.utc).isoformat()
        action.approval_status = ApprovalStatus.APPROVED

        # Execute approved action
        self._apply_containment(action)
        action.approval_status = ApprovalStatus.EXECUTED
        action.executed_at = datetime.now(timezone.utc).isoformat()

        logger.info(
            f"HUMAN APPROVAL: Action {action_id} ({action.action_type.value}) approved by analyst '{analyst_id}'"
        )
        return action

    def reject_action(self, action_id: str, analyst_id: str, reason: str = "") -> AgentAction:
        """Human analyst rejection gate: rejects a pending action."""
        action = self.actions_registry.get(action_id)
        if not action:
            raise KeyError(f"Action '{action_id}' not found in registry")

        action.approved_by = analyst_id
        action.approved_at = datetime.now(timezone.utc).isoformat()
        action.approval_status = ApprovalStatus.REJECTED
        action.parameters["rejection_reason"] = reason

        logger.info(
            f"HUMAN REJECTION: Action {action_id} rejected by analyst '{analyst_id}'. Reason: {reason}"
        )
        return action

    def revoke_action(self, action_id: str, analyst_id: Optional[str] = None) -> AgentAction:
        """
        Instant rollback procedure (<30s SLA): reverts and releases an executed containment action.
        """
        action = self.actions_registry.get(action_id)
        if not action:
            raise KeyError(f"Action '{action_id}' not found in registry")

        if action.approval_status != ApprovalStatus.EXECUTED:
            raise ValueError(
                f"Action '{action_id}' is not in EXECUTED state (current: {action.approval_status.value})"
            )

        # Release containment
        self._release_containment(action)
        action.approval_status = ApprovalStatus.REVOKED
        action.revoked_at = datetime.now(timezone.utc).isoformat()
        if analyst_id:
            action.parameters["revoked_by"] = analyst_id

        logger.info(f"CONTAINMENT REVOKED: Action {action_id} ({action.action_type.value}) rolled back.")
        return action

    def _apply_containment(self, action: AgentAction) -> None:
        """Internal enforcement of containment state."""
        tgt = action.target_entity
        if action.action_type == ActionType.RATE_LIMIT:
            self.active_rate_limits[tgt] = action.parameters.get("rate_limit", 5)
        elif action.action_type == ActionType.QUARANTINE_IP_TEMP:
            self.active_quarantined_ips[tgt] = action.justification
        elif action.action_type == ActionType.CHALLENGE_MFA:
            self.active_challenges[tgt] = action.justification
        elif action.action_type == ActionType.SUSPEND_ACCOUNT:
            self.active_challenges[tgt] = "SUSPENDED"

    def _release_containment(self, action: AgentAction) -> None:
        """Internal rollback of containment state."""
        tgt = action.target_entity
        if action.action_type == ActionType.RATE_LIMIT:
            self.active_rate_limits.pop(tgt, None)
        elif action.action_type == ActionType.QUARANTINE_IP_TEMP:
            self.active_quarantined_ips.pop(tgt, None)
        elif action.action_type in (ActionType.CHALLENGE_MFA, ActionType.SUSPEND_ACCOUNT):
            self.active_challenges.pop(tgt, None)
