"""
Core Contracts and Base Classes for Security Agents
Enforces strict least-privilege roles, approval gates, and audit trails.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Any
import uuid
import logging

logger = logging.getLogger(__name__)


class AgentRole(str, Enum):
    DETECTION = "detection"
    INVESTIGATION = "investigation"
    THREAT_INTEL = "threat_intel"
    RESPONSE = "response"
    REPORTING = "reporting"


class ActionType(str, Enum):
    # Automated, safe, reversible actions
    RATE_LIMIT = "rate_limit"
    CHALLENGE_MFA = "challenge_mfa"
    REVOKE_SESSION = "revoke_session"
    QUARANTINE_IP_TEMP = "quarantine_ip_temp"

    # High-impact actions requiring EXPLICIT human approval
    SUSPEND_ACCOUNT = "suspend_account"
    BLOCK_CIDR_ORGANIZATION = "block_cidr_organization"
    ROLLBACK_DATA = "rollback_data"
    CHANGE_PRIVILEGES = "change_privileges"


class ApprovalStatus(str, Enum):
    AUTO_APPROVED = "auto_approved"
    PENDING_HUMAN_APPROVAL = "pending_human_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXECUTED = "executed"
    REVOKED = "revoked"


# Actions classified as strictly requiring human approval before execution
HUMAN_APPROVAL_REQUIRED_ACTIONS = {
    ActionType.SUSPEND_ACCOUNT,
    ActionType.BLOCK_CIDR_ORGANIZATION,
    ActionType.ROLLBACK_DATA,
    ActionType.CHANGE_PRIVILEGES,
}


@dataclass
class AgentAction:
    """Security containment action formulated by the Response Agent."""
    action_type: ActionType
    target_entity: str
    justification: str
    action_id: str = field(default_factory=lambda: f"act-{uuid.uuid4().hex[:12]}")
    reversible: bool = True
    requires_human_approval: bool = False
    approval_status: ApprovalStatus = ApprovalStatus.AUTO_APPROVED
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    executed_at: Optional[str] = None
    revoked_at: Optional[str] = None
    duration_seconds: Optional[int] = 3600  # Default 1 hour temporary containment
    parameters: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if self.action_type in HUMAN_APPROVAL_REQUIRED_ACTIONS:
            self.requires_human_approval = True
            if self.approval_status == ApprovalStatus.AUTO_APPROVED:
                self.approval_status = ApprovalStatus.PENDING_HUMAN_APPROVAL

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["action_type"] = self.action_type.value
        d["approval_status"] = self.approval_status.value
        return d


@dataclass
class AgentAuditRecord:
    """Immutable audit trail record documenting every agent analysis, finding, and proposed action."""
    audit_id: str
    agent_role: AgentRole
    agent_name: str
    timestamp: str
    target_ref: str
    trigger_event_id: Optional[str]
    input_summary: Dict[str, Any]
    findings: Dict[str, Any]
    actions_proposed: List[Dict[str, Any]]
    execution_status: str
    latency_ms: float

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["agent_role"] = self.agent_role.value
        return d


class BaseSecurityAgent(ABC):
    """Abstract base class for all security agents with least-privilege boundaries and auditing."""

    def __init__(self, role: AgentRole, name: str):
        self.role = role
        self.name = name
        self.audit_records: List[AgentAuditRecord] = []

    def _record_audit(
        self,
        target_ref: str,
        input_summary: Dict[str, Any],
        findings: Dict[str, Any],
        actions_proposed: List[AgentAction],
        execution_status: str,
        latency_ms: float,
        trigger_event_id: Optional[str] = None
    ) -> AgentAuditRecord:
        record = AgentAuditRecord(
            audit_id=f"aud-{uuid.uuid4().hex[:12]} ",
            agent_role=self.role,
            agent_name=self.name,
            timestamp=datetime.now(timezone.utc).isoformat(),
            target_ref=target_ref,
            trigger_event_id=trigger_event_id,
            input_summary=input_summary,
            findings=findings,
            actions_proposed=[a.to_dict() for a in actions_proposed],
            execution_status=execution_status,
            latency_ms=round(latency_ms, 3)
        )
        self.audit_records.append(record)
        return record
