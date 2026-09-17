"""
Security Agents Package (Phase 7)
Autonomous, specialized, but strictly bounded security agents for ERP protection.
"""

from agents.base import (
    AgentRole,
    ActionType,
    ApprovalStatus,
    AgentAction,
    AgentAuditRecord,
    BaseSecurityAgent
)
from agents.detection_agent import DetectionAgent, SecurityAlert
from agents.threat_intel_agent import ThreatIntelAgent, ThreatIntelEnrichment
from agents.investigation_agent import InvestigationAgent, InvestigationReport, TimelineEvent
from agents.response_agent import ResponseAgent, ResponsePlan
from agents.orchestrator import SecurityOrchestrator, security_orchestrator

__all__ = [
    "AgentRole",
    "ActionType",
    "ApprovalStatus",
    "AgentAction",
    "AgentAuditRecord",
    "BaseSecurityAgent",
    "DetectionAgent",
    "SecurityAlert",
    "ThreatIntelAgent",
    "ThreatIntelEnrichment",
    "InvestigationAgent",
    "InvestigationReport",
    "TimelineEvent",
    "ResponseAgent",
    "ResponsePlan",
    "SecurityOrchestrator",
    "security_orchestrator"
]
