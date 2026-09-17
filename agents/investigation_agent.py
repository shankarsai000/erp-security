"""
Investigation Agent (Phase 7)
Autonomy: Read-only
Reconstructs incident timelines, entity profiles, and blast radius assessments without modifying system state.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import time
from typing import Dict, List, Optional, Any
import uuid
import logging

from agents.base import AgentRole, BaseSecurityAgent
from agents.detection_agent import SecurityAlert
from agents.threat_intel_agent import ThreatIntelEnrichment

logger = logging.getLogger(__name__)


@dataclass
class TimelineEvent:
    """Chronological event element within an incident timeline."""
    timestamp: str
    request_id: str
    path: str
    method: str
    decision: str
    risk_score: float
    fired_rules: List[str] = field(default_factory=list)
    ml_score: float = 0.0
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationReport:
    """Structured incident investigation dossier with timeline and blast radius."""
    incident_id: str
    target_entity: str
    alert_ref: Optional[str]
    timeline: List[TimelineEvent]
    blast_radius: Dict[str, Any]
    user_profile: Dict[str, Any]
    threat_intel: Optional[Dict[str, Any]]
    root_cause_hypothesis: str
    risk_level: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["timeline"] = [t.to_dict() if hasattr(t, "to_dict") else t for t in self.timeline]
        return d


class InvestigationAgent(BaseSecurityAgent):
    """
    Investigation Agent correlates evidence and historical telemetry.
    Operates strictly in Read-only mode — never mutates data, gateways, or configurations.
    """

    def __init__(self, name: str = "investigation_agent_v1"):
        super().__init__(role=AgentRole.INVESTIGATION, name=name)

    def investigate(
        self,
        alert: SecurityAlert,
        events: List[dict],
        threat_intel: Optional[ThreatIntelEnrichment] = None
    ) -> InvestigationReport:
        """
        Build an end-to-end investigation dossier for a security alert.
        """
        t0 = time.perf_counter()
        target_entity = alert.target_entity
        incident_id = f"inc-{uuid.uuid4().hex[:10]}"

        # 1. Timeline Reconstruction
        timeline = []
        endpoints_accessed = set()
        sensitive_records = set()
        roles_observed = set()

        sorted_events = sorted(
            events,
            key=lambda e: e.get("timestamp", "")
        )

        for e in sorted_events:
            path = e.get("path", "")
            method = e.get("method", "GET")
            req_id = e.get("request_id", "")
            dec = e.get("decision", "ALLOW")
            risk = float(e.get("risk_score", 0.0))
            rules = e.get("fired_rules", [])
            ml = float(e.get("ml_score", 0.0))

            endpoints_accessed.add(path)
            if "/orders/" in path or "/inventory/" in path or "/finance/" in path:
                sensitive_records.add(path)

            role = e.get("current_role") or e.get("role")
            if role:
                roles_observed.add(role)

            summary = f"{method} {path} [{dec}]"
            if rules:
                summary += f" rules={','.join(rules)}"

            timeline.append(TimelineEvent(
                timestamp=e.get("timestamp", ""),
                request_id=req_id,
                path=path,
                method=method,
                decision=dec,
                risk_score=risk,
                fired_rules=rules,
                ml_score=ml,
                summary=summary
            ))

        # 2. Blast Radius Assessment
        blast_radius = {
            "total_requests_analyzed": len(events),
            "distinct_endpoints_accessed": len(endpoints_accessed),
            "sensitive_endpoints_targeted": list(sensitive_records)[:10],
            "roles_involved": list(roles_observed),
            "data_exfiltration_risk": "HIGH" if len(sensitive_records) > 5 else "LOW"
        }

        # 3. User / Principal Profile Context
        latest_event = sorted_events[-1] if sorted_events else {}
        user_profile = {
            "account_age_days": latest_event.get("user_account_age_days", 365),
            "past_incident_count": latest_event.get("user_incident_count", 0),
            "client_ip": latest_event.get("client_ip", target_entity),
            "user_agent": latest_event.get("user_agent", "unknown")
        }

        # 4. Root Cause Hypothesis Formulation
        hypothesis = (
            f"Entity '{target_entity}' exhibited suspicious activity matching category '{alert.threat_category}'. "
            f"Evidence indicates {len(alert.evidence)} correlation points across {len(events)} requests. "
        )
        if threat_intel and threat_intel.reputation_category == "MALICIOUS":
            hypothesis += f"Corroborated by high-risk threat intel tags: {', '.join(threat_intel.tags)}."
        else:
            hypothesis += "Activity warrants containment review based on internal anomaly thresholds."

        report = InvestigationReport(
            incident_id=incident_id,
            target_entity=target_entity,
            alert_ref=alert.alert_id,
            timeline=timeline,
            blast_radius=blast_radius,
            user_profile=user_profile,
            threat_intel=threat_intel.to_dict() if threat_intel else None,
            root_cause_hypothesis=hypothesis,
            risk_level=alert.severity
        )

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        self._record_audit(
            target_ref=target_entity,
            input_summary={"alert_id": alert.alert_id, "events_count": len(events)},
            findings=report.to_dict(),
            actions_proposed=[],
            execution_status="COMPLETED",
            latency_ms=elapsed_ms,
            trigger_event_id=alert.alert_id
        )

        return report
