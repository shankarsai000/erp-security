"""Enterprise Security Metrics and KPI Retrospective Tracker (Phase 9).

Computes core enterprise security metrics:
- MTTD (Mean Time to Detect): Time elapsed from initial anomaly event to alert creation.
- MTTR (Mean Time to Respond): Time elapsed from alert creation to containment execution.
- Containment Efficiency: Automated mitigation success rate vs human escalations.
- Total traffic and decision breakdown.
"""

from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import threading
import time
from typing import Dict, List, Optional, Any


@dataclass
class IncidentMetric:
    incident_id: str
    event_timestamp: float
    alert_timestamp: float
    containment_timestamp: Optional[float] = None
    threat_category: str = "UNKNOWN"
    automated: bool = True
    resolved: bool = True


class SecurityMetricsTracker:
    """Thread-safe KPI tracker for MTTD, MTTR, and Gateway security analytics."""

    def __init__(self, max_history: int = 1000):
        self._lock = threading.RLock()
        self.max_history = max_history

        # Rolling incident metrics: deque of IncidentMetric
        self.incident_history: deque = deque(maxlen=max_history)

        # Traffic counters
        self.total_requests: int = 0
        self.decision_counts: Dict[str, int] = {
            "ALLOW": 0,
            "CHALLENGE": 0,
            "LIMIT": 0,
            "BLOCK": 0,
            "MITIGATED": 0
        }

        # Start time
        self.started_at = datetime.now(timezone.utc).isoformat()

    def record_request_decision(self, decision_str: str) -> None:
        """Increment traffic counters."""
        with self._lock:
            self.total_requests += 1
            key = decision_str.upper()
            if key not in self.decision_counts:
                self.decision_counts[key] = 0
            self.decision_counts[key] += 1

    def record_incident_lifecycle(
        self,
        incident_id: str,
        event_time_epoch: float,
        alert_time_epoch: float,
        containment_time_epoch: Optional[float] = None,
        threat_category: str = "UNKNOWN",
        automated: bool = True
    ) -> None:
        """Records an incident from detection through response for MTTD and MTTR computation."""
        with self._lock:
            self.incident_history.append(
                IncidentMetric(
                    incident_id=incident_id,
                    event_timestamp=event_time_epoch,
                    alert_timestamp=alert_time_epoch,
                    containment_timestamp=containment_time_epoch,
                    threat_category=threat_category,
                    automated=automated
                )
            )

    def get_kpis(self) -> Dict[str, Any]:
        """Calculates MTTD, MTTR, containment efficiency, and traffic totals."""
        with self._lock:
            mttd_list = []
            mttr_list = []
            auto_count = 0
            total_incidents = len(self.incident_history)

            for inc in self.incident_history:
                # MTTD: alert_time - event_time
                ttd = max(0.0, inc.alert_timestamp - inc.event_timestamp)
                mttd_list.append(ttd)

                # MTTR: containment_time - alert_time
                if inc.containment_timestamp and inc.containment_timestamp >= inc.alert_timestamp:
                    ttr = inc.containment_timestamp - inc.alert_timestamp
                    mttr_list.append(ttr)

                if inc.automated:
                    auto_count += 1

            avg_mttd_seconds = (sum(mttd_list) / len(mttd_list)) if mttd_list else 0.0
            avg_mttr_seconds = (sum(mttr_list) / len(mttr_list)) if mttr_list else 0.0
            containment_efficiency = (auto_count / total_incidents) if total_incidents > 0 else 1.0

            mitigated_total = self.decision_counts.get("BLOCK", 0) + self.decision_counts.get("MITIGATED", 0)
            blocked_percentage = (mitigated_total / self.total_requests * 100) if self.total_requests > 0 else 0.0

            return {
                "tracker_started_at": self.started_at,
                "total_requests_processed": self.total_requests,
                "traffic_breakdown": dict(self.decision_counts),
                "threat_mitigation_rate_pct": round(blocked_percentage, 2),
                "incident_kpis": {
                    "total_incidents_tracked": total_incidents,
                    "mttd_mean_seconds": round(avg_mttd_seconds, 3),
                    "mttr_mean_seconds": round(avg_mttr_seconds, 3),
                    "automated_containment_rate_pct": round(containment_efficiency * 100, 1),
                    "target_sla_mttd": "< 5.0 seconds",
                    "target_sla_mttr": "< 30.0 seconds"
                }
            }


# Singleton instance for gateway tracking
security_metrics_tracker = SecurityMetricsTracker()
