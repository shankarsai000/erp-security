"""
Threat Intel Agent (Phase 7)
Autonomy: Read/Enrich
Enriches IP addresses and User-Agent signatures with threat intelligence reputation data.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import ipaddress
import time
from typing import Dict, List, Optional, Any, Set
import logging

from agents.base import AgentRole, BaseSecurityAgent

logger = logging.getLogger(__name__)


@dataclass
class ThreatIntelEnrichment:
    """Reputation enrichment details for network and client indicators."""
    ip: str
    ip_reputation_score: float  # Bounded 0.0 - 100.0 (higher = riskier)
    is_tor_exit_node: bool
    is_known_botnet: bool
    is_datacenter_proxy: bool
    user_agent_risk: float  # Bounded 0.0 - 100.0
    is_scanner_tool: bool
    reputation_category: str  # "CLEAN", "SUSPICIOUS", "MALICIOUS"
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ThreatIntelAgent(BaseSecurityAgent):
    """
    Threat Intel Agent enriches observed entities with threat intelligence feeds.
    Operates in Read/Enrich mode — provides context without modifying policies.
    """

    def __init__(self, name: str = "threat_intel_agent_v1"):
        super().__init__(role=AgentRole.THREAT_INTEL, name=name)

        # Curated Threat Intelligence Repositories (Mock / Local Feeds)
        self.known_botnet_ips: Set[str] = {
            "198.51.100.200", "198.51.100.201", "198.51.100.202",
            "203.0.113.100", "203.0.113.101"
        }
        self.known_tor_nodes: Set[str] = {
            "198.51.100.250", "198.51.100.251", "203.0.113.250"
        }
        self.known_datacenters: Set[str] = {
            "198.51.100.150", "198.51.100.151", "10.0.99.1"
        }

        # Scanner and exploit tool signatures in User-Agent headers
        self.scanner_signatures = [
            "sqlmap", "nikto", "dirbuster", "gobuster",
            "hydra", "masscan", "zgrab", "burpcollaborator"
        ]

    def enrich_indicator(self, ip: str, user_agent: str = "") -> ThreatIntelEnrichment:
        """
        Enrich an IP address and User-Agent with threat reputation scoring and categorizations.
        """
        t0 = time.perf_counter()
        tags = []
        ip_score = 0.0
        ua_score = 0.0

        is_bot = ip in self.known_botnet_ips
        is_tor = ip in self.known_tor_nodes
        is_dc = ip in self.known_datacenters

        # 1. IP Threat Evaluation
        if is_bot:
            ip_score = 100.0
            tags.append("KNOWN_BOTNET_C2")
        elif is_tor:
            ip_score = 85.0
            tags.append("TOR_EXIT_NODE")
        elif is_dc:
            ip_score = 60.0
            tags.append("DATACENTER_PROXY")
        else:
            # Check private or loopback ranges
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.is_private or ip_obj.is_loopback:
                    tags.append("INTERNAL_NETWORK")
                    ip_score = 0.0
            except ValueError:
                pass

        # 2. User-Agent Threat Evaluation
        ua_lower = (user_agent or "").lower()
        is_scanner = False
        for sig in self.scanner_signatures:
            if sig in ua_lower:
                is_scanner = True
                ua_score = 95.0
                tags.append(f"SCANNER_SIGNATURE:{sig.upper()}")
                break

        if not is_scanner and ua_lower in ("python-requests", "curl", "wget", ""):
            ua_score = 30.0
            tags.append("GENERIC_HTTP_CLIENT")

        # Category mapping
        combined_max = max(ip_score, ua_score)
        if combined_max >= 80.0:
            category = "MALICIOUS"
        elif combined_max >= 40.0:
            category = "SUSPICIOUS"
        else:
            category = "CLEAN"

        enrichment = ThreatIntelEnrichment(
            ip=ip,
            ip_reputation_score=round(ip_score, 1),
            is_tor_exit_node=is_tor,
            is_known_botnet=is_bot,
            is_datacenter_proxy=is_dc,
            user_agent_risk=round(ua_score, 1),
            is_scanner_tool=is_scanner,
            reputation_category=category,
            tags=tags
        )

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        self._record_audit(
            target_ref=ip,
            input_summary={"ip": ip, "user_agent": user_agent},
            findings=enrichment.to_dict(),
            actions_proposed=[],
            execution_status="COMPLETED",
            latency_ms=elapsed_ms
        )

        return enrichment
