from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional
import math

class Decision(str, Enum):
    ALLOW = "ALLOW"
    LIMIT = "LIMIT"
    CHALLENGE = "CHALLENGE"
    BLOCK = "BLOCK"

@dataclass
class RiskScore:
    overall: float
    components: Dict[str, float]
    reasons: List[str]
    decision: Decision

# Endpoint Data Sensitivity Catalog (0.0 to 1.0)
ENDPOINT_SENSITIVITY = {
    "/health": 0.0,
    "/api/auth/login": 0.9,      # Credentials
    "/api/orders": 0.8,          # Financial + Customer PII
    "/api/users": 0.85,          # User PII
    "/api/inventory": 0.5,      # Operational Business Data
}

def get_endpoint_sensitivity(path: str) -> float:
    """Matches path to known sensitivity rating."""
    for prefix, sensitivity in ENDPOINT_SENSITIVITY.items():
        if path == prefix or path.startswith(prefix + "/"):
            return sensitivity
    return 0.5  # Default baseline for unknown /api/* endpoints

def calculate_risk(
    waf_severity: float,
    auth_anomaly: float,
    rate_severity: float,
    path: str,
    user_trust: float = 1.0,      # 0.0 to 1.0 (1.0 = fully trusted, 0.0 = untrusted/anonymous)
    contextual_risk: float = 0.0, # 0.0 to 1.0
    rule_severity: float = 0.0,   # 0.0 to 100.0 (Phase 4 Deterministic Business Logic Rules)
    anomaly_score: float = 0.0,   # 0.0 to 100.0 (Phase 5 Statistical Anomaly Detection)
    extra_reasons: Optional[List[str]] = None
) -> RiskScore:
    """
    Computes bounded, explainable risk score (0-100) per CRITICAL_IMPROVEMENTS_SUMMARY #1.
    Integrates WAF, Auth, Rate, Context, Deterministic Rules, and Statistical Anomaly score.
    """
    reasons = list(extra_reasons or [])
    
    # 1. Threat dimensions composite (0-100)
    # If WAF or Rules Engine has a critical trigger (>=80), elevate threat score immediately
    raw_threat_avg = (waf_severity + auth_anomaly + rate_severity + rule_severity) / 4.0
    if waf_severity >= 90:
        threat_score = max(waf_severity, raw_threat_avg)
    elif rule_severity >= 80:
        threat_score = max(rule_severity, raw_threat_avg)
    elif auth_anomaly >= 90:
        threat_score = max(auth_anomaly, raw_threat_avg)
    else:
        threat_score = min(100.0, max(raw_threat_avg, rule_severity * 0.5))
        
    threat_score = max(0.0, min(100.0, threat_score))
    
    # 2. Endpoint Data Sensitivity (0-100)
    sensitivity_factor = get_endpoint_sensitivity(path)
    sensitivity_score = max(0.0, min(100.0, sensitivity_factor * 100.0))
    
    # 3. User Trustworthiness (0-100)
    user_trust_score = max(0.0, min(100.0, user_trust * 100.0))
    
    # 4. Contextual Risk (0-100) - includes statistical anomaly score
    context_score = max(0.0, min(100.0, max(contextual_risk * 100.0, anomaly_score)))
    
    # 5. Weighted composite formula
    overall = (
        threat_score * 0.40 +
        sensitivity_score * 0.25 +
        (100.0 - user_trust_score) * 0.20 +
        context_score * 0.15
    )
    
    # Hard boundary guarantees
    if waf_severity >= 80 or rule_severity >= 80:
        overall = max(overall, 85.0)  # Guarantees BLOCK (HTTP 403)
    elif rule_severity >= 60:
        overall = max(overall, 65.0)  # Guarantees CHALLENGE (HTTP 401) or LIMIT
    elif auth_anomaly >= 80 and path.startswith("/api/") and path != "/api/auth/login":
        if waf_severity < 75.0 and rule_severity < 75.0:
            overall = min(74.0, max(overall, 60.0))  # Guarantees CHALLENGE (HTTP 401)
        else:
            overall = max(overall, 85.0)  # Combined with attack -> BLOCK (HTTP 403)
        
    # Clamp strictly between 0 and 100
    overall = max(0.0, min(100.0, round(overall, 2)))
    
    # Determine Policy Decision
    if overall <= 20.0:
        decision = Decision.ALLOW
    elif overall <= 50.0:
        decision = Decision.LIMIT
    elif overall <= 75.0:
        decision = Decision.CHALLENGE
    else:
        decision = Decision.BLOCK
        
    return RiskScore(
        overall=overall,
        components={
            "threat": round(threat_score, 2),
            "sensitivity": round(sensitivity_score, 2),
            "user_trust": round(user_trust_score, 2),
            "context": round(context_score, 2),
            "waf_severity": waf_severity,
            "rule_severity": rule_severity,
            "anomaly_score": round(anomaly_score, 2),
            "auth_anomaly": auth_anomaly,
            "rate_severity": rate_severity,
        },
        reasons=reasons,
        decision=decision
    )

