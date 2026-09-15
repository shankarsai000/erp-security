import pytest
from gateway.risk_engine import calculate_risk, Decision, get_endpoint_sensitivity

def test_risk_score_is_strictly_bounded():
    """Ensure risk scores are always clamped between 0.0 and 100.0."""
    # Extreme high input
    r_high = calculate_risk(
        waf_severity=250.0,
        auth_anomaly=300.0,
        rate_severity=500.0,
        path="/api/orders",
        user_trust=0.0,
        contextual_risk=1.0
    )
    assert 0.0 <= r_high.overall <= 100.0
    assert r_high.overall >= 75.0
    assert r_high.decision == Decision.BLOCK

    # Extreme low input
    r_low = calculate_risk(
        waf_severity=0.0,
        auth_anomaly=0.0,
        rate_severity=0.0,
        path="/health",
        user_trust=1.0,
        contextual_risk=0.0
    )
    assert 0.0 <= r_low.overall <= 100.0
    assert r_low.overall < 20.0
    assert r_low.decision == Decision.ALLOW

def test_critical_waf_triggers_block():
    """SQLi or severe attack pattern must yield BLOCK (>= 75.0)."""
    score = calculate_risk(
        waf_severity=95.0,
        auth_anomaly=0.0,
        rate_severity=0.0,
        path="/api/orders",
        user_trust=1.0,
        extra_reasons=["SQL injection literal detected"]
    )
    assert score.overall >= 75.0
    assert score.decision == Decision.BLOCK
    assert "SQL injection literal detected" in score.reasons

def test_unauthenticated_api_triggers_challenge():
    """Missing auth token on protected endpoint should yield CHALLENGE."""
    score = calculate_risk(
        waf_severity=0.0,
        auth_anomaly=85.0,
        rate_severity=0.0,
        path="/api/orders/101",
        user_trust=0.0,
        extra_reasons=["Missing Authorization header"]
    )
    assert 50.0 <= score.overall < 75.0
    assert score.decision == Decision.CHALLENGE

def test_endpoint_sensitivity_mapping():
    assert get_endpoint_sensitivity("/health") == 0.0
    assert get_endpoint_sensitivity("/api/orders/123") == 0.8
    assert get_endpoint_sensitivity("/api/users/1") == 0.85
    assert get_endpoint_sensitivity("/api/inventory") == 0.5
