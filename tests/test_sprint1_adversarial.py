"""
Sprint 1 Adversarial Security Regression Tests.

Validates remediation of the 5 critical security blockers identified in the audit:
- SEC-01: Real JWT signature verification (rejects forged/tampered tokens with 401)
- SEC-02: Enforced production secrets (gateway refuses startup if secrets are missing/short)
- SEC-03: Mandatory freshness on state mutations (rejects replays and missing freshness headers)
- SEC-04: Zero-PII IP redaction (raw client IPs are never written to general telemetry)
- SEC-05: Trusted proxy validation & IP quarantine immunity for whitelisted/internal subnets
"""

import base64
import json
import os
import time
import uuid
from pathlib import Path

import jwt
import pytest
from fastapi.testclient import TestClient

from agents.base import ActionType, AgentAction, ApprovalStatus
from gateway.app import app
from gateway.auth_engine import auth_engine
from gateway.config import GatewayConfig, config
from gateway.mitigation_engine import MitigationEngine
from gateway.replay_guard import replay_guard


@pytest.fixture
def valid_auth_token():
    """Generates a valid, cryptographically-signed JWT using the gateway's secret."""
    return auth_engine.generate_token("sales_alice", roles=["sales"], expires_in_seconds=3600)


@pytest.fixture
def admin_auth_token():
    """Generates an authentic admin token signed with the gateway's secret."""
    return auth_engine.generate_token("admin_bob", roles=["admin"], expires_in_seconds=3600)


class TestSEC01RealJWTSignatureVerification:
    """SEC-01: Proves that unsigned, forged, or tampered tokens are rejected with 401."""

    def test_forged_signature_returns_401(self):
        """Token with genuine payload structure but signed with an attacker's key is rejected."""
        attacker_secret = "attacker_rogue_secret_key_1234567890!"
        forged_token = jwt.encode(
            {"sub": "admin", "roles": ["admin"], "role": "admin", "exp": int(time.time()) + 3600},
            attacker_secret,
            algorithm="HS256"
        )
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/api/orders", headers={"Authorization": f"Bearer {forged_token}"})
            assert resp.status_code == 401
            assert "invalid" in resp.json().get("message", "").lower()

    def test_algorithm_none_attack_returns_401(self):
        """Attacker attempts alg: none exploit to bypass signature verification."""
        header_b64 = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps({"sub": "admin", "roles": ["admin"], "exp": int(time.time()) + 3600}).encode()
        ).decode().rstrip("=")
        none_token = f"{header_b64}.{payload_b64}."

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/api/orders", headers={"Authorization": f"Bearer {none_token}"})
            assert resp.status_code == 401

    def test_tampered_claims_in_transit_returns_401(self, valid_auth_token):
        """Attacker intercepts valid token and modifies claims payload."""
        parts = valid_auth_token.split(".")
        # Tamper payload to escalate role to admin
        tampered_payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "sales_alice", "role": "admin", "roles": ["admin"], "exp": int(time.time()) + 3600}).encode()
        ).decode().rstrip("=")
        tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"

        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/api/orders", headers={"Authorization": f"Bearer {tampered_token}"})
            assert resp.status_code == 401

    def test_authentic_signed_token_passes_auth(self, valid_auth_token):
        """Verifies that an authentic token signed with the genuine secret passes."""
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get("/api/orders", headers={"Authorization": f"Bearer {valid_auth_token}"})
            assert resp.status_code == 200
            assert resp.headers.get("X-Decision") == "ALLOW"


class TestSEC02ProductionSecretsEnforcement:
    """SEC-02: Proves that missing or weak secrets cause fail-fast refusal in production."""

    def test_production_mode_refuses_startup_on_missing_secrets(self):
        prod_config = GatewayConfig(
            environment="production",
            _jwt_secret_key="",
            _compliance_signing_secret="",
            _telemetry_salt=""
        )
        with pytest.raises(ValueError, match="FATAL: Missing required production secrets"):
            prod_config.validate_production_secrets()

    def test_production_mode_refuses_weak_short_keys(self):
        prod_config = GatewayConfig(
            environment="production",
            _jwt_secret_key="short_weak_key",
            _compliance_signing_secret="also_too_short",
            _telemetry_salt="salt"
        )
        with pytest.raises(ValueError, match="at least 32 characters"):
            prod_config.validate_production_secrets()

    def test_production_mode_accepts_compliant_secrets(self):
        prod_config = GatewayConfig(
            environment="production",
            _jwt_secret_key="a" * 32,
            _compliance_signing_secret="b" * 32,
            _telemetry_salt="c" * 16
        )
        # Should not raise
        prod_config.validate_production_secrets()


class TestSEC03MandatoryFreshnessOnMutations:
    """SEC-03: Proves that state-mutating requests require freshness headers and block replays."""

    def test_mutation_without_freshness_rejected_with_400(self, valid_auth_token):
        """Mutating order request lacking X-Nonce, Idempotency-Key, and timestamp is rejected."""
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post(
                "/api/orders",
                headers={"Authorization": f"Bearer {valid_auth_token}"},
                json={"customer_id": "cust-freshness", "items": ["Industrial Widget A"], "total_amount": 100.0}
            )
            assert resp.status_code == 400
            data = resp.json()
            assert "freshness verification" in data.get("message", "").lower()

    def test_mutation_with_valid_idempotency_key_succeeds(self, valid_auth_token):
        """Mutating request with fresh Idempotency-Key is accepted."""
        from gateway.rules_engine import rules_engine
        rules_engine.reset_state()
        unique_key = f"idemp-{uuid.uuid4().hex}"
        cust_id = f"cust-{uuid.uuid4().hex[:6]}"
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post(
                "/api/orders",
                headers={
                    "Authorization": f"Bearer {valid_auth_token}",
                    "Idempotency-Key": unique_key
                },
                json={"customer_id": cust_id, "items": ["Industrial Widget A"], "total_amount": 100.0}
            )
            assert resp.status_code == 200

    def test_replay_of_same_idempotency_key_is_blocked_with_403(self, valid_auth_token):
        """Submitting the same idempotency key a second time is blocked as a replay."""
        from gateway.rules_engine import rules_engine
        rules_engine.reset_state()
        unique_key = f"idemp-dupe-{uuid.uuid4().hex}"
        cust_id = f"cust-dupe-{uuid.uuid4().hex[:6]}"
        payload = {"customer_id": cust_id, "items": ["Industrial Widget A"], "total_amount": 100.0}
        headers = {
            "Authorization": f"Bearer {valid_auth_token}",
            "Idempotency-Key": unique_key
        }
        with TestClient(app, raise_server_exceptions=False) as client:
            resp1 = client.post("/api/orders", headers=headers, json=payload)
            assert resp1.status_code == 200

            # Replay attempt
            resp2 = client.post("/api/orders", headers=headers, json=payload)
            assert resp2.status_code == 403
            assert "replay attack detected" in resp2.json().get("message", "").lower()

    def test_expired_timestamp_rejected_with_403(self, valid_auth_token):
        """Mutating request with timestamp skewed beyond 300 seconds is blocked."""
        expired_ts = str(time.time() - 400)  # 400 seconds in past
        cust_id = f"cust-exp-{uuid.uuid4().hex[:6]}"
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.post(
                "/api/orders",
                headers={
                    "Authorization": f"Bearer {valid_auth_token}",
                    "X-Timestamp": expired_ts,
                    "X-Nonce": f"nonce-{uuid.uuid4().hex}"
                },
                json={"customer_id": cust_id, "items": ["Industrial Widget A"], "total_amount": 100.0}
            )
            assert resp.status_code == 403
            assert "outside valid window" in resp.json().get("message", "").lower()


class TestSEC04ZeroPIITelemetryRedaction:
    """SEC-04: Proves that raw IP addresses are never written to general telemetry logs."""

    def test_raw_ip_absent_from_telemetry_jsonl(self, valid_auth_token):
        raw_test_ip = "198.51.100.177"
        with TestClient(app, raise_server_exceptions=False) as client:
            resp = client.get(
                "/api/orders",
                headers={
                    "Authorization": f"Bearer {valid_auth_token}",
                    "X-Forwarded-For": raw_test_ip
                }
            )
            assert resp.status_code == 200

        telemetry_path = Path("events/telemetry.jsonl")
        assert telemetry_path.exists()

        # Read latest telemetry entry generated by the request
        with open(telemetry_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]

        assert len(lines) > 0
        latest_record = json.loads(lines[-1])
        logged_ip = latest_record.get("client_ip", "")
        assert logged_ip != raw_test_ip, f"Raw IP leaked into telemetry: {logged_ip}"
        assert logged_ip.startswith("p-") or logged_ip == "anon"
        assert raw_test_ip not in json.dumps(latest_record)


class TestSEC05TrustedProxyAndIPQuarantineImmunity:
    """SEC-05: Proves that spoofed X-Forwarded-For cannot quarantine internal/corporate infrastructure."""

    def test_untrusted_peer_cannot_spoof_client_ip(self):
        """When an untrusted direct peer sends X-Forwarded-For, gateway ignores it."""
        from gateway.app import get_verified_client_ip
        from starlette.requests import Request

        # Direct untrusted external peer attempting to spoof internal IP
        untrusted_scope = {
            "type": "http",
            "client": ("203.0.113.195", 54321),
            "headers": [(b"x-forwarded-for", b"10.0.0.1")],
        }
        req_untrusted = Request(untrusted_scope)
        resolved_ip = get_verified_client_ip(req_untrusted)
        assert resolved_ip == "203.0.113.195"
        assert resolved_ip != "10.0.0.1"

        # Trusted proxy forwarding external client IP
        trusted_scope = {
            "type": "http",
            "client": ("127.0.0.1", 54321),
            "headers": [(b"x-forwarded-for", b"203.0.113.195")],
        }
        req_trusted = Request(trusted_scope)
        resolved_trusted = get_verified_client_ip(req_trusted)
        assert resolved_trusted == "203.0.113.195"

    def test_internal_and_loopback_ips_immune_to_automated_quarantine(self):
        """Mitigation engine rejects quarantining whitelisted internal or loopback IPs."""
        mit_engine = MitigationEngine()

        whitelisted_targets = ["127.0.0.1", "::1", "10.0.0.5", "192.168.1.1", "172.16.0.1"]
        for target in whitelisted_targets:
            action = AgentAction(
                action_id=f"act-{uuid.uuid4().hex[:6]}",
                action_type=ActionType.QUARANTINE_IP_TEMP,
                target_entity=target,
                duration_seconds=3600,
                approval_status=ApprovalStatus.APPROVED,
                justification="Attacker attempted to spoof corporate network"
            )
            # Engine must refuse to quarantine whitelisted IP
            applied = mit_engine.apply_action(action)
            assert applied is False, f"Failed to protect whitelisted IP {target} from quarantine!"
            assert target not in mit_engine.quarantined_ips
