"""Phase 10: Enterprise Hardening, HA/DR & Multi-Standard Compliance Test Suite.

Verifies:
1. Resilient Circuit Breaker state transitions (CLOSED -> OPEN -> HALF_OPEN -> CLOSED).
2. Deep Kubernetes readiness probe and component diagnostics.
3. Cryptographic tamper-evident audit logging (HMAC-SHA256 non-repudiation chain).
4. Immediate detection of log tampering, payload modifications, or deleted blocks.
5. Multi-standard compliance reporting: SOC 2 Type II, ISO 27001, GDPR Art 32, SOX 404.
6. Gateway HA, readiness, and compliance HTTP endpoints.
"""

import json
from pathlib import Path
import time
import pytest
from fastapi.testclient import TestClient

from gateway.app import app
from gateway.compliance import (
    ComplianceReportGenerator,
    TamperEvidentAuditChain,
    compliance_reporter,
    tamper_evident_audit_chain
)
from gateway.ha_dr import (
    CircuitBreaker,
    CircuitBreakerState,
    HighAvailabilityManager,
    circuit_breaker,
    ha_manager
)


@pytest.fixture
def temp_audit_file(tmp_path):
    """Isolated temporary audit log path for testing tamper-evident chaining."""
    return str(tmp_path / "test_tamper_evident_audit.jsonl")


@pytest.fixture
def isolated_audit_chain(temp_audit_file):
    """Fresh isolated TamperEvidentAuditChain instance."""
    return TamperEvidentAuditChain(audit_file=temp_audit_file)


class TestHighAvailabilityAndCircuitBreaker:
    """Unit tests for Circuit Breaker and HA readiness diagnostics."""

    def test_circuit_breaker_normal_closed(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout_seconds=0.5)
        assert cb.state == CircuitBreakerState.CLOSED
        assert cb.allow_request() is True

        cb.record_success()
        assert cb.failure_count == 0
        assert cb.state == CircuitBreakerState.CLOSED

    def test_circuit_breaker_trips_to_open_on_consecutive_failures(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout_seconds=0.5)

        cb.record_failure("Upstream 504 gateway timeout")
        cb.record_failure("Connection refused")
        assert cb.state == CircuitBreakerState.CLOSED

        # 3rd failure reaches threshold -> trips to OPEN
        cb.record_failure("Read timeout")
        assert cb.state == CircuitBreakerState.OPEN
        assert cb.allow_request() is False

    def test_circuit_breaker_cooldown_and_half_open_recovery(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout_seconds=0.2, half_open_success_threshold=2)

        cb.record_failure("Err 1")
        cb.record_failure("Err 2")
        assert cb.state == CircuitBreakerState.OPEN
        assert cb.allow_request() is False

        # Wait for recovery cooldown
        time.sleep(0.25)

        # First request after cooldown enters HALF_OPEN
        assert cb.allow_request() is True
        assert cb.state == CircuitBreakerState.HALF_OPEN

        # 2 successful trial requests recover to CLOSED
        cb.record_success()
        assert cb.state == CircuitBreakerState.HALF_OPEN
        cb.record_success()
        assert cb.state == CircuitBreakerState.CLOSED
        assert cb.allow_request() is True

    def test_deep_readiness_probe_healthy(self):
        manager = HighAvailabilityManager()
        is_ready, details = manager.evaluate_readiness(
            rules_engine=type("RulesMock", (), {"rules": {"R001": None}})(),
            ml_service=type("MLMock", (), {"get_health": lambda *args, **kwargs: {"status": "ready"}})(),
            mitigation_engine=type("MitMock", (), {"get_status": lambda *args, **kwargs: {"total_mitigations_enforced": 0}})(),
            rate_limiter=object()
        )
        assert is_ready is True
        assert details["status"] == "READY"
        assert details["components"]["rules_engine"]["status"] == "HEALTHY"

    def test_readiness_probe_fails_when_rules_unloaded(self):
        manager = HighAvailabilityManager()
        is_ready, details = manager.evaluate_readiness(
            rules_engine=type("RulesEmpty", (), {"rules": {}})(),  # Empty rules!
            ml_service=type("MLMock", (), {"get_health": lambda *args, **kwargs: {"status": "ready"}})(),
            mitigation_engine=type("MitMock", (), {"get_status": lambda *args, **kwargs: {}})(),
            rate_limiter=object()
        )
        assert is_ready is False
        assert details["status"] == "NOT_READY"
        assert details["components"]["rules_engine"]["status"] == "UNHEALTHY"


class TestTamperEvidentAuditLogging:
    """Unit tests for cryptographic log chaining and non-repudiation."""

    def test_cryptographic_audit_log_chaining(self, isolated_audit_chain, temp_audit_file):
        # Append 5 events
        for i in range(5):
            event = {
                "request_id": f"req-audit-{i}",
                "client_ip": "10.0.0.1",
                "action": "ALLOW",
                "risk_score": 10.0 + i
            }
            block = isolated_audit_chain.append_event(event)
            assert block["block_index"] == i
            assert "block_signature" in block

        # Verify chain integrity
        is_valid, count, err = isolated_audit_chain.verify_chain()
        assert is_valid is True
        assert count == 5
        assert err is None

    def test_tamper_detection_on_modified_payload(self, isolated_audit_chain, temp_audit_file):
        for i in range(4):
            isolated_audit_chain.append_event({"req": i, "data": f"clean_{i}"})

        # Tamper with block 2 in the log file
        lines = []
        with open(temp_audit_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

        tampered_block = json.loads(lines[2])
        tampered_block["payload"]["data"] = "TAMPERED_CONTENT"
        lines[2] = json.dumps(tampered_block) + "\n"

        with open(temp_audit_file, "w", encoding="utf-8") as f:
            f.writelines(lines)

        # Verification must catch the tamper
        is_valid, failed_index, reason = isolated_audit_chain.verify_chain()
        assert is_valid is False
        assert failed_index == 2
        assert "cryptographic signature mismatch" in reason

    def test_tamper_detection_on_deleted_block(self, isolated_audit_chain, temp_audit_file):
        for i in range(4):
            isolated_audit_chain.append_event({"req": i, "val": i * 10})

        # Delete line 1 (block index 1)
        lines = []
        with open(temp_audit_file, "r", encoding="utf-8") as f:
            lines = f.readlines()

        del lines[1]  # Delete block 1

        with open(temp_audit_file, "w", encoding="utf-8") as f:
            f.writelines(lines)

        # Verification must catch broken chain or index discontinuity
        is_valid, failed_index, reason = isolated_audit_chain.verify_chain()
        assert is_valid is False
        assert failed_index == 1
        assert "Block index discontinuity" in reason or "previous_hash mismatch" in reason


class TestComplianceReporting:
    """Unit tests for multi-standard compliance generation."""

    def test_generate_full_compliance_report(self, isolated_audit_chain):
        # Seal test event
        isolated_audit_chain.append_event({"compliance_test": True})

        generator = ComplianceReportGenerator(audit_chain=isolated_audit_chain)
        report = generator.generate_full_compliance_report()

        assert report["overall_compliance_status"] == "COMPLIANT"
        assert report["audit_trail_integrity"]["chain_valid"] is True
        assert "SOC_2_TYPE_II" in report["frameworks"]
        assert "ISO_IEC_27001_2022" in report["frameworks"]
        assert "GDPR_ARTICLE_32" in report["frameworks"]
        assert "SOX_SECTION_404" in report["frameworks"]


class TestGatewayHardeningAndComplianceEndpoints:
    """Live Gateway API tests for Phase 10 endpoints."""

    def test_liveness_and_readiness_probes(self):
        client = TestClient(app)

        live_res = client.get("/health/live")
        assert live_res.status_code == 200
        assert live_res.json()["status"] == "alive"

        ready_res = client.get("/health/ready")
        assert ready_res.status_code in (200, 503)
        assert "components" in ready_res.json()

    def test_compliance_report_api(self):
        client = TestClient(app)
        res = client.get("/api/compliance/report")
        assert res.status_code == 200
        data = res.json()
        assert "frameworks" in data
        assert "SOC_2_TYPE_II" in data["frameworks"]

    def test_compliance_verify_chain_api(self):
        client = TestClient(app)
        res = client.post("/api/compliance/verify-chain")
        assert res.status_code == 200
        data = res.json()
        assert "chain_intact" in data
        assert "verified_blocks" in data

    def test_ha_status_api(self):
        client = TestClient(app)
        res = client.get("/api/ha/status")
        assert res.status_code == 200
        data = res.json()
        assert "circuit_breaker" in data
        assert data["circuit_breaker"]["state"] in ("CLOSED", "OPEN", "HALF_OPEN")
