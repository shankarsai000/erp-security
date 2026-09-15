import os
import json
import time
import pytest
from gateway.telemetry.redaction import sanitize_telemetry, pseudonymize_identifier
from gateway.telemetry.event_pipeline import TelemetryPipeline
from gateway.telemetry.anti_poisoning import AntiPoisoningFilter
from gateway.telemetry.baseline_gates import evaluate_baseline_trustworthiness

class TestZeroPIIRedaction:
    def test_passwords_and_tokens_redacted(self):
        payload = {
            "username": "sales_john",
            "password": "SuperSecretPassword123!",
            "access_token": "eyJhbGciOiJIUzI1NiIsIn...",
            "authorization": "Bearer eyJhbGciOiJIUzI1NiIsIn...",
            "api_key": "sec_key_999888777",
            "secret": "my_master_secret"
        }
        sanitized = sanitize_telemetry(payload)
        assert sanitized["password"] == "[REDACTED]"
        assert sanitized["access_token"] == "[REDACTED]"
        assert sanitized["authorization"] == "[REDACTED]"
        assert sanitized["api_key"] == "[REDACTED]"
        assert sanitized["secret"] == "[REDACTED]"
        assert sanitized["username"] == "sales_john"

    def test_credit_card_and_email_scrubbed_from_text(self):
        payload = {
            "comment": "Contact me at alice.smith@company.com with card 4111 2222 3333 4444 please"
        }
        sanitized = sanitize_telemetry(payload)
        assert "[REDACTED_EMAIL]" in sanitized["comment"]
        assert "alice.smith@company.com" not in sanitized["comment"]
        assert "[REDACTED_CARD]" in sanitized["comment"]
        assert "4111 2222 3333 4444" not in sanitized["comment"]

    def test_pseudonymization_is_deterministic_and_irreversible(self):
        ref1 = pseudonymize_identifier("192.168.1.50")
        ref2 = pseudonymize_identifier("192.168.1.50")
        ref_diff = pseudonymize_identifier("10.0.0.99")
        
        assert ref1 == ref2
        assert ref1.startswith("p-")
        assert ref1 != ref_diff
        assert "192.168.1.50" not in ref1

    def test_risk_metrics_not_redacted(self):
        event = {
            "risk_score": 35.5,
            "components": {
                "waf_severity": 0.0,
                "auth_anomaly": 40.0,
                "rate_severity": 10.0,
                "sensitivity": 80.0
            }
        }
        sanitized = sanitize_telemetry(event)
        assert sanitized["components"]["auth_anomaly"] == 40.0
        assert sanitized["components"]["waf_severity"] == 0.0

class TestTelemetryEventPipeline:
    def test_pipeline_persistence_and_flush(self, tmp_path):
        test_dir = str(tmp_path / "test_events")
        pipeline = TelemetryPipeline(output_dir=test_dir)
        
        test_event = {
            "request_id": "req-telemetry-001",
            "decision": "ALLOW",
            "risk_score": 12.5,
            "latency_ms": 5.4,
            "principal_ref": "p-abc12345"
        }
        
        pipeline.emit(test_event)
        pipeline.flush()
        
        log_file = os.path.join(test_dir, "telemetry.jsonl")
        assert os.path.exists(log_file)
        
        with open(log_file, "r", encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]
            
        assert len(lines) >= 1
        assert any(e["request_id"] == "req-telemetry-001" for e in lines)
        pipeline.running = False

class TestAntiPoisoningQuarantine:
    def test_clean_session_classified_as_baseline(self, tmp_path):
        test_dir = str(tmp_path / "anti_poison")
        filter_engine = AntiPoisoningFilter(output_dir=test_dir)
        
        clean_event = {
            "request_id": "req-clean-100",
            "decision": "ALLOW",
            "risk_score": 15.0,
            "components": {"waf_severity": 0.0, "auth_anomaly": 0.0, "rate_severity": 0.0}
        }
        
        tier, quarantined = filter_engine.process_event(clean_event)
        filter_engine.flush()
        
        assert tier == "TIER_1_BASELINE"
        assert quarantined is False
        assert os.path.exists(filter_engine.baseline_file)
        filter_engine.running = False

    def test_medium_risk_throttled_session_routed_to_quarantine(self, tmp_path):
        test_dir = str(tmp_path / "anti_poison")
        filter_engine = AntiPoisoningFilter(output_dir=test_dir)
        
        throttled_event = {
            "request_id": "req-throttled-200",
            "decision": "LIMIT",
            "risk_score": 35.0,
            "components": {"waf_severity": 0.0, "auth_anomaly": 0.0, "rate_severity": 30.0}
        }
        
        tier, quarantined = filter_engine.process_event(throttled_event)
        filter_engine.flush()
        
        assert tier == "TIER_2_REVIEW"
        assert quarantined is True
        assert os.path.exists(filter_engine.quarantine_file)
        filter_engine.running = False

    def test_attack_and_block_session_routed_to_quarantine(self, tmp_path):
        test_dir = str(tmp_path / "anti_poison")
        filter_engine = AntiPoisoningFilter(output_dir=test_dir)
        
        attack_event = {
            "request_id": "req-attack-300",
            "decision": "BLOCK",
            "risk_score": 90.0,
            "reasons": ["SQL injection attempt detected"],
            "components": {"waf_severity": 95.0, "auth_anomaly": 0.0, "rate_severity": 0.0}
        }
        
        tier, quarantined = filter_engine.process_event(attack_event)
        filter_engine.flush()
        
        assert tier == "TIER_3_QUARANTINE"
        assert quarantined is True
        assert os.path.exists(filter_engine.quarantine_file)
        filter_engine.running = False

class TestBaselineTrustworthinessGates:
    def test_gates_fail_when_insufficient_duration_or_events(self):
        # Scenario: Only 10 days of collection and 25,000 events (Day 30 requires >= 30 days and >= 100k events)
        metrics = {
            "days_collected": 10,
            "total_events": 25000,
            "analyst_reviews": 100,
            "false_positive_rate": 0.01,
            "endpoint_coverage": 0.98
        }
        result = evaluate_baseline_trustworthiness(metrics)
        assert result.is_ready_for_ml is False
        assert any("Days collected" in r for r in result.failed_gates)
        assert any("Total events" in r for r in result.failed_gates)

    def test_gates_pass_when_all_readiness_criteria_met(self):
        # Scenario: Day 30 readiness criteria all met
        metrics = {
            "days_collected": 32,
            "total_events": 125000,
            "analyst_reviews": 550,
            "false_positive_rate": 0.012,  # < 2% target
            "endpoint_coverage": 0.97      # >= 95% target
        }
        result = evaluate_baseline_trustworthiness(metrics)
        assert result.is_ready_for_ml is True
        assert len(result.failed_gates) == 0
        assert len(result.passed_gates) >= 5

