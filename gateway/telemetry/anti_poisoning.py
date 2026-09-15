import os
import json
import logging
import queue
import threading
from enum import Enum
from typing import Dict, Any, Tuple

logger = logging.getLogger("gateway.telemetry.anti_poisoning")

class EventTier(str, Enum):
    TIER_1_PRISTINE = "tier_1_pristine_baseline"
    TIER_2_REVIEW = "tier_2_review_quarantine"
    TIER_3_HARD_QUARANTINE = "tier_3_hard_quarantine"

class AntiPoisoningFilter:
    """
    Enforces 'Allowed != Normal'. Excludes suspicious, flagged, or elevated risk
    sessions from contaminating the machine learning baseline (Critical Improvement #3, #10).
    Routes events across 3 tiers (Pristine Baseline, Review Quarantine, Hard Quarantine).
    Uses background worker queue for non-blocking disk persistence.
    """
    def __init__(self, output_dir: str = "events", max_queue_size: int = 10000):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        self.baseline_file = os.path.join(self.output_dir, "baseline_candidates.jsonl")
        self.quarantine_file = os.path.join(self.output_dir, "quarantined_events.jsonl")
        self.queue = queue.Queue(maxsize=max_queue_size)
        self.running = True
        self._worker = threading.Thread(target=self._process_queue, daemon=True)
        self._worker.start()

    def classify_event(self, event: Dict[str, Any]) -> EventTier:
        """
        Classifies incoming telemetry event into one of 3 tiers.
        Only TIER_1_PRISTINE events may ever enter baseline models.
        """
        decision = str(event.get("decision", "ALLOW")).upper()
        risk_score = float(event.get("risk_score", 0.0))
        rule_count = len(event.get("fired_rules", []))
        user_age_days = event.get("user_account_age_days", 30)
        incident_count = event.get("user_incident_count", 0)
        components = event.get("components", {})
        
        waf_severity = float(components.get("waf_severity", 0.0) or 0.0)
        auth_anomaly = float(components.get("auth_anomaly", 0.0) or 0.0)

        # Hard VETO: Blocking decisions, explicit attacks, or critical risk go directly to Tier 3 Hard Quarantine
        if decision == "BLOCK" or waf_severity > 0 or auth_anomaly > 0 or risk_score > 50.0:
            return EventTier.TIER_3_HARD_QUARANTINE

        # VETO: Accounts under 7 days or accounts with prior incident history go to Tier 2 Review
        if user_age_days < 7 or incident_count > 0:
            return EventTier.TIER_2_REVIEW

        # Tier 2 Review: Throttled / LIMIT decision, moderate risk, or rule firings
        if decision == "LIMIT" or 20.0 < risk_score <= 50.0 or rule_count > 0:
            return EventTier.TIER_2_REVIEW

        # Tier 1 Pristine Baseline: Low risk (<= 20), ALLOW, 0 rule firings, clean trusted session
        if decision == "ALLOW" and risk_score <= 20.0 and rule_count == 0:
            return EventTier.TIER_1_PRISTINE

        return EventTier.TIER_3_HARD_QUARANTINE

    def process_event(self, event: Dict[str, Any]) -> Tuple[str, bool]:
        """
        Classifies and routes event into 'baseline' or 'quarantine' in memory,
        and enqueues disk write asynchronously.
        Returns: (tier_classification, is_quarantined)
        """
        tier = self.classify_event(event)

        if tier == EventTier.TIER_1_PRISTINE:
            event["quarantined"] = False
            event["tier"] = tier.value
            self._enqueue(self.baseline_file, event)
            return "TIER_1_BASELINE", False

        if tier == EventTier.TIER_2_REVIEW:
            event["quarantined"] = True
            event["tier"] = tier.value
            event["quarantine_reasons"] = ["Moderate risk score or review quarantine - awaiting analyst review"]
            self._enqueue(self.quarantine_file, event)
            return "TIER_2_REVIEW", True

        # Tier 3 Hard Quarantine
        event["quarantined"] = True
        event["tier"] = tier.value
        event["quarantine_reasons"] = event.get("reasons") or ["Elevated risk, security attack or blocking decision"]
        self._enqueue(self.quarantine_file, event)
        return "TIER_3_QUARANTINE", True

    def _enqueue(self, file_path: str, data: Dict[str, Any]):
        try:
            self.queue.put_nowait((file_path, data))
        except queue.Full:
            self._append_jsonl(file_path, data)

    def _process_queue(self):
        while self.running:
            try:
                file_path, data = self.queue.get(timeout=1.0)
                self._append_jsonl(file_path, data)
                self.queue.task_done()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Error persisting anti-poisoning event: {e}")

    def _append_jsonl(self, file_path: str, data: Dict[str, Any]):
        try:
            with open(file_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(data) + "\n")
        except Exception as e:
            logger.error(f"Failed writing anti-poisoning log {file_path}: {e}")

    def flush(self):
        while not self.queue.empty():
            try:
                file_path, data = self.queue.get_nowait()
                self._append_jsonl(file_path, data)
                self.queue.task_done()
            except queue.Empty:
                break

anti_poisoning_filter = AntiPoisoningFilter()
AntiPoisoningTriage = AntiPoisoningFilter

