import os
import json
import logging
import queue
import threading
from typing import Dict, Any, Tuple

logger = logging.getLogger("gateway.telemetry.anti_poisoning")

class AntiPoisoningFilter:
    """
    Enforces 'Allowed != Normal'. Excludes suspicious, flagged, or elevated risk
    sessions from contaminating the machine learning baseline (Critical Improvement #3, #10).
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

    def process_event(self, event: Dict[str, Any]) -> Tuple[str, bool]:
        """
        Classifies and routes event into 'baseline' or 'quarantine' in memory,
        and enqueues disk write asynchronously.
        Returns: (tier_classification, is_quarantined)
        """
        risk_score = float(event.get("risk_score", 0.0))
        reasons = event.get("reasons", [])
        decision = event.get("decision", "ALLOW")
        components = event.get("components", {})
        
        try:
            waf_severity = float(components.get("waf_severity", 0.0) or 0.0)
        except (ValueError, TypeError):
            waf_severity = 0.0

        try:
            auth_anomaly = float(components.get("auth_anomaly", 0.0) or 0.0)
        except (ValueError, TypeError):
            auth_anomaly = 0.0

        try:
            rate_severity = float(components.get("rate_severity", 0.0) or 0.0)
        except (ValueError, TypeError):
            rate_severity = 0.0
        
        # Tier 3: Hard Quarantine (Attacks, high risk, or any blocking policy)
        if decision == "BLOCK" or risk_score > 50.0 or waf_severity > 0 or auth_anomaly > 0:
            event["quarantined"] = True
            event["quarantine_reasons"] = reasons or ["Elevated risk or security anomaly detected"]
            self._enqueue(self.quarantine_file, event)
            return "TIER_3_QUARANTINE", True
            
        # Tier 2: Medium Risk / Throttled (Needs review before baseline inclusion)
        if 20.0 < risk_score <= 50.0 or decision == "LIMIT":
            event["quarantined"] = True
            event["quarantine_reasons"] = ["Moderate risk score - awaiting analyst review"]
            self._enqueue(self.quarantine_file, event)
            return "TIER_2_REVIEW", True
            
        # Tier 1: Pristine Baseline Candidate (Allowed, risk <= 20, 0 rule firings)
        event["quarantined"] = False
        self._enqueue(self.baseline_file, event)
        return "TIER_1_BASELINE", False

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

