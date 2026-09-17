"""SOC Analyst Feedback and Continuous Rule Tuning Engine (Phase 9).

Ingests analyst feedback on detections, maintains an immutable journal in events/soc_feedback.jsonl,
computes precision/recall analytics per rule, and generates automated threshold tuning recommendations.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
import json
import logging
from pathlib import Path
import threading
from typing import Dict, List, Optional, Any
import uuid

logger = logging.getLogger(__name__)


class FeedbackTag(str, Enum):
    FALSE_POSITIVE = "FALSE_POSITIVE"
    FALSE_NEGATIVE = "FALSE_NEGATIVE"
    CONFIRMED_ATTACK = "CONFIRMED_ATTACK"
    TUNING_REQUEST = "TUNING_REQUEST"


@dataclass
class SOCFeedbackRecord:
    """Feedback submitted by a SOC security analyst on a detection event or alert."""
    feedback_id: str = field(default_factory=lambda: f"fb-{uuid.uuid4().hex[:10]}")
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    analyst_id: str = "soc_analyst"
    tag: FeedbackTag = FeedbackTag.CONFIRMED_ATTACK
    request_id: Optional[str] = None
    alert_id: Optional[str] = None
    rule_id: Optional[str] = None
    notes: str = ""
    target_entity: Optional[str] = None
    recommended_action: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["tag"] = self.tag.value
        return d


class SOCFeedbackEngine:
    """Maintains SOC analyst verdicts, evaluates rule accuracy, and proposes tuning."""

    def __init__(self, feedback_file: str = "events/soc_feedback.jsonl"):
        self.feedback_file = Path(feedback_file)
        self.feedback_file.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.records: List[SOCFeedbackRecord] = []
        self._load_existing_records()

    def _load_existing_records(self) -> None:
        if not self.feedback_file.exists():
            return
        try:
            with open(self.feedback_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        d = json.loads(line)
                        d["tag"] = FeedbackTag(d.get("tag", "CONFIRMED_ATTACK"))
                        self.records.append(SOCFeedbackRecord(**d))
        except Exception as e:
            logger.warning(f"Error loading existing SOC feedback: {e}")

    def submit_feedback(
        self,
        tag: FeedbackTag,
        analyst_id: str = "soc_analyst",
        request_id: Optional[str] = None,
        alert_id: Optional[str] = None,
        rule_id: Optional[str] = None,
        notes: str = "",
        target_entity: Optional[str] = None,
        recommended_action: Optional[str] = None
    ) -> SOCFeedbackRecord:
        """Records an analyst verdict and appends to persistent journal."""
        record = SOCFeedbackRecord(
            analyst_id=analyst_id,
            tag=tag,
            request_id=request_id,
            alert_id=alert_id,
            rule_id=rule_id,
            notes=notes,
            target_entity=target_entity,
            recommended_action=recommended_action
        )

        with self._lock:
            self.records.append(record)
            try:
                with open(self.feedback_file, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record.to_dict()) + "\n")
            except Exception as e:
                logger.error(f"Failed to persist SOC feedback {record.feedback_id}: {e}")

        logger.info(f"SOC FEEDBACK: {record.feedback_id} [{record.tag.value}] by {analyst_id} on rule={rule_id}")
        return record

    def get_accuracy_metrics(self) -> Dict[str, Any]:
        """Calculates rule precision and false positive rates based on analyst tags."""
        with self._lock:
            total = len(self.records)
            by_tag = {t.value: 0 for t in FeedbackTag}
            rule_stats: Dict[str, Dict[str, int]] = {}

            for r in self.records:
                by_tag[r.tag.value] = by_tag.get(r.tag.value, 0) + 1
                if r.rule_id:
                    if r.rule_id not in rule_stats:
                        rule_stats[r.rule_id] = {"TP": 0, "FP": 0, "FN": 0, "total": 0}
                    rule_stats[r.rule_id]["total"] += 1
                    if r.tag == FeedbackTag.CONFIRMED_ATTACK:
                        rule_stats[r.rule_id]["TP"] += 1
                    elif r.tag == FeedbackTag.FALSE_POSITIVE:
                        rule_stats[r.rule_id]["FP"] += 1
                    elif r.tag == FeedbackTag.FALSE_NEGATIVE:
                        rule_stats[r.rule_id]["FN"] += 1

            # Precision per rule
            rule_precision = {}
            for r_id, stats in rule_stats.items():
                evaluated = stats["TP"] + stats["FP"]
                precision = (stats["TP"] / evaluated) if evaluated > 0 else 1.0
                rule_precision[r_id] = {
                    "precision": round(precision, 3),
                    "false_positive_count": stats["FP"],
                    "confirmed_attack_count": stats["TP"],
                    "total_feedbacks": stats["total"]
                }

            overall_evaluated = by_tag["CONFIRMED_ATTACK"] + by_tag["FALSE_POSITIVE"]
            overall_precision = (by_tag["CONFIRMED_ATTACK"] / overall_evaluated) if overall_evaluated > 0 else 1.0

            return {
                "total_feedbacks": total,
                "feedback_by_tag": by_tag,
                "overall_precision": round(overall_precision, 3),
                "rule_precision": rule_precision
            }

    def generate_tuning_recommendations(self) -> List[Dict[str, Any]]:
        """Analyzes recurring false positives and outputs safe, bounded tuning recommendations."""
        recommendations = []
        metrics = self.get_accuracy_metrics()
        rule_precision = metrics.get("rule_precision", {})

        with self._lock:
            for rule_id, stats in rule_precision.items():
                fp_count = stats.get("false_positive_count", 0)
                precision = stats.get("precision", 1.0)

                # Flag rules with elevated FP count or precision below 80%
                if fp_count >= 2 or precision < 0.80:
                    if rule_id == "R006":  # Mass scraping
                        recommendations.append({
                            "rule_id": rule_id,
                            "type": "THRESHOLD_INCREASE",
                            "current_precision": precision,
                            "false_positive_count": fp_count,
                            "recommendation": "Increase mass scraping threshold from 15 req/5s to 25 req/5s or whitelist batch sync endpoints.",
                            "safety_guard": "Max threshold allowed is 50 req/5s to maintain scraper protection."
                        })
                    elif rule_id == "R002":  # Duplicate orders
                        recommendations.append({
                            "rule_id": rule_id,
                            "type": "WINDOW_TIGHTENING",
                            "current_precision": precision,
                            "false_positive_count": fp_count,
                            "recommendation": "Reduce duplicate order check window from 5s to 2s to allow legitimate rapid re-orders.",
                            "safety_guard": "Min window allowed is 1s."
                        })
                    else:
                        recommendations.append({
                            "rule_id": rule_id,
                            "type": "RULE_SENSITIVITY_TUNE",
                            "current_precision": precision,
                            "false_positive_count": fp_count,
                            "recommendation": f"Add path exemption or require secondary confirmation for {rule_id}.",
                            "safety_guard": "Requires senior security engineer sign-off before applying."
                        })

        return recommendations

    def export_labeled_events(self) -> List[Dict[str, Any]]:
        """Exports analyst-verified events as ground-truth labels for ML retraining."""
        with self._lock:
            labeled = []
            for r in self.records:
                if r.request_id and r.tag in (FeedbackTag.CONFIRMED_ATTACK, FeedbackTag.FALSE_POSITIVE):
                    labeled.append({
                        "request_id": r.request_id,
                        "ground_truth_label": 1 if r.tag == FeedbackTag.CONFIRMED_ATTACK else 0,
                        "tag": r.tag.value,
                        "rule_id": r.rule_id,
                        "analyst_id": r.analyst_id
                    })
            return labeled


# Singleton instance for gateway application
soc_feedback_engine = SOCFeedbackEngine()
