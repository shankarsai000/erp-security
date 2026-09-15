"""
Baseline Statistics Engine
Builds deterministic baselines from clean traffic.
Uses statistical thresholds, not ML models.
Pure math and statistics (median, percentiles, peak operational hours).
"""

import os
import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
import numpy as np

logger = logging.getLogger("gateway.baselines")

@dataclass
class BaselineStats:
    """Statistical baseline profile for a user/endpoint pair."""
    user_id: str
    endpoint: str
    
    # Request volume statistics
    call_count: int
    call_rate_per_hour: float  # Median calls/hour
    call_rate_p95: float  # 95th percentile calls/hour
    
    # Payload statistics
    request_size_median: int  # Bytes
    request_size_p95: int
    response_time_median: float  # Milliseconds
    response_time_p95: float
    
    # Temporal patterns
    peak_hours: List[int]  # [0-23] when user typically calls this endpoint
    
    # Metadata
    updated_at: str
    data_points: int  # Observations used to build this profile

class BaselineEngine:
    """
    Builds, validates, and maintains deterministic statistical baselines
    from clean Tier 1 telemetry events.
    """
    
    # Trustworthiness readiness gates per CRITICAL_IMPROVEMENTS_SUMMARY.md #2
    MIN_DATA_POINTS = 100
    MIN_EVENTS_TOTAL = 100_000
    MIN_DAYS = 30
    MIN_ENDPOINT_COVERAGE = 0.95  # 95% of endpoints have baselines
    MIN_USER_COVERAGE = 0.90      # 90% of users have baselines
    
    def __init__(self, baselines_path: str = "baselines/baselines.json"):
        self.baselines_path = baselines_path
        self.baselines: Dict[str, BaselineStats] = {}
        self.events_processed = 0
        self.unique_users_seen = set()
        self.unique_endpoints_seen = set()
        self.oldest_event_time: Optional[datetime] = None
        self.newest_event_time: Optional[datetime] = None
        
        if os.path.exists(self.baselines_path):
            self.load_baselines()

    def build_baseline_from_clean_events(
        self,
        events_file: str,
        min_samples: Optional[int] = None
    ):
        """
        Build baselines from clean telemetry events (e.g. events/baseline_candidates.jsonl).
        Only Tier 1 clean events are ingested to prevent baseline poisoning.
        """
        min_points = min_samples if min_samples is not None else self.MIN_DATA_POINTS
        if not os.path.exists(events_file):
            logger.warning("Telemetry file %s not found; skipping baseline build", events_file)
            return

        user_endpoint_data: Dict[str, Dict[str, List]] = {}
        logger.info("Building deterministic baselines from %s", events_file)

        with open(events_file, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue
                try:
                    event = json.loads(line_str)
                except Exception:
                    continue

                self.events_processed += 1
                
                # Extract user & endpoint references
                user_id = (
                    event.get("principal_ref")
                    or event.get("pseudonymized_user_id")
                    or event.get("user_id")
                    or "unknown"
                )
                endpoint = event.get("path") or event.get("endpoint") or "unknown"
                
                self.unique_users_seen.add(user_id)
                self.unique_endpoints_seen.add(endpoint)
                
                key = f"{user_id}:{endpoint}"
                if key not in user_endpoint_data:
                    user_endpoint_data[key] = {
                        "request_sizes": [],
                        "response_times": [],
                        "call_times": [],
                        "timestamps": []
                    }
                
                # Payload size
                req_size = int(event.get("request_size_bytes", 0) or len(str(event.get("body", ""))))
                user_endpoint_data[key]["request_sizes"].append(req_size)
                
                # Latency
                resp_time = float(event.get("latency_ms", 0.0) or event.get("response_time_ms", 0.0))
                user_endpoint_data[key]["response_times"].append(resp_time)
                
                # Timestamp & hour of day
                ts_str = event.get("timestamp")
                if ts_str:
                    try:
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        user_endpoint_data[key]["call_times"].append(ts.hour)
                        user_endpoint_data[key]["timestamps"].append(ts.timestamp())
                        
                        if self.oldest_event_time is None or ts < self.oldest_event_time:
                            self.oldest_event_time = ts
                        if self.newest_event_time is None or ts > self.newest_event_time:
                            self.newest_event_time = ts
                    except Exception:
                        pass

        # Compute deterministic statistics for each user-endpoint pair
        for key, data in user_endpoint_data.items():
            sizes = data["request_sizes"]
            times = data["response_times"]
            hours = data["call_times"]
            ts_list = data["timestamps"]
            
            if len(sizes) < min_points:
                logger.debug("Skipping %s: insufficient sample points (%d < %d)", key, len(sizes), min_points)
                continue

            user_id, endpoint = key.split(":", 1)
            
            call_rate_hour, call_rate_p95 = self._compute_call_rate(ts_list)
            
            baseline = BaselineStats(
                user_id=user_id,
                endpoint=endpoint,
                call_count=len(sizes),
                call_rate_per_hour=round(float(call_rate_hour), 2),
                call_rate_p95=round(float(call_rate_p95), 2),
                request_size_median=int(np.median(sizes)),
                request_size_p95=int(np.percentile(sizes, 95)),
                response_time_median=round(float(np.median(times)), 2),
                response_time_p95=round(float(np.percentile(times, 95)), 2),
                peak_hours=self._compute_peak_hours(hours),
                updated_at=datetime.now(timezone.utc).isoformat(),
                data_points=len(sizes)
            )
            self.baselines[key] = baseline

        logger.info(
            "Constructed %d user-endpoint baselines from %d processed clean events",
            len(self.baselines), self.events_processed
        )

    def _compute_call_rate(self, timestamps: List[float]) -> Tuple[float, float]:
        """Estimates median and 95th percentile calls per hour from timestamp deltas."""
        if len(timestamps) < 2:
            return 1.0, 1.0
        
        sorted_ts = sorted(timestamps)
        duration_hours = max((sorted_ts[-1] - sorted_ts[0]) / 3600.0, 0.01)
        mean_rate = len(sorted_ts) / duration_hours
        
        # Sliding 1-hour window counts
        window_sec = 3600.0
        hourly_counts = []
        i = 0
        for start_t in sorted_ts:
            count = sum(1 for t in sorted_ts if start_t <= t < (start_t + window_sec))
            hourly_counts.append(count)
        
        if hourly_counts:
            return float(np.median(hourly_counts)), float(np.percentile(hourly_counts, 95))
        return mean_rate, mean_rate * 1.5

    def _compute_peak_hours(self, call_hours: List[int]) -> List[int]:
        """Identifies top operational hours (up to top 8) for the principal."""
        if not call_hours:
            return list(range(8, 18))  # Default 8 AM - 6 PM standard business hours
        
        hour_counts: Dict[int, int] = {}
        for h in call_hours:
            hour_counts[h] = hour_counts.get(h, 0) + 1
            
        sorted_hours = sorted(hour_counts.items(), key=lambda x: x[1], reverse=True)
        return sorted([h for h, _ in sorted_hours[:8]])

    def get_baseline(self, user_id: str, endpoint: str) -> Optional[BaselineStats]:
        """Retrieves statistical baseline for a specific user and endpoint."""
        key = f"{user_id}:{endpoint}"
        return self.baselines.get(key)

    def evaluate_trustworthiness_gates(
        self,
        total_endpoints: int = 20,
        total_users: int = 500,
        min_events: Optional[int] = None
    ) -> Tuple[bool, List[str]]:
        """
        Evaluates whether baseline statistics satisfy enterprise readiness gates
        before higher-level ML or blocking models are allowed to deploy.
        Per CRITICAL_IMPROVEMENTS_SUMMARY.md #2:
        - Minimum 100,000 clean events
        - Minimum 30 days telemetry span
        - 95% endpoint coverage
        - 90% user coverage
        """
        blockers = []
        min_ev = min_events if min_events is not None else self.MIN_EVENTS_TOTAL

        # Gate 1: Event volume
        if self.events_processed < min_ev:
            blockers.append(
                f"Data volume gate failed: processed {self.events_processed} clean events (threshold: {min_ev})"
            )

        # Gate 2: Temporal duration
        if self.oldest_event_time and self.newest_event_time:
            span_days = (self.newest_event_time - self.oldest_event_time).total_seconds() / 86400.0
            if span_days < self.MIN_DAYS:
                blockers.append(
                    f"Temporal span gate failed: {span_days:.1f} days collected (threshold: {self.MIN_DAYS} days)"
                )
        else:
            blockers.append("Temporal span gate failed: insufficient timestamp history")

        # Gate 3: Endpoint coverage
        covered_endpoints = len(set(b.endpoint for b in self.baselines.values()))
        endpoint_coverage = covered_endpoints / max(total_endpoints, 1)
        if endpoint_coverage < self.MIN_ENDPOINT_COVERAGE:
            blockers.append(
                f"Endpoint coverage gate failed: {endpoint_coverage:.1%} covered (threshold: {self.MIN_ENDPOINT_COVERAGE:.1%})"
            )

        # Gate 4: User coverage
        covered_users = len(set(b.user_id for b in self.baselines.values()))
        user_coverage = covered_users / max(total_users, 1)
        if user_coverage < self.MIN_USER_COVERAGE:
            blockers.append(
                f"User coverage gate failed: {user_coverage:.1%} covered (threshold: {self.MIN_USER_COVERAGE:.1%})"
            )

        return len(blockers) == 0, blockers

    def save_baselines(self, output_file: Optional[str] = None):
        """Serializes statistical baseline dictionary to JSON."""
        out_path = output_file or self.baselines_path
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        
        serialized = {key: asdict(stat) for key, stat in self.baselines.items()}
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(serialized, f, indent=2)
        logger.info("Saved %d baselines to %s", len(self.baselines), out_path)

    def load_baselines(self, input_file: Optional[str] = None):
        """Loads baseline profiles from JSON file."""
        in_path = input_file or self.baselines_path
        if not os.path.exists(in_path):
            return
        
        with open(in_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            
        self.baselines = {}
        for key, item in data.items():
            self.baselines[key] = BaselineStats(**item)
        logger.info("Loaded %d baselines from %s", len(self.baselines), in_path)

baseline_engine = BaselineEngine()
