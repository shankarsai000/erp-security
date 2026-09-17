"""
Feature Engineering for ML Anomaly Detection Models
Extracts multi-dimensional behavioral, temporal, volumetric, and trust features.
"""

from collections import Counter
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import math
from typing import Dict, List, Optional, Any
import numpy as np
import logging

logger = logging.getLogger(__name__)

FEATURE_NAMES = [
    "request_count_1h",
    "request_count_1d",
    "unique_endpoints_1h",
    "unique_endpoints_1d",
    "request_size_deviation",
    "response_time_deviation",
    "hour_of_day",
    "day_of_week",
    "is_peak_hour",
    "endpoint_entropy",
    "time_between_requests",
    "account_age_days",
    "past_incident_count",
    "device_diversity",
    "payload_size_bytes",
    "method_is_mutation"
]


@dataclass
class Features:
    """Multi-dimensional behavioral, temporal, and volumetric features for ML models."""
    # Volume features
    request_count_1h: int
    request_count_1d: int
    unique_endpoints_1h: int
    unique_endpoints_1d: int
    
    # Statistical deviations against baseline
    request_size_deviation: float  # (actual - median) / max(median, 1)
    response_time_deviation: float  # (actual - median) / max(median, 1)
    
    # Temporal features
    hour_of_day: int
    day_of_week: int
    is_peak_hour: bool
    
    # Behavioral features
    endpoint_entropy: float  # Shannon entropy of recent endpoint access
    api_sequence_pattern: str  # Encoded transition representation
    time_between_requests: float  # Average seconds between requests
    
    # Trust & identity features
    account_age_days: int
    past_incident_count: int
    device_diversity: int  # Distinct client IP / User-Agent combinations
    
    # Payload & protocol features
    payload_size_bytes: int
    method_is_mutation: float  # 1.0 for POST/PUT/DELETE/PATCH, 0.0 for GET/HEAD

    def to_vector(self) -> List[float]:
        """Convert features to a numeric vector for scikit-learn models."""
        return [
            float(self.request_count_1h),
            float(self.request_count_1d),
            float(self.unique_endpoints_1h),
            float(self.unique_endpoints_1d),
            float(self.request_size_deviation),
            float(self.response_time_deviation),
            float(self.hour_of_day),
            float(self.day_of_week),
            1.0 if self.is_peak_hour else 0.0,
            float(self.endpoint_entropy),
            float(self.time_between_requests),
            float(self.account_age_days),
            float(self.past_incident_count),
            float(self.device_diversity),
            float(self.payload_size_bytes),
            float(self.method_is_mutation)
        ]

    def to_dict(self) -> Dict[str, Any]:
        """Return features as a dictionary."""
        return asdict(self)


class FeatureExtractor:
    """Extract ML-ready feature vectors from request telemetry and baseline engines."""

    def extract_features(
        self,
        user_events: Optional[List[dict]] = None,
        baseline_engine: Any = None,
        current_event: Optional[dict] = None
    ) -> Features:
        """
        Extract features from recent user events and current request context.
        """
        events = list(user_events or [])
        if current_event:
            # Current event is the focal evaluation point
            curr = current_event
        elif events:
            curr = events[-1]
        else:
            return self._default_features()

        now_epoch = curr.get("ts_epoch")
        if now_epoch is None:
            now_dt = self._parse_iso_timestamp(curr.get("timestamp"))
            now_epoch = now_dt.timestamp()
            hour_of_day = curr.get("hour_of_day", now_dt.hour)
            day_of_week = curr.get("day_of_week", now_dt.weekday())
        else:
            hour_of_day = curr.get("hour_of_day")
            day_of_week = curr.get("day_of_week")
            if hour_of_day is None or day_of_week is None:
                now_dt = datetime.fromtimestamp(now_epoch, tz=timezone.utc)
                hour_of_day = now_dt.hour if hour_of_day is None else hour_of_day
                day_of_week = now_dt.weekday() if day_of_week is None else day_of_week

        # 1. Volume & Endpoint Diversity in 1h and 1d windows
        req_1h = 0
        req_1d = 0
        endpoints_1h = set()
        endpoints_1d = set()
        devices = set()
        inter_arrival_times = []
        recent_endpoints = []

        prev_epoch = None
        for ev in events:
            ev_epoch = ev.get("ts_epoch")
            if ev_epoch is None:
                ev_epoch = self._parse_iso_timestamp(ev.get("timestamp")).timestamp()

            age_sec = max(0.0, now_epoch - ev_epoch)
            path = ev.get("path", "")
            ip = ev.get("client_ip", "")
            ua = ev.get("user_agent", "")
            if ip or ua:
                devices.add(f"{ip}:{ua}")

            if age_sec <= 3600.0:
                req_1h += 1
                if path:
                    endpoints_1h.add(path)

            if age_sec <= 86400.0:
                req_1d += 1
                if path:
                    endpoints_1d.add(path)

            if path:
                recent_endpoints.append(path)

            # Compute inter-arrival deltas
            if prev_epoch is not None:
                delta = max(0.0, ev_epoch - prev_epoch)
                inter_arrival_times.append(delta)
            prev_epoch = ev_epoch

        # Ensure current request is counted if not already in user_events
        if current_event and current_event not in events:
            req_1h += 1
            req_1d += 1
            c_path = curr.get("path", "")
            if c_path:
                endpoints_1h.add(c_path)
                endpoints_1d.add(c_path)
                recent_endpoints.append(c_path)
            c_ip = curr.get("client_ip", "")
            c_ua = curr.get("user_agent", "")
            if c_ip or c_ua:
                devices.add(f"{c_ip}:{c_ua}")

        # 2. Statistical Baseline Deviations
        user_id = curr.get("user_id") or curr.get("principal_ref") or "anonymous"
        endpoint = curr.get("path", "")
        payload_size = curr.get("request_size_bytes") or curr.get("payload_size_bytes") or 0
        resp_time = curr.get("latency_ms") or curr.get("response_time_ms") or 0.0

        size_dev = 0.0
        resp_dev = 0.0
        is_peak = True

        if baseline_engine is not None:
            baseline = baseline_engine.get_baseline(user_id, endpoint)
            if baseline:
                if baseline.request_size_median > 0:
                    size_dev = (payload_size - baseline.request_size_median) / baseline.request_size_median
                if baseline.response_time_median > 0:
                    resp_dev = (resp_time - baseline.response_time_median) / baseline.response_time_median
                if baseline.peak_hours:
                    is_peak = (hour_of_day in baseline.peak_hours)
            else:
                # Unseen endpoint / path: mark deviation if payload or latency is unusually high
                if payload_size > 4096:
                    size_dev = float((payload_size - 512) / 512)
                if resp_time > 100.0:
                    resp_dev = float((resp_time - 20.0) / 20.0)
                is_peak = False
        else:
            if payload_size > 4096:
                size_dev = float((payload_size - 512) / 512)
            if resp_time > 100.0:
                resp_dev = float((resp_time - 20.0) / 20.0)

        # 3. Behavioral Features: Entropy & Sequence pattern
        # Look at last 20 endpoints for entropy
        entropy_endpoints = recent_endpoints[-20:] if recent_endpoints else [endpoint]
        endpoint_entropy = self._compute_entropy(entropy_endpoints)
        
        # Sequence pattern encoding: comma-separated sequence of last 5 paths
        seq_pattern = "->".join(recent_endpoints[-5:]) if recent_endpoints else endpoint

        # Mean inter-arrival time
        mean_inter_arrival = (
            float(np.mean(inter_arrival_times)) if inter_arrival_times else 30.0
        )

        # 4. Trust & Identity Features
        account_age = curr.get("user_account_age_days") or curr.get("account_age_days", 365)
        past_incidents = curr.get("user_incident_count") or curr.get("past_incident_count", 0)
        device_div = max(1, len(devices))

        # 5. Method Mutation
        method = curr.get("method", "GET").upper()
        is_mutation = 1.0 if method in ("POST", "PUT", "DELETE", "PATCH") else 0.0

        return Features(
            request_count_1h=req_1h,
            request_count_1d=req_1d,
            unique_endpoints_1h=max(1, len(endpoints_1h)),
            unique_endpoints_1d=max(1, len(endpoints_1d)),
            request_size_deviation=float(round(size_dev, 4)),
            response_time_deviation=float(round(resp_dev, 4)),
            hour_of_day=int(hour_of_day),
            day_of_week=int(day_of_week),
            is_peak_hour=bool(is_peak),
            endpoint_entropy=float(round(endpoint_entropy, 4)),
            api_sequence_pattern=seq_pattern,
            time_between_requests=float(round(mean_inter_arrival, 2)),
            account_age_days=int(account_age),
            past_incident_count=int(past_incidents),
            device_diversity=int(device_div),
            payload_size_bytes=int(payload_size),
            method_is_mutation=float(is_mutation)
        )

    def _compute_entropy(self, values: List[str]) -> float:
        """Compute normalized Shannon entropy: H = -sum(p * log2(p))."""
        if not values or len(values) <= 1:
            return 0.0
        counts = Counter(values)
        total = float(len(values))
        entropy = -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)
        return float(entropy)

    def _parse_iso_timestamp(self, ts: Optional[str]) -> datetime:
        """Safely parse ISO timestamp with UTC fallback."""
        if not ts:
            return datetime.now(timezone.utc)
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except Exception:
            return datetime.now(timezone.utc)

    def _default_features(self) -> Features:
        """Safe neutral defaults for cold-start requests."""
        now = datetime.now(timezone.utc)
        return Features(
            request_count_1h=1,
            request_count_1d=1,
            unique_endpoints_1h=1,
            unique_endpoints_1d=1,
            request_size_deviation=0.0,
            response_time_deviation=0.0,
            hour_of_day=now.hour,
            day_of_week=now.weekday(),
            is_peak_hour=True,
            endpoint_entropy=0.0,
            api_sequence_pattern="root",
            time_between_requests=60.0,
            account_age_days=365,
            past_incident_count=0,
            device_diversity=1,
            payload_size_bytes=256,
            method_is_mutation=0.0
        )
