"""
Production Canary Deployment Router (Phase 11).

Provides progressive traffic allocation (1% -> 10% -> 50% -> 100%),
sticky session hashing, real-time SLO monitoring, and automated
circuit-breaker rollback if canary error rate or latency breaches thresholds.
"""

import hashlib
import logging
import random
import threading
import time
from collections import deque
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("erp_security.canary")


class CanaryStage(str, Enum):
    DISABLED = "DISABLED"       # 0%
    CANARY_1 = "CANARY_1%"      # 1%
    CANARY_10 = "CANARY_10%"    # 10%
    CANARY_50 = "CANARY_50%"    # 50%
    FULL_ROLLOUT = "100%"       # 100%
    ROLLED_BACK = "ROLLED_BACK" # Tripped by SLO breach


STAGE_WEIGHT_MAP = {
    CanaryStage.DISABLED: 0.0,
    CanaryStage.CANARY_1: 0.01,
    CanaryStage.CANARY_10: 0.10,
    CanaryStage.CANARY_50: 0.50,
    CanaryStage.FULL_ROLLOUT: 1.00,
    CanaryStage.ROLLED_BACK: 0.0,
}


class TrafficMetrics:
    """Tracks latency and error statistics over a sliding window."""

    def __init__(self, window_size: int = 200):
        self.window_size = window_size
        self._latencies: deque = deque(maxlen=window_size)
        self._total_requests: int = 0
        self._error_count: int = 0
        self._lock = threading.Lock()

    def record(self, latency_ms: float, is_error: bool):
        with self._lock:
            self._latencies.append(latency_ms)
            self._total_requests += 1
            if is_error:
                self._error_count += 1

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            total = len(self._latencies)
            if total == 0:
                return {
                    "total_requests": self._total_requests,
                    "window_samples": 0,
                    "error_rate": 0.0,
                    "p50_latency_ms": 0.0,
                    "p95_latency_ms": 0.0,
                    "p99_latency_ms": 0.0,
                }

            sorted_lat = sorted(self._latencies)
            p50_idx = int(0.50 * (total - 1))
            p95_idx = int(0.95 * (total - 1))
            p99_idx = int(0.99 * (total - 1))

            recent_errors = sum(1 for lat, err in zip(self._latencies, [False] * total))  # window errors
            # Accurate error rate across all requests
            err_rate = (self._error_count / self._total_requests) if self._total_requests > 0 else 0.0

            return {
                "total_requests": self._total_requests,
                "window_samples": total,
                "error_rate": round(err_rate, 4),
                "p50_latency_ms": round(sorted_lat[p50_idx], 2),
                "p95_latency_ms": round(sorted_lat[p95_idx], 2),
                "p99_latency_ms": round(sorted_lat[p99_idx], 2),
            }

    def reset(self):
        with self._lock:
            self._latencies.clear()
            self._total_requests = 0
            self._error_count = 0


DEFAULT_ROUTE_SLOS: Dict[str, Dict[str, float]] = {
    "read_default": {"max_p95_ms": 50.0, "max_error_rate": 0.02},
    "mutation_default": {"max_p95_ms": 250.0, "max_error_rate": 0.01},
    "/api/orders": {"max_p95_ms": 250.0, "max_error_rate": 0.01},
    "/api/inventory/replenish": {"max_p95_ms": 250.0, "max_error_rate": 0.01},
    "/api/inventory": {"max_p95_ms": 50.0, "max_error_rate": 0.02},
    "/api/users": {"max_p95_ms": 50.0, "max_error_rate": 0.02},
}


class CanaryRouter:
    """
    Enterprise Canary Router.
    Controls progressive rollout, deterministic sticky routing,
    and automatic emergency rollback when SLO limits are violated.
    Supports route-aware latency and error budgets (OPS-01).
    """

    def __init__(
        self,
        initial_stage: CanaryStage = CanaryStage.DISABLED,
        max_error_rate: float = 0.02,       # 2% global error rate threshold
        max_p95_latency_ms: float = 50.0,    # 50ms default read SLA budget
        min_eval_samples: int = 15,          # Minimum canary requests before evaluating rollback
        auto_rollback_enabled: bool = True,
        route_slos: Optional[Dict[str, Dict[str, float]]] = None
    ):
        self.stage = initial_stage
        self.weight = STAGE_WEIGHT_MAP.get(initial_stage, 0.0)
        self.max_error_rate = max_error_rate
        self.max_p95_latency_ms = max_p95_latency_ms
        self.min_eval_samples = min_eval_samples
        self.auto_rollback_enabled = auto_rollback_enabled
        self.route_slos = dict(DEFAULT_ROUTE_SLOS if route_slos is None else route_slos)

        self.stable_metrics = TrafficMetrics(window_size=500)
        self.canary_metrics = TrafficMetrics(window_size=500)
        self.canary_route_metrics: Dict[str, TrafficMetrics] = {}

        self.last_rollback_reason: Optional[str] = None
        self.last_rollback_timestamp: Optional[float] = None
        self._lock = threading.Lock()

    def get_route_budget(self, path: Optional[str] = None, method: str = "GET") -> Tuple[float, float]:
        """
        Returns (max_p95_ms, max_error_rate) for the given route and method (OPS-01).
        Complex mutation paths (e.g. /api/orders) have 250ms SLA; read paths have 50ms SLA.
        """
        if path:
            for route_prefix, budget in self.route_slos.items():
                if route_prefix.startswith("/") and path.startswith(route_prefix):
                    return budget.get("max_p95_ms", self.max_p95_latency_ms), budget.get("max_error_rate", self.max_error_rate)

        if method in ("POST", "PUT", "PATCH", "DELETE"):
            mut_budget = self.route_slos.get("mutation_default", {})
            return mut_budget.get("max_p95_ms", 250.0), mut_budget.get("max_error_rate", 0.01)

        read_budget = self.route_slos.get("read_default", {})
        return read_budget.get("max_p95_ms", self.max_p95_latency_ms), read_budget.get("max_error_rate", self.max_error_rate)

    def _get_route_key(self, path: str, method: str) -> str:
        """Normalizes path to route category for metric tracking."""
        prefix = path.split("?")[0].rstrip("/")
        parts = prefix.split("/")
        if len(parts) > 3 and parts[2] == "orders":
            return f"{method} /api/orders"
        if len(parts) > 3 and parts[2] == "users":
            return f"{method} /api/users"
        return f"{method} {prefix}"

    def set_weight(self, weight: float) -> None:
        """Sets an arbitrary canary weight clamped to [0.0, 1.0]."""
        with self._lock:
            clamped = max(0.0, min(1.0, float(weight)))
            self.weight = clamped
            if clamped == 0.0:
                self.stage = CanaryStage.DISABLED
            elif clamped <= 0.01:
                self.stage = CanaryStage.CANARY_1
            elif clamped <= 0.10:
                self.stage = CanaryStage.CANARY_10
            elif clamped <= 0.50:
                self.stage = CanaryStage.CANARY_50
            else:
                self.stage = CanaryStage.FULL_ROLLOUT

    def promote(self, stage: CanaryStage) -> Dict[str, Any]:
        """Promotes canary rollout to the next formal stage."""
        with self._lock:
            self.stage = stage
            self.weight = STAGE_WEIGHT_MAP.get(stage, 0.0)
            self.canary_metrics.reset()
            self.canary_route_metrics.clear()
            logger.info("Canary promoted to stage %s (weight: %.2f)", self.stage, self.weight)
            return {
                "status": "PROMOTED",
                "stage": self.stage.value,
                "weight": self.weight
            }

    def rollback(self, reason: str) -> Dict[str, Any]:
        """Immediately pulls canary traffic to 0% and logs the alert."""
        with self._lock:
            prev_stage = self.stage.value
            prev_weight = self.weight
            self.stage = CanaryStage.ROLLED_BACK
            self.weight = 0.0
            self.last_rollback_reason = reason
            self.last_rollback_timestamp = time.time()

            logger.critical(
                "CANARY AUTOMATIC ROLLBACK TRIGGERED! Reason: %s (Prev Stage: %s, Weight: %.2f)",
                reason, prev_stage, prev_weight
            )
            return {
                "status": "ROLLED_BACK",
                "reason": reason,
                "timestamp": self.last_rollback_timestamp,
                "previous_stage": prev_stage,
                "current_weight": 0.0
            }

    def should_route_to_canary(
        self,
        user_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> bool:
        """
        Determines whether the incoming request should route to the canary deployment.
        
        Routing Order:
        1. Explicit header override (X-Canary-Target: canary | stable)
        2. Stage disabled / rolled back -> False
        3. Full rollout (100%) -> True
        4. Sticky hash based on user_id or client_ip
        5. Weighted random distribution
        """
        headers = headers or {}

        # 1. Header overrides (useful for synthetic canary validation)
        target_override = headers.get("x-canary-target", "").lower()
        if target_override == "canary":
            return True
        if target_override == "stable":
            return False

        with self._lock:
            weight = self.weight

        if weight <= 0.0:
            return False
        if weight >= 1.0:
            return True

        # Sticky hashing if user_id or client_ip is available
        identifier = user_id or client_ip
        if identifier:
            hash_val = int(hashlib.md5(identifier.encode("utf-8")).hexdigest()[:8], 16)
            normalized = (hash_val % 10000) / 10000.0
            return normalized < weight

        # Otherwise fallback to uniform random
        return random.random() < weight

    def record_metric(
        self,
        is_canary: bool,
        latency_ms: float,
        status_code: int,
        path: Optional[str] = None,
        method: str = "GET"
    ) -> None:
        """
        Records telemetry for the request and validates SLO compliance.
        Supports route-specific tagging for differentiated budgets (OPS-01).
        If canary breaches error rate or latency limits, automated rollback fires.
        """
        is_error = status_code >= 500

        if is_canary:
            self.canary_metrics.record(latency_ms, is_error)
            if path:
                route_key = self._get_route_key(path, method)
                with self._lock:
                    if route_key not in self.canary_route_metrics:
                        self.canary_route_metrics[route_key] = TrafficMetrics(window_size=500)
                    metric = self.canary_route_metrics[route_key]
                metric.record(latency_ms, is_error)

            if self.auto_rollback_enabled:
                self._evaluate_canary_slo(path=path, method=method)
        else:
            self.stable_metrics.record(latency_ms, is_error)

    def _evaluate_canary_slo(self, path: Optional[str] = None, method: str = "GET") -> None:
        """Evaluates canary error rate and p95 latency against enterprise and route thresholds."""
        budget_p95, budget_err = self.get_route_budget(path, method) if path else (self.max_p95_latency_ms, self.max_error_rate)

        # 1. Route-specific evaluation if route metrics exist
        if path:
            route_key = self._get_route_key(path, method)
            with self._lock:
                route_metric = self.canary_route_metrics.get(route_key)
            if route_metric:
                r_stats = route_metric.get_stats()
                if r_stats["window_samples"] >= min(self.min_eval_samples, 15):
                    if r_stats["error_rate"] > budget_err:
                        self.rollback(
                            f"Canary route '{route_key}' error rate {r_stats['error_rate'] * 100:.1f}% exceeded budget {budget_err * 100:.1f}%"
                        )
                        return
                    if r_stats["p95_latency_ms"] > budget_p95:
                        self.rollback(
                            f"Canary route '{route_key}' p95 latency {r_stats['p95_latency_ms']:.1f}ms breached SLA limit {budget_p95:.1f}ms"
                        )
                        return

        # 2. Aggregate canary metrics evaluation
        stats = self.canary_metrics.get_stats()
        samples = stats["window_samples"]

        if samples < self.min_eval_samples:
            return

        err_rate = stats["error_rate"]
        p95_lat = stats["p95_latency_ms"]

        # When evaluating aggregate metrics, use the effective threshold
        effective_err_limit = max(self.max_error_rate, budget_err) if path else self.max_error_rate
        effective_p95_limit = max(self.max_p95_latency_ms, budget_p95) if path else self.max_p95_latency_ms

        if err_rate > effective_err_limit:
            self.rollback(
                f"Canary error rate {err_rate * 100:.1f}% exceeded limit {effective_err_limit * 100:.1f}%"
            )
        elif p95_lat > effective_p95_limit:
            self.rollback(
                f"Canary p95 latency {p95_lat:.1f}ms breached SLA limit {effective_p95_limit:.1f}ms"
            )

    def get_status(self) -> Dict[str, Any]:
        """Returns comprehensive canary status and telemetry breakdown."""
        with self._lock:
            return {
                "stage": self.stage.value,
                "weight": self.weight,
                "auto_rollback_enabled": self.auto_rollback_enabled,
                "slo_limits": {
                    "max_error_rate": self.max_error_rate,
                    "max_p95_latency_ms": self.max_p95_latency_ms,
                    "min_eval_samples": self.min_eval_samples,
                    "route_slos": self.route_slos,
                },
                "last_rollback": {
                    "reason": self.last_rollback_reason,
                    "timestamp": self.last_rollback_timestamp,
                } if self.last_rollback_reason else None,
                "canary_metrics": self.canary_metrics.get_stats(),
                "stable_metrics": self.stable_metrics.get_stats(),
            }


# Global Singleton Canary Router
canary_router = CanaryRouter()

