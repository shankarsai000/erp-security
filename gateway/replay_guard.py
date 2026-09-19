"""
Replay and Freshness Guard (SEC-03).
Validates cryptographic nonces, idempotency keys, and timestamp freshness
for state-mutating operations (orders, payments, profile updates).
"""

import hashlib
import threading
import time
from typing import List, Optional, Tuple


from gateway.state_store import DistributedStateStore, state_store as global_state_store


class ReplayGuard:
    """
    Prevents replaying of sensitive state-changing operations.
    Enforces freshness window and single-use idempotency/nonce guarantees across
    horizontal replicas using Redis atomic primitives with thread-safe in-memory fallback.
    """

    def __init__(self, max_skew_seconds: int = 300, state_store: Optional[DistributedStateStore] = None):
        self.max_skew_seconds = max_skew_seconds
        self.state_store = state_store or global_state_store

    @property
    def _seen_nonces(self):
        """Backward compatibility accessor for legacy test inspections."""
        return self.state_store.fallback._nonces

    def validate_request(
        self,
        nonce: Optional[str] = None,
        idempotency_key: Optional[str] = None,
        timestamp_str: Optional[str] = None,
        body_bytes: bytes = b""
    ) -> Tuple[bool, int, List[str]]:
        """
        Validates timestamp freshness and single-use nonce/idempotency key uniqueness.
        Returns: (is_replay, threat_score_0_to_100, reasons)
        """
        now = time.time()

        # 1. Timestamp Freshness Check
        if timestamp_str:
            try:
                ts = float(timestamp_str)
                skew = abs(now - ts)
                if skew > self.max_skew_seconds:
                    return True, 85, [
                        f"Request timestamp expired (skew: {skew:.1f}s exceeds {self.max_skew_seconds}s limit)"
                    ]
            except ValueError:
                return True, 80, ["Malformed timestamp header in request"]

        # 2. Nonce / Idempotency Key Uniqueness Check via Distributed Store
        unique_key = nonce or idempotency_key
        if unique_key:
            is_unique = self.state_store.set_nonce_nx(unique_key, ttl_seconds=self.max_skew_seconds)
            if not is_unique:
                return True, 95, [
                    f"Transaction replay detected: nonce/idempotency key '{unique_key}' already executed"
                ]

        return False, 0, []


replay_guard = ReplayGuard(max_skew_seconds=300)
