"""
Replay and Freshness Guard (SEC-03).
Validates cryptographic nonces, idempotency keys, and timestamp freshness
for state-mutating operations (orders, payments, profile updates).
"""

import hashlib
import threading
import time
from typing import List, Optional, Tuple


class ReplayGuard:
    """
    Prevents replaying of sensitive state-changing operations.
    Enforces freshness window and single-use idempotency/nonce guarantees.
    """

    def __init__(self, max_skew_seconds: int = 300):
        self.max_skew_seconds = max_skew_seconds
        self._lock = threading.Lock()
        self._seen_nonces = {}  # key -> expiry timestamp

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

        # 1. Cleanup expired nonces
        with self._lock:
            expired_keys = [k for k, exp in self._seen_nonces.items() if exp < now]
            for k in expired_keys:
                del self._seen_nonces[k]

        reasons = []

        # 2. Timestamp Freshness Check
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

        # 3. Nonce / Idempotency Key Uniqueness Check
        unique_key = nonce or idempotency_key
        if unique_key:
            with self._lock:
                if unique_key in self._seen_nonces:
                    return True, 95, [
                        f"Transaction replay detected: nonce/idempotency key '{unique_key}' already executed"
                    ]
                self._seen_nonces[unique_key] = now + self.max_skew_seconds

        return False, 0, []


replay_guard = ReplayGuard(max_skew_seconds=300)
