import time
import threading
import hashlib
from typing import Tuple, List, Optional

class ReplayGuard:
    """
    Prevents replaying of sensitive state-changing operations (orders, payments).
    """
    def __init__(self, max_skew_seconds: int = 300):
        self.max_skew_seconds = max_skew_seconds
        self._lock = threading.Lock()
        self._seen_nonces = {}  # nonce -> expiry timestamp

    def validate_request(
        self,
        nonce: Optional[str],
        timestamp_str: Optional[str],
        body_bytes: bytes = b""
    ) -> Tuple[bool, int, List[str]]:
        """
        Validates timestamp freshness and nonce uniqueness.
        Returns: (is_replay, threat_score_0_to_100, reasons)
        """
        now = time.time()
        
        # Cleanup expired nonces
        with self._lock:
            expired_keys = [k for k, exp in self._seen_nonces.items() if exp < now]
            for k in expired_keys:
                del self._seen_nonces[k]

        reasons = []
        
        # 1. Timestamp Freshness Check
        if timestamp_str:
            try:
                ts = float(timestamp_str)
                skew = abs(now - ts)
                if skew > self.max_skew_seconds:
                    return True, 85, [f"Request timestamp expired (skew: {skew:.1f}s exceeds {self.max_skew_seconds}s limit)"]
            except ValueError:
                return True, 80, ["Malformed timestamp header in request"]

        # 2. Nonce Uniqueness Check
        if nonce:
            with self._lock:
                if nonce in self._seen_nonces:
                    return True, 95, [f"Transaction replay detected: nonce '{nonce}' already executed"]
                self._seen_nonces[nonce] = now + self.max_skew_seconds

        return False, 0, []

replay_guard = ReplayGuard(max_skew_seconds=300)
