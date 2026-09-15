import time
import threading
from collections import defaultdict
from typing import Tuple, List

class CredentialDefense:
    """
    Day-1 Credential stuffing and brute-force detection (Critical Improvement #3).
    Tracks authentication failures across IP and username dimensions.
    """
    def __init__(self, failure_threshold: int = 5, window_seconds: int = 300):
        self.failure_threshold = failure_threshold
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._ip_failures = defaultdict(list)
        self._user_failures = defaultdict(list)

    def record_failure(self, client_ip: str, username: str = ""):
        now = time.time()
        with self._lock:
            self._ip_failures[client_ip].append(now)
            if username:
                self._user_failures[username].append(now)

    def check_status(self, client_ip: str, username: str = "") -> Tuple[bool, int, List[str]]:
        """
        Returns: (is_blocked_or_flagged, threat_score_0_to_100, reasons)
        """
        now = time.time()
        cutoff = now - self.window_seconds
        reasons = []
        threat = 0
        
        with self._lock:
            # Purge outdated timestamps
            ip_times = [t for t in self._ip_failures[client_ip] if t > cutoff]
            self._ip_failures[client_ip] = ip_times
            
            user_times = []
            if username:
                user_times = [t for t in self._user_failures[username] if t > cutoff]
                self._user_failures[username] = user_times
                
        ip_count = len(ip_times)
        user_count = len(user_times)
        
        if ip_count >= self.failure_threshold:
            threat = max(threat, 95)
            reasons.append(f"Brute force alert: {ip_count} failed logins in 5m from IP {client_ip}")
            
        if user_count >= self.failure_threshold:
            threat = max(threat, 95)
            reasons.append(f"Account targeted: {user_count} failed logins in 5m for user '{username}'")
            
        is_flagged = threat >= 90
        return is_flagged, threat, reasons

    def reset(self, client_ip: str = "", username: str = ""):
        """Clears tracked failures for IP or username, or resets all if empty."""
        with self._lock:
            if client_ip:
                self._ip_failures.pop(client_ip, None)
            if username:
                self._user_failures.pop(username, None)
            if not client_ip and not username:
                self._ip_failures.clear()
                self._user_failures.clear()

credential_defense = CredentialDefense(failure_threshold=5, window_seconds=300)
