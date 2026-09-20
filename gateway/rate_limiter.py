import time
import threading
import logging
from collections import defaultdict
from typing import Tuple

logger = logging.getLogger("gateway.rate_limiter")

class InMemoryRateLimiter:
    """Thread-safe in-memory rate limiter for graceful degradation if Redis fails."""
    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        self._lock = threading.Lock()
        self._records = defaultdict(list)
        
    def check_and_increment(self, key: str) -> int:
        now = time.time()
        cutoff = now - self.window_seconds
        with self._lock:
            timestamps = self._records[key]
            # Purge outdated timestamps
            self._records[key] = [t for t in timestamps if t > cutoff]
            self._records[key].append(now)
            return len(self._records[key])

class RateLimiter:
    def __init__(self, redis_host: str = "127.0.0.1", redis_port: int = 6379, redis_timeout: float = 0.5):
        if redis_host == "localhost":
            redis_host = "127.0.0.1"
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.redis_timeout = redis_timeout
        self.fallback = InMemoryRateLimiter(window_seconds=60)
        self._redis_client = None
        self._redis_available = False
        self._last_check = 0.0
        
    def _get_redis(self):
        now = time.time()
        if self._redis_available and self._redis_client is not None:
            return self._redis_client
        if not self._redis_available and (now - self._last_check < 300):
            return None
        self._last_check = now
        try:
            import socket
            with socket.create_connection((self.redis_host, self.redis_port), timeout=0.05):
                pass
            import redis
            from redis.retry import Retry
            from redis.backoff import NoBackoff
            r = redis.Redis(
                host=self.redis_host,
                port=self.redis_port,
                socket_connect_timeout=0.05,
                socket_timeout=self.redis_timeout,
                retry_on_timeout=False,
                retry=Retry(NoBackoff(), 0),
                decode_responses=True
            )
            r.ping()
            self._redis_client = r
            self._redis_available = True
            logger.info("Connected to Redis rate limiter successfully.")
            return self._redis_client
        except Exception as e:
            self._redis_client = None
            self._redis_available = False
            logger.warning(f"Redis connection unavailable ({e}); utilizing local in-memory fallback rate limiter.")
            return None

    def check_rate(self, key: str) -> Tuple[int, int]:
        """
        Returns (current_count_in_window, rate_score_0_to_100)
        Thresholds:
          - <= 100 req/min: score 0
          - 101-500 req/min: score 30-50
          - 501-1000 req/min: score 70-80
          - > 1000 req/min: score 100 (Abuse threshold)
        """
        r = self._get_redis()
        rate_key = f"rate:{key}"
        count = 0
        if r:
            try:
                pipe = r.pipeline()
                pipe.incr(rate_key)
                pipe.expire(rate_key, 60)
                results = pipe.execute()
                count = int(results[0])
            except Exception as e:
                logger.warning(f"Redis rate check error ({e}), switching to fallback limiter")
                self._redis_available = False
                count = self.fallback.check_and_increment(rate_key)
        else:
            count = self.fallback.check_and_increment(rate_key)
            
        # Score calculation
        if count <= 100:
            rate_score = 0
        elif count <= 300:
            rate_score = 25
        elif count <= 600:
            rate_score = 50
        elif count <= 1000:
            rate_score = 75
        else:
            rate_score = 100
            
        return count, rate_score
