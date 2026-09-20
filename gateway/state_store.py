"""
Distributed State Store (ARCH-01).
Provides high-performance, shared state synchronization across horizontal gateway replicas
using Redis primitives, with seamless, thread-safe in-memory graceful fallback for standalone
deployments, testing environments, and during temporary Redis disconnects.
"""

import json
import logging
import threading
import time
from typing import Any, Dict, List, Optional, Set

from gateway.config import config

logger = logging.getLogger("gateway.state_store")


class InMemoryStateStore:
    """Thread-safe local in-memory fallback state store."""

    def __init__(self):
        self._lock = threading.RLock()
        self._nonces: Dict[str, float] = {}  # key -> expiry_epoch
        self._sets: Dict[str, Set[str]] = {}  # set_name -> set of members
        self._hashes: Dict[str, Dict[str, Any]] = {}  # hash_name -> {field: value}

    def set_nonce_nx(self, key: str, ttl_seconds: int) -> bool:
        now = time.time()
        with self._lock:
            # Purge expired
            if key in self._nonces and self._nonces[key] < now:
                del self._nonces[key]

            if key in self._nonces:
                return False  # Already exists -> replay

            self._nonces[key] = now + ttl_seconds
            return True

    def add_to_set(self, set_name: str, member: str) -> None:
        with self._lock:
            if set_name not in self._sets:
                self._sets[set_name] = set()
            self._sets[set_name].add(member)

    def remove_from_set(self, set_name: str, member: str) -> bool:
        with self._lock:
            if set_name in self._sets and member in self._sets[set_name]:
                self._sets[set_name].remove(member)
                return True
            return False

    def is_member(self, set_name: str, member: str) -> bool:
        with self._lock:
            return member in self._sets.get(set_name, set())

    def get_set_members(self, set_name: str) -> Set[str]:
        with self._lock:
            return set(self._sets.get(set_name, set()))

    def set_hash_entry(self, hash_name: str, key: str, value: Any) -> None:
        with self._lock:
            if hash_name not in self._hashes:
                self._hashes[hash_name] = {}
            self._hashes[hash_name][key] = value

    def get_hash_entry(self, hash_name: str, key: str) -> Optional[Any]:
        with self._lock:
            return self._hashes.get(hash_name, {}).get(key)

    def get_all_hash_entries(self, hash_name: str) -> Dict[str, Any]:
        with self._lock:
            return dict(self._hashes.get(hash_name, {}))

    def delete_hash_entry(self, hash_name: str, key: str) -> bool:
        with self._lock:
            if hash_name in self._hashes and key in self._hashes[hash_name]:
                del self._hashes[hash_name][key]
                return True
            return False

    def clear(self) -> None:
        with self._lock:
            self._nonces.clear()
            self._sets.clear()
            self._hashes.clear()


class DistributedStateStore:
    """
    Centralized distributed state store abstraction.
    Connects to Redis when available, otherwise gracefully falls back to thread-safe
    in-memory storage with zero service interruption.
    """

    def __init__(
        self,
        redis_host: Optional[str] = None,
        redis_port: Optional[int] = None,
        redis_timeout: Optional[float] = None,
        redis_client: Optional[Any] = None
    ):
        host = redis_host or config.redis_host
        self.redis_host = "127.0.0.1" if host == "localhost" else host
        self.redis_port = redis_port or config.redis_port
        self.redis_timeout = redis_timeout or config.redis_timeout
        self.fallback = InMemoryStateStore()
        self._redis_client = redis_client
        self._redis_available = redis_client is not None
        self._last_check = 0.0

    def _get_redis(self):
        if self._redis_client is not None and self._redis_available:
            return self._redis_client
        now = time.time()
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
            logger.info("Connected to Redis distributed state store.")
            return self._redis_client
        except Exception:
            self._redis_client = None
            self._redis_available = False
            return None

    def set_nonce_nx(self, key: str, ttl_seconds: int = 300) -> bool:
        """Atomically records a single-use nonce if not already present."""
        r = self._get_redis()
        if r:
            try:
                # Redis SET key value EX ttl NX returns True if set, None/False if already exists
                res = r.set(f"nonce:{key}", "1", ex=ttl_seconds, nx=True)
                return bool(res)
            except Exception as e:
                logger.warning(f"Redis set_nonce_nx failed ({e}), falling back to in-memory store")
        return self.fallback.set_nonce_nx(key, ttl_seconds)

    def add_to_set(self, set_name: str, member: str) -> None:
        """Adds a member to a distributed set (e.g. revoked_tokens)."""
        r = self._get_redis()
        if r:
            try:
                r.sadd(f"set:{set_name}", member)
            except Exception as e:
                logger.warning(f"Redis sadd failed ({e}), using in-memory store")
        self.fallback.add_to_set(set_name, member)

    def remove_from_set(self, set_name: str, member: str) -> bool:
        """Removes a member from a distributed set."""
        r = self._get_redis()
        if r:
            try:
                r.srem(f"set:{set_name}", member)
            except Exception as e:
                logger.warning(f"Redis srem failed ({e})")
        return self.fallback.remove_from_set(set_name, member)

    def is_member(self, set_name: str, member: str) -> bool:
        """Checks membership in a distributed set."""
        r = self._get_redis()
        if r:
            try:
                return bool(r.sismember(f"set:{set_name}", member))
            except Exception as e:
                logger.warning(f"Redis sismember failed ({e}), falling back to in-memory store")
        return self.fallback.is_member(set_name, member)

    def get_set_members(self, set_name: str) -> Set[str]:
        r = self._get_redis()
        if r:
            try:
                return set(r.smembers(f"set:{set_name}"))
            except Exception as e:
                logger.warning(f"Redis smembers failed ({e}), falling back to in-memory store")
        return self.fallback.get_set_members(set_name)

    def set_hash_entry(self, hash_name: str, key: str, value: Any, ttl_seconds: Optional[int] = None) -> None:
        """Stores structured data in a hash table."""
        serialized = json.dumps(value)
        r = self._get_redis()
        if r:
            try:
                r.hset(f"hash:{hash_name}", key, serialized)
                if ttl_seconds:
                    r.expire(f"hash:{hash_name}", ttl_seconds)
            except Exception as e:
                logger.warning(f"Redis hset failed ({e}), using in-memory store")
        self.fallback.set_hash_entry(hash_name, key, value)

    def get_hash_entry(self, hash_name: str, key: str) -> Optional[Any]:
        """Retrieves structured data from a hash table."""
        r = self._get_redis()
        if r:
            try:
                val = r.hget(f"hash:{hash_name}", key)
                if val:
                    return json.loads(val)
                return None
            except Exception as e:
                logger.warning(f"Redis hget failed ({e}), falling back to in-memory store")
        return self.fallback.get_hash_entry(hash_name, key)

    def get_all_hash_entries(self, hash_name: str) -> Dict[str, Any]:
        """Retrieves all entries from a hash table."""
        r = self._get_redis()
        if r:
            try:
                raw_entries = r.hgetall(f"hash:{hash_name}")
                return {k: json.loads(v) for k, v in raw_entries.items()}
            except Exception as e:
                logger.warning(f"Redis hgetall failed ({e}), falling back to in-memory store")
        return self.fallback.get_all_hash_entries(hash_name)

    def delete_hash_entry(self, hash_name: str, key: str) -> bool:
        """Deletes an entry from a hash table."""
        r = self._get_redis()
        if r:
            try:
                r.hdel(f"hash:{hash_name}", key)
            except Exception as e:
                logger.warning(f"Redis hdel failed ({e})")
        return self.fallback.delete_hash_entry(hash_name, key)

    def reset_state(self) -> None:
        """Resets both in-memory and Redis caches (for test isolation)."""
        self.fallback.clear()
        r = self._get_redis()
        if r:
            try:
                keys = r.keys("nonce:*") + r.keys("set:*") + r.keys("hash:*")
                if keys:
                    r.delete(*keys)
            except Exception:
                pass


state_store = DistributedStateStore()
