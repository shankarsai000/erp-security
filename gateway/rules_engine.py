"""
Deterministic Rules Engine
Detects ERP-specific business logic violations.
NOT ML. NOT learned. Explicitly coded and config-driven rules.
"""

import os
import time
import json
import yaml
import hashlib
import logging
import threading
from dataclasses import dataclass
from typing import List, Dict, Any, Callable, Tuple, Optional
from enum import Enum

logger = logging.getLogger("gateway.rules_engine")

class RuleCategory(str, Enum):
    BUSINESS_LOGIC = "business_logic"
    SEQUENCE_VIOLATION = "sequence_violation"
    RESOURCE_DEPLETION = "resource_depletion"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    API_ABUSE = "api_abuse"

@dataclass
class Rule:
    """Single deterministic rule definition."""
    rule_id: str
    category: RuleCategory
    description: str
    severity: int  # 0-100
    check_fn: Callable[[Dict[str, Any]], Tuple[bool, str]]
    remediation: str  # e.g., "block", "challenge", "limit"

# Static warehouse baseline catalog for deterministic inventory depletion checks
KNOWN_INVENTORY = {
    "SKU-9901": 420,
    "SKU-9902": 1850,
    "SKU-9903": 34,
    "Industrial Widget A": 420,
    "Bearing Assembly": 1850,
    "Hydraulic Pump v2": 34,
}

class RulesEngine:
    """
    Deterministic rules engine with hot-reloadable YAML configuration,
    in-memory state tracking for replay/duplicate and scraping prevention,
    and sub-millisecond evaluation overhead.
    """
    def __init__(self, config_path: str = "config/rules.yaml"):
        self.config_path = config_path
        self.rules: List[Rule] = []
        self.fired_rules: List[str] = []
        self.fired_reasons: List[str] = []
        self._last_mtime: float = 0.0
        
        # State tracking caches
        self._lock = threading.Lock()
        self._order_hash_history: Dict[str, List[float]] = {}
        self._mass_access_history: Dict[str, List[float]] = {}
        
        # Inventory reference (can be synced or updated)
        self.inventory: Dict[str, int] = dict(KNOWN_INVENTORY)
        
        # Load rules from YAML if present, else fallback to defaults
        self._load_rules()

    def _load_rules(self):
        """Loads rules from YAML config or initializes defaults."""
        if os.path.exists(self.config_path):
            try:
                self._last_mtime = os.path.getmtime(self.config_path)
                with open(self.config_path, "r", encoding="utf-8") as f:
                    config_data = yaml.safe_load(f) or {}
                
                self.rules = []
                for rc in config_data.get("rules", []):
                    rule = self._build_rule_from_config(rc)
                    if rule:
                        self.rules.append(rule)
                logger.info("Loaded %d deterministic rules from %s", len(self.rules), self.config_path)
                return
            except Exception as e:
                logger.error("Failed to parse %s: %s; falling back to programmatic defaults", self.config_path, e)

        # Built-in programmatic defaults
        self.rules = [
            Rule(
                rule_id="R001",
                category=RuleCategory.BUSINESS_LOGIC,
                description="Order item has negative price",
                severity=100,
                check_fn=self._check_negative_price,
                remediation="block"
            ),
            Rule(
                rule_id="R002",
                category=RuleCategory.API_ABUSE,
                description="Same order placed twice in <5 seconds",
                severity=60,
                check_fn=self._check_duplicate_order,
                remediation="challenge"
            ),
            Rule(
                rule_id="R003",
                category=RuleCategory.RESOURCE_DEPLETION,
                description="Order quantity would deplete inventory below 0",
                severity=80,
                check_fn=self._check_inventory_depletion,
                remediation="block"
            ),
            Rule(
                rule_id="R004",
                category=RuleCategory.PRIVILEGE_ESCALATION,
                description="User attempting to grant themselves admin role",
                severity=100,
                check_fn=self._check_role_escalation,
                remediation="block"
            ),
            Rule(
                rule_id="R005",
                category=RuleCategory.SEQUENCE_VIOLATION,
                description="POST /api/orders without prior authentication",
                severity=75,
                check_fn=self._check_auth_sequence,
                remediation="challenge"
            ),
            Rule(
                rule_id="R006",
                category=RuleCategory.API_ABUSE,
                description="User accessing excessive orders in 1 minute (mass scraping)",
                severity=65,
                check_fn=self._check_mass_access,
                remediation="limit"
            ),
        ]
        logger.info("Initialized %d default deterministic rules", len(self.rules))

    def _build_rule_from_config(self, rule_cfg: dict) -> Optional[Rule]:
        """Maps declarative YAML configuration entry to a Rule object."""
        rule_id = rule_cfg.get("rule_id")
        check_type = rule_cfg.get("check_type")
        category_str = rule_cfg.get("category", "business_logic")
        category = getattr(RuleCategory, category_str.upper(), RuleCategory.BUSINESS_LOGIC)
        description = rule_cfg.get("description", "")
        severity = int(rule_cfg.get("severity", 50))
        remediation = rule_cfg.get("remediation", "block")

        dispatch = {
            "negative_price": self._check_negative_price,
            "duplicate_order": self._check_duplicate_order,
            "inventory_depletion": self._check_inventory_depletion,
            "role_escalation": self._check_role_escalation,
            "sequence_violation": self._check_auth_sequence,
            "mass_access": self._check_mass_access,
        }

        check_fn = dispatch.get(check_type)
        if not check_fn:
            logger.warning("Unrecognized rule check_type: %s for %s", check_type, rule_id)
            return None

        return Rule(
            rule_id=rule_id,
            category=category,
            description=description,
            severity=severity,
            check_fn=check_fn,
            remediation=remediation
        )

    def reload_rules(self):
        """Hot-reloads rules from configuration file."""
        self._load_rules()

    def check_hot_reload(self):
        """Checks if rules file modification timestamp changed and reloads if necessary."""
        if os.path.exists(self.config_path):
            try:
                mtime = os.path.getmtime(self.config_path)
                if mtime > self._last_mtime:
                    logger.info("Detected update to %s; triggering hot reload", self.config_path)
                    self.reload_rules()
            except Exception as e:
                logger.error("Error checking hot-reload: %e", e)

    def evaluate(self, request_data: dict) -> Tuple[int, List[str]]:
        """
        Evaluates all deterministic rules against incoming request payload.
        Returns: (max_severity, list_of_fired_rule_ids)
        Also updates self.fired_rules and self.fired_reasons.
        """
        self.check_hot_reload()
        self.fired_rules = []
        self.fired_reasons = []
        max_severity = 0

        for rule in self.rules:
            try:
                fired, reason = rule.check_fn(request_data)
                if fired:
                    self.fired_rules.append(rule.rule_id)
                    self.fired_reasons.append(reason or rule.description)
                    max_severity = max(max_severity, rule.severity)
                    logger.warning("Deterministic Rule Fired: [%s] %s (Severity: %d)", rule.rule_id, rule.description, rule.severity)
            except Exception as e:
                logger.error("Error evaluating rule %s: %s", rule.rule_id, e)

        return max_severity, self.fired_rules

    # =========================================================================
    # DETERMINISTIC RULE IMPLEMENTATIONS
    # =========================================================================

    def _check_negative_price(self, request_data: dict) -> Tuple[bool, str]:
        """R001: Check if order or item has negative price or total amount < 0."""
        path = request_data.get("path", "")
        method = request_data.get("method", "").upper()
        if method != "POST" or not path.startswith("/api/orders"):
            return False, ""

        body = request_data.get("body", {})
        if not isinstance(body, dict):
            return False, ""

        # Direct total_amount negative check
        if body.get("total_amount", 0) < 0:
            return True, "Negative order total_amount detected"

        # Item-level price check
        items = body.get("items", [])
        if isinstance(items, list):
            for itm in items:
                if isinstance(itm, dict):
                    if itm.get("price", 0) < 0 or itm.get("unit_price", 0) < 0 or itm.get("quantity", 0) < 0:
                        return True, f"Negative price or quantity detected on item: {itm}"
        return False, ""

    def _check_duplicate_order(self, request_data: dict) -> Tuple[bool, str]:
        """R002: Check if identical order is placed twice within < 5 seconds."""
        path = request_data.get("path", "")
        method = request_data.get("method", "").upper()
        if method != "POST" or not path.startswith("/api/orders"):
            return False, ""

        body = request_data.get("body", {})
        if not body:
            return False, ""

        client_ref = request_data.get("user_id") or request_data.get("client_ip") or "anon"
        # Stable normalized hash of the order payload + client
        try:
            order_repr = json.dumps(body, sort_keys=True)
        except Exception:
            order_repr = str(body)

        order_hash = hashlib.sha256(f"{client_ref}:{order_repr}".encode("utf-8")).hexdigest()
        now = time.time()
        ttl = 5.0

        with self._lock:
            history = self._order_hash_history.get(order_hash, [])
            # Purge entries older than TTL
            history = [t for t in history if (now - t) < ttl]
            history.append(now)
            self._order_hash_history[order_hash] = history

            if len(history) >= 2:
                time_diff = history[-1] - history[-2]
                return True, f"Duplicate order placed within {time_diff:.2f}s (< 5.0s window)"

        return False, ""

    def _check_inventory_depletion(self, request_data: dict) -> Tuple[bool, str]:
        """R003: Check if order item quantity would deplete warehouse stock below 0."""
        path = request_data.get("path", "")
        method = request_data.get("method", "").upper()
        if method != "POST" or not path.startswith("/api/orders"):
            return False, ""

        body = request_data.get("body", {})
        if not isinstance(body, dict):
            return False, ""

        items = body.get("items", [])
        if isinstance(items, list):
            for itm in items:
                sku_or_name = None
                qty = 1
                if isinstance(itm, dict):
                    sku_or_name = itm.get("sku") or itm.get("name") or itm.get("item_id")
                    qty = itm.get("quantity", 1)
                elif isinstance(itm, str):
                    # Item could be SKU string e.g. "SKU-9901:500" or item name
                    if ":" in itm:
                        parts = itm.split(":")
                        sku_or_name = parts[0].strip()
                        try:
                            qty = int(parts[1])
                        except ValueError:
                            qty = 1
                    else:
                        sku_or_name = itm.strip()

                if sku_or_name and sku_or_name in self.inventory:
                    available = self.inventory[sku_or_name]
                    if qty > available:
                        return True, f"Order quantity {qty} exceeds available warehouse stock ({available}) for '{sku_or_name}'"

        return False, ""

    def _check_role_escalation(self, request_data: dict) -> Tuple[bool, str]:
        """R004: Check if non-admin user is attempting to grant themselves the admin role."""
        path = request_data.get("path", "")
        method = request_data.get("method", "").upper()
        if not path.startswith("/api/users") or method not in ["POST", "PUT"]:
            return False, ""

        body = request_data.get("body", {})
        if not isinstance(body, dict):
            return False, ""

        requested_role = body.get("role")
        current_role = request_data.get("current_role") or "user"

        if requested_role == "admin" and current_role != "admin":
            return True, f"Unauthorized privilege escalation: role '{current_role}' attempted to assign role 'admin'"

        return False, ""

    def _check_auth_sequence(self, request_data: dict) -> Tuple[bool, str]:
        """R005: Check if sensitive resource is called without authenticated principal."""
        path = request_data.get("path", "")
        method = request_data.get("method", "").upper()
        if method == "POST" and path.startswith("/api/orders"):
            is_authenticated = request_data.get("is_authenticated", False)
            user_id = request_data.get("user_id")
            if not is_authenticated or not user_id:
                return True, "Sequence violation: POST /api/orders executed without prior authentication"

        return False, ""

    def _check_mass_access(self, request_data: dict) -> Tuple[bool, str]:
        """R006: Check if user or IP accesses > 100 sensitive records in 1 minute."""
        path = request_data.get("path", "")
        if not (path.startswith("/api/orders") or path.startswith("/api/users")):
            return False, ""

        client_ref = request_data.get("user_id") or request_data.get("client_ip") or "anon"
        now = time.time()
        window = 60.0

        with self._lock:
            history = self._mass_access_history.get(client_ref, [])
            history = [t for t in history if (now - t) < window]
            history.append(now)
            self._mass_access_history[client_ref] = history

            if len(history) > 100:
                return True, f"Mass record access threshold exceeded: {len(history)} requests in 1m (threshold: 100)"

        return False, ""

    def reset_state(self):
        """Clears in-memory state tracking caches (used for test isolation)."""
        with self._lock:
            self._order_hash_history.clear()
            self._mass_access_history.clear()

rules_engine = RulesEngine()
