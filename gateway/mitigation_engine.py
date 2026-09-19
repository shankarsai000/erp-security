"""Active Mitigation Engine for Phase 8 Automated Response.

Provides real-time, zero-latency mitigation enforcement in the Gateway middleware:
- Safe, reversible, automated containment (Rate Limiting, MFA Challenges, Session Revocation, Temporary IP Quarantine < 1hr).
- Strict Human Approval Gates: High-impact actions (Account Suspension, CIDR blocks) are strictly blocked from autonomous execution.
- O(1) evaluation, TTL auto-expiry, and sub-second programmatic rollback.
"""

from dataclasses import dataclass, field
import datetime
import threading
from typing import Dict, Optional, Set, Tuple

from agents.base import ActionType, AgentAction, ApprovalStatus
from gateway.config import config
import logging

logger = logging.getLogger("erp_security.mitigation")


class UnauthorizedMitigationError(Exception):
    """Raised when an attempt is made to execute an unapproved or unauthorized high-impact mitigation."""
    pass


@dataclass
class MitigationDecision:
    """Result of evaluating incoming request against active mitigations."""
    is_mitigated: bool
    action: Optional[ActionType] = None
    http_status: int = 200
    reason: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    action_id: Optional[str] = None


class MitigationEngine:
    """Thread-safe active mitigation registry and enforcement engine."""

    MAX_AUTO_QUARANTINE_SECONDS: int = 3600  # Strict policy: Max 1 hour for automated IP quarantines

    def __init__(self):
        self._lock = threading.RLock()

        # Active mitigations
        # IP -> {"until": datetime.datetime, "reason": str, "action_id": str}
        self.quarantined_ips: Dict[str, dict] = {}

        # Revoked raw tokens or JTI IDs
        self.revoked_tokens: Set[str] = set()

        # Principal -> {"until": datetime.datetime, "reason": str, "action_id": str}
        self.revoked_principals: Dict[str, dict] = {}

        # Principals requiring step-up MFA verification
        self.mfa_enforced_principals: Dict[str, dict] = {}

        # Entity -> {"limit": int, "window_seconds": int, "until": datetime.datetime, "action_id": str}
        self.dynamic_rate_limits: Dict[str, dict] = {}

        # Strictly human-approved suspended accounts: principal -> {"action_id": str, "approved_by": str}
        self.suspended_accounts: Dict[str, dict] = {}

        # Registry mapping action_id -> (ActionType, target_entity) for instant rollback
        self._action_registry: Dict[str, Tuple[ActionType, str]] = {}

    def apply_action(self, action: AgentAction) -> bool:
        """Apply an agent action to active gateway mitigation state.

        Enforces strict safety rules:
        - High impact actions (SUSPEND_ACCOUNT, BLOCK_CIDR_ORGANIZATION) MUST have ApprovalStatus.APPROVED.
        - Automated IP quarantines cannot exceed MAX_AUTO_QUARANTINE_SECONDS.
        """
        with self._lock:
            # 1. Enforce Human Approval Gate for high-impact actions
            if action.action_type in (ActionType.SUSPEND_ACCOUNT, ActionType.BLOCK_CIDR_ORGANIZATION):
                if action.approval_status not in (ApprovalStatus.APPROVED, ApprovalStatus.EXECUTED):
                    raise UnauthorizedMitigationError(
                        f"High-impact action {action.action_type.value} on target '{action.target_entity}' "
                        f"requires explicit human approval. Current status: {action.approval_status.value}."
                    )

            now = datetime.datetime.now(datetime.timezone.utc)
            duration = action.duration_seconds or 900

            # 2. Prevent DoS on whitelisted corporate, internal, or loopback IPs (SEC-05)
            if action.action_type in (ActionType.QUARANTINE_IP_TEMP, ActionType.BLOCK_CIDR_ORGANIZATION):
                if config.is_ip_whitelisted(action.target_entity):
                    logger.warning(
                        "Attempted to quarantine whitelisted internal/corporate IP '%s'. Mitigation rejected.",
                        action.target_entity
                    )
                    return False

            # 3. Cap automated IP quarantines to safety threshold
            if action.action_type == ActionType.QUARANTINE_IP_TEMP:
                duration = min(duration, self.MAX_AUTO_QUARANTINE_SECONDS)

            until = now + datetime.timedelta(seconds=duration)

            # 3. Route and register mitigation
            if action.action_type == ActionType.QUARANTINE_IP_TEMP:
                self.quarantined_ips[action.target_entity] = {
                    "until": until,
                    "reason": action.justification,
                    "action_id": action.action_id
                }
                self._action_registry[action.action_id] = (action.action_type, action.target_entity)
                return True

            elif action.action_type == ActionType.REVOKE_SESSION:
                # Target can be a token string or a principal identifier
                if action.target_entity.startswith("Bearer ") or len(action.target_entity) > 32:
                    clean_token = action.target_entity.replace("Bearer ", "").strip()
                    self.revoked_tokens.add(clean_token)
                else:
                    self.revoked_principals[action.target_entity] = {
                        "until": until,
                        "reason": action.justification,
                        "action_id": action.action_id
                    }
                self._action_registry[action.action_id] = (action.action_type, action.target_entity)
                return True

            elif action.action_type == ActionType.CHALLENGE_MFA:
                self.mfa_enforced_principals[action.target_entity] = {
                    "until": until,
                    "reason": action.justification,
                    "action_id": action.action_id
                }
                self._action_registry[action.action_id] = (action.action_type, action.target_entity)
                return True

            elif action.action_type == ActionType.RATE_LIMIT:
                self.dynamic_rate_limits[action.target_entity] = {
                    "limit": 5,  # Restrictive dynamic throttle (5 req/min)
                    "window_seconds": 60,
                    "until": until,
                    "action_id": action.action_id
                }
                self._action_registry[action.action_id] = (action.action_type, action.target_entity)
                return True

            elif action.action_type == ActionType.SUSPEND_ACCOUNT:
                # Only reachable if APPROVED by human analyst
                self.suspended_accounts[action.target_entity] = {
                    "action_id": action.action_id,
                    "approved_by": action.approved_by or "HUMAN_ANALYST",
                    "timestamp": now.isoformat(),
                    "reason": action.justification
                }
                self._action_registry[action.action_id] = (action.action_type, action.target_entity)
                return True

            return False

    def rollback_action(self, action_id: str) -> bool:
        """Instantly revokes and purges an active mitigation by action_id."""
        with self._lock:
            if action_id not in self._action_registry:
                return False

            action_type, target = self._action_registry[action_id]

            if action_type == ActionType.QUARANTINE_IP_TEMP:
                self.quarantined_ips.pop(target, None)
            elif action_type == ActionType.REVOKE_SESSION:
                clean_token = target.replace("Bearer ", "").strip()
                self.revoked_tokens.discard(clean_token)
                self.revoked_principals.pop(target, None)
            elif action_type == ActionType.CHALLENGE_MFA:
                self.mfa_enforced_principals.pop(target, None)
            elif action_type == ActionType.RATE_LIMIT:
                self.dynamic_rate_limits.pop(target, None)
            elif action_type == ActionType.SUSPEND_ACCOUNT:
                self.suspended_accounts.pop(target, None)

            del self._action_registry[action_id]
            return True

    def evaluate_request(
        self,
        client_ip: str,
        principal_ref: Optional[str] = None,
        auth_token: Optional[str] = None,
        path: str = ""
    ) -> MitigationDecision:
        """Evaluates incoming request against active mitigations.

        Execution is O(1) in-memory lookup with latency budget < 0.5ms.
        Automatically sweeps expired TTL entries.
        """
        now = datetime.datetime.now(datetime.timezone.utc)

        with self._lock:
            # 1. Evaluate Suspended Accounts (Strict Human Approved)
            if principal_ref and principal_ref in self.suspended_accounts:
                info = self.suspended_accounts[principal_ref]
                return MitigationDecision(
                    is_mitigated=True,
                    action=ActionType.SUSPEND_ACCOUNT,
                    http_status=403,
                    reason=f"Account '{principal_ref}' is suspended by security policy. Contact administrator.",
                    action_id=info["action_id"]
                )

            # 2. Evaluate Temporary IP/Entity Quarantine with TTL auto-expiry
            quarantine_key = client_ip if client_ip in self.quarantined_ips else (principal_ref if principal_ref and principal_ref in self.quarantined_ips else None)
            if quarantine_key:
                info = self.quarantined_ips[quarantine_key]
                if now <= info["until"]:
                    remaining_seconds = max(1, int((info["until"] - now).total_seconds()))
                    return MitigationDecision(
                        is_mitigated=True,
                        action=ActionType.QUARANTINE_IP_TEMP,
                        http_status=403,
                        reason=f"Entity '{quarantine_key}' is quarantined due to automated threat containment. {info['reason']}",
                        headers={"Retry-After": str(remaining_seconds)},
                        action_id=info["action_id"]
                    )
                else:
                    # Clean TTL auto-expiry
                    del self.quarantined_ips[quarantine_key]

            # 3. Evaluate Revoked Tokens or Principal Sessions
            if auth_token:
                clean_token = auth_token.replace("Bearer ", "").strip()
                if clean_token in self.revoked_tokens:
                    return MitigationDecision(
                        is_mitigated=True,
                        action=ActionType.REVOKE_SESSION,
                        http_status=401,
                        reason="Session authentication token has been revoked by security response.",
                        headers={"WWW-Authenticate": "Bearer error=\"invalid_token\", error_description=\"token_revoked\""}
                    )

            if principal_ref and principal_ref in self.revoked_principals:
                info = self.revoked_principals[principal_ref]
                if now <= info["until"]:
                    return MitigationDecision(
                        is_mitigated=True,
                        action=ActionType.REVOKE_SESSION,
                        http_status=401,
                        reason=f"Active session for user '{principal_ref}' has been revoked. Re-authentication required.",
                        headers={"WWW-Authenticate": "Bearer error=\"session_revoked\""},
                        action_id=info["action_id"]
                    )
                else:
                    del self.revoked_principals[principal_ref]

            # 4. Evaluate Step-up MFA Challenge
            if principal_ref and principal_ref in self.mfa_enforced_principals:
                info = self.mfa_enforced_principals[principal_ref]
                if now <= info["until"]:
                    return MitigationDecision(
                        is_mitigated=True,
                        action=ActionType.CHALLENGE_MFA,
                        http_status=403,
                        reason="Multi-factor authentication challenge required due to anomalous activity.",
                        headers={"X-MFA-Required": "true", "X-MFA-Reason": info["reason"]},
                        action_id=info["action_id"]
                    )
                else:
                    del self.mfa_enforced_principals[principal_ref]

            # 5. Dynamic rate limit check is handled or flagged
            if (client_ip in self.dynamic_rate_limits) or (principal_ref and principal_ref in self.dynamic_rate_limits):
                target_key = client_ip if client_ip in self.dynamic_rate_limits else principal_ref
                info = self.dynamic_rate_limits[target_key]
                if now <= info["until"]:
                    return MitigationDecision(
                        is_mitigated=True,
                        action=ActionType.RATE_LIMIT,
                        http_status=429,
                        reason="Dynamic security throttling enforced due to rapid anomalous behavior.",
                        headers={"Retry-After": "60", "X-RateLimit-Limit": str(info["limit"])},
                        action_id=info["action_id"]
                    )
                else:
                    del self.dynamic_rate_limits[target_key]

        # No active mitigation
        return MitigationDecision(is_mitigated=False)

    def get_status(self) -> dict:
        """Returns summary of all active mitigations."""
        with self._lock:
            return {
                "active_quarantined_ips": len(self.quarantined_ips),
                "active_revoked_tokens": len(self.revoked_tokens),
                "active_revoked_principals": len(self.revoked_principals),
                "active_mfa_challenges": len(self.mfa_enforced_principals),
                "active_dynamic_rate_limits": len(self.dynamic_rate_limits),
                "active_suspended_accounts": len(self.suspended_accounts),
                "total_mitigations_enforced": len(self._action_registry)
            }
