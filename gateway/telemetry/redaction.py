import hashlib
import hmac
import re
from typing import Any, Dict, List, Union

SALT = b"telemetry_pseudonym_salt_2026"

SENSITIVE_KEYS = {
    "password", "passwd", "secret", "token", "access_token", "refresh_token",
    "authorization", "auth_token", "x_auth_token", "x-auth-token", "api_key", "card_number", "cvv", "ssn", "pin"
}

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
CREDIT_CARD_REGEX = re.compile(r"\b(?:\d[ -]*?){13,16}\b")

def pseudonymize_identifier(identifier: str) -> str:
    """Generates an irreversible, salted HMAC pseudonym for user/client tracking."""
    if not identifier:
        return "anon"
    return "p-" + hmac.new(SALT, identifier.encode("utf-8"), hashlib.sha256).hexdigest()[:16]

def sanitize_telemetry(data: Union[Dict[str, Any], List[Any], str, Any]) -> Any:
    """
    Recursively scrubs PII, secrets, and raw tokens from telemetry payloads.
    """
    if isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            k_lower = k.lower()
            if k_lower in SENSITIVE_KEYS or any(s in k_lower for s in ["password", "secret", "token"]) or k_lower == "authorization" or k_lower.startswith("auth_header"):
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = sanitize_telemetry(v)
        return cleaned
    elif isinstance(data, list):
        return [sanitize_telemetry(item) for item in data]
    elif isinstance(data, str):
        # Scrub email and card patterns if present
        s = EMAIL_REGEX.sub("[REDACTED_EMAIL]", data)
        s = CREDIT_CARD_REGEX.sub("[REDACTED_CARD]", s)
        return s
    return data

