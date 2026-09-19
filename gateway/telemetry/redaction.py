import hashlib
import hmac
import ipaddress
import re
from typing import Any, Dict, List, Union

from gateway.config import config

SENSITIVE_KEYS = {
    "password", "passwd", "secret", "token", "access_token", "refresh_token",
    "authorization", "auth_token", "x_auth_token", "x-auth-token", "api_key",
    "card_number", "cvv", "ssn", "pin", "client_ip", "ip", "remote_addr",
    "x_forwarded_for", "x-forwarded-for"
}

EMAIL_REGEX = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
CREDIT_CARD_REGEX = re.compile(r"\b(?:\d[ -]*?){13,16}\b")
IPV4_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def mask_ip(ip_str: str) -> str:
    """Masks an IP address to preserve subnet privacy (e.g. /24 for IPv4, /64 for IPv6)."""
    if not ip_str:
        return "anon"
    clean = ip_str.strip()
    if clean.startswith("[") and "]" in clean:
        clean = clean.split("]")[0].lstrip("[")
    elif clean.count(":") == 1:
        clean = clean.split(":")[0].strip()
    try:
        ip = ipaddress.ip_address(clean)
        if isinstance(ip, ipaddress.IPv4Address):
            net = ipaddress.ip_network(f"{clean}/24", strict=False)
            return str(net)
        else:
            net = ipaddress.ip_network(f"{clean}/64", strict=False)
            return str(net)
    except ValueError:
        return "anon"


def pseudonymize_identifier(identifier: str) -> str:
    """Generates an irreversible, salted HMAC pseudonym for user/client tracking."""
    if not identifier:
        return "anon"
    salt = config.telemetry_salt
    return "p-" + hmac.new(salt, identifier.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def sanitize_telemetry(data: Union[Dict[str, Any], List[Any], str, Any]) -> Any:
    """
    Recursively scrubs PII, secrets, raw tokens, and IP addresses from telemetry payloads.
    """
    if isinstance(data, dict):
        cleaned = {}
        for k, v in data.items():
            k_lower = k.lower()
            if (
                k_lower in SENSITIVE_KEYS
                or any(s in k_lower for s in ["password", "secret", "token", "auth_header"])
            ):
                if k_lower in ("client_ip", "ip", "remote_addr") and isinstance(v, str):
                    cleaned[k] = pseudonymize_identifier(v)
                else:
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
