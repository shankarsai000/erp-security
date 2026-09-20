import re
import urllib.parse
from typing import Tuple, List

# Compiled regexes for high-performance deterministic inspection (< 1ms overhead)
SQLI_PATTERNS = [
    re.compile(r"(\%27)|(\')|(\-\-)|(\%23)|(#)", re.IGNORECASE),
    re.compile(r"\b(OR|AND)\b\s+[\'\"]?\d+[\'\"]?\s*=\s*[\'\"]?\d+", re.IGNORECASE),
    re.compile(r"\bUNION\b\s+(\bALL\b\s+)?\bSELECT\b", re.IGNORECASE),
    re.compile(r"\b(DROP|ALTER|TRUNCATE)\b\s+\bTABLE\b", re.IGNORECASE),
    re.compile(r"\bDELETE\b\s+\bFROM\b", re.IGNORECASE),
    re.compile(r"\bINSERT\b\s+\bINTO\b", re.IGNORECASE),
    re.compile(r"\bEXEC(\s|\+)+(s|x)p\w+", re.IGNORECASE),
    re.compile(r"\b(BENCHMARK|SLEEP|WAITFOR\s+DELAY)\b", re.IGNORECASE),
]

# Literal substring heuristics for immediate detection
SQLI_SUBSTRINGS = [
    "' or '1'='1",
    "' or 1=1",
    "\" or \"1\"=\"1",
    "\" or 1=1",
    "union select",
    "drop table",
    "delete from",
    "insert into",
    "--",
    "/*",
]

XSS_PATTERNS = [
    re.compile(r"<\s*script[^>]*>", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"on(error|load|click|mouseover|focus|blur)\s*=", re.IGNORECASE),
    re.compile(r"<\s*iframe[^>]*>", re.IGNORECASE),
    re.compile(r"<\s*img[^>]+src=[^>]*onerror=", re.IGNORECASE),
    re.compile(r"eval\s*\(.*\)", re.IGNORECASE),
]

XSS_SUBSTRINGS = [
    "<script",
    "</script>",
    "javascript:",
    "onerror=",
    "onload=",
    "<iframe",
]

PATH_TRAVERSAL_PATTERNS = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"%2e%2e", re.IGNORECASE),
    re.compile(r"(/etc/passwd|/etc/shadow|/proc/self|/windows/system32|cmd\.exe)", re.IGNORECASE),
]

import json
from typing import Tuple, List, Any, Optional

def _unescape_unicode_and_hex(s: str) -> str:
    """Safely decodes \\uXXXX and \\xXX escape sequences to raw characters."""
    def _replace_u(match):
        try:
            return chr(int(match.group(1), 16))
        except Exception:
            return match.group(0)

    def _replace_x(match):
        try:
            return chr(int(match.group(1), 16))
        except Exception:
            return match.group(0)

    res = re.sub(r"\\u([0-9a-fA-F]{4})", _replace_u, s)
    res = re.sub(r"\\x([0-9a-fA-F]{2})", _replace_x, res)
    return res


def inspect_content(content: str, _recurse_json: bool = True) -> Tuple[bool, List[str], int]:
    """
    Inspects string content (paths, query strings, headers, body) for attack vectors.
    Evaluates raw, URL-decoded, and Unicode/hex-unescaped variants to prevent evasion.
    Returns: (is_attack, list_of_reasons, threat_score 0-100)
    """
    if not content:
        return False, [], 0

    # Build comprehensive normalized variants
    variants = [content]
    decoded = urllib.parse.unquote(content)
    if decoded != content:
        variants.append(decoded)
        double_decoded = urllib.parse.unquote(decoded)
        if double_decoded != decoded:
            variants.append(double_decoded)

    # Unicode & hex escape unescaping (SEC-07 evasion protection)
    for text in list(variants):
        unescaped = _unescape_unicode_and_hex(text)
        if unescaped not in variants:
            variants.append(unescaped)
            unescaped_decoded = urllib.parse.unquote(unescaped)
            if unescaped_decoded not in variants:
                variants.append(unescaped_decoded)

    reasons: List[str] = []
    threat_score = 0

    # 1. SQL Injection Check across all variants
    for variant in variants:
        lower_v = variant.lower()
        for sub in SQLI_SUBSTRINGS:
            if sub in lower_v:
                reasons.append(f"SQL injection literal detected: '{sub}'")
                threat_score = max(threat_score, 95)
                break
        if threat_score >= 95:
            break

    if threat_score < 90:
        for variant in variants:
            for pat in SQLI_PATTERNS:
                if pat.search(variant):
                    reasons.append(f"SQL injection regex pattern match: {pat.pattern}")
                    threat_score = max(threat_score, 90)
                    break
            if threat_score >= 90:
                break

    # 2. XSS Check across all variants
    for variant in variants:
        lower_v = variant.lower()
        for sub in XSS_SUBSTRINGS:
            if sub in lower_v:
                reasons.append(f"XSS literal detected: '{sub}'")
                threat_score = max(threat_score, 90)
                break
        if threat_score >= 90:
            break

    if threat_score < 85:
        for variant in variants:
            for pat in XSS_PATTERNS:
                if pat.search(variant):
                    reasons.append(f"XSS regex pattern match: {pat.pattern}")
                    threat_score = max(threat_score, 85)
                    break
            if threat_score >= 85:
                break

    # 3. Path Traversal Check across all variants
    for variant in variants:
        for pat in PATH_TRAVERSAL_PATTERNS:
            if pat.search(variant):
                reasons.append("Path traversal attempt detected")
                threat_score = max(threat_score, 95)
                break
        if threat_score >= 95:
            break

    # 4. JSON Content Inspection (if body is a serialized JSON object/array)
    if _recurse_json:
        stripped = content.strip()
        if stripped.startswith(("{", "[")):
            try:
                parsed_json = json.loads(stripped)
                is_json_attack, json_reasons, json_score = inspect_payload(parsed_json)
                if is_json_attack:
                    reasons.extend(json_reasons)
                    threat_score = max(threat_score, json_score)
            except Exception:
                pass

    dedup_reasons = list(dict.fromkeys(reasons))
    is_attack = len(dedup_reasons) > 0
    return is_attack, dedup_reasons, min(100, threat_score)


def inspect_payload(payload: Any) -> Tuple[bool, List[str], int]:
    """
    Recursively inspects dictionary, list, or primitive JSON payloads for injection attacks.
    Inspects all dictionary keys and string values with Unicode & URL unescaping.
    """
    if payload is None:
        return False, [], 0

    reasons: List[str] = []
    max_threat = 0

    def _traverse(item: Any) -> None:
        nonlocal max_threat
        if isinstance(item, dict):
            for k, v in item.items():
                if isinstance(k, str):
                    is_att, r, sc = inspect_content(k, _recurse_json=False)
                    if is_att:
                        reasons.extend(r)
                        max_threat = max(max_threat, sc)
                _traverse(v)
        elif isinstance(item, (list, tuple, set)):
            for elem in item:
                _traverse(elem)
        elif isinstance(item, str):
            is_att, r, sc = inspect_content(item, _recurse_json=False)
            if is_att:
                reasons.extend(r)
                max_threat = max(max_threat, sc)

    _traverse(payload)
    dedup_reasons = list(dict.fromkeys(reasons))
    return len(dedup_reasons) > 0, dedup_reasons, min(100, max_threat)

