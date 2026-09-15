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

def inspect_content(content: str) -> Tuple[bool, List[str], int]:
    """
    Inspects string content (paths, query strings, headers, body) for attack vectors.
    Returns: (is_attack, list_of_reasons, threat_score 0-100)
    """
    if not content:
        return False, [], 0
    
    # Check both raw content and URL-decoded content
    decoded = urllib.parse.unquote(content)
    lower_raw = content.lower()
    lower_decoded = decoded.lower()
    
    reasons = []
    threat_score = 0
    
    # 1. SQL Injection Check
    for sub in SQLI_SUBSTRINGS:
        if sub in lower_raw or sub in lower_decoded:
            reasons.append(f"SQL injection literal detected: '{sub}'")
            threat_score = max(threat_score, 95)
            break
            
    if threat_score < 90:
        for pat in SQLI_PATTERNS:
            if pat.search(content) or pat.search(decoded):
                reasons.append(f"SQL injection regex pattern match: {pat.pattern}")
                threat_score = max(threat_score, 90)
                break

    # 2. XSS Check
    for sub in XSS_SUBSTRINGS:
        if sub in lower_raw or sub in lower_decoded:
            reasons.append(f"XSS literal detected: '{sub}'")
            threat_score = max(threat_score, 90)
            break
            
    if threat_score < 85:
        for pat in XSS_PATTERNS:
            if pat.search(content) or pat.search(decoded):
                reasons.append(f"XSS regex pattern match: {pat.pattern}")
                threat_score = max(threat_score, 85)
                break

    # 3. Path Traversal Check
    for pat in PATH_TRAVERSAL_PATTERNS:
        if pat.search(content) or pat.search(decoded):
            reasons.append("Path traversal attempt detected")
            threat_score = max(threat_score, 95)
            break
            
    is_attack = len(reasons) > 0
    return is_attack, reasons, min(100, threat_score)
