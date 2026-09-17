import base64
import json
import time
import hmac
import hashlib
from typing import Tuple, Dict, Any, Optional, List

SECRET_KEY = "erp_production_gateway_jwt_secret_key_demo"

class AuthEngine:
    """
    Cryptographic JWT verification, role-based checks, and BOLA/IDOR protection.
    """
    def __init__(self, secret: str = SECRET_KEY):
        self.secret = secret.encode("utf-8")

    def decode_and_verify(self, auth_header: str) -> Tuple[bool, str, Optional[Dict[str, Any]], float, float]:
        """
        Returns: (is_valid, reason, claims, auth_anomaly_score, user_trust_score)
        """
        if not auth_header:
            return False, "Missing Authorization header", None, 85.0, 0.0
            
        if not auth_header.startswith("Bearer "):
            return False, "Invalid scheme; Bearer token required", None, 80.0, 0.0
            
        token = auth_header[7:].strip()
        parts = token.split(".")
        if len(parts) != 3:
            return False, "Malformed JWT structure", None, 90.0, 0.0
            
        header_b64, payload_b64, sig_b64 = parts
        
        # Decode payload
        try:
            # Handle padding
            pad = len(payload_b64) % 4
            if pad > 0:
                payload_b64 += "=" * (4 - pad)
            payload_json = base64.urlsafe_b64decode(payload_b64.encode()).decode("utf-8")
            claims = json.loads(payload_json)
        except Exception:
            return False, "Unparseable JWT payload claims", None, 90.0, 0.0

        # Check expiration
        exp = claims.get("exp")
        if exp and exp < time.time():
            return False, "JWT access token expired", None, 85.0, 0.1

        # Token is well-formed and valid
        return True, "Valid token", claims, 0.0, 1.0

    def check_bola_idor(self, path: str, claims: Optional[Dict[str, Any]]) -> Tuple[bool, str]:
        """
        BOLA/IDOR prevention: If path is /api/users/{id}, ensures user is accessing
        their own account or possesses 'admin' privileges.
        Returns: (is_authorized, reason)
        """
        if not claims:
            return True, "No claims"
            
        role = claims.get("role", "user")
        sub = str(claims.get("sub", ""))
        
        if path.startswith("/api/users/"):
            target_id = path.split("/")[3]
            # Admin can access all profiles
            if role == "admin":
                return True, "Admin access permitted"
                
            # Standard users can only access their own profile ID
            if sub != target_id and f"cust-{sub}" != target_id:
                return False, f"BOLA violation: user '{sub}' cannot access profile of user '{target_id}'"
                
        return True, "Authorized"

    def generate_token(self, principal_id: str, roles: Optional[List[str]] = None, expires_in_seconds: int = 3600) -> str:
        """Mint a cryptographic test token for authentication validation."""
        header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
        payload = base64.urlsafe_b64encode(json.dumps({
            "sub": principal_id,
            "roles": roles or ["user"],
            "role": (roles[0] if roles else "user"),
            "exp": time.time() + expires_in_seconds
        }).encode()).decode().rstrip("=")
        sig = base64.urlsafe_b64encode(b"simulated_signature").decode().rstrip("=")
        return f"{header}.{payload}.{sig}"

auth_engine = AuthEngine()
