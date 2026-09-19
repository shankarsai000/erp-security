import ipaddress
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Tuple


# Safe default keys used STRICTLY for local testing/development
DEFAULT_DEV_JWT_SECRET = "erp_dev_jwt_secret_key_minimum_32_bytes_long_2026!"
DEFAULT_DEV_COMPLIANCE_SECRET = "erp_gateway_enterprise_tamper_evident_secret_key_2026"
DEFAULT_DEV_TELEMETRY_SALT = "erp_dev_telemetry_pseudonym_salt_2026!"


@dataclass
class GatewayConfig:
    host: str = os.getenv("GATEWAY_HOST", "0.0.0.0")
    port: int = int(os.getenv("GATEWAY_PORT", "8000"))
    backend_url: str = os.getenv("BACKEND_URL", "http://127.0.0.1:8001")
    redis_host: str = os.getenv("REDIS_HOST", "127.0.0.1")
    redis_port: int = int(os.getenv("REDIS_PORT", "6379"))
    redis_timeout: float = float(os.getenv("REDIS_TIMEOUT", "0.5"))
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    max_body_bytes: int = int(os.getenv("MAX_BODY_BYTES", "10485760"))  # 10 MB
    environment: str = os.getenv("ENVIRONMENT", "test").lower()

    # Cryptographic Secrets (SEC-02)
    _jwt_secret_key: str = os.getenv("JWT_SECRET_KEY", "")
    jwt_algorithm: str = os.getenv("JWT_ALGORITHM", "HS256")
    _compliance_signing_secret: str = os.getenv("COMPLIANCE_SIGNING_SECRET", "")
    _telemetry_salt: str = os.getenv("TELEMETRY_SALT", "")

    # Network Security & Proxy Trust (SEC-05)
    # Default trusted proxies: local loopbacks and common container host ingress
    trusted_proxies: List[str] = field(default_factory=lambda: [
        s.strip() for s in os.getenv("TRUSTED_PROXIES", "127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16").split(",") if s.strip()
    ])

    # Internal subnets / hosts that must NEVER be quarantined by automated mitigations
    internal_ip_whitelist: List[str] = field(default_factory=lambda: [
        s.strip() for s in os.getenv("INTERNAL_IP_WHITELIST", "127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,localhost").split(",") if s.strip()
    ])

    # Phase 6 Machine Learning Anomaly Detection configuration
    ml_enabled: bool = os.getenv("ML_ENABLED", "true").lower() == "true"
    ml_canary_percentage: float = float(os.getenv("ML_CANARY_PERCENTAGE", "100.0"))
    ml_model_dir: str = os.getenv("ML_MODEL_DIR", "ml/models")
    ml_max_inference_ms: float = float(os.getenv("ML_MAX_INFERENCE_MS", "50.0"))

    # Policy threshold mapping: (min_inclusive, max_exclusive, decision_name)
    risk_policy: Dict[str, Tuple[float, float]] = field(default_factory=lambda: {
        "ALLOW": (0.0, 20.0),
        "LIMIT": (20.0, 50.0),
        "CHALLENGE": (50.0, 75.0),
        "BLOCK": (75.0, 100.01),
    })

    @property
    def jwt_secret_key(self) -> str:
        if self._jwt_secret_key:
            return self._jwt_secret_key
        if self.environment == "production":
            raise ValueError("FATAL: JWT_SECRET_KEY environment variable is required in production mode.")
        return DEFAULT_DEV_JWT_SECRET

    @property
    def compliance_signing_secret(self) -> str:
        if self._compliance_signing_secret:
            return self._compliance_signing_secret
        if self.environment == "production":
            raise ValueError("FATAL: COMPLIANCE_SIGNING_SECRET environment variable is required in production mode.")
        return DEFAULT_DEV_COMPLIANCE_SECRET

    @property
    def telemetry_salt(self) -> bytes:
        raw = self._telemetry_salt or (DEFAULT_DEV_TELEMETRY_SALT if self.environment != "production" else "")
        if not raw and self.environment == "production":
            raise ValueError("FATAL: TELEMETRY_SALT environment variable is required in production mode.")
        return raw.encode("utf-8")

    def validate_production_secrets(self) -> None:
        """Enforces that all production cryptographic secrets are present and meet minimum strength."""
        if self.environment != "production":
            return

        missing = []
        if not self._jwt_secret_key:
            missing.append("JWT_SECRET_KEY")
        elif len(self._jwt_secret_key) < 32:
            raise ValueError("JWT_SECRET_KEY must be at least 32 characters (256 bits) in production.")

        if not self._compliance_signing_secret:
            missing.append("COMPLIANCE_SIGNING_SECRET")
        elif len(self._compliance_signing_secret) < 32:
            raise ValueError("COMPLIANCE_SIGNING_SECRET must be at least 32 characters in production.")

        if not self._telemetry_salt:
            missing.append("TELEMETRY_SALT")
        elif len(self._telemetry_salt) < 16:
            raise ValueError("TELEMETRY_SALT must be at least 16 characters in production.")

        if missing:
            raise ValueError(f"FATAL: Missing required production secrets: {', '.join(missing)}")

    @staticmethod
    def _clean_ip(ip_str: str) -> str:
        if not ip_str:
            return ""
        clean = ip_str.strip()
        if clean.startswith("[") and "]" in clean:
            clean = clean.split("]")[0].lstrip("[")
        elif clean.count(":") == 1:
            clean = clean.split(":")[0].strip()
        return clean

    def is_ip_whitelisted(self, ip_str: str) -> bool:
        """Determines whether an IP address is part of the protected internal whitelist."""
        if not ip_str:
            return False
        clean_ip = self._clean_ip(ip_str)
        if clean_ip in ("127.0.0.1", "::1", "localhost", "testclient"):
            return True
        try:
            addr = ipaddress.ip_address(clean_ip)
            for cidr in self.internal_ip_whitelist:
                if cidr in ("localhost", "testclient"):
                    continue
                try:
                    if "/" in cidr:
                        if addr in ipaddress.ip_network(cidr, strict=False):
                            return True
                    else:
                        if addr == ipaddress.ip_address(cidr):
                            return True
                except ValueError:
                    continue
        except ValueError:
            pass
        return False

    def is_trusted_proxy(self, ip_str: str) -> bool:
        """Checks whether the immediate TCP peer is an authorized reverse proxy."""
        if not ip_str:
            return False
        clean_ip = self._clean_ip(ip_str)
        if clean_ip in ("127.0.0.1", "::1", "localhost", "testclient"):
            return True
        try:
            addr = ipaddress.ip_address(clean_ip)
            for cidr in self.trusted_proxies:
                try:
                    if "/" in cidr:
                        if addr in ipaddress.ip_network(cidr, strict=False):
                            return True
                    else:
                        if addr == ipaddress.ip_address(cidr):
                            return True
                except ValueError:
                    continue
        except ValueError:
            pass
        return False


config = GatewayConfig()
