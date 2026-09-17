import os
from dataclasses import dataclass, field
from typing import Dict, Tuple

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

config = GatewayConfig()

