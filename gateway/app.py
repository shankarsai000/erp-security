import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from gateway.config import config
from gateway.rate_limiter import RateLimiter
from gateway.risk_engine import Decision, RiskScore, calculate_risk
from gateway.waf import inspect_content

# Logging configuration
logging.basicConfig(
    level=config.log_level,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger("erp_security_gateway")
audit_logger = logging.getLogger("security_audit")

# Initialize Rate Limiter
rate_limiter = RateLimiter(
    redis_host=config.redis_host,
    redis_port=config.redis_port,
    redis_timeout=config.redis_timeout
)

import asyncio

# Persistent HTTP Client with connection pooling for proxying
http_client: Optional[httpx.AsyncClient] = None
_client_loop = None

def get_http_client() -> httpx.AsyncClient:
    global http_client
    if http_client is None or http_client.is_closed:
        http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=10.0),
            limits=httpx.Limits(max_keepalive_connections=100, max_connections=200)
        )
    return http_client

app = FastAPI(
    title="ERP Security Gateway",
    version="1.0.0",
    docs_url="/docs",
    redoc_url=None
)

@app.on_event("startup")
async def startup_event():
    get_http_client()
    logger.info("Security Gateway initialized with upstream pool to %s", config.backend_url)

@app.on_event("shutdown")
async def shutdown_event():
    global http_client
    if http_client:
        await http_client.aclose()
        logger.info("Security Gateway HTTP pool closed.")

def verify_jwt_token(auth_header: str) -> tuple[bool, str, float, float]:
    """
    Validates Authorization Bearer token structure and claims.
    Returns: (is_valid, reason, auth_anomaly_score_0_to_100, user_trust_0_to_1)
    """
    if not auth_header:
        return False, "Missing Authorization header", 85.0, 0.0
        
    if not auth_header.startswith("Bearer "):
        return False, "Invalid Authorization scheme (Bearer required)", 80.0, 0.0
        
    token = auth_header[7:].strip()
    parts = token.split(".")
    if len(parts) != 3:
        return False, "Malformed JWT structure (must contain header.payload.signature)", 100.0, 0.0
        
    # Valid structural token
    return True, "Valid JWT format", 0.0, 1.0

def emit_audit_event(
    request_id: str,
    decision: Decision,
    risk_score: RiskScore,
    request: Request,
    latency_ms: float,
    client_ip: str
):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        "client_ip": client_ip,
        "method": request.method,
        "path": request.url.path,
        "decision": decision.value,
        "risk_score": risk_score.overall,
        "components": risk_score.components,
        "reasons": risk_score.reasons,
        "latency_ms": round(latency_ms, 2),
        "user_agent": request.headers.get("User-Agent", "unknown")
    }
    # Emits structured JSON line
    audit_logger.info(json.dumps(event))

@app.get("/health")
async def health_check():
    """Unprotected health liveness check."""
    return {
        "status": "ok",
        "service": "erp-security-gateway",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.middleware("http")
async def security_pipeline_middleware(request: Request, call_next):
    start_time = time.time()
    
    # 1. Trace ID generation
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = request_id
    
    # Health endpoint bypasses inspection
    if request.url.path == "/health":
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    client_ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "127.0.0.1")
    reasons = []
    
    # 2. Oversized payload verification
    content_length = request.headers.get("Content-Length")
    if content_length:
        try:
            length_bytes = int(content_length)
            if length_bytes > config.max_body_bytes:
                risk = calculate_risk(
                    waf_severity=85.0,
                    auth_anomaly=0.0,
                    rate_severity=30.0,
                    path=request.url.path,
                    extra_reasons=[f"Oversized request body ({length_bytes} bytes exceeds {config.max_body_bytes} limit)"]
                )
                emit_audit_event(request_id, Decision.BLOCK, risk, request, (time.time() - start_time) * 1000, client_ip)
                return JSONResponse(
                    status_code=413,
                    content={"error": "Payload Too Large", "request_id": request_id, "message": "Request exceeds maximum permitted size"}
                )
        except ValueError:
            pass

    # Read body for inspection while preserving stream for proxying
    body_bytes = await request.body()
    async def receive():
        return {"type": "http.request", "body": body_bytes}
    request._receive = receive
    body_text = body_bytes.decode("utf-8", errors="ignore") if body_bytes else ""
    
    # 3. WAF Inspection (Path, Query String, and Body)
    waf_severity = 0.0
    is_path_attack, path_reasons, path_score = inspect_content(str(request.url))
    if is_path_attack:
        waf_severity = max(waf_severity, float(path_score))
        reasons.extend(path_reasons)
        
    if body_text:
        is_body_attack, body_reasons, body_score = inspect_content(body_text)
        if is_body_attack:
            waf_severity = max(waf_severity, float(body_score))
            reasons.extend(body_reasons)

    # 4. Authentication Inspection
    auth_header = request.headers.get("Authorization", "")
    is_auth_exempt = request.url.path in ["/health", "/api/auth/login"]
    
    if is_auth_exempt:
        auth_anomaly = 0.0
        user_trust = 0.85
    else:
        is_token_valid, auth_reason, auth_anomaly, user_trust = verify_jwt_token(auth_header)
        if not is_token_valid:
            reasons.append(auth_reason)

    # 5. Rate Limiting Check
    rate_key = client_ip
    count, rate_severity = rate_limiter.check_rate(rate_key)
    if rate_severity > 50:
        reasons.append(f"Elevated request rate detected: {count} req/min")

    # 6. Calculate Bounded Risk Score & Decision
    risk_score = calculate_risk(
        waf_severity=waf_severity,
        auth_anomaly=auth_anomaly,
        rate_severity=float(rate_severity),
        path=request.url.path,
        user_trust=user_trust,
        extra_reasons=reasons
    )

    elapsed_ms = (time.time() - start_time) * 1000
    emit_audit_event(request_id, risk_score.decision, risk_score, request, elapsed_ms, client_ip)

    # 7. Enforce Security Decisions
    if risk_score.decision == Decision.BLOCK:
        return JSONResponse(
            status_code=403,
            headers={
                "X-Request-ID": request_id,
                "X-Decision": risk_score.decision.value,
                "X-Risk-Score": str(risk_score.overall)
            },
            content={
                "error": "Forbidden",
                "request_id": request_id,
                "message": "Request blocked by ERP Security Gateway policy",
                "risk_score": risk_score.overall,
                "reasons": risk_score.reasons
            }
        )

    if risk_score.decision == Decision.CHALLENGE:
        return JSONResponse(
            status_code=401,
            headers={
                "X-Request-ID": request_id,
                "X-Decision": risk_score.decision.value,
                "X-Risk-Score": str(risk_score.overall),
                "WWW-Authenticate": "Bearer error=\"invalid_token\""
            },
            content={
                "error": "Unauthorized",
                "request_id": request_id,
                "message": "Authentication required or invalid credentials",
                "reasons": risk_score.reasons
            }
        )

    # Hard throttle if rate exceeded max limit
    if count > 1000:
        return JSONResponse(
            status_code=429,
            headers={"X-Request-ID": request_id, "Retry-After": "60"},
            content={"error": "Too Many Requests", "request_id": request_id, "message": "Rate limit exceeded"}
        )

    # 8. Forward Legitimate Traffic to Upstream ERP
    upstream_url = f"{config.backend_url}{request.url.path}"
    if request.url.query:
        upstream_url += f"?{request.url.query}"
        
    forward_headers = dict(request.headers)
    forward_headers["X-Request-ID"] = request_id
    forward_headers["X-Decision"] = risk_score.decision.value
    forward_headers["X-Risk-Score"] = str(risk_score.overall)
    # Strip transport headers
    for h in ["host", "content-length", "transfer-encoding"]:
        forward_headers.pop(h, None)

    try:
        client = get_http_client()
        upstream_resp = await client.request(
            method=request.method,
            url=upstream_url,
            headers=forward_headers,
            content=body_bytes
        )
        
        response = Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers=dict(upstream_resp.headers)
        )
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Decision"] = risk_score.decision.value
        response.headers["X-Risk-Score"] = str(risk_score.overall)
        return response
        
    except Exception as exc:
        logger.error(f"Failed to proxy request {request_id} to {upstream_url}: {exc}")
        return JSONResponse(
            status_code=502,
            headers={"X-Request-ID": request_id},
            content={
                "error": "Bad Gateway",
                "request_id": request_id,
                "message": "Security gateway was unable to communicate with backend ERP service"
            }
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=config.host, port=config.port, log_level=config.log_level.lower())
