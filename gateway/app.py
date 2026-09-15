import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Optional, List

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from gateway.anomaly_detection import anomaly_detector
from gateway.auth_engine import auth_engine
from gateway.config import config
from gateway.credential_defense import credential_defense
from gateway.rate_limiter import RateLimiter
from gateway.replay_guard import replay_guard
from gateway.risk_engine import Decision, RiskScore, calculate_risk
from gateway.route_allowlist import route_allowlist
from gateway.rules_engine import rules_engine
from gateway.schemas import LoginSchema, OrderCreateSchema
from gateway.telemetry.anti_poisoning import anti_poisoning_filter

from gateway.telemetry.event_pipeline import telemetry_pipeline
from gateway.telemetry.redaction import pseudonymize_identifier, sanitize_telemetry
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

# Persistent HTTP Client with connection pooling for proxying
http_client: Optional[httpx.AsyncClient] = None

def get_http_client() -> httpx.AsyncClient:
    global http_client
    loop = None
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        pass

    recreate = False
    if http_client is None or http_client.is_closed:
        recreate = True
    elif hasattr(http_client, "_loop") and http_client._loop is not None and (http_client._loop.is_closed() or (loop is not None and http_client._loop != loop)):
        recreate = True

    if recreate:
        http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=10.0),
            limits=httpx.Limits(max_keepalive_connections=100, max_connections=200)
        )
        http_client._loop = loop
    return http_client


app = FastAPI(
    title="ERP Security Gateway",
    version="2.0.0",
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

def emit_audit_event(
    request_id: str,
    decision: Decision,
    risk_score: RiskScore,
    request: Request,
    latency_ms: float,
    client_ip: str,
    principal: str = "",
    fired_rules: Optional[List[str]] = None,
    anomaly_score: float = 0.0,
    anomaly_reasons: Optional[List[str]] = None
):
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        "principal_ref": pseudonymize_identifier(principal or client_ip),
        "client_ip": client_ip,
        "method": request.method,
        "path": request.url.path,
        "decision": decision.value,
        "risk_score": risk_score.overall,
        "components": risk_score.components,
        "fired_rules": fired_rules or [],
        "anomaly_score": round(anomaly_score, 2),
        "anomaly_reasons": anomaly_reasons or [],
        "reasons": risk_score.reasons,
        "latency_ms": round(latency_ms, 2),
        "user_agent": request.headers.get("User-Agent", "unknown")
    }
    # Scrub any accidental PII before serialization
    sanitized_event = sanitize_telemetry(event)

    
    # 1. Local structured logger
    audit_logger.info(json.dumps(sanitized_event))
    
    # 2. Asynchronous Guaranteed Telemetry Pipeline (Phase 3)
    telemetry_pipeline.emit(sanitized_event)
    
    # 3. Anti-Poisoning Quarantine Routing (Phase 3)
    anti_poisoning_filter.process_event(sanitized_event)

@app.get("/health")
async def health_check():
    """Unprotected health liveness check."""
    return {
        "status": "ok",
        "service": "erp-security-gateway",
        "version": "2.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.middleware("http")
async def security_pipeline_middleware(request: Request, call_next):
    start_time = time.time()
    
    # 1. Trace ID generation
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = request_id
    
    # Health endpoint bypasses security pipeline
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
                    headers={"X-Request-ID": request_id, "X-Decision": "BLOCK"},
                    content={"error": "Payload Too Large", "request_id": request_id, "message": "Request exceeds maximum permitted size"}
                )
        except ValueError:
            pass

    # Read body for inspection while preserving receive channel for proxying
    body_bytes = await request.body()
    async def receive():
        return {"type": "http.request", "body": body_bytes}
    request._receive = receive
    body_text = body_bytes.decode("utf-8", errors="ignore") if body_bytes else ""

    # 3. Credential Defense Status Check (Brute-force velocity lockout)
    is_brute_force, cred_threat, cred_reasons = credential_defense.check_status(client_ip)
    if is_brute_force:
        reasons.extend(cred_reasons)
        risk = calculate_risk(
            waf_severity=float(cred_threat),
            auth_anomaly=0.0,
            rate_severity=80.0,
            path=request.url.path,
            extra_reasons=reasons
        )
        emit_audit_event(request_id, Decision.BLOCK, risk, request, (time.time() - start_time) * 1000, client_ip)
        return JSONResponse(
            status_code=403,
            headers={"X-Request-ID": request_id, "X-Decision": "BLOCK", "X-Risk-Score": str(risk.overall)},
            content={"error": "Forbidden", "request_id": request_id, "message": "Access temporarily locked due to repeated authentication failures", "reasons": reasons}
        )

    # 4. WAF Inspection (Inspect raw URL and body for SQLi, XSS, Path Traversal)
    waf_severity = float(cred_threat)
    is_path_attack, path_reasons, path_score = inspect_content(str(request.url))
    if is_path_attack:
        waf_severity = max(waf_severity, float(path_score))
        reasons.extend(path_reasons)
        
    if body_text:
        is_body_attack, body_reasons, body_score = inspect_content(body_text)
        if is_body_attack:
            waf_severity = max(waf_severity, float(body_score))
            reasons.extend(body_reasons)

    if is_path_attack or (body_text and is_body_attack):
        risk = calculate_risk(
            waf_severity=waf_severity,
            auth_anomaly=0.0,
            rate_severity=0.0,
            path=request.url.path,
            extra_reasons=reasons
        )
        emit_audit_event(request_id, Decision.BLOCK, risk, request, (time.time() - start_time) * 1000, client_ip)
        return JSONResponse(
            status_code=403,
            headers={
                "X-Request-ID": request_id,
                "X-Decision": "BLOCK",
                "X-Risk-Score": str(risk.overall)
            },
            content={
                "error": "Forbidden",
                "request_id": request_id,
                "message": "Request blocked by ERP Security Gateway policy",
                "risk_score": risk.overall,
                "reasons": risk.reasons
            }
        )

    # 5. Route Allowlisting Check
    is_known, is_method_allowed, matching_rule, route_reason = route_allowlist.validate_route(
        request.url.path, request.method
    )
    if not is_known:
        return JSONResponse(
            status_code=404,
            headers={"X-Request-ID": request_id, "X-Decision": "BLOCK"},
            content={"error": "Not Found", "request_id": request_id, "message": route_reason}
        )
    if not is_method_allowed:
        return JSONResponse(
            status_code=405,
            headers={"X-Request-ID": request_id, "X-Decision": "BLOCK"},
            content={"error": "Method Not Allowed", "request_id": request_id, "message": route_reason}
        )

    # 6. JSON Schema Validation
    if request.method in ["POST", "PUT"] and body_text:
        try:
            payload = json.loads(body_text)
            if request.url.path == "/api/auth/login":
                LoginSchema(**payload)
            elif request.url.path == "/api/orders":
                OrderCreateSchema(**payload)
        except json.JSONDecodeError:
            return JSONResponse(
                status_code=400,
                headers={"X-Request-ID": request_id, "X-Decision": "BLOCK"},
                content={"error": "Bad Request", "request_id": request_id, "message": "Malformed JSON in request body"}
            )
        except Exception as e:
            return JSONResponse(
                status_code=422,
                headers={"X-Request-ID": request_id, "X-Decision": "BLOCK"},
                content={"error": "Unprocessable Entity", "request_id": request_id, "message": f"Schema validation failed: {e}"}
            )

    # 7. Replay Protection Guard
    if request.method in ["POST", "PUT", "DELETE"]:
        nonce = request.headers.get("X-Nonce")
        timestamp_str = request.headers.get("X-Timestamp")
        is_replay, replay_threat, replay_reasons = replay_guard.validate_request(nonce, timestamp_str, body_bytes)
        if is_replay:
            reasons.extend(replay_reasons)
            waf_severity = max(waf_severity, replay_threat)
            risk = calculate_risk(
                waf_severity=waf_severity,
                auth_anomaly=0.0,
                rate_severity=50.0,
                path=request.url.path,
                extra_reasons=reasons
            )
            emit_audit_event(request_id, Decision.BLOCK, risk, request, (time.time() - start_time) * 1000, client_ip)
            return JSONResponse(
                status_code=403,
                headers={"X-Request-ID": request_id, "X-Decision": "BLOCK", "X-Risk-Score": str(risk.overall)},
                content={"error": "Forbidden", "request_id": request_id, "message": "Replay attack detected or timestamp outside valid window", "reasons": reasons}
            )

    # 8. Cryptographic JWT & BOLA/IDOR Authorization
    auth_header = request.headers.get("Authorization", "")
    is_auth_exempt = request.url.path in ["/health", "/api/auth/login"]
    user_principal = ""
    
    if is_auth_exempt:
        auth_anomaly = 0.0
        user_trust = 0.85
    else:
        is_token_valid, auth_reason, claims, auth_anomaly, user_trust = auth_engine.decode_and_verify(auth_header)
        if not is_token_valid:
            reasons.append(auth_reason)
        else:
            user_principal = str(claims.get("sub", ""))
            # BOLA/IDOR Context Check
            is_authorized, bola_reason = auth_engine.check_bola_idor(request.url.path, claims)
            if not is_authorized:
                reasons.append(bola_reason)
                waf_severity = max(waf_severity, 95.0)  # Hard block IDOR tampering

    # 9. Phase 4: Deterministic Business Logic Rules Engine
    payload_dict = {}
    if body_text:
        try:
            payload_dict = json.loads(body_text) if isinstance(body_text, str) and body_text.strip().startswith(("{", "[")) else {}
        except Exception:
            payload_dict = {}

    current_role = ""
    if not is_auth_exempt and 'claims' in locals() and claims:
        current_role = str(claims.get("role", ""))

    rule_request_data = {
        "method": request.method,
        "path": request.url.path,
        "body": payload_dict,
        "client_ip": client_ip,
        "user_id": user_principal or client_ip,
        "current_role": current_role,
        "is_authenticated": (not is_auth_exempt and bool(user_principal)),
        "headers": dict(request.headers),
    }

    rule_severity, fired_rules = rules_engine.evaluate(rule_request_data)
    if fired_rules:
        reasons.extend(rules_engine.fired_reasons)

    # 10. Phase 5: Deterministic Statistical Anomaly Detection
    anomaly_request_data = {
        "user_id": user_principal or client_ip,
        "path": request.url.path,
        "request_size_bytes": len(body_bytes),
        "latency_ms": (time.time() - start_time) * 1000.0,
        "request_hour": datetime.now(timezone.utc).hour,
    }
    anomaly_res = anomaly_detector.detect_anomalies(anomaly_request_data)
    if anomaly_res.is_anomalous:
        reasons.extend(anomaly_res.reasons)

    # 11. Rate Limiting Check
    rate_key = client_ip
    count, rate_severity = rate_limiter.check_rate(rate_key)
    if rate_severity > 50:
        reasons.append(f"Elevated request rate detected: {count} req/min")

    # 12. Calculate Bounded Risk Score & Decision
    risk_score = calculate_risk(
        waf_severity=waf_severity,
        auth_anomaly=auth_anomaly,
        rate_severity=float(rate_severity),
        path=request.url.path,
        user_trust=user_trust,
        rule_severity=float(rule_severity),
        anomaly_score=float(anomaly_res.score),
        extra_reasons=reasons
    )

    elapsed_ms = (time.time() - start_time) * 1000
    emit_audit_event(
        request_id, risk_score.decision, risk_score, request, elapsed_ms, client_ip,
        user_principal, fired_rules=fired_rules, anomaly_score=anomaly_res.score,
        anomaly_reasons=anomaly_res.reasons
    )



    # 11. Enforce Security Decisions
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

    if count > 1000:
        return JSONResponse(
            status_code=429,
            headers={"X-Request-ID": request_id, "Retry-After": "60"},
            content={"error": "Too Many Requests", "request_id": request_id, "message": "Rate limit exceeded"}
        )

    # 12. Forward Legitimate Traffic to Upstream ERP
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
        
        # Track failed logins for brute force defense
        if request.url.path == "/api/auth/login" and upstream_resp.status_code == 401:
            try:
                login_body = json.loads(body_text)
                credential_defense.record_failure(client_ip, login_body.get("username", ""))
            except Exception:
                credential_defense.record_failure(client_ip)

        response = Response(
            content=upstream_resp.content,
            status_code=upstream_resp.status_code,
            headers=dict(upstream_resp.headers)
        )
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Decision"] = risk_score.decision.value
        response.headers["X-Risk-Score"] = str(risk_score.overall)
        return response

    except RuntimeError as exc:
        if "Event loop is closed" in str(exc):
            http_client = None
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
        logger.error(f"RuntimeError proxying request {request_id} to {upstream_url}: {exc}")
        return JSONResponse(
            status_code=502,
            headers={"X-Request-ID": request_id},
            content={
                "error": "Bad Gateway",
                "request_id": request_id,
                "message": "Security gateway was unable to communicate with backend ERP service"
            }
        )
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
