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

from ml.model_service import MLModelService
from ml.feature_engineering import FeatureExtractor
from collections import deque
from agents.orchestrator import security_orchestrator
from gateway.mitigation_engine import MitigationEngine, MitigationDecision, UnauthorizedMitigationError
from gateway.soc_feedback import soc_feedback_engine, FeedbackTag
from gateway.security_metrics import security_metrics_tracker
from ml.retraining_pipeline import ModelRetrainingPipeline

mitigation_engine = MitigationEngine()
security_orchestrator.mitigation_engine = mitigation_engine

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

# Initialize Phase 6 Machine Learning Anomaly Detection Service & Feature Extractor
ml_service = MLModelService(
    model_dir=config.ml_model_dir,
    canary_percentage=config.ml_canary_percentage,
    enabled=config.ml_enabled
)
ml_feature_extractor = FeatureExtractor()
user_recent_events: dict[str, deque] = {}

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
    anomaly_reasons: Optional[List[str]] = None,
    ml_score: float = 0.0,
    ml_confidence: float = 0.0,
    ml_anomalous: bool = False
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
        "ml_score": round(ml_score, 2),
        "ml_confidence": round(ml_confidence, 2),
        "ml_anomalous": ml_anomalous,
        "ml_advisory": True,
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

    # 4. Phase 9: Record decision metrics in SecurityMetricsTracker
    security_metrics_tracker.record_request_decision(decision.value)

    # 5. Phase 7: Security Agents Evaluation for suspicious or elevated-risk events
    if risk_score.overall >= 30.0 or len(fired_rules or []) > 0 or ml_anomalous:
        try:
            user_key = principal or client_ip
            recent_hist = list(user_recent_events.get(user_key, []))
            plan = security_orchestrator.process_security_event(sanitized_event, recent_hist)
            if plan:
                now_epoch = time.time()
                security_metrics_tracker.record_incident_lifecycle(
                    incident_id=plan.incident_id,
                    event_timestamp=now_epoch - (latency_ms / 1000.0),
                    alert_timestamp=now_epoch,
                    containment_timestamp=now_epoch if plan.auto_executed_actions else None,
                    threat_category=plan.actions[0].action_type.value if plan.actions else "UNKNOWN",
                    automated=len(plan.auto_executed_actions) > 0
                )
        except Exception as exc:
            logger.error(f"Error in SecurityOrchestrator: {exc}")

@app.get("/health")
async def health_check():
    """Unprotected health liveness check."""
    return {
        "status": "ok",
        "service": "erp-security-gateway",
        "version": "2.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

@app.get("/api/ml/health")
async def ml_health_check():
    """Advisory ML Model Service diagnostic status and performance metrics."""
    return ml_service.get_health()

@app.post("/api/ml/rollback")
async def ml_emergency_rollback(reason: str = "Operator invoked emergency rollback"):
    """Instant rollback procedure (< 30 seconds SLA). Halts ML scoring immediately."""
    ml_service.rollback(reason=reason)
    return {"status": "rolled_back", "reason": reason}

@app.post("/api/ml/recover")
async def ml_service_recover():
    """Recover ML Service from rollback back into normal canary operation."""
    ml_service.recover()
    return {"status": "recovered", "health": ml_service.get_health()}

# Phase 7: Security Agents Analyst Endpoints
@app.get("/api/agents/status")
async def agents_status():
    """Status summary of all Phase 7 security agents and active containment."""
    return security_orchestrator.get_status()

@app.get("/api/agents/alerts")
async def agents_alerts(limit: int = 50):
    """Retrieve security alerts detected by DetectionAgent."""
    return security_orchestrator.get_alerts(limit=limit)

@app.get("/api/agents/incidents/{incident_id}")
async def agents_incident_dossier(incident_id: str):
    """Retrieve full incident timeline and blast radius report."""
    incident = security_orchestrator.get_incident(incident_id)
    if not incident:
        return JSONResponse(status_code=404, content={"error": "Incident not found"})
    return incident

@app.get("/api/agents/actions/pending")
async def agents_pending_actions():
    """Retrieve containment actions awaiting human analyst approval."""
    return security_orchestrator.get_pending_actions()

@app.post("/api/agents/actions/{action_id}/approve")
async def agents_approve_action(action_id: str, analyst_id: str = "security_analyst"):
    """Human approval gate: authorize high-impact containment action."""
    try:
        return security_orchestrator.approve_action(action_id, analyst_id)
    except KeyError:
        return JSONResponse(status_code=404, content={"error": "Action not found"})
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})

@app.post("/api/agents/actions/{action_id}/reject")
async def agents_reject_action(action_id: str, analyst_id: str = "security_analyst", reason: str = ""):
    """Human approval gate: reject high-impact containment action."""
    try:
        return security_orchestrator.reject_action(action_id, analyst_id, reason)
    except KeyError:
        return JSONResponse(status_code=404, content={"error": "Action not found"})

@app.post("/api/agents/actions/{action_id}/revoke")
async def agents_revoke_action(action_id: str, analyst_id: str = "security_analyst"):
    """Instant containment rollback (<30s SLA): revert executed action."""
    try:
        return security_orchestrator.revoke_action(action_id, analyst_id)
    except KeyError:
        return JSONResponse(status_code=404, content={"error": "Action not found"})
    except ValueError as e:
        return JSONResponse(status_code=400, content={"error": str(e)})


@app.get("/api/mitigations/status")
async def mitigations_status():
    """Active mitigation engine status and registry counts (Phase 8)."""
    return mitigation_engine.get_status()


# Phase 9: Continuous Improvement & SOC Feedback Endpoints
@app.post("/api/soc/feedback")
async def submit_soc_feedback(payload: dict):
    """Submit SOC analyst verdict on a detection, request, or rule firing."""
    tag_str = payload.get("tag", "CONFIRMED_ATTACK").upper()
    try:
        tag_enum = FeedbackTag(tag_str)
    except ValueError:
        return JSONResponse(status_code=400, content={"error": f"Invalid tag: {tag_str}"})

    record = soc_feedback_engine.submit_feedback(
        tag=tag_enum,
        analyst_id=payload.get("analyst_id", "soc_analyst"),
        request_id=payload.get("request_id"),
        alert_id=payload.get("alert_id"),
        rule_id=payload.get("rule_id"),
        notes=payload.get("notes", ""),
        target_entity=payload.get("target_entity"),
        recommended_action=payload.get("recommended_action")
    )
    return record.to_dict()


@app.get("/api/soc/feedback")
async def get_soc_feedback():
    """Retrieve SOC feedback history and rule precision metrics."""
    return {
        "metrics": soc_feedback_engine.get_accuracy_metrics(),
        "recent_records": [r.to_dict() for r in soc_feedback_engine.records[-50:]]
    }


@app.get("/api/soc/tuning-recommendations")
async def get_soc_tuning_recommendations():
    """Retrieve automated threshold tuning recommendations based on recurring FPs."""
    return {
        "recommendations": soc_feedback_engine.generate_tuning_recommendations()
    }


@app.post("/api/ml/retrain")
async def trigger_ml_retraining():
    """Executes automated model retraining cycle with concept drift analysis and promotion gating."""
    import numpy as np
    pipeline = ModelRetrainingPipeline(model_dir=config.ml_model_dir)
    rng = np.random.default_rng(42)
    X_train = rng.normal(loc=0.0, scale=1.0, size=(200, 16))
    X_val_norm = rng.normal(loc=0.0, scale=1.0, size=(100, 16))
    X_val_anom = rng.normal(loc=4.5, scale=1.5, size=(20, 16))

    result = pipeline.run_retraining_cycle(
        X_clean_train=X_train,
        X_validation_normal=X_val_norm,
        X_validation_anomalous=X_val_anom,
        X_reference_baseline=X_val_norm
    )
    return result.to_dict()


@app.get("/api/metrics/security")
async def get_security_kpis():
    """Retrieve enterprise security KPIs: MTTD, MTTR, mitigation rates, and traffic totals."""
    return security_metrics_tracker.get_kpis()


@app.middleware("http")
async def security_pipeline_middleware(request: Request, call_next):
    start_time = time.time()
    
    # 1. Trace ID generation
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
    request.state.request_id = request_id
    
    # Health and management endpoints bypass proxying and security pipeline
    if (
        request.url.path in ("/health", "/api/ml/health", "/api/ml/rollback", "/api/ml/recover", "/api/mitigations/status", "/api/ml/retrain", "/api/metrics/security")
        or request.url.path.startswith("/api/agents")
        or request.url.path.startswith("/api/soc")
        or request.url.path.startswith("/api/metrics")
    ):
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        return response

    client_ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "127.0.0.1")
    reasons = []

    # Phase 8: Active IP & Token Mitigation Check (Fast O(1) Pre-Routing Drop)
    auth_header = request.headers.get("Authorization", "")
    mitigation = mitigation_engine.evaluate_request(
        client_ip=client_ip,
        auth_token=auth_header,
        path=request.url.path
    )
    if mitigation.is_mitigated:
        headers = {"X-Request-ID": request_id, "X-Decision": "BLOCK", **mitigation.headers}
        return JSONResponse(
            status_code=mitigation.http_status,
            headers=headers,
            content={
                "error": "Access Denied" if mitigation.http_status == 403 else ("Too Many Requests" if mitigation.http_status == 429 else "Unauthorized"),
                "request_id": request_id,
                "message": mitigation.reason,
                "mitigation_action": mitigation.action.name if mitigation.action else "ACTIVE_MITIGATION"
            }
        )

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
            # Phase 8: Principal Active Mitigation Check (Suspended Account, MFA Challenge)
            principal_mitigation = mitigation_engine.evaluate_request(
                client_ip=client_ip,
                principal_ref=user_principal,
                auth_token=auth_header,
                path=request.url.path
            )
            if principal_mitigation.is_mitigated:
                headers = {"X-Request-ID": request_id, "X-Decision": "BLOCK", **principal_mitigation.headers}
                return JSONResponse(
                    status_code=principal_mitigation.http_status,
                    headers=headers,
                    content={
                        "error": "Access Denied" if principal_mitigation.http_status == 403 else ("Too Many Requests" if principal_mitigation.http_status == 429 else "Unauthorized"),
                        "request_id": request_id,
                        "message": principal_mitigation.reason,
                        "mitigation_action": principal_mitigation.action.name if principal_mitigation.action else "ACTIVE_MITIGATION"
                    }
                )

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

    # Phase 6: Advisory Machine Learning Anomaly Detection (Canary evaluation)
    ml_score = 0.0
    ml_confidence = 0.0
    ml_anomalous = False

    uid_key = user_principal or client_ip
    if uid_key not in user_recent_events:
        user_recent_events[uid_key] = deque(maxlen=50)

    now_utc = datetime.now(timezone.utc)
    curr_event_record = {
        "timestamp": now_utc.isoformat(),
        "ts_epoch": time.time(),
        "hour_of_day": now_utc.hour,
        "day_of_week": now_utc.weekday(),
        "user_id": uid_key,
        "principal_ref": uid_key,
        "path": request.url.path,
        "method": request.method,
        "client_ip": client_ip,
        "user_agent": request.headers.get("User-Agent", "unknown"),
        "request_size_bytes": len(body_bytes),
        "latency_ms": (time.time() - start_time) * 1000.0,
    }
    user_recent_events[uid_key].append(curr_event_record)

    if ml_service.should_evaluate_ml(request_id):
        ml_features = ml_feature_extractor.extract_features(
            user_events=list(user_recent_events[uid_key]),
            baseline_engine=anomaly_detector.baseline_engine,
            current_event=curr_event_record
        )
        ml_res = ml_service.score_request(ml_features)
        ml_score = ml_res.ml_score
        ml_confidence = ml_res.ml_confidence
        ml_anomalous = ml_res.ml_anomalous
        # CRITICAL CONSTRAINT: ML scores are strictly advisory.
        # They are recorded in telemetry for analysis, but do NOT elevate risk decision to BLOCK.

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
        anomaly_reasons=anomaly_res.reasons, ml_score=ml_score, ml_confidence=ml_confidence,
        ml_anomalous=ml_anomalous
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
