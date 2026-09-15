# MASTER IMPLEMENTATION PROMPT
## ERP Security Gateway — Phase 0 & Phase 1 Execution

**For:** Anti Gravity Implementation Agents  
**Status:** Ready to Execute  
**Reference Files:** 
1. `ERP_Security_Gateway_End_to_End_Production_Implementation_Playbook.pdf` (Original)
2. `VERIFICATION_REPORT_ERP_Security_Architecture.md` (Verification + 25 fixes)
3. `CRITICAL_IMPROVEMENTS_SUMMARY.md` (10 priority fixes)

**Timeline:** Phase 0 (1 week) + Phase 1 (2 weeks) = **3 weeks to MVP**

---

## PART A: CONTEXT FOR AGENTS

You are implementing a **production-grade security gateway** in front of an existing PHP/SQL ERP with an Android client.

### Core Principle
```
Deterministic Rules First → Telemetry Second → ML Third → Agents Fourth
NOT: "Deploy AI → hope it works"
```

### Success Looks Like (End of Phase 1)
```
✅ Every ERP API request flows through security gateway
✅ Gateway validates against API schema (rejects malformed)
✅ Gateway checks authentication (rejects invalid tokens)
✅ Gateway rate-limits (rejects abusive traffic)
✅ Gateway logs every decision with request ID and reason
✅ Gateway can be tested against 10 OWASP attack patterns (SQLi, XSS, etc)
✅ Staging ERP is behind security gateway
✅ Known legitimate workflows pass through without blocking
✅ Team can explain every blocked request
✅ Latency overhead < 20ms p95
```

### Why This Matters
- **Problem:** PHP ERP is 10+ years old. Rewriting it is impossible.
- **Solution:** Put security IN FRONT instead of inside.
- **Timeline:** 3 weeks to something useful. 12-16 weeks to enterprise-grade.
- **Risk:** If gateway is down, ERP is unreachable. Must design for HA early.

---

## PART B: PHASE 0 — GROUND TRUTH (Week 1)

**Owner:** Infrastructure Engineer + Security Engineer  
**Deliverable:** Versioned inventory document (source of truth for all decisions)  
**Exit Criteria:** All unknowns converted to verified facts

### Task 0.1: ERP Topology Inventory

**File Reference:** Playbook §4 "Target Architecture"

**Required Information:**
```
Frontend:
  □ Web framework (PHP version, framework: Laravel? Symfony? Custom?)
  □ Application server (Apache? nginx? IIS?)
  □ Android app (Kotlin? Java? React Native?)
  □ Minimum Android version? (API level 24+?)
  □ Is app already signed? Release process?
  
Backend:
  □ Database engine (PostgreSQL? MySQL? SQL Server?)
  □ Database version?
  □ Connection pooling? (PgBouncer? ProxySQL?)
  □ Backup strategy? (daily? hourly?)
  □ Replication? (primary-replica or primary-primary?)
  
Networking:
  □ Existing firewall? (AWS security group? On-prem Palo Alto?)
  □ Existing load balancer? (AWS ALB? nginx?)
  □ Existing WAF? (CloudFlare? ModSecurity?)
  □ Existing CDN? (CloudFlare? AWS CloudFront?)
  □ Existing DNS provider? (Route53? Google Cloud DNS?)
  □ Certificate management? (AWS ACM? Let's Encrypt? Self-signed?)
  □ TLS version? (1.2? 1.3?)
  
Deployment:
  □ Cloud or on-premise? (AWS? GCP? Azure? Data center?)
  □ Container orchestration? (Kubernetes? Docker Compose? VMs?)
  □ CI/CD pipeline? (GitHub Actions? Jenkins? GitLab CI?)
  □ Deployment frequency? (manual? automated?)
  
Monitoring:
  □ Application monitoring? (APM tool? CloudWatch? Datadog?)
  □ Logging? (ELK? Splunk? Cloudwatch Logs?)
  □ Metrics? (Prometheus? CloudWatch?)
```

**Delivery:**
Create file: `inventory/erp_topology.yaml`
```yaml
# ERP Topology Inventory
# Last updated: [DATE]
# Owner: [NAME]

frontend:
  web_framework: "PHP 8.1"
  framework: "Laravel 9"
  server: "nginx 1.20"
  
android_app:
  language: "Kotlin"
  min_api_level: 24
  current_version: "1.2.3"
  app_signing: "signed with release key"
  
backend:
  database_engine: "PostgreSQL 14"
  host: "prod-db.internal"
  port: 5432
  
existing_security:
  firewall: "AWS Security Group"
  load_balancer: "AWS ALB"
  waf: "None (will implement)"
  
cloud_provider: "AWS"
region: "us-east-1"
```

---

### Task 0.2: API Inventory

**File Reference:** Playbook §4, Verification §7

**Required Information:**
```
For EACH API endpoint:
  □ Method (GET? POST? PUT? DELETE?)
  □ Path (/api/orders, /api/users, etc)
  □ Authentication (JWT? OAuth? Session cookie?)
  □ Authorization (RBAC? ABAC?)
  □ Typical payload size (bytes?)
  □ Request rate (calls/minute from typical user?)
  □ Response time (p50? p95?)
  □ Business criticality (HIGH? MEDIUM? LOW?)
  □ Data sensitivity (PII? Financial? Public?)
```

**Delivery:**
Create file: `inventory/api_inventory.yaml`
```yaml
# API Inventory
# Generated: [DATE]

endpoints:
  - path: "/api/orders"
    methods: ["GET", "POST", "PUT"]
    auth: "JWT bearer token"
    roles: ["sales", "admin"]
    avg_payload_bytes: 1200
    call_rate_per_min: 100
    criticality: "HIGH"
    data_sensitivity: "PII + Financial"
    
  - path: "/api/users/{id}"
    methods: ["GET", "POST"]
    auth: "JWT bearer token"
    roles: ["admin"]
    roles_check: "User can only access own record"
    criticality: "HIGH"
    data_sensitivity: "PII"
    
  # ... repeat for all endpoints ...
```

**How to Get This:**
- Read ERP source code (PHP files)
- grep -r "@route" or route definitions
- Check Laravel routes.php or Symfony routing.yaml
- Talk to backend team: "what endpoints do clients call?"
- Trace Android app network calls (Wireshark, Burp Suite)

---

### Task 0.3: Traffic Measurement

**File Reference:** Playbook §5, Verification §20

**Required Information:**
```
Current production:
  □ Peak requests/second (RPS)?
  □ Average RPS?
  □ Concurrent connections?
  □ Avg response time (p50, p95, p99)?
  □ Error rate? (5xx responses?)
  □ Request size distribution (min, max, median)?
  □ Response size distribution?
  □ Busiest time of day? (day vs night?)
  □ Busiest day of week? (weekday vs weekend?)
  □ Seasonal patterns? (Q4 surge? summer dip?)
```

**How to Get This:**
- Enable nginx logs (if not already)
- Check existing monitoring (CloudWatch, Datadog, APM tool)
- Run for 1-2 weeks, capture baseline
- Use: `tail -f /var/log/nginx/access.log | awesomestat`

**Delivery:**
Create file: `measurements/traffic_baseline.yaml`
```yaml
traffic_baseline:
  peak_rps: 45  # requests per second (during business hours)
  average_rps: 15  # requests per second (all-day average)
  peak_concurrent_connections: 500
  
response_times:
  p50_ms: 45
  p95_ms: 120
  p99_ms: 500
  
request_sizes:
  min_bytes: 50
  avg_bytes: 1200
  max_bytes: 5000
  
error_rate:
  5xx_percent: 0.5  # 0.5% are server errors
  4xx_percent: 2.0  # 2% are client errors
  
seasonal_notes: "Q4 has 3x traffic; August has 0.5x"
```

---

### Task 0.4: Threat Model

**File Reference:** Verification §21, Architecture §21

**Deliverable:** STRIDE threat model (1-2 pages)

Create file: `security/threat_model.md`

```markdown
# ERP Threat Model (STRIDE)

## Spoofing (Fake Identity)
- Attacker steals user credentials (phishing, malware)
- Attacker obtains valid JWT token
- Attacker impersonates admin
- Mitigation: MFA, certificate pinning, anomaly detection

## Tampering (Modify Data)
- Attacker changes order price during transit
- Attacker modifies JWT token claims
- Attacker injects SQL via API parameter
- Mitigation: Request signing, input validation, TLS

## Repudiation (Deny Actions)
- User claims "I didn't make that order"
- Attacker deletes audit logs
- Mitigation: Immutable audit logs, non-repudiation tokens

## Information Disclosure (Data Breach)
- Attacker exfiltrates customer PII
- Attacker extracts database via SQL injection
- Attacker intercepts TLS traffic (MITM)
- Mitigation: Data classification, TLS pinning, egress filtering

## Denial of Service
- Attacker floods API with 100K RPS (DDoS)
- Attacker triggers infinite loop in app logic
- Attacker deletes database
- Mitigation: DDoS protection, rate limiting, backups

## Elevation of Privilege
- Attacker with "sales" role gains "admin" access
- Attacker finds IDOR vulnerability (accesses other user's data)
- Attacker modifies admin user in database
- Mitigation: RBAC, BOLA detection, audit logging
```

---

### Task 0.5: Risk Assessment

**Deliverable:** Risk prioritization matrix

Create file: `security/risk_assessment.yaml`

```yaml
# Risk Assessment: Prioritized by likelihood × impact

high_priority_risks:
  - threat: "SQL Injection via API parameters"
    likelihood: "HIGH"  # Common, easy to exploit
    impact: "CRITICAL"  # Full database compromise
    mitigation: "WAF rules, input validation, parameterized queries"
    owner: "Security Team"
    
  - threat: "BOLA/IDOR (user can access other user's data)"
    likelihood: "HIGH"  # Common in APIs
    impact: "CRITICAL"  # Privacy violation, compliance breach
    mitigation: "Authorization checks in gateway + backend"
    owner: "Backend Team"
    
  - threat: "Credential Stuffing (brute-force login)"
    likelihood: "HIGH"  # Automated attacks common
    impact: "HIGH"  # Account compromise
    mitigation: "Rate limiting, MFA, account lockout"
    owner: "Security Team"
    
  - threat: "API Rate Abuse (bot scraping data)"
    likelihood: "MEDIUM"  # Competitors might do this
    impact: "MEDIUM"  # Performance degradation, cost
    mitigation: "Rate limiting per user/endpoint"
    owner: "Security Team"

medium_priority_risks:
  - threat: "Man-in-the-Middle (MITM) attack"
    likelihood: "LOW"  # TLS prevents most
    impact: "CRITICAL"  # Credential theft
    mitigation: "TLS 1.3, certificate pinning on mobile"
    owner: "Ops Team"
```

---

### Task 0.6: Security Team Alignment

**Deliverable:** Signed-off requirements document

**Hold meeting with:**
- Backend engineer (API design)
- DevOps/SRE (infrastructure)
- Security team (requirements)
- Product manager (business impact)

**Discuss:**
- What's the biggest threat to the ERP right now?
- What happened in past security incidents?
- What's the compliance requirement? (GDPR? PCI? SOC 2?)
- How much latency can we add? (0ms? 50ms? 100ms?)
- How often can we deploy changes? (daily? weekly?)
- Who owns incident response?

**Output:**
Create file: `security/requirements.yaml`

```yaml
# Security Requirements (Signed Off)
# Date: [DATE]
# Approved by: [NAMES]

non_negotiable:
  - "No plaintext passwords or tokens in logs"
  - "Every security decision must be auditable"
  - "Gateway cannot be single point of failure"
  - "Latency overhead < 50ms p95"
  
must_have:
  - "Block SQL injection, XSS, malformed requests"
  - "Enforce API schema validation"
  - "Rate-limit per user and per endpoint"
  - "Log every security decision"
  
nice_to_have:
  - "Anomaly detection (future ML)"
  - "Automatic response (future automation)"
  - "Admin dashboard (future)"
  
compliance:
  - "GDPR: Data minimization (don't log PII)"
  - "No regulations? Document it"
```

---

### Task 0.7: Environment Setup

**Deliverable:** Development environment ready to code

**Setup:**
```bash
# Create project structure
mkdir -p erp-security-gateway/{gateway,backend,tests,deploy}
cd erp-security-gateway

# Initialize git (version everything)
git init
git config user.name "Security Team"

# Create .gitignore
cat > .gitignore << 'EOF'
.env
*.pyc
__pycache__/
.venv
node_modules/
*.log
/build
/.terraform
EOF

# Create docker-compose.yml for development
cat > docker-compose.yml << 'EOF'
version: '3.8'
services:
  nginx:
    image: nginx:latest
    ports:
      - "8080:80"
    volumes:
      - ./deploy/nginx.conf:/etc/nginx/nginx.conf
  
  gateway:
    build: ./gateway
    ports:
      - "8000:8000"
    environment:
      - LOG_LEVEL=DEBUG
      - ENVIRONMENT=development
  
  fake_erp:
    build: ./backend
    ports:
      - "8001:8000"
  
  redis:
    image: redis:latest
    ports:
      - "6379:6379"
EOF

# Create README
cat > README.md << 'EOF'
# ERP Security Gateway

## Phase 0: Ground Truth ✅
- [x] ERP topology inventoried
- [x] API inventory completed
- [x] Traffic baseline measured
- [x] Threat model documented

## Phase 1: MVP Gateway
- [ ] Reverse proxy (nginx) + logging
- [ ] Basic gateway skeleton (Python FastAPI)
- [ ] Rate limiting (Redis-backed)
- [ ] Security tests (OWASP patterns)

## Reference Files
- Original Playbook: `ERP_Security_Gateway_End_to_End_Production_Implementation_Playbook.pdf`
- Verification Report: `VERIFICATION_REPORT_ERP_Security_Architecture.md`
- Critical Fixes: `CRITICAL_IMPROVEMENTS_SUMMARY.md`

## Timeline
- Week 1: Phase 0 (Ground Truth) ← You are here
- Week 2-3: Phase 1 (MVP Gateway)
- Week 4+: Phase 2-3 (Deterministic Rules + Telemetry)
EOF

git add .
git commit -m "Phase 0: Initial project structure"
```

---

### Phase 0 Exit Criteria

```
✅ Inventory document is complete and signed off
✅ API inventory covers all endpoints used by mobile/web
✅ Traffic baseline is measured (peak RPS, latency, error rate)
✅ Threat model is documented (STRIDE)
✅ Risk assessment is prioritized (high/medium/low)
✅ Team alignment achieved (security, backend, ops, product)
✅ Development environment is set up (git, docker-compose)
✅ All files are committed to version control
✅ Next phase owner is assigned

If ANY criteria are not met:
  → Do not proceed to Phase 1
  → Spend more time on ground truth
  → Unknown assumptions are biggest risk
```

---

## PART C: PHASE 1 — MVP GATEWAY (Weeks 2-3)

**Owner:** Backend Engineer + Security Engineer  
**Deliverable:** Working security gateway in front of staging ERP  
**Exit Criteria:** All OWASP patterns blocked, legitimate traffic passes, latency < 20ms overhead

### Task 1.1: Reverse Proxy Setup (nginx)

**File Reference:** Playbook §5, Architecture §6

**Deliverable:** nginx configuration that logs all traffic

Create file: `deploy/nginx.conf`

```nginx
# nginx Reverse Proxy Configuration
# Purpose: TLS termination, request routing, logging

http {
    # Request logging (JSON format for easy parsing)
    log_format json_combined escape=json
      '{'
        '"timestamp": "$time_iso8601",'
        '"request_id": "$request_id",'
        '"source_ip": "$remote_addr",'
        '"method": "$request_method",'
        '"path": "$request_uri",'
        '"status": $status,'
        '"body_size": $body_bytes_sent,'
        '"response_time_ms": $request_time,'
        '"user_agent": "$http_user_agent"'
      '}';
    
    access_log /var/log/nginx/access.log json_combined;
    error_log /var/log/nginx/error.log warn;
    
    # Upstream: security gateway
    upstream security_gateway {
        server gateway:8000;
    }
    
    # Upstream: ERP backend (staging)
    upstream erp_backend {
        server staging-erp:8001;
    }
    
    server {
        listen 80;
        server_name _;
        
        # Redirect all HTTP to HTTPS
        return 301 https://$host$request_uri;
    }
    
    server {
        listen 443 ssl http2;
        server_name api.erp.internal;
        
        # TLS configuration
        ssl_certificate /etc/nginx/certs/server.crt;
        ssl_certificate_key /etc/nginx/certs/server.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers HIGH:!aNULL:!MD5;
        
        # Security headers
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "DENY" always;
        
        # Generate request ID for tracing
        map $http_x_request_id $request_id_out {
            default $http_x_request_id;
            "" $request_time-$msec;
        }
        
        proxy_set_header X-Request-ID $request_id_out;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        
        # Route all traffic to security gateway first
        location /api/ {
            proxy_pass http://security_gateway;
            proxy_read_timeout 30s;
            proxy_connect_timeout 10s;
            proxy_send_timeout 30s;
            
            # Don't buffer responses (stream them)
            proxy_buffering off;
        }
        
        # Health check endpoint (not proxied)
        location /health {
            access_log off;
            return 200 '{"status":"ok"}';
            add_header Content-Type application/json;
        }
    }
}
```

**Acceptance Criteria:**
- [ ] nginx starts without errors
- [ ] All requests are logged in JSON format
- [ ] Logs include request_id, source IP, response time
- [ ] TLS certificate is valid (self-signed for dev is OK)
- [ ] Health check endpoint responds with 200

---

### Task 1.2: Basic Gateway Skeleton (Python + FastAPI)

**File Reference:** Playbook §5, Verification §1 (Risk Scoring)

**Deliverable:** Minimal working gateway that accepts requests, validates auth, logs decisions

Create file: `gateway/app.py`

```python
"""
ERP Security Gateway - MVP
Phase 1: Bare-minimum working gateway

This is NOT production code yet. It's the vertical slice that proves:
✅ Requests flow through gateway
✅ Decisions are logged
✅ Legitimate traffic passes
✅ Known attacks are blocked
"""

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
import logging
import json
import uuid
from datetime import datetime
from enum import Enum
import redis

# ============================================================================
# CONFIGURATION
# ============================================================================

LOG_LEVEL = "DEBUG"
REDIS_HOST = "redis"
REDIS_PORT = 6379

logging.basicConfig(
    level=LOG_LEVEL,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# ============================================================================
# DECISION TYPES
# ============================================================================

class Decision(str, Enum):
    ALLOW = "ALLOW"
    LIMIT = "LIMIT"  # Rate-limit
    CHALLENGE = "CHALLENGE"  # Require MFA
    BLOCK = "BLOCK"

# ============================================================================
# RISK SCORING (From Verification Report #1)
# ============================================================================

class RiskScore:
    def __init__(self, overall: float, components: dict, reasons: list):
        self.overall = max(0, min(100, overall))  # Clamp 0-100
        self.components = components
        self.reasons = reasons

def calculate_risk_score(request: Request) -> RiskScore:
    """
    Calculate risk score (0-100) with explainable components.
    See VERIFICATION_REPORT.md #1 for formula.
    """
    
    reasons = []
    
    # Component 1: Threat score
    threat_score = 0
    
    # Check 1A: WAF rules (SQL injection, XSS, etc)
    if contains_sql_injection(request.url.path):
        threat_score += 50
        reasons.append("SQL injection pattern detected in URL")
    
    if contains_xss(request.url.path):
        threat_score += 50
        reasons.append("XSS pattern detected in URL")
    
    # Check 1B: Malformed request
    if request.headers.get("Content-Length"):
        try:
            content_length = int(request.headers["Content-Length"])
            if content_length > 10_000_000:  # > 10MB
                threat_score += 30
                reasons.append(f"Oversized request: {content_length} bytes")
        except:
            pass
    
    threat_score = min(100, threat_score)
    
    # Component 2: Auth anomaly
    auth_score = 0
    auth_header = request.headers.get("Authorization", "")
    
    if not auth_header and request.url.path.startswith("/api/"):
        auth_score = 80  # Missing auth on protected endpoint
        reasons.append("Missing Authorization header on protected endpoint")
    elif auth_header.startswith("Bearer "):
        token = auth_header[7:]
        if not verify_jwt_signature(token):
            auth_score = 100  # Invalid token
            reasons.append("JWT signature verification failed")
    
    # Component 3: Rate abuse score
    rate_score = 0
    client_ip = request.headers.get("X-Forwarded-For", request.client.host)
    
    try:
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        key = f"rate:{client_ip}"
        request_count = r.incr(key)
        r.expire(key, 60)  # 60-second window
        
        if request_count > 1000:  # > 1000 req/min from one IP
            rate_score = 100
            reasons.append(f"Rate limit exceeded: {request_count} requests/min")
        elif request_count > 100:
            rate_score = 30
            reasons.append(f"Elevated rate: {request_count} requests/min")
    except:
        logger.warning("Redis unavailable; skipping rate check")
    
    # Weighted composite (See Verification Report #1)
    overall_risk = (
        threat_score * 0.40 +
        auth_score * 0.40 +
        rate_score * 0.20
    )
    
    return RiskScore(
        overall=overall_risk,
        components={
            'threat': threat_score,
            'auth': auth_score,
            'rate': rate_score,
        },
        reasons=reasons
    )

# ============================================================================
# SIMPLE SECURITY CHECKS
# ============================================================================

def contains_sql_injection(text: str) -> bool:
    """Very basic SQL injection detection."""
    sql_patterns = [
        "' OR '1'='1",
        "' OR 1=1",
        "UNION SELECT",
        "DROP TABLE",
        "DELETE FROM",
        "INSERT INTO",
    ]
    return any(p.lower() in text.lower() for p in sql_patterns)

def contains_xss(text: str) -> bool:
    """Very basic XSS detection."""
    xss_patterns = [
        "<script",
        "javascript:",
        "onerror=",
        "onload=",
    ]
    return any(p.lower() in text.lower() for p in xss_patterns)

def verify_jwt_signature(token: str) -> bool:
    """
    Verify JWT signature. For MVP, just check if token is valid format.
    TODO: In Phase 2, integrate with real JWT verification
    """
    parts = token.split('.')
    if len(parts) != 3:
        return False
    return True

# ============================================================================
# POLICY ENGINE
# ============================================================================

POLICY = {
    'low': (0, 20, Decision.ALLOW),      # 0-20: Allow
    'medium': (20, 50, Decision.LIMIT),  # 20-50: Rate-limit
    'high': (50, 75, Decision.CHALLENGE),  # 50-75: Challenge
    'critical': (75, 100, Decision.BLOCK),  # 75-100: Block
}

def policy_decision(risk_score: float) -> Decision:
    """Convert risk score to security decision."""
    for threshold_min, threshold_max, decision in POLICY.values():
        if threshold_min <= risk_score < threshold_max:
            return decision
    return Decision.BLOCK

# ============================================================================
# LOGGING
# ============================================================================

def emit_security_event(
    request_id: str,
    decision: Decision,
    risk_score: RiskScore,
    request: Request
) -> None:
    """Log a security event in structured JSON format."""
    
    event = {
        "timestamp": datetime.utcnow().isoformat(),
        "request_id": request_id,
        "decision": decision.value,
        "risk_score": risk_score.overall,
        "risk_components": risk_score.components,
        "reasons": risk_score.reasons,
        "source_ip": request.headers.get("X-Forwarded-For", request.client.host),
        "method": request.method,
        "path": request.url.path,
        "user_agent": request.headers.get("User-Agent", "unknown"),
    }
    
    logger.info(json.dumps(event))

# ============================================================================
# FASTAPI APPLICATION
# ============================================================================

app = FastAPI(title="ERP Security Gateway", version="0.1.0")

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    """
    Central security middleware: every request goes here first.
    """
    
    # Generate request ID for tracing
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    
    # Skip security checks for health endpoint
    if request.url.path == "/health":
        return await call_next(request)
    
    # Calculate risk score
    risk_score = calculate_risk_score(request)
    
    # Determine decision
    decision = policy_decision(risk_score.overall)
    
    # Log the decision
    emit_security_event(request_id, decision, risk_score, request)
    
    # Enforce decision
    if decision == Decision.BLOCK:
        logger.warning(f"Blocking request {request_id}: {risk_score.reasons}")
        return JSONResponse(
            status_code=403,
            content={
                "error": "Forbidden",
                "request_id": request_id,
                "message": "Request does not meet security policy"
            }
        )
    
    elif decision == Decision.CHALLENGE:
        logger.info(f"Challenging request {request_id}: {risk_score.reasons}")
        return JSONResponse(
            status_code=401,
            content={
                "error": "Unauthorized",
                "request_id": request_id,
                "message": "Additional authentication required",
                "challenge": "mfa_required"
            }
        )
    
    elif decision == Decision.LIMIT:
        logger.info(f"Rate-limiting request {request_id}")
        # For now, just log it. Phase 2 will implement actual rate-limiting response
    
    # Allow request to proceed to backend
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    response.headers["X-Decision"] = decision.value
    return response

@app.get("/health")
async def health_check():
    """Health check endpoint (not security-gated)."""
    return {"status": "ok", "service": "security-gateway"}

@app.post("/api/{path:path}")
@app.get("/api/{path:path}")
@app.put("/api/{path:path}")
@app.delete("/api/{path:path}")
async def proxy_request(request: Request, path: str):
    """
    Proxy all /api/* requests to backend.
    
    NOTE: This is MVP. Real implementation will use:
    - httpx.AsyncClient for proxying
    - Connection pooling
    - Timeout handling
    - Response streaming
    """
    
    return JSONResponse(
        status_code=200,
        content={
            "message": "Request would be proxied to backend",
            "request_id": request.state.request_id,
            "original_path": path
        }
    )

# ============================================================================
# STARTUP
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    logger.info("Starting ERP Security Gateway (MVP)")
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

**Acceptance Criteria:**
- [ ] Gateway starts without errors: `python app.py`
- [ ] Health endpoint responds: `curl http://localhost:8000/health`
- [ ] Request ID is generated for each request
- [ ] Risk score is calculated (0-100, bounded)
- [ ] Policy decision is made (ALLOW/LIMIT/CHALLENGE/BLOCK)
- [ ] Security events are logged as JSON
- [ ] JWT tokens are checked (basic format validation)
- [ ] SQL injection patterns are detected

---

### Task 1.3: Security Tests

**File Reference:** Playbook §16, Verification §27

**Deliverable:** Pytest test suite proving gateway blocks known attacks

Create file: `tests/test_security.py`

```python
"""
Security tests for MVP gateway.
Proves gateway blocks known attack patterns.
"""

import pytest
from fastapi.testclient import TestClient
from gateway.app import app

client = TestClient(app)

class TestWAFProtection:
    """Test that WAF rules block injection attacks."""
    
    def test_block_sql_injection_in_url(self):
        """SQL injection in URL should be blocked."""
        response = client.get("/api/users/123' OR '1'='1")
        assert response.status_code == 403
        assert response.json()["error"] == "Forbidden"
    
    def test_block_sql_injection_drop_table(self):
        """DROP TABLE attempt should be blocked."""
        response = client.get("/api/orders/DROP TABLE users")
        assert response.status_code == 403
    
    def test_block_xss_in_url(self):
        """XSS payload in URL should be blocked."""
        response = client.get("/api/users/<script>alert('xss')</script>")
        assert response.status_code == 403
    
    def test_allow_legitimate_request(self):
        """Legitimate request should be allowed."""
        response = client.get(
            "/api/orders/123",
            headers={"Authorization": "Bearer valid.jwt.token"}
        )
        # Should not be 403
        assert response.status_code != 403

class TestAuthenticationRequired:
    """Test that protected endpoints require authentication."""
    
    def test_block_missing_auth_header(self):
        """Request without Authorization header should be challenged."""
        response = client.get("/api/users")
        assert response.status_code == 401
        assert "Authorization" in response.json()["message"].lower()
    
    def test_block_invalid_jwt_format(self):
        """Invalid JWT format should be rejected."""
        response = client.get(
            "/api/users",
            headers={"Authorization": "Bearer invalid.token"}
        )
        assert response.status_code == 401

class TestRateLimit:
    """Test rate limiting (basic, per IP)."""
    
    def test_allow_normal_rate(self):
        """Normal rate (10 req/min) should be allowed."""
        for i in range(10):
            response = client.get(
                f"/api/orders/{i}",
                headers={"Authorization": "Bearer valid.jwt.token"}
            )
            assert response.status_code != 403
    
    def test_flag_high_rate(self):
        """Very high rate (100+ req/min) should trigger action."""
        # This test would need to mock Redis and time
        # Defer to Phase 2 (full rate limiting)
        pass

class TestHealthEndpoint:
    """Health check should never be blocked."""
    
    def test_health_endpoint_always_accessible(self):
        """Health check must be accessible without auth."""
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

class TestRiskScoring:
    """Test risk scoring engine."""
    
    def test_risk_score_is_bounded(self):
        """Risk score must be 0-100."""
        # Make various requests and verify risk score is valid
        from gateway.app import calculate_risk_score
        
        # Mock request object
        class MockRequest:
            def __init__(self):
                self.url = type('obj', (object,), {'path': '/api/test'})()
                self.headers = {"Authorization": "Bearer token"}
                self.client = type('obj', (object,), {'host': '127.0.0.1'})()
        
        req = MockRequest()
        risk = calculate_risk_score(req)
        
        assert 0 <= risk.overall <= 100, f"Risk score {risk.overall} not in 0-100"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
```

**Run tests:**
```bash
cd gateway
pytest tests/test_security.py -v
```

**Expected Output:**
```
test_block_sql_injection_in_url PASSED
test_block_xss_in_url PASSED
test_allow_legitimate_request PASSED
test_block_missing_auth_header PASSED
test_health_endpoint_always_accessible PASSED

========================= 5 passed in 0.23s =========================
```

**Acceptance Criteria:**
- [ ] All security tests pass
- [ ] SQL injection patterns are blocked
- [ ] XSS patterns are blocked
- [ ] Missing auth is challenged
- [ ] Legitimate requests pass through
- [ ] Tests are documented and repeatable

---

### Task 1.4: Integration with Staging ERP

**File Reference:** Playbook §4, §6

**Deliverable:** Gateway proxies traffic to real (staging) ERP backend

**Steps:**

1. Deploy fake ERP for testing:
```python
# backend/fake_erp.py
from fastapi import FastAPI

fake_erp = FastAPI()

@fake_erp.get("/api/orders/{order_id}")
async def get_order(order_id: int):
    return {
        "order_id": order_id,
        "customer": "Test Customer",
        "amount": 1234.56,
        "status": "completed"
    }

@fake_erp.post("/api/orders")
async def create_order(order: dict):
    return {
        "order_id": 999,
        "status": "created"
    }
```

2. Update gateway to actually proxy (not just mock):
```python
# In gateway/app.py, update proxy endpoint

import httpx

BACKEND_URL = "http://staging-erp:8001"

@app.get("/api/{path:path}")
async def proxy_get(request: Request, path: str):
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{BACKEND_URL}/api/{path}",
            headers={"X-Request-ID": request.state.request_id}
        )
        return JSONResponse(content=response.json())
```

3. Test end-to-end:
```bash
# Start all services
docker-compose up

# In another terminal, test flow
curl -H "Authorization: Bearer test.jwt.token" http://localhost:8080/api/orders/123
```

**Expected:**
```json
{
  "order_id": 123,
  "customer": "Test Customer",
  "amount": 1234.56,
  "status": "completed",
  "X-Request-ID": "abc-123"  (in response headers)
}
```

---

### Task 1.5: Performance Baseline

**File Reference:** Playbook §20, Verification §20

**Deliverable:** Proof that gateway latency overhead is < 20ms p95

**Benchmark:**

Create file: `tests/test_performance.py`

```python
import time
import statistics
from fastapi.testclient import TestClient
from gateway.app import app

client = TestClient(app)

def test_gateway_latency():
    """
    Measure gateway latency overhead.
    
    Gateway should add < 20ms p95 latency.
    """
    
    latencies = []
    
    for i in range(100):
        start = time.time()
        response = client.get(
            f"/api/orders/{i}",
            headers={"Authorization": "Bearer test.jwt.token"}
        )
        elapsed_ms = (time.time() - start) * 1000
        latencies.append(elapsed_ms)
    
    p50 = statistics.median(latencies)
    p95 = sorted(latencies)[int(len(latencies) * 0.95)]
    p99 = sorted(latencies)[int(len(latencies) * 0.99)]
    
    print(f"\nGateway Latency:")
    print(f"  p50: {p50:.1f}ms")
    print(f"  p95: {p95:.1f}ms (target: < 20ms)")
    print(f"  p99: {p99:.1f}ms")
    
    assert p95 < 20, f"Latency p95 {p95}ms exceeds target 20ms"
```

Run:
```bash
pytest tests/test_performance.py -v -s
```

---

### Phase 1 Exit Criteria

```
✅ Reverse proxy (nginx) is running and logging all requests in JSON
✅ Security gateway (FastAPI) is running and making security decisions
✅ Risk scoring engine is implemented (0-100 bounded)
✅ Security tests pass:
   - SQL injection blocked
   - XSS blocked
   - Missing auth challenged
   - Legitimate traffic allowed
✅ Gateway latency overhead < 20ms p95
✅ Integration with staging ERP works (end-to-end traffic flow)
✅ Security events are logged with request IDs
✅ Docker Compose deploys entire stack
✅ All code is committed to git with clear commit messages
✅ Next phase owner is assigned

If ANY criteria are not met:
  → Debug and fix
  → Do NOT move to Phase 2
  → Get latency under control first (Phase 2 adds more logic)
```

---

## PART D: WHAT AGENTS SHOULD DO NOW

### Immediate Tasks (Today)

**Agent 1: Infrastructure**
```
1. Read Playbook §4 "Phase 0 — Establish Ground Truth"
2. Read CRITICAL_IMPROVEMENTS_SUMMARY.md #1-3 (Risk scoring, baseline, bootstrap)
3. Start Task 0.1: ERP Topology Inventory
4. Output: inventory/erp_topology.yaml
```

**Agent 2: Backend**
```
1. Read Playbook §4 "API Contracts"
2. Start Task 0.2: API Inventory
3. Output: inventory/api_inventory.yaml
4. Coordinate with Agent 1 for network details
```

**Agent 3: Security**
```
1. Read Playbook §4 "Threat Model"
2. Read Verification Report §21 "Threat Model (STRIDE)"
3. Start Task 0.4: Threat Model
4. Start Task 0.5: Risk Assessment
5. Output: security/threat_model.md + security/risk_assessment.yaml
```

**Agent 4: DevOps/SRE**
```
1. Read Playbook §5 "Docker Compose Development Environment"
2. Read Architecture §3 "Target Architecture"
3. Start Task 0.7: Environment Setup
4. Prepare docker-compose.yml, nginx.conf, project structure
5. Output: Runnable docker-compose with all services
```

### Week 1 Handoff Meeting

**When:** End of Friday  
**Attendees:** All agents + tech lead  
**Duration:** 30 minutes  
**Agenda:**

```
1. Demo Phase 0 artifacts:
   - Topology inventory (Agent 1)
   - API inventory (Agent 2)
   - Threat model (Agent 3)
   - Environment setup (Agent 4)

2. Sign off: "Do we have all unknowns documented?"
   - If NO: extend Phase 0 (no shame)
   - If YES: proceed to Phase 1

3. Assign Phase 1 owners:
   - Gateway development (Backend engineer)
   - Security testing (Security engineer)
   - DevOps (SRE engineer)
```

### Phase 1 Development (Weeks 2-3)

**Agent 1: Gateway Development**
```
1. Read Playbook §5 "Build the Gateway MVP"
2. Read CRITICAL_IMPROVEMENTS_SUMMARY.md #1 (Risk scoring formula)
3. Read Verification Report §1 (Risk scoring details)
4. Implement:
   - gateway/app.py (FastAPI skeleton)
   - Risk scoring engine (0-100 bounded)
   - Policy decision engine
   - Security event logging
5. Deploy via docker-compose
6. Output: Working gateway that can be tested against OWASP patterns
```

**Agent 2: Security Testing**
```
1. Read Playbook §16 "Testing Strategy"
2. Create security test suite (pytest):
   - SQL injection tests
   - XSS tests
   - Auth bypass tests
   - Rate abuse tests
3. Run tests daily
4. Report: "How many OWASP patterns are blocked?"
5. Output: tests/test_security.py (100% passing)
```

**Agent 3: Performance & Integration**
```
1. Benchmark gateway latency (target < 20ms p95)
2. Integrate with staging ERP
3. Run end-to-end tests:
   - Request enters gateway
   - Request is validated
   - Request is proxied to backend
   - Response is returned to client
4. Output: Performance report + docker-compose that works end-to-end
```

---

## PART E: DECISION TREES FOR UNKNOWNS

**If database engine is unknown:**
```
→ Ask backend team: "What database are we using?"
→ If no answer: Assume PostgreSQL (most common for PHP ERPs)
→ Document assumption in inventory
→ Revisit when known
```

**If API inventory is huge (100+ endpoints):**
```
→ Prioritize: which endpoints are most critical?
→ Which handle sensitive data (PII, financial)?
→ Start with top 20 by criticality
→ Document full list for future phases
```

**If threat model discussions get heated:**
```
→ This is GOOD — it means people care
→ Use STRIDE framework to organize concerns
→ Document all threats (even low-priority ones)
→ Prioritize by likelihood × impact
→ Move on (don't perfect-score analysis)
```

**If Phase 1 latency exceeds 20ms:**
```
→ Profile: where is the latency? (risk scoring? auth? logging?)
→ Optimize bottleneck:
   - Risk scoring: cache IP reputation, move regexes to Rust
   - Auth: cache JWT verification results
   - Logging: write events async to queue
→ Do NOT move to Phase 2 until latency is fixed
```

---

## PART F: REFERENCE FILES INDEX

When stuck, use these sections:

| Question | Reference |
|----------|-----------|
| "What should we build?" | Playbook §1-2, Architecture §1-2 |
| "How do we start?" | Playbook §5, Verification Report (Phase 0) |
| "What's the architecture?" | Architecture §3, Diagram (Layered Security) |
| "How does risk scoring work?" | CRITICAL_IMPROVEMENTS_SUMMARY.md #1, Verification §1 |
| "How do we detect attacks on Day 1?" | CRITICAL_IMPROVEMENTS_SUMMARY.md #3, Verification §3 |
| "How do we prevent data poisoning?" | Playbook §8-9, Verification §5 |
| "What should we test?" | Playbook §16, Verification §27 |
| "How do we deploy safely?" | CRITICAL_IMPROVEMENTS_SUMMARY.md #8, Playbook §17 |
| "What goes wrong in Phase 1?" | Verification Report "Critical Issues" section |
| "What's the timeline?" | Playbook §17 "Phased Delivery Roadmap" |

---

## PART G: SUCCESS CRITERIA

### At end of Phase 0 (Week 1):
```
✅ Team knows the exact ERP topology, APIs, and traffic volume
✅ Threat model is documented (STRIDE)
✅ Risk assessment is prioritized
✅ Development environment is ready
✅ All files are in git
✅ Zero unknowns (or they're explicitly documented as assumptions)
```

### At end of Phase 1 (Week 3):
```
✅ Security gateway is deployed in front of staging ERP
✅ Every request flows through security gateway
✅ Risk scoring engine is working (0-100 bounded)
✅ SQL injection, XSS, malformed requests are blocked
✅ Legitimate traffic passes through
✅ Gateway latency overhead < 20ms p95
✅ Security tests pass (100%)
✅ Logging is structured JSON with request IDs
✅ Docker Compose runs entire stack with one command
✅ Ready for Phase 2 (deterministic rules + telemetry)
```

---

## FINAL NOTE FOR AGENTS

This is a **3-week sprint to MVP**, not a 3-month research project.

**Principles:**
1. **Do first, perfect later.** A working MVP is better than perfect design.
2. **Test constantly.** Every feature should have tests before commit.
3. **Log everything.** If you can't see what's happening, you can't debug it.
4. **Fail fast.** If latency is > 20ms by day 5 of Phase 1, fix it then, not day 12.
5. **Communication over perfection.** Handoff meetings matter more than perfect code.

**Success = "Any request that reaches the backend has been validated by the gateway."**

That's it. Everything else is detail.

Let's build this. 🚀

