# ERP Security Gateway: Enterprise Production Operations Runbook

**Document Revision:** 2.0.0 (Post Phase 11 Final Certification)  
**Target Audience:** Site Reliability Engineers (SRE), Security Operations Center (SOC), DevSecOps  
**Scope:** Production deployments, zero-downtime canary rollouts, incident playbooks, and disaster recovery.

---

## 1. System Architecture Overview

The ERP Security Gateway operates as a low-latency (p95 < 50ms budget), high-availability proxy safeguarding ERP core services against OWASP API Top 10, advanced business logic manipulation, and insider threats.

```mermaid
graph TD
    Client[Enterprise ERP Clients / Web / Mobile] -->|HTTPS 443| LB[Application Load Balancer / Ingress]
    LB -->|Port 8000| Gateway[ERP Security Gateway (FastAPI / Uvicorn)]
    
    subgraph Gateway Pipeline
        WAF[Deterministic WAF & Route Allowlist]
        RateLimit[Rate Limiter & Credential Defense]
        Rules[Phase 4: Business Logic Rules R001-R006]
        Baselines[Phase 5: Baseline Statistics Engine]
        ML[Phase 6: Advisory Isolation Forest ML]
        Agents[Phase 7: Autonomous Security Multi-Agents]
        Mitigation[Phase 8: Active Mitigation Engine]
        Canary[Phase 11: Canary Traffic Router]
    end
    
    Gateway --> WAF --> RateLimit --> Rules --> Baselines --> ML --> Agents --> Mitigation --> Canary
    Canary -->|Stable 90-99%| ERP_Stable[Core ERP Upstream (Production)]
    Canary -->|Canary 1-10%| ERP_Canary[Core ERP Upstream (Canary)]
    
    Gateway -.->|HMAC-SHA256 Chained| AuditTrail[Tamper-Evident Audit Chain]
    Gateway -.->|Zero-PII Redacted| TelemetryBus[Async Telemetry JSONL Pipeline]
```

---

## 2. Health, Liveness & Deep Readiness Probes

### Kubernetes Probe Configuration
```yaml
livenessProbe:
  httpGet:
    path: /health/live
    port: 8000
  initialDelaySeconds: 5
  periodSeconds: 10
  timeoutSeconds: 2
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /health/ready
    port: 8000
  initialDelaySeconds: 10
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 2
```

### Readiness Evaluation Components
The `/health/ready` probe verifies:
1. **Rules Engine:** Confirms minimum 6 deterministic business logic rules loaded into memory.
2. **ML Model Service:** Verifies Isolation Forest serialization and inference capability.
3. **Mitigation Engine:** Confirms in-memory hash sets for IP quarantine and session revocation are clean and accessible.
4. **Rate Limiter:** Validates memory or Redis backend connectivity.

---

## 3. Canary Deployment & Progressive Rollout Procedure

The Gateway implements continuous canary routing with automated SLO circuit-breaking.

### Progression Timeline
1. **Stage 1: Internal Shadowing (1%)**
   ```bash
   curl -X POST http://localhost:8000/api/canary/promote \
     -H "Content-Type: application/json" \
     -d '{"stage": "CANARY_1%"}'
   ```
   - **Bake Time:** 30 minutes
   - **Target Traffic:** Internal synthetic monitoring, automated health checkers.

2. **Stage 2: Pilot Canary (10%)**
   ```bash
   curl -X POST http://localhost:8000/api/canary/promote \
     -H "Content-Type: application/json" \
     -d '{"stage": "CANARY_10%"}'
   ```
   - **Bake Time:** 2 hours
   - **Verification:** Monitor `/api/canary/status` error rate < 0.1% and p95 latency < 50ms.

3. **Stage 3: Broad Production (50%)**
   ```bash
   curl -X POST http://localhost:8000/api/canary/promote \
     -H "Content-Type: application/json" \
     -d '{"stage": "CANARY_50%"}'
   ```
   - **Bake Time:** 4 hours

4. **Stage 4: Full Production Rollout (100%)**
   ```bash
   curl -X POST http://localhost:8000/api/canary/promote \
     -H "Content-Type: application/json" \
     -d '{"stage": "100%"}'
   ```

### Emergency Canary Rollback (< 5 Seconds SLA)
If error rate > 2% or p95 latency > 50ms, the router triggers an automatic rollback.
For manual operator override:
```bash
curl -X POST http://localhost:8000/api/canary/rollback \
  -H "Content-Type: application/json" \
  -d '{"reason": "Operator observed memory leak in canary upstream"}'
```

---

## 4. Incident Response & Escalation Matrix

| Severity | Definition | Target MTTD | Target MTTR | Escalation Path |
| :--- | :--- | :--- | :--- | :--- |
| **P1 - Critical** | Gateway outage, upstream ERP unreachable, or active credential stuffing campaign. | < 5.0s | < 30.0s | PagerDuty: On-Call Security Lead + Primary SRE |
| **P2 - High** | Business logic rule triggering at >10% of transaction volume (potential attack or rule drift). | < 30.0s | < 5.0m | Slack `#soc-alerts` + SRE on-call |
| **P3 - Moderate** | Single account credential lockout, off-hours anomaly alert, or ML concept drift detected. | < 2.0m | < 1.0h | SOC Ticket Queue |

---

## 5. Security Operations Center (SOC) Operational Workflows

### 5.1 Human Approval Gate for Account Suspension
High-impact containment actions (e.g. permanent account suspension) require explicit analyst approval:
1. Review pending actions:
   ```bash
   curl http://localhost:8000/api/agents/actions/pending
   ```
2. Approve action:
   ```bash
   curl -X POST http://localhost:8000/api/agents/actions/{action_id}/approve \
     -d "analyst_id=sec_analyst_jane"
   ```
3. Instant revocation / rollback:
   ```bash
   curl -X POST http://localhost:8000/api/agents/actions/{action_id}/revoke \
     -d "analyst_id=sec_analyst_jane"
   ```

### 5.2 SOC Feedback & Model Tuning
When an analyst identifies a false positive:
```bash
curl -X POST http://localhost:8000/api/soc/feedback \
  -H "Content-Type: application/json" \
  -d '{
    "request_id": "req-12345",
    "analyst_id": "sec_analyst_jane",
    "feedback_tag": "FALSE_POSITIVE",
    "notes": "Verified partner order during scheduled load test",
    "rule_id": "R001"
  }'
```

---

## 6. Cryptographic Compliance & Audit Trail Verification

The audit engine maintains an immutable block chain using HMAC-SHA256 (RFC 6962 / SOC 2 Type II non-repudiation).

### Verification Command
To ensure zero unauthorized file modification or log deletion:
```bash
curl -X POST http://localhost:8000/api/compliance/verify-chain
```
**Expected Response:**
```json
{
  "chain_intact": true,
  "verified_blocks": 1542,
  "integrity_error": null
}
```

### Compliance Export
To download the auditor package:
```bash
curl http://localhost:8000/api/compliance/report > /var/reports/compliance_soc2_iso27001.json
```
