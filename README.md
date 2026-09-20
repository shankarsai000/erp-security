# ERP Security Gateway: Enterprise Defense Platform

[![CI / CD Test Suite](https://img.shields.io/badge/Tests-193%20Passed-brightgreen)](https://github.com/shankarsai000/erp-security)
[![Certification](https://img.shields.io/badge/Production%20Certification-12%2F12%20Phases%20(100%25)-blue)](file:///reports/production_readiness_scorecard.json)
[![Compliance](https://img.shields.io/badge/Compliance-SOC%202%20%7C%20ISO%2027001%20%7C%20GDPR%20%7C%20SOX-purple)](file:///docs/PRODUCTION_RUNBOOK.md)
[![Performance SLA](https://img.shields.io/badge/Socket%20p95%20Latency-72.5ms%20(%3C%2080ms%20SLA)-success)](file:///reports/socket_benchmark_report.json)

> 📘 **New to the project or non-technical?** Read our **[End-to-End Plain English Guide](file:///d:/ERP%20security/END_TO_END_EXPLAINER.md)** explaining all 9 checkpoints, or run `python scripts/demo_end_to_end.py` to watch live attacks get blocked in your terminal in 3 seconds!

A zero-trust, low-latency API security gateway designed specifically for enterprise ERP environments (SAP, Oracle NetSuite, Dynamics 365, custom systems). Combines deterministic defense-in-depth, zero-PII cryptographic telemetry, statistical baselining, advisory machine learning, autonomous security agents with human approval gates, real-time automated mitigations, and tamper-evident audit logging.

---

## Complete 12-Phase Architecture & Implementation Status

| Phase | Component / Capability | Status | Core File Artifacts |
| :---: | :--- | :---: | :--- |
| **0** | Threat Model, Risk Assessment & Requirements | **COMPLETE** | `security/risk_assessment.yaml`, `security/requirements.yaml` |
| **1** | Core Gateway MVP, Deterministic WAF, Rate Limiter | **COMPLETE** | `gateway/app.py`, `gateway/waf.py`, `gateway/rate_limiter.py` |
| **2** | Route Allowlist, Pydantic v2 Schemas, Replay Guard | **COMPLETE** | `gateway/route_allowlist.py`, `gateway/schemas.py`, `gateway/replay_guard.py` |
| **3** | Zero-PII Telemetry Pipeline & Cryptographic Redaction | **COMPLETE** | `gateway/telemetry/redaction.py`, `gateway/telemetry/event_pipeline.py` |
| **4** | ERP Business Logic Rules Engine (R001–R006) & Hot Reload | **COMPLETE** | `gateway/rules_engine.py`, `config/rules.yaml` |
| **5** | Baseline Statistics Engine & 3-Tier Anti-Poisoning | **COMPLETE** | `gateway/baselines/baseline_engine.py`, `gateway/telemetry/anti_poisoning.py` |
| **6** | Advisory Machine Learning (Isolation Forest) & SLA Guard | **COMPLETE** | `ml/model_service.py`, `ml/feature_engineering.py`, `ml/train_models.py` |
| **7** | Specialized Security Multi-Agents & Human Approval Gates | **COMPLETE** | `agents/orchestrator.py`, `agents/detection_agent.py`, `agents/response_agent.py` |
| **8** | Automated Mitigation Engine & Sub-ms Active Enforcement | **COMPLETE** | `gateway/mitigation_engine.py`, `tests/test_phase8_automated_response.py` |
| **9** | SOC Continuous Feedback, Concept Drift & Auto-Retraining | **COMPLETE** | `gateway/soc_feedback.py`, `ml/retraining_pipeline.py`, `gateway/security_metrics.py` |
| **10** | High Availability Circuit Breaker & Tamper-Evident Auditing | **COMPLETE** | `gateway/ha_dr.py`, `gateway/compliance.py`, `tests/test_phase10_hardening_compliance.py` |
| **11** | Production Canary Traffic Router & Enterprise Runbooks | **COMPLETE** | `gateway/canary_router.py`, `scripts/verify_production_readiness.py`, `docs/` |

---

## Architectural Workflow

```mermaid
flowchart TD
    A[Client Request] --> B[WAF & Input Sanitization]
    B --> C[Route Catalog & Schema Validation]
    C --> D[Credential Abuse Velocity & Replay Guard]
    D --> E[Active Mitigation Engine: O(1) Pre-Routing Drop]
    E --> F[Business Logic Rules Engine: R001-R006]
    F --> G[Baseline Statistical Anomaly Profiler]
    G --> H[Advisory ML Isolation Forest]
    H --> I[Bounded Risk Scoring Engine: 0-100]
    I --> J{Risk Decision}
    J -->|Block / Challenge| K[Instant Threat Mitigation & Alert]
    J -->|Allow| L[HA Circuit Breaker & Deep Health Probe]
    L --> M[Canary Deployment Router: 1% -> 10% -> 50% -> 100%]
    M --> N[Upstream Core ERP Service]
    
    K -.-> O[Autonomous Security Multi-Agents]
    O -.->|Human Approval Gate| P[Permanent Containment / Account Suspension]
    A -.-> Q[Zero-PII Cryptographic Telemetry]
    A -.-> R[HMAC-SHA256 Tamper-Evident Audit Block Chain]
```

---

## Quick Start & Verification

### 1. Requirements & Setup
```bash
# Python 3.10+ required
pip install -r requirements.txt
```

### 2. Run Interactive 8-Scenario Security Demonstration
```bash
python scripts/demo_end_to_end.py
```

### 3. Run the Full Automated Test Suite (193 Tests)
```bash
python -m pytest tests -q
```

### 4. Run Production Readiness Certification (12/12 Phases)
```bash
python scripts/verify_production_readiness.py
```
*Output: 12/12 Phases Passed (100.0%) - Certified for Enterprise Production Deployment.*

### 5. Run Live Multi-Threaded TCP Socket Benchmark
```bash
python benchmarks/socket_benchmark.py
```
*Output: 40/40 passed (100% success rate), p50: ~53ms, p95: ~72ms (< 80ms SLA).*

---

## Key API Endpoints Reference

| Endpoint | Method | Purpose |
| :--- | :---: | :--- |
| `/health/live` | `GET` | Kubernetes liveness probe |
| `/health/ready` | `GET` | Deep subsystem readiness probe (rules, ML, rate limiter, mitigations) |
| `/api/canary/status` | `GET` | Canary traffic stage, routing weights, p95 latency & error telemetry |
| `/api/canary/promote` | `POST` | Progressive canary promotion (`CANARY_1%`, `CANARY_10%`, `CANARY_50%`, `100%`) |
| `/api/canary/rollback` | `POST` | Emergency manual canary traffic cutoff to 0% (< 5s SLA) |
| `/api/ha/status` | `GET` | Circuit breaker state (`CLOSED`, `OPEN`, `HALF_OPEN`) and failure history |
| `/api/compliance/verify-chain` | `POST` | Cryptographic HMAC-SHA256 audit log integrity verification |
| `/api/compliance/report` | `GET` | Export compliance package (SOC 2 Type II, ISO 27001, GDPR Art 32, SOX 404) |
| `/api/agents/status` | `GET` | Status of autonomous security agents (Detection, Intel, Investigation, Response) |
| `/api/agents/actions/pending` | `GET` | High-impact actions awaiting human security analyst authorization |
| `/api/agents/actions/{id}/approve` | `POST` | Human Analyst approval gate for account suspension |
| `/api/soc/feedback` | `POST` | Analyst label feedback loop (`CONFIRMED_ATTACK`, `FALSE_POSITIVE`, `TUNING_REQUEST`) |
| `/api/metrics/security` | `GET` | Real-time MTTD, MTTR, traffic breakdown, and containment KPIs |

---

## Documentation & Runbooks

- **[Production Operations Runbook](file:///docs/PRODUCTION_RUNBOOK.md)**: Deployment playbooks, zero-downtime upgrades, monitoring alerts, and incident escalation.
- **[Disaster Recovery Plan](file:///docs/DISASTER_RECOVERY.md)**: Multi-region failover, circuit breaker recovery, database/audit log sync, and cold start restore.
- **[Verification Report](file:///VERIFICATION_REPORT_ERP_Security_Architecture.md)**: Architectural benchmarks, test evidence, and latency measurements.