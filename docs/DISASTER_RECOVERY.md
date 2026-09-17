# ERP Security Gateway: High Availability & Disaster Recovery Plan

**Document Version:** 2.0.0  
**Target SLAs:** RTO < 60 seconds | RPO < 5 seconds | Availability 99.95%  
**Compliance Mandate:** SOC 2 Type II (CC7.3 / CC9.1), ISO 27001 (A.8.14), SOX 404

---

## 1. High Availability Architecture & Resilience Strategy

The ERP Security Gateway is designed as a stateless, horizontally autoscaling layer situated between external ingress and the backend ERP microservices.

```
       [ Regional DNS / Geo-IP Anycast ]
                      |
        +-------------+-------------+
        |                           |
  [ Region Alpha ]            [ Region Bravo (Hot Standby) ]
   - 3x Gateway Replicas       - 3x Gateway Replicas
   - Shared Redis Cluster      - Replicated Redis Cluster
   - Core ERP Services         - Core ERP Standby
```

### Subsystem Resilience Summary
| Subsystem | Failure Mode | Resilience / Fallback Mechanism |
| :--- | :--- | :--- |
| **Upstream ERP Core** | Latency spike, HTTP 500 crashes | Circuit Breaker trips to `OPEN`; immediately returns HTTP 503 with `Retry-After: 10`. Prevents thundering herd. |
| **Redis Cache** | Network partition, node failure | Graceful fallback to thread-safe in-memory sliding window rate limiting. Gateway remains 100% operational. |
| **ML Model Service** | Memory corruption, NaN output | Fallback to deterministic baseline engine; instant operator rollback via `/api/ml/rollback`. |
| **Canary Deployment** | Error rate > 2%, p95 > 50ms | Automated SLO circuit breaker reverts 100% of traffic to stable upstream. |
| **Audit Log Disk** | High I/O, disk full | Cryptographic HMAC-SHA256 block chain buffers in memory before atomic flush. |

---

## 2. Circuit Breaker Operational Runbook

The Gateway features an automated, thread-safe Circuit Breaker protecting backend ERP applications from cascading failure.

### Circuit Breaker States
1. **CLOSED (Normal):** All legitimate requests are forwarded upstream.
2. **OPEN (Isolated):** 5 consecutive upstream failures trip breaker to `OPEN`. Upstream requests are immediately blocked with HTTP 503.
3. **HALF_OPEN (Testing):** After 10.0 seconds cooldown, gateway admits trial requests. 2 consecutive successes transition state back to `CLOSED`.

### Manual Circuit Breaker Diagnostics & Reset
```bash
# Check status
curl http://localhost:8000/api/ha/status

# Example Output:
# {
#   "circuit_breaker": {
#     "state": "CLOSED",
#     "consecutive_failures": 0,
#     "cooldown_period_seconds": 10.0,
#     "last_failure_reason": null
#   }
# }
```

---

## 3. Disaster Recovery Procedures

### Scenario A: Full Upstream ERP Outage
**Symptoms:** Gateway returns 502 Bad Gateway or 503 Service Unavailable with `circuit_breaker.state = OPEN`.
1. **Verify Gateway Status:**
   ```bash
   curl http://localhost:8000/health/ready
   ```
2. **Isolate Problem:** Determine if backend ERP database or container cluster is down.
3. **Traffic Shedding:** Gateway automatically shields the ERP backend from being overwhelmed during recovery.
4. **Recovery Verification:** Once upstream returns 200 OK, the gateway automatically self-heals through the `HALF_OPEN` state.

---

### Scenario B: Audit Log Tampering or Disk Corruption
**Symptoms:** `/api/compliance/verify-chain` returns `chain_intact: false`.
1. **Execute Forensic Chain Audit:**
   ```bash
   python -c "
   from gateway.compliance import tamper_evident_audit_chain
   valid, blocks, err = tamper_evident_audit_chain.verify_chain()
   print(f'Valid: {valid}, Blocks: {blocks}, Error: {err}')
   "
   ```
2. **Investigate Block Index:** The error output pinpoints the exact line number, block ID, and calculated vs recorded HMAC hash.
3. **Isolate Server Node:** Remove compromised node from load balancer pool and snapshot disk for forensic investigation.
4. **Restore Audit Trail:** Restore audit chain from append-only write-once-read-many (WORM) cloud storage (e.g. AWS S3 Object Lock).

---

### Scenario C: Cold Start Gateway Disaster Recovery (< 60 Seconds)
In the event of total datacenter loss:
1. **Spin up Gateway Pods:** Deploy via Helm or Docker Compose.
2. **Run Production Readiness Certification:**
   ```bash
   python scripts/verify_production_readiness.py
   ```
   *Must report 12/12 phases passed (100.0%).*
3. **Initiate Canary Traffic at 1%:**
   ```bash
   curl -X POST http://localhost:8000/api/canary/promote -H "Content-Type: application/json" -d '{"stage": "CANARY_1%"}'
   ```
4. **Progress to 100%:** Promote through 10% -> 50% -> 100% over standard deployment intervals.
