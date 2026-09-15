# ERP SECURITY GATEWAY — QUICK REFERENCE CARD
**Print this. Post on wall. Follow it.**

---

## 🎯 THE MISSION
Build a security gateway in front of an existing PHP/SQL ERP with Android client.  
**Success:** Every API request is validated before reaching backend.

---

## 📅 TIMELINE: 3 WEEKS TO MVP
```
Week 1: PHASE 0 — Ground Truth (Inventory, topology, APIs, threats)
Week 2-3: PHASE 1 — MVP Gateway (Reverse proxy, security engine, tests)
Week 4+: PHASE 2+ (Deterministic rules, telemetry, ML baseline)
```

---

## 📋 PHASE 0 CHECKLIST (Week 1)

| Task | Owner | Output | Status |
|------|-------|--------|--------|
| **0.1** ERP Topology | Infra Engineer | `inventory/erp_topology.yaml` | [ ] |
| **0.2** API Inventory | Backend Engineer | `inventory/api_inventory.yaml` | [ ] |
| **0.3** Traffic Baseline | DevOps | `measurements/traffic_baseline.yaml` | [ ] |
| **0.4** Threat Model (STRIDE) | Security Engineer | `security/threat_model.md` | [ ] |
| **0.5** Risk Assessment | Security Engineer | `security/risk_assessment.yaml` | [ ] |
| **0.6** Team Alignment | Tech Lead | `security/requirements.yaml` (signed) | [ ] |
| **0.7** Dev Environment | DevOps | `docker-compose.yml` + `git init` | [ ] |

**PHASE 0 SUCCESS:** All items checked. Zero unknowns. Code in git.

---

## 🏗️ PHASE 1 CHECKLIST (Weeks 2-3)

| Task | Owner | Output | Status |
|------|-------|--------|--------|
| **1.1** Nginx Reverse Proxy | DevOps | `deploy/nginx.conf` | [ ] |
| **1.2** Gateway Skeleton (FastAPI) | Backend Engineer | `gateway/app.py` | [ ] |
| **1.3** Security Tests (pytest) | Security Engineer | `tests/test_security.py` (all passing) | [ ] |
| **1.4** End-to-End Integration | Backend Engineer | Gateway → Staging ERP works | [ ] |
| **1.5** Performance Baseline | DevOps | Latency p95 < 20ms | [ ] |

**PHASE 1 SUCCESS:** Docker Compose runs entire stack. Tests pass. Latency good.

---

## ⚡ 10 CRITICAL IMPROVEMENTS TO IMPLEMENT

Read `CRITICAL_IMPROVEMENTS_SUMMARY.md`. Apply all 10:

1. ✅ Risk scoring formula (0-100 bounded)
2. ✅ Baseline trustworthiness gates (30 days, 500 analyst reviews)
3. ✅ Bootstrap paradox solved (Day-1 threat detection)
4. ✅ Event pipeline reliability (Kafka, DLQ, fallback)
5. ✅ Model rollback procedure (instant, < 30 sec)
6. ✅ Database audit strategy (immutable logs)
7. ✅ HA failover SLA (< 5sec instance, < 30sec DB)
8. ✅ Canary deployment (1% → 10% → 50% → 100%)
9. ✅ Incident response workflow (RACI + SLOs)
10. ✅ Analyst workload (stratified sampling)

---

## 🚨 BLOCKER CHECKLIST (Do NOT Proceed If Any Are Unchecked)

- [ ] Phase 0 exit criteria met (see above)
- [ ] Risk scoring is bounded 0-100 (not unbounded additive)
- [ ] Bootstrap detection is implemented (not relying on baseline Day 1)
- [ ] Gateway latency < 20ms p95 (not 50ms or 100ms)
- [ ] Security tests pass (not "we'll test later")
- [ ] All code is in git (not on someone's laptop)
- [ ] Team alignment is documented (not assumed)
- [ ] No hardcoded secrets in config (not "we'll fix later")

---

## 📖 REFERENCE FILES — USE THESE

**When designing:**
- `ERP_Security_Gateway_End_to_End_Production_Implementation_Playbook.pdf` (original)
- `VERIFICATION_REPORT_ERP_Security_Architecture.md` (validation + 25 fixes)

**When implementing:**
- `CRITICAL_IMPROVEMENTS_SUMMARY.md` (copy-paste code for fixes)
- `MASTER_IMPLEMENTATION_PROMPT_Phase_0_1.md` (detailed tasks)
- **THIS CARD** (quick checklist)

**When stuck:**
- Playbook §5 (MVP gateway)
- Playbook §16 (testing strategy)
- Verification §1 (risk scoring)
- Verification §3 (bootstrap paradox)

---

## 🧪 TESTING REQUIREMENTS (Phase 1)

Gateway MUST block:
- ✅ SQL injection (`' OR '1'='1`, `DROP TABLE`, `UNION SELECT`)
- ✅ XSS (`<script>`, `javascript:`, `onerror=`)
- ✅ Missing auth (no Authorization header)
- ✅ Invalid JWT (malformed token)
- ✅ Oversized requests (> 10MB)

Gateway MUST allow:
- ✅ Valid JWT tokens
- ✅ Legitimate API requests
- ✅ Normal traffic volume

---

## ⏱️ LATENCY BUDGET (Phase 1)

```
Gateway adds < 20ms p95 overhead

Breakdown:
  - Normalization: < 1ms
  - Risk scoring: < 5ms
  - Auth check: < 2ms
  - Policy decision: < 1ms
  - Logging queue: < 2ms
  - Proxy overhead: < 9ms
  ────────────────────
  TOTAL: < 20ms ✅
```

If Phase 1 latency > 20ms, **STOP AND FIX IT.**

---

## 📊 RISK SCORING FORMULA (Copy This)

```python
# Risk score MUST be 0-100 (bounded, normalized)

threat_score = min(100, sum([waf_rules, auth_anomaly, rate_abuse]) / 3)
user_trust_score = account_trustworthiness * 100
sensitivity_score = endpoint_data_sensitivity * 100
context_score = time_of_day_anomaly * 100

overall_risk = (
    threat_score * 0.40 +
    sensitivity_score * 0.25 +
    (100 - user_trust_score) * 0.20 +
    context_score * 0.15
)

risk_score = min(100, max(0, overall_risk))  # Clamp 0-100

# Policy decisions
if risk_score < 20: ALLOW
elif risk_score < 50: LIMIT (rate-limit)
elif risk_score < 75: CHALLENGE (MFA)
else: BLOCK
```

---

## 🔒 AUTHENTICATION POLICY (Phase 1)

```
Protected endpoint (/api/*):
  ✅ MUST have Authorization: Bearer <JWT>
  ✅ JWT MUST have valid signature (basic format check in Phase 1)
  ✅ If missing → 401 challenge
  ✅ If invalid → 401 challenge
  
Health endpoint (/health):
  ✅ No auth required
  ✅ Always accessible
  ✅ Used for monitoring
```

---

## 🛠️ DAILY STANDUP TEMPLATE

```
Phase 0 (Week 1):
  Agent 1 (Infra): "I've completed ___. Blocker: ___."
  Agent 2 (Backend): "I've completed ___. Blocker: ___."
  Agent 3 (Security): "I've completed ___. Blocker: ___."
  Agent 4 (DevOps): "I've completed ___. Blocker: ___."

Phase 1 (Weeks 2-3):
  Agent 1 (Gateway): "Security tests passing: ___/10. Latency: ___ms p95."
  Agent 2 (Testing): "OWASP patterns blocked: ___/10. Next: ___."
  Agent 3 (Integration): "End-to-end working: YES/NO. Latency issue: ___."
```

---

## ⚠️ DO NOT

❌ Deploy without Phase 0 complete  
❌ Use unbounded risk scoring (must be 0-100)  
❌ Trust ML without trustworthiness gates  
❌ Let latency exceed 20ms in Phase 1  
❌ Ship code with hardcoded secrets  
❌ Skip security tests (they're not optional)  
❌ Proceed to Phase 2 without Phase 1 success  

---

## ✅ DO

✅ Read reference files (they have answers)  
✅ Test constantly (every day)  
✅ Log everything (JSON format)  
✅ Commit code daily (git discipline)  
✅ Have daily standups (15 minutes)  
✅ Document unknowns (don't hide assumptions)  
✅ Escalate blockers immediately (don't suffer alone)  

---

## 🚀 LAUNCH SEQUENCE

```
Day 1: Read all reference files
Day 1-2: Complete Phase 0 kickoff meeting
Day 3-4: Inventory work (topology, APIs, traffic)
Day 5: Threat model + risk assessment
Day 6: Team alignment + sign-off
Day 7: Environment setup complete, code in git

Day 8: Phase 1 starts (gateway development)
Day 9-10: Gateway skeleton + risk scoring
Day 11-12: Security tests (blocking attacks)
Day 13: End-to-end integration + performance
Day 14: Latency optimization (if needed)
Day 15: Phase 1 handoff, ready for Phase 2
```

---

## 📞 ESCALATION

**Blocker:** Something is stopping forward progress  
**Action:** Ping tech lead → immediate 15-min sync  

**Examples:**
- "I don't know which database we're using" → blocker
- "Latency is 50ms, need optimization strategy" → blocker
- "Security test failing, not sure why" → blocker

**Do NOT hide blockers. Escalate same day.**

---

## 💾 GIT DISCIPLINE

```bash
# Commit message format
git commit -m "Phase 0.1: Complete ERP topology inventory"
git commit -m "Phase 1.2: Implement risk scoring (0-100 bounded)"
git commit -m "Phase 1.3: Add OWASP security tests"

# Branch strategy
main = production-ready
phase0 = Week 1 work
phase1 = Weeks 2-3 work
```

---

## 📞 QUESTIONS? READ THESE FIRST

| Q | A |
|---|---|
| What should I build? | Playbook §1-2 |
| What's the architecture? | Architecture §3 |
| How do I start Phase 0? | MASTER_IMPLEMENTATION_PROMPT (Part B) |
| How do I implement Phase 1? | MASTER_IMPLEMENTATION_PROMPT (Part C) |
| Risk scoring is confusing | CRITICAL_IMPROVEMENTS_SUMMARY.md #1 |
| Baseline trustworthiness? | CRITICAL_IMPROVEMENTS_SUMMARY.md #2 |
| Latency is high | MASTER_IMPLEMENTATION_PROMPT §1.5 |
| Tests are failing | Playbook §16 (Testing Strategy) |

---

**Last Updated:** September 15, 2026  
**Status:** Ready for Agent Handoff  
**Next:** Phase 0 Kickoff Meeting (Today)

🚀 **LET'S BUILD THIS**

