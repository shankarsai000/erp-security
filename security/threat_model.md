# ERP Security Gateway: STRIDE Threat Model

**Document Version:** 1.0.0  
**Date:** September 15, 2026  
**Scope:** Android Mobile Client, Nginx Reverse Proxy, Security Gateway, Legacy PHP ERP Backend, PostgreSQL Database

---

## 1. System Overview & Trust Boundaries

```
[Android Mobile App] 
       │ (Untrusted Internet / TLS 1.3)
───────▼──────────────────────────────────────── Trust Boundary 1 (Edge)
[Nginx Reverse Proxy]
       │ (Private Network / HTTP/2)
───────▼──────────────────────────────────────── Trust Boundary 2 (Inspection)
[ERP Security Gateway (FastAPI + WAF + Risk Engine)]
       │ (Validated & Traced Requests / Forward Proxy)
───────▼──────────────────────────────────────── Trust Boundary 3 (Core ERP)
[PHP 8.1 ERP Backend] ──> [PostgreSQL 14 DB]
```

---

## 2. STRIDE Threat Analysis

### S — Spoofing (Identity Deception)
- **Threat S1:** Attacker steals valid user credentials via mobile malware, phishing, or credential stuffing.
  - *Impact:* Unauthorized access to ERP tenant data under legitimate guise.
  - *Gateway Mitigation:* Anomaly detection on authentication attempts (>5 failures in 5 min = high risk), geographical impossibility checks, velocity caps, and JWT signature verification.
- **Threat S2:** Attacker fabricates or replays arbitrary JWT tokens.
  - *Impact:* Bypasses user authentication entirely.
  - *Gateway Mitigation:* Cryptographic verification of JWT headers/signatures; revocation cache in Redis; token format strict checks.

### T — Tampering (Data Modification)
- **Threat T1:** SQL Injection payloads injected via query parameters, path variables, or POST bodies (`' OR '1'='1`, `UNION SELECT`, `DROP TABLE`).
  - *Impact:* Direct exfiltration or destruction of PostgreSQL database records.
  - *Gateway Mitigation:* Deterministic WAF inspection before request reaches PHP/SQL layers; automatic rejection (HTTP 403) and high risk score assignment.
- **Threat T2:** Request body tampering or parameter tampering in-flight (e.g., altering price/quantities on `/api/orders`).
  - *Impact:* Fraudulent orders or inventory discrepancies.
  - *Gateway Mitigation:* Strict JSON schema validation, payload length enforcement, and TLS 1.3 encryption in transit.

### R — Repudiation (Denial of Action)
- **Threat R1:** Malicious insider executes sensitive order deletions or alterations and claims they did not perform the action.
  - *Impact:* Lack of legal or forensic accountability.
  - *Gateway Mitigation:* Mandatory structured JSON audit log for every single request containing `request_id`, user ID, client IP, endpoint, payload hash, and gateway policy decision (`ALLOW`, `LIMIT`, `CHALLENGE`, `BLOCK`).
- **Threat R2:** Compromised application or admin deletes audit trail.
  - *Impact:* Complete loss of forensic trail.
  - *Gateway Mitigation:* Append-only log forwarding to centralized, immutable storage (S3 with Object Lock / versioning; PostgreSQL `pgaudit` extension).

### I — Information Disclosure (Data Leakage)
- **Threat I1:** Sensitive PII or financial data returned in verbose error messages or unauthenticated endpoints.
  - *Impact:* GDPR / privacy compliance violation and confidential leak.
  - *Gateway Mitigation:* Normalized error responses (sanitized JSON without stack traces); gateway blocks requests missing authentication on `/api/*`.
- **Threat I2:** Broken Object Level Authorization (BOLA / IDOR) where User A queries `/api/users/{id}` of User B.
  - *Impact:* Horizontal privilege escalation and privacy breach.
  - *Gateway Mitigation:* Contextual identity checks matching token `sub`/tenant claims against path variables.

### D — Denial of Service (Availability Loss)
- **Threat D1:** High-volume automated HTTP floods (e.g. 10,000+ RPS) targeting expensive database endpoints like `/api/inventory` or `/api/orders`.
  - *Impact:* Gateway and PHP backend exhaustion, making the ERP unavailable.
  - *Gateway Mitigation:* Multi-tiered rate limiting (per-IP, per-user, per-endpoint) backed by Redis; instantaneous 429 / 403 responses.
- **Threat D2:** Oversized malicious payload submissions (e.g. 50MB bomb).
  - *Impact:* Memory exhaustion on gateway workers.
  - *Gateway Mitigation:* Strict body size limits (10MB max cap enforced at Nginx and Gateway layers).

### E — Elevation of Privilege (Unauthorized Escalation)
- **Threat E1:** Standard user with `sales` role invokes restricted admin APIs or actions (`DELETE /api/orders/{id}`).
  - *Impact:* Unauthorized configuration or record deletion.
  - *Gateway Mitigation:* Gateway enforces Role-Based Access Control (RBAC) mapping endpoints to authorized roles defined in API inventory.
- **Threat E2:** Attacker exploits legacy PHP vulnerability to gain shell on ERP host.
  - *Impact:* Total system takeover.
  - *Gateway Mitigation:* The security gateway acts as an isolated bastion; direct public access to the PHP host is completely firewalled off.
