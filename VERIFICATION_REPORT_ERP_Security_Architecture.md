# VERIFICATION REPORT: ERP Security Architecture & Implementation Playbook

**Date:** September 15, 2026  
**Status:** COMPREHENSIVE REVIEW COMPLETE  
**Verdict:** Architecturally sound; implementation playbook practical; **25 critical gaps and improvements identified**

---

## EXECUTIVE SUMMARY

### What's Right ✅
1. **Layered architecture** (edge → firewall → WAF → security gateway → backend) is correct and production-tested
2. **Cold-start approach** (rules + threat intel first, ML later) is pragmatic and secure
3. **Emphasis on deterministic enforcement** over ML is fundamentally correct
4. **Explainability requirement** for security decisions is essential
5. **Anti-poisoning controls** in baseline learning acknowledge real threat
6. **Phased implementation** (Phases 0-11) is realistic and achievable

### What Needs Fixing 🔧
1. **Risk scoring formula is undefined** — bounds, normalization, and scaling unclear
2. **Baseline trustworthiness criteria missing** — when is baseline safe to use?
3. **Bootstrap paradox unsolved** — how to identify suspicious behavior before baseline exists?
4. **Event pipeline reliability not specified** — what happens when Kafka fails?
5. **Model rollback procedure absent** — how to rollback without data inconsistency?
6. **Database audit strategy incomplete** — which DB engine? who secures audit logs?
7. **High-availability design lacks detail** — sticky sessions? shared rate-limit state? failover SLA?
8. **Canary deployment undefined** — rollout percentage? rollback criteria? SLO thresholds?
9. **Incident response workflow missing** — who does what, in what order, with what approval?
10. **Analyst workload at scale undefined** — how to review 100K events/day manually?

### Overall Quality
- **Architecture depth:** ⭐⭐⭐⭐⭐ (comprehensive, well-reasoned)
- **Implementation clarity:** ⭐⭐⭐⭐☆ (good, but operationalization vague in places)
- **Production readiness:** ⭐⭐⭐☆☆ (missing HA, observability, incident response detail)
- **Security rigor:** ⭐⭐⭐⭐⭐ (excellent threat modeling, defense-in-depth)
- **Practicality:** ⭐⭐⭐⭐☆ (achievable MVP, but enterprise scaling unclear)

---

## CRITICAL ISSUES (Must Fix Before Production)

### 1. Risk Scoring Formula Is Undefined ⚠️ CRITICAL

**Current State:**
```
risk = base + rule_severity + auth_anomaly + rate_abuse 
       + endpoint_anomaly + reputation_signal + sequence_anomaly 
       - trusted_context
```

**Problems:**
- What is the numeric range? (0-100? 0-1000?)
- Is `trusted_context` a multiplier or subtraction?
- What happens if sum is negative? Clamp to 0?
- How are individual components normalized?
- No definition of "base" value

**Real-World Impact:**
If risk = 487 on a scale meant to be 0-100, policy thresholds fail unpredictably.

**Fix:**
```python
# Proper bounded risk scoring

def calculate_risk(features: RiskFeatures) -> RiskScore:
    """
    Multi-dimensional risk scoring with explainability.
    
    Returns normalized score 0-100 and reasoning.
    """
    
    # Component scores: each is 0-100
    threat_score = min(100, 
        sum([
            rule_fire_severity(features),  # 0-100
            auth_anomaly_magnitude(features),  # 0-100
            rate_abuse_severity(features)  # 0-100
        ]) / 3
    )
    
    sensitivity_score = calculate_data_sensitivity(features.endpoint) * 100  # 0-100
    
    user_trust_score = calculate_user_trustworthiness(features.user_id) * 100  # 0-100
    
    context_score = calculate_contextual_risk(features) * 100  # 0-100
    
    # Weighted composite (normalization preserves 0-100 range)
    weights = {
        'threat': 0.40,
        'sensitivity': 0.25,
        'user_trust': 0.20,
        'context': 0.15
    }
    
    overall_risk = (
        threat_score * weights['threat'] +
        sensitivity_score * weights['sensitivity'] +
        (100 - user_trust_score) * weights['user_trust'] +  # Invert: low trust = high risk
        context_score * weights['context']
    )
    
    # Clamp to 0-100
    risk_score = max(0, min(100, overall_risk))
    
    return RiskScore(
        overall=risk_score,
        components={
            'threat': threat_score,
            'sensitivity': sensitivity_score,
            'user_trust': user_trust_score,
            'context': context_score
        },
        reasons=[...]  # Explainable evidence
    )

# Policy thresholds (clear, testable, auditable)
RISK_POLICY = {
    (0, 20): Decision.ALLOW,
    (20, 50): Decision.LIMIT,  # Rate-limit or monitor
    (50, 75): Decision.CHALLENGE,  # MFA required
    (75, 100): Decision.BLOCK,
}
```

**Acceptance Criteria:**
- [ ] Risk score is always 0-100, normalized, and bounded
- [ ] Component scores are decomposable and auditable
- [ ] Thresholds are configurable per endpoint
- [ ] A=B testing validates thresholds against real traffic
- [ ] Edge case handling documented (all 0? all 100?)

---

### 2. Baseline Trustworthiness Criteria Missing ⚠️ CRITICAL

**Current State:**
Document says "Introduce ML only after telemetry and the baseline are trustworthy" but doesn't define what "trustworthy" means.

**Problems:**
- How many days of data = trustworthy? (7? 30? 90?)
- What FPR on analyst feedback is acceptable? (< 2%? < 5%?)
- How many analyst decisions needed to verify baseline? (50? 500?)
- What if baseline is incomplete (missing night shift users, Q4 seasonal spike)?

**Real-World Impact:**
Teams deploy ML to production because "they feel ready" → catastrophic false positives or false negatives.

**Fix:**

```python
class BaselineTrustworthiness:
    """
    Explicit gates for moving from rules to behavioral ML.
    All criteria must pass before ML is deployed.
    """
    
    MINIMUM_CRITERIA = {
        # Data quantity
        'days_of_telemetry': 30,  # At least 30 days to catch weekly patterns
        'minimum_requests': 100_000,  # Statistically meaningful sample
        'minimum_unique_users': 100,  # Broad coverage, not just power users
        
        # Data quality
        'analyst_reviewed_decisions': 500,  # Analyst marked 500+ as "correct/incorrect"
        'false_positive_rate_on_labels': 0.02,  # < 2% FP on analyst-labeled data
        'false_negative_rate_on_labels': 0.05,  # < 5% FN on known-bad data
        
        # Completeness
        'coverage_by_endpoint': 0.95,  # 95% of endpoints have >= 100 baseline samples
        'coverage_by_user_type': 0.90,  # 90% of user types represented
        'coverage_by_time': 0.95,  # Cover Mon-Sun, peak and off-hours
        
        # Stability
        'baseline_weekly_drift': 0.05,  # Baseline shouldn't change > 5% week-to-week
        'analyst_disagreement_rate': 0.03,  # < 3% of analyst reviews disagree with each other
    }
    
    def can_deploy_ml(self, baseline: Baseline, test_data: TestDataset) -> Tuple[bool, List[str]]:
        """
        Check all gates. Return (can_deploy, blockers).
        """
        blockers = []
        
        # Gate 1: Data volume
        if baseline.days_collected < self.MINIMUM_CRITERIA['days_of_telemetry']:
            blockers.append(
                f"Only {baseline.days_collected} days; need {self.MINIMUM_CRITERIA['days_of_telemetry']}"
            )
        
        # Gate 2: Analyst labeling
        analyst_accuracy = self.calculate_analyst_agreement(baseline.analyst_labels)
        if analyst_accuracy < (1 - self.MINIMUM_CRITERIA['analyst_disagreement_rate']):
            blockers.append(f"Analyst agreement {analyst_accuracy:.1%}; need > {(1 - 0.03):.1%}")
        
        # Gate 3: ML model validation on test data
        fp_rate = test_data.false_positives / len(test_data)
        if fp_rate > self.MINIMUM_CRITERIA['false_positive_rate_on_labels']:
            blockers.append(f"ML FP rate {fp_rate:.1%}; threshold {self.MINIMUM_CRITERIA['false_positive_rate_on_labels']:.1%}")
        
        # Gate 4: Coverage completeness
        endpoint_coverage = self.measure_endpoint_coverage(baseline)
        if endpoint_coverage < self.MINIMUM_CRITERIA['coverage_by_endpoint']:
            blockers.append(f"Endpoint coverage {endpoint_coverage:.1%}; need {self.MINIMUM_CRITERIA['coverage_by_endpoint']:.1%}")
        
        return len(blockers) == 0, blockers

# Usage:
if can_deploy_ml:
    deploy_ml_model()
else:
    print(f"Blockers: {blockers}")
    # Extend baseline collection, improve analyst labeling, retrain
```

**Acceptance Criteria:**
- [ ] All gates documented and measurable
- [ ] Gates enforced in CI/CD (cannot merge ML changes if gates fail)
- [ ] Historical record of gate passages (audit trail)
- [ ] Quarterly re-validation (does ML still pass gates?)

---

### 3. Bootstrap Paradox: Identifying "Suspicious" Before Baseline Exists ⚠️ CRITICAL

**Current State:**
Anti-poisoning rule says: "Allowed does not automatically mean normal. Suspicious sessions, high-risk activity and unreviewed anomalies must be excluded"

**Problem:**
Day 1, no baseline exists. How do you identify "suspicious" without a baseline?

**Real-World Impact:**
Teams accidentally include a 2-week attack campaign in their baseline because nothing was marked suspicious.

**Fix:**

```python
class BootstrapDetection:
    """
    Identify clearly-suspicious traffic on Day 1 without a baseline.
    Uses threat intelligence + deterministic rules only.
    """
    
    def is_suspicious_on_day_one(self, request: Request) -> Tuple[bool, str]:
        """
        Return (is_suspicious, reason).
        Only return True if signal is high-confidence.
        """
        
        # Signal 1: IP Reputation (threat intelligence)
        ip_risk = self.ip_reputation_service.lookup(request.source_ip)
        if ip_risk.threat_level == 'CRITICAL':
            return True, f"IP {request.source_ip} in malware botnet list"
        
        # Signal 2: Known malicious payloads (WAF rules)
        if self.waf_engine.check_injection(request):
            return True, "WAF detected SQL injection / XSS pattern"
        
        # Signal 3: Auth abuse (deterministic)
        auth_failures = self.auth_store.get_recent_failures(
            request.user_id, 
            time_window=timedelta(minutes=5)
        )
        if len(auth_failures) > 5:
            return True, f"User {request.user_id} failed auth 5 times in 5 min (brute force)"
        
        # Signal 4: Rate abuse (deterministic)
        request_rate = self.rate_store.check_rate(request.user_id)
        if request_rate > 1000 / 60:  # > 1000 RPS from one user (impossible)
            return True, f"User {request.user_id} exceeded 1000 RPS (bot)"
        
        # Signal 5: Impossible geography (if we know user's home location)
        if self.has_user_profile(request.user_id):
            last_location = self.user_profiles[request.user_id].last_location
            time_diff = request.timestamp - self.user_profiles[request.user_id].last_request_time
            distance = geopy.distance.geodesic(last_location, request.geoip_location).km
            travel_speed = distance / time_diff.total_seconds()  # km/second
            
            # Can't travel > 900 km/hour (supersonic)
            if travel_speed > 900 / 3600:
                return True, f"Impossible travel: {travel_speed:.0f} km/h"
        
        # Signal 6: Known-bad user agent / Android version (if applicable)
        user_agent_risk = self.user_agent_db.lookup(request.headers.get('User-Agent'))
        if user_agent_risk.threat_level == 'CRITICAL':
            return True, f"User-Agent is known malicious (old Android malware)"
        
        # All checks passed: not suspicious on Day 1
        return False, "All Day-1 checks passed"

# Day-1 baseline construction:
baseline_candidates = []
for event in day_one_traffic:
    is_suspicious, reason = bootstrap_detection.is_suspicious_on_day_one(event.request)
    
    if not is_suspicious and event.decision == ALLOW:
        # Include in baseline: not flagged as malicious AND allowed
        baseline_candidates.append(event)
    elif is_suspicious:
        # Exclude: marked as suspicious, DON'T include in baseline
        quarantine.append((event, reason))
    else:
        # Exclude: we blocked it (we don't know if it's malicious)
        excluded.append((event, "blocked by policy"))

# Result: baseline has only traffic that passed both Day-1 security checks
# AND passed our enforced policies.
```

**Acceptance Criteria:**
- [ ] Day-1 signal detection implemented (IP rep, WAF, auth abuse, rate abuse, geography, UA)
- [ ] All signals are deterministic and explainable
- [ ] Suspicious traffic is quarantined, NOT included in baseline
- [ ] Baseline excludes both malicious and blocked-by-policy traffic
- [ ] Bootstrap logic documented and tested

---

### 4. Event Pipeline Reliability Not Specified ⚠️ CRITICAL

**Current State:**
Document mentions "Event-loss rate" as a metric but doesn't specify how to prevent it.

**Problem:**
If security events are lost (Kafka crashes, queue fills), you're flying blind. Attacks happen, you have no evidence.

**Real-World Impact:**
Ransomware incident happens. You investigate and find: "No logs from 2-4 AM" → compliance audit fails → incident unrecoverable.

**Fix:**

```python
class EventPipelineReliability:
    """
    No event loss. Ever.
    """
    
    RELIABILITY_CONTRACT = {
        # The gateway must NEVER lose a security decision.
        # It must reach persistent storage OR fail the request.
        
        'local_queue_size': 10_000,  # In-memory queue (gateway -> Kafka)
        'local_queue_timeout': 5,  # Drop request if queue takes > 5 sec
        'kafka_replication': 3,  # 3 replicas, survive 2 failures
        'kafka_acks': 'all',  # Don't return until all replicas confirm
        'kafka_retention': '90 days',  # Keep logs for 90 days
        'dead_letter_queue': True,  # Failed events go to DLQ for manual review
    }
    
    def emit_security_event(self, event: SecurityEvent) -> None:
        """
        Log a security event. Must not fail silently.
        """
        
        # 1. Write to local persistent queue (if Kafka is down)
        try:
            self.local_queue.put_nowait(event, timeout=1)
        except queue.Full:
            # Local queue is full (Kafka is down for > 5 minutes)
            # This is a critical infrastructure failure.
            # Stop processing requests to avoid data loss.
            self.send_alert(
                severity='CRITICAL',
                message='Event queue full; stopping request processing to prevent data loss',
                action='page_oncall'
            )
            raise CriticalInfrastructureFailure("Event pipeline is down")
        
        # 2. Async push to Kafka
        try:
            future = self.kafka_producer.send_async(
                topic='security-events',
                value=event.to_json(),
                key=event.request_id,
                acks='all'  # Wait for all replicas
            )
            # Optional: wait for confirmation
            future.get(timeout=10)
        except kafka.errors.KafkaError as e:
            # Kafka is down, but we have it in local queue.
            # Log the error, keep trying.
            self.logger.error(f"Kafka send failed: {e}; event in local queue")
            self.metrics.increment('events.kafka_failed')
        
        # 3. If Kafka stays down for 1 hour, write to fallback (S3, local disk)
        if self.local_queue.size() > 1000 and self.kafka_down_duration > 3600:
            self.fallback_storage.write(self.local_queue.drain())
            self.logger.warning("Fallback to S3 storage due to Kafka outage")

# Configuration
KAFKA_CONFIG = {
    'bootstrap.servers': ['kafka1:9092', 'kafka2:9092', 'kafka3:9092'],
    'acks': 'all',  # All replicas must confirm
    'retries': 999,  # Retry forever (with backoff)
    'request.timeout.ms': 30_000,  # 30-second timeout
    'compression.type': 'snappy',  # Compression
}

# Monitoring
METRICS_TO_TRACK = [
    'events.total',  # Emitted per second
    'events.kafka_failed',  # Kafka send failures
    'events.local_queue_size',  # How full is local queue?
    'events.kafka_latency_ms',  # How fast is Kafka?
    'events.dead_letter_count',  # Dead-letter queue depth
]

# Alerting
ALERTS = [
    'Local queue size > 5000',  # Kafka is falling behind
    'Kafka latency > 1 second',  # Degradation
    'Kafka replica count < 2',  # Fault tolerance lost
    'Dead-letter queue depth > 100',  # Persistent send failures
]
```

**Acceptance Criteria:**
- [ ] Event pipeline never silently loses data
- [ ] Kafka cluster is 3-node minimum (fault-tolerant)
- [ ] Local persistent queue acts as buffer
- [ ] Dead-letter queue captures failed events
- [ ] Fallback storage (S3, local disk) exists
- [ ] Metrics track pipeline health in real-time
- [ ] Alerts page oncall if pipeline is degraded

---

### 5. Model Rollback Procedure Absent ⚠️ CRITICAL

**Current State:**
"Models are versioned and rollbackable" but no procedure defined.

**Problem:**
Model deployed 2 days ago has 10% false positive rate. How do you rollback?
- Do you rollback just the model, or also the training data?
- What about decisions made by the bad model? (Did they poison the baseline?)
- How fast can you rollback (seconds? minutes?)?

**Real-World Impact:**
Bad model blocks legitimate users for 6 hours while you scramble to rollback.

**Fix:**

```python
class ModelGovernance:
    """
    Version, deploy, monitor, and rollback ML models safely.
    """
    
    def deploy_model(self, model: MLModel, version: str) -> None:
        """
        Canary -> validation -> gradual rollout -> full rollout.
        """
        
        # Step 1: Canary (1% of traffic)
        self.model_service.set_canary_traffic(version=version, percentage=1)
        self.monitor(duration=1_hour)
        
        # Step 2: Validate canary metrics
        canary_metrics = self.metrics.get_metrics_for_version(version)
        if not self.validate_canary(canary_metrics, threshold=0.05):  # FP rate < 5%
            self.logger.error(f"Canary failed: FP rate too high")
            self.rollback_to(previous_version)
            return
        
        # Step 3: Gradual rollout (1% -> 10% -> 50% -> 100%)
        for percentage in [10, 50, 100]:
            self.model_service.set_traffic(version=version, percentage=percentage)
            self.monitor(duration=2_hours)
            metrics = self.metrics.get_metrics_for_version(version)
            
            if not self.validate_rollout(metrics, threshold=0.03):  # FP rate < 3%
                self.rollback_to(previous_version)
                return
        
        # Step 4: Lock new version as production
        self.model_registry.set_production_version(version=version)
        self.logger.info(f"Model {version} is now production")
    
    def rollback_to(self, previous_version: str) -> None:
        """
        Fast rollback to previous version (seconds, not minutes).
        """
        
        # Instant redirect all traffic to old model
        self.model_service.set_traffic(
            version=previous_version,
            percentage=100
        )
        
        # Stop serving bad model
        self.model_service.stop_model(version=self.current_version)
        
        # Alert oncall
        self.send_alert(
            severity='HIGH',
            message=f'Rolled back model to {previous_version}',
            action='page_on_call'
        )
        
        # Trigger investigation
        bad_model_metrics = self.get_model_metrics(self.current_version)
        self.create_incident(
            title=f'Model {self.current_version} rollback',
            evidence=bad_model_metrics,
            owners=['ml-team@company.com']
        )
    
    def handle_model_poisoning(self, version: str) -> None:
        """
        If a bad model was used to generate baseline/training data,
        we need to quarantine that data.
        """
        
        # Find all events scored by bad model
        poisoned_events = self.event_store.query(
            f"model_version = '{version}'"
        )
        
        # Mark as quarantined (don't use for baseline/training)
        for event in poisoned_events:
            event.tag('quarantined_by_model_' + version)
            event.exclude_from_baseline = True
        
        # Manual review required
        self.create_incident(
            title=f'Possible model poisoning from {version}',
            description=f'{len(poisoned_events)} events scored by bad model',
            action='analyst_review_required'
        )

# Validation criteria
ROLLBACK_CRITERIA = {
    # Automatic rollback if ANY of these are true during canary
    'false_positive_rate_too_high': 0.10,  # > 10% FP rate
    'false_negative_rate_too_high': 0.20,  # > 20% FN rate (worse than baseline)
    'latency_degraded': 2.0,  # Inference > 2 seconds
    'model_crashed': True,  # Any exceptions
    'unavailable': True,  # Model service not responding
}

# Version management
MODEL_VERSIONS = {
    'v1': {'hash': 'sha256:abc123', 'status': 'deprecated'},
    'v2': {'hash': 'sha256:def456', 'status': 'production'},
    'v3': {'hash': 'sha256:ghi789', 'status': 'canary'},
    'v4': {'hash': 'sha256:jkl012', 'status': 'training'},
}
```

**Acceptance Criteria:**
- [ ] Model versioning is strict (hash, timestamp, training data hash)
- [ ] Canary-to-production pipeline is automated
- [ ] Rollback is < 30 seconds (instant traffic redirect)
- [ ] Bad model doesn't poison future baselines (quarantine logic)
- [ ] Historical record of all deployments/rollbacks (audit)
- [ ] Oncall is paged immediately if rollback occurs

---

### 6. Database Audit Strategy Incomplete ⚠️ CRITICAL

**Current State:**
"Database audit logging" mentioned but no specifics on what/how/who.

**Problem:**
- Which database engine? (PostgreSQL pgaudit? MySQL? SQL Server?)
- Who has access to audit logs? (Can admin delete them?)
- How are logs protected from tampering?
- What's the retention and cost?

**Real-World Impact:**
Insider threat deletes audit logs of their theft. Forensics finds nothing.

**Fix:**

```python
class DatabaseAuditStrategy:
    """
    Comprehensive database audit across different DB engines.
    """
    
    # PostgreSQL + pgaudit (most common for PHP ERPs)
    POSTGRESQL_CONFIG = {
        # Enable at superuser level, can't be disabled at runtime
        'pgaudit.log': [
            'ALL',  # Log all commands
            'ROLE',  # GRANT/REVOKE
            'DDL',  # ALTER TABLE, etc
        ],
        'pgaudit.log_level': 'WARNING',  # Severity level
        'pgaudit.log_connections': 'on',  # Who connects
        'pgaudit.log_disconnections': 'on',
        'pgaudit.log_statement': 'on',  # Log SQL statements
        'pgaudit.log_statement_once': 'off',  # Log every occurrence
    }
    
    POSTGRESQL_AUDIT_LOG_FORMAT = {
        'timestamp': '2024-01-15T10:23:45.123456',
        'user': 'app_user',
        'database': 'erp_production',
        'statement': 'SELECT * FROM orders WHERE order_id = $1',
        'parameters': ['12345'],  # Parameterized, not hardcoded
        'duration_ms': 45,
        'result': 'OK' | 'ERROR',
    }
    
    # MySQL + audit plugin
    MYSQL_CONFIG = {
        'server_audit_logging': 'ON',
        'server_audit_events': [
            'CONNECT',
            'QUERY_DDL',  # ALTER, CREATE, DROP
            'QUERY_DML_WRITE',  # INSERT, UPDATE, DELETE
            'QUERY_DML_SELECT',  # SELECT (high volume; be selective)
        ],
        'server_audit_output_type': 'SYSLOG',  # Don't write to filesystem
    }
    
    # SQL Server + auditing
    SQLSERVER_CONFIG = {
        'audit_type': 'DATABASE',  # Database-level audit
        'audit_events': [
            'SUCCESSFUL_LOGIN',
            'FAILED_LOGIN',
            'AUDIT_CHANGE',
            'DATABASE_CHANGE',  # ALTER DATABASE
            'SCHEMA_OBJECT_CHANGE',  # CREATE/ALTER/DROP tables
        ],
        'audit_destination': 'APPLICATION_LOG',  # Windows Event Log or SQL Server logs
    }

def setup_database_audit():
    """
    Implement across all database engines.
    """
    
    if db_engine == 'postgresql':
        setup_pgaudit()
    elif db_engine == 'mysql':
        setup_mysql_audit()
    elif db_engine == 'sqlserver':
        setup_sqlserver_audit()

def setup_pgaudit():
    """PostgreSQL audit with tamper-proof storage."""
    
    # 1. Install pgaudit extension
    execute_sql('''
        CREATE EXTENSION IF NOT EXISTS pgaudit;
    ''')
    
    # 2. Configure audit logging
    execute_sql('''
        ALTER SYSTEM SET pgaudit.log = 'ALL';
        ALTER SYSTEM SET pgaudit.log_connections = 'on';
        ALTER SYSTEM SET pgaudit.log_disconnections = 'on';
        ALTER SYSTEM SET log_destination = 'stderr';
        ALTER SYSTEM SET logging_collector = 'on';
    ''')
    
    # 3. Protect audit logs (immutable storage)
    #    - Write to AWS S3 (versioning enabled)
    #    - OR write to separate immutable filesystem
    #    - OR stream to centralized SIEM
    configure_log_shipping(
        destination='s3://audit-logs-immutable/postgresql/',
        encryption='AES-256',
        versioning='enabled',  # Prevent deletion
        access_logging='enabled'  # Track who reads logs
    )
    
    # 4. Verify: who has access to audit logs?
    verify_audit_log_access(
        who_can_read=['security_team', 'compliance_team'],  # Least privilege
        who_can_delete=['nobody'],  # Immutable
        who_can_modify=['nobody']
    )
    
    # 5. Monitor audit log deletion attempts
    create_alert(
        name='Audit log deletion attempt',
        condition='DELETE FROM pg_logs',
        action='IMMEDIATE_PAGE'
    )

# Audit log retention
AUDIT_LOG_RETENTION = {
    'hot': '30 days',  # Fast query (Elasticsearch)
    'warm': '90 days',  # Slower query (ClickHouse)
    'cold': '7 years',  # Compliance requirement (S3 Glacier)
}

# Sample audit query (for investigation)
def audit_query_example():
    """
    Investigation: did user X access customer data?
    """
    results = audit_log_store.query(f'''
        SELECT timestamp, user, statement, parameters
        FROM audit_logs
        WHERE user = 'john@company.com'
          AND statement LIKE '%customers%'
          AND timestamp > NOW() - INTERVAL 7 DAYS
        ORDER BY timestamp DESC
    ''')
    return results

# Tamper detection
def verify_audit_integrity():
    """
    Periodically verify audit logs haven't been deleted/modified.
    """
    
    # Expected: 86,400 events per day (1 per second, average)
    events_today = count_audit_logs_for_date(today)
    expected_minimum = 50_000  # Conservative estimate
    
    if events_today < expected_minimum:
        alert(
            'Audit log volume unexpectedly low; possible deletion',
            severity='CRITICAL'
        )
```

**Acceptance Criteria:**
- [ ] Audit logging enabled at DB level (not application level)
- [ ] Logs are immutable (can't be deleted by admin)
- [ ] Logs shipped to separate secure storage (S3, syslog, SIEM)
- [ ] Access to audit logs controlled (who can read? who can delete? audit that too)
- [ ] Retention meets compliance requirements (GDPR, PCI, SOC 2)
- [ ] Audit queries support forensic investigation

---

### 7. High Availability Design Lacks Critical Detail ⚠️ HIGH

**Current State:**
"Multiple gateway instances where availability requires it" but no specifics.

**Problem:**
- Are instances stateless? (Can traffic switch between instances without losing rate-limit state?)
- Is rate-limit counter shared (Redis)? If yes, what if Redis fails?
- Is session state shared? (If user logs in to instance 1, can instance 2 recognize them?)
- What's the failover latency? (instant? 30 seconds? 5 minutes?)

**Fix:**

```python
class HighAvailabilityDesign:
    """
    Gateway HA: stateless instances, shared state, graceful degradation.
    """
    
    ARCHITECTURE = {
        'instances': [
            {'id': 'gw-1', 'zone': 'us-east-1a', 'status': 'ACTIVE'},
            {'id': 'gw-2', 'zone': 'us-east-1b', 'status': 'ACTIVE'},
            {'id': 'gw-3', 'zone': 'us-east-1c', 'status': 'STANDBY'},  # Spare
        ],
        'load_balancer': {
            'type': 'network_load_balancer',  # Layer 4, not Layer 7 (for speed)
            'health_check_interval': '5s',
            'health_check_timeout': '2s',
            'unhealthy_threshold': 2,  # Mark unhealthy after 2 failures
            'connection_drain_timeout': '30s',  # Graceful shutdown
        },
        'shared_state': {
            'redis_cluster': ['redis-1:6379', 'redis-2:6379', 'redis-3:6379'],
            'persistence': 'AOF',  # Append-only file
            'failover': 'automatic',  # Sentinel handles failover
            'replication': 'master-replica-replica',  # 3 nodes for HA
        },
    }
    
    def handle_instance_failure(self) -> None:
        """
        Gateway instance crashes. What happens?
        """
        
        # Load balancer detects failure (2 failed health checks)
        # → Removes unhealthy instance from rotation (< 5 seconds)
        # → Routes all traffic to remaining healthy instances
        
        # Impact: 
        #   - No user-facing request loss (LB redirects instantly)
        #   - Rate-limit state preserved (Redis is separate)
        #   - ML model state preserved (model service is separate)
        
        # Auto-recovery:
        # → Auto-scaler detects low instance count
        # → Launches replacement instance (2-3 minutes)
        # → New instance joins load balancer
        
        pass
    
    def handle_redis_failure(self) -> None:
        """
        Redis (rate-limit store) fails.
        """
        
        # Scenario: Redis cluster loses majority (e.g., 2 of 3 nodes fail)
        
        # Option A (default): Fail-closed
        # → Gateway cannot write rate-limit counters
        # → Cannot verify rate limits
        # → BLOCK all traffic? (safest, but kills availability)
        
        # Option B (chosen): Graceful degradation
        # → Use local in-memory rate-limit cache
        # → If Redis is unreachable, allow 1 missed update per user
        # → If Redis stays down > 1 hour, trigger fallback
        
        if redis_unreachable:
            # Local fallback: keep rate-limit counters in memory
            self.local_rate_limiter.enable()
            # → Less accurate (in-memory lost on instance restart)
            # → But better than blocking all traffic
            # Alert oncall: Redis needs recovery
            self.alert('Redis unreachable for 5 minutes', severity='HIGH')
            
            # If Redis stays down > 1 hour, switch to strict mode
            if redis_outage_duration > 3600:
                self.local_rate_limiter.strict_mode()  # Stricter limits
    
    def handle_database_failure(self) -> None:
        """
        Backend database fails (gateway can't reach DB for security decisions).
        """
        
        # Scenario: PostgreSQL is down (maintenance, crash, network)
        
        # Gateway still needs to make decisions (gateway is stateless)
        # Solution: Cache security decisions made in last 10 minutes
        
        # If DB is unreachable:
        # 1. Check cache: is this user/endpoint combination in cache?
        #    → If yes, use cached decision (allow/block)
        # 2. If not in cache, apply conservative default:
        #    → LIMIT (slow down), not BLOCK (avoid false negatives)
        #    → Allow request, but log it as "made during DB outage"
        
        db_decision_cache = TTLCache(
            maxsize=100_000,
            ttl=600  # 10-minute cache
        )
        
        if not db_reachable:
            if (user_id, endpoint) in db_decision_cache:
                decision = db_decision_cache[(user_id, endpoint)]
                return decision
            else:
                return Decision.LIMIT  # Safe default during outage
    
    def failover_latency_sla(self) -> None:
        """
        What's our RTO (Recovery Time Objective)?
        """
        
        FAILOVER_SLA = {
            'gateway_instance_failure': '5 seconds',  # LB detects health fail
            'redis_node_failure': '10 seconds',  # Redis Sentinel promotes replica
            'database_failure': '30 seconds',  # Connection pool drains, failover
            'load_balancer_failure': '60 seconds',  # DNS update propagates
        }
        
        # Measurement: synthetic monitoring checks failover time
        def test_failover_sla():
            # Simulate gateway crash
            kill_gateway_instance('gw-1')
            
            # Measure: how long until traffic reroutes?
            start = time.time()
            while not health_check_passes('gw-1'):
                time.sleep(0.1)
                if time.time() - start > 10:  # Timeout after 10 seconds
                    raise FailoverSLAViolation("Failover took > 10 seconds")
            
            failover_time = time.time() - start
            assert failover_time < 5, f"Failover SLA violated: {failover_time}s"
```

**Acceptance Criteria:**
- [ ] Gateway instances are stateless (kill any instance, no data loss)
- [ ] Shared state (rate limits, sessions) in Redis cluster (HA)
- [ ] Load balancer actively monitors health (health checks every 5s)
- [ ] Failover latency is < 5 seconds for instance failure
- [ ] Graceful degradation defined for each dependency (Redis, DB, model service)
- [ ] Synthetic monitoring validates failover SLA

---

### 8. Canary Deployment Process Undefined ⚠️ HIGH

**Current State:**
"Canary + rollback + SLO evidence" but no specifics.

**Problem:**
- 1% of traffic = canary? 10%? 0.1%?
- How long do you observe canary? 1 hour? 1 day?
- What metric triggers automatic rollback? (FP rate? latency? both?)
- Who approves moving from canary to production?

**Fix:**

```python
class CanaryDeploymentProcess:
    """
    Safe rollout of new security rules, models, or configurations.
    """
    
    CANARY_CONFIG = {
        'phase_1_canary': {
            'percentage': 1,  # 1% of traffic
            'duration': '2 hours',
            'metrics_to_track': [
                'false_positive_rate',
                'false_negative_rate',
                'latency_p95',
                'error_rate',
                'alert_rate',
            ],
            'auto_rollback_on': [
                ('false_positive_rate', '>', 0.10),  # > 10% FP = auto rollback
                ('latency_p95', '>', 200),  # > 200ms = auto rollback
                ('error_rate', '>', 0.05),  # > 5% errors = auto rollback
            ],
            'manual_approval': True,  # Analyst reviews canary metrics
        },
        'phase_2_ramp': {
            'percentage': 10,  # 10% of traffic
            'duration': '4 hours',
            'metrics_to_track': ['same as phase 1'],
            'auto_rollback_on': [
                ('false_positive_rate', '>', 0.05),  # Stricter threshold
                ('latency_p95', '>', 150),
                ('error_rate', '>', 0.02),
            ],
            'manual_approval': True,
        },
        'phase_3_majority': {
            'percentage': 50,  # 50% of traffic
            'duration': '8 hours',  # Overnight to catch night shift behavior
            'metrics_to_track': ['same'],
            'auto_rollback_on': [
                ('false_positive_rate', '>', 0.03),  # Even stricter
                ('latency_p95', '>', 100),
                ('error_rate', '>', 0.01),
            ],
            'manual_approval': True,
        },
        'phase_4_production': {
            'percentage': 100,  # All traffic
            'duration': 'ongoing',
            'metrics_to_track': ['same'],
            'auto_rollback_on': [
                ('false_positive_rate', '>', 0.02),  # Production threshold
                ('latency_p95', '>', 100),
                ('error_rate', '>', 0.01),
            ],
            'manual_approval': False,  # Already in production
            'post_deployment': [
                'Verify SLOs are met',
                'Analyst reviews first 24 hours of decisions',
                'Rollback if needed',
            ],
        },
    }
    
    def execute_canary(self, change: Change) -> bool:
        """
        Roll out change through canary pipeline.
        Returns True if successful, False if rolled back.
        """
        
        for phase_name, phase_config in self.CANARY_CONFIG.items():
            self.logger.info(f"Starting {phase_name}: {phase_config['percentage']}% traffic")
            
            # Deploy to this percentage
            self.deploy(change, percentage=phase_config['percentage'])
            
            # Monitor
            metrics = self.monitor(
                duration=phase_config['duration'],
                metrics=phase_config['metrics_to_track']
            )
            
            # Check auto-rollback criteria
            for metric_name, operator, threshold in phase_config['auto_rollback_on']:
                metric_value = metrics[metric_name]
                if self._should_rollback(metric_value, operator, threshold):
                    self.logger.error(
                        f"{metric_name}={metric_value} {operator} {threshold}; auto-rollback triggered"
                    )
                    self.rollback()
                    return False
            
            # Manual approval (except production)
            if phase_config['manual_approval']:
                approval = self.request_approval(phase_name, metrics)
                if not approval:
                    self.logger.info("Analyst rejected canary; rolling back")
                    self.rollback()
                    return False
        
        # All phases complete: change is in production
        self.logger.info("Change fully deployed to production")
        return True
    
    def _should_rollback(self, value: float, operator: str, threshold: float) -> bool:
        """Check if metric crosses threshold."""
        if operator == '>':
            return value > threshold
        elif operator == '<':
            return value < threshold
        elif operator == '==':
            return value == threshold
        return False

# Example: Deploy a new ML model through canary
def deploy_ml_model_v3():
    change = Change(
        type='ml_model',
        from_version='v2',
        to_version='v3',
        timestamp=datetime.now()
    )
    
    success = canary.execute_canary(change)
    
    if success:
        print("✅ Model v3 successfully deployed")
    else:
        print("❌ Model v3 rollback completed; v2 is active")
```

**Acceptance Criteria:**
- [ ] Canary phases are 1% → 10% → 50% → 100%
- [ ] Each phase has defined monitoring duration (2h → 4h → 8h)
- [ ] Auto-rollback criteria per phase (stricter in later phases)
- [ ] Manual approval gate at each phase
- [ ] Rollback is instant (traffic redirect, not gradual)
- [ ] Historical record of all canaries (audit trail)

---

## IMPORTANT GAPS (Fix Before Scaling)

### 9. Incident Response Workflow Missing ⚠️ HIGH

**Current State:**
Dashboard shows "Incident" view but doesn't define workflow.

**Gap:**
Who reviews? Who decides to block a user? Who notifies the user? SLA?

**Fix:**
```python
# Incident workflow: Detection → Investigation → Decision → Action → Notification

INCIDENT_WORKFLOW = {
    'detection': {
        'trigger': 'Alert from security gateway / ML',
        'slo': '< 1 minute',
        'action': 'Create incident ticket'
    },
    'triage': {
        'owner': 'On-call SOC analyst',
        'slo': '< 5 minutes',
        'action': 'Assess severity; gather evidence'
    },
    'investigation': {
        'owner': 'SOC analyst / Security engineer',
        'slo': '< 30 minutes for HIGH/CRITICAL',
        'action': 'Correlate events; determine root cause'
    },
    'decision': {
        'owner': 'SOC analyst',
        'slo': '< 60 minutes',
        'action': 'Decide: Allow / Block / Challenge / Limit / Investigate Further',
        'approval_required': 'If blocking user / account suspension'
    },
    'action': {
        'owner': 'Gateway / Security system',
        'slo': '< 5 minutes after decision',
        'actions': [
            'Block IP / user / device',
            'Notify user (optional, if not blocking)',
            'Escalate to incident response team',
        ]
    },
    'notification': {
        'owner': 'Comms / Legal',
        'slo': 'Per compliance requirement (GDPR, etc)',
        'recipients': ['Affected user', 'Management', 'Compliance', 'Legal']
    },
    'post_incident': {
        'owner': 'Security team',
        'slo': '< 24 hours',
        'action': [
            'Retrospective: what went wrong',
            'Prevention: update rules / ML',
            'Monitoring: add alert to prevent recurrence',
        ]
    }
}
```

**Acceptance Criteria:**
- [ ] Incident response workflow documented (RACI matrix)
- [ ] SLO per stage (detection < 1 min, triage < 5 min, decision < 60 min)
- [ ] Approval gates for high-impact actions
- [ ] Notification templates (user, management, compliance)

---

### 10. Analyst Workload at Scale Undefined ⚠️ HIGH

**Current State:**
"Analyst reviews baseline candidates" but if 100K events/day, analyst can't review all.

**Gap:**
At scale, manual review is impossible. How to sample? Which events to prioritize?

**Fix:**
```python
class AnalystWorkload:
    """
    Scale analyst review through sampling, automation, and prioritization.
    """
    
    def review_at_scale(self, events: List[Event], daily_volume: int) -> None:
        """
        100K events/day, 1 analyst. Prioritize.
        """
        
        if daily_volume > 10_000:
            # Too many to review manually; use stratified sampling
            
            # Tier 1: Automatic (no review needed)
            auto_approved = filter_by_criteria(events, {
                'decision': 'ALLOW',
                'risk_score': 0-20,
                'waf_rules_fired': False,
                'user_account_age': '> 1 year',
                'user_incident_history': '== 0',
            })
            # → Include 100% in baseline
            
            # Tier 2: Low-risk sample (random 10%)
            low_risk = filter_by_criteria(events, {
                'decision': 'ALLOW',
                'risk_score': 20-50,
                'user_account_age': '> 3 months',
            })
            sample_low = random.sample(low_risk, min(1000, len(low_risk) // 10))
            # → Analyst reviews 1000 samples
            # → If > 98% analyst approves, include all in baseline
            
            # Tier 3: Medium-risk (all reviewed)
            medium_risk = filter_by_criteria(events, {
                'risk_score': 50-75,
            })
            # → Analyst reviews ALL (or samples 5%)
            # → Decide: baseline or quarantine
            
            # Tier 4: High-risk (quarantine by default)
            high_risk = filter_by_criteria(events, {
                'risk_score': 75-100,
            })
            # → Quarantine (don't use for baseline)
            # → Investigate manually or via agent
            
        # Analyst dashboard: prioritized review
        analyst_queue = [
            ('URGENT', high_risk),  # ~50 events, 1-2 hours
            ('HIGH', sample_medium_risk),  # ~500 events, 2-4 hours
            ('MEDIUM', sample_low_risk),  # ~1000 events, 4-8 hours
            ('LOW', auto_approved),  # 0 review needed
        ]
        
        # Analyst marks decisions: "APPROVE" / "REJECT" / "ESCALATE"
        for decision, events in analyst_queue:
            analyst_feedback = collect_analyst_feedback(events)
            # → Use feedback to tune risk scoring, update rules, etc
```

**Acceptance Criteria:**
- [ ] Stratified sampling defined (auto-approve, sample, all-review, quarantine)
- [ ] Analyst workload is realistic (4-8 hours/day max)
- [ ] Analyst feedback is used to improve rules/ML
- [ ] Escalation path for high-risk events

---

## OTHER IMPORTANT GAPS (Should Fix Before Scaling)

### 11. Device Integrity Signal Confidence Not Defined

**Issue:** Play Integrity API returns confidence levels (LOW/MEDIUM/HIGH). Document doesn't explain how to act on different confidence levels.

**Fix:**
```python
# Play Integrity confidence levels

if integrity_token.verdict == 'PLAY_INTEGRITY_VERDICT_UNRECOGNIZED':
    risk_adjustment = 0  # Unknown = neutral (not risky)
elif integrity_token.verdict == 'PLAY_INTEGRITY_VERDICT_FAILED':
    confidence = integrity_token.confidence_level
    if confidence == HIGH:
        risk_adjustment = +30  # Definitely compromised
    elif confidence == MEDIUM:
        risk_adjustment = +15  # Probably compromised
    elif confidence == LOW:
        risk_adjustment = +5  # Maybe compromised; challenge user
```

---

### 12. Database Credential Rotation SLA Missing

**Issue:** "Short-lived credentials (1-hour TTL)" but no mechanism defined. How does app get new credential? What if Vault is unreachable?

**Fix:**
```python
# Credential rotation SLA

CREDENTIAL_SLA = {
    'ttl': '1 hour',  # Credentials expire after 1 hour
    'refresh_before_expiry': '15 minutes',  # Get new one 15 min before expiry
    'fallback': 'Long-lived backup credential (24 hour TTL, only if Vault fails)',
    'vault_unavailable_actions': [
        'Use fallback credential (risky, but better than no access)',
        'Page oncall: Vault is down',
        'Audit all queries made with fallback',
    ],
}
```

---

### 13. Egress Anomaly Detection Not Detailed

**Issue:** "Unexpected outbound connections" mentioned but no specifics.

**Fix:**
```python
# Egress anomaly detection

EGRESS_ANOMALIES = {
    'volume_spike': 'If outbound bytes > 10x baseline, alert',
    'new_destination': 'If ERP connects to IP not in allowlist, alert',
    'dns_tunneling': 'If DNS queries spike (> 1000/min), alert (possible DNS exfiltration)',
    'known_c2': 'If destination in threat intel (Abuse.ch, VirusTotal), block',
    'unusual_port': 'If ERP connects to non-standard port (e.g., port 666), alert',
    'protocol_violation': 'If TLS handshake fails but connection persists, alert',
}
```

---

## MODERATE ISSUES (Nice-to-Have)

### 14. ML Model Explanation / Interpretability

**Issue:** ML component doesn't explain why a score is high/low.

**Recommendation:**
Use SHAP (SHapley Additive exPlanations) values to explain model decisions:
```python
import shap
explainer = shap.TreeExplainer(model)
shap_values = explainer.shap_values(request_features)
# Output: which features contributed to high risk score?
```

---

### 15. Replay Protection for Sensitive Operations

**Issue:** Mentioned but not designed. Where's the nonce / timestamp check?

**Fix:**
```python
# Replay protection for money transfer, password change, etc

if request.operation in SENSITIVE_OPERATIONS:
    # Require fresh timestamp (< 60 seconds old)
    if abs(request.timestamp - current_time) > 60:
        return REJECT
    
    # Require nonce (single-use ID)
    if nonce_store.was_seen(request.nonce):
        return REJECT  # Already processed
    
    nonce_store.mark_as_used(request.nonce)
```

---

### 16. Outbound Allowlist Maintenance

**Issue:** Allowlisting is good, but who maintains the list? Automated discovery or manual?

**Recommendation:**
```python
# Outbound allowlist: hybrid approach

OUTBOUND_ALLOWLIST = {
    'stripe.com': {'ports': [443], 'protocol': 'https', 'approved_by': 'Payment team'},
    'sendgrid.com': {'ports': [587], 'protocol': 'smtp', 'approved_by': 'Ops team'},
    # ...
}

# Quarterly review: are all allowlisted destinations still needed?
# Automated: if destination isn't used for 30 days, flag for removal
```

---

### 17. Certificate Pinning Rotation Plan

**Issue:** "Robust rotation and recovery plan" is too vague.

**Fix:**
```python
# Certificate pinning: rotation & recovery

PINNING_STRATEGY = {
    'primary_pin': 'Current production certificate',
    'backup_pin_1': 'Next certificate (staged, not live)',
    'backup_pin_2': 'Fallback certificate (emergency recovery)',
    
    'rotation_schedule': 'Every 90 days',
    'rotation_process': [
        '1. Generate new cert + new key',
        '2. Add backup_pin_2 to all apps in store (prepare)',
        '3. Deploy cert to production (primary_pin changes)',
        '4. Rollout app update (pin changes in app)',
        '5. Monitor for connection failures',
        '6. After rollout complete, retire old pins',
    ],
    'recovery': [
        'If new cert fails, server falls back to backup_pin_1',
        'If that fails, users must update app (force upgrade)',
        'Never hardcode pins; require server-provided pins for emergencies',
    ],
}
```

---

## MISSING SECTIONS (Comprehensive Playbook)

### 18. Android Release Management & Rollback

**Gap:** How to rollback Android app if new version has security bug?

**Fix:**
```python
# Android rollback strategy

ANDROID_RELEASE_SLA = {
    'testing': '2 weeks (closed beta testing)',
    'rollout': '1% → 10% → 50% → 100% (over 2 weeks)',
    'crash_monitoring': 'Firebase Crashlytics (auto-rollback if crash rate > 1%)',
    'pin_rotation': 'If new app must support cert rotation, include backup pin',
    'forced_upgrade': 'Can force users to upgrade if security bug found',
}
```

---

### 19. Compliance & Audit Logging

**Gap:** GDPR, SOC 2, PCI-DSS requirements not mentioned.

**Fix:**
```python
# Compliance logging

COMPLIANCE_REQUIREMENTS = {
    'GDPR': {
        'purpose': 'Legal basis for processing, data minimization',
        'logging_requirement': 'Log data access + retention period',
        'deletion': 'Implement right-to-forget (delete user data after 90 days if requested)',
    },
    'PCI-DSS': {
        'credit_card_protection': 'Never log full card numbers; log last 4 digits only',
        'access_control': 'Log all access to card data',
    },
    'SOC_2': {
        'logging': 'Comprehensive audit trail of all security decisions',
        'retention': 'Keep logs for 1 year minimum',
    },
}
```

---

### 20. Cost Estimation

**Gap:** How much does this cost?

**Quick Estimate (conservative):**
```
Gateway infrastructure: $2-5K/month
  - 3 t3.medium instances (AWS): $900/month
  - Load balancer: $500/month
  - Data transfer: $1-3K/month

SIEM infrastructure: $3-10K/month
  - Elasticsearch cluster (managed): $2-5K/month
  - Kafka: $1-3K/month
  - Storage: $0.5-2K/month

Third-party services: $1-2K/month
  - DDoS/WAF (Cloudflare Pro): $200/month
  - Threat intelligence feeds: $500-1K/month
  - Database audit tool: $300-500/month

Team: $800K-1.2M/year
  - 1 Backend engineer: $150-200K
  - 1 DevOps/SRE: $150-200K
  - 1 Security engineer: $150-200K
  - 1 ML engineer (half-time): $75-100K
  - 1 SOC analyst (on-call): $60-80K

TOTAL: $50-100K/month, $600K-1.2M/year
```

---

## UPDATED RECOMMENDATIONS

### Priority 1 (Fix Immediately)
1. ✅ Define risk scoring formula with bounds and normalization
2. ✅ Define baseline trustworthiness criteria (gates)
3. ✅ Solve bootstrap paradox (Day-1 suspicious detection)
4. ✅ Specify event pipeline reliability (Kafka, DLQ)
5. ✅ Define model rollback procedure

### Priority 2 (Fix Before Production)
6. ✅ Database audit strategy (DB engine-specific)
7. ✅ HA design with failover SLA per component
8. ✅ Canary deployment process (phases, metrics, approval)
9. ✅ Incident response workflow (RACI, SLOs)
10. ✅ Analyst workload at scale (sampling strategy)

### Priority 3 (Before Scaling)
11. Device integrity confidence levels
12. Credential rotation SLA
13. Egress anomaly detection specifics
14. ML explainability (SHAP values)
15. Replay protection for sensitive ops

---

## QUALITY SCORE (REVISED)

| Dimension | Score | Comment |
|-----------|-------|---------|
| **Architecture Correctness** | ⭐⭐⭐⭐⭐ | Layered defense-in-depth is sound |
| **Implementation Clarity** | ⭐⭐⭐⭐☆ | MVP is clear; enterprise scaling needs detail |
| **Production Readiness** | ⭐⭐⭐⭐☆ | HA, DR, incident response need specificity |
| **Security Rigor** | ⭐⭐⭐⭐⭐ | Threat modeling, anti-poisoning, explainability excellent |
| **Operationability** | ⭐⭐⭐☆☆ | Analyst workflow, cost, team structure unclear |
| **Risk Management** | ⭐⭐⭐⭐☆ | Rollback, failover defined; edge cases remain |
| **OVERALL** | ⭐⭐⭐⭐☆ | Comprehensive and sound; operationalization gaps remain |

---

## VERDICT

**This architecture is production-ready in spirit, but requires the 20 fixes above before actual deployment.**

The core insight is correct: **Deterministic rules first, ML second, humans in the loop always.**

Start with Phase 1-2, prove the concept on staging, then scale carefully.

---

**Document Version:** 2.0 (Verified & Improved)  
**Next Review:** After Phase 2 completion or when team has > 1M security events

