import pytest
from fastapi.testclient import TestClient
from gateway.app import app

client = TestClient(app, raise_server_exceptions=False)

VALID_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzYWxlc19qb2huIiwicm9sZSI6InNhbGVzIn0.c2ltdWxhdGVkX3NpZw"

class TestHealthAndBypass:
    def test_health_endpoint_accessible_without_auth(self):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "X-Request-ID" in response.headers

class TestWAFProtection:
    def test_block_sql_injection_in_path(self):
        response = client.get(
            "/api/orders/1' OR '1'='1",
            headers={"Authorization": f"Bearer {VALID_JWT}"}
        )
        assert response.status_code == 403
        data = response.json()
        assert data["error"] == "Forbidden"
        assert any("SQL injection" in r for r in data["reasons"])
        assert float(response.headers["X-Risk-Score"]) >= 75.0

    def test_block_sql_injection_drop_table(self):
        response = client.get(
            "/api/orders/DROP TABLE users",
            headers={"Authorization": f"Bearer {VALID_JWT}"}
        )
        assert response.status_code == 403
        assert response.headers["X-Decision"] == "BLOCK"

    def test_block_sql_injection_in_body(self):
        response = client.post(
            "/api/orders",
            headers={"Authorization": f"Bearer {VALID_JWT}"},
            json={"customer_id": "cust-1", "items": ["Widget"], "query": "UNION SELECT * FROM users"}
        )
        assert response.status_code == 403
        data = response.json()
        assert any("SQL injection" in r for r in data["reasons"])

    def test_block_xss_in_path(self):
        response = client.get(
            "/api/users/<script>alert(1)</script>",
            headers={"Authorization": f"Bearer {VALID_JWT}"}
        )
        assert response.status_code == 403
        data = response.json()
        assert any("XSS" in r for r in data["reasons"])

    def test_block_xss_in_body(self):
        response = client.post(
            "/api/orders",
            headers={"Authorization": f"Bearer {VALID_JWT}"},
            json={"comment": "<img src=x onerror=alert('xss')>"}
        )
        assert response.status_code == 403

    def test_block_path_traversal(self):
        response = client.get(
            "/api/orders?file=../../etc/passwd",
            headers={"Authorization": f"Bearer {VALID_JWT}"}
        )
        assert response.status_code == 403
        data = response.json()
        assert any("Path traversal" in r for r in data["reasons"])

class TestAuthenticationPolicy:
    def test_missing_auth_header_challenged(self):
        response = client.get("/api/orders/101")
        assert response.status_code == 401
        data = response.json()
        assert data["error"] == "Unauthorized"
        assert any("Missing Authorization" in r for r in data["reasons"])
        assert response.headers["X-Decision"] == "CHALLENGE"

    def test_malformed_jwt_token_challenged(self):
        response = client.get(
            "/api/orders/101",
            headers={"Authorization": "Bearer invalid_non_jwt_token"}
        )
        assert response.status_code == 401
        data = response.json()
        assert any("Malformed JWT" in r for r in data["reasons"])

    def test_invalid_auth_scheme_challenged(self):
        response = client.get(
            "/api/orders/101",
            headers={"Authorization": "Basic dXNlcjpwYXNz"}
        )
        assert response.status_code == 401
        assert response.headers["X-Decision"] == "CHALLENGE"

class TestTraceabilityAndHeaders:
    def test_trace_id_propagated_or_generated(self):
        # Custom trace ID
        custom_id = "trace-test-uuid-9999"
        response = client.get("/health", headers={"X-Request-ID": custom_id})
        assert response.headers["X-Request-ID"] == custom_id
