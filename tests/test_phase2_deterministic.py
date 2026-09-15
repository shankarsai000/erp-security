import time
import uuid
import base64
import json
import pytest
from fastapi.testclient import TestClient
from gateway.app import app
from gateway.credential_defense import credential_defense
from gateway.replay_guard import replay_guard

client = TestClient(app, raise_server_exceptions=False)

def make_jwt(sub: str, role: str, exp_offset: int = 3600) -> str:
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    payload = base64.urlsafe_b64encode(json.dumps({
        "sub": sub,
        "role": role,
        "exp": int(time.time()) + exp_offset
    }).encode()).decode().rstrip("=")
    sig = base64.urlsafe_b64encode(b"simulated_mock_cryptographic_signature").decode().rstrip("=")
    return f"{header}.{payload}.{sig}"

SALES_TOKEN = make_jwt("sales_john", "sales")
ADMIN_TOKEN = make_jwt("admin", "admin")

class TestRouteAllowlist:
    def test_unregistered_route_returns_404(self):
        response = client.get(
            "/api/unknown/backdoor",
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"}
        )
        assert response.status_code == 404
        data = response.json()
        assert data["error"] == "Not Found"
        assert "not registered in API catalog" in data["message"]
        assert response.headers["X-Decision"] == "BLOCK"

    def test_disallowed_method_returns_405(self):
        # /api/orders only allows GET and POST. DELETE is not allowed on collection endpoint.
        response = client.delete(
            "/api/orders",
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"}
        )
        assert response.status_code == 405
        data = response.json()
        assert data["error"] == "Method Not Allowed"
        assert "not permitted on endpoint" in data["message"]

    def test_post_disallowed_on_readonly_inventory(self):
        # /api/inventory only allows GET
        response = client.post(
            "/api/inventory",
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
            json={"sku": "NEW-SKU", "quantity": 10}
        )
        assert response.status_code == 405

class TestStrictSchemaValidation:
    def test_malformed_json_body_returns_400(self):
        response = client.post(
            "/api/orders",
            headers={
                "Authorization": f"Bearer {SALES_TOKEN}",
                "Content-Type": "application/json"
            },
            content='{"customer_id": "cust-1", "items": ["Widget"], "unclosed_brace": 123'
        )
        assert response.status_code == 400
        data = response.json()
        assert data["error"] == "Bad Request"
        assert "Malformed JSON" in data["message"]

    def test_invalid_order_missing_items_returns_422(self):
        response = client.post(
            "/api/orders",
            headers={"Authorization": f"Bearer {SALES_TOKEN}"},
            json={
                "customer_id": "cust-99",
                "items": [],  # Min 1 item required
                "total_amount": 100.0
            }
        )
        assert response.status_code == 422
        data = response.json()
        assert data["error"] == "Unprocessable Entity"
        assert "Schema validation failed" in data["message"]

    def test_invalid_order_negative_amount_returns_422(self):
        response = client.post(
            "/api/orders",
            headers={"Authorization": f"Bearer {SALES_TOKEN}"},
            json={
                "customer_id": "cust-99",
                "items": ["Widget A"],
                "total_amount": -50.0  # Must be > 0
            }
        )
        assert response.status_code == 422

    def test_invalid_login_username_characters_returns_422(self):
        response = client.post(
            "/api/auth/login",
            json={
                "username": "user with spaces",
                "password": "validPassword123"
            }
        )
        assert response.status_code == 422
        data = response.json()
        assert "Schema validation failed" in data["message"]

class TestCredentialAbuseDefense:
    def test_brute_force_lockout_after_consecutive_failures(self):
        attacker_ip = "192.168.100.99"
        credential_defense.reset(attacker_ip)

        # Record 5 consecutive failed logins
        for _ in range(5):
            credential_defense.record_failure(attacker_ip, "admin")

        # The 6th request from this IP must be blocked by the Gateway
        response = client.post(
            "/api/auth/login",
            headers={"X-Forwarded-For": attacker_ip},
            json={"username": "admin", "password": "password123"}
        )
        assert response.status_code == 403
        data = response.json()
        assert data["error"] == "Forbidden"
        assert any("Brute force alert" in r or "Credential abuse" in r for r in data["reasons"])
        assert float(response.headers["X-Risk-Score"]) >= 75.0

        # Reset to avoid polluting subsequent tests
        credential_defense.reset(attacker_ip)

class TestReplayProtection:
    def test_expired_timestamp_rejected(self):
        stale_ts = str(int(time.time()) - 360)  # 6 minutes ago (tolerance 300s)
        response = client.post(
            "/api/orders",
            headers={
                "Authorization": f"Bearer {SALES_TOKEN}",
                "X-Timestamp": stale_ts,
                "X-Nonce": str(uuid.uuid4())
            },
            json={"customer_id": "cust-1", "items": ["Widget A"], "total_amount": 99.0}
        )
        assert response.status_code == 403
        data = response.json()
        assert any("expired" in r.lower() for r in data["reasons"])

    def test_future_timestamp_rejected(self):
        future_ts = str(int(time.time()) + 400)  # Clock skew > 300s
        response = client.post(
            "/api/orders",
            headers={
                "Authorization": f"Bearer {SALES_TOKEN}",
                "X-Timestamp": future_ts,
                "X-Nonce": str(uuid.uuid4())
            },
            json={"customer_id": "cust-1", "items": ["Widget A"], "total_amount": 99.0}
        )
        assert response.status_code == 403
        data = response.json()
        assert any("skew" in r.lower() or "expired" in r.lower() for r in data["reasons"])

    def test_replayed_nonce_rejected(self):
        nonce = f"nonce-{uuid.uuid4()}"
        ts = str(int(time.time()))
        payload = {"customer_id": "cust-1", "items": ["Widget A"], "total_amount": 99.0}

        # First request with this nonce passes replay check
        client_ip = f"10.150.1.{uuid.uuid4().hex[:4]}"
        headers = {
            "Authorization": f"Bearer {SALES_TOKEN}",
            "X-Forwarded-For": client_ip,
            "X-Timestamp": ts,
            "X-Nonce": nonce
        }
        resp1 = client.post(
            "/api/orders",
            headers=headers,
            json=payload
        )
        assert resp1.status_code == 200

        # Duplicate request with the identical nonce must be rejected
        resp2 = client.post(
            "/api/orders",
            headers=headers,
            json=payload
        )
        assert resp2.status_code == 403
        data = resp2.json()
        assert any("replay" in r.lower() for r in data["reasons"])


class TestBOLAandIDORDefense:
    def test_user_cannot_access_other_user_profile(self):
        # sales_john has sub="sales_john". Querying /api/users/1 (admin user) is a BOLA violation.
        response = client.get(
            "/api/users/1",
            headers={"Authorization": f"Bearer {SALES_TOKEN}"}
        )
        assert response.status_code == 403
        data = response.json()
        assert data["error"] == "Forbidden"
        assert any("BOLA violation" in r for r in data["reasons"])
        assert float(response.headers["X-Risk-Score"]) >= 75.0

    def test_admin_can_access_any_user_profile(self):
        # Admin has role="admin". Accessing /api/users/1 or /api/users/2 is allowed.
        response = client.get(
            "/api/users/1",
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["user"]["username"] == "admin"

