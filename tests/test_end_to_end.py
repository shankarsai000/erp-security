import pytest
from fastapi.testclient import TestClient
from gateway.app import app

def test_end_to_end_login_and_fetch_orders():
    with TestClient(app, raise_server_exceptions=False) as client:
        # 1. Login through Gateway to acquire JWT from backend fake_erp
        login_resp = client.post(
            "/api/auth/login",
            json={"username": "sales_john", "password": "password123"}
        )
        assert login_resp.status_code == 200
        token_data = login_resp.json()
        assert "access_token" in token_data
        token = token_data["access_token"]
        
        # 2. Query orders with acquired token
        orders_resp = client.get(
            "/api/orders",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert orders_resp.status_code == 200
        orders_data = orders_resp.json()
        assert "orders" in orders_data
        assert len(orders_data["orders"]) >= 2
        assert orders_resp.headers["X-Decision"] == "ALLOW"
        assert "X-Request-ID" in orders_resp.headers
        assert orders_data["forwarded_request_id"] == orders_resp.headers["X-Request-ID"]

def test_end_to_end_single_order_and_inventory():
    with TestClient(app, raise_server_exceptions=False) as client:
        # Authenticate as admin
        login_resp = client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "password123"}
        )
        token = login_resp.json()["access_token"]
        
        # Fetch Order 101 through Gateway
        order_resp = client.get(
            "/api/orders/101",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert order_resp.status_code == 200
        order_data = order_resp.json()
        assert order_data["order"]["order_id"] == 101
        assert order_resp.headers["X-Decision"] == "ALLOW"
        
        # Fetch Inventory through Gateway
        inv_resp = client.get(
            "/api/inventory",
            headers={"Authorization": f"Bearer {token}"}
        )
        assert inv_resp.status_code == 200
        inv_data = inv_resp.json()
        assert inv_data["item_count"] >= 3
