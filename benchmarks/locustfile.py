"""
Locust Performance & Load Testing Suite for ERP Security Gateway (PERF-01).

Simulates high-concurrency enterprise traffic over real network sockets:
- 40% Read Inventory: GET /api/inventory
- 40% Read Orders: GET /api/orders/101
- 20% Mutate Orders: POST /api/orders with genuine JWT, freshness headers, and unique nonces
"""

import time
import uuid
from locust import HttpUser, task, between

# Import gateway's authentic token generator
from gateway.auth_engine import auth_engine


class ERPUser(HttpUser):
    wait_time = between(0.01, 0.05)  # 10ms - 50ms pacing for high throughput

    def on_start(self):
        """Pre-generate authentic JWT for the simulated user."""
        self.username = f"user_locust_{uuid.uuid4().hex[:6]}"
        self.token = auth_engine.generate_token(
            principal_id=self.username,
            roles=["sales"],
            expires_in_seconds=3600
        )
        self.auth_headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        }

    @task(4)
    def read_inventory(self):
        """Read-only high-volume query."""
        self.client.get(
            "/api/inventory",
            headers=self.auth_headers,
            name="/api/inventory"
        )

    @task(4)
    def read_order_detail(self):
        """Read-only object query."""
        self.client.get(
            "/api/orders/101",
            headers=self.auth_headers,
            name="/api/orders/{id}"
        )

    @task(2)
    def create_order_mutation(self):
        """State-mutating transaction with fresh idempotency and nonce headers (SEC-03)."""
        nonce = f"nonce-{uuid.uuid4().hex}"
        idemp_key = f"idemp-{uuid.uuid4().hex}"
        timestamp = str(time.time())

        headers = {
            **self.auth_headers,
            "X-Nonce": nonce,
            "Idempotency-Key": idemp_key,
            "X-Timestamp": timestamp
        }
        payload = {
            "customer_id": f"cust-perf-{uuid.uuid4().hex[:6]}",
            "items": ["Widget High-Velocity", "Industrial Bearing"],
            "total_amount": 149.99
        }

        self.client.post(
            "/api/orders",
            headers=headers,
            json=payload,
            name="/api/orders [MUTATION]"
        )
