import time
import statistics
import pytest
import httpx
from fastapi.testclient import TestClient
from gateway.app import app
import gateway.app as gateway_module

client = TestClient(app, raise_server_exceptions=False)
VALID_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzYWxlc19qb2huIiwicm9sZSI6InNhbGVzIn0.c2ltdWxhdGVkX3NpZw"

def test_gateway_latency_overhead():
    """
    Measures gateway security pipeline latency overhead across 100 requests.
    Target: p95 latency overhead < 20ms.
    Uses mock upstream transport so backend delay is 0ms and pure gateway overhead is measured.
    """
    original_client = gateway_module.http_client
    try:
        # Setup zero-latency mock upstream to isolate pure gateway overhead
        mock_transport = httpx.MockTransport(
            lambda request: httpx.Response(200, json={"order_id": 101, "status": "completed"})
        )
        gateway_module.http_client = httpx.AsyncClient(mounts={"http://": mock_transport, "https://": mock_transport})
        
        # Pre-warm middleware, rate limiter, and logging
        client.get("/api/orders/101", headers={"Authorization": f"Bearer {VALID_JWT}"})
        
        latencies = []
        for i in range(100):
            start = time.perf_counter()
            response = client.get(
                "/api/orders/101",
                headers={"Authorization": f"Bearer {VALID_JWT}"}
            )
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            assert response.status_code == 200
            latencies.append(elapsed_ms)
            
        p50 = statistics.median(latencies)
        sorted_latencies = sorted(latencies)
        p95 = sorted_latencies[int(len(latencies) * 0.95)]
        p99 = sorted_latencies[int(len(latencies) * 0.99)]
        
        print(f"\n[Gateway Security Pipeline Latency Benchmark (100 runs)]")
        print(f"  p50: {p50:.2f} ms")
        print(f"  p95: {p95:.2f} ms (Target: < 20ms)")
        print(f"  p99: {p99:.2f} ms")
        
        assert p95 < 20.0, f"Gateway p95 latency overhead {p95:.2f}ms exceeded 20ms budget!"
    finally:
        gateway_module.http_client = original_client

