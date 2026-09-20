"""
Automated Multi-Threaded Real Socket Benchmark Harness for ERP Security Gateway (PERF-01).

Bypasses in-memory test mocks to validate real socket latency overhead, TCP connection
handling, and concurrency over local network sockets.
"""

import asyncio
import json
import queue
import socket
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any

import httpx
import uvicorn

# Workspace setup
WORKSPACE_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WORKSPACE_ROOT))

from gateway.app import app
from gateway.auth_engine import auth_engine


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class SocketBenchmarkRunner:
    def __init__(self, host: str = "127.0.0.1", concurrency: int = 5, total_requests: int = 50):
        self.host = host
        self.gateway_port = find_free_port()
        self.erp_port = find_free_port()
        self.base_url = f"http://{self.host}:{self.gateway_port}"
        self.concurrency = concurrency
        self.total_requests = total_requests

        self.gateway_server: Optional[uvicorn.Server] = None
        self.erp_server: Optional[uvicorn.Server] = None
        self.gateway_thread: Optional[threading.Thread] = None
        self.erp_thread: Optional[threading.Thread] = None

        # Pre-generate tokens for simulated concurrent users
        self.user_tokens = [
            auth_engine.generate_token(
                principal_id=f"sales_benchmarker_{i}",
                roles=["sales"],
                expires_in_seconds=3600
            )
            for i in range(concurrency)
        ]

    def _wait_for_port(self, port: int, max_retries: int = 60):
        for _ in range(max_retries):
            try:
                with socket.create_connection((self.host, port), timeout=0.1):
                    return
            except (ConnectionRefusedError, OSError):
                time.sleep(0.05)
        raise RuntimeError(f"Server failed to bind to {self.host}:{port}")

    def start_server(self):
        """Starts both upstream ERP and Security Gateway on real TCP loopback sockets."""
        from backend.fake_erp import fake_erp
        from gateway.config import config
        from gateway.ha_dr import circuit_breaker, CircuitBreakerState
        from gateway.rules_engine import rules_engine

        # Configure gateway to point to the live fake_erp socket
        config.backend_url = f"http://{self.host}:{self.erp_port}"
        import gateway.app as gw
        gw.http_client = None  # Reset client so it connects to new URL

        circuit_breaker.state = CircuitBreakerState.CLOSED
        circuit_breaker.failure_count = 0
        rules_engine.reset_state()

        # 1. Start Upstream Fake ERP on TCP socket
        erp_cfg = uvicorn.Config(app=fake_erp, host=self.host, port=self.erp_port, log_level="error", access_log=False)
        self.erp_server = uvicorn.Server(erp_cfg)
        self.erp_thread = threading.Thread(target=self.erp_server.run, daemon=True)
        self.erp_thread.start()
        self._wait_for_port(self.erp_port)

        # 2. Start Security Gateway on TCP socket
        gw_cfg = uvicorn.Config(app=app, host=self.host, port=self.gateway_port, log_level="error", access_log=False)
        self.gateway_server = uvicorn.Server(gw_cfg)
        self.gateway_thread = threading.Thread(target=self.gateway_server.run, daemon=True)
        self.gateway_thread.start()
        self._wait_for_port(self.gateway_port)

    def stop_server(self):
        """Gracefully terminates both Uvicorn instances."""
        if self.gateway_server:
            self.gateway_server.should_exit = True
            if self.gateway_thread and self.gateway_thread.is_alive():
                self.gateway_thread.join(timeout=1.5)
        if self.erp_server:
            self.erp_server.should_exit = True
            if self.erp_thread and self.erp_thread.is_alive():
                self.erp_thread.join(timeout=1.5)

    def _worker(
        self,
        worker_id: int,
        req_queue: queue.Queue,
        results: List[Dict[str, Any]]
    ):
        token = self.user_tokens[worker_id % len(self.user_tokens)]
        headers_base = {
            "Authorization": f"Bearer {token}",
            "X-Forwarded-For": f"198.51.100.{10 + (worker_id % 50)}"
        }
        limits = httpx.Limits(max_connections=10, max_keepalive_connections=10)
        timeout = httpx.Timeout(10.0, connect=5.0)

        with httpx.Client(limits=limits, timeout=timeout) as client:
            # Pre-connect TCP keep-alive connection
            try:
                client.get(f"{self.base_url}/health")
            except Exception:
                pass

            while not req_queue.empty():
                try:
                    req_idx, req_type = req_queue.get_nowait()
                except queue.Empty:
                    break
                t0 = time.perf_counter()
                status_code = 0
                success = False
                try:
                    if req_type == "read_inventory":
                        resp = client.get(
                            f"{self.base_url}/api/inventory",
                            headers=headers_base
                        )
                        status_code = resp.status_code
                        success = (status_code == 200)

                    elif req_type == "read_order":
                        resp = client.get(
                            f"{self.base_url}/api/orders/101",
                            headers=headers_base
                        )
                        status_code = resp.status_code
                        success = (status_code == 200)

                    elif req_type == "mutate_order":
                        nonce = f"sock-nonce-{uuid.uuid4().hex}"
                        idemp = f"sock-idemp-{uuid.uuid4().hex}"
                        resp = client.post(
                            f"{self.base_url}/api/orders",
                            headers={
                                **headers_base,
                                "X-Nonce": nonce,
                                "Idempotency-Key": idemp,
                                "X-Timestamp": str(time.time())
                            },
                            json={
                                "customer_id": f"cust-{uuid.uuid4().hex[:6]}",
                                "items": [f"Turbine-{req_idx}", "Gasket Ring"],
                                "total_amount": 280.0 + (req_idx % 100)
                            }
                        )
                        status_code = resp.status_code
                        success = (status_code == 200)

                except Exception:
                    status_code = 0
                    success = False

                latency_ms = (time.perf_counter() - t0) * 1000.0
                results.append({
                    "req_idx": req_idx,
                    "type": req_type,
                    "latency_ms": latency_ms,
                    "status_code": status_code,
                    "success": success
                })
                req_queue.task_done()

    def run_load_test(self) -> Dict[str, Any]:
        """Runs concurrent client requests over real TCP sockets using thread workers."""
        req_queue: queue.Queue = queue.Queue()
        for i in range(self.total_requests):
            # 50% inventory, 30% order detail, 20% mutation
            if i % 10 < 5:
                req_type = "read_inventory"
            elif i % 10 < 8:
                req_type = "read_order"
            else:
                req_type = "mutate_order"
            req_queue.put((i, req_type))

        results: List[Dict[str, Any]] = []
        t_start = time.perf_counter()
        threads = [
            threading.Thread(target=self._worker, args=(w_id, req_queue, results))
            for w_id in range(self.concurrency)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        total_duration = time.perf_counter() - t_start

        latencies = [r["latency_ms"] for r in results]
        latencies.sort()
        n = len(latencies)

        p50 = latencies[int(n * 0.50)] if n else 0.0
        p95 = latencies[int(n * 0.95)] if n else 0.0
        p99 = latencies[int(n * 0.99)] if n else 0.0
        success_count = sum(1 for r in results if r["success"])
        rps = round(n / total_duration, 2) if total_duration > 0 else 0.0

        read_latencies = [r["latency_ms"] for r in results if "read" in r["type"]]
        read_latencies.sort()
        read_p95 = read_latencies[int(len(read_latencies) * 0.95)] if read_latencies else 0.0

        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": self.base_url,
            "concurrency": self.concurrency,
            "total_requests": n,
            "successful_requests": success_count,
            "success_rate": round(success_count / n, 4) if n else 0.0,
            "total_duration_seconds": round(total_duration, 3),
            "requests_per_second": rps,
            "latency_stats_ms": {
                "min": round(latencies[0], 2) if n else 0.0,
                "p50": round(p50, 2),
                "p95": round(p95, 2),
                "p99": round(p99, 2),
                "max": round(latencies[-1], 2) if n else 0.0,
                "read_p95": round(read_p95, 2)
            },
            "sla_verification": {
                "read_p95_under_80ms": read_p95 < 80.0,
                "overall_success_over_99pct": (success_count / n) >= 0.99 if n else False,
                "sla_passed": read_p95 < 80.0 and ((success_count / n) >= 0.99 if n else False)
            }
        }
        return report

    def prewarm(self):
        """Pre-warms connection pools, ML models, and routing before benchmarking."""
        from gateway.rules_engine import rules_engine
        try:
            with httpx.Client(timeout=5.0) as client:
                client.get(f"{self.base_url}/health")
                client.get(f"{self.base_url}/api/inventory", headers={"Authorization": f"Bearer {self.user_tokens[0]}"})
                client.get(f"{self.base_url}/api/orders/101", headers={"Authorization": f"Bearer {self.user_tokens[0]}"})
                client.post(
                    f"{self.base_url}/api/orders",
                    headers={
                        "Authorization": f"Bearer {self.user_tokens[0]}",
                        "X-Nonce": f"prewarm-nonce-{uuid.uuid4().hex}",
                        "Idempotency-Key": f"prewarm-idemp-{uuid.uuid4().hex}",
                        "X-Timestamp": str(time.time())
                    },
                    json={"customer_id": "prewarm-cust", "items": ["Item A"], "total_amount": 100.0}
                )
            rules_engine.reset_state()
        except Exception:
            pass

    def execute(self) -> Dict[str, Any]:
        """Main execution flow: setup, socket load, teardown, report."""
        print("\n" + "=" * 70)
        print("  ERP SECURITY GATEWAY - REAL SOCKET BENCHMARK (PERF-01)")
        print(f"  Concurrency: {self.concurrency} workers | Requests: {self.total_requests}")
        print("=" * 70)

        try:
            print("  [1/4] Starting gateway on TCP loopback socket...")
            self.start_server()
            print(f"  [2/4] Server listening on {self.base_url}")

            print("  [3/5] Pre-warming gateway connection pools and ML models...")
            self.prewarm()

            print(f"  [4/5] Dispatching {self.total_requests} concurrent socket requests...")
            report = self.run_load_test()

            print("  [5/5] Benchmark completed successfully.")
            print("-" * 70)
            print(f"  Throughput:  {report['requests_per_second']} requests/sec")
            print(f"  Success:     {report['successful_requests']}/{report['total_requests']} ({report['success_rate']*100:.1f}%)")
            print(f"  Socket p50:  {report['latency_stats_ms']['p50']} ms")
            print(f"  Socket p95:  {report['latency_stats_ms']['p95']} ms")
            print(f"  Read p95:    {report['latency_stats_ms']['read_p95']} ms (SLA Target: < 80ms)")
            print(f"  Socket p99:  {report['latency_stats_ms']['p99']} ms")
            sla_status = "PASSED" if report['sla_verification']['sla_passed'] else "FAILED"
            print(f"  SLA Result:  [{sla_status}]")
            print("=" * 70 + "\n")

            # Persist report
            reports_dir = WORKSPACE_ROOT / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            report_file = reports_dir / "socket_benchmark_report.json"
            with open(report_file, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

            return report

        finally:
            self.stop_server()


if __name__ == "__main__":
    runner = SocketBenchmarkRunner(concurrency=4, total_requests=40)
    res = runner.execute()
    passed = res.get("sla_verification", {}).get("sla_passed", False)
    sys.exit(0 if passed else 1)
