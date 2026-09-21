"""
Unit and integration tests for Real ERP Pre-Flight Connectivity Probe (scripts/probe_real_erp.py)
and Dynamic Route Catalog configuration (gateway/route_allowlist.py).
"""

import threading
import time
import socket
import pytest
from pathlib import Path
import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from scripts.probe_real_erp import ERPProbeRunner
from gateway.route_allowlist import RouteAllowlist, RouteRule


@pytest.fixture(scope="module")
def mock_erp_server():
    """Spins up a lightweight mock ERP server on a random local port for probe testing."""
    test_app = FastAPI()

    @test_app.get("/health")
    def health():
        return {"status": "ok", "system": "mock-real-erp"}

    @test_app.get("/api/v1/ping")
    def ping():
        return {"ping": "pong"}

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    cfg = uvicorn.Config(test_app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(cfg)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    # Wait for server to bind
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                break
        except Exception:
            time.sleep(0.05)

    yield f"http://127.0.0.1:{port}"

    server.should_exit = True
    thread.join(timeout=1.0)


class TestRealERPProbeRunner:
    def test_probe_success_against_mock_erp(self, mock_erp_server):
        runner = ERPProbeRunner(
            target_url=mock_erp_server,
            probe_path="/health",
            auth_type="none",
            timeout_seconds=2.0
        )
        report = runner.run()

        assert report["verdict"] == "PASSED"
        assert report["checks"]["dns"]["status"] == "PASS"
        assert report["checks"]["tcp"]["status"] == "PASS"
        assert report["checks"]["http"]["status"] == "PASS"
        assert report["checks"]["http"]["http_status"] == 200
        assert report["compatibility"]["upstream_responsive"] is True
        assert report["recommended_env"]["BACKEND_URL"] == mock_erp_server

    def test_probe_custom_path_and_auth_headers(self, mock_erp_server):
        runner = ERPProbeRunner(
            target_url=mock_erp_server,
            probe_path="/api/v1/ping",
            auth_type="bearer",
            token="test-mock-token-xyz",
            timeout_seconds=2.0
        )
        report = runner.run()

        assert report["verdict"] == "PASSED"
        assert report["checks"]["http"]["http_status"] == 200

    def test_probe_unreachable_target_fails_cleanly(self):
        runner = ERPProbeRunner(
            target_url="http://127.0.0.1:59998",
            probe_path="/health",
            timeout_seconds=0.5
        )
        report = runner.run()

        assert report["verdict"] == "FAILED"
        assert report["checks"]["tcp"]["status"] == "FAIL"
        assert report["compatibility"]["upstream_responsive"] is False


class TestDynamicRouteCatalog:
    def test_dynamic_add_route(self):
        catalog = RouteAllowlist()
        # Add custom ERP endpoint
        catalog.add_route("/custom/erp/finance", ["GET", "POST"], auth_required=True, roles=["finance"])

        is_known, is_allowed, rule, reason = catalog.validate_route("/custom/erp/finance", "GET")
        assert is_known is True
        assert is_allowed is True
        assert rule.roles == ["finance"]

        # Disallowed method
        is_known, is_allowed, rule, reason = catalog.validate_route("/custom/erp/finance", "DELETE")
        assert is_known is True
        assert is_allowed is False

    def test_wildcard_prefix_matching(self):
        catalog = RouteAllowlist()
        catalog.add_route("/sap/opu/odata/*", ["GET", "POST"], auth_required=True, roles=["sales"])

        is_known, is_allowed, rule, _ = catalog.validate_route("/sap/opu/odata/BILLING_SERVICE/Invoices", "GET")
        assert is_known is True
        assert is_allowed is True

        is_known, is_allowed, rule, _ = catalog.validate_route("/sap/opu/odata", "GET")
        assert is_known is True
        assert is_allowed is True

    def test_load_from_yaml_file(self, tmp_path):
        routes_file = tmp_path / "custom_routes.yaml"
        routes_file.write_text(
            """
routes:
  - path: "/netsuite/rest/v1/records/*"
    methods: ["GET", "POST"]
    auth_required: true
    roles: ["admin"]
  - path: "/dynamics/data/v9.2/accounts"
    methods: ["GET"]
    auth_required: false
""",
            encoding="utf-8"
        )

        catalog = RouteAllowlist()
        count = catalog.load_from_yaml(str(routes_file))
        assert count == 2

        is_known, is_allowed, rule, _ = catalog.validate_route("/netsuite/rest/v1/records/customers", "GET")
        assert is_known is True
        assert rule.roles == ["admin"]

        is_known, is_allowed, rule, _ = catalog.validate_route("/dynamics/data/v9.2/accounts", "GET")
        assert is_known is True
        assert rule.auth_required is False
