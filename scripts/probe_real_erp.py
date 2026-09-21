"""
Real ERP Integration & Pre-Flight Connectivity Diagnostic Probe.

Automated utility to test network reachability, TLS certificates, TCP handshake,
HTTP latency, and API compatibility before pointing the ERP Security Gateway
to a live or staging ERP instance (SAP, Oracle NetSuite, Dynamics 365, custom).
"""

import argparse
import json
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent


class ERPProbeRunner:
    def __init__(
        self,
        target_url: str,
        probe_path: str = "/health",
        auth_type: str = "none",
        token: Optional[str] = None,
        api_key: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: bool = True,
        timeout_seconds: float = 5.0,
    ):
        self.target_url = target_url.rstrip("/")
        self.probe_path = ("/" + probe_path.lstrip("/")) if probe_path else "/health"
        self.auth_type = auth_type.lower()
        self.token = token
        self.api_key = api_key
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.timeout_seconds = timeout_seconds

        parsed = urlparse(self.target_url)
        self.scheme = parsed.scheme or "http"
        self.hostname = parsed.hostname or "127.0.0.1"
        self.port = parsed.port or (443 if self.scheme == "https" else 80)
        self.full_probe_url = f"{self.target_url}{self.probe_path}"

        self.report: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target": {
                "base_url": self.target_url,
                "scheme": self.scheme,
                "hostname": self.hostname,
                "port": self.port,
                "probe_path": self.probe_path,
                "full_url": self.full_probe_url,
            },
            "checks": {},
            "latency_ms": {},
            "compatibility": {},
            "verdict": "PENDING",
            "recommended_env": {},
        }

    def check_dns(self) -> bool:
        """Resolves target hostname to IP address."""
        t0 = time.perf_counter()
        try:
            addr_info = socket.getaddrinfo(self.hostname, self.port)
            ips = list({item[4][0] for item in addr_info})
            duration_ms = (time.perf_counter() - t0) * 1000.0
            self.report["checks"]["dns"] = {
                "status": "PASS",
                "resolved_ips": ips,
                "duration_ms": round(duration_ms, 2),
            }
            return True
        except Exception as exc:
            self.report["checks"]["dns"] = {
                "status": "FAIL",
                "error": str(exc),
            }
            return False

    def check_tcp(self) -> bool:
        """Establishes raw TCP socket connection and measures connect latency."""
        t0 = time.perf_counter()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout_seconds)
        try:
            sock.connect((self.hostname, self.port))
            duration_ms = (time.perf_counter() - t0) * 1000.0
            self.report["checks"]["tcp"] = {
                "status": "PASS",
                "host": self.hostname,
                "port": self.port,
                "connect_latency_ms": round(duration_ms, 2),
            }
            return True
        except Exception as exc:
            self.report["checks"]["tcp"] = {
                "status": "FAIL",
                "host": self.hostname,
                "port": self.port,
                "error": str(exc),
            }
            return False
        finally:
            sock.close()

    def check_tls(self) -> bool:
        """Validates TLS handshake, certificate validity, and encryption cipher."""
        if self.scheme != "https":
            self.report["checks"]["tls"] = {
                "status": "SKIPPED",
                "reason": "HTTP target scheme does not utilize TLS",
            }
            return True

        t0 = time.perf_counter()
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((self.hostname, self.port), timeout=self.timeout_seconds) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    duration_ms = (time.perf_counter() - t0) * 1000.0
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    self.report["checks"]["tls"] = {
                        "status": "PASS",
                        "tls_version": version,
                        "cipher": cipher[0] if cipher else "unknown",
                        "handshake_latency_ms": round(duration_ms, 2),
                        "cert_subject": dict(x[0] for x in cert.get("subject", [])) if cert else "none",
                        "cert_expires": cert.get("notAfter", "unknown") if cert else "unverified (insecure mode)",
                    }
                    return True
        except Exception as exc:
            self.report["checks"]["tls"] = {
                "status": "FAIL",
                "error": str(exc),
            }
            return False

    def check_http_probe(self) -> bool:
        """Sends an HTTP GET probe and inspects upstream status, headers, and latency."""
        headers = {
            "User-Agent": "ERP-Security-Gateway-Probe/2.0",
            "Accept": "application/json, text/plain, */*",
        }
        if self.auth_type == "bearer" and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        elif self.auth_type == "api-key" and self.api_key:
            headers["X-API-Key"] = self.api_key
        elif self.auth_type == "basic" and self.username and self.password:
            import base64
            cred = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            headers["Authorization"] = f"Basic {cred}"

        t0 = time.perf_counter()
        try:
            with httpx.Client(verify=self.verify_ssl, timeout=self.timeout_seconds) as client:
                resp = client.get(self.full_probe_url, headers=headers)
                latency_ms = (time.perf_counter() - t0) * 1000.0
                body_sample = resp.text[:300] if resp.text else ""

                self.report["checks"]["http"] = {
                    "status": "PASS" if resp.status_code < 500 else "FAIL",
                    "http_status": resp.status_code,
                    "latency_ms": round(latency_ms, 2),
                    "server_header": resp.headers.get("Server", "undisclosed"),
                    "content_type": resp.headers.get("Content-Type", "unknown"),
                    "body_snippet": body_sample,
                }
                return resp.status_code < 500
        except Exception as exc:
            duration_ms = (time.perf_counter() - t0) * 1000.0
            self.report["checks"]["http"] = {
                "status": "FAIL",
                "error": str(exc),
                "duration_ms": round(duration_ms, 2),
            }
            return False

    def evaluate_compatibility(self) -> Dict[str, Any]:
        """Evaluates gateway latency budget, keep-alive, and security compatibility."""
        http_check = self.report["checks"].get("http", {})
        latency = http_check.get("latency_ms", 9999.0)
        status_code = http_check.get("http_status", 0)

        meets_latency_budget = latency < 250.0  # Production ERP upstream budget
        is_responsive = 200 <= status_code < 500

        self.report["compatibility"] = {
            "upstream_responsive": is_responsive,
            "latency_acceptable_for_gateway": meets_latency_budget,
            "observed_latency_ms": latency,
            "recommended_sla_tier": "FAST (<50ms)" if latency < 50 else ("NORMAL (<250ms)" if latency < 250 else "SLOW (>250ms)"),
        }

        dns_pass = self.report["checks"].get("dns", {}).get("status") == "PASS"
        tcp_pass = self.report["checks"].get("tcp", {}).get("status") == "PASS"
        tls_pass = self.report["checks"].get("tls", {}).get("status") in ("PASS", "SKIPPED")
        http_pass = is_responsive

        all_passed = dns_pass and tcp_pass and tls_pass and http_pass
        self.report["verdict"] = "PASSED" if all_passed else "FAILED"

        self.report["recommended_env"] = {
            "BACKEND_URL": self.target_url,
            "ENVIRONMENT": "staging",
            "GATEWAY_PORT": 8000,
            "UPSTREAM_TIMEOUT": str(max(5.0, round(latency * 3 / 1000.0, 1))),
        }
        return self.report["compatibility"]

    def run(self) -> Dict[str, Any]:
        """Executes full diagnostic test suite and prints results."""
        print("\n" + "=" * 75)
        print("   ERP SECURITY GATEWAY - REAL ERP PRE-FLIGHT CONNECTIVITY PROBE")
        print(f"   Target URL:  {self.target_url}")
        print(f"   Probe Path:  {self.probe_path}")
        print(f"   Auth Scheme: {self.auth_type.upper()}")
        print(f"   Timestamp:   {self.report['timestamp']}")
        print("=" * 75)

        # 1. DNS Resolution
        print("\n[Step 1/4] Resolving DNS for host:", self.hostname)
        dns_ok = self.check_dns()
        if dns_ok:
            ips = ", ".join(self.report["checks"]["dns"]["resolved_ips"])
            ms = self.report["checks"]["dns"]["duration_ms"]
            print(f"  --> [PASS] Resolved to [{ips}] in {ms}ms")
        else:
            print(f"  --> [FAIL] DNS resolution failed: {self.report['checks']['dns'].get('error')}")

        # 2. TCP Socket Connection
        print(f"\n[Step 2/4] Testing TCP Socket Connection to {self.hostname}:{self.port}")
        tcp_ok = self.check_tcp()
        if tcp_ok:
            ms = self.report["checks"]["tcp"]["connect_latency_ms"]
            print(f"  --> [PASS] TCP handshaked successfully in {ms}ms")
        else:
            print(f"  --> [FAIL] TCP connection failed: {self.report['checks']['tcp'].get('error')}")

        # 3. TLS Handshake & Cipher Check
        if self.scheme == "https":
            print(f"\n[Step 3/4] Validating TLS Handshake & Security Certificates")
            tls_ok = self.check_tls()
            if tls_ok:
                v = self.report["checks"]["tls"]["tls_version"]
                c = self.report["checks"]["tls"]["cipher"]
                ms = self.report["checks"]["tls"]["handshake_latency_ms"]
                print(f"  --> [PASS] TLS established: {v} ({c}) in {ms}ms")
            else:
                print(f"  --> [FAIL] TLS negotiation failed: {self.report['checks']['tls'].get('error')}")
        else:
            print(f"\n[Step 3/4] TLS Check: Skipped (plain HTTP target)")
            self.check_tls()

        # 4. HTTP Request & Latency Check
        print(f"\n[Step 4/4] Sending Non-Destructive HTTP GET to {self.full_probe_url}")
        http_ok = self.check_http_probe()
        if http_ok:
            sc = self.report["checks"]["http"]["http_status"]
            ms = self.report["checks"]["http"]["latency_ms"]
            srv = self.report["checks"]["http"]["server_header"]
            print(f"  --> [PASS] HTTP Response: {sc} OK | Latency: {ms}ms | Upstream Server: {srv}")
        else:
            err = self.report["checks"]["http"].get("error", f"Status {self.report['checks']['http'].get('http_status')}")
            print(f"  --> [FAIL] HTTP Probe failed: {err}")

        # Summary & Compatibility Evaluation
        self.evaluate_compatibility()
        print("\n" + "-" * 75)
        print("   PRE-FLIGHT DIAGNOSTIC VERDICT")
        print("-" * 75)
        print(f"   Connectivity Status:  [{self.report['verdict']}]")
        print(f"   Upstream Responsive:  {self.report['compatibility']['upstream_responsive']}")
        print(f"   Round-Trip Latency:   {self.report['compatibility']['observed_latency_ms']} ms")
        print(f"   Gateway Budget Fit:   {self.report['compatibility']['latency_acceptable_for_gateway']}")
        print(f"   Latency Tier:         {self.report['compatibility']['recommended_sla_tier']}")
        print("-" * 75)

        if self.report["verdict"] == "PASSED":
            print("\n   [RECOMMENDED .env CONFIGURATION]")
            print(f"   BACKEND_URL=\"{self.target_url}\"")
            print(f"   ENVIRONMENT=\"staging\"")
            print(f"   GATEWAY_PORT=8000")
            print("=" * 75 + "\n")
        else:
            print("\n   [ACTION REQUIRED]")
            print("   Please ensure target ERP host is reachable from this machine and not blocked by firewall/VPN.")
            print("=" * 75 + "\n")

        # Save report
        reports_dir = WORKSPACE_ROOT / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        report_path = reports_dir / "real_erp_probe_report.json"
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(self.report, f, indent=2)

        return self.report


def parse_args():
    parser = argparse.ArgumentParser(description="ERP Security Gateway - Real ERP Pre-Flight Connectivity Probe")
    parser.add_argument("--url", type=str, default="http://127.0.0.1:8001", help="Base URL of target ERP system (e.g. https://erp.internal.corp:8443)")
    parser.add_argument("--path", type=str, default="/health", help="Relative path for non-destructive health/probe request (default: /health)")
    parser.add_argument("--auth", type=str, default="none", choices=["none", "bearer", "basic", "api-key"], help="Authentication scheme")
    parser.add_argument("--token", type=str, default=None, help="Bearer JWT token (for --auth bearer)")
    parser.add_argument("--api-key", type=str, default=None, help="API Key header value (for --auth api-key)")
    parser.add_argument("--user", type=str, default=None, help="Username (for --auth basic)")
    parser.add_argument("--password", type=str, default=None, help="Password (for --auth basic)")
    parser.add_argument("--insecure", action="store_true", help="Allow self-signed or invalid TLS certificates (for internal staging)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Connection timeout in seconds (default: 5.0)")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    runner = ERPProbeRunner(
        target_url=args.url,
        probe_path=args.path,
        auth_type=args.auth,
        token=args.token,
        api_key=args.api_key,
        username=args.user,
        password=args.password,
        verify_ssl=not args.insecure,
        timeout_seconds=args.timeout,
    )
    result = runner.run()
    sys.exit(0 if result["verdict"] == "PASSED" else 1)
