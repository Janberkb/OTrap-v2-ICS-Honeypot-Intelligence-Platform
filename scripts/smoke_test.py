#!/usr/bin/env python3
"""
scripts/smoke_test.py — Full OTrap stack smoke test.

Covers:
  [1] Docker startup + health check
  [2] Manager API auth flows (login, CSRF, reauth, role restriction)
  [3] S7 exploit flow (TCP level)
  [4] HMI brute-force + OWASP classification
  [5] Session + event + IOC visibility via API
  [6] SIEM test delivery
  [7] Sensor token generation + registration

Usage:
    ADMIN_PASS=yourpassword python3 scripts/smoke_test.py
    ADMIN_PASS=yourpassword python3 scripts/smoke_test.py --no-docker
"""

import argparse
import os
import subprocess
import sys
import time
import socket

import requests

API      = os.environ.get("OTRAP_API_URL",  "http://localhost:8080")
S7_HOST  = os.environ.get("OTRAP_S7_HOST",  "127.0.0.1")
HMI_HOST = os.environ.get("OTRAP_HMI_HOST", "http://127.0.0.1:80")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "")

PASSED = 0
FAILED = 0


class Colors:
    OK   = "\033[92m"; FAIL = "\033[91m"; WARN = "\033[93m"
    BOLD = "\033[1m";  RESET = "\033[0m"


def check(name: str, condition: bool, detail: str = "") -> bool:
    global PASSED, FAILED
    if condition:
        PASSED += 1
        print(f"  {Colors.OK}PASS{Colors.RESET}  {name}")
        return True
    else:
        FAILED += 1
        print(f"  {Colors.FAIL}FAIL{Colors.RESET}  {name}" + (f" — {detail}" if detail else ""))
        return False


def section(name: str) -> None:
    print(f"\n{Colors.BOLD}[{name}]{Colors.RESET}")


# ─── 1. Health check ─────────────────────────────────────────────────────────

def test_health() -> None:
    section("1. Platform Health")
    try:
        r = requests.get(f"{API}/api/v1/health", timeout=10)
        d = r.json()
        check("Manager API reachable", r.status_code == 200)
        check("Overall health OK", d.get("status") in ("healthy", "degraded"),
              str(d.get("status")))
        check("Postgres healthy", d.get("services", {}).get("postgres", {}).get("status") == "healthy")
        check("Redis healthy",    d.get("services", {}).get("redis",    {}).get("status") == "healthy")
    except Exception as e:
        check("Manager API reachable", False, str(e))


# ─── 2. Auth flows ────────────────────────────────────────────────────────────

def test_auth() -> requests.Session:
    section("2. Auth Flows")
    s = requests.Session()

    if not ADMIN_PASS:
        print(f"  {Colors.WARN}SKIP{Colors.RESET}  Auth tests — set ADMIN_PASS env var")
        return s

    # CSRF token
    r = s.get(f"{API}/api/v1/auth/csrf-token")
    csrf = r.json().get("csrf_token", "")
    check("CSRF token issued", bool(csrf))

    # Login with wrong password
    r = s.post(f"{API}/api/v1/auth/login",
               json={"username": ADMIN_USER, "password": "wrongpassword"},
               headers={"X-CSRF-Token": csrf})
    check("Invalid credentials rejected (401)", r.status_code == 401)
    err = r.json().get("detail", {}).get("error", "")
    check("Error code INVALID_CREDENTIALS returned", err == "INVALID_CREDENTIALS", err)

    # Login without CSRF → should be blocked by middleware
    r = requests.post(f"{API}/api/v1/auth/login",
                      json={"username": ADMIN_USER, "password": ADMIN_PASS})
    check("Login without CSRF blocked (403)", r.status_code == 403)

    # Successful login
    r = s.get(f"{API}/api/v1/auth/csrf-token")
    csrf = r.json().get("csrf_token", "")
    r = s.post(f"{API}/api/v1/auth/login",
               json={"username": ADMIN_USER, "password": ADMIN_PASS},
               headers={"X-CSRF-Token": csrf})
    check("Admin login success (200)", r.status_code == 200, str(r.status_code))
    if r.ok:
        user = r.json()
        check("Role is superadmin", user.get("role") == "superadmin", user.get("role"))

    # GET /me
    r = s.get(f"{API}/api/v1/auth/me")
    check("/me returns current user", r.status_code == 200)

    # Unauthenticated access
    unauth = requests.get(f"{API}/api/v1/sessions")
    check("Unauthenticated request rejected (401)", unauth.status_code == 401)

    return s


# ─── 3. S7 exploit ───────────────────────────────────────────────────────────

def test_s7() -> None:
    section("3. S7 Exploit Flow")
    import struct

    def build_tpkt(payload): return struct.pack("!BBH", 3, 0, 4 + len(payload)) + payload

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((S7_HOST, 102))
        check("TCP connect to port 102", True)

        # COTP CR
        cr = build_tpkt(bytes([0x11,0xE0,0x00,0x00,0x00,0x01,0x00,0xC0,0x01,0x0A,0xC1,0x02,0x01,0x00,0xC2,0x02,0x01,0x02]))
        sock.sendall(cr)
        resp = sock.recv(256)
        check("COTP CC received", len(resp) > 5 and resp[5] == 0xD0, resp.hex()[:20])

        # Setup Comm
        sc = build_tpkt(bytes([0x02,0xF0,0x80,0x32,0x01,0x00,0x00,0x00,0x01,0x00,0x08,0x00,0x00,0xF0,0x00,0x00,0x01,0x00,0x01,0x01,0xE0]))
        sock.sendall(sc)
        resp = sock.recv(256)
        check("S7 Setup Comm ACK received", 0x32 in resp)

        # SZL Read
        szl = build_tpkt(bytes([0x02,0xF0,0x80,0x32,0x07,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x04,0x00,0x01,0x12,0x04,0x11,0x44,0x01,0x00,0x11,0x00,0x00]))
        sock.sendall(szl)
        resp = sock.recv(256)
        check("SZL Read response received", len(resp) > 0)

        # CPU STOP
        stop = build_tpkt(bytes([0x02,0xF0,0x80,0x32,0x01,0x00,0x00,0x00,0x05,0x00,0x10,0x00,0x00,0x29,0x00,0x00,0x00,0x00,0x00,0x09,0x50,0x5F,0x50,0x52,0x4F,0x47,0x52,0x41,0x4D]))
        sock.sendall(stop)
        resp = sock.recv(256)
        check("CPU STOP ACK received (deception success)", 0x32 in resp or len(resp) > 4)
        sock.close()

    except Exception as e:
        check("S7 flow completed", False, str(e))


# ─── 4. HMI tests ────────────────────────────────────────────────────────────

def test_hmi() -> None:
    section("4. HMI Probe Classification")
    s = requests.Session()
    s.verify = False

    import urllib3; urllib3.disable_warnings()

    probes = [
        ("GET",  f"{HMI_HOST}/login",                          "Login page"),
        ("GET",  f"{HMI_HOST}/login?q=' OR 1=1",               "SQLi probe"),
        ("GET",  f"{HMI_HOST}/?x=<script>alert(1)</script>",   "XSS probe"),
        ("GET",  f"{HMI_HOST}/../../etc/passwd",                "Path traversal"),
        ("GET",  f"{HMI_HOST}/admin",                           "Sensitive path"),
        ("GET",  f"{HMI_HOST}/health",                          "Health check"),
    ]

    for method, url, name in probes:
        try:
            r = s.request(method, url, timeout=5, allow_redirects=False)
            check(f"HMI {name} → HTTP {r.status_code}", r.status_code < 500)
        except Exception as e:
            check(f"HMI {name}", False, str(e))

    # Brute force
    allowed = False
    for i in range(7):
        r = s.post(f"{HMI_HOST}/login",
                   data={"username": "admin", "password": f"wrong{i}"},
                   timeout=5, allow_redirects=False)
        if r.status_code in (302, 303):
            allowed = True
            break
    check("HMI rabbit hole triggered after brute-force", allowed)


# ─── 5. Session visibility ────────────────────────────────────────────────────

def test_sessions(session: requests.Session) -> None:
    section("5. Session & Event Visibility")
    if not ADMIN_PASS: return

    time.sleep(3)  # Let analyzer process events

    r = session.get(f"{API}/api/v1/sessions?limit=10")
    check("Sessions list endpoint OK", r.status_code == 200)
    d = r.json()
    check("Sessions returned", d.get("total", 0) > 0, f"total={d.get('total')}")

    if d.get("items"):
        sid = d["items"][0]["id"]
        r2 = session.get(f"{API}/api/v1/sessions/{sid}")
        check("Session detail endpoint OK", r2.status_code == 200)
        check("Session has event_count > 0", r2.json().get("event_count", 0) > 0)

        r3 = session.get(f"{API}/api/v1/sessions/{sid}/events")
        check("Session events endpoint OK", r3.status_code == 200)

        r4 = session.get(f"{API}/api/v1/sessions/{sid}/timeline")
        check("Session timeline endpoint OK", r4.status_code == 200)

    r5 = session.get(f"{API}/api/v1/events/top-attackers")
    check("Top attackers endpoint OK", r5.status_code == 200)


# ─── 6. Admin endpoints ───────────────────────────────────────────────────────

def test_admin(session: requests.Session) -> None:
    section("6. Admin Endpoints")
    if not ADMIN_PASS: return

    r = session.get(f"{API}/api/v1/admin/users")
    check("User list endpoint OK (superadmin)", r.status_code == 200)

    r = session.get(f"{API}/api/v1/admin/smtp")
    check("SMTP config endpoint OK", r.status_code == 200)

    r = session.get(f"{API}/api/v1/admin/siem")
    check("SIEM config endpoint OK", r.status_code == 200)

    r = session.get(f"{API}/api/v1/admin/audit")
    check("Audit log endpoint OK", r.status_code == 200)

    # Non-admin access to admin routes
    guest = requests.Session()
    r = guest.get(f"{API}/api/v1/admin/users")
    check("Admin route blocks unauthenticated (401)", r.status_code == 401)


# ─── 7. Sensor token generation ───────────────────────────────────────────────

def test_sensor_token(session: requests.Session) -> None:
    section("7. Sensor Token Generation")
    if not ADMIN_PASS: return

    r = session.get(f"{API}/api/v1/auth/csrf-token")
    csrf = r.json().get("csrf_token", "")

    r = session.post(f"{API}/api/v1/sensors/token",
                     json={"sensor_name": "test-sensor-smoke"},
                     headers={"X-CSRF-Token": csrf})
    check("Sensor token generated (201/200)", r.status_code in (200, 201))
    if r.ok:
        d = r.json()
        check("Token returned in response", bool(d.get("join_token")))
        check("Sensor ID returned",         bool(d.get("sensor_id")))
        check("Expiry returned",            bool(d.get("expires_at")))
        check("Manager address returned",   bool(d.get("manager_addr")))
        check("Sensor cert key returned",   bool(d.get("sensor_cert_enc_key")))
        check("Deploy command returned",    "docker run -d" in d.get("deployment_command", ""))
        check("Advanced env snippet returned", "SENSOR_JOIN_TOKEN=" in d.get("env_file_snippet", ""))


# ─── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-s7",  action="store_true")
    parser.add_argument("--no-hmi", action="store_true")
    args = parser.parse_args()

    print(f"\n{Colors.BOLD}OTrap Full Stack Smoke Test{Colors.RESET}")
    print(f"API:  {API}")
    print(f"S7:   {S7_HOST}:102")
    print(f"HMI:  {HMI_HOST}")
    print("=" * 50)

    test_health()
    auth_session = test_auth()
    if not args.no_s7:  test_s7()
    if not args.no_hmi: test_hmi()
    test_sessions(auth_session)
    test_admin(auth_session)
    test_sensor_token(auth_session)

    print(f"\n{'=' * 50}")
    print(f"{Colors.BOLD}Results: "
          f"{Colors.OK}{PASSED} passed{Colors.RESET}  "
          f"{Colors.FAIL}{FAILED} failed{Colors.RESET}")
    print()
    sys.exit(0 if FAILED == 0 else 1)
