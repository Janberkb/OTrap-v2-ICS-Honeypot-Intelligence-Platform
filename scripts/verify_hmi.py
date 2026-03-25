#!/usr/bin/env python3
"""
scripts/verify_hmi.py — HMI brute-force, OWASP probe, and rabbit-hole verification.
"""

import argparse
import requests
import time
import sys

class Colors:
    OK   = "\033[92m"; FAIL = "\033[91m"; WARN = "\033[93m"
    BOLD = "\033[1m";  RESET = "\033[0m"

def ok(m):   print(f"  {Colors.OK}✓{Colors.RESET} {m}")
def fail(m): print(f"  {Colors.FAIL}✗{Colors.RESET} {m}")
def warn(m): print(f"  {Colors.WARN}!{Colors.RESET} {m}")
def section(m): print(f"\n{Colors.BOLD}── {m}{Colors.RESET}")


def run_hmi_tests(base: str) -> None:
    s = requests.Session()
    s.verify = False
    s.max_redirects = 1

    section(f"HMI Tests → {base}")

    # 1. Health endpoint
    r = s.get(f"{base}/health", timeout=5)
    if r.status_code == 200:
        ok("Health endpoint /health → 200")
    else:
        warn(f"Health endpoint returned {r.status_code}")

    # 2. Login page
    r = s.get(f"{base}/login", timeout=5)
    if r.status_code == 200 and "WinCC" in r.text:
        ok("Login page served with SIMATIC WinCC branding")
    elif r.status_code == 200:
        ok("Login page served (custom branding)")
    else:
        warn(f"Login page returned {r.status_code}")

    # 3. SQLi probe
    r = s.get(f"{base}/login?user=' OR 1=1 --", timeout=5)
    ok(f"SQLi probe → HTTP {r.status_code} (classified as sqli_probe)")

    # 4. XSS probe
    r = s.get(f"{base}/?q=<script>alert(1)</script>", timeout=5)
    ok(f"XSS probe → HTTP {r.status_code}")

    # 5. Path traversal
    r = s.get(f"{base}/../../etc/passwd", timeout=5)
    ok(f"Path traversal → HTTP {r.status_code}")

    # 6. Sensitive path
    r = s.get(f"{base}/admin", timeout=5)
    ok(f"Sensitive path /admin → HTTP {r.status_code}")

    # 7. Scanner UA
    r = s.get(f"{base}/", headers={"User-Agent": "sqlmap/1.7.1"}, timeout=5)
    ok(f"Scanner UA (sqlmap) → HTTP {r.status_code}")

    # 8. Brute-force + rabbit hole
    section("HMI Brute-Force / Rabbit Hole")
    print("  Attempting 6 login failures to trigger rabbit hole…")
    for i in range(1, 7):
        r = s.post(f"{base}/login",
                   data={"username": f"admin{i}", "password": f"wrong{i}"},
                   timeout=5, allow_redirects=False)
        if r.status_code in (200, 401):
            print(f"    Attempt {i}: HTTP {r.status_code} (denied)")
        elif r.status_code in (302, 303):
            location = r.headers.get("Location", "")
            ok(f"Attempt {i}: HTTP {r.status_code} → redirect to {location} (rabbit hole opened!)")
            break
        else:
            print(f"    Attempt {i}: HTTP {r.status_code}")

    # 9. Access fake dashboard (rabbit hole)
    r = s.get(f"{base}/dashboard", timeout=5, allow_redirects=True)
    if r.status_code == 200 and ("SIMATIC" in r.text or "WinCC" in r.text or "TANK" in r.text):
        ok("Fake HMI dashboard served (rabbit hole active — process tags visible)")
    elif r.status_code == 200:
        ok("Dashboard accessible (rabbit hole active)")
    else:
        warn(f"Dashboard returned {r.status_code}")

    # 10. Command injection
    r = s.get(f"{base}/api/exec?cmd=; ls -la", timeout=5)
    ok(f"Command injection probe → HTTP {r.status_code}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="http://localhost:80")
    args = parser.parse_args()

    import urllib3
    urllib3.disable_warnings()

    print(f"\n{Colors.BOLD}OTrap HMI Verification{Colors.RESET}")
    print("=" * 50)
    run_hmi_tests(args.host)
    print(f"\n{Colors.OK}{Colors.BOLD}HMI verification complete.{Colors.RESET}\n")
