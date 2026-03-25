"""
tests/test_api.py — Manager API integration tests.

Run with:
    pytest tests/test_api.py -v
    ADMIN_PASS=yourpassword pytest tests/test_api.py -v

Prerequisites:
    - Manager running at OTRAP_API_URL (default: http://localhost:8080)
    - Correct ADMIN_PASS set
"""

from __future__ import annotations

import os
import pytest
import requests

BASE      = os.environ.get("OTRAP_API_URL",  "http://localhost:8080")
API       = f"{BASE}/api/v1"
ADMIN     = os.environ.get("ADMIN_USER",     "admin")
PASS      = os.environ.get("ADMIN_PASS",     "")
SKIP_AUTH = not PASS


# ─── Session fixture ──────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def auth_session() -> requests.Session:
    if SKIP_AUTH:
        pytest.skip("Set ADMIN_PASS to run auth tests")
    s = requests.Session()
    r = s.get(f"{API}/auth/csrf-token")
    csrf = r.json()["csrf_token"]
    r = s.post(f"{API}/auth/login",
               json={"username": ADMIN, "password": PASS},
               headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200, f"Login failed: {r.text}"
    s.headers["X-CSRF-Token"] = csrf
    return s


# ─── Health tests ─────────────────────────────────────────────────────────────

class TestHealth:
    def test_health_endpoint_reachable(self):
        r = requests.get(f"{API}/health")
        assert r.status_code == 200

    def test_health_returns_status(self):
        r = requests.get(f"{API}/health")
        d = r.json()
        assert "status" in d
        assert d["status"] in ("healthy", "degraded")

    def test_health_has_postgres_service(self):
        r = requests.get(f"{API}/health")
        svcs = r.json().get("services", {})
        assert "postgres" in svcs

    def test_health_has_redis_service(self):
        r = requests.get(f"{API}/health")
        svcs = r.json().get("services", {})
        assert "redis" in svcs


# ─── Auth tests ───────────────────────────────────────────────────────────────

class TestAuth:
    def test_csrf_token_issued(self):
        s = requests.Session()
        r = s.get(f"{API}/auth/csrf-token")
        assert r.status_code == 200
        assert "csrf_token" in r.json()
        assert "csrf_token" in r.cookies

    def test_login_without_csrf_blocked(self):
        r = requests.post(f"{API}/auth/login",
                          json={"username": ADMIN, "password": PASS})
        assert r.status_code == 403
        assert r.json()["error"] in ("CSRF_REQUIRED", "CSRF_FAILED")

    @pytest.mark.skipif(SKIP_AUTH, reason="No ADMIN_PASS")
    def test_login_wrong_password(self):
        s = requests.Session()
        csrf = s.get(f"{API}/auth/csrf-token").json()["csrf_token"]
        r = s.post(f"{API}/auth/login",
                   json={"username": ADMIN, "password": "wrongpassword"},
                   headers={"X-CSRF-Token": csrf})
        assert r.status_code == 401
        assert r.json()["detail"]["error"] == "INVALID_CREDENTIALS"

    @pytest.mark.skipif(SKIP_AUTH, reason="No ADMIN_PASS")
    def test_login_success(self, auth_session):
        r = auth_session.get(f"{API}/auth/me")
        assert r.status_code == 200
        d = r.json()
        assert d["username"] == ADMIN
        assert d["role"] == "superadmin"

    def test_unauthenticated_sessions_blocked(self):
        r = requests.get(f"{API}/sessions")
        assert r.status_code == 401

    def test_unauthenticated_admin_blocked(self):
        r = requests.get(f"{API}/admin/users")
        assert r.status_code == 401


# ─── Sessions tests ───────────────────────────────────────────────────────────

class TestSessions:
    @pytest.mark.skipif(SKIP_AUTH, reason="No ADMIN_PASS")
    def test_sessions_list(self, auth_session):
        r = auth_session.get(f"{API}/sessions")
        assert r.status_code == 200
        d = r.json()
        assert "total" in d
        assert "items" in d
        assert isinstance(d["items"], list)

    @pytest.mark.skipif(SKIP_AUTH, reason="No ADMIN_PASS")
    def test_sessions_filter_severity(self, auth_session):
        r = auth_session.get(f"{API}/sessions?severity=critical")
        assert r.status_code == 200
        for item in r.json()["items"]:
            assert item["severity"] == "critical"

    @pytest.mark.skipif(SKIP_AUTH, reason="No ADMIN_PASS")
    def test_sessions_filter_cpu_stop(self, auth_session):
        r = auth_session.get(f"{API}/sessions?cpu_stop=true")
        assert r.status_code == 200
        for item in r.json()["items"]:
            assert item["cpu_stop_occurred"] is True

    @pytest.mark.skipif(SKIP_AUTH, reason="No ADMIN_PASS")
    def test_sessions_export_csv(self, auth_session):
        r = auth_session.get(f"{API}/sessions/export/csv")
        assert r.status_code == 200
        assert "text/csv" in r.headers.get("Content-Type", "")

    @pytest.mark.skipif(SKIP_AUTH, reason="No ADMIN_PASS")
    def test_sessions_pagination(self, auth_session):
        r1 = auth_session.get(f"{API}/sessions?limit=5&offset=0")
        r2 = auth_session.get(f"{API}/sessions?limit=5&offset=5")
        assert r1.status_code == 200
        assert r2.status_code == 200
        # IDs should not overlap (unless fewer than 10 total sessions)
        ids1 = {i["id"] for i in r1.json()["items"]}
        ids2 = {i["id"] for i in r2.json()["items"]}
        assert not (ids1 & ids2)


# ─── Events tests ─────────────────────────────────────────────────────────────

class TestEvents:
    @pytest.mark.skipif(SKIP_AUTH, reason="No ADMIN_PASS")
    def test_events_list(self, auth_session):
        r = auth_session.get(f"{API}/events")
        assert r.status_code == 200
        assert "items" in r.json()

    @pytest.mark.skipif(SKIP_AUTH, reason="No ADMIN_PASS")
    def test_top_attackers(self, auth_session):
        r = auth_session.get(f"{API}/events/top-attackers")
        assert r.status_code == 200
        for item in r.json().get("items", []):
            assert "source_ip" in item
            assert "event_count" in item


# ─── Admin tests ──────────────────────────────────────────────────────────────

class TestAdmin:
    @pytest.mark.skipif(SKIP_AUTH, reason="No ADMIN_PASS")
    def test_user_list(self, auth_session):
        r = auth_session.get(f"{API}/admin/users")
        assert r.status_code == 200
        items = r.json()["items"]
        assert any(u["username"] == ADMIN for u in items)

    @pytest.mark.skipif(SKIP_AUTH, reason="No ADMIN_PASS")
    def test_smtp_config_endpoint(self, auth_session):
        r = auth_session.get(f"{API}/admin/smtp")
        assert r.status_code == 200
        # Password must never be returned
        d = r.json()
        assert "password" not in d
        assert "password_enc" not in d

    @pytest.mark.skipif(SKIP_AUTH, reason="No ADMIN_PASS")
    def test_siem_config_endpoint(self, auth_session):
        r = auth_session.get(f"{API}/admin/siem")
        assert r.status_code == 200
        d = r.json()
        assert "token" not in d
        assert "token_enc" not in d

    @pytest.mark.skipif(SKIP_AUTH, reason="No ADMIN_PASS")
    def test_audit_log_endpoint(self, auth_session):
        r = auth_session.get(f"{API}/admin/audit")
        assert r.status_code == 200
        assert "items" in r.json()

    @pytest.mark.skipif(SKIP_AUTH, reason="No ADMIN_PASS")
    def test_sensors_list(self, auth_session):
        r = auth_session.get(f"{API}/sensors")
        assert r.status_code == 200
        assert "items" in r.json()

    @pytest.mark.skipif(SKIP_AUTH, reason="No ADMIN_PASS")
    def test_sensor_token_generation(self, auth_session):
        r = auth_session.post(f"{API}/sensors/token",
                              json={"sensor_name": "pytest-sensor"})
        assert r.status_code in (200, 201)
        d = r.json()
        assert "join_token" in d
        assert "sensor_id" in d
        assert "expires_at" in d
        # Clean up — revoke the test sensor
        auth_session.delete(f"{API}/sensors/{d['sensor_id']}")

    @pytest.mark.skipif(SKIP_AUTH, reason="No ADMIN_PASS")
    def test_reauth_required_for_user_delete(self, auth_session):
        """Delete without reauth should fail with REAUTH_REQUIRED."""
        # Create a temp user
        r = auth_session.post(f"{API}/admin/users",
                              json={"username": "tmpuser_pytest", "email": "tmp@test.com",
                                    "password": "Pytest12345!", "role": "user"})
        if r.status_code not in (200, 201):
            pytest.skip("Could not create temp user")
        uid = r.json()["id"]

        # Try to delete without reauth
        r2 = auth_session.delete(f"{API}/admin/users/{uid}")
        # Should fail (REAUTH_REQUIRED) since we haven't re-authed
        assert r2.status_code == 403
        err = r2.json().get("detail", {}).get("error", "")
        assert err == "REAUTH_REQUIRED"

        # Clean up — can't delete without reauth in test, just deactivate
        auth_session.put(f"{API}/admin/users/{uid}", json={"is_active": False})
