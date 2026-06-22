"""Shared base class for Sentinel test cases.

Each test gets a freshly-loaded backend module with all sentinel_*.json
and sentinel.key removed first, so test runs are deterministic and
isolated from any data already on disk."""
import importlib
import os
import sys
import unittest

# allow `import dashboard_routes` from the parent directory
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


_ARTIFACTS = ["sentinel_users.json", "sentinel_reports.json", "sentinel_events.json",
              "sentinel_audit.json", "sentinel_settings.json", "sentinel_threatintel.json",
              "sentinel.key", "sentinel.log"]


def _wipe_state():
    for fn in _ARTIFACTS:
        p = os.path.join(ROOT, fn)
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass


class SentinelTestCase(unittest.TestCase):
    """Reloads the backend module once per class, then gives every test
    a fresh test_client (no leaked cookies) and a clean users/sessions state."""

    @classmethod
    def setUpClass(cls):
        _wipe_state()
        os.environ.setdefault("SENTINEL_OFFLINE", "1")
        os.environ.setdefault("SENTINEL_NO_ENCRYPT", "")
        os.environ["SENTINEL_RATE_LIMIT"] = "10000"
        if "dashboard_routes" in sys.modules:
            del sys.modules["dashboard_routes"]
        cls.m = importlib.import_module("dashboard_routes")
        cls.app = cls.m.create_app()

    def setUp(self):
        # fresh client per test → no cookies leak between tests
        self.client = self.app.test_client()
        # clean auth state per test (other modules can re-seed in their own setUp)
        self.m._USERS.clear()
        self.m._SESSIONS.clear()

    @classmethod
    def tearDownClass(cls):
        _wipe_state()

    def _register_admin(self, u="admin", pw="secret123", name="Admin"):
        r = self.client.post("/api/auth/register",
                             json={"username": u, "name": name, "password": pw})
        return r.get_json()

    def _login(self, u="admin", pw="secret123", code=""):
        r = self.client.post("/api/auth/login",
                             json={"username": u, "password": pw, "code": code})
        return r.get_json()

    def _admin_session(self):
        """Convenience: register + login an admin, return CSRF headers."""
        self._register_admin()
        j = self._login()
        return {"X-CSRF-Token": j["csrf"]}
