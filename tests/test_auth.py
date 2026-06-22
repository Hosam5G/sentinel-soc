"""Authentication, sessions, roles, MFA, lockout, CSRF."""
import time
import unittest
from _base import SentinelTestCase


class TestAuth(SentinelTestCase):

    # ---- registration ----

    def test_first_user_becomes_admin(self):
        j = self._register_admin()
        self.assertTrue(j["ok"])
        self.assertEqual(j["user"]["role"], "admin")
        self.assertTrue(j["firstAdmin"])

    def test_second_registration_requires_admin(self):
        self._register_admin()
        # logout — no session
        r = self.client.post("/api/auth/register",
                             json={"username": "bob", "name": "Bob", "password": "pass1234"})
        self.assertEqual(r.status_code, 403)

    def test_weak_password_rejected(self):
        h = self._admin_session()
        # password too short
        r = self.client.post("/api/auth/register",
                             json={"username": "x", "name": "X", "password": "1234"}, headers=h)
        self.assertEqual(r.status_code, 400)
        # no digits
        r = self.client.post("/api/auth/register",
                             json={"username": "y", "name": "Y", "password": "abcdefgh"}, headers=h)
        self.assertEqual(r.status_code, 400)

    # ---- login & lockout ----

    def test_login_returns_csrf(self):
        self._register_admin()
        j = self._login()
        self.assertTrue(j["ok"])
        self.assertTrue(j.get("csrf"))
        self.assertEqual(j["user"]["role"], "admin")

    def test_account_locks_after_failed_attempts(self):
        self._register_admin()
        for _ in range(5):
            self._login(pw="wrong")
        r = self.client.post("/api/auth/login", json={"username": "admin", "password": "secret123"})
        self.assertEqual(r.status_code, 423)
        self.assertIn("locked", r.get_json()["error"].lower())

    # ---- MFA / TOTP ----

    def test_totp_round_trip(self):
        secret = self.m._totp_secret()
        code_now = self.m._totp_at(secret, time.time())
        self.assertEqual(len(code_now), 6)
        self.assertTrue(self.m._totp_verify(secret, code_now))
        self.assertFalse(self.m._totp_verify(secret, "000000"))

    def test_mfa_blocks_login_without_code(self):
        h = self._admin_session()
        setup = self.client.post("/api/auth/mfa/setup", headers=h).get_json()
        code = self.m._totp_at(setup["secret"], time.time())
        en = self.client.post("/api/auth/mfa/enable", json={"code": code}, headers=h).get_json()
        self.assertTrue(en["ok"])
        # logout and try logging in without a code
        self.client.post("/api/auth/logout", headers=h)
        j1 = self._login()
        self.assertTrue(j1.get("mfaRequired"))
        # log in with a fresh code
        j2 = self._login(code=self.m._totp_at(setup["secret"], time.time()))
        self.assertTrue(j2["ok"])

    # ---- roles ----

    def test_viewer_cannot_run_scan(self):
        h = self._admin_session()
        # admin creates a viewer
        self.client.post("/api/auth/register",
                         json={"username": "v", "name": "V", "role": "viewer", "password": "pass1234"},
                         headers=h)
        # logout admin, login viewer
        self.client.post("/api/auth/logout", headers=h)
        vj = self._login(u="v", pw="pass1234")
        r = self.client.post("/api/security/scan", headers={"X-CSRF-Token": vj["csrf"]})
        self.assertEqual(r.status_code, 403)

    def test_analyst_can_run_scan(self):
        h = self._admin_session()
        self.client.post("/api/auth/register",
                         json={"username": "a", "name": "A", "role": "analyst", "password": "pass1234"},
                         headers=h)
        self.client.post("/api/auth/logout", headers=h)
        aj = self._login(u="a", pw="pass1234")
        r = self.client.post("/api/security/scan", headers={"X-CSRF-Token": aj["csrf"]})
        self.assertEqual(r.status_code, 200)

    # ---- CSRF ----

    def test_csrf_required_on_mutations(self):
        self._register_admin()
        self._login()
        # missing CSRF header
        r = self.client.post("/api/security/scan")
        self.assertEqual(r.status_code, 403)

    def test_password_pbkdf2_hashing(self):
        h1 = self.m._hash_pw("hello")
        h2 = self.m._hash_pw("hello")
        # different salts -> different hashes
        self.assertNotEqual(h1["hash"], h2["hash"])
        self.assertEqual(h1["algo"], "pbkdf2")
        self.assertTrue(self.m._verify_pw(h1, "hello"))
        self.assertFalse(self.m._verify_pw(h1, "wrong"))

    def test_legacy_sha256_still_verifies(self):
        import hashlib
        legacy = hashlib.sha256(("sentinel-salt:" + "old").encode()).hexdigest()
        self.assertTrue(self.m._verify_pw(legacy, "old"))

    # ---- hardening: path traversal, headers, request size ----
    def test_path_traversal_blocked(self):
        for evil in ["/../dashboard_routes.py", "/..%2f..%2fetc%2fpasswd",
                     "/sentinel.key", "/sentinel_users.json"]:
            r = self.client.get(evil)
            self.assertIn(r.status_code, (403, 404),
                          f"{evil} returned {r.status_code} — possible file disclosure")

    def test_security_headers_present(self):
        r = self.client.get("/api/health")
        for h in ("X-Content-Type-Options", "X-Frame-Options",
                  "Content-Security-Policy", "Referrer-Policy"):
            self.assertIn(h, r.headers)
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")

    def test_max_content_length_configured(self):
        self.assertEqual(self.app.config.get("MAX_CONTENT_LENGTH"), 8 * 1024 * 1024)

    def test_no_fabricated_findings_at_startup(self):
        # findings must come from a real scan, not seeded fake hosts
        fake_hosts = {"web-03", "db-01", "gw-edge", "k8s-node-2", "web-05", "ci-01"}
        for f in self.m._FINDINGS:
            self.assertNotIn(f.get("asset"), fake_hosts,
                             "a fabricated finding leaked into the live store")


if __name__ == "__main__":
    unittest.main()
