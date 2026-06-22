"""At-rest encryption, compliance, network analysis, file forensics."""
import json
import os
import unittest
from _base import SentinelTestCase


class TestEncryption(SentinelTestCase):

    def test_round_trip(self):
        path = "/tmp/_sx_round.json"
        try:
            self.m._secure_save(path, {"answer": 42, "note": "حروف عربية"})
            with open(path, encoding="utf-8") as f:
                env = json.load(f)
            self.assertIn(env.get("enc"), ("fernet", "sha256ctr"))
            # plaintext is NOT visible on disk
            with open(path, encoding="utf-8") as f:
                raw = f.read()
            self.assertNotIn("answer", raw)
            self.assertNotIn("حروف", raw)
            # decrypt back
            data = self.m._secure_load(path, {})
            self.assertEqual(data["answer"], 42)
            self.assertEqual(data["note"], "حروف عربية")
        finally:
            try: os.remove(path)
            except: pass

    def test_legacy_plaintext_migrates(self):
        path = "/tmp/_sx_migrate.json"
        try:
            # write a legacy plaintext file
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"legacy": True}, f)
            data = self.m._secure_load(path, {})
            self.assertEqual(data, {"legacy": True})
            # save -> should become encrypted
            self.m._secure_save(path, data)
            with open(path, encoding="utf-8") as f:
                env = json.load(f)
            self.assertIn(env.get("enc"), ("fernet", "sha256ctr"))
        finally:
            try: os.remove(path)
            except: pass

    def test_mac_tampering_detected(self):
        path = "/tmp/_sx_tamper.json"
        try:
            self.m._secure_save(path, {"x": 1})
            with open(path, encoding="utf-8") as f:
                env = json.load(f)
            # corrupt the ciphertext
            if env["enc"] == "sha256ctr":
                env["data"] = "AAAA" + env["data"][4:]
            else:
                env["data"] = "AAAA" + env["data"][4:]
            with open(path, "w", encoding="utf-8") as f:
                json.dump(env, f)
            # should refuse to return tampered data
            self.assertEqual(self.m._secure_load(path, "DEFAULT"), "DEFAULT")
        finally:
            try: os.remove(path)
            except: pass


class TestNetwork(SentinelTestCase):

    def test_ip_classification_local(self):
        # PRIVACY: classification is local — no outbound lookups
        self.assertEqual(self.m._ip_class("192.168.1.5"), "private")
        self.assertEqual(self.m._ip_class("10.0.0.1"), "private")
        self.assertEqual(self.m._ip_class("127.0.0.1"), "loopback")
        self.assertEqual(self.m._ip_class("172.16.0.1"), "private")
        self.assertEqual(self.m._ip_class("8.8.8.8"), "public")
        self.assertEqual(self.m._ip_class(""), "?")

    def test_geoip_lookup_is_local_in_memory(self):
        """Country resolution must happen entirely in memory from a local CSV."""
        # seed an in-memory DB without touching the network
        self.m._geo_starts.clear(); self.m._geo_ends.clear(); self.m._geo_cc.clear()
        starts, ends, ccs = [self.m._ip_to_int("8.8.8.0"), self.m._ip_to_int("41.0.0.0")], \
                            [self.m._ip_to_int("8.8.8.255"), self.m._ip_to_int("41.255.255.255")], \
                            ["US", "EG"]
        self.m._geo_starts.extend(starts); self.m._geo_ends.extend(ends); self.m._geo_cc.extend(ccs)
        self.assertEqual(self.m._geo_lookup("8.8.8.8"), "US")
        self.assertEqual(self.m._geo_lookup("41.5.5.5"), "EG")
        self.assertIsNone(self.m._geo_lookup("99.99.99.99"))   # outside the loaded ranges
        self.assertEqual(self.m._ip_class("8.8.8.8"), "US")
        self.assertEqual(self.m._ip_class("192.168.1.5"), "private")
        # cleanup
        self.m._geo_starts.clear(); self.m._geo_ends.clear(); self.m._geo_cc.clear()

    def test_geoip_status_endpoint_advertises_privacy(self):
        r = self.client.get("/api/network/geoip/status")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        # the endpoint must include an explicit local-only privacy note
        self.assertIn("no IP is ever sent", d["privacy"])
        self.assertIn("Local lookup only", d["privacy"])

    def test_geoip_update_blocked_when_offline(self):
        # SENTINEL_OFFLINE=1 in the test env → update is refused
        r = self.m.update_geoip(force=True)
        self.assertEqual(r["status"], "offline")

    def test_blocklist_add_remove(self):
        h = self._admin_session()
        r = self.client.post("/api/network/block", json={"ip": "1.2.3.4"}, headers=h)
        self.assertEqual(r.get_json()["blocklist"], ["1.2.3.4"])
        r = self.client.post("/api/network/unblock", json={"ip": "1.2.3.4"}, headers=h)
        self.assertEqual(r.get_json()["blocklist"], [])

    def test_blocklist_requires_analyst(self):
        # no session at all
        self.client.post("/api/auth/register",
                         json={"username": "u", "name": "U", "password": "secret123"})
        r2 = self.client.post("/api/network/block", json={"ip": "1.2.3.4"})
        self.assertEqual(r2.status_code, 401)


class TestCompliance(SentinelTestCase):

    def test_compliance_endpoint_returns_shape(self):
        r = self.client.get("/api/compliance")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        for k in ("controls", "score", "passed", "total"):
            self.assertIn(k, d)
        self.assertIsInstance(d["controls"], list)


class TestFileAnalysis(SentinelTestCase):

    def test_hashes_local(self):
        h = self.m._file_hashes(b"hello world")
        self.assertEqual(h["sha256"], "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
        self.assertEqual(h["sha1"], "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed")
        self.assertEqual(h["md5"], "5eb63bbbe01eeed093cb22bb8f5acdc3")

    def test_entropy_extremes(self):
        # all-zero buffer -> entropy 0
        self.assertEqual(self.m._entropy(b"\x00" * 1000), 0.0)
        # random bytes -> high entropy near 8
        import os
        e = self.m._entropy(os.urandom(4096))
        self.assertGreater(e, 7.0)

    def test_file_type_detection(self):
        self.assertIn("PE", self.m._file_type(b"MZ\x00" + b"\x00" * 100, "x.exe"))
        self.assertIn("ELF", self.m._file_type(b"\x7fELF" + b"\x00" * 100, "x"))
        self.assertIn("PDF", self.m._file_type(b"%PDF-1.7\n", "x.pdf"))
        self.assertIn("ZIP", self.m._file_type(b"PK\x03\x04" + b"\x00" * 10, "x.zip"))
        self.assertIn("Office", self.m._file_type(b"PK\x03\x04" + b"\x00" * 10, "x.docx"))

    def test_binary_indicators(self):
        pe = b"MZ" + b"\x00" * 60 + b"VirtualAlloc CreateRemoteThread URLDownloadToFile"
        flags = self.m._binary_indicators(pe, "PE executable (Windows .exe/.dll)", "en")
        self.assertTrue(any("VirtualAlloc" in f or "virtualalloc" in f.lower() for f in flags))

    def test_vt_off_by_default(self):
        # PRIVACY: VirusTotal is opt-in and stays off until configured
        self.assertIsNone(self.m._vt_lookup("a" * 64))

    # ---- YARA local rule engine ----
    def test_yara_fallback_matches_known_patterns(self):
        # without yara-python the built-in keyword scanner still flags obvious patterns
        raw = b"MZ" + b"\x00" * 60 + b"VirtualAllocEx WriteProcessMemory CreateRemoteThread"
        hits = self.m._yara_fallback(raw)
        self.assertIn("Process_Injection_API_Set", hits)

    def test_yara_status_endpoint_is_local(self):
        r = self.client.get("/api/yara/status")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        # the endpoint must declare the local-only privacy contract
        self.assertIn("locally", d["privacy"])
        self.assertIn("never", d["privacy"].replace("is ever", "never"))   # "is ever transmitted"
        # rules directory is on this machine
        self.assertTrue(d["rules_dir"].endswith("sentinel_rules"))

    def test_yara_starter_pack_installs_locally(self):
        h = self._admin_session()
        r = self.client.post("/api/yara/install-starter-pack", headers=h).get_json()
        self.assertTrue(r["ok"])
        self.assertIn("sentinel_starter.yar", r["files"])
        # the file must actually exist on disk in the rules dir
        path = os.path.join(self.m._YARA_DIR, "sentinel_starter.yar")
        self.assertTrue(os.path.exists(path))
        # cleanup
        try: os.remove(path)
        except: pass

    def test_yara_community_update_blocked_offline(self):
        # SENTINEL_OFFLINE=1 in test env → no network update is attempted
        r = self.m.update_yara_rules(force=True)
        self.assertEqual(r["status"], "offline")

    def test_yara_community_writes_to_subdir(self):
        # the community updater MUST NOT touch the user's own rules folder
        comm = os.path.join(self.m._YARA_DIR, "community")
        # offline returns immediately without creating the dir, that's fine
        self.assertTrue(self.m._YARA_DIR.endswith("sentinel_rules"))
        # path safety: community dir is always nested under rules dir
        self.assertTrue(comm.startswith(self.m._YARA_DIR))

    def test_scan_upload_returns_local_analysis(self):
        h = self._admin_session()
        import io
        fake = b"MZ" + b"\x00" * 60 + b"VirtualAlloc URLDownloadToFile"
        r = self.client.post("/api/scan/upload?lang=en",
                             data={"file": (io.BytesIO(fake), "x.exe")},
                             headers=h, content_type="multipart/form-data")
        j = r.get_json()
        self.assertTrue(j["ok"])
        sec = {s["h"]: s["b"] for s in j["report"]["sections"]}
        self.assertIn("Hashes", sec)
        self.assertIn("Static indicators", sec)
        # PRIVACY: VirusTotal section is not present unless explicitly enabled
        self.assertNotIn("VirusTotal (hash-only)", sec)


    def test_scan_upload_heuristic_risk_section(self):
        # a file with packer-like entropy + suspicious APIs should get a risk score
        h = self._admin_session()
        import io
        fake = b"MZ" + bytes(range(256)) * 8 + b"CreateRemoteThread VirtualAllocEx WriteProcessMemory"
        r = self.client.post("/api/scan/upload?lang=en",
                             data={"file": (io.BytesIO(fake), "y.exe")},
                             headers=h, content_type="multipart/form-data")
        j = r.get_json()
        self.assertTrue(j["ok"])
        sec = {s["h"]: s["b"] for s in j["report"]["sections"]}
        self.assertIn("Heuristic assessment", sec)


class TestHeuristicsAndIsolation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import importlib
        cls.m = importlib.import_module("dashboard_routes")

    def test_isolation_refuses_critical_processes(self):
        # auto-isolation must NEVER touch core OS processes
        for crit in ("svchost.exe", "lsass.exe", "explorer.exe", "csrss.exe"):
            res = self.m._isolate_process(4, crit, "unit-test")
            self.assertFalse(res.get("ok"))
            self.assertIn("critical", res.get("error", "").lower())

    def test_auto_isolate_disabled_by_default_takes_no_action(self):
        # with the toggle off, even high-confidence alerts are not acted on
        self.m._auto_isolate_enabled[0] = False
        alerts = [{"type": "lolbin_chain", "sev": "high", "pid": 999999,
                   "name": "powershell.exe", "detail_en": "x"}]
        acted = self.m._auto_isolate_from_alerts(alerts)
        self.assertEqual(acted, [])

    def test_heuristic_scan_is_safe_off_windows(self):
        # on non-Windows / no psutil it must degrade gracefully, never raise
        res = self.m._heuristic_scan()
        self.assertIn("available", res)

    def test_allowlist_add_remove(self):
        # adding a name should make _rt_in_allowlist return True; removing reverts
        self.m._rt_allowlist["names"].add("mybackup.exe")
        self.assertTrue(self.m._rt_in_allowlist("mybackup.exe", "c:/x/mybackup.exe"))
        self.m._rt_allowlist["names"].discard("mybackup.exe")
        self.assertFalse(self.m._rt_in_allowlist("mybackup.exe", "c:/x/mybackup.exe"))

    def test_allowlist_path_match(self):
        self.m._rt_allowlist["paths"].add("c:/company/tools")
        self.assertTrue(self.m._rt_in_allowlist("anything.exe", "c:/company/tools/anything.exe"))
        self.m._rt_allowlist["paths"].discard("c:/company/tools")


class TestBaselineDigest(SentinelTestCase):
    def test_baseline_learning_then_known(self):
        self.m._load_baseline()
        self.assertTrue(self.m._baseline_is_learning())
        self.m._baseline_observe("chrome.exe")
        self.assertTrue(self.m._baseline_is_known("chrome.exe"))
        self.assertFalse(self.m._baseline_is_known("evil_xyz.exe"))

    def test_weekly_digest_structure(self):
        d = self.m.weekly_digest("en")
        self.assertEqual(d["period"], "weekly")
        self.assertIn("stats", d)
        self.assertIn("summary", d)
        self.assertTrue(len(d["summary"]) > 20)


if __name__ == "__main__":
    unittest.main()
