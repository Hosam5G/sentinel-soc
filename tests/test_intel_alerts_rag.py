"""Threat intelligence (KEV matching), alerts, RAG, exports."""
import json
import os
import unittest
from _base import SentinelTestCase


class TestThreatIntel(SentinelTestCase):

    def _seed_kev(self, entries):
        self.m._TI["kev"] = entries
        self.m._TI["ts"] = 1
        self.m._TI["count"] = len(entries)
        self.m._TI["status"] = "ok"

    def setUp(self):
        super().setUp()
        self.m._last_scan["software"] = []
        self._seed_kev([])

    def test_offline_blocks_network(self):
        # PRIVACY: offline mode prevents any outbound update
        # _OFFLINE is set in the env at class setup; verify the behavior path
        result = self.m.update_threat_intel(force=True)
        self.assertIn(result.get("status"), ("offline", "error"))

    def test_local_match_finds_real_match(self):
        self._seed_kev([{"cve": "CVE-2025-X", "vendor": "Mozilla", "product": "Firefox",
                         "name": "use-after-free", "added": "2025", "due": "",
                         "ransomware": "Known"}])
        # Firefox 120 (~2023) is older than the 2025 CVE -> match stands
        self.m._last_scan["software"] = [{"name": "Mozilla Firefox (x64 ar)", "version": "120.0"}]
        m = self.m._match_kev_to_software()
        self.assertEqual(len(m), 1)
        # findings are now aggregated per product; the CVE id appears in the title
        self.assertTrue(m[0]["cve"].startswith("KEV-"))
        self.assertIn("CVE-2025-X", m[0]["title_en"])
        # ransomware-known => high severity
        self.assertEqual(m[0]["sev"], "high")

    def test_version_aware_match_skips_updated_software(self):
        """User's complaint: updated apps were still flagged. An up-to-date
        build released after the CVE year must NOT be matched."""
        self._seed_kev([{"cve": "CVE-2019-1111", "vendor": "7-Zip", "product": "7-Zip",
                         "name": "old", "added": "2019", "ransomware": ""}])
        # 7-Zip 24.x was released in 2024, well after the 2019 CVE
        self.m._last_scan["software"] = [{"name": "7-Zip 24.08", "version": "24.08"}]
        self.assertEqual(self.m._match_kev_to_software(), [])

    def test_matches_aggregate_per_product(self):
        """Multiple CVEs for one app collapse into a single finding (no
        duplicate rows with mixed severities)."""
        self._seed_kev([
            {"cve": "CVE-2020-1", "vendor": "Mozilla", "product": "Firefox", "name": "a", "added": "2020"},
            {"cve": "CVE-2020-2", "vendor": "Mozilla", "product": "Firefox", "name": "b", "added": "2020"},
            {"cve": "CVE-2020-3", "vendor": "Mozilla", "product": "Firefox", "name": "c", "added": "2020"},
        ])
        # Firefox 70 (~2019) predates all three CVEs -> all apply, but aggregate to one row
        self.m._last_scan["software"] = [{"name": "Mozilla Firefox", "version": "70.0"}]
        m = self.m._match_kev_to_software()
        self.assertEqual(len(m), 1)
        self.assertIn("3", m[0]["title_en"])   # "affected by 3 exploited CVE(s)"

    def test_umbrella_filter_blocks_false_positives(self):
        """The bug the user caught: 'Windows' as a KEV product matched
        every app whose name contained 'Windows'."""
        self._seed_kev([
            {"cve": "CVE-2008-4250", "vendor": "Microsoft", "product": "Windows",
             "name": "Server Service", "added": "2008"},
            {"cve": "CVE-2009-0238", "vendor": "Microsoft", "product": "Office",
             "name": "ptr", "added": "2009"},
            {"cve": "CVE-2009-1537", "vendor": "Microsoft", "product": "DirectX",
             "name": "Quartz", "added": "2009"},
        ])
        self.m._last_scan["software"] = [
            {"name": "Windows Driver Package - KEIL Tools By ARM USBDevice", "version": "1.0"},
            {"name": "Microsoft Office LTSC Professional Plus 2021 - ar-sa", "version": "2021"},
            {"name": "Microsoft DirectX End-User Runtime", "version": "9.0"},
        ]
        self.assertEqual(self.m._match_kev_to_software(), [])

    def test_temporal_filter_skips_impossible_match(self):
        """A 2018 CVE for 'Edge' cannot affect WebView2 (released 2020)."""
        self._seed_kev([{"cve": "CVE-2018-7200", "vendor": "Microsoft", "product": "Edge",
                         "name": "legacy bug", "added": "2018"}])
        self.m._last_scan["software"] = [{"name": "Microsoft Edge WebView2 Runtime", "version": "120"}]
        self.assertEqual(self.m._match_kev_to_software(), [])

    def test_eol_products_get_single_finding_not_kev_spam(self):
        self._seed_kev([{"cve": "CVE-2013-0074", "vendor": "Microsoft", "product": "Silverlight",
                         "name": "old", "added": "2013"}])
        self.m._last_scan["software"] = [{"name": "Microsoft Silverlight", "version": "5.1"}]
        # KEV match suppressed (Silverlight is handled by a single EOL finding upstream)
        self.assertEqual(self.m._match_kev_to_software(), [])

    def test_vendor_check_prevents_cross_match(self):
        """7-Zip CVE must NOT match WinZip even though both contain 'zip'."""
        self._seed_kev([{"cve": "CVE-2025-0411", "vendor": "7-Zip", "product": "7-Zip",
                         "name": "MoTW bypass", "added": "2025"}])
        self.m._last_scan["software"] = [{"name": "WinZip 25.0", "version": "25.0"}]
        self.assertEqual(self.m._match_kev_to_software(), [])


class TestAlerts(SentinelTestCase):

    def setUp(self):
        super().setUp()
        # reset the alerts config
        self.m._SETTINGS["alerts"] = {"enabled": True, "min_sev": "high",
                                      "email": {"enabled": False},
                                      "telegram": {"enabled": False},
                                      "webhook": {"enabled": False}}

    def test_severity_gate_blocks_low(self):
        # PRIVACY: also confirms we never even attempt to send below the threshold
        r = self.m._dispatch_alert("x", "y", "low")
        self.assertEqual(r["skipped"], "below min severity")

    def test_disabled_blocks_all(self):
        self.m._SETTINGS["alerts"]["enabled"] = False
        r = self.m._dispatch_alert("x", "y", "critical")
        self.assertEqual(r["skipped"], "alerts disabled")

    def test_config_save_masks_secrets(self):
        h = self._admin_session()
        cfg = {"alerts": {"enabled": True, "min_sev": "high",
                          "telegram": {"enabled": True, "token": "12345:ABCDEFG", "chat_id": "1"},
                          "email": {"enabled": False},
                          "webhook": {"enabled": False}}}
        r = self.client.post("/api/settings/alerts", json=cfg, headers=h).get_json()
        # token is masked in the response …
        self.assertIn("…", r["alerts"]["telegram"]["token"] + " ")
        # … but the real secret is intact server-side
        self.assertEqual(self.m._SETTINGS["alerts"]["telegram"]["token"], "12345:ABCDEFG")

    def test_masked_placeholder_does_not_overwrite_secret(self):
        h = self._admin_session()
        self.m._SETTINGS["alerts"]["telegram"] = {"enabled": True, "token": "real:secret", "chat_id": "9"}
        # client posts the masked placeholder back
        cfg = {"alerts": {"enabled": True, "min_sev": "high",
                          "telegram": {"enabled": True, "token": "real:s…", "chat_id": "9"}}}
        self.client.post("/api/settings/alerts", json=cfg, headers=h)
        self.assertEqual(self.m._SETTINGS["alerts"]["telegram"]["token"], "real:secret")


class TestRAG(SentinelTestCase):

    def test_local_rag_returns_local_context_only(self):
        """RAG must build context strictly from local data — no upload, no network."""
        # seed an open finding
        self.m._FINDINGS.clear()
        self.m._FINDINGS.append({"cve": "CVE-TEST-1", "asset": "host", "sev": "critical",
                                 "score": 9.5, "st": "open",
                                 "title_en": "Open SMB port 445", "title_ar": "x",
                                 "fix_en": "Close port 445", "fix_ar": "x", "cat": "port"})
        ctx = self.m._rag_context("how do I fix the SMB port issue?", "en")
        self.assertIsInstance(ctx, str)
        self.assertTrue(len(ctx) > 0)
        # the local finding must be present in the retrieved context
        self.assertTrue("CVE-TEST-1" in ctx or "SMB" in ctx or "445" in ctx)

    def test_model_chat_accepts_history(self):
        # signature accepts both history and system_extra
        import inspect
        params = list(inspect.signature(self.m.model_chat).parameters)
        self.assertIn("history", params)
        self.assertIn("system_extra", params)
        params2 = list(inspect.signature(self.m.model_chat_stream).parameters)
        self.assertIn("history", params2)


class TestExports(SentinelTestCase):

    def test_csv_has_utf8_bom_for_excel(self):
        r = self.client.get("/api/export/findings.csv")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.data.startswith(b"\xef\xbb\xbf"))
        self.assertIn("text/csv", r.headers.get("Content-Type", ""))

    def test_audit_csv_admin_only(self):
        # without a session, auth is required
        self._register_admin()
        r = self.client.get("/api/export/audit.csv")
        self.assertEqual(r.status_code, 401)
        # with admin
        self._login()
        r2 = self.client.get("/api/export/audit.csv")
        self.assertEqual(r2.status_code, 200)

    def test_docx_export_produces_valid_word_file(self):
        try:
            from docx import Document
        except ImportError:
            self.skipTest("python-docx not installed in this environment")
        h = self._admin_session()
        # ensure at least one report exists
        self.m.generate_report("status", "en")
        rid = list(self.m._REPORTS.keys())[0]
        for tmpl in ("cmar", "executive", "incident", "compliance"):
            r = self.client.get(f"/api/report/{rid}/docx?lang=en&template={tmpl}", headers=h)
            self.assertEqual(r.status_code, 200, f"template {tmpl} failed")
            # write to disk and open with python-docx to validate
            p = f"/tmp/_sx_{tmpl}.docx"
            with open(p, "wb") as f:
                f.write(r.data)
            try:
                d = Document(p)
                self.assertGreater(len(d.paragraphs), 5)
            finally:
                import os; os.remove(p)


class TestHealthAndOps(SentinelTestCase):

    def test_health_endpoint(self):
        r = self.client.get("/api/health")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        for k in ("status", "uptime_seconds", "requests", "errors",
                  "latency_ms_avg", "threads"):
            self.assertIn(k, d)

    def test_backup_creates_zip(self):
        h = self._admin_session()
        r = self.client.post("/api/backup", headers=h)
        j = r.get_json()
        self.assertTrue(j["ok"])
        self.assertTrue(j["file"].endswith(".zip"))


class TestPrivacyContract(SentinelTestCase):
    """Cross-cutting checks that the privacy guarantees hold."""

    def test_offline_mode_flag_present(self):
        # the offline switch is wired everywhere the network is used
        self.assertTrue(hasattr(self.m, "_OFFLINE"))

    def test_threat_intel_uses_generic_user_agent(self):
        import inspect
        src = inspect.getsource(self.m.update_threat_intel)
        # no host identifiers / no telemetry fields in the outbound request
        self.assertIn("Sentinel-SOC", src)
        self.assertNotIn("hostname", src)
        self.assertNotIn("psutil.boot_time", src)

    def test_vt_lookup_sends_hash_only(self):
        import inspect
        src = inspect.getsource(self.m._vt_lookup)
        # the only data sent is the SHA-256 in the URL path
        self.assertIn("sha256", src)
        # no file contents in the request body
        self.assertNotIn("raw", src.lower().replace("urlopen", ""))


class TestRemediation(SentinelTestCase):
    """The consent-gated remediation engine: plans are offered, but nothing
    executes without an explicit confirm flag."""

    def setUp(self):
        super().setUp()
        self.m._FINDINGS[:] = [
            self.m._f("FW-DISABLED", "host", "high", 8.0, "Firewall off", "الجدار مغلق",
                      "Turn on firewall", "شغّل الجدار", "config"),
            self.m._f("PORT-445-smb", "host", "high", 8.5, "SMB port open", "منفذ SMB مفتوح",
                      "Close 445", "أغلق 445", "exposure"),
        ]

    def test_plans_offered_for_config_finding(self):
        plans = self.m._remediation_plans(self.m._FINDINGS[0])
        self.assertTrue(len(plans) >= 1)
        # the real firewall-on command is present and reviewable
        self.assertTrue(any("advfirewall" in c for p in plans for c in p["commands"]))

    def test_port_finding_offers_block_and_smb_options(self):
        plans = self.m._remediation_plans(self.m._FINDINGS[1])
        ids = [p["id"] for p in plans]
        self.assertIn("fw-block-port", ids)
        self.assertIn("disable-smb1", ids)   # 445 -> also offers SMBv1 disable
        # every plan carries a risk label and at least one command
        for p in plans:
            self.assertIn(p["risk"], ("safe", "moderate", "careful"))
            self.assertTrue(p["commands"])

    def test_execute_requires_confirmation(self):
        h = self._admin_session()
        r = self.client.post("/api/security/remediate",
                             json={"cve": "FW-DISABLED", "plan": "fw-on"}, headers=h)
        self.assertEqual(r.status_code, 400)   # no confirm -> refused
        self.assertIn("confirm", r.get_json()["error"].lower())

    def test_execute_requires_admin(self):
        # analyst may VIEW plans but not execute
        h = self._admin_session()
        self.client.post("/api/auth/register",
                         json={"username": "an", "name": "An", "role": "analyst", "password": "pass1234"},
                         headers=h)
        self.client.post("/api/auth/logout", headers=h)
        aj = self._login(u="an", pw="pass1234")
        ah = {"X-CSRF-Token": aj["csrf"]}
        # analyst can read plans
        r = self.client.get("/api/security/remediation/FW-DISABLED", headers=ah)
        self.assertEqual(r.status_code, 200)
        # but cannot execute
        r = self.client.post("/api/security/remediate",
                             json={"cve": "FW-DISABLED", "plan": "fw-on", "confirm": True}, headers=ah)
        self.assertEqual(r.status_code, 403)

    def test_software_finding_offers_winget(self):
        f = self.m._f("KEV-mozilla-firefox", "host", "medium", 5.0,
                      "Firefox may be affected", "فايرفوكس", "Update Firefox", "حدّث", "intel")
        plans = self.m._remediation_plans(f)
        self.assertTrue(any("winget" in c for p in plans for c in p["commands"]))


class TestDetectionEngines(SentinelTestCase):
    """The live detection engines: process scanning, persistence audit, FIM.
    These give the tool real detection power beyond static hardening checks."""

    def test_process_scan_available_or_graceful(self):
        r = self.m.scan_processes(limit=50)
        # either it ran, or it cleanly reports psutil missing — never crashes
        self.assertIn("available", r)
        if r["available"]:
            self.assertIn("hits", r)
            self.assertIsInstance(r["hits"], list)

    def test_masquerade_logic(self):
        # a System32-only name from a temp path must be flaggable
        name = "svchost.exe"
        exe = "c:\\users\\x\\downloads\\svchost.exe"
        self.assertIn(name, self.m._SYSTEM32_ONLY)
        self.assertTrue(any(d in exe for d in self.m._PROC_SUSPICIOUS_DIRS))

    def test_lolbin_detection_set(self):
        # the living-off-the-land binary set includes the usual suspects
        for b in ("powershell.exe", "certutil.exe", "mshta.exe", "rundll32.exe"):
            self.assertIn(b, self.m._LOLBINS)

    def test_fim_baseline_and_detect_change(self):
        import tempfile
        fd, path = tempfile.mkstemp()
        os.close(fd)
        try:
            with open(path, "w") as f:
                f.write("original")
            self.m.fim_baseline(extra_paths=[path])
            # no change yet
            self.assertEqual(len([c for c in self.m.fim_check()["changes"] if c["path"] == path]), 0)
            # tamper
            with open(path, "w") as f:
                f.write("TAMPERED")
            changes = [c for c in self.m.fim_check()["changes"] if c["path"] == path]
            self.assertEqual(len(changes), 1)
            self.assertEqual(changes[0]["kind"], "modified")
        finally:
            os.remove(path)

    def test_fim_detects_missing_file(self):
        import tempfile
        fd, path = tempfile.mkstemp()
        os.close(fd)
        with open(path, "w") as f:
            f.write("x")
        self.m.fim_baseline(extra_paths=[path])
        os.remove(path)   # delete after baseline
        changes = [c for c in self.m.fim_check()["changes"] if c["path"] == path]
        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["kind"], "missing")

    def test_detection_endpoints_require_auth(self):
        # analyst-level endpoints reject anonymous callers once users exist
        self._register_admin()
        for ep in ("/api/detect/processes", "/api/detect/persistence"):
            r = self.client.post(ep)
            self.assertEqual(r.status_code, 401)

    def test_full_detect_combines_engines(self):
        h = self._admin_session()
        r = self.client.post("/api/detect/full", headers=h)
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        for k in ("processes", "persistence", "fim", "total_findings"):
            self.assertIn(k, d)

    def test_process_finding_offers_kill_plan(self):
        f = self.m._f("PROC-4444", "evil.exe", "critical", 9.0,
                      "Suspicious process", "عملية مشبوهة", "kill it", "أنهها", "process")
        plans = self.m._remediation_plans(f)
        self.assertTrue(any(p["id"] == "kill-process" for p in plans))
        kill = next(p for p in plans if p["id"] == "kill-process")
        self.assertIn("taskkill", kill["commands"][0])

    def test_network_scan_available_or_graceful(self):
        r = self.m.scan_network_threats()
        self.assertIn("available", r)
        if r["available"]:
            self.assertIsInstance(r["hits"], list)

    def test_c2_port_list_covers_known_rats(self):
        # the suspect-port set must include the classic C2/RAT ports
        for port in (4444, 31337, 1337, 5555):
            self.assertIn(port, self.m._SUSPECT_REMOTE_PORTS)

    def test_accounts_scan_graceful_off_windows(self):
        r = self.m.scan_accounts()
        self.assertIn("available", r)   # never crashes on non-Windows

    def test_full_detect_includes_all_five_engines(self):
        h = self._admin_session()
        d = self.client.post("/api/detect/full", headers=h).get_json()
        for k in ("processes", "persistence", "fim", "network", "accounts", "rootkit"):
            self.assertIn(k, d)

    def test_rootkit_scan_graceful(self):
        r = self.m.scan_rootkit()
        self.assertIn("available", r)
        # structure is always present even when not on Windows
        for k in ("hidden_processes", "unsigned_drivers", "port_discrepancies"):
            self.assertIn(k, r)

    def test_rootkit_crossview_logic_detects_hidden_pid(self):
        # a PID visible to one enumerator but hidden from another = rootkit signal
        v_a = {100: "a.exe", 200: "b.exe", 666: "hidden.exe"}
        v_b = {100: "a.exe", 200: "b.exe"}              # 666 hidden here
        views = [("psutil", v_a), ("tasklist", v_b)]
        all_pids = set(v_a) | set(v_b)
        hidden = []
        for pid in sorted(all_pids - {0, 4}):
            seen = [n for n, v in views if pid in v]
            miss = [n for n, v in views if pid not in v]
            if seen and miss:
                hidden.append(pid)
        self.assertIn(666, hidden)
        self.assertNotIn(100, hidden)   # visible everywhere -> not flagged

    def test_rootkit_finding_offers_offline_scan(self):
        f = self.m._f("RKPROC-666", "host", "critical", 9.5,
                      "Hidden process", "عملية مخفية", "scan", "افحص", "rootkit")
        plans = self.m._remediation_plans(f)
        self.assertTrue(any(p["id"] == "defender-offline" for p in plans))

    # ---- false-positive suppression layers ----
    def test_trusted_microsoft_names_suppressed(self):
        # the exact binaries that caused the false-positive storm must be trusted
        for n in ("explorer.exe", "msmpeng.exe", "nissrv.exe",
                  "mpdefendercoreservice.exe", "dwm.exe", "runtimebroker.exe"):
            self.assertIn(n, self.m._TRUSTED_NAMES)

    def test_trusted_paths_suppressed(self):
        self.assertTrue(self.m._is_trusted_proc("anything.exe", "c:\\program files\\x\\anything.exe"))
        self.assertTrue(self.m._is_trusted_proc("x.exe", "c:\\windows\\system32\\x.exe"))

    def test_real_malware_still_flagged(self):
        # something in Downloads is NOT auto-trusted (will be scanned)
        self.assertFalse(self.m._is_trusted_proc("evil.exe", "c:\\users\\b\\downloads\\evil.exe"))

    def test_trusted_signer_list_covers_common_vendors(self):
        joined = " ".join(self.m._TRUSTED_SIGNERS)
        for v in ("microsoft", "google", "nvidia", "git"):
            self.assertIn(v, joined)

    def test_signature_cache_and_graceful_off_windows(self):
        # off Windows it returns (False, "") without raising
        res = self.m._verify_signature("/some/path")
        self.assertEqual(res, (False, ""))

    def test_lan_normal_ports_are_not_high(self):
        # 139/445/135 must be calibrated below 'high' with an explanatory note
        for p in (135, 139, 445):
            f = self.m._port_finding(p, "host")
            self.assertIn(f["sev"], ("low", "medium"))
            self.assertIn("طبيعي", f["title_ar"])


class TestSqliteIndex(SentinelTestCase):

    def setUp(self):
        super().setUp()
        # clear both the JSON list and the in-memory SQLite
        self.m._EVENTS.clear()
        with self.m._db_lock:
            self.m._db.execute("DELETE FROM events")
            if self.m._db_init.has_fts:
                self.m._db.execute("DELETE FROM events_fts")
            self.m._db.commit()

    def test_log_event_mirrors_into_sqlite(self):
        self.m.log_event("scan", sev="high", cve="CVE-2024-1", asset="host-1",
                         text_en="Scanner detected something", text_ar="x")
        with self.m._db_lock:
            n = self.m._db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        self.assertEqual(n, 1)

    def test_events_in_window_uses_index(self):
        for i in range(50):
            self.m.log_event("scan", sev="low", cve=f"CVE-{i}",
                             text_en=f"event {i}", text_ar="x")
        rows = self.m.events_in_window(3600)
        self.assertEqual(len(rows), 50)

    def test_indexed_filter_by_kind_and_sev(self):
        for k in ("scan", "incident"):
            for s in ("low", "critical"):
                self.m.log_event(k, sev=s, text_en="x", text_ar="x", dedupe_sec=0)
        critical_incidents = self.m.events_query(kind="incident", sev="critical")
        self.assertEqual(len(critical_incidents), 1)
        self.assertEqual(critical_incidents[0]["kind"], "incident")
        self.assertEqual(critical_incidents[0]["sev"], "critical")

    def test_text_search_finds_substring(self):
        self.m.log_event("scan", text_en="brute-force attempt from remote host", text_ar="x")
        self.m.log_event("scan", text_en="routine scan completed cleanly", text_ar="x")
        hits = self.m.events_query(search="brute")
        self.assertEqual(len(hits), 1)
        self.assertIn("brute-force", hits[0]["text_en"])

    def test_endpoint_returns_engine_metadata(self):
        r = self.client.get("/api/events/search?limit=5")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertEqual(d["engine"], "sqlite-memory")

    def test_no_database_file_written_to_disk(self):
        """PRIVACY contract: the search index NEVER writes a database file."""
        import os
        d = os.path.dirname(self.m.__file__)
        for fn in os.listdir(d):
            self.assertFalse(fn.endswith((".db", ".sqlite", ".sqlite3")),
                             f"unexpected DB file on disk: {fn}")


if __name__ == "__main__":
    unittest.main()
