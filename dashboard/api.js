/* Equilibrium Sentinel — Frontend data layer (window.API)
   ---------------------------------------------------------------
   - Talks to the backend over SAME-ORIGIN relative paths by default
     (works when app.py serves the dashboard on 127.0.0.1:8000).
   - Configurable: set window.SENTINEL_API = { base, timeout, pollMs }
     BEFORE this script loads to point at a different origin.
   - Every call has a timeout and a graceful MOCKUP fallback, so the
     design stays intact even with the backend offline.
   - Plain <script> (NOT babel) — attaches window.API.
   --------------------------------------------------------------- */
(function () {
  var CFG     = window.SENTINEL_API || {};
  var BASE    = (CFG.base != null) ? CFG.base : '';      // '' = same-origin
  var TIMEOUT = CFG.timeout || 6000;                     // ms per request

  function _saveBlob(blob, filename) {
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    setTimeout(function () { URL.revokeObjectURL(url); }, 1500);
  }

  // resolve to a PDF blob, or reject with the server's error message
  function _pdfOrError(r) {
    var ct = r.headers.get('Content-Type') || '';
    if (r.ok && ct.indexOf('application/pdf') >= 0) return r.blob();
    return r.json().then(function (j) { throw new Error((j && j.error) || 'PDF failed'); },
                         function () { throw new Error('PDF failed (HTTP ' + r.status + ')'); });
  }
  var POLL_MS = CFG.pollMs  || 15000;                    // overview poll cadence
  var CSRF = null;                                       // set after login / getMe

  /* ---- low-level fetch with timeout (sends session cookie + CSRF on writes) ---- */
  function call(path, opts) {
    opts = opts || {};
    var ctrl = new AbortController();
    var ms = opts.timeout || TIMEOUT;
    var timer = setTimeout(function () { ctrl.abort(); }, ms);
    var method = opts.method || 'GET';
    var headers = Object.assign({ 'Content-Type': 'application/json' }, opts.headers || {});
    if (CSRF && method !== 'GET') headers['X-CSRF-Token'] = CSRF;   // CSRF for mutating requests
    return fetch(BASE + path, {
      method: method,
      headers: headers,
      credentials: 'same-origin',                        // send the session cookie
      body: opts.body ? JSON.stringify(opts.body) : undefined,
      signal: ctrl.signal,
    }).then(function (res) {
      if (!res.ok) throw new Error('HTTP ' + res.status);
      return res.json();
    }).finally(function () { clearTimeout(timer); });
  }

  /* ---- helpers for realistic mock drift (keeps the panel "alive" offline) ---- */
  function jit(base, amp) { return Math.max(0, base + (Math.random() * 2 - 1) * amp); }
  function r1(n) { return Math.round(n * 10) / 10; }

  function L(lang) {
    var I = window.I18N || {};
    return I[lang] || I.en || {};
  }

  /* ---- MOCKUP fallbacks (mirror the design defaults, localized via I18N) ---- */
  function mockOverview(lang) {
    var t = L(lang);
    var ai = t.ai || {};
    var cpu = Math.round(jit(38, 6));
    var ram = r1(jit(11.4, 0.8));
    var net = Math.round(jit(248, 22));
    var threats = 2;
    var score = 92;
    return {
      source: 'mock',
      ts: Date.now(),
      score: score,
      verdict: ai.verdict || 'All systems nominal.',
      summary: ai.summary || '',
      secured: true,
      vitals: { threats: String(threats), uptime: '99.98%' },
      chips: {
        threats: String(threats),
        cpu: cpu + '%',
        net: String(net),
        score: String(score),
      },
      cards: {
        cpu:     { value: String(cpu),  unit: '%',  trendDir: 'down', trendText: '4%'  },
        ram:     { value: String(ram),  unit: 'GB', trendDir: 'up',   trendText: '6%'  },
        threat:  { value: String(threats),           trendDir: 'down', trendText: '1'   },
        traffic: { value: String(net),  unit: (t.units && t.units.mbps) || 'Mbps', trendDir: 'up', trendText: '12%' },
      },
      reports: (ai.reports || []).slice(),
      stream: null, // null => page keeps its own seeded stream
    };
  }

  function mockAnswer(q, lang) {
    return (lang === 'ar')
      ? 'النموذج غير متصل حالياً، لكن آخر حالة معروفة: درجة الأمان ٩٢، تهديدان نشطان على web-03. شغّل الـ backend للحصول على إجابة حيّة.'
      : 'The model is offline right now, but the last known posture is: security score 92, 2 active threats on web-03. Start the backend for a live answer.';
  }

  /* ---- public API ---- */
  window.API = {
    base: BASE,
    pollMs: POLL_MS,
    source: 'unknown',

    getOverview: function (lang) {
      var self = this;
      return call('/api/dashboard/overview?lang=' + encodeURIComponent(lang || 'en'))
        .then(function (d) { self.source = 'live'; d.source = 'live'; return d; })
        .catch(function () { self.source = 'mock'; return mockOverview(lang); });
    },

    scanNow: function () {
      var self = this;
      return call('/api/dashboard/scan-now', { method: 'POST' })
        .then(function (d) { self.source = 'live'; return d; })
        .catch(function () { self.source = 'mock'; return { ok: true, source: 'mock', startedAt: Date.now() }; });
    },

    ask: function (q, lang, history) {
      var self = this;
      return call('/api/dashboard/ask', { method: 'POST', timeout: 180000,
                  body: { q: q, lang: lang || 'en', history: history || [] } })
        .then(function (d) { self.source = 'live'; return d; })
        .catch(function () { self.source = 'mock'; return { source: 'mock', answer: mockAnswer(q, lang) }; });
    },

    // streaming chat — onDelta(textChunk) fires as the model generates; returns a promise that resolves on done.
    askStream: function (q, lang, onDelta, history) {
      var self = this;
      return fetch(BASE + '/api/dashboard/ask-stream', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        credentials: 'same-origin',
        body: JSON.stringify({ q: q, lang: lang || 'en', history: history || [] }),
      }).then(function (resp) {
        if (!resp.body || !resp.body.getReader) {   // no streaming support → fall back
          return self.ask(q, lang).then(function (d) { onDelta(d.answer || '', true); });
        }
        self.source = 'live';
        var reader = resp.body.getReader(); var dec = new TextDecoder(); var buf = '';
        function pump() {
          return reader.read().then(function (res) {
            if (res.done) return;
            buf += dec.decode(res.value, { stream: true });
            var idx;
            while ((idx = buf.indexOf('\n\n')) >= 0) {
              var chunk = buf.slice(0, idx); buf = buf.slice(idx + 2);
              var line = chunk.replace(/^data: /, '');
              try { var o = JSON.parse(line); if (o.delta) onDelta(o.delta, false); } catch (e) {}
            }
            return pump();
          });
        }
        return pump();
      }).catch(function () {
        self.source = 'mock';
        onDelta(mockAnswer(q, lang), true);
      });
    },

    /* ---------------- SECURITY page ---------------- */
    getSecurity: function (lang) {
      var self = this;
      return call('/api/security/overview?lang=' + encodeURIComponent(lang || 'en'))
        .then(function (d) { self.source = 'live'; d.source = 'live'; return d; })
        .catch(function () { self.source = 'mock'; return mockSecurity(lang); });
    },

    // action = 'apply' | 'dismiss' ; resolves to the finding's new status
    findingAction: function (cve, action, lang) {
      var self = this;
      return call('/api/security/finding-action', { method: 'POST', body: { cve: cve, action: action, lang: lang || 'en' } })
        .then(function (d) { self.source = 'live'; return d; })
        .catch(function () {
          self.source = 'mock';
          return { source: 'mock', cve: cve, status: action === 'apply' ? 'patched' : 'dismissed' };
        });
    },

    // action = 'apply' | 'dismiss'
    recAction: function (id, action, lang) {
      var self = this;
      return call('/api/security/rec-action', { method: 'POST', body: { id: id, action: action, lang: lang || 'en' } })
        .then(function (d) { self.source = 'live'; return d; })
        .catch(function () {
          self.source = 'mock';
          return { source: 'mock', id: id, state: action === 'apply' ? 'applied' : 'dismissed' };
        });
    },

    /* ---------------- LIVE STREAM (SSE) ---------------- */
    // onMsg receives parsed event objects: {type:'tick', data:{...}} | {type:'notification',...} | {type:'surprise_report',...}
    // returns a handle with .close(); auto-falls back to polling if SSE fails.
    streamConnect: function (lang, onMsg) {
      var self = this;
      var closed = false, es = null, pollTimer = null;
      function startPolling() {
        if (pollTimer) return;
        var tick = function () {
          self.getOverview(lang).then(function (d) { if (!closed) onMsg({ type: 'tick', data: d }); });
        };
        tick();
        pollTimer = setInterval(tick, self.pollMs || 15000);
      }
      try {
        es = new EventSource(BASE + '/api/stream?lang=' + encodeURIComponent(lang || 'en'));
        es.onmessage = function (e) {
          if (closed) return;
          self.source = 'live';
          var msg;
          try { msg = JSON.parse(e.data); } catch (err) { return; }
          // fan notifications out to any component (e.g. the bell in the top bar)
          if (msg && msg.type === 'notification') {
            try { window.dispatchEvent(new CustomEvent('sx-notification', { detail: msg.notification })); } catch (x) {}
          }
          onMsg(msg);
        };
        es.onerror = function () {
          // SSE dropped -> fall back to polling (design stays alive)
          self.source = 'mock';
          if (es) { es.close(); es = null; }
          startPolling();
        };
      } catch (err) {
        startPolling();
      }
      return { close: function () { closed = true; if (es) es.close(); if (pollTimer) clearInterval(pollTimer); } };
    },

    /* ---------------- NOTIFICATIONS ---------------- */
    getNotifications: function (lang) {
      var self = this;
      return call('/api/notifications?lang=' + encodeURIComponent(lang || 'en'))
        .then(function (d) { self.source = 'live'; return d.notifications || []; })
        .catch(function () { self.source = 'mock'; return null; });   // null => UI keeps its own seed
    },
    clearNotifications: function () {
      return call('/api/notifications/clear', { method: 'POST' }).catch(function () { return { ok: false }; });
    },

    /* ---------------- REPORTS ---------------- */
    getReports: function (lang) {
      var self = this;
      return call('/api/reports?lang=' + encodeURIComponent(lang || 'en'))
        .then(function (d) { self.source = 'live'; return d.reports || []; })
        .catch(function () { self.source = 'mock'; return null; });
    },
    generatePeriodReport: function (period, lang, template) {
      return call('/api/reports?period=' + encodeURIComponent(period) + '&lang=' + encodeURIComponent(lang || 'en') + '&template=' + encodeURIComponent(template || ''))
        .then(function (d) { return d.report; })
        .catch(function () { return null; });
    },
    explainFinding: function (cve, lang, useAi) {
      return call('/api/security/explain',
                  { method: 'POST', body: { cve: cve, lang: lang || 'ar', ai: !!useAi },
                    timeout: useAi ? 90000 : 15000 })
        .then(function (d) { return d && d.ok ? d.explanation : null; })
        .catch(function () { return null; });
    },
    getReport: function (id, lang) {
      return call('/api/report/' + encodeURIComponent(id))
        .then(function (d) { return d.report; })
        .catch(function () { return null; });
    },

    /* ---------------- MODEL (q4 / q8 switch) ---------------- */
    getModels: function (lang) {
      return call('/api/models?lang=' + encodeURIComponent(lang || 'en'))
        .then(function (d) { return d; })
        .catch(function () {
          return { current: 'q4', models: [
            { id: 'q4', label: 'Foundation-Sec 8B · Q4', note: lang==='ar'?'أخف':'Lighter' },
            { id: 'q8', label: 'Foundation-Sec 8B · Full', note: lang==='ar'?'أدق':'Higher accuracy' },
          ] };
        });
    },
    setModel: function (id) {
      return call('/api/model', { method: 'POST', body: { id: id } })
        .then(function (d) { return d; })
        .catch(function () { return { ok: false }; });
    },
    modelPing: function () {
      // lightweight liveness check — returns {reachable, model_ready, connected}
      return call('/api/model/ping')
        .then(function (d) { return d; })
        .catch(function () { return { reachable: false, model_ready: false, connected: false }; });
    },

    /* ---------------- EMPLOYEE AUTH ---------------- */
    register: function (username, name, role, password, email) {
      return call('/api/auth/register', { method: 'POST', body: { username: username, name: name, role: role, password: password, email: email || '' } })
        .then(function (d) { if (d && d.csrf) CSRF = d.csrf; return d; })
        .catch(function (e) { return { ok: false, error: String(e).indexOf('403') >= 0 ? 'forbidden' : 'offline' }; });
    },
    login: function (username, password, code) {
      return call('/api/auth/login', { method: 'POST', body: { username: username, password: password, code: code || '' } })
        .then(function (d) { if (d && d.csrf) CSRF = d.csrf; return d; })
        .catch(function () { return { ok: false, error: 'offline' }; });
    },
    logout: function () {
      return call('/api/auth/logout', { method: 'POST' }).then(function (d) { CSRF = null; return d; }).catch(function () { CSRF = null; return { ok: false }; });
    },
    getMe: function () {
      return call('/api/auth/me').then(function (d) { if (d && d.csrf) CSRF = d.csrf; return d; }).catch(function () { return { user: null }; });
    },
    mfaSetup: function () {
      return call('/api/auth/mfa/setup', { method: 'POST' }).catch(function () { return null; });
    },
    mfaEnable: function (code) {
      return call('/api/auth/mfa/enable', { method: 'POST', body: { code: code } }).catch(function (e) { return { ok: false, error: 'invalid' }; });
    },
    mfaDisable: function () {
      return call('/api/auth/mfa/disable', { method: 'POST' }).catch(function () { return { ok: false }; });
    },
    setUserRole: function (username, role) {
      return call('/api/auth/user/role', { method: 'POST', body: { username: username, role: role } }).catch(function () { return { ok: false }; });
    },
    deleteUser: function (username) {
      return call('/api/auth/user/delete', { method: 'POST', body: { username: username } }).catch(function () { return { ok: false }; });
    },
    getAudit: function () {
      return call('/api/audit').then(function (d) { return d; }).catch(function () { return { items: [], count: 0 }; });
    },
    getAlertSettings: function () {
      return call('/api/settings/alerts').then(function (d) { return d.alerts; }).catch(function () { return null; });
    },
    saveAlertSettings: function (alerts) {
      return call('/api/settings/alerts', { method: 'POST', body: { alerts: alerts } }).catch(function () { return { ok: false }; });
    },
    testAlerts: function () {
      return call('/api/settings/alerts/test', { method: 'POST', timeout: 30000 }).catch(function () { return { ok: false }; });
    },
    exportCsv: function (kind, lang) {
      window.open(BASE + '/api/export/' + kind + '.csv?lang=' + (lang || 'en'), '_blank');
    },
    downloadReportDocx: function (id, lang, template) {
      window.open(BASE + '/api/report/' + encodeURIComponent(id) + '/docx?lang=' + (lang || 'en') + '&template=' + (template || 'cmar'), '_blank');
    },
    getReportTemplates: function () {
      return call('/api/report/templates').then(function (d) { return d.templates || []; }).catch(function () { return []; });
    },
    getHealth: function () {
      return call('/api/health').catch(function () { return null; });
    },
    createBackup: function () {
      return call('/api/backup', { method: 'POST' }).catch(function () { return { ok: false }; });
    },
    downloadBackup: function () {
      window.open(BASE + '/api/backup/download', '_blank');
    },
    exportAuditCsv: function () {
      window.open(BASE + '/api/export/audit.csv', '_blank');
    },
    getCompliance: function () {
      return call('/api/compliance', { timeout: 20000 }).catch(function () { return null; });
    },
    getNetworkAnalysis: function () {
      return call('/api/network/analysis', { timeout: 20000 }).catch(function () { return null; });
    },
    blockIp: function (ip) {
      return call('/api/network/block', { method: 'POST', body: { ip: ip } }).catch(function () { return { ok: false }; });
    },
    unblockIp: function (ip) {
      return call('/api/network/unblock', { method: 'POST', body: { ip: ip } }).catch(function () { return { ok: false }; });
    },
    getGeoIpStatus: function () {
      return call('/api/network/geoip/status').catch(function () { return null; });
    },
    updateGeoIp: function (force) {
      return call('/api/network/geoip/update', { method: 'POST', body: { force: !!force }, timeout: 180000 }).catch(function () { return { status: 'error' }; });
    },
    getSystemMetrics: function () {
      return call('/api/system/metrics', { timeout: 20000 }).catch(function () { return null; });
    },
    scanSystem: function () {
      return call('/api/security/scan', { method: 'POST' }).catch(function () { return null; });
    },
    getScanStatus: function () {
      return call('/api/security/scan/status').catch(function () { return null; });
    },
    getSoftware: function () {
      return call('/api/security/software').catch(function () { return { count: 0, software: [] }; });
    },
    getThreatIntel: function () {
      return call('/api/threat-intel/latest').catch(function () { return null; });
    },
    updateThreatIntel: function () {
      return call('/api/threat-intel/update', { method: 'POST' }).catch(function () { return null; });
    },
    scanIncidents: function () {
      return call('/api/incidents/scan').catch(function () { return null; });
    },

    getUsers: function () {
      return call('/api/auth/users').then(function (d) { return d.users || []; }).catch(function () { return []; });
    },

    /* ---------------- PDF REPORTS ---------------- */
    /* ---------------- PDF / PRINT REPORTS ---------------- */
    // Open a print-ready HTML report in a new tab; the browser renders Arabic
    // perfectly and prints to a flawless PDF (Ctrl+P -> Save as PDF, auto-triggered).
    openReportPrint: function (id, lang, template) {
      var url = BASE + '/api/report/' + encodeURIComponent(id) + '/html?print=1&lang=' + (lang || 'en') + '&template=' + (template || 'cmar');
      window.open(url, '_blank');
    },
    generateReportPrint: function (period, lang, template) {
      var url = BASE + '/api/report/generate-html?print=1&period=' + encodeURIComponent(period || 'status') + '&lang=' + (lang || 'en') + '&template=' + (template || 'cmar');
      window.open(url, '_blank');
    },
    // fetch a report as a professional PDF and trigger download. returns a promise.
    downloadReportPdf: function (id, lang, filename) {
      return fetch(BASE + '/api/report/' + encodeURIComponent(id) + '/pdf?lang=' + (lang || 'en'))
        .then(_pdfOrError)
        .then(function (blob) { _saveBlob(blob, filename || ('sentinel-report-' + id + '.pdf')); return true; });
    },
    generateReportPdf: function (period, lang) {
      return fetch(BASE + '/api/report/generate-pdf?period=' + encodeURIComponent(period || 'status') + '&lang=' + (lang || 'en'))
        .then(_pdfOrError)
        .then(function (blob) { _saveBlob(blob, 'sentinel-status-report.pdf'); return true; });
    },

    /* ---------------- SCAN AN UPLOADED FILE ---------------- */
    scanUpload: function (filename, content, lang) {
      return call('/api/scan/upload?lang=' + encodeURIComponent(lang || 'en'),
                  { method: 'POST', timeout: 180000, body: { filename: filename, content: content } })
        .then(function (d) { return d; })
        .catch(function () { return { ok: false, error: 'offline' }; });
    },
    scanUploadFile: function (file, lang) {
      // multipart upload so BINARY files (exe/pdf/office) are hashed/analysed byte-accurate
      var fd = new FormData();
      fd.append('file', file);
      var headers = {};
      if (CSRF) headers['X-CSRF-Token'] = CSRF;
      return fetch(BASE + '/api/scan/upload?lang=' + encodeURIComponent(lang || 'en'),
                   { method: 'POST', headers: headers, credentials: 'same-origin', body: fd })
        .then(function (r) { return r.json(); })
        .catch(function () { return { ok: false, error: 'offline' }; });
    },
    getVtSettings: function () {
      return call('/api/settings/virustotal').catch(function () { return null; });
    },
    saveVtSettings: function (vt) {
      return call('/api/settings/virustotal', { method: 'POST', body: { virustotal: vt } }).catch(function () { return { ok: false }; });
    },
    getRemediationPlans: function (cve) {
      return call('/api/security/remediation/' + encodeURIComponent(cve))
        .catch(function (e) {
          // surface auth errors so the UI can prompt for login
          var msg = String(e && e.message ? e.message : e || '');
          if (msg.indexOf('auth') !== -1 || msg.indexOf('401') !== -1)
            return { error: 'authentication required', ok: false };
          return null;
        });
    },
    executeRemediation: function (cve, plan) {
      return call('/api/security/remediate', { method: 'POST', body: { cve: cve, plan: plan, confirm: true }, timeout: 200000 }).catch(function (e) { return { ok: false, error: String(e) }; });
    },
    runFullDetection: function () {
      return call('/api/detect/full', { method: 'POST', timeout: 120000 }).catch(function () { return null; });
    },
    runHeuristics: function () {
      return call('/api/detect/heuristics', { method: 'POST', timeout: 60000 }).catch(function () { return null; });
    },
    getIsolationLog: function () {
      return call('/api/isolation/log').catch(function () { return null; });
    },
    toggleAutoIsolate: function (enabled) {
      return call('/api/isolation/toggle', { method: 'POST', body: { enabled: !!enabled } }).catch(function () { return { ok: false }; });
    },
    resumeProcess: function (pid) {
      return call('/api/isolation/resume/' + encodeURIComponent(pid), { method: 'POST' }).catch(function (e) { return { ok: false, error: String(e) }; });
    },
    getRealtimeStatus: function () {
      return call('/api/realtime/status').catch(function () { return null; });
    },
    toggleRealtime: function (enabled) {
      return call('/api/realtime/toggle', { method: 'POST', body: { enabled: !!enabled } }).catch(function () { return { ok: false }; });
    },
    getAllowlist: function () {
      return call('/api/allowlist').catch(function () { return null; });
    },
    allowlistAdd: function (name, path) {
      return call('/api/allowlist/add', { method: 'POST', body: { name: name || '', path: path || '' } }).catch(function () { return { ok: false }; });
    },
    allowlistRemove: function (name, path) {
      return call('/api/allowlist/remove', { method: 'POST', body: { name: name || '', path: path || '' } }).catch(function () { return { ok: false }; });
    },
    setMonitorOnly: function (enabled) {
      return call('/api/isolation/monitor-only', { method: 'POST', body: { enabled: !!enabled } }).catch(function () { return { ok: false }; });
    },
    getIsolationSuggestions: function () {
      return call('/api/isolation/suggestions').catch(function () { return null; });
    },
    getBaselineStatus: function () {
      return call('/api/baseline/status').catch(function () { return null; });
    },
    resetBaseline: function () {
      return call('/api/baseline/reset', { method: 'POST' }).catch(function () { return { ok: false }; });
    },
    getWeeklyDigest: function () {
      return call('/api/digest/weekly').catch(function () { return null; });
    },
    fimBaseline: function () {
      return call('/api/detect/fim/baseline', { method: 'POST', body: {} }).catch(function () { return null; });
    },
    searchEvents: function (opts) {
      opts = opts || {};
      var qs = [];
      if (opts.q) qs.push('q=' + encodeURIComponent(opts.q));
      if (opts.kind) qs.push('kind=' + encodeURIComponent(opts.kind));
      if (opts.sev) qs.push('sev=' + encodeURIComponent(opts.sev));
      if (opts.limit) qs.push('limit=' + opts.limit);
      return call('/api/events/search' + (qs.length ? '?' + qs.join('&') : '')).catch(function () { return null; });
    },
    getYaraStatus: function () {
      return call('/api/yara/status').catch(function () { return null; });
    },
    reloadYara: function () {
      return call('/api/yara/reload', { method: 'POST' }).catch(function () { return null; });
    },
    installYaraStarter: function () {
      return call('/api/yara/install-starter-pack', { method: 'POST' }).catch(function () { return null; });
    },
    updateYaraCommunity: function () {
      return call('/api/yara/update-community', { method: 'POST', timeout: 120000 }).catch(function () { return { status: 'error' }; });
    },
  };

  /* ---- SECURITY mock fallback (mirrors the page design defaults) ---- */
  function mockSecurity(lang) {
    var ar = lang === 'ar';
    return {
      source: 'mock',
      counts: [
        { k: 'critical', n: 2 }, { k: 'high', n: 5 }, { k: 'medium', n: 9 }, { k: 'low', n: 14 },
      ],
      riskScore: 68,
      findings: [
        { cve: 'CVE-2024-6387', asset: 'web-03', sev: 'critical', score: 9.8, st: 'open', fix: ar ? 'ترقية OpenSSH إلى 9.8p1' : 'Upgrade OpenSSH to 9.8p1' },
        { cve: 'CVE-2024-3094', asset: 'db-01', sev: 'critical', score: 9.1, st: 'investigating', fix: ar ? 'إزالة حزمة xz المصابة' : 'Remove affected xz package' },
        { cve: 'CVE-2023-44487', asset: 'gw-edge', sev: 'high', score: 7.5, st: 'open', fix: ar ? 'تفعيل حد HTTP/2' : 'Enable HTTP/2 rate limit' },
        { cve: 'CVE-2024-21626', asset: 'k8s-node-2', sev: 'high', score: 8.6, st: 'patched', fix: ar ? 'تحديث runc إلى 1.1.12' : 'Update runc to 1.1.12' },
        { cve: 'CVE-2024-1086', asset: 'app-02', sev: 'medium', score: 5.4, st: 'open', fix: ar ? 'ترقيع نواة لينكس' : 'Apply kernel patch' },
        { cve: 'CVE-2023-38545', asset: 'proxy-01', sev: 'medium', score: 6.1, st: 'resolved', fix: ar ? 'تحديث curl/libcurl' : 'Update curl/libcurl' },
      ],
      recommendations: ar ? [
        { id: 'r1', text: 'فعّل المصادقة الثنائية على جميع حسابات المسؤول.', state: 'open' },
        { id: 'r2', text: 'أغلق المنفذ 23 (Telnet) غير المشفّر على bastion-01.', state: 'open' },
        { id: 'r3', text: 'جدول فحص الثغرات الأسبوعي تلقائياً.', state: 'open' },
      ] : [
        { id: 'r1', text: 'Enforce MFA on all administrator accounts.', state: 'open' },
        { id: 'r2', text: 'Close unencrypted port 23 (Telnet) on bastion-01.', state: 'open' },
        { id: 'r3', text: 'Schedule weekly vulnerability scans automatically.', state: 'open' },
      ],
    };
  }
})();
