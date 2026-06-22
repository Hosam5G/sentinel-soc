/* Equilibrium Sentinel — Alerts + Profile(login) pages */
(function () {
  const { useState, useEffect, useRef } = React;
  const { Icon, CardHead, StatusPill } = window;
  const toneColor = { danger: 'var(--critical)', warning: 'var(--warning)', success: 'var(--success)', info: 'var(--secondary)' };

  function PageHead({ t, lang, title, sub, actions }) {
    return (
      <div className="page-head">
        <div className="ph-t"><h2>{title}</h2><p>{sub}</p></div>
        <div className="ph-actions">{actions}</div>
      </div>
    );
  }

  const fmt = (ts, lang) => { try { return ts ? new Date(ts).toLocaleString(lang === 'ar' ? 'ar-EG' : 'en-US', { dateStyle: 'medium', timeStyle: 'short' }) : '—'; } catch (e) { return '—'; } };
  const ago = (ts, lang) => {
    if (!ts) return '';
    const s = Math.max(0, (Date.now() - ts) / 1000);
    if (s < 60) return lang === 'ar' ? 'الآن' : 'now';
    if (s < 3600) return (lang === 'ar' ? 'منذ ' : '') + Math.floor(s / 60) + (lang === 'ar' ? ' د' : 'm');
    if (s < 86400) return (lang === 'ar' ? 'منذ ' : '') + Math.floor(s / 3600) + (lang === 'ar' ? ' س' : 'h');
    return (lang === 'ar' ? 'منذ ' : '') + Math.floor(s / 86400) + (lang === 'ar' ? ' يوم' : 'd');
  };

  /* ---------------- ALERTS ---------------- */
  function Alerts({ t, lang }) {
    const [notifs, setNotifs] = useState([]);
    const [isAdmin, setIsAdmin] = useState(false);
    const [cfg, setCfg] = useState(null);
    const [vt, setVt] = useState(null);
    const [vtKey, setVtKey] = useState('');
    const [yara, setYara] = useState(null);
    const [yaraBusy, setYaraBusy] = useState(false);
    const [testMsg, setTestMsg] = useState('');
    const [saved, setSaved] = useState(false);
    const [isoLog, setIsoLog] = useState(null);     // {enabled, items}
    const [isoBusy, setIsoBusy] = useState(false);
    const [rt, setRt] = useState(null);             // realtime status
    const [rtBusy, setRtBusy] = useState(false);
    const [allow, setAllow] = useState(null);       // {names, paths}
    const [allowInput, setAllowInput] = useState('');
    const mounted = useRef(true);

    const load = () => {
      if (window.API && window.API.getNotifications)
        window.API.getNotifications(lang).then(list => { if (mounted.current && list) setNotifs(list); });
      if (window.API && window.API.getMe)
        window.API.getMe().then(d => {
          if (!mounted.current) return;
          const admin = !!(d && d.user && d.user.role === 'admin');
          setIsAdmin(admin);
          if (admin && window.API.getAlertSettings)
            window.API.getAlertSettings().then(a => { if (mounted.current && a) setCfg(a); });
          if (admin && window.API.getVtSettings)
            window.API.getVtSettings().then(v => { if (mounted.current && v) setVt(v); });
          if (admin && window.API.getYaraStatus)
            window.API.getYaraStatus().then(y => { if (mounted.current && y) setYara(y); });
          if (admin && window.API.getIsolationLog)
            window.API.getIsolationLog().then(s => { if (mounted.current && s) setIsoLog(s); });
          if (admin && window.API.getRealtimeStatus)
            window.API.getRealtimeStatus().then(s => { if (mounted.current && s) setRt(s); });
          if (admin && window.API.getAllowlist)
            window.API.getAllowlist().then(a => { if (mounted.current && a) setAllow(a); });
        });
    };
    useEffect(() => {
      mounted.current = true; load();
      const iv = setInterval(load, 15000);
      const onN = (e) => {
        const n = e.detail; if (!n || !mounted.current) return;
        setNotifs(prev => [{ id: n.id, ic: n.ic, tone: n.tone, t: (lang === 'ar' ? n.ar : n.en), s: (lang === 'ar' ? n.sub_ar : n.sub_en), route: n.route, report_id: n.report_id, ts: n.ts }, ...prev].slice(0, 50));
      };
      window.addEventListener('sx-notification', onN);
      return () => { mounted.current = false; clearInterval(iv); window.removeEventListener('sx-notification', onN); };
    }, [lang]);

    const goTo = (n) => {
      // clicking an alert takes you to the relevant page
      const route = n.route || 'alerts';
      if (n.report_id) window.__sxOpenReport = n.report_id;   // Reports page picks this up on mount
      window.dispatchEvent(new CustomEvent('sx-navigate', { detail: route }));
    };

    const counts = notifs.reduce((a, n) => { a[n.tone] = (a[n.tone] || 0) + 1; return a; }, {});
    const cards = [
      { k: 'danger', label: lang === 'ar' ? 'حرجة' : 'Critical' },
      { k: 'warning', label: lang === 'ar' ? 'تحذيرات' : 'Warnings' },
      { k: 'success', label: lang === 'ar' ? 'إيجابية' : 'Resolved' },
    ];

    return (
      <div>
        <PageHead t={t} lang={lang} title={t.nav.alerts} sub={lang === 'ar' ? 'كل التنبيهات والإشعارات الحيّة' : 'All live alerts and notifications'}
          actions={<><button className="btn btn-ghost" onClick={load}><Icon name="refresh" size={15} />{lang === 'ar' ? 'تحديث' : 'Refresh'}</button>
            <button className="btn btn-ghost" onClick={() => {
              setNotifs([]);
              if (window.API && window.API.clearNotifications) window.API.clearNotifications();
            }}><Icon name="check" size={15} />{t.misc.markRead}</button></>} />

        <div className="grid" style={{ gridTemplateColumns: 'repeat(3,1fr)', gap: 16, marginBottom: 20 }}>
          {cards.map(c => {
            const col = toneColor[c.k];
            return (
              <div className="card card-pad" key={c.k}>
                <div className="row" style={{ justifyContent: 'space-between', marginBottom: 8 }}>
                  <span className="muted" style={{ fontSize: 12.5 }}>{c.label}</span>
                  <span style={{ color: col }}><Icon name="bell" size={16} /></span>
                </div>
                <div className="value tnum" style={{ fontSize: 30, fontWeight: 700, color: col }}>{counts[c.k] || 0}</div>
              </div>
            );
          })}
        </div>

        <div className="card">
          <CardHead title={t.misc.notifications} icon="bell" iconColor="var(--warning)"
            right={<StatusPill tone="info" live>{t.misc.live}</StatusPill>} />
          <div className="card-pad" style={{ paddingTop: 4 }}>
            {notifs.length === 0 && <div className="muted" style={{ padding: '18px', textAlign: 'center', fontSize: 13 }}>{lang === 'ar' ? 'لا تنبيهات' : 'No alerts'}</div>}
            {notifs.map((n, i) => {
              const c = toneColor[n.tone] || 'var(--primary)';
              return (
                <div key={n.id || i} className="act" onClick={() => goTo(n)} style={{ cursor: 'pointer', borderRadius: 12 }}>
                  <span className="ai" style={{ color: c, background: `color-mix(in srgb, ${c} 15%, transparent)` }}><Icon name={n.ic} size={16} /></span>
                  <div className="at"><div className="t1">{n.t}</div><div className="t2">{n.s}</div></div>
                  <span className="row gap8" style={{ marginInlineStart: 'auto', color: 'var(--text-3)' }}>
                    <span className="when">{ago(n.ts, lang)}</span>
                    <Icon name={lang === 'ar' ? 'chevLeft' : 'chevRight'} size={15} />
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {isAdmin && cfg ? (() => {
          const upd = (path, val) => {
            setCfg(prev => {
              const n = JSON.parse(JSON.stringify(prev));
              if (path.length === 1) n[path[0]] = val;
              else { n[path[0]] = n[path[0]] || {}; n[path[0]][path[1]] = val; }
              return n;
            });
            setSaved(false);
          };
          const chInput = (ch, key, ph, type) => (
            <label className="tb-search" style={{ width: '100%', margin: '0 0 8px' }}>
              <input type={type || 'text'} placeholder={ph} value={(cfg[ch] && cfg[ch][key]) || ''} onChange={e => upd([ch, key], e.target.value)} />
            </label>
          );
          const tgl = (ch) => (
            <label className="row gap8" style={{ cursor: 'pointer', fontSize: 12.5 }}>
              <input type="checkbox" checked={!!(cfg[ch] && cfg[ch].enabled)} onChange={e => upd([ch, 'enabled'], e.target.checked)} />
              {lang === 'ar' ? 'مُفعّل' : 'Enabled'}
            </label>
          );
          const save = () => { window.API.saveAlertSettings(cfg).then(r => { if (r && r.ok) { setSaved(true); if (r.alerts) setCfg(r.alerts); } }); };
          const test = () => { setTestMsg(lang === 'ar' ? 'جارٍ الإرسال…' : 'Sending…'); window.API.testAlerts().then(r => { setTestMsg(JSON.stringify((r && r.results) || {})); }); };
          return (
            <div className="card" style={{ marginTop: 20 }}>
              <CardHead title={lang === 'ar' ? 'إعدادات التنبيهات والتكامل' : 'Alerts & integrations'} icon="bell" iconColor="var(--primary)"
                right={<label className="row gap8" style={{ cursor: 'pointer', fontSize: 12.5 }}>
                  <input type="checkbox" checked={!!cfg.enabled} onChange={e => upd(['enabled'], e.target.checked)} />
                  {lang === 'ar' ? 'تفعيل الإرسال' : 'Dispatch on'}
                </label>} />
              <div className="card-pad" style={{ paddingTop: 8 }}>
                <div className="muted" style={{ fontSize: 11.5, marginBottom: 12 }}>
                  🔒 {lang === 'ar' ? 'تُرسَل التنبيهات فقط إلى قنواتك أنت (SMTP/بوت Telegram/Webhook). لا يُرسَل شيء عن جهازك سوى نص التنبيه.' : 'Alerts go only to your own channels (your SMTP / Telegram bot / webhook). Nothing but the alert text is sent.'}
                </div>
                <div className="row gap8" style={{ marginBottom: 14, fontSize: 12.5, alignItems: 'center' }}>
                  <span className="muted">{lang === 'ar' ? 'أدنى خطورة للإرسال:' : 'Min severity:'}</span>
                  <select className="tb-search" style={{ padding: '4px 8px' }} value={cfg.min_sev || 'high'} onChange={e => upd(['min_sev'], e.target.value)}>
                    <option value="medium">medium</option><option value="high">high</option><option value="critical">critical</option>
                  </select>
                </div>
                <div className="grid" style={{ gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
                  <div>
                    <div className="row" style={{ justifyContent: 'space-between', marginBottom: 8 }}><b style={{ fontSize: 13 }}>Email (SMTP)</b>{tgl('email')}</div>
                    {chInput('email', 'host', lang === 'ar' ? 'خادم SMTP (مثال: smtp.gmail.com)' : 'SMTP host (e.g. smtp.gmail.com)')}
                    {chInput('email', 'port', lang === 'ar' ? 'المنفذ (587 أو 465)' : 'Port (587 or 465)', 'number')}
                    {chInput('email', 'user', lang === 'ar' ? 'بريدك الكامل (you@gmail.com)' : 'your full email (you@gmail.com)')}
                    {chInput('email', 'password', lang === 'ar' ? 'كلمة مرور التطبيقات' : 'app password', 'password')}
                    {chInput('email', 'to', lang === 'ar' ? 'إلى مَن تُرسل التنبيهات' : 'send alerts to (recipient)')}
                    <div className="muted" style={{ fontSize: 11, lineHeight: 1.7, marginTop: 4 }}>
                      {lang === 'ar'
                        ? '⚠ لـ Gmail: فعّل التحقّق بخطوتين ثم أنشئ «كلمة مرور تطبيقات» من إعدادات حساب Google (لا تستخدم كلمة سرّك العادية). الخادم: smtp.gmail.com · المنفذ: 587.'
                        : '⚠ For Gmail: enable 2-Step Verification, then create an "App Password" in your Google Account (not your normal password). Host: smtp.gmail.com · Port: 587.'}
                    </div>
                  </div>
                  <div>
                    <div className="row" style={{ justifyContent: 'space-between', marginBottom: 8 }}><b style={{ fontSize: 13 }}>Telegram</b>{tgl('telegram')}</div>
                    {chInput('telegram', 'token', lang === 'ar' ? 'توكن البوت' : 'bot token')}
                    {chInput('telegram', 'chat_id', 'chat id')}
                    <div className="muted" style={{ fontSize: 11 }}>{lang === 'ar' ? 'أنشئ بوتاً عبر @BotFather واحصل على chat_id.' : 'Create a bot via @BotFather, then get your chat_id.'}</div>
                  </div>
                  <div>
                    <div className="row" style={{ justifyContent: 'space-between', marginBottom: 8 }}><b style={{ fontSize: 13 }}>Webhook</b>{tgl('webhook')}</div>
                    {chInput('webhook', 'url', 'https://hooks.slack.com/…')}
                    <div className="muted" style={{ fontSize: 11 }}>{lang === 'ar' ? 'متوافق مع Slack/Discord/Teams وأي webhook يقبل JSON.' : 'Works with Slack/Discord/Teams or any JSON webhook.'}</div>
                  </div>
                </div>
                <div className="row gap8" style={{ marginTop: 16 }}>
                  <button className="btn btn-primary btn-sm" onClick={save}><Icon name="check" size={14} />{lang === 'ar' ? 'حفظ' : 'Save'}</button>
                  <button className="btn btn-ghost btn-sm" onClick={test}><Icon name="zap" size={14} />{lang === 'ar' ? 'إرسال تجربة' : 'Send test'}</button>
                  {saved ? <span className="muted" style={{ fontSize: 12, color: 'var(--success)' }}>{lang === 'ar' ? 'حُفظ' : 'Saved'}</span> : null}
                  {testMsg ? <span className="mono muted" style={{ fontSize: 11 }}>{testMsg}</span> : null}
                </div>
              </div>
            </div>
          );
        })() : null}

        {isAdmin && vt ? (
          <div className="card" style={{ marginTop: 20 }}>
            <CardHead title={lang === 'ar' ? 'VirusTotal (اختياري — فحص البصمة فقط)' : 'VirusTotal (optional — hash lookup only)'} icon="globe" iconColor="var(--secondary)"
              right={<label className="row gap8" style={{ cursor: 'pointer', fontSize: 12.5 }}>
                <input type="checkbox" checked={!!vt.virustotal.enabled} onChange={e => setVt(p => ({ ...p, virustotal: { ...p.virustotal, enabled: e.target.checked } }))} />
                {lang === 'ar' ? 'تفعيل' : 'Enable'}
              </label>} />
            <div className="card-pad" style={{ paddingTop: 8 }}>
              <div className="muted" style={{ fontSize: 11.5, marginBottom: 12 }}>
                🔒 {lang === 'ar'
                  ? 'مُطفأ افتراضياً. عند تفعيله، يُرسَل فقط بصمة الملف (SHA-256) إلى حسابك في VirusTotal بمفتاحك أنت — لا يُرفع الملف نفسه أبداً. يُعطَّل تلقائياً في الوضع غير المتصل.'
                  : 'Off by default. When enabled, only the file hash (SHA-256) is sent to VirusTotal using your own key — the file itself is never uploaded. Disabled automatically in offline mode.'}
              </div>
              <div className="row gap8">
                <label className="tb-search" style={{ flex: 1, margin: 0 }}>
                  <Icon name="lock" size={15} />
                  <input type="password" placeholder={vt.virustotal.api_key ? '********' : (lang === 'ar' ? 'مفتاح API الخاص بك' : 'your API key')} value={vtKey} onChange={e => setVtKey(e.target.value)} />
                </label>
                <button className="btn btn-primary btn-sm" onClick={() => {
                  const payload = { enabled: vt.virustotal.enabled };
                  if (vtKey) payload.api_key = vtKey;
                  window.API.saveVtSettings(payload).then(() => { setVtKey(''); window.API.getVtSettings().then(v => v && setVt(v)); });
                }}>{lang === 'ar' ? 'حفظ' : 'Save'}</button>
              </div>
              {vt.offline ? <div className="muted" style={{ fontSize: 11, marginTop: 8, color: 'var(--warning)' }}>{lang === 'ar' ? 'الوضع غير المتصل مُفعّل — VirusTotal معطّل.' : 'Offline mode is on — VirusTotal is disabled.'}</div> : null}
            </div>
          </div>
        ) : null}

        {isAdmin ? (
          <div className="card" style={{ marginTop: 20 }}>
            <CardHead title={lang === 'ar' ? 'الحماية النشطة (كشف سلوكي + عزل تلقائي)' : 'Active protection (behavioral + auto-isolation)'} icon="shield-check" iconColor="var(--success)"
              right={<StatusPill tone={(isoLog && isoLog.enabled) ? 'success' : 'info'} live={!!(isoLog && isoLog.enabled)}>
                {(isoLog && isoLog.enabled) ? (lang === 'ar' ? 'العزل مُفعّل' : 'Isolation ON') : (lang === 'ar' ? 'العزل متوقّف' : 'Isolation OFF')}
              </StatusPill>} />
            <div className="card-pad">
              <div className="muted" style={{ fontSize: 12.5, marginBottom: 14, lineHeight: 1.85 }}>
                {lang === 'ar'
                  ? '🛡️ المحرّك السلوكي يكشف التهديدات بسلوكها (لا بتوقيعها): تشفير فدية، beaconing، وسلاسل برامج خبيثة. عند تفعيل العزل التلقائي، يُعلّق البرنامج العمليات الخبيثة الواضحة فوراً (تعليق قابل للتراجع — لا حذف). العمليات الحرجة للنظام محميّة ولن تُمسّ أبداً.'
                  : '🛡️ The behavioral engine catches threats by behavior (not signature): ransomware encryption, beaconing, malicious process chains. With auto-isolation on, clear malicious processes are suspended instantly (reversible — never deleted). Critical OS processes are protected and never touched.'}
              </div>
              {(() => { const R = rt || { running: true, stats: {} }; return (
                <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', padding: '12px 14px', background: 'color-mix(in srgb, var(--success) 10%, transparent)', borderRadius: 10, marginBottom: 12, border: '1px solid var(--success)' }}>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontWeight: 600, fontSize: 13.5 }}>
                      {lang === 'ar' ? '⚡ الحماية اللحظية (مراقبة مستمرة)' : '⚡ Real-time protection (always-on)'}
                    </div>
                    <div className="muted" style={{ fontSize: 11.5, marginTop: 2, lineHeight: 1.6 }}>
                      {lang === 'ar'
                        ? 'مفعّلة دائماً. تراقب كل عملية جديدة + الاتصالات + ملفاتك لحظياً عبر أحداث النظام، وتعزل التهديد فور ظهوره.'
                        : 'Always on. Watches every new process + connections + your files in real time via OS events, isolating threats the moment they appear.'}
                    </div>
                    <div className="mono" style={{ fontSize: 11, color: 'var(--success)', marginTop: 4 }}>
                      {lang === 'ar' ? 'نشط · ' : 'Active · '}{(R.stats && R.stats.events) || 0}{lang === 'ar' ? ' حدث · ' : ' events · '}{(R.stats && R.stats.isolations) || 0}{lang === 'ar' ? ' عزل' : ' isolations'}
                      {R.engine ? ' · ' + (R.engine === 'sysmon+etw' ? (lang === 'ar' ? 'محرّك Sysmon/ETW' : 'Sysmon/ETW engine') : R.engine === 'wmi' ? (lang === 'ar' ? 'أحداث WMI' : 'WMI events') : (lang === 'ar' ? 'مسح دوري' : 'polling')) : ''}
                    </div>
                    {R.engine && R.engine === 'polling' ? (
                      <div className="muted" style={{ fontSize: 10.5, marginTop: 3, lineHeight: 1.6 }}>
                        {lang === 'ar'
                          ? '💡 لأداء أعلى وأخفّ: ثبّت Sysmon من Microsoft (telemetry بمستوى ETW)، أو pywin32 لأحداث WMI.'
                          : '💡 For lighter, richer detection: install Sysmon from Microsoft (ETW-grade), or pywin32 for WMI events.'}
                      </div>
                    ) : null}
                  </div>
                  <StatusPill tone="success" live>{lang === 'ar' ? 'يعمل' : 'ON'}</StatusPill>
                </div>
              ); })()}
              {rt && rt.baseline ? (
                <div style={{ padding: '12px 14px', background: rt.baseline.learning ? 'color-mix(in srgb, var(--primary) 9%, transparent)' : 'rgba(255,255,255,0.04)', borderRadius: 10, marginBottom: 12, border: rt.baseline.learning ? '1px solid color-mix(in srgb, var(--primary) 35%, transparent)' : '1px solid transparent' }}>
                  <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', marginBottom: rt.baseline.learning ? 8 : 0 }}>
                    <div>
                      <div style={{ fontWeight: 600, fontSize: 13.5 }}>{lang === 'ar' ? '🧠 خط الأساس السلوكي' : '🧠 Behavioral baseline'}</div>
                      <div className="muted" style={{ fontSize: 11.5, marginTop: 2, lineHeight: 1.6 }}>
                        {rt.baseline.learning
                          ? (lang === 'ar'
                            ? `يتعلّم ما هو طبيعي على جهازك (${rt.baseline.days_elapsed}/${rt.baseline.days_target} يوم · ${rt.baseline.known_processes} عملية معروفة). بعد اكتماله يقلّل الإنذارات الكاذبة بشكل كبير.`
                            : `Learning what's normal on your machine (${rt.baseline.days_elapsed}/${rt.baseline.days_target} days · ${rt.baseline.known_processes} known processes). Once complete it sharply cuts false positives.`)
                          : (lang === 'ar'
                            ? `مكتمل ✓ — يعرف ${rt.baseline.known_processes} عملية معتادة على جهازك ويستخدمها لتقليل الإنذارات الكاذبة.`
                            : `Complete ✓ — knows ${rt.baseline.known_processes} normal processes on your machine and uses them to cut false positives.`)}
                      </div>
                    </div>
                    <StatusPill tone={rt.baseline.learning ? 'info' : 'success'} live={rt.baseline.learning}>
                      {rt.baseline.learning ? (lang === 'ar' ? 'يتعلّم' : 'Learning') : (lang === 'ar' ? 'مكتمل' : 'Ready')}
                    </StatusPill>
                  </div>
                  {rt.baseline.learning ? (
                    <div style={{ height: 6, background: 'rgba(255,255,255,0.1)', borderRadius: 3, overflow: 'hidden' }}>
                      <div style={{ width: rt.baseline.progress_pct + '%', height: '100%', background: 'var(--primary)', borderRadius: 3, transition: 'width .4s' }} />
                    </div>
                  ) : null}
                </div>
              ) : null}
              <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', padding: '12px 14px', background: (rt && rt.monitor_only) ? 'color-mix(in srgb, var(--secondary) 10%, transparent)' : 'rgba(255,255,255,0.04)', borderRadius: 10, marginBottom: 12, border: (rt && rt.monitor_only) ? '1px solid var(--secondary)' : '1px solid transparent' }}>
                <div style={{ minWidth: 0 }}>
                  <div style={{ fontWeight: 600, fontSize: 13.5 }}>{lang === 'ar' ? '👁️ وضع المراقبة فقط (Monitor-Only)' : '👁️ Monitor-Only mode'}</div>
                  <div className="muted" style={{ fontSize: 11.5, marginTop: 2, lineHeight: 1.6 }}>
                    {lang === 'ar'
                      ? 'يُنبّه دون عزل. مُستحسَن أوّل ١-٢ أسبوع: راقب الإنذارات، أضف برامجك الموثوقة لقائمة السماح، ثمّ عطّله لتفعيل العزل. (هكذا تبدأ أنظمة EDR الحقيقية.)'
                      : 'Alerts without isolating. Recommended for the first 1-2 weeks: watch alerts, allowlist your trusted apps, then turn it off to enable isolation. (How real EDRs roll out.)'}
                  </div>
                </div>
                <button className={'btn btn-sm ' + ((rt && rt.monitor_only) ? 'btn-primary' : 'btn-ghost')} disabled={rtBusy}
                  onClick={() => {
                    setRtBusy(true);
                    window.API.setMonitorOnly(!(rt && rt.monitor_only)).then(r => {
                      setRtBusy(false);
                      if (r && r.ok) setRt(s => ({ ...(s || {}), monitor_only: r.monitor_only }));
                    });
                  }}>
                  <Icon name={(rt && rt.monitor_only) ? 'eye' : 'x'} size={14} />
                  {(rt && rt.monitor_only) ? (lang === 'ar' ? 'مُفعّل' : 'On') : (lang === 'ar' ? 'مُعطّل' : 'Off')}
                </button>
              </div>
              <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', padding: '12px 14px', background: 'rgba(255,255,255,0.04)', borderRadius: 10, marginBottom: 12, opacity: (rt && rt.monitor_only) ? 0.55 : 1 }}>
                <div>
                  <div style={{ fontWeight: 600, fontSize: 13.5 }}>{lang === 'ar' ? 'العزل التلقائي للتهديدات الواضحة' : 'Auto-isolate clear threats'}</div>
                  <div className="muted" style={{ fontSize: 11.5, marginTop: 2 }}>{(rt && rt.monitor_only) ? (lang === 'ar' ? '⏸ معطّل مؤقّتاً بسبب وضع المراقبة فقط' : '⏸ Paused by Monitor-Only mode') : (lang === 'ar' ? 'يعلّق العمليات الخبيثة المؤكّدة دون انتظار موافقتك' : 'Suspends confirmed-malicious processes without waiting for approval')}</div>
                </div>
                <button className={'btn btn-sm ' + ((isoLog && isoLog.enabled) ? 'btn-primary' : 'btn-ghost')} disabled={isoBusy}
                  onClick={() => {
                    setIsoBusy(true);
                    window.API.toggleAutoIsolate(!(isoLog && isoLog.enabled)).then(r => {
                      setIsoBusy(false);
                      if (r && r.ok) setIsoLog(s => ({ ...s, enabled: r.enabled }));
                    });
                  }}>
                  <Icon name={(isoLog && isoLog.enabled) ? 'check' : 'x'} size={14} />
                  {(isoLog && isoLog.enabled) ? (lang === 'ar' ? 'مُفعّل' : 'Enabled') : (lang === 'ar' ? 'مُعطّل' : 'Disabled')}
                </button>
              </div>
              {(isoLog && isoLog.enabled) ? (
                <div style={{ fontSize: 11.5, color: 'var(--warning)', marginBottom: 12, padding: '8px 12px', background: 'color-mix(in srgb, var(--warning) 10%, transparent)', borderRadius: 8 }}>
                  ⚠ {lang === 'ar' ? 'العزل التلقائي نشط. أي عملية تُعلّق ستظهر أدناه مع طريقة التراجع.' : 'Auto-isolation is active. Any suspended process appears below with an undo.'}
                </div>
              ) : null}
              <div style={{ fontWeight: 600, fontSize: 12.5, marginBottom: 8 }}>{lang === 'ar' ? 'سجلّ العزل' : 'Isolation log'}</div>
              {(!isoLog || (isoLog.items || []).length === 0) ? (
                <div className="muted" style={{ fontSize: 12.5 }}>{lang === 'ar' ? 'لم يُعزَل أي شيء — جهازك نظيف حتى الآن.' : 'Nothing isolated — your machine is clean so far.'}</div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {((isoLog && isoLog.items) || []).slice(0, 8).map((it, i) => (
                    <div key={i} className="row" style={{ justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, padding: '10px 12px', background: 'rgba(255,255,255,0.04)', borderRadius: 9 }}>
                      <div style={{ minWidth: 0, flex: 1 }}>
                        <div style={{ fontSize: 12.5, fontWeight: 600 }}>{it.name} <span className="mono muted" style={{ fontSize: 11 }}>pid {it.pid}</span></div>
                        <div className="muted" style={{ fontSize: 11.5, marginTop: 2, wordBreak: 'break-word' }}>{it.reason}</div>
                      </div>
                      <button className="btn btn-ghost btn-sm" style={{ flexShrink: 0 }}
                        onClick={() => { window.API.resumeProcess(it.pid).then(() => load()); }}>
                        <Icon name="refresh" size={12} />{lang === 'ar' ? 'استئناف' : 'Resume'}</button>
                    </div>
                  ))}
                </div>
              )}

              <div style={{ marginTop: 16, paddingTop: 14, borderTop: '1px solid rgba(255,255,255,0.08)' }}>
                <div style={{ fontWeight: 600, fontSize: 12.5, marginBottom: 4 }}>{lang === 'ar' ? 'قائمة السماح (برامج موثوقة)' : 'Allowlist (trusted apps)'}</div>
                <div className="muted" style={{ fontSize: 11.5, marginBottom: 10, lineHeight: 1.7 }}>
                  {lang === 'ar'
                    ? 'برامجك الموثوقة (أدوات إدارة، نسخ احتياطي، سكربتات داخلية) لن تُنبّه أو تُعزل. أضف اسم البرنامج (مثل mytool.exe) أو جزءاً من مساره.'
                    : 'Your trusted apps (admin tools, backup, internal scripts) will never alert or isolate. Add a process name (e.g. mytool.exe) or a path fragment.'}
                </div>
                <div className="row gap8" style={{ marginBottom: 10 }}>
                  <input type="text" className="tb-search" style={{ flex: 1, padding: '7px 11px', fontSize: 12.5 }}
                    placeholder={lang === 'ar' ? 'اسم برنامج أو مسار…' : 'process name or path…'}
                    value={allowInput} onChange={e => setAllowInput(e.target.value)}
                    onKeyDown={e => { if (e.key === 'Enter' && allowInput.trim()) {
                      const v = allowInput.trim();
                      const isPath = v.indexOf('\\') >= 0 || v.indexOf('/') >= 0 || v.indexOf(':') >= 0;
                      window.API.allowlistAdd(isPath ? '' : v, isPath ? v : '').then(r => { if (r && r.ok) { setAllow({ names: r.names, paths: r.paths }); setAllowInput(''); } });
                    } }} />
                  <button className="btn btn-primary btn-sm" onClick={() => {
                    const v = allowInput.trim(); if (!v) return;
                    if (!(window.API && window.API.allowlistAdd)) {
                      if (window.toast) window.toast(lang === 'ar' ? 'حدّث ملف api.js أولاً (نسخة قديمة)' : 'Update api.js first (stale version)');
                      return;
                    }
                    const isPath = v.indexOf('\\') >= 0 || v.indexOf('/') >= 0 || v.indexOf(':') >= 0;
                    window.API.allowlistAdd(isPath ? '' : v, isPath ? v : '').then(r => {
                      if (r && r.ok) {
                        setAllow({ names: r.names, paths: r.paths }); setAllowInput('');
                        if (window.toast) window.toast(lang === 'ar' ? 'أُضيف لقائمة السماح' : 'Added to allowlist');
                      } else if (window.toast) {
                        window.toast(lang === 'ar' ? 'تعذّرت الإضافة — تأكّد أنك مدير' : 'Could not add — ensure you are admin');
                      }
                    });
                  }}><Icon name="plus" size={13} />{lang === 'ar' ? 'إضافة' : 'Add'}</button>
                </div>
                {allow && ((allow.names || []).length || (allow.paths || []).length) ? (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                    {[].concat((allow.names || []).map(n => ({ v: n, isPath: false })), (allow.paths || []).map(p => ({ v: p, isPath: true }))).map((it, i) => (
                      <span key={i} className="row gap8" style={{ fontSize: 11.5, padding: '4px 10px', background: 'rgba(255,255,255,0.06)', borderRadius: 20 }}>
                        <Icon name={it.isPath ? 'folder' : 'cpu'} size={11} />{it.v}
                        <span style={{ cursor: 'pointer', opacity: 0.6 }} onClick={() => {
                          window.API.allowlistRemove(it.isPath ? '' : it.v, it.isPath ? it.v : '').then(r => { if (r && r.ok) setAllow({ names: r.names, paths: r.paths }); });
                        }}><Icon name="x" size={11} /></span>
                      </span>
                    ))}
                  </div>
                ) : (
                  <div className="muted" style={{ fontSize: 11.5 }}>{lang === 'ar' ? 'لا برامج في قائمة السماح بعد.' : 'No allowlisted apps yet.'}</div>
                )}
              </div>
            </div>
          </div>
        ) : null}

        {isAdmin && yara ? (
          <div className="card" style={{ marginTop: 20 }}>
            <CardHead title={lang === 'ar' ? 'قواعد YARA (فحص ملفات بقواعد محلية)' : 'YARA rules (local pattern scanning)'} icon="shield" iconColor="var(--primary)"
              right={<span className="row gap8" style={{ fontSize: 12.5 }}>
                {yara.loaded ? <StatusPill tone="success" live>{yara.rule_files.length} {lang === 'ar' ? 'ملف' : 'files'}</StatusPill>
                  : <StatusPill tone="warning">{lang === 'ar' ? 'بلا قواعد' : 'No rules'}</StatusPill>}
              </span>} />
            <div className="card-pad" style={{ paddingTop: 8 }}>
              <div className="muted" style={{ fontSize: 11.5, marginBottom: 10, lineHeight: 1.8 }}>
                🔒 {lang === 'ar'
                  ? 'YARA تفحص الملفات محلياً ضد قواعد على جهازك — لا يُرفع أي ملف لأي مكان.'
                  : 'YARA scans files locally against rules on your machine — nothing is uploaded.'}
                <br/>{lang === 'ar'
                  ? '📁 قواعدك الخاصة: ضع ملفات .yar في مجلد '
                  : '📁 Your own rules: drop .yar files into '}<code>sentinel_rules/</code>{lang === 'ar' ? ' بجوار البرنامج.' : ' beside the app.'}
                <br/>{lang === 'ar'
                  ? '🌐 قواعد المجتمع تُحمّل وتُحدّث تلقائياً كل ٢٤ ساعة إلى '
                  : '🌐 Community rules auto-download & update every 24h into '}<code>sentinel_rules/community/</code>
              </div>
              <div className="muted" style={{ fontSize: 12, marginBottom: 8 }}>
                {lang === 'ar' ? 'المحرّك: ' : 'Engine: '}<b>{yara.engine}</b>
                {!yara.yara_python_installed ? <span style={{ display: 'block', marginTop: 4, color: 'var(--warning)' }}>
                  {lang === 'ar'
                    ? '⚠ المحرّك البديل المدمج يعمل (الكشف فعّال). لتفعيل محرّك YARA الكامل، إن كانت yara-python مثبّتة وما زالت لا تعمل فالمشكلة في libyara.dll — جرّب: '
                    : '⚠ The built-in fallback engine is active (detection works). For the full YARA engine, if yara-python is installed but still failing, libyara.dll is the issue — try: '}
                  <code>pip install --force-reinstall yara-python</code>
                </span> : null}
              </div>
              {yara.rule_files.length ? (
                <div className="muted" style={{ fontSize: 11.5, marginBottom: 10 }}>
                  {(lang === 'ar' ? 'قواعدك: ' : 'Your rules: ') + yara.rule_files.join(', ')}
                </div>
              ) : null}
              {yara.community_files && yara.community_files.length ? (
                <div className="muted" style={{ fontSize: 11.5, marginBottom: 10 }}>
                  {(lang === 'ar' ? 'قواعد المجتمع: ' : 'Community rules: ') + yara.community_files.length + ' ' + (lang === 'ar' ? 'ملف' : 'files')}
                </div>
              ) : null}
              {yara.auto_update ? (
                <div className="muted" style={{ fontSize: 11, marginBottom: 10, padding: '6px 10px', background: 'var(--bg-inset)', borderRadius: 6 }}>
                  {lang === 'ar' ? '🔄 التحديث الدوري كل ' : '🔄 Auto-update every '}{yara.auto_update.interval_hours}{lang === 'ar' ? ' ساعة' : 'h'}
                  {yara.auto_update.last_run_ts > 0
                    ? <span> · {lang === 'ar' ? 'آخر تحديث: ' : 'last: '}{new Date(yara.auto_update.last_run_ts).toLocaleString(lang === 'ar' ? 'ar' : 'en')} ({yara.auto_update.downloaded} ✓ · {yara.auto_update.failed} ✗)</span>
                    : <span> · {lang === 'ar' ? 'لم يُشغّل بعد' : 'not run yet'}</span>}
                  {yara.auto_update.last_error ? <div style={{ marginTop: 4, color: 'var(--warning)' }}>⚠ {yara.auto_update.last_error}</div> : null}
                </div>
              ) : null}
              <div className="row gap8">
                <button className="btn btn-primary btn-sm" disabled={yaraBusy} onClick={() => {
                  setYaraBusy(true);
                  window.API.installYaraStarter().then(() => window.API.getYaraStatus().then(y => { setYara(y); setYaraBusy(false); }));
                }}>
                  <Icon name="download" size={13} />{lang === 'ar' ? 'ثبّت قواعد مبدئية' : 'Install starter rules'}
                </button>
                <button className="btn btn-primary btn-sm" disabled={yaraBusy} onClick={() => {
                  setYaraBusy(true);
                  window.API.updateYaraCommunity().then(() => window.API.getYaraStatus().then(y => { setYara(y); setYaraBusy(false); }));
                }}>
                  <Icon name="refresh" size={13} />{lang === 'ar' ? 'حدّث قواعد المجتمع الآن' : 'Update community rules now'}
                </button>
                <button className="btn btn-ghost btn-sm" disabled={yaraBusy} onClick={() => {
                  setYaraBusy(true);
                  window.API.reloadYara().then(() => window.API.getYaraStatus().then(y => { setYara(y); setYaraBusy(false); }));
                }}>
                  <Icon name="refresh" size={13} />{lang === 'ar' ? 'إعادة تحميل' : 'Reload local'}
                </button>
              </div>
            </div>
          </div>
        ) : null}
      </div>
    );
  }
  function Profile({ t, lang }) {
    const [me, setMe] = useState(null);
    const [users, setUsers] = useState([]);
    const [mode, setMode] = useState('signin');   // 'signin' | 'register'
    const [u, setU] = useState('');
    const [p, setP] = useState('');
    const [nm, setNm] = useState('');
    const [em, setEm] = useState('');
    const [role, setRole] = useState('analyst');
    const [showAddUser, setShowAddUser] = useState(false);
    const [err, setErr] = useState('');
    const [busy, setBusy] = useState(false);
    const [code, setCode] = useState('');
    const [mfaStep, setMfaStep] = useState(false);   // login needs a 2FA code
    const [needsSetup, setNeedsSetup] = useState(false);
    const mounted = useRef(true);

    const refresh = () => {
      if (!window.API) return;
      window.API.getMe().then(m => {
        if (!mounted.current) return;
        setMe(m && m.user ? m.user : null);
        setNeedsSetup(!!(m && m.needsSetup));
      });
      window.API.getUsers().then(list => { if (mounted.current) setUsers(list); });
    };
    useEffect(() => { mounted.current = true; refresh(); return () => { mounted.current = false; }; }, []);

    const doLogin = () => {
      if (!u.trim() || !p || busy) return;
      setBusy(true); setErr('');
      window.API.login(u.trim(), p, code).then(res => {
        if (res && res.ok) {
          setMe(res.user); setP(''); setU(''); setCode(''); setMfaStep(false);
          window.dispatchEvent(new Event('sx-auth-changed'));
          refresh();
        } else if (res && res.mfaRequired) {
          setMfaStep(true);
          setErr(code ? (lang === 'ar' ? 'رمز غير صحيح' : 'Invalid code') : '');
        } else if (res && res.error && res.error.indexOf('locked') >= 0) {
          setErr(lang === 'ar' ? 'الحساب مقفل مؤقتاً بعد محاولات فاشلة' : res.error);
        } else { setErr(lang === 'ar' ? 'بيانات الدخول غير صحيحة' : 'Invalid credentials'); }
      }).finally(() => mounted.current && setBusy(false));
    };
    const pwOk = (s) => s.length >= 8 && /[a-zA-Z]/.test(s) && /[0-9]/.test(s);
    const doRegister = () => {
      if (!u.trim() || !nm.trim() || busy) { setErr(lang === 'ar' ? 'أكمل كل الحقول' : 'Fill all fields'); return; }
      if (!pwOk(p)) { setErr(lang === 'ar' ? 'كلمة السر: ٨ أحرف فأكثر وتحوي حروفاً وأرقاماً' : 'Password: 8+ chars with letters and numbers'); return; }
      setBusy(true); setErr('');
      window.API.register(u.trim(), nm.trim(), role || 'analyst', p, em.trim()).then(res => {
        if (res && res.ok) {
          window.API.login(u.trim(), p).then(r2 => {
            if (r2 && r2.ok) { setMe(r2.user); window.dispatchEvent(new Event('sx-auth-changed')); }
            setP(''); setNm(''); setRole('analyst'); setMode('signin'); refresh();
          });
        } else if (res && res.error === 'forbidden') {
          setErr(lang === 'ar' ? 'فقط المدير يمكنه إنشاء حسابات' : 'Only an admin can create accounts');
        } else { setErr(res && res.error === 'username already exists' ? (lang === 'ar' ? 'اسم المستخدم موجود' : 'Username already exists') : (res && res.error) || (lang === 'ar' ? 'تعذّر إنشاء الحساب' : 'Could not create account')); }
      }).finally(() => mounted.current && setBusy(false));
    };
    // admin creates an account WITHOUT switching the current session to it
    const doRegisterByAdmin = () => {
      if (!u.trim() || !nm.trim() || busy) { setErr(lang === 'ar' ? 'أكمل كل الحقول' : 'Fill all fields'); return; }
      if (!pwOk(p)) { setErr(lang === 'ar' ? 'كلمة السر: ٨ أحرف فأكثر وتحوي حروفاً وأرقاماً' : 'Password: 8+ chars with letters and numbers'); return; }
      setBusy(true); setErr('');
      window.API.register(u.trim(), nm.trim(), role || 'analyst', p, em.trim()).then(res => {
        if (res && res.ok) {
          setU(''); setP(''); setNm(''); setEm(''); setRole('analyst');
          setShowAddUser(false); refresh();
        } else if (res && (res.error === 'forbidden' || (res.error || '').includes('admin'))) {
          setErr(lang === 'ar' ? 'فقط المدير يمكنه إنشاء حسابات' : 'Only an admin can create accounts');
        } else {
          setErr(res && res.error === 'username already exists' ? (lang === 'ar' ? 'اسم المستخدم موجود' : 'Username already exists') : (res && res.error) || (lang === 'ar' ? 'تعذّر إنشاء الحساب' : 'Could not create account'));
        }
      }).finally(() => mounted.current && setBusy(false));
    };
    const doLogout = () => {
      window.API.logout().then(() => { setMe(null); window.dispatchEvent(new Event('sx-auth-changed')); refresh(); });
    };

    // MFA enrolment
    const [mfaInfo, setMfaInfo] = useState(null);   // {secret, otpauth}
    const [mfaCode, setMfaCode] = useState('');
    const startMfa = () => { window.API.mfaSetup().then(d => { if (d && d.ok) setMfaInfo(d); }); };
    const confirmMfa = () => {
      window.API.mfaEnable(mfaCode).then(d => {
        if (d && d.ok) { setMfaInfo(null); setMfaCode(''); refresh(); }
        else setErr(lang === 'ar' ? 'رمز غير صحيح' : 'Invalid code');
      });
    };
    const disableMfa = () => { window.API.mfaDisable().then(() => refresh()); };
    const changeRole = (uname, r) => { window.API.setUserRole(uname, r).then(() => refresh()); };
    const removeUser = (uname) => { window.API.deleteUser(uname).then(() => refresh()); };
    const isAdmin = me && me.role === 'admin';
    const [health, setHealth] = useState(null);
    const [audit, setAudit] = useState([]);
    const [bkMsg, setBkMsg] = useState('');
    useEffect(() => {
      if (!isAdmin || !window.API) return;
      window.API.getHealth().then(h => { if (mounted.current) setHealth(h); });
      window.API.getAudit().then(a => { if (mounted.current && a) setAudit(a.items || []); });
    }, [isAdmin]);
    const doBackup = () => { setBkMsg(lang === 'ar' ? 'جارٍ…' : 'Working…'); window.API.createBackup().then(r => setBkMsg(r && r.ok ? (lang === 'ar' ? 'تم: ' : 'Saved: ') + r.file : (lang === 'ar' ? 'فشل' : 'Failed'))); };

    const sub = lang === 'ar' ? 'تسجيل دخول الموظفين وسجلّ الجلسات' : 'Employee sign-in and session log';
    const field = (icon, ph, val, set, type) => (
      <label className="tb-search" style={{ width: '100%', margin: '0 0 10px' }}>
        <Icon name={icon} size={16} />
        <input type={type || 'text'} placeholder={ph} value={val} onChange={e => set(e.target.value)} onKeyDown={e => e.key === 'Enter' && (mode === 'signin' ? doLogin() : doRegister())} />
      </label>
    );

    return (
      <div>
        <PageHead t={t} lang={lang} title={t.nav.profile} sub={sub} actions={null} />

        <window.BackgroundPicker lang={lang} />

        <div className="grid" style={{ gridTemplateColumns: me ? '1fr' : 'minmax(0,440px) 1fr', gap: 20, marginBottom: 20 }}>
          {!me ? (
            <div className="card card-pad" style={{ maxWidth: 440 }}>
              <div className="row" style={{ gap: 8, marginBottom: 14 }}>
                <button className={'btn btn-sm ' + (mode === 'signin' ? 'btn-primary' : 'btn-ghost')} onClick={() => { setMode('signin'); setErr(''); }}>{lang === 'ar' ? 'دخول' : 'Sign in'}</button>
                <button className={'btn btn-sm ' + (mode === 'register' ? 'btn-primary' : 'btn-ghost')} onClick={() => { setMode('register'); setErr(''); }}>{lang === 'ar' ? 'حساب جديد' : 'Create account'}</button>
              </div>
              {mode === 'signin' ? (
                <>
                  {needsSetup ? <div className="muted" style={{ fontSize: 12, marginBottom: 10 }}>{lang === 'ar' ? 'لا يوجد مستخدمون بعد — أنشئ أول حساب (سيكون مديراً).' : 'No users yet — create the first account (it becomes admin).'}</div> : null}
                  {field('user', lang === 'ar' ? 'اسم المستخدم' : 'Username', u, setU)}
                  {field('lock', lang === 'ar' ? 'كلمة السر' : 'Password', p, setP, 'password')}
                  {mfaStep ? (
                    <label className="tb-search" style={{ width: '100%', margin: '0 0 10px' }}>
                      <Icon name="shield" size={16} />
                      <input type="text" inputMode="numeric" maxLength={6}
                        placeholder={lang === 'ar' ? 'رمز المصادقة (٦ أرقام)' : 'Authenticator code (6 digits)'}
                        value={code} onChange={e => setCode(e.target.value)} onKeyDown={e => e.key === 'Enter' && doLogin()} autoFocus />
                    </label>
                  ) : null}
                  {err && <div style={{ color: 'var(--critical)', fontSize: 12.5, marginBottom: 12 }}>{err}</div>}
                  <button className="btn btn-primary" style={{ width: '100%', justifyContent: 'center' }} onClick={doLogin} disabled={busy}>
                    <Icon name={busy ? 'refresh' : 'lock'} size={15} sw={2} />{lang === 'ar' ? 'دخول' : 'Sign in'}
                  </button>
                </>
              ) : (
                <>
                  {field('user', lang === 'ar' ? 'اسم المستخدم (للدخول)' : 'Username (to sign in)', u, setU)}
                  {field('user', lang === 'ar' ? 'الاسم الكامل' : 'Full name', nm, setNm)}
                  {field('globe', lang === 'ar' ? 'البريد الإلكتروني (اختياري)' : 'Email (optional)', em, setEm)}
                  <label className="tb-search" style={{ width: '100%', margin: '0 0 4px' }}>
                    <Icon name="shield" size={16} />
                    <select value={role} onChange={e => setRole(e.target.value)}
                      style={{ width: '100%', background: 'transparent', border: 'none', color: 'inherit', fontSize: 13.5, outline: 'none', cursor: 'pointer' }}>
                      <option value="viewer">{lang === 'ar' ? 'مشاهد (viewer) — عرض فقط' : 'Viewer — read only'}</option>
                      <option value="analyst">{lang === 'ar' ? 'محلّل (analyst) — فحص وتقارير' : 'Analyst — scans & reports'}</option>
                      <option value="admin">{lang === 'ar' ? 'مدير (admin) — كل الصلاحيات' : 'Admin — full control'}</option>
                    </select>
                  </label>
                  <div className="muted" style={{ fontSize: 11, marginBottom: 10, paddingInlineStart: 4, lineHeight: 1.6 }}>
                    {role === 'viewer'
                      ? (lang === 'ar' ? '👁️ يرى الداشبورد والتقارير فقط، لا يعدّل شيئاً.' : '👁️ Sees dashboard and reports only, changes nothing.')
                      : role === 'analyst'
                        ? (lang === 'ar' ? '🔍 يشغّل الفحوصات، يولّد التقارير، يعالج الثغرات. لا يدير المستخدمين.' : '🔍 Runs scans, generates reports, fixes findings. No user management.')
                        : (lang === 'ar' ? '🛡️ كل الصلاحيات: إنشاء حسابات، عزل، حظر IP، إدارة. امنحه بحذر.' : '🛡️ Full control: create accounts, isolate, block IPs, manage. Grant carefully.')}
                  </div>
                  {field('lock', lang === 'ar' ? 'كلمة السر (٨+ حروف وأرقام)' : 'Password (8+ letters & numbers)', p, setP, 'password')}
                  {err && <div style={{ color: 'var(--critical)', fontSize: 12.5, marginBottom: 12 }}>{err}</div>}
                  <button className="btn btn-primary" style={{ width: '100%', justifyContent: 'center' }} onClick={doRegister} disabled={busy}>
                    <Icon name={busy ? 'refresh' : 'plus'} size={15} sw={2} />{lang === 'ar' ? 'إنشاء الحساب' : 'Create account'}
                  </button>
                </>
              )}
            </div>
          ) : (
            <div className="card card-pad">
              <div className="row gap16" style={{ alignItems: 'center' }}>
                <span style={{ width: 56, height: 56, borderRadius: 16, display: 'grid', placeItems: 'center', fontSize: 20, fontWeight: 700, color: 'var(--primary)', background: 'color-mix(in srgb, var(--primary) 15%, transparent)' }}>{me.initials}</span>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 19, fontWeight: 700 }}>{me.name}</div>
                  <div className="muted" style={{ fontSize: 13 }}>{me.role}{me.email ? ' · ' + me.email : ''}</div>
                </div>
                <StatusPill tone="success" live>{lang === 'ar' ? 'متصل' : 'Online'}</StatusPill>
                <button className="btn btn-ghost" onClick={doLogout}><Icon name="lock" size={15} />{lang === 'ar' ? 'خروج' : 'Sign out'}</button>
              </div>
              <div className="row gap16" style={{ marginTop: 16, flexWrap: 'wrap' }}>
                <div><div className="muted" style={{ fontSize: 12 }}>{lang === 'ar' ? 'اسم المستخدم' : 'Username'}</div><div style={{ fontSize: 14, fontWeight: 600 }}>{me.username}</div></div>
                <div><div className="muted" style={{ fontSize: 12 }}>{lang === 'ar' ? 'البريد الإلكتروني' : 'Email'}</div><div style={{ fontSize: 14, fontWeight: 600 }}>{me.email || (lang === 'ar' ? '— غير مُسجّل' : '— not set')}</div></div>
                <div><div className="muted" style={{ fontSize: 12 }}>{lang === 'ar' ? 'وقت الدخول' : 'Signed in at'}</div><div style={{ fontSize: 14, fontWeight: 600 }}>{fmt(me.last_login, lang)}</div></div>
              </div>
              {/* ---- two-factor authentication ---- */}
              <div style={{ marginTop: 16, paddingTop: 16, borderTop: '1px solid var(--hairline)' }}>
                <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center' }}>
                  <span className="row gap8"><Icon name="shield" size={16} /><b style={{ fontSize: 14 }}>{lang === 'ar' ? 'المصادقة الثنائية (2FA)' : 'Two-factor authentication'}</b></span>
                  {me.mfa
                    ? <span className="row gap8"><StatusPill tone="success" live>{lang === 'ar' ? 'مُفعّلة' : 'Enabled'}</StatusPill><button className="btn btn-ghost btn-sm" onClick={disableMfa}>{lang === 'ar' ? 'تعطيل' : 'Disable'}</button></span>
                    : (!mfaInfo ? <button className="btn btn-primary btn-sm" onClick={startMfa}><Icon name="lock" size={13} />{lang === 'ar' ? 'تفعيل' : 'Enable'}</button> : null)}
                </div>
                {mfaInfo && !me.mfa ? (
                  <div style={{ marginTop: 12 }}>
                    <div className="muted" style={{ fontSize: 12.5, marginBottom: 8 }}>
                      {lang === 'ar' ? 'أضف هذا المفتاح في تطبيق مصادقة (Google Authenticator / Authy) ثم أدخل الرمز:' : 'Add this key to an authenticator app (Google Authenticator / Authy), then enter the code:'}
                    </div>
                    <div className="mono" style={{ fontSize: 13, padding: '8px 12px', background: 'var(--bg-inset)', borderRadius: 8, border: '1px solid var(--hairline)', wordBreak: 'break-all', marginBottom: 10 }}>{mfaInfo.secret}</div>
                    <div className="row gap8">
                      <label className="tb-search" style={{ flex: 1, margin: 0 }}>
                        <Icon name="shield" size={15} />
                        <input type="text" inputMode="numeric" maxLength={6} placeholder={lang === 'ar' ? 'رمز ٦ أرقام' : '6-digit code'} value={mfaCode} onChange={e => setMfaCode(e.target.value)} />
                      </label>
                      <button className="btn btn-primary btn-sm" onClick={confirmMfa}>{lang === 'ar' ? 'تأكيد' : 'Confirm'}</button>
                    </div>
                  </div>
                ) : null}
              </div>
            </div>
          )}
        </div>

        <div className="card">
          <CardHead title={lang === 'ar' ? 'الموظفون' : 'Employees'} icon="user"
            right={<span className="row gap8">
              {isAdmin ? (
                <button className="btn btn-primary btn-sm" onClick={() => setShowAddUser(v => !v)}>
                  <Icon name={showAddUser ? 'x' : 'plus'} size={13} />
                  {showAddUser ? (lang === 'ar' ? 'إغلاق' : 'Close') : (lang === 'ar' ? 'إضافة موظف' : 'Add employee')}
                </button>
              ) : null}
              <span className="muted" style={{ fontSize: 12.5 }}>{users.length}</span>
            </span>} />
          {isAdmin && showAddUser ? (
            <div className="card-pad" style={{ borderBottom: '1px solid var(--hairline)', background: 'rgba(255,255,255,0.02)' }}>
              <div className="grid" style={{ gridTemplateColumns: 'repeat(2,1fr)', gap: 10, marginBottom: 10 }}>
                {field('user', lang === 'ar' ? 'اسم المستخدم' : 'Username', u, setU)}
                {field('user', lang === 'ar' ? 'الاسم الكامل' : 'Full name', nm, setNm)}
              </div>
              <div className="grid" style={{ gridTemplateColumns: 'repeat(2,1fr)', gap: 10, marginBottom: 10 }}>
                {field('globe', lang === 'ar' ? 'البريد (اختياري)' : 'Email (optional)', em, setEm)}
                {field('lock', lang === 'ar' ? 'كلمة السر (٨+)' : 'Password (8+)', p, setP, 'password')}
              </div>
              <label className="tb-search" style={{ width: '100%', margin: '0 0 4px' }}>
                <Icon name="shield" size={16} />
                <select value={role} onChange={e => setRole(e.target.value)}
                  style={{ width: '100%', background: 'transparent', border: 'none', color: 'inherit', fontSize: 13.5, outline: 'none', cursor: 'pointer' }}>
                  <option value="viewer">{lang === 'ar' ? 'مشاهد (viewer) — عرض فقط' : 'Viewer — read only'}</option>
                  <option value="analyst">{lang === 'ar' ? 'محلّل (analyst) — فحص وتقارير' : 'Analyst — scans & reports'}</option>
                  <option value="admin">{lang === 'ar' ? 'مدير (admin) — كل الصلاحيات' : 'Admin — full control'}</option>
                </select>
              </label>
              <div className="muted" style={{ fontSize: 11, marginBottom: 10, paddingInlineStart: 4, lineHeight: 1.6 }}>
                {role === 'viewer'
                  ? (lang === 'ar' ? '👁️ يرى الداشبورد والتقارير فقط.' : '👁️ Sees dashboard and reports only.')
                  : role === 'analyst'
                    ? (lang === 'ar' ? '🔍 يشغّل الفحوصات ويولّد التقارير. لا يدير المستخدمين.' : '🔍 Runs scans and reports. No user management.')
                    : (lang === 'ar' ? '🛡️ كل الصلاحيات. امنحه بحذر.' : '🛡️ Full control. Grant carefully.')}
              </div>
              {err && <div style={{ color: 'var(--critical)', fontSize: 12.5, marginBottom: 10 }}>{err}</div>}
              <button className="btn btn-primary btn-sm" onClick={() => doRegisterByAdmin()} disabled={busy}>
                <Icon name={busy ? 'refresh' : 'plus'} size={14} />{lang === 'ar' ? 'إنشاء الحساب' : 'Create account'}
              </button>
            </div>
          ) : null}
          <table className="tbl">
            <thead><tr>
              <th>{lang === 'ar' ? 'الموظف' : 'Employee'}</th>
              <th>{lang === 'ar' ? 'الدور' : 'Role'}</th>
              <th>2FA</th>
              <th>{lang === 'ar' ? 'آخر دخول' : 'Last login'}</th>
              <th>{lang === 'ar' ? 'الحالة' : 'Status'}</th>
              {isAdmin ? <th></th> : null}
            </tr></thead>
            <tbody>
              {users.map((x, i) => (
                <tr key={x.username || i}>
                  <td><span className="row gap12">
                    <span style={{ width: 32, height: 32, borderRadius: 9, display: 'grid', placeItems: 'center', fontSize: 12, fontWeight: 700, color: 'var(--secondary)', background: 'color-mix(in srgb, var(--secondary) 15%, transparent)' }}>{x.initials}</span>
                    <span style={{ color: 'var(--text-1)', fontWeight: 500 }}>{x.name}</span></span></td>
                  <td>{isAdmin && x.username !== (me && me.username) ? (
                    <select className="tb-search" style={{ padding: '4px 8px', fontSize: 12.5 }} value={x.role} onChange={e => changeRole(x.username, e.target.value)}>
                      <option value="viewer">viewer</option><option value="analyst">analyst</option><option value="admin">admin</option>
                    </select>
                  ) : <span className="muted">{x.role}</span>}</td>
                  <td>{x.mfa ? <span style={{ color: 'var(--success)' }}>✓</span> : <span className="muted">—</span>}</td>
                  <td className="mono muted">{fmt(x.last_login, lang)}</td>
                  <td>{x.online
                    ? <span className="sev" style={{ color: 'var(--success)', background: 'color-mix(in srgb, var(--success) 16%, transparent)' }}><span className="dot" style={{ background: 'var(--success)' }} />{lang === 'ar' ? 'متصل' : 'Online'}</span>
                    : (x.locked ? <span className="sev" style={{ color: 'var(--critical)', background: 'color-mix(in srgb, var(--critical) 14%, transparent)' }}><span className="dot" style={{ background: 'var(--critical)' }} />{lang === 'ar' ? 'مقفل' : 'Locked'}</span>
                    : <span className="sev" style={{ color: 'var(--text-3)', background: 'color-mix(in srgb, var(--text-3) 14%, transparent)' }}><span className="dot" style={{ background: 'var(--text-3)' }} />{lang === 'ar' ? 'غير متصل' : 'Offline'}</span>)}</td>
                  {isAdmin ? <td>{x.username !== (me && me.username) ? <button className="btn btn-ghost btn-sm" onClick={() => removeUser(x.username)} title={lang === 'ar' ? 'حذف' : 'Delete'}><Icon name="x" size={14} /></button> : null}</td> : null}
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {isAdmin ? (
          <div className="grid" style={{ gridTemplateColumns: '1fr 1fr', gap: 20, marginTop: 20 }}>
            <div className="card">
              <CardHead title={lang === 'ar' ? 'صحة التطبيق' : 'Application health'} icon="activity" iconColor="var(--primary)"
                right={<span className="row gap8">
                  <button className="btn btn-ghost btn-sm" onClick={doBackup}><Icon name="server" size={13} />{lang === 'ar' ? 'نسخة احتياطية' : 'Backup'}</button>
                  <button className="btn btn-ghost btn-sm" onClick={() => window.API.downloadBackup()}><Icon name="download" size={13} />{lang === 'ar' ? 'تنزيل' : 'Download'}</button>
                </span>} />
              <div className="card-pad" style={{ paddingTop: 6 }}>
                {health ? (
                  <div className="grid" style={{ gridTemplateColumns: '1fr 1fr', gap: 10, fontSize: 12.5 }}>
                    <div><span className="muted">{lang === 'ar' ? 'زمن التشغيل' : 'Uptime'}: </span><b>{Math.floor(health.uptime_seconds / 60)}m</b></div>
                    <div><span className="muted">{lang === 'ar' ? 'الطلبات' : 'Requests'}: </span><b>{health.requests}</b></div>
                    <div><span className="muted">{lang === 'ar' ? 'الأخطاء' : 'Errors'}: </span><b style={{ color: health.errors ? 'var(--critical)' : 'var(--success)' }}>{health.errors}</b></div>
                    <div><span className="muted">{lang === 'ar' ? 'زمن الاستجابة' : 'Latency'}: </span><b>{health.latency_ms_avg} ms</b></div>
                    <div><span className="muted">{lang === 'ar' ? 'ذاكرة التطبيق' : 'App RAM'}: </span><b>{health.process_mem_mb} MB</b></div>
                    <div><span className="muted">{lang === 'ar' ? 'الخيوط' : 'Threads'}: </span><b>{health.threads}</b></div>
                  </div>
                ) : <div className="muted" style={{ fontSize: 12.5 }}>—</div>}
                {bkMsg ? <div className="muted" style={{ fontSize: 12, marginTop: 10 }}>{bkMsg}</div> : null}
              </div>
            </div>
            <div className="card">
              <CardHead title={lang === 'ar' ? 'سجلّ التدقيق' : 'Audit log'} icon="lock" iconColor="var(--secondary)"
                right={<button className="btn btn-ghost btn-sm" onClick={() => window.API.exportAuditCsv()}><Icon name="download" size={13} />CSV</button>} />
              <div className="card-pad" style={{ paddingTop: 4, maxHeight: 220, overflowY: 'auto' }}>
                {audit.length === 0 ? <div className="muted" style={{ fontSize: 12.5 }}>{lang === 'ar' ? 'لا سجلّات' : 'No entries'}</div> :
                  audit.slice(0, 30).map((e, i) => (
                    <div key={i} className="row" style={{ justifyContent: 'space-between', padding: '6px 0', borderBottom: i < 29 ? '1px solid var(--hairline)' : 'none', fontSize: 12 }}>
                      <span className="row gap8" style={{ minWidth: 0 }}>
                        <span className="mono" style={{ color: 'var(--text-1)' }}>{e.action}</span>
                        <span className="muted" style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 200 }}>{e.user} {e.detail ? '· ' + e.detail : ''}</span>
                      </span>
                      <span className="muted tnum" style={{ fontSize: 11 }}>{fmt(e.ts, lang)}</span>
                    </div>
                  ))}
              </div>
            </div>
          </div>
        ) : null}
      </div>
    );
  }

  /* ---------------- BACKGROUND PICKER (settings) ---------------- */
  function BackgroundPicker({ lang }) {
    const { useState } = React;
    const [bg, setBg] = useState(() => localStorage.getItem('sx-bg') || 'video-current');
    const opts = [
      { id: 'video-current', ar: 'الفيديو الأصلي', en: 'Original video', kind: 'video', sw: 'linear-gradient(135deg,#0b1f1a,#10403080)' },
      { id: 'video-1', ar: 'فيديو ١', en: 'Video 1', kind: 'video', sw: 'linear-gradient(135deg,#11223a,#1b4a6b80)' },
      { id: 'video-2', ar: 'فيديو ٢', en: 'Video 2', kind: 'video', sw: 'linear-gradient(135deg,#2a1140,#5a1b8b80)' },
      { id: 'aurora-green', ar: 'شفق أخضر', en: 'Aurora green', kind: 'css', sw: 'radial-gradient(circle 30px at 25% 85%,#3fff75,#00ff8030,transparent),#0a1410' },
      { id: 'blue-waves', ar: 'موجات زرقاء', en: 'Blue waves', kind: 'css', sw: 'radial-gradient(circle 28px at 70% 30%,#3a7bff66,transparent),linear-gradient(135deg,#0a1228,#1b3a6b)' },
      { id: 'purple-nebula', ar: 'سديم بنفسجي', en: 'Purple nebula', kind: 'css', sw: 'radial-gradient(circle 28px at 30% 70%,#9b4bff66,transparent),linear-gradient(135deg,#160a28,#3a1b6b)' },
    ];
    const pick = (id) => {
      setBg(id);
      localStorage.setItem('sx-bg', id);
      window.dispatchEvent(new CustomEvent('sx-set-bg', { detail: id }));
    };
    return (
      <div className="card card-pad" style={{ marginBottom: 20 }}>
        <CardHead title={lang === 'ar' ? 'خلفية اللوحة' : 'Dashboard background'} icon="eye" iconColor="var(--primary)" />
        <div className="muted" style={{ fontSize: 11.5, margin: '4px 0 14px' }}>
          🔒 {lang === 'ar'
            ? 'كل الخلفيات محلية على جهازك — لا اتصال خارجي. الفيديوهات من مجلد media، والبقية رسوم CSS.'
            : 'All backgrounds are local — no external requests. Videos come from the media folder; the rest are CSS.'}
        </div>
        <div className="grid" style={{ gridTemplateColumns: 'repeat(3,1fr)', gap: 12 }}>
          {opts.map(o => (
            <button key={o.id} onClick={() => pick(o.id)}
              style={{
                cursor: 'pointer', borderRadius: 12, padding: 0, overflow: 'hidden',
                height: 76, position: 'relative', background: o.sw,
                border: bg === o.id ? '2px solid var(--primary)' : '2px solid transparent',
                boxShadow: bg === o.id ? '0 0 0 3px color-mix(in srgb, var(--primary) 25%, transparent)' : 'none',
                transition: 'all .2s',
              }}>
              <span style={{ position: 'absolute', top: 6, insetInlineStart: 8, fontSize: 9.5, padding: '2px 7px', borderRadius: 20, background: 'rgba(0,0,0,.45)', color: '#fff' }}>
                {o.kind === 'video' ? '🎬' : '🎨'} {o.kind === 'video' ? (lang === 'ar' ? 'فيديو' : 'video') : 'CSS'}
              </span>
              <span style={{ position: 'absolute', bottom: 0, insetInline: 0, padding: '5px', fontSize: 11, textAlign: 'center', background: 'rgba(0,0,0,.5)', color: '#fff' }}>
                {lang === 'ar' ? o.ar : o.en}
              </span>
              {bg === o.id ? <span style={{ position: 'absolute', top: 6, insetInlineEnd: 8, color: 'var(--primary)' }}><Icon name="check" size={15} sw={3} /></span> : null}
            </button>
          ))}
        </div>
        <div className="muted" style={{ fontSize: 11, marginTop: 10 }}>
          {lang === 'ar'
            ? 'ملاحظة: خيارات الفيديو تحتاج وضع الملفات في dashboard/media/ (bg-video-current.mp4, bg-video-1.mp4, bg-video-2.mp4).'
            : 'Note: video options need files placed in dashboard/media/ (bg-video-current.mp4, bg-video-1.mp4, bg-video-2.mp4).'}
        </div>
      </div>
    );
  }

  Object.assign(window, { Alerts, Profile, BackgroundPicker });
})();
