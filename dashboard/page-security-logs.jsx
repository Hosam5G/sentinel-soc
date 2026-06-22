/* Equilibrium Sentinel — Security & Logs pages
   Security: live data from window.API (fallback to mockup) +
   in-style Apply / Dismiss actions on vulnerability findings and
   on recommendations. Design unchanged — actions reuse existing
   .btn / .sev / StatusPill styling. Logs left untouched. */
(function () {
  const R = React;
  const { useState, useEffect, useRef } = React;
  const { Icon, CardHead, SevPill, StatusPill, Bar, ScoreRing, Donut,
          Bars, AreaChart } = window;

  function PageHead({ t, lang, title, sub, actions }) {
    return (
      <div className="page-head">
        <div className="ph-t"><h2>{title}</h2><p>{sub}</p></div>
        <div className="ph-actions">{actions}</div>
      </div>
    );
  }

  /* ---------------- SECURITY ---------------- */
  function Security({ t, lang }) {
    const FALLBACK_COUNTS = [
      { k: 'critical', n: 0 }, { k: 'high', n: 0 }, { k: 'medium', n: 0 }, { k: 'low', n: 0 },
    ];
    const fbFindings = () => ([]);
    const fbRecs = () => ([]);

    const [counts, setCounts] = useState(FALLBACK_COUNTS);
    const [risk, setRisk] = useState(null);
    const [findings, setFindings] = useState(fbFindings);
    const [recs, setRecs] = useState(fbRecs);
    const [search, setSearch] = useState('');
    const [lastUpdate, setLastUpdate] = useState(0);
    // remediation modal state
    const [remFinding, setRemFinding] = useState(null);    // the finding being fixed
    const [remPlans, setRemPlans] = useState(null);        // plans list from server
    const [remBusy, setRemBusy] = useState(false);
    const [remResult, setRemResult] = useState(null);      // execution result
    // explanation modal state
    const [explainFor, setExplainFor] = useState(null);    // the finding being explained
    const [explainText, setExplainText] = useState('');
    const [explainBusy, setExplainBusy] = useState(false);
    const _localExplain = (cve) => {
      const c = (cve || '').toUpperCase();
      const E = {
        'PORT-135': 'منفذ RPC (135) يستخدمه ويندوز داخلياً. مفتوح على كل أجهزة ويندوز تقريباً. خطر فقط لو جهازك مكشوف مباشرةً للإنترنت. لو لا تشارك خدمات عبر الشبكة، يمكنك حظره بأمان عبر زر «معالجة».',
        'PORT-139': 'منفذ NetBIOS (139) لمشاركة الملفات القديمة في ويندوز. طبيعي على الشبكات المنزلية. أغلقه فقط إن كنت لا تشارك ملفات أو طابعات عبر الشبكة المحلية.',
        'PORT-445': 'منفذ SMB (445) لمشاركة الملفات الحديثة. طبيعي داخل المنزل، لكنه كان ناقل هجمات WannaCry حين يكون مكشوفاً للإنترنت. خلف راوتر منزلي آمن نسبياً.',
        'KEV': 'برنامج مُثبَّت عندك ورد في قائمة CISA للثغرات المُستغَلّة فعلياً في هجمات حقيقية. المعنى: قد يكون إصدارك قديماً وفيه ثغرة معروفة. الحل: حدّث البرنامج عبر زر «معالجة» (winget). من أهم الثغرات التي يجب الانتباه لها.',
        'PERSIST': 'مدخل بدء تشغيل يعمل تلقائياً مع ويندوز. البرمجيات الخبيثة تستخدم هذا لتبقى بعد إعادة التشغيل. راجعه: إن كان لبرنامج تعرفه فهو سليم، وإلا احذفه.',
        'PROC': 'عملية قيد التشغيل بدت مشبوهة. راجع مسارها: إن كانت برنامجاً تعرفه فهي غالباً سليمة. إن كانت في مجلد مؤقت/تنزيلات ولا تعرفها، افحصها.',
        'NET': 'اتصال شبكي بدا غير طبيعي (منفذ معروف للبرمجيات الخبيثة أو سلوك beaconing). افحص أي برنامج يفتح هذا الاتصال.',
        'ACCT': 'ملاحظة على حسابات المستخدمين (حساب مخفي أو صلاحيات غير متوقّعة). راجع الحسابات وعطّل ما لا تعرفه.',
        'RKPROC': 'مؤشّر محتمل لـ rootkit (عملية ظهرت مخفية من بعض أدوات النظام). قد يكون إنذاراً كاذباً من توقيت الفحص. لو تكرّر، شغّل فحص Defender دون اتصال.',
        'RKDRV': 'درايفر نواة غير موقّع أو في مكان غير معتاد. الدرايفرات الخبيثة تُستخدم في الـ rootkits. تحقّق من مصدره.',
        'FIM': 'ملف نظام مهم تغيّر منذ آخر فحص. لو كان بسبب تحديث ويندوز فهو طبيعي. وإلا فقد يدل على تلاعب.',
        'FW-DISABLED': 'جدار حماية ويندوز مُطفأ. يُنصح بشدّة بتشغيله عبر زر «معالجة» — يحمي جهازك من اتصالات غير مرغوبة.',
        'AV-RTP-OFF': 'الحماية اللحظية في Defender مُطفأة. شغّلها فوراً عبر «معالجة» — هي خط دفاعك الأول.',
      };
      const en = {
        'PORT-135': 'RPC port (135), used internally by Windows. Open on nearly all Windows PCs. Only risky if your machine is directly exposed to the internet. Safe to block via Fix if you don\'t share network services.',
        'KEV': 'Installed software that appears on CISA\'s actively-exploited list. Your version may be outdated with a known vulnerability. Update it via the Fix button (winget).',
      };
      const dict = (lang === 'ar') ? E : en;
      const keys = Object.keys(dict).sort((a, b) => b.length - a.length);
      for (const k of keys) if (c.startsWith(k)) return dict[k];
      return lang === 'ar'
        ? 'ملاحظة أمنية على جهازك. راجع عمود «المعالجة» لإصلاحها.'
        : 'A security finding on your machine. See the Fix column.';
    };
    const explain = (f) => {
      setExplainFor(f); setExplainText(''); setExplainBusy(true);
      const fallback = _localExplain(f.cve);
      if (window.API && window.API.explainFinding) {
        window.API.explainFinding(f.cve, lang, false).then(txt => {
          setExplainBusy(false);
          // prefer the server explanation, but never show "unavailable" —
          // fall back to the built-in explainer baked into the UI.
          setExplainText((txt && txt.length > 5) ? txt : fallback);
        }).catch(() => { setExplainBusy(false); setExplainText(fallback); });
      } else {
        setExplainBusy(false); setExplainText(fallback);
      }
    };
    const explainWithAi = () => {
      if (!explainFor) return;
      const baseText = explainText;
      setExplainBusy(true);
      setExplainText((baseText ? baseText + '\n\n' : '') + (lang==='ar'
        ? '⏳ النموذج المحلي يكتب تحليلاً أعمق… قد يستغرق حتى دقيقة على المعالج.'
        : '⏳ The local model is writing a deeper analysis… up to a minute on CPU.'));
      window.API.explainFinding(explainFor.cve, lang, true).then(txt => {
        setExplainBusy(false);
        if (txt && txt.length > 5) {
          setExplainText(txt);
        } else {
          setExplainText((baseText || '') + '\n\n' + (lang==='ar'
            ? '⚠️ تعذّر الحصول على تحليل النموذج (قد يكون Ollama غير مشغّل أو النموذج يُحمّل). الشرح المبسّط أعلاه يكفي عادةً.'
            : '⚠️ Could not get the model analysis (Ollama may be off or loading). The plain explanation above is usually enough.'));
        }
      }).catch(() => {
        setExplainBusy(false);
        setExplainText((baseText || '') + '\n\n' + (lang==='ar'
          ? '⚠️ تعذّر الاتصال بالنموذج المحلي. تأكّد أن Ollama يعمل.'
          : '⚠️ Could not reach the local model. Make sure Ollama is running.'));
      });
    };
    const openRemediation = (f) => {
      setRemFinding(f); setRemPlans(null); setRemResult(null);
      if (window.API && window.API.getRemediationPlans)
        window.API.getRemediationPlans(f.cve).then(d => {
          // distinguish "not logged in" from "genuinely no plan" so the user
          // gets an actionable message instead of a misleading empty state.
          if (d && (d.error === 'authentication required' || d.ok === false)) {
            setRemPlans({ authRequired: true });
          } else {
            setRemPlans((d && d.plans) || []);
          }
        }).catch(() => setRemPlans([]));
    };
    const runPlan = (planId) => {
      if (!remFinding) return;
      setRemBusy(true); setRemResult(null);
      window.API.executeRemediation(remFinding.cve, planId).then(r => {
        setRemBusy(false); setRemResult(r);
        if (r && r.verified) {
          setFindings(prev => prev.map(x => x.cve === remFinding.cve ? Object.assign({}, x, { st: 'patched' }) : x));
        }
      });
    };
    const closeRemediation = () => { setRemFinding(null); setRemPlans(null); setRemResult(null); };
    const [busy, setBusy] = useState({});            // {key: true} while a request is in-flight
    const [scanning, setScanning] = useState(false);
    const [detecting, setDetecting] = useState(false);
    const [detectResult, setDetectResult] = useState(window.__detectCache || null);
    const [behaviorBaseline, setBehaviorBaseline] = useState(null);
    const [allowedItems, setAllowedItems] = useState({});   // track items just allowlisted
    const [scanInfo, setScanInfo] = useState(null);  // {ts, count, software_count}
    const [intel, setIntel] = useState(null);        // latest exploited-CVE feed
    const [comp, setComp] = useState(null);          // CIS compliance
    const mounted = useRef(true);
    // persist detection results across language switches / remounts: the parent
    // may rebuild this page when the language flips, which would otherwise wipe
    // the live-detection results the user just ran. Caching on window keeps them.
    const saveDetect = (d) => { window.__detectCache = d; setDetectResult(d); };

    const reload = () => {
      if (window.API && window.API.getSecurity) {
        window.API.getSecurity(lang).then(d => {
          if (!mounted.current || !d) return;
          if (d.counts) setCounts(d.counts);
          if (typeof d.riskScore === 'number') setRisk(d.riskScore);
          if (d.findings) setFindings(d.findings);
          if (d.recommendations) setRecs(d.recommendations);
          setLastUpdate(Date.now());
        });
      }
      if (window.API && window.API.getScanStatus) {
        window.API.getScanStatus().then(s => { if (mounted.current && s) setScanInfo(s); });
      }
      if (window.API && window.API.getThreatIntel) {
        window.API.getThreatIntel().then(d => { if (mounted.current && d) setIntel(d); });
      }
      if (window.API && window.API.getCompliance) {
        window.API.getCompliance().then(d => { if (mounted.current && d) setComp(d); });
      }
      if (window.API && window.API.getBaselineStatus) {
        window.API.getBaselineStatus().then(d => { if (mounted.current && d) setBehaviorBaseline(d); });
      }
    };

    useEffect(() => {
      mounted.current = true;
      reload();
      // auto-run live detection on open + refresh it periodically so the tiles
      // update on their own (no need to press "Live detect" every time).
      const autoDetect = () => {
        if (!mounted.current || !window.API || !window.API.runFullDetection) return;
        window.API.runFullDetection().then(r => {
          if (mounted.current && r) { saveDetect(r); }
        }).catch(() => {});
      };
      const t0 = setTimeout(autoDetect, 800);
      const iv = setInterval(autoDetect, 45000);
      return () => { mounted.current = false; clearTimeout(t0); clearInterval(iv); };
    }, [lang]);

    const doScan = () => {
      if (scanning || !window.API || !window.API.scanSystem) return;
      setScanning(true);
      window.API.scanSystem().then(() => {
        // poll status until the scan finishes, then reload findings
        const poll = () => {
          if (!mounted.current) return;
          window.API.getScanStatus().then(s => {
            if (!mounted.current) return;
            if (s && !s.running) { setScanning(false); setScanInfo(s); reload(); }
            else setTimeout(poll, 2000);
          }).catch(() => { if (mounted.current) { setScanning(false); reload(); } });
        };
        setTimeout(poll, 2000);
      }).catch(() => mounted.current && setScanning(false));
    };

    const doDetect = () => {
      if (detecting || !window.API || !window.API.runFullDetection) return;
      setDetecting(true); saveDetect(null);
      window.API.runFullDetection().then(r => {
        if (!mounted.current) return;
        setDetecting(false);
        saveDetect(r);
        reload();   // new threats also surface as findings
      }).catch(() => mounted.current && setDetecting(false));
    };

    const stTone = { open: 'danger', investigating: 'warning', patched: 'info', resolved: 'success' };
    const txt = {
      actions: lang==='ar' ? 'إجراءات' : 'Actions',
      apply:   lang==='ar' ? 'تنفيذ'   : 'Apply',
      dismiss: lang==='ar' ? 'رفض'     : 'Dismiss',
      applied: lang==='ar' ? 'مُنفّذة'  : 'Applied',
      dismissed: lang==='ar' ? 'مرفوضة' : 'Dismissed',
      openFindings: lang==='ar' ? 'ثغرة مفتوحة' : 'open findings',
    };
    const isActioned = st => (st === 'patched' || st === 'resolved' || st === 'dismissed');

    // muted neutral pill (in-style with .sev) for the "dismissed" state
    const MutedPill = ({ children }) => (
      <span className="sev" style={{ color: 'var(--text-3)', background: 'color-mix(in srgb, var(--text-3) 14%, transparent)' }}>
        <span className="dot" style={{ background: 'var(--text-3)' }} />{children}
      </span>
    );

    const setBusyKey = (k, v) => setBusy(prev => { const n = Object.assign({}, prev); if (v) n[k] = true; else delete n[k]; return n; });

    const doFinding = (cve, action) => {
      const key = 'f:' + cve;
      if (busy[key]) return;
      setBusyKey(key, true);
      const apiCall = (window.API && window.API.findingAction)
        ? window.API.findingAction(cve, action, lang)
        : Promise.resolve({ status: action === 'apply' ? 'patched' : 'dismissed' });
      Promise.resolve(apiCall).then(res => {
        if (!mounted.current) return;
        const newSt = (res && res.status) || (action === 'apply' ? 'patched' : 'dismissed');
        setFindings(prev => prev.map(f => f.cve === cve ? Object.assign({}, f, { st: newSt }) : f));
      }).finally(() => mounted.current && setBusyKey(key, false));
    };

    const doRec = (id, action) => {
      const key = 'r:' + id;
      if (busy[key]) return;
      setBusyKey(key, true);
      const apiCall = (window.API && window.API.recAction)
        ? window.API.recAction(id, action, lang)
        : Promise.resolve({ state: action === 'apply' ? 'applied' : 'dismissed' });
      Promise.resolve(apiCall).then(res => {
        if (!mounted.current) return;
        const newState = (res && res.state) || (action === 'apply' ? 'applied' : 'dismissed');
        setRecs(prev => prev.map(r => r.id === id ? Object.assign({}, r, { state: newState }) : r));
      }).finally(() => mounted.current && setBusyKey(key, false));
    };

    const [range, setRange] = useState('7d');

    return (
      <div>
        <PageHead t={t} lang={lang} title={t.nav.security} sub={t.pageSub.security}
          actions={<><div className="seg">
            <button className={range === '7d' ? 'on' : ''} onClick={() => setRange('7d')}>{t.btn.last7}</button>
            <button className={range === '30d' ? 'on' : ''} onClick={() => setRange('30d')}>{t.btn.last30}</button>
          </div>
          <button className="btn btn-primary" onClick={doScan} disabled={scanning}>
            <Icon name={scanning ? 'refresh' : 'shield'} size={15} sw={2} />
            {scanning ? (lang==='ar'?'يفحص النظام…':'Scanning…') : (lang==='ar'?'افحص النظام':'Scan system')}
          </button>
          <button className="btn btn-primary" onClick={doDetect} disabled={detecting} title={lang==='ar'?'فحص العمليات والاستمرارية وسلامة الملفات':'Scan processes, persistence & file integrity'}>
            <Icon name={detecting ? 'refresh' : 'activity'} size={15} sw={2} />
            {detecting ? (lang==='ar'?'يكشف…':'Detecting…') : (lang==='ar'?'كشف حيّ':'Live detect')}
          </button>
          <button className="btn btn-ghost" onClick={() => window.API && window.API.exportCsv && window.API.exportCsv('findings', lang)}>
            <Icon name="download" size={15} />{lang==='ar'?'تصدير CSV':'Export CSV'}
          </button></>} />
        {scanInfo && scanInfo.ts ? (
          <div className="muted" style={{ fontSize: 12, marginTop: -8, marginBottom: 14 }}>
            {lang==='ar' ? 'آخر فحص حقيقي للنظام: ' : 'Last real system scan: '}
            {new Date(scanInfo.ts).toLocaleString(lang==='ar'?'ar':'en')}
            {' · '}{scanInfo.count} {lang==='ar'?'نتيجة':'findings'}
            {scanInfo.software_count ? ' · ' + scanInfo.software_count + (lang==='ar'?' برنامج مثبّت':' installed apps') : ''}
          </div>
        ) : null}

        <div className="card" style={{ marginBottom: 18, background: 'rgba(255,255,255,0.04)' }}>
          <div className="card-pad" style={{ fontSize: 12.5, lineHeight: 1.9, color: 'rgba(255,255,255,0.8)' }}>
            {lang==='ar' ? (
              <span>
                📖 <b>دليل سريع لهذه الصفحة</b> — هنا تجد ٤ أقسام مختلفة:
                <br/>① <b>الكشف الحيّ:</b> فحص فوري للعمليات/الشبكة/الذاكرة (اضغط «كشف حيّ»).
                {' '}② <b>الامتثال:</b> هل إعدادات أمان جهازك مضبوطة حسب المعايير.
                <br/>③ <b>نتائج الثغرات:</b> نقاط الضعف الفعلية في جهازك (مع زر إصلاح لكلٍّ).
                {' '}④ <b>CISA KEV:</b> قائمة عالمية مرجعية للتهديدات النشطة — <b>ليست</b> ثغرات جهازك.
                <br/>💡 أمّا <b>صفحة «السجلات»</b> فتعرض ما حدث <b>زمنياً</b> (متى فُحص، متى اكتُشف تهديد).
              </span>
            ) : (
              <span>
                📖 <b>Quick guide to this page</b> — it has 4 different sections:
                <br/>① <b>Live detection:</b> instant process/network/memory scan (press "Live detect").
                {' '}② <b>Compliance:</b> whether your security settings match best-practice benchmarks.
                <br/>③ <b>Vulnerability findings:</b> actual weaknesses on your machine (each has a Fix button).
                {' '}④ <b>CISA KEV:</b> a global reference list of active threats — <b>not</b> your machine's flaws.
                <br/>💡 The <b>Logs page</b> instead shows what happened <b>over time</b> (when scans ran, when threats were caught).
              </span>
            )}
          </div>
        </div>

        {detectResult ? (
          <div className="card" style={{ marginBottom: 20, borderColor: detectResult.total_findings ? 'var(--critical)' : 'var(--success)' }}>
            <CardHead title={lang==='ar'?'① نتائج الكشف الحيّ':'① Live detection results'} icon="activity"
              iconColor={detectResult.total_findings ? 'var(--critical)' : 'var(--success)'}
              right={<StatusPill tone={detectResult.total_findings ? 'danger' : 'success'}>
                {detectResult.total_findings ? (detectResult.total_findings + ' ' + (lang==='ar'?'تهديد':'threats')) : (lang==='ar'?'نظيف':'clean')}
              </StatusPill>} />
            <div className="card-pad" style={{ paddingTop: 8 }}>
              <div className="grid" style={{ gridTemplateColumns: 'repeat(7,1fr)', gap: 8, marginBottom: 12 }}>
                {[
                  { label: lang==='ar'?'العمليات':'Processes', icon: 'cpu',
                    n: (detectResult.processes && detectResult.processes.hits || []).length,
                    avail: detectResult.processes && detectResult.processes.available },
                  { label: lang==='ar'?'الاستمرارية':'Persist', icon: 'refresh',
                    n: (detectResult.persistence && detectResult.persistence.items || []).length,
                    avail: detectResult.persistence && detectResult.persistence.available },
                  { label: lang==='ar'?'الشبكة':'Network', icon: 'wifi',
                    n: (detectResult.network && detectResult.network.hits || []).length,
                    avail: detectResult.network && detectResult.network.available },
                  { label: lang==='ar'?'الحسابات':'Accounts', icon: 'user',
                    n: (detectResult.accounts && detectResult.accounts.items || []).length,
                    avail: detectResult.accounts && detectResult.accounts.available },
                  { label: 'Rootkit', icon: 'shield',
                    n: (detectResult.rootkit && detectResult.rootkit.total) || 0,
                    avail: detectResult.rootkit && detectResult.rootkit.available },
                  { label: lang==='ar'?'السلامة':'Integrity', icon: 'lock',
                    n: (detectResult.fim && detectResult.fim.changes || []).length,
                    avail: detectResult.fim && detectResult.fim.baselined },
                  { label: lang==='ar'?'سلوكي':'Behavior', icon: 'pulse',
                    n: (detectResult.heuristics && detectResult.heuristics.count) || 0,
                    avail: detectResult.heuristics && detectResult.heuristics.available },
                ].map((s, i) => (
                  <div key={i} style={{ textAlign: 'center', padding: '10px 4px', background: 'var(--bg-inset)', borderRadius: 9 }}>
                    <Icon name={s.icon} size={16} style={{ color: s.n ? 'var(--critical)' : 'var(--success)' }} />
                    <div style={{ fontSize: 18, fontWeight: 700, marginTop: 3, color: s.n ? 'var(--critical)' : 'var(--text-1)' }}>
                      {s.avail === false ? '—' : s.n}
                    </div>
                    <div className="muted" style={{ fontSize: 10 }}>{s.label}</div>
                    {s.avail === false ? <div className="muted" style={{ fontSize: 9, color: 'var(--warning)' }}>{lang==='ar'?'غ/م':'n/a'}</div> : null}
                  </div>
                ))}
              </div>

              {/* behavioral baseline status — learn-then-deviate */}
              {behaviorBaseline ? (
                <div style={{ padding: '11px 14px', borderRadius: 10, marginBottom: 12,
                  background: behaviorBaseline.learning ? 'color-mix(in srgb, var(--primary) 8%, transparent)' : 'color-mix(in srgb, var(--sev-low) 8%, transparent)',
                  border: '1px solid ' + (behaviorBaseline.learning ? 'color-mix(in srgb, var(--primary) 30%, transparent)' : 'color-mix(in srgb, var(--sev-low) 30%, transparent)') }}>
                  <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                    <div style={{ minWidth: 0 }}>
                      <div style={{ fontWeight: 700, fontSize: 12.5 }}>
                        <Icon name="activity" size={13} /> {lang==='ar' ? 'خط الأساس السلوكي' : 'Behavioral baseline'}
                      </div>
                      <div className="muted" style={{ fontSize: 11.5, marginTop: 3, lineHeight: 1.6 }}>
                        {behaviorBaseline.learning
                          ? (lang==='ar'
                              ? `يتعلّم ما هو طبيعي على جهازك (${behaviorBaseline.days_elapsed} من ${behaviorBaseline.days_target} أيام · ${behaviorBaseline.known_processes} برنامج معروف). بعد التعلّم، سينبّه على أي سلوك جديد غير معتاد.`
                              : `Learning what's normal on your machine (${behaviorBaseline.days_elapsed} of ${behaviorBaseline.days_target} days · ${behaviorBaseline.known_processes} known apps). After learning, it flags anything new or unusual.`)
                          : (lang==='ar'
                              ? `اكتمل التعلّم ✅ يعرف ${behaviorBaseline.known_processes} برنامجاً معتاداً على جهازك. أي برنامج جديد لم يُرَ من قبل يحصل على نقاط خطورة إضافية.`
                              : `Learning complete ✅ Knows ${behaviorBaseline.known_processes} normal apps on your machine. Any never-before-seen app gets extra risk score.`)}
                      </div>
                    </div>
                    <div style={{ flexShrink: 0, textAlign: 'center' }}>
                      <div style={{ fontWeight: 700, fontSize: 18, color: behaviorBaseline.learning ? 'var(--primary)' : 'var(--sev-low)' }}>
                        {behaviorBaseline.learning ? behaviorBaseline.progress_pct + '%' : '✓'}
                      </div>
                      <div className="muted" style={{ fontSize: 10 }}>{behaviorBaseline.learning ? (lang==='ar'?'تعلّم':'learning') : (lang==='ar'?'جاهز':'ready')}</div>
                    </div>
                  </div>
                  {behaviorBaseline.learning ? (
                    <div style={{ height: 5, background: 'rgba(255,255,255,0.1)', borderRadius: 3, marginTop: 9, overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: behaviorBaseline.progress_pct + '%', background: 'var(--primary)', borderRadius: 3 }} />
                    </div>
                  ) : null}
                </div>
              ) : null}

              {/* detailed breakdown of WHAT was detected + how to fix it */}
              {(() => {
                const pers = (detectResult.persistence && detectResult.persistence.items) || [];
                const fims = (detectResult.fim && detectResult.fim.changes) || [];
                const procs = (detectResult.processes && detectResult.processes.hits) || [];
                const nets = (detectResult.network && detectResult.network.hits) || [];
                const accts = (detectResult.accounts && detectResult.accounts.items) || [];
                const hasDetail = pers.length || fims.length || procs.length || nets.length || accts.length;
                if (!hasDetail) return null;
                return (
                  <div style={{ marginBottom: 12 }}>
                    <div style={{ fontWeight: 700, fontSize: 12.5, marginBottom: 8, color: 'var(--text-1)' }}>
                      {lang==='ar' ? '🔍 ما الذي اكتُشف بالضبط وكيف تحلّه' : '🔍 What was detected & how to fix it'}
                    </div>
                    {pers.map((it, i) => {
                      const itemKey = 'p:' + (it.name || '') + ':' + (it.source || '');
                      if (allowedItems[itemKey]) {
                        return (
                          <div key={'p'+i} style={{ padding: '10px 13px', background: 'color-mix(in srgb, var(--sev-low) 10%, transparent)', borderRadius: 9, marginBottom: 7, border: '1px solid color-mix(in srgb, var(--sev-low) 35%, transparent)' }}>
                            <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--sev-low)' }}>
                              <Icon name="check" size={13} /> {lang==='ar'?'تمّت إضافته لقائمة السماح: ':'Allowlisted: '}{it.name}
                            </div>
                            <div className="muted" style={{ fontSize: 11, marginTop: 3 }}>
                              {lang==='ar'?'لن يُنبّهك عنه بعد الآن. سيختفي عند الفحص التالي.':'Won\'t alert on it anymore. It will disappear on the next scan.'}
                            </div>
                          </div>
                        );
                      }
                      return (
                      <div key={'p'+i} style={{ padding: '10px 13px', background: 'color-mix(in srgb, var(--warning) 8%, transparent)', borderRadius: 9, marginBottom: 7, border: '1px solid color-mix(in srgb, var(--warning) 30%, transparent)' }}>
                        <div style={{ fontSize: 12.5, fontWeight: 600 }}>
                          <Icon name="refresh" size={12} /> {lang==='ar'?'استمرارية: ':'Persistence: '}{it.source} · {it.name}
                        </div>
                        {it.value ? <div className="mono muted" style={{ fontSize: 10.5, marginTop: 3, wordBreak: 'break-all' }}>{String(it.value).slice(0, 140)}</div> : null}
                        {it.reasons && it.reasons.length ? <div style={{ fontSize: 11, marginTop: 4, color: 'var(--warning)' }}>{(lang==='ar'?'السبب: ':'Why: ')}{it.reasons.join(' · ')}</div> : null}
                        <div style={{ fontSize: 11, marginTop: 5, lineHeight: 1.7, color: 'rgba(255,255,255,0.75)' }}>
                          {lang==='ar'
                            ? '🛠️ لو لا تعرف هذا البرنامج: عطّله من «مدير المهام ← بدء التشغيل». لو تعرفه (تطبيق نزّلته)، اضغط «آمن» ليتوقّف عن تنبيهك.'
                            : '🛠️ If unknown: disable it via Task Manager → Startup. If it\'s an app you installed, click "Safe" to stop the alerts.'}
                        </div>
                        <div className="row gap8" style={{ marginTop: 8 }}>
                          <button className="btn btn-primary btn-sm" onClick={() => {
                            const nm = (it.name || '').toLowerCase();
                            const exe = (String(it.value||'').match(/[a-z]:\\[^"]+\.exe/i) || [''])[0].toLowerCase();
                            const doMark = () => setAllowedItems(prev => ({ ...prev, [itemKey]: true }));
                            if (window.API && window.API.allowlistAdd) {
                              window.API.allowlistAdd(nm.endsWith('.exe') ? nm : '', exe || (nm.endsWith('.exe') ? '' : nm))
                                .then(r => { doMark(); })
                                .catch(() => doMark());
                            } else { doMark(); }
                          }}><Icon name="check" size={12} />{lang==='ar'?'آمن — أضِف لقائمة السماح':'Safe — allowlist it'}</button>
                        </div>
                      </div>
                      );
                    })}
                    {fims.map((it, i) => (
                      <div key={'f'+i} style={{ padding: '10px 13px', background: 'color-mix(in srgb, var(--critical) 8%, transparent)', borderRadius: 9, marginBottom: 7, border: '1px solid color-mix(in srgb, var(--critical) 30%, transparent)' }}>
                        <div style={{ fontSize: 12.5, fontWeight: 600 }}>
                          <Icon name="lock" size={12} /> {lang==='ar'?'تغيّر ملف مراقَب: ':'Watched file changed: '}{it.path || it.file || it.name}
                        </div>
                        <div style={{ fontSize: 11, marginTop: 5, lineHeight: 1.7, color: 'rgba(255,255,255,0.75)' }}>
                          {lang==='ar'
                            ? '🛠️ الحل: لو غيّرت هذا الملف بنفسك (أو تحديث ويندوز فعله)، فهذا طبيعي — أعد ضبط الأساس من زر «إعادة ضبط مراقبة الملفات». لو لم تغيّره، فقد يكون تعديلاً مشبوهاً — افحص الملف بـ Defender.'
                            : '🛠️ Fix: If you (or a Windows update) changed this file, it\'s normal — re-baseline via "Reset file monitoring". If you didn\'t change it, it may be a suspicious edit — scan the file with Defender.'}
                        </div>
                      </div>
                    ))}
                    {procs.map((it, i) => (
                      <div key={'pr'+i} style={{ padding: '10px 13px', background: 'color-mix(in srgb, var(--critical) 8%, transparent)', borderRadius: 9, marginBottom: 7 }}>
                        <div style={{ fontSize: 12.5, fontWeight: 600 }}><Icon name="cpu" size={12} /> {it.name} {it.pid ? <span className="mono muted">pid {it.pid}</span> : null}</div>
                        {it.reasons && it.reasons.length ? <div style={{ fontSize: 11, marginTop: 4, color: 'var(--critical)' }}>{it.reasons.join(' · ')}</div> : null}
                        <div style={{ fontSize: 11, marginTop: 5, color: 'rgba(255,255,255,0.75)' }}>
                          {lang==='ar' ? '🛠️ الحل: افحص العملية في مدير المهام. لو خبيثة، أنهِها وافحص الجهاز بـ Defender.' : '🛠️ Fix: Inspect in Task Manager; if malicious, end it and run a Defender scan.'}
                        </div>
                      </div>
                    ))}
                    {nets.map((it, i) => (
                      <div key={'n'+i} style={{ padding: '10px 13px', background: 'color-mix(in srgb, var(--warning) 8%, transparent)', borderRadius: 9, marginBottom: 7 }}>
                        <div style={{ fontSize: 12.5, fontWeight: 600 }}><Icon name="wifi" size={12} /> {it.remote || it.name || (lang==='ar'?'اتصال مشبوه':'Suspicious connection')}</div>
                        {it.reasons && it.reasons.length ? <div style={{ fontSize: 11, marginTop: 4, color: 'var(--warning)' }}>{it.reasons.join(' · ')}</div> : null}
                        <div style={{ fontSize: 11, marginTop: 5, color: 'rgba(255,255,255,0.75)' }}>
                          {lang==='ar' ? '🛠️ الحل: لو لا تعرف هذا الاتصال، اقطعه عبر جدار الحماية وافحص العملية المسؤولة.' : '🛠️ Fix: If unknown, block it via the firewall and inspect the owning process.'}
                        </div>
                      </div>
                    ))}
                  </div>
                );
              })()}
              <div style={{ fontSize: 11.5, color: 'rgba(255,255,255,0.7)', lineHeight: 1.8, marginBottom: 12, padding: '10px 13px', background: 'rgba(255,255,255,0.05)', borderRadius: 9 }}>
                {lang==='ar' ? (
                  <span>
                    ℹ️ <b>معنى النتائج:</b> الرقم بجانب كل بند = عدد التهديدات المكتشفة فيه (٠ = سليم ✓).
                    <br/>• <b>العمليات</b>: برامج مشبوهة قيد التشغيل.
                    {' '}• <b>الاستمرارية</b>: برامج تبدأ تلقائياً مع ويندوز قد تكون خبيثة.
                    {' '}• <b>الشبكة</b>: اتصالات مشبوهة (منافذ قراصنة).
                    <br/>• <b>الحسابات</b>: حسابات مخفية أو صلاحيات غريبة.
                    {' '}• <b>Rootkit</b>: برامج تخفي نفسها عن النظام.
                    {' '}• <b>السلامة</b>: تغيّر في ملفات النظام الحرجة.
                  </span>
                ) : (
                  <span>
                    ℹ️ <b>What the numbers mean:</b> each tile shows how many threats were found (0 = clean ✓).
                    Processes = suspicious running programs; Persistence = auto-start entries; Network = suspicious
                    connections; Accounts = hidden/odd accounts; Rootkit = programs hiding from the OS; Integrity =
                    changes to critical system files.
                  </span>
                )}
              </div>
              {detectResult.heuristics && (detectResult.heuristics.alerts || []).length > 0 ? (
                <div style={{ padding: '12px 14px', background: 'color-mix(in srgb, var(--warning) 12%, transparent)', borderRadius: 10, marginBottom: 12, border: '1px solid var(--warning)' }}>
                  <div style={{ fontWeight: 700, fontSize: 13, color: 'var(--warning)', marginBottom: 6 }}>
                    🧠 {lang==='ar'?'تنبيهات سلوكية (كشف بدون توقيع)':'Behavioral alerts (signature-less)'}
                  </div>
                  {(detectResult.heuristics.alerts || []).map((a, i) => (
                    <div key={'beh'+i} style={{ fontSize: 11.5, marginBottom: 4, color: 'rgba(255,255,255,0.85)' }}>
                      • <b>{a.name}</b>{a.pid ? <span className="mono muted"> (pid {a.pid})</span> : null} — {lang==='ar' ? a.detail_ar : a.detail_en}
                    </div>
                  ))}
                </div>
              ) : null}
              {detectResult.isolated && detectResult.isolated.length > 0 ? (
                <div style={{ padding: '12px 14px', background: 'color-mix(in srgb, var(--success) 12%, transparent)', borderRadius: 10, marginBottom: 12, border: '1px solid var(--success)' }}>
                  <div style={{ fontWeight: 700, fontSize: 13, color: 'var(--success)', marginBottom: 6 }}>
                    🛡️ {lang==='ar'?'عُزل تلقائياً (عُلّقت العمليات)':'Auto-isolated (processes suspended)'}
                  </div>
                  {detectResult.isolated.map((it, i) => (
                    <div key={'iso'+i} style={{ fontSize: 11.5, marginBottom: 3, color: 'rgba(255,255,255,0.85)' }}>
                      • {it.name} <span className="mono muted">(pid {it.pid})</span> — {lang==='ar'?'عُلّق بنجاح':'suspended'}
                    </div>
                  ))}
                </div>
              ) : null}
              {detectResult.rootkit && detectResult.rootkit.total > 0 ? (
                <div style={{ padding: '12px 14px', background: 'color-mix(in srgb, var(--critical) 12%, transparent)', borderRadius: 10, marginBottom: 12, border: '1px solid var(--critical)' }}>
                  <div style={{ fontWeight: 700, fontSize: 13, color: 'var(--critical)', marginBottom: 6 }}>
                    🚨 {lang==='ar'?'مؤشّرات Rootkit مكتشفة':'Rootkit indicators detected'}
                  </div>
                  {(detectResult.rootkit.hidden_processes || []).map((h, i) => (
                    <div key={'h'+i} className="muted" style={{ fontSize: 11.5, marginBottom: 3 }}>
                      • {lang==='ar'?'عملية مخفية':'Hidden process'} PID {h.pid} ({h.name}) — {lang==='ar'?'ظاهرة في':'in'} {(h.seen_in||[]).join(',')} {lang==='ar'?'مخفية عن':'hidden from'} {(h.hidden_from||[]).join(',')}
                    </div>
                  ))}
                  {(detectResult.rootkit.unsigned_drivers || []).map((d, i) => (
                    <div key={'d'+i} className="muted" style={{ fontSize: 11.5, marginBottom: 3 }}>
                      • {lang==='ar'?'درايفر مشبوه':'Suspicious driver'} '{d.name}' ({d.signature})
                    </div>
                  ))}
                </div>
              ) : null}
              {detectResult.fim && !detectResult.fim.baselined ? (
                <div className="muted" style={{ fontSize: 12, padding: '10px 12px', background: 'color-mix(in srgb, var(--warning) 10%, transparent)', borderRadius: 8, marginBottom: 8 }}>
                  {lang==='ar'
                    ? 'لم يُنشأ خط أساس لسلامة الملفات بعد. أنشئه ليبدأ Sentinel مراقبة تعديل ملفات النظام الحرجة.'
                    : 'No file-integrity baseline yet. Create one so Sentinel can watch for tampering of critical system files.'}
                  <button className="btn btn-primary btn-sm" style={{ marginInlineStart: 10 }} onClick={() => window.API.fimBaseline().then(() => doDetect())}>
                    <Icon name="lock" size={12} />{lang==='ar'?'أنشئ خط الأساس':'Create baseline'}
                  </button>
                </div>
              ) : (detectResult.fim && detectResult.fim.baselined ? (
                <div style={{ fontSize: 12, padding: '10px 12px', background: 'rgba(255,255,255,0.04)', borderRadius: 8, marginBottom: 8, display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}>
                  <span className="muted">
                    {lang==='ar'
                      ? '✅ خط الأساس مُفعّل. لو تغيّر ملف بشكل شرعي (تحديث منك)، أعد ضبط الأساس ليُعتمد الوضع الحالي كمرجع جديد.'
                      : '✅ Baseline active. If a file changed legitimately (your update), reset the baseline to accept the current state as the new reference.'}
                  </span>
                  <button className="btn btn-ghost btn-sm" style={{ flexShrink: 0 }} onClick={() => {
                    window.API.fimBaseline().then(() => {
                      doDetect();
                      if (window.toast) window.toast(lang==='ar'?'أُعيد ضبط خط الأساس — الوضع الحالي صار المرجع':'Baseline reset — current state is now the reference');
                    });
                  }}>
                    <Icon name="refresh" size={12} />{lang==='ar'?'إعادة ضبط خط الأساس':'Reset baseline'}
                  </button>
                </div>
              ) : null)}
              <div className="muted" style={{ fontSize: 11.5 }}>
                🔒 {lang==='ar'
                  ? 'كل الكشف يتم محلياً على جهازك — لا تُرفع أي بيانات. التهديدات المكتشفة تظهر أيضاً في جدول الثغرات أدناه.'
                  : 'All detection runs locally — nothing is uploaded. Detected threats also appear in the findings table below.'}
              </div>
            </div>
          </div>
        ) : null}

        {comp && comp.total ? (
          <div className="card" style={{ marginBottom: 20 }}>
            <CardHead title={lang==='ar'?'② الامتثال (معايير CIS)':'② Compliance (CIS benchmarks)'} icon="check" iconColor="var(--primary)"
              right={<span className="row gap8" style={{fontSize:12.5}}>
                <b style={{color: comp.score>=80?'var(--success)':comp.score>=50?'var(--warning)':'var(--critical)'}}>{comp.score}%</b>
                <span className="muted">{comp.passed}/{comp.total}</span></span>} />
            <div className="card-pad" style={{ paddingTop: 6 }}>
              {comp.controls.filter(c=>c.status!=='manual').map((c,i) => (
                <div key={i} className="row" style={{ justifyContent:'space-between', padding:'7px 0', borderBottom: i<comp.controls.length-1?'1px solid var(--hairline)':'none', fontSize:12.5 }}>
                  <span className="row gap8" style={{minWidth:0}}>
                    <span className="mono muted" style={{fontSize:11}}>{c.id}</span>
                    <span style={{color:'var(--text-1)'}}>{lang==='ar'?c.title_ar:c.title_en}</span>
                  </span>
                  <span className="sev" style={{ color: c.status==='pass'?'var(--success)':'var(--critical)', background:`color-mix(in srgb, ${c.status==='pass'?'var(--success)':'var(--critical)'} 14%, transparent)` }}>
                    <span className="dot" style={{background: c.status==='pass'?'var(--success)':'var(--critical)'}}/>{c.status==='pass'?(lang==='ar'?'مجتاز':'Pass'):(lang==='ar'?'فاشل':'Fail')}
                  </span>
                </div>
              ))}
            </div>
          </div>
        ) : null}

        {intel ? (
          <div className="card" style={{ marginBottom: 20, background: 'rgba(10,16,20,0.82)', backdropFilter: 'blur(14px)' }}>
            <CardHead title={lang==='ar'?'④ أحدث الثغرات المُستغَلّة فعلياً عالمياً (CISA KEV)':'④ Latest actively-exploited vulnerabilities worldwide (CISA KEV)'}
              icon="zap" iconColor="var(--critical)"
              right={<span className="row gap12" style={{fontSize:11.5}}>
                <span style={{color:'rgba(255,255,255,0.7)'}}>{intel.offline ? (lang==='ar'?'وضع غير متصل':'Offline mode')
                  : (intel.updated ? (lang==='ar'?'حُدّث: ':'Updated: ')+new Date(intel.updated).toLocaleString(lang==='ar'?'ar':'en') : (lang==='ar'?'بانتظار التحديث':'pending'))}</span>
                {!intel.offline && window.API && window.API.updateThreatIntel ?
                  <button className="btn btn-ghost btn-sm" onClick={() => { window.API.updateThreatIntel().then(()=>setTimeout(reload,2500)); }}>
                    <Icon name="refresh" size={13} />{lang==='ar'?'تحديث الآن':'Update now'}</button> : null}
              </span>} />
            <div className="card-pad" style={{ paddingTop: 8 }}>
              <div style={{ fontSize: 12.5, marginBottom: 12, padding: '10px 13px', background: 'rgba(255,255,255,0.06)', borderRadius: 9, color: 'rgba(255,255,255,0.82)', lineHeight: 1.7 }}>
                {lang==='ar'
                  ? 'ℹ️ ما هذا القسم؟ قائمة عامة من الحكومة الأمريكية (CISA) بالثغرات التي يستغلّها القراصنة الآن في هجمات حقيقية حول العالم. هذه ليست ثغرات في جهازك — بل مرجع للتهديدات النشطة عالمياً. كلمة «فدية» تعني أن الثغرة استُخدمت في هجمات برامج الفدية. جهازك يُقارَن بها محلياً، ونتائج جهازك تظهر في قسم «نتائج الثغرات» أعلاه.'
                  : 'ℹ️ What is this? A public US-government (CISA) list of vulnerabilities hackers are exploiting RIGHT NOW worldwide. These are NOT flaws on your machine — just a reference of active global threats. "Ransomware" means the flaw has been used in ransomware attacks. Your machine is compared against this list locally; your own results appear in "Vulnerability Findings" above.'}
              </div>
              <div style={{ fontSize: 11.5, marginBottom: 10, color: 'rgba(255,255,255,0.6)' }}>
                🔒 {lang==='ar'
                  ? 'الخصوصية: تُسحب هذه القائمة العامة فقط (اتجاه واحد). لا يُرسَل أي شيء عن جهازك.'
                  : 'Privacy: this public list is downloaded one-way only. Nothing about your machine is ever sent.'}
              </div>
              {(intel.latest || []).length === 0 ? (
                <div style={{ fontSize: 12.5, color: 'rgba(255,255,255,0.7)' }}>{intel.offline ? (lang==='ar'?'التحديث معطّل (وضع غير متصل).':'Updates disabled (offline mode).') : (lang==='ar'?'جارٍ جلب أحدث التهديدات…':'Fetching latest threats…')}</div>
              ) : (
                <div style={{ display:'flex', flexDirection:'column', gap:7 }}>
                  {(intel.latest || []).slice(0,8).map((k,i) => (
                    <div key={i} className="row" style={{ justifyContent:'space-between', alignItems:'flex-start', gap:12, padding:'9px 0', borderBottom: i<7?'1px solid rgba(255,255,255,0.08)':'none' }}>
                      <span style={{ minWidth:0, flex:1, display:'flex', flexDirection:'column', gap:3 }}>
                        <span className="mono" style={{ color:'#ff6b6a', fontWeight:700, fontSize:12.5 }}>{k.cve}</span>
                        <span style={{ fontSize:12.5, lineHeight:1.55, wordBreak:'break-word', color:'rgba(255,255,255,0.88)' }}>{k.vendor} {k.product} — {k.name}</span>
                      </span>
                      {String(k.ransomware||'').toLowerCase().indexOf('known')===0 ?
                        <span className="sev" style={{ flexShrink:0, color:'#fff', background:'var(--critical)', fontWeight:600 }}><span className="dot" style={{background:'#fff'}}/>{lang==='ar'?'فدية':'Ransomware'}</span>
                        : <span className="tnum" style={{ fontSize:11, flexShrink:0, color:'rgba(255,255,255,0.55)' }}>{k.added}</span>}
                    </div>
                  ))}
                </div>
              )}
              <div style={{ fontSize:11, marginTop:10, color:'rgba(255,255,255,0.5)' }}>
                {intel.total ? (lang==='ar'? ('إجمالي الثغرات المُستغَلّة المعروفة: '+intel.total) : (intel.total+' known exploited vulnerabilities tracked')) : ''}
              </div>
            </div>
          </div>
        ) : null}

        <div className="grid" style={{ gridTemplateColumns: '1fr 1fr 1fr 1fr 1.3fr', gap: 16, marginBottom: 20 }}>
          {counts.map(c => {
            const col = window.SEV_COLORS[c.k];
            return (
              <div className="card card-pad" key={c.k}>
                <div className="row" style={{ justifyContent: 'space-between', marginBottom: 10 }}>
                  <SevPill level={c.k} label={t.sev[c.k]} />
                  <span style={{ color: col }}><Icon name="shield" size={18} /></span>
                </div>
                <div className="value tnum" style={{ fontSize: 32, fontWeight: 700, color: col }}>{c.n}</div>
                <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>{txt.openFindings}</div>
              </div>
            );
          })}
          <div className="card card-pad row" style={{ gap: 16 }}>
            <ScoreRing value={risk != null ? risk : 0} size={92} thickness={9} color="var(--warning)" label={t.tbl.risk} />
            <div>
              <div className="eyebrow" style={{ marginBottom: 6 }}>{t.tbl.risk}</div>
              <div style={{ fontSize: 14, fontWeight: 600, color: 'var(--warning)' }}>
                {risk == null ? (lang==='ar'?'جارٍ الحساب…':'Calculating…')
                  : risk >= 70 ? (lang==='ar'?'خطورة عالية':'High risk')
                  : risk >= 40 ? (lang==='ar'?'خطورة متوسطة':'Moderate risk')
                  : (lang==='ar'?'خطورة منخفضة':'Low risk')}
              </div>
              <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                {(() => { const tot = counts.reduce((a,c)=>a+(c.n||0),0);
                  return lang==='ar' ? `${tot} ثغرة إجمالاً` : `${tot} total findings`; })()}
              </div>
            </div>
          </div>
        </div>

        <div className="grid" style={{ gridTemplateColumns: '1.7fr 1fr', gap: 20 }}>
          <div className="card">
            <CardHead title={'③ ' + t.sec.findings} icon="alert" iconColor="var(--critical)"
              right={<span className="row gap8">
                <LastUpdated ts={lastUpdate} lang={lang} />
                <TableSearch value={search} onChange={setSearch} lang={lang} />
              </span>} />
            <div className="muted" style={{ fontSize: 11.5, padding: '0 16px', marginTop: -6, marginBottom: 6 }}>
              {lang==='ar'
                ? 'نقاط الضعف الفعلية المكتشفة على جهازك. اضغط «معالجة» بجانب أيٍّ منها لإصلاحها.'
                : 'Actual weaknesses found on your machine. Click "Fix" next to any to remediate it.'}
            </div>
            <div style={{ overflowX: 'auto' }}>
              <table className="tbl">
                <thead><tr><th>{t.tbl.cve}</th><th>{t.tbl.asset}</th><th>{t.tbl.severity}</th><th>CVSS</th><th>{t.tbl.status}</th><th>{t.tbl.fix}</th><th>{txt.actions}</th></tr></thead>
                <tbody>
                  {findings.filter(r => {
                    // time-range filter: keep findings first seen within the window.
                    // findings without a timestamp are always shown (current state).
                    if (range !== 'all' && r.first_seen) {
                      const days = range === '7d' ? 7 : 30;
                      const cutoff = Date.now() - days * 86400000;
                      if (r.first_seen < cutoff) return false;
                    }
                    if (!search) return true;
                    const q = search.toLowerCase();
                    return (r.cve||'').toLowerCase().includes(q)
                        || (r.asset||'').toLowerCase().includes(q)
                        || (r.sev||'').toLowerCase().includes(q)
                        || (r.st||'').toLowerCase().includes(q)
                        || (r.fix||'').toLowerCase().includes(q);
                  }).map((r, i) => {
                    const actioned = isActioned(r.st);
                    const fKey = 'f:' + r.cve;
                    const working = !!busy[fKey];
                    return (
                      <tr key={r.cve || i} style={r.st === 'dismissed' ? { opacity: 0.55 } : null}>
                        <td className="mono" style={{ color: 'var(--text-1)' }}>{r.cve}</td>
                        <td>{r.asset}</td>
                        <td><SevPill level={r.sev} label={t.sev[r.sev]} /></td>
                        <td className="tnum" style={{ fontWeight: 600, color: 'var(--text-1)' }}>{r.score}</td>
                        <td>{r.st === 'dismissed'
                          ? <MutedPill>{txt.dismissed}</MutedPill>
                          : <StatusPill tone={stTone[r.st]}>{t.sevWord[r.st]}</StatusPill>}</td>
                        <td style={{ maxWidth: 220, color: 'var(--text-2)', textDecoration: r.st === 'dismissed' ? 'line-through' : 'none' }}>{r.fix}</td>
                        <td>
                          {actioned ? (
                            <span className="muted" style={{ fontSize: 12 }}>—</span>
                          ) : (
                            <div className="row gap8" style={{ flexWrap: 'nowrap' }}>
                              <button className="btn btn-primary btn-sm" onClick={() => openRemediation(r)} disabled={working} title={lang==='ar'?'عرض خطط الإصلاح الفعلية وتنفيذها':'Show & run the real fix'}>
                                <Icon name="zap" size={13} sw={2.2} />{lang==='ar'?'معالجة':'Fix'}
                              </button>
                              <button className="btn btn-ghost btn-sm" onClick={() => explain(r)} disabled={working} title={lang==='ar'?'اشرح هذه الثغرة ببساطة':'Explain this finding'}>
                                <Icon name="eye" size={13} sw={2.2} style={{ color: 'var(--primary)' }} />{lang==='ar'?'اشرح':'Explain'}
                              </button>
                              <button className="btn btn-ghost btn-sm" onClick={() => doFinding(r.cve, 'dismiss')} disabled={working} title={lang==='ar'?'هذه آمنة/مقبولة لديّ — لا تعدّها ثغرة بعد الآن':'This is safe/accepted — stop flagging it'}>
                                <Icon name="check" size={13} sw={2.2} />{lang==='ar'?'آمنة':'Safe'}
                              </button>
                            </div>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          <div className="grid" style={{ gap: 20, alignContent: 'start' }}>
            <div className="card">
              <CardHead title={lang==='ar'?'توزيع الخطورة':'Severity mix'} icon="shield" />
              <div className="card-pad row" style={{ gap: 18, justifyContent: 'center' }}>
                <div style={{ position: 'relative' }}>
                  <Donut size={130} thickness={16} segments={counts.map(c => ({ value: c.n, color: window.SEV_COLORS[c.k] }))} />
                </div>
                <div className="grid" style={{ gap: 8 }}>
                  {counts.map(c => (
                    <div key={c.k} className="row gap8" style={{ fontSize: 12.5 }}>
                      <span className="dot" style={{ background: window.SEV_COLORS[c.k] }} />
                      <span className="muted" style={{ minWidth: 54 }}>{t.sev[c.k]}</span>
                      <span className="tnum" style={{ fontWeight: 600 }}>{c.n}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
            <div className="card">
              <CardHead title={lang==='ar'?'توصيات أمنية':'Recommendations'} icon="check" iconColor="var(--success)" />
              <div className="card-pad" style={{ paddingTop: 6 }}>
                {recs.map((r, i) => {
                  const done = r.state === 'applied';
                  const dropped = r.state === 'dismissed';
                  const rKey = 'r:' + r.id;
                  const working = !!busy[rKey];
                  return (
                    <div key={r.id || i} className="row gap12"
                      style={{ padding: '9px 0', borderBottom: i < recs.length-1 ? '1px solid var(--hairline)' : 'none', opacity: dropped ? 0.5 : 1 }}>
                      <span style={{ color: done ? 'var(--success)' : (dropped ? 'var(--text-3)' : 'var(--success)'), flexShrink: 0, marginTop: 1 }}>
                        <Icon name={dropped ? 'x' : 'check'} size={16} sw={2.2} />
                      </span>
                      <span style={{ fontSize: 13, color: 'var(--text-2)', flex: 1, textDecoration: dropped ? 'line-through' : 'none' }}>{r.text}</span>
                      {done ? (
                        <span className="sev" style={{ color: 'var(--success)', background: 'color-mix(in srgb, var(--success) 16%, transparent)' }}><span className="dot" style={{ background: 'var(--success)' }} />{txt.applied}</span>
                      ) : dropped ? (
                        <MutedPill>{txt.dismissed}</MutedPill>
                      ) : (
                        <div className="row gap8" style={{ flexShrink: 0 }}>
                          {r.cve ? (
                            <button className="btn btn-primary btn-sm" onClick={() => { const f = findings.find(x => x.cve === r.cve); if (f) openRemediation(f); }} disabled={working} title={lang==='ar'?'خطط الإصلاح':'Fix plans'}>
                              <Icon name="zap" size={13} sw={2.2} />{lang==='ar'?'معالجة':'Fix'}
                            </button>
                          ) : null}
                          <button className="btn btn-ghost btn-sm" onClick={() => doRec(r.id, 'apply')} disabled={working} title={txt.apply}>
                            <Icon name={working ? 'refresh' : 'check'} size={13} sw={2.2} style={{ color: 'var(--success)' }} />{txt.apply}
                          </button>
                          <button className="btn btn-ghost btn-sm" onClick={() => doRec(r.id, 'dismiss')} disabled={working} title={txt.dismiss}>
                            <Icon name="x" size={13} sw={2.2} />{txt.dismiss}
                          </button>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>

        {explainFor ? (
          <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.6)', zIndex: 1001, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16, overflowY: 'auto' }} onClick={() => setExplainFor(null)}>
            <div className="card" style={{ width: 'min(560px, 96vw)', maxHeight: '85vh', overflowY: 'auto', margin: 'auto' }} onClick={e => e.stopPropagation()}>
              <CardHead title={(lang==='ar' ? 'شرح: ' : 'Explain: ') + explainFor.cve} icon="eye" iconColor="var(--primary)"
                right={<button className="btn btn-ghost btn-sm" onClick={() => setExplainFor(null)}><Icon name="x" size={14} /></button>} />
              <div className="card-pad" style={{ paddingTop: 6 }}>
                {explainBusy && !explainText ? (
                  <div className="muted" style={{ fontSize: 13, padding: '20px 0', textAlign: 'center' }}>
                    <Icon name="refresh" size={18} /> {lang==='ar'?'جارٍ التحضير…':'Preparing…'}
                  </div>
                ) : (
                  <div style={{ fontSize: 13.5, lineHeight: 1.85, color: 'var(--text-1)', whiteSpace: 'pre-wrap' }}>
                    {explainText}
                  </div>
                )}
                <div style={{ marginTop: 16, paddingTop: 14, borderTop: '0.5px solid var(--border)', display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                  <button className="btn btn-ghost btn-sm" onClick={explainWithAi} disabled={explainBusy}>
                    <Icon name={explainBusy ? 'refresh' : 'terminal'} size={13} sw={2} style={{ color: 'var(--primary)' }} />
                    {lang==='ar'?'اشرح بذكاء أعمق (نموذج محلي)':'Deeper AI explanation (local model)'}
                  </button>
                  <span className="muted" style={{ fontSize: 11 }}>
                    🔒 {lang==='ar'?'الشرح يتم محلياً':'Explained locally'}
                  </span>
                </div>
              </div>
            </div>
          </div>
        ) : null}

        {remFinding ? (
          <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.6)', zIndex: 1000, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16, overflowY: 'auto' }} onClick={closeRemediation}>
            <div className="card" style={{ width: 'min(720px, 96vw)', maxHeight: '88vh', overflowY: 'auto', margin: 'auto' }} onClick={e => e.stopPropagation()}>
              <CardHead title={(lang==='ar' ? 'خطط معالجة: ' : 'Fix plans: ') + remFinding.cve} icon="zap" iconColor="var(--primary)"
                right={<button className="btn btn-ghost btn-sm" onClick={closeRemediation}><Icon name="x" size={14} /></button>} />
              <div className="card-pad" style={{ paddingTop: 6 }}>
                <div className="muted" style={{ fontSize: 12, marginBottom: 12, lineHeight: 1.7 }}>
                  🔒 {lang==='ar'
                    ? 'لا يُنفَّذ أي أمر إلا بموافقتك الصريحة. راجع الأوامر كاملة أدناه — كل أمر يعمل محلياً على جهازك فقط، ومعظم الخطط لها أمر تراجع.'
                    : 'Nothing runs without your explicit approval. Review the full commands below — everything runs locally, and most plans include an undo command.'}
                </div>

                {remPlans === null ? (
                  <div className="muted" style={{ fontSize: 12.5 }}>{lang==='ar'?'جارٍ جلب الخطط…':'Loading plans…'}</div>
                ) : (remPlans && remPlans.authRequired) ? (
                  <div style={{ fontSize: 13, padding: '14px 16px', background: 'color-mix(in srgb, var(--warning) 12%, transparent)', border: '1px solid var(--warning)', borderRadius: 10, lineHeight: 1.8 }}>
                    🔐 {lang==='ar'
                      ? 'يجب تسجيل الدخول لعرض خطط الإصلاح وتنفيذها. اذهب لصفحة «الملف الشخصي» وسجّل الدخول (أو أنشئ حساباً — أول حساب يصبح مديراً)، ثم عُد واضغط «معالجة».'
                      : 'You must sign in to view and run fix plans. Go to the Profile page and log in (or create an account — the first one becomes admin), then come back and click Fix.'}
                  </div>
                ) : remPlans.length === 0 ? (
                  <div className="muted" style={{ fontSize: 12.5 }}>
                    {lang==='ar'
                      ? 'لا خطة تلقائية آمنة لهذه الثغرة — اتبع التوصية في عمود "الإصلاح" يدوياً.'
                      : 'No safe automated plan for this finding — follow the Fix column manually.'}
                  </div>
                ) : remPlans.map(p => {
                  const riskColor = p.risk === 'safe' ? 'var(--success)' : p.risk === 'moderate' ? 'var(--warning)' : 'var(--critical)';
                  const riskWord = lang==='ar'
                    ? (p.risk === 'safe' ? 'آمن' : p.risk === 'moderate' ? 'متوسّط' : 'انتبه')
                    : p.risk;
                  return (
                    <div key={p.id} style={{ border: '1px solid var(--border)', borderRadius: 10, padding: 14, marginBottom: 12 }}>
                      <div className="row gap8" style={{ justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 6 }}>
                        <div style={{ fontWeight: 600, color: 'var(--text-1)', fontSize: 13.5 }}>{lang==='ar' ? p.title_ar : p.title_en}</div>
                        <span className="sev" style={{ color: riskColor, background: `color-mix(in srgb, ${riskColor} 14%, transparent)`, whiteSpace: 'nowrap' }}>
                          <span className="dot" style={{ background: riskColor }} />{riskWord}</span>
                      </div>
                      <div className="muted" style={{ fontSize: 12, marginBottom: 8, lineHeight: 1.6 }}>{lang==='ar' ? p.note_ar : p.note_en}</div>
                      <div className="mono" style={{ fontSize: 11, background: 'var(--bg-inset)', borderRadius: 8, padding: '8px 10px', marginBottom: 8, direction: 'ltr', textAlign: 'left', overflowX: 'auto' }}>
                        {p.commands.map((c, i) => <div key={i}>$ {c}</div>)}
                      </div>
                      {p.undo && p.undo.length ? (
                        <div className="muted" style={{ fontSize: 11, marginBottom: 8 }}>
                          ↩ {lang==='ar'?'التراجع: ':'Undo: '}<span className="mono" style={{ direction: 'ltr', display: 'inline-block' }}>{p.undo[0]}</span>
                        </div>
                      ) : null}
                      <button className="btn btn-primary btn-sm" disabled={remBusy} onClick={() => runPlan(p.id)}>
                        <Icon name={remBusy ? 'refresh' : 'check'} size={13} sw={2.2} />
                        {remBusy ? (lang==='ar'?'جارٍ التنفيذ…':'Running…') : (lang==='ar'?'أوافق — نفّذ هذه الخطة':'I approve — run this plan')}
                      </button>
                    </div>
                  );
                })}

                {remResult ? (
                  <div style={{ borderRadius: 10, padding: 14, background: remResult.verified ? 'color-mix(in srgb, var(--success) 12%, transparent)' : 'color-mix(in srgb, var(--warning) 12%, transparent)' }}>
                    <div style={{ fontWeight: 600, fontSize: 13, marginBottom: 6, color: remResult.verified ? 'var(--success)' : 'var(--warning)' }}>
                      {remResult.ok
                        ? (remResult.verified
                            ? (lang==='ar' ? '✓ نُفّذت وتحقّقنا — الثغرة أُغلقت' : '✓ Executed & verified — finding closed')
                            : (lang==='ar' ? '⏳ نُفّذت — سيتأكّد الفحص القادم من الإغلاق' : '⏳ Executed — next scan will confirm closure'))
                        : ('✗ ' + (remResult.error || 'failed'))}
                    </div>
                    {(remResult.results || []).map((r, i) => (
                      <div key={i} className="mono muted" style={{ fontSize: 10.5, direction: 'ltr', textAlign: 'left', whiteSpace: 'pre-wrap', marginBottom: 4 }}>
                        $ {r.cmd}{'\n'}{(r.output || '').slice(0, 240)}
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>
            </div>
          </div>
        ) : null}
      </div>
    );
  }

  /* ---------------- LOGS ---------------- */
  function Logs({ t, lang }) {
    const { useState, useEffect, useRef } = React;
    const [level, setLevel] = useState('all');
    const [search, setSearch] = useState('');
    const [events, setEvents] = useState(null);
    const mref = useRef(true);
    const levels = ['all', 'critical', 'warning', 'info'];
    const levelName = { all: lang==='ar'?'الكل':'All', critical: t.sev.critical, warning: lang==='ar'?'تحذير':'Warning', info: t.sev.info };
    const lvlColor = { critical: 'var(--critical)', warning: 'var(--warning)', info: 'var(--primary)', success: 'var(--success)' };

    const loadEvents = () => {
      if (!(window.API && window.API.searchEvents)) { setEvents([]); return; }
      window.API.searchEvents({ limit: 200 }).then(d => {
        if (!mref.current) return;
        setEvents((d && d.items) ? d.items : []);
      });
    };
    useEffect(() => { mref.current = true; loadEvents();
      const iv = setInterval(loadEvents, 20000);
      return () => { mref.current = false; clearInterval(iv); }; }, []);

    // map real backend events -> table rows
    const sevMap = { critical: 'critical', high: 'critical', medium: 'warning', low: 'info', info: 'info' };
    const all = (events || []).map(e => ({
      tm: e.ts ? new Date(e.ts).toLocaleTimeString(lang==='ar'?'ar-EG':'en-US') : '',
      lv: sevMap[(e.sev||'info').toLowerCase()] || 'info',
      src: e.kind || 'system',
      ev: (lang==='ar' ? (e.text_ar || e.text_en) : (e.text_en || e.text_ar)) || '',
      h: e.asset || '',
    }));
    const filtered = level === 'all' ? all : all.filter(r => r.lv === level);
    const rows = !search ? filtered : filtered.filter(r => {
      const q = search.toLowerCase();
      return (r.tm||'').toLowerCase().includes(q) || (r.src||'').toLowerCase().includes(q)
          || (r.ev||'').toLowerCase().includes(q) || (r.h||'').toLowerCase().includes(q);
    });

    return (
      <div>
        <PageHead t={t} lang={lang} title={t.nav.logs} sub={t.pageSub.logs}
          actions={<><button className="btn btn-ghost" onClick={() => window.API && window.API.exportCsv && window.API.exportCsv('events', lang)}><Icon name="download" size={15} />{t.btn.exportCsv}</button></>} />
        <div style={{ fontSize: 12.5, color: 'rgba(255,255,255,0.72)', lineHeight: 1.7, marginBottom: 14, padding: '11px 14px', background: 'rgba(255,255,255,0.05)', borderRadius: 9 }}>
          ℹ️ {lang==='ar'
            ? 'هذه صفحة سجلّ الأحداث: تعرض كل ما رصده البرنامج فعلياً على جهازك (فحوصات، تهديدات مكتشفة، معالجات نُفّذت، أحداث تسجيل دخول…) مرتّبة زمنياً. استخدمها لمراجعة ما حدث ومتى. كل الأحداث محلية على جهازك.'
            : 'This is the event log: everything Sentinel actually observed on your machine (scans, detected threats, remediations run, login events…) in time order. Use it to review what happened and when. All events are local.'}
        </div>
        <div className="card">
          <div className="card-head" style={{ gap: 12, flexWrap: 'wrap' }}>
            <TableSearch value={search} onChange={setSearch} lang={lang} />
            <div className="seg">
              {levels.map(l => <button key={l} className={level === l ? 'on' : ''} onClick={() => setLevel(l)}>{levelName[l]}</button>)}
            </div>
            <div className="spacer" />
            <button className="btn btn-ghost btn-sm" onClick={loadEvents}><Icon name="refresh" size={14} />{lang==='ar'?'تحديث':'Refresh'}</button>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table className="tbl">
              <thead><tr><th>{t.tbl.time}</th><th>{t.tbl.level}</th><th>{t.tbl.source}</th><th>{t.tbl.event}</th><th>{t.tbl.host}</th></tr></thead>
              <tbody>
                {events === null ? (
                  <tr><td colSpan={5} style={{ textAlign: 'center', padding: 24, color: 'var(--text-3)' }}>{lang==='ar'?'جارٍ التحميل…':'Loading…'}</td></tr>
                ) : rows.length === 0 ? (
                  <tr><td colSpan={5} style={{ textAlign: 'center', padding: 24, color: 'var(--text-3)' }}>{lang==='ar'?'لا أحداث بعد — شغّل فحصاً لتبدأ.':'No events yet — run a scan to start.'}</td></tr>
                ) : rows.map((r, i) => (
                  <tr key={i}>
                    <td className="mono">{r.tm}</td>
                    <td><span className="sev" style={{ color: lvlColor[r.lv], background: `color-mix(in srgb, ${lvlColor[r.lv]} 15%, transparent)` }}><span className="dot" style={{ background: lvlColor[r.lv] }} />{levelName[r.lv]}</span></td>
                    <td className="mono" style={{ color: 'var(--text-2)' }}>{r.src}</td>
                    <td style={{ color: 'var(--text-1)' }}>{r.ev}</td>
                    <td className="mono" style={{ color: 'var(--text-2)' }}>{r.h}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="row" style={{ justifyContent: 'space-between', padding: '14px 18px' }}>
            <span className="muted" style={{ fontSize: 12.5 }}>{lang==='ar'?`عرض ${rows.length} حدث`:`Showing ${rows.length} events`}</span>
          </div>
        </div>
      </div>
    );
  }

  Object.assign(window, { Security, Logs, PageHead });
})();
