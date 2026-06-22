/* Equilibrium Sentinel — Sidebar + TopBar */
(function () {
  const { Icon } = window;
  const { useState } = React;

  const NAV = [
    { group: 'monitor', items: [
      { id: 'overview', icon: 'overview' },
      { id: 'system', icon: 'cpu' },
      { id: 'network', icon: 'network' },
    ]},
    { group: 'secure', items: [
      { id: 'security', icon: 'shield', badge: 7 },
      { id: 'alerts', icon: 'bell', badge: 3 },
      { id: 'logs', icon: 'logs' },
    ]},
    { group: 'manage', items: [
      { id: 'reports', icon: 'report' },
      { id: 'devices', icon: 'devices' },
      { id: 'settings', icon: 'settings' },
    ]},
  ];

  function Sidebar({ t, route, setRoute, collapsed }) {
    const { useState, useEffect } = React;
    const [me, setMe] = useState(null);
    // expose the router so other components (e.g. the notification dropdown in
    // the top bar) can navigate without prop-drilling.
    useEffect(() => { window.__sxSetRoute = setRoute; }, [setRoute]);
    useEffect(() => {
      let alive = true;
      const refresh = () => { if (window.API && window.API.getMe) window.API.getMe().then(u => { if (alive) setMe(u); }); };
      refresh();
      window.addEventListener('sx-auth-changed', refresh);
      return () => { alive = false; window.removeEventListener('sx-auth-changed', refresh); };
    }, []);
    const lang = (t && t._dir === 'rtl') ? 'ar' : 'en';
    return (
      <aside className="sidebar">
        <div className="sb-brand">
          <span className="mark"><Icon name="shield" size={19} sw={2} /></span>
          <div className="label">
            <div className="name">Sentinel</div>
            <div className="tag">{t.brandTag}</div>
          </div>
        </div>

        <nav className="sb-section">
          {NAV.map(sec => (
            <div key={sec.group}>
              <div className="sb-heading">{t.navGroups[sec.group]}</div>
              {sec.items.map(it => (
                <button key={it.id}
                  className={'nav-item' + (route === it.id ? ' active' : '')}
                  onClick={() => setRoute(it.id)} title={t.nav[it.id]}>
                  <span className="ico"><Icon name={it.icon} size={19} /></span>
                  <span className="lbl">{t.nav[it.id]}</span>
                  {it.badge && (
                    <span className="badge-dot pill" style={{ marginInlineStart: 'auto', padding: '2px 8px', fontSize: 11,
                      color: route === it.id ? 'var(--primary)' : 'var(--text-2)',
                      background: 'var(--bg-inset)' }}>{it.badge}</span>
                  )}
                </button>
              ))}
            </div>
          ))}
        </nav>

        <div className="sb-foot">
          <button className={'nav-item' + (route === 'profile' ? ' active' : '')} onClick={() => setRoute('profile')} title={t.nav.profile} style={{ marginBottom: 6 }}>
            <span className="ico"><Icon name="user" size={19} /></span>
            <span className="lbl">{t.nav.profile}</span>
          </button>
          <div className="sb-user" onClick={() => setRoute('profile')} style={{ cursor: 'pointer' }} title={t.nav.profile}>
            <span className="av">{me ? me.initials : <Icon name="user" size={16} />}</span>
            <div className="who">
              <div className="n">{me ? me.name : (lang === 'ar' ? 'تسجيل الدخول' : 'Sign in')}</div>
              <div className="r">{me ? me.role : (lang === 'ar' ? 'غير مسجَّل' : 'Not signed in')}</div>
            </div>
            <span className="chev" style={{ marginInlineStart: 'auto', color: 'var(--text-3)' }}><Icon name={lang === 'ar' ? 'chevLeft' : 'chevRight'} size={16} /></span>
          </div>
        </div>
      </aside>
    );
  }

  function TopBar({ t, lang, route, onToggleSidebar, onToggleLang }) {
    const { useState, useEffect, useRef } = React;
    const [notifOpen, setNotifOpen] = useState(false);
    const [modelOpen, setModelOpen] = useState(false);
    const [scanning, setScanning] = useState(false);
    const [scanReport, setScanReport] = useState(null);
    const fileRef = useRef(null);

    // Scan Now -> pick a log/json/text file -> upload -> model analyzes -> report
    const onPickFile = () => { if (!scanning && fileRef.current) fileRef.current.click(); };
    const onFileChosen = (e) => {
      const file = e.target.files && e.target.files[0];
      e.target.value = '';                 // allow re-selecting the same file
      if (!file) return;
      setScanning(true);
      const finish = (res) => {
        setScanning(false);
        if (res && res.ok && res.report) setScanReport(res.report);
        window.dispatchEvent(new Event('sx-scan-done'));
      };
      // multipart upload => byte-accurate hashing/analysis for binary files too
      if (window.API && window.API.scanUploadFile)
        Promise.resolve(window.API.scanUploadFile(file, lang)).then(finish).catch(() => finish(null));
      else finish(null);
    };

    const toneColor = { danger: 'var(--critical)', warning: 'var(--warning)', success: 'var(--success)', info: 'var(--secondary)' };

    const [notifs, setNotifs] = useState([]);   // filled from real backend events
    const [models, setModels] = useState(null);
    const [curModel, setCurModel] = useState('q4');
    const mounted = useRef(true);

    // live notifications: initial fetch + poll + instant updates from the SSE bus
    useEffect(() => {
      mounted.current = true;
      const load = () => {
        if (window.API && window.API.getNotifications) {
          window.API.getNotifications(lang).then(list => { if (mounted.current && list) setNotifs(list); });
        }
      };
      load();
      const iv = setInterval(load, 15000);
      const onNotif = (e) => {
        const n = e.detail; if (!n || !mounted.current) return;
        setNotifs(prev => [{ id: n.id, ic: n.ic, tone: n.tone, t: (lang==='ar'?n.ar:n.en) || n.t, s: (lang==='ar'?n.sub_ar:n.sub_en) || n.s }, ...prev].slice(0, 12));
      };
      window.addEventListener('sx-notification', onNotif);
      return () => { mounted.current = false; clearInterval(iv); window.removeEventListener('sx-notification', onNotif); };
    }, [lang]);

    // model list (q4 / q8)
    useEffect(() => {
      if (window.API && window.API.getModels) {
        window.API.getModels(lang).then(d => { if (mounted.current && d) { setModels(d.models || []); setCurModel(d.current || 'q4'); } });
      }
    }, [lang]);

    const pickModel = (id) => {
      setCurModel(id); setModelOpen(false);
      if (window.API && window.API.setModel) {
        window.API.setModel(id).then(() => {
          // confirm to the user that the switch took effect everywhere
          const label = (models.find(m => m.id === id) || {}).label || id;
          // notify the overview hero (and anything else) to refresh the model name
          window.dispatchEvent(new Event('sx-model-changed'));
          if (window.toast) window.toast(lang==='ar' ? ('تم التبديل إلى ' + label + ' — سيُستخدم في كل التحليل والتقارير') : ('Switched to ' + label + ' — used for all analysis & reports'));
        });
      }
    };

    const curLabel = (models && models.find(m => m.id === curModel) || {}).label || (curModel === 'q4' ? 'Foundation-Sec · Q4' : 'Foundation-Sec · Full');

    return (
      <header className="topbar">
        <button className="tb-toggle" onClick={onToggleSidebar} aria-label="menu"><Icon name="menu" size={20} /></button>
        <div className="tb-title">
          <h1>{t.nav[route] || t.nav.overview}</h1>
          <p>{t.pageSub[route] || ''}</p>
        </div>

        <label className="tb-search">
          <Icon name="search" size={17} />
          <input placeholder={t.search} />
          <kbd>⌘K</kbd>
        </label>

        <div className="tb-actions">
          {/* MODEL SWITCHER (q4 / q8) */}
          <div style={{ position: 'relative' }}>
            <button className="lang-btn" onClick={() => { setModelOpen(v => !v); setNotifOpen(false); }} title={lang==='ar'?'النموذج':'Model'} style={{ gap: 7 }}>
              <Icon name="zap" size={15} sw={2} />
              <span style={{ fontSize: 12, fontWeight: 600, maxWidth: 130, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{curLabel}</span>
              <Icon name="chevDown" size={13} />
            </button>
            {modelOpen && (
              <div className="pop" style={{ minWidth: 268 }}>
                <div style={{ fontWeight: 600, fontSize: 13.5, padding: '6px 10px 8px' }}>{lang==='ar'?'اختر النموذج':'Choose model'}</div>
                {(models || []).map(m => (
                  <div className="pi" key={m.id} onClick={() => pickModel(m.id)} style={{ cursor: 'pointer', borderRadius: 10, background: m.id === curModel ? 'color-mix(in srgb, var(--primary) 12%, transparent)' : 'transparent' }}>
                    <span style={{ width: 30, height: 30, borderRadius: 9, flexShrink: 0, display: 'grid', placeItems: 'center', color: 'var(--primary)', background: 'color-mix(in srgb, var(--primary) 14%, transparent)' }}>
                      <Icon name={m.id === curModel ? 'check' : 'cpu'} size={15} sw={2.2} />
                    </span>
                    <div style={{ minWidth: 0 }}>
                      <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-1)' }}>{m.label}</div>
                      <div style={{ fontSize: 11.5, color: 'var(--text-3)', marginTop: 1 }}>{m.note}</div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          <button className="lang-btn" onClick={onToggleLang} title="Language">
            <Icon name="globe" size={17} />{t._langShort}
          </button>
          <div style={{ position: 'relative' }}>
            <button className="icon-btn" onClick={() => { setNotifOpen(v => !v); setModelOpen(false); }}>
              <Icon name="bell" size={19} />{notifs.length > 0 && <span className="ping" />}
            </button>
            {notifOpen && (
              <div className="pop" style={{ minWidth: 320 }}>
                <div className="row" style={{ justifyContent: 'space-between', padding: '6px 10px 10px' }}>
                  <span style={{ fontWeight: 600, fontSize: 13.5 }}>{t.misc.notifications}</span>
                  <button style={{ fontSize: 12, color: 'var(--primary)', fontWeight: 600 }} onClick={() => setNotifs([])}>{t.misc.markRead}</button>
                </div>
                {notifs.length === 0 && <div className="pi" style={{ color: 'var(--text-3)', fontSize: 12.5 }}>{lang==='ar'?'لا إشعارات':'No notifications'}</div>}
                {notifs.map((n, i) => {
                  const c = toneColor[n.tone] || 'var(--primary)';
                  return (
                    <div className="pi" key={n.id || i} style={{ cursor: 'pointer' }}
                      onClick={() => {
                        setNotifOpen(false);
                        // navigate to the Alerts page (the global router hook is
                        // exposed on window by the app shell).
                        if (window.__sxSetRoute) window.__sxSetRoute('alerts');
                        else window.dispatchEvent(new CustomEvent('sx-navigate', { detail: 'alerts' }));
                      }}>
                      <span style={{ width: 32, height: 32, borderRadius: 9, flexShrink: 0, display: 'grid', placeItems: 'center', color: c, background: `color-mix(in srgb, ${c} 15%, transparent)` }}>
                        <Icon name={n.ic} size={16} />
                      </span>
                      <div style={{ minWidth: 0 }}>
                        <div style={{ fontSize: 13, fontWeight: 500, color: 'var(--text-1)' }}>{n.t}</div>
                        <div style={{ fontSize: 11.5, color: 'var(--text-3)', marginTop: 1 }}>{n.s}</div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
          <button className="btn btn-primary btn-sm" style={{ marginInlineStart: 4 }}
            onClick={onPickFile} disabled={scanning} title={lang==='ar'?'ارفع أي ملف للفحص المحلي (لا يُرفع لأي خادم)':'Upload any file for local analysis (never sent to any server)'}>
            <Icon name={scanning ? 'refresh' : 'zap'} size={15} sw={2} />
            {scanning ? (lang === 'ar' ? 'يفحص…' : 'Scanning…') : t.btn.scanNow}
          </button>
          <input ref={fileRef} type="file"
            style={{ display: 'none' }} onChange={onFileChosen} />
        </div>
        {scanReport && <ScanReportModal lang={lang} report={scanReport} onClose={() => setScanReport(null)} />}
      </header>
    );
  }

  /* ---------------- SCAN REPORT MODAL (works on any page) ---------------- */
  function ScanReportModal({ lang, report, onClose }) {
    const { useEffect } = React;
    useEffect(() => {
      const onKey = e => { if (e.key === 'Escape') onClose(); };
      window.addEventListener('keydown', onKey);
      return () => window.removeEventListener('keydown', onKey);
    }, []);
    const toneColor = { danger: 'var(--critical)', warning: 'var(--warning)', success: 'var(--success)', info: 'var(--secondary)' };
    const c = toneColor[report.tone] || 'var(--primary)';
    return ReactDOM.createPortal(
      <div onClick={onClose} style={{ position: 'fixed', inset: 0, zIndex: 120, background: 'rgba(8,10,16,0.55)', backdropFilter: 'blur(4px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20 }}>
        <div onClick={e => e.stopPropagation()} className="glass glass-3" style={{ width: 'min(680px,100%)', maxHeight: '85vh', overflowY: 'auto', borderRadius: 22, padding: 26 }}>
          <div className="row" style={{ justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 14 }}>
            <div>
              <span className="sev" style={{ color: c, background: `color-mix(in srgb, ${c} 16%, transparent)` }}><span className="dot" style={{ background: c }} />{report.byModel ? (lang==='ar'?'حُلّل بالنموذج':'Model-analyzed') : (lang==='ar'?'فحص':'Scan')}</span>
              <h2 style={{ fontSize: 21, margin: '12px 0 0', letterSpacing: '-0.02em' }}>{report.title}</h2>
            </div>
            <button className="btn btn-ghost btn-sm" onClick={onClose} aria-label="close"><Icon name="x" size={16} sw={2.2} /></button>
          </div>
          <p style={{ color: 'var(--text-2)', fontSize: 14, lineHeight: 1.65, marginBottom: 18 }}>{report.summary}</p>
          {(report.sections || []).map((s, i) => (
            <div key={i} style={{ marginBottom: 16 }}>
              <h4 style={{ fontSize: 13.5, color: 'var(--text-1)', margin: '0 0 5px', fontWeight: 700 }}>{s.h}</h4>
              <p style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.6, margin: 0, whiteSpace: 'pre-wrap' }}>{s.b}</p>
            </div>
          ))}
        </div>
      </div>,
      document.body
    );
  }

  Object.assign(window, { Sidebar, TopBar });
})();
