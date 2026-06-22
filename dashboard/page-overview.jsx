/* Equilibrium Sentinel — Overview (AI Command Center)
   LIVE build: polls window.API every ~15s for real system status,
   falls back to the mockup design when the backend is offline.
   3D laptop core, parallax, count-up vitals, arc gauge, event stream
   are all preserved exactly. */
(function () {
  const { useState, useEffect, useRef } = React;
  const { Icon, PIcon, StatCard, CardHead, StatusPill, AreaChart, LaptopCore,
          CountUp, ArcGauge } = window;

  const toneColor = { danger: 'var(--critical)', info: 'var(--secondary)', success: 'var(--success)', warning: 'var(--warning)' };

  /* ---------------- HERO: AI loader orb + title + ask bar ---------------- */
  function AiLoaderHero({ t, lang, d, source, modelLive, onAsk, onAskStream }) {
    const [q, setQ] = useState('');
    const [answer, setAnswer] = useState('');
    const [busy, setBusy] = useState(false);
    const [streaming, setStreaming] = useState(false);
    const [history, setHistory] = useState([]);
    const [modelLabel, setModelLabel] = useState('Foundation-Sec 8B');

    // resolve the active model name and keep it in sync when the user switches it
    useEffect(() => {
      let alive = true;
      const refresh = () => {
        if (window.API && window.API.getModels) {
          window.API.getModels(lang).then(r => {
            if (!alive || !r) return;
            const cur = (r.models || []).find(m => m.id === r.current);
            setModelLabel((cur && cur.label) || r.current || 'Foundation-Sec 8B');
          });
        }
      };
      refresh();
      window.addEventListener('sx-model-changed', refresh);
      return () => { alive = false; window.removeEventListener('sx-model-changed', refresh); };
    }, [lang]);

    // use the REAL backend summary; never fall back to the fabricated demo text
    // (the old i18n default mentioned web-03 / OpenSSL which aren't on this machine).
    const realSummary = (d && d.summary) || '';
    const summary = realSummary;
    const verdict = (d && d.verdict) || (lang === 'ar' ? 'تحليل وضع الجهاز' : 'Machine posture');

    // the orb shows while the periodic AI summary is still being produced, or
    // while a user question is streaming. Once we have text, it gives way to it.
    const hasText = !!(answer || summary);
    const working = busy || streaming || !summary;

    const answerTimer = useRef(null);
    const submit = () => {
      const text = q.trim();
      if (!text || busy) return;
      setBusy(true); setAnswer(''); setStreaming(true); setQ('');
      if (answerTimer.current) clearTimeout(answerTimer.current);
      let acc = '';
      const onDelta = (delta) => { acc += delta; setAnswer(acc); };
      const recent = history.slice(-6);
      const stream = onAskStream
        ? onAskStream(text, onDelta, recent)
        : Promise.resolve(onAsk && onAsk(text, recent)).then(r => onDelta((r && r.answer) || ''));
      Promise.resolve(stream).finally(() => {
        setBusy(false); setStreaming(false);
        if (acc.trim()) setHistory(h => h.concat([{ role: 'user', content: text }, { role: 'assistant', content: acc }]));
        answerTimer.current = setTimeout(() => setAnswer(''), 45000);
      });
    };
    const newChat = () => { setHistory([]); setAnswer(''); setQ(''); };
    useEffect(() => () => { if (answerTimer.current) clearTimeout(answerTimer.current); }, []);

    const offline = (modelLive && modelLive.connected === false) || source === 'mock';
    const cursor = <span style={{ display: 'inline-block', width: 7, marginInlineStart: 2, color: 'var(--primary)', animation: 'sxBlink 1s steps(1) infinite' }}>▍</span>;
    const shownText = answer || summary;

    return (
      <div className="ai-hero glass glass-3" data-reveal style={{ '--d': 0 }}>
        <div className="ai-hero-row">
          {/* left: the animated AI orb */}
          <div className="ai-orb-wrap" aria-hidden="true">
            <div className="ai-orb-text"><span>A</span><span>n</span><span>a</span><span>l</span><span>y</span><span>z</span><span>i</span><span>n</span><span>g</span></div>
            <div className="ai-orb"></div>
          </div>

          {/* right: title + live summary/answer + meta */}
          <div className="ai-hero-body">
            <div className="ai-hero-eyebrow">{t.ai.badge}</div>
            <h3 className="ai-hero-title">{answer ? (lang === 'ar' ? 'إجابة المحلّل' : 'Analyst answer') : verdict}</h3>
            <p className="ai-hero-summary">
              {shownText ? <>{shownText}{(streaming || (working && !answer)) && cursor}</> : <>{(lang === 'ar' ? 'جارٍ تحليل وضع جهازك…' : 'Analyzing your machine…')}{cursor}</>}
            </p>
            <div className="ai-hero-meta">
              <span className="ai-model-dot" />
              <span className="ai-model-name">{modelLabel}</span>
              {offline
                ? <span className="src-badge offline" style={{ marginInlineStart: 'auto' }}>{lang === 'ar' ? 'النموذج غير متصل' : 'Model offline'}</span>
                : (working || streaming)
                  ? <StatusPill tone="info" live><span style={{ marginInlineStart: 'auto' }}>{lang === 'ar' ? 'يحلّل…' : 'Analyzing…'}</span></StatusPill>
                  : <StatusPill tone="success" live><span style={{ marginInlineStart: 'auto' }}>{lang === 'ar' ? 'النموذج متصل' : 'Model connected'}</span></StatusPill>}
              {history.length > 0 ? (
                <button onClick={newChat} className="btn btn-ghost btn-sm" style={{ fontSize: 11 }} title={lang === 'ar' ? 'محادثة جديدة' : 'New chat'}>
                  <Icon name="refresh" size={11} /><span className="mono">{Math.floor(history.length / 2)}</span>{lang === 'ar' ? ' جولات' : ' turns'}
                </button>
              ) : null}
            </div>
          </div>
        </div>

        {/* ask bar — full width under the hero row */}
        <div className="ask-bar ai-hero-ask">
          <Icon name="zap" size={16} style={{ color: 'var(--primary)' }} />
          <input
            placeholder={t.ai.ask}
            value={q}
            onChange={e => setQ(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') submit(); }}
            disabled={busy}
          />
          <button className="ask-send" aria-label="send" onClick={submit} disabled={busy}>
            <Icon name={busy ? 'refresh' : (lang === 'ar' ? 'chevLeft' : 'chevRight')} size={17} sw={2.2} />
          </button>
        </div>
      </div>
    );
  }

  /* ---------------- AI OVERVIEW PANEL with arc gauge ---------------- */
  function AIPanel({ t, lang, d, source, onAsk, onAskStream }) {
    const [q, setQ] = useState('');
    const [answer, setAnswer] = useState('');
    const [busy, setBusy] = useState(false);
    const [streaming, setStreaming] = useState(false);
    const [history, setHistory] = useState([]);            // conversation memory (last N turns)

    const score = (d && typeof d.score === 'number') ? d.score : 92;
    const vit = (d && d.vitals) || {};
    const verdict = (d && d.verdict) || t.ai.verdict;
    const summary = (d && d.summary) || t.ai.summary;

    // typewriter applies to the SUMMARY only (the streamed answer reveals itself
    // live, so it doesn't go through the typewriter). Re-types only on change.
    const [typed, setTyped] = useState('');
    const [typing, setTyping] = useState(false);
    const prevText = useRef('');
    useEffect(() => {
      const text = summary || '';
      if (text === prevText.current) return;
      prevText.current = text;
      if (!text) { setTyped(''); return; }
      let i = 0; const total = text.length;
      const step = Math.max(1, Math.round(total / 70));
      setTyped(''); setTyping(true);
      const id = setInterval(() => {
        i += step;
        if (i >= total) { setTyped(text); setTyping(false); clearInterval(id); }
        else setTyped(text.slice(0, i));
      }, 20);
      return () => clearInterval(id);
    }, [summary]);

    const vitals = [
      { n: t.ai.vitals.threats, v: (vit.threats != null ? vit.threats : '—'), c: 'var(--critical)' },
      { n: t.ai.vitals.uptime, v: (vit.uptime != null ? vit.uptime : '—'), c: 'var(--text-1)' },
    ];

    const answerTimer = useRef(null);
    const submit = () => {
      const text = q.trim();
      if (!text || busy) return;
      setBusy(true); setAnswer(''); setStreaming(true); setQ('');
      if (answerTimer.current) clearTimeout(answerTimer.current);
      let acc = '';
      const onDelta = (delta) => { acc += delta; setAnswer(acc); };
      // send the last 6 turns as memory so the model remembers context
      const recent = history.slice(-6);
      const stream = onAskStream
        ? onAskStream(text, onDelta, recent)
        : Promise.resolve(onAsk && onAsk(text, recent)).then(r => onDelta((r && r.answer) || ''));
      Promise.resolve(stream).finally(() => {
        setBusy(false); setStreaming(false);
        // commit the turn to memory once the answer is complete
        if (acc.trim()) setHistory(h => h.concat([{ role: 'user', content: text }, { role: 'assistant', content: acc }]));
        // after a while, hand the panel back to the live periodic summary
        answerTimer.current = setTimeout(() => setAnswer(''), 30000);
      });
    };
    const newChat = () => { setHistory([]); setAnswer(''); setQ(''); };
    useEffect(() => () => { if (answerTimer.current) clearTimeout(answerTimer.current); }, []);

    const offline = source === 'mock';
    const cursor = <span style={{ display: 'inline-block', width: 7, marginInlineStart: 2, color: 'var(--primary)', animation: 'sxBlink 1s steps(1) infinite' }}>▍</span>;

    return (
      <div className="ai-panel glass glass-2" data-reveal style={{ '--d': 1 }}>
        <div className="ai-top">
          <span className="eyebrow">{t.ai.badge}</span>
          {history.length > 0 ? (
            <button onClick={newChat} className="btn btn-ghost btn-sm"
              style={{ marginInlineStart: 8, fontSize: 11 }}
              title={lang === 'ar' ? 'محادثة جديدة' : 'New chat'}>
              <Icon name="refresh" size={11} />
              <span className="mono">{Math.floor(history.length / 2)}</span>
              {lang === 'ar' ? 'جولات' : 'turns'}
            </button>
          ) : null}
          <span className="spacer" style={{ marginInlineStart: 'auto' }} />
          {offline
            ? <span className="src-badge offline">{lang === 'ar' ? 'غير متصل' : 'OFFLINE'}</span>
            : <StatusPill tone="info" live>{t.misc.live}</StatusPill>}
        </div>
        <div className="ai-headrow">
          <div className="ai-gauge">
            <ArcGauge value={score} max={100} size={172} thickness={15} lang={lang} label={t.ai.vitals.score} />
          </div>
          <div className="ai-headtxt">
            <h3 className="ai-verdict">{verdict}</h3>
            <div className="ai-minivitals">
              {vitals.map((v, i) => (
                <div className="mv" key={i}>
                  <span className="mv-n">{v.n}</span>
                  <span className="mv-v tnum" style={{ color: v.c }}><CountUp value={v.v} lang={lang} live /></span>
                </div>
              ))}
            </div>
          </div>
        </div>
        <p className="ai-summary">{answer ? <>{answer}{streaming && cursor}</> : <>{typed}{typing && cursor}</>}</p>
        <div className="ask-bar">
          <Icon name="zap" size={16} style={{ color: 'var(--primary)' }} />
          <input
            placeholder={t.ai.ask}
            value={q}
            onChange={e => setQ(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') submit(); }}
            disabled={busy}
          />
          <button className="ask-send" aria-label="send" onClick={submit} disabled={busy}>
            <Icon name={busy ? 'refresh' : (lang === 'ar' ? 'chevLeft' : 'chevRight')} size={17} sw={2.2} />
          </button>
        </div>
      </div>
    );
  }

  /* ---------------- AI REPORTS ---------------- */
  function Reports({ t, lang, d, onGenerate, onRead }) {
    const [busy, setBusy] = useState(false);
    const list = (d && d.reports && d.reports.length) ? d.reports : t.ai.reports;

    const gen = () => {
      if (busy || !onGenerate) return;
      setBusy(true);
      Promise.resolve(onGenerate()).finally(() => setBusy(false));
    };

    return (
      <div style={{ marginBottom: 22 }}>
        <div className="page-head" data-reveal style={{ marginBottom: 16, '--d': 2 }}>
          <div className="ph-t">
            <h2 style={{ fontSize: 19 }}>{t.ai.reportsHead}</h2>
            <p>{t.ai.reportsSub}</p>
          </div>
          <div className="ph-actions">
            <button className="btn btn-ghost btn-sm" onClick={gen} disabled={busy}>
              <Icon name={busy ? 'refresh' : 'refresh'} size={14} sw={2} />
              {t.btn.viewAll}
            </button>
          </div>
        </div>
        <div className="reports-grid">
          {list.map((r, i) => {
            const c = toneColor[r.tone];
            return (
              <article className="report glass glass-2" key={i} data-reveal style={{ '--d': 3 + i, cursor: onRead ? 'pointer' : 'default' }}
                onClick={() => onRead && onRead(r)}>
                <div className="rrow">
                  <span className="sev" style={{ color: c, background: `color-mix(in srgb, ${c} 16%, transparent)` }}><span className="dot" style={{ background: c }} />{r.tag}</span>
                  <span className="muted" style={{ marginInlineStart: 'auto', fontSize: 12 }}>{r.time}</span>
                </div>
                <h4>{r.title}</h4>
                <p className="rex">{r.ex}</p>
                <div className="rfoot">
                  <span className="row gap8"><Icon name="clock" size={13} />{r.read} {t.ai.readTime}</span>
                  <span className="rmore" onClick={(e) => { e.stopPropagation(); onRead && onRead(r); }}>{t.ai.readMore}<Icon name={lang === 'ar' ? 'chevLeft' : 'chevRight'} size={14} sw={2.2} /></span>
                </div>
              </article>
            );
          })}
        </div>
      </div>
    );
  }

  /* ---------------- LIVE EVENT STREAM (real events only) ---------------- */
  function LiveStream({ t, lang, d }) {
    // REAL recent activity from the backend event log — no fabricated items.
    const [items, setItems] = useState([]);
    const mounted = useRef(true);
    useEffect(() => {
      mounted.current = true;
      const sevIcon = (sev, kind) => {
        if (kind === 'scan') return ['refresh', 'var(--primary)'];
        if (kind === 'incident') return ['alert', sev === 'critical' || sev === 'high' ? 'var(--critical)' : 'var(--warning)'];
        if (kind === 'auth') return ['lock', 'var(--warning)'];
        if (kind === 'block') return ['shield', 'var(--success)'];
        if (sev === 'critical' || sev === 'high') return ['alert', 'var(--critical)'];
        if (sev === 'medium') return ['alert', 'var(--warning)'];
        return ['activity', 'var(--sev-low)'];
      };
      const rel = (ts) => {
        const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
        if (s < 60) return lang === 'ar' ? `قبل ${s} ث` : `${s}s`;
        if (s < 3600) return lang === 'ar' ? `قبل ${Math.round(s/60)} د` : `${Math.round(s/60)}m`;
        if (s < 86400) return lang === 'ar' ? `قبل ${Math.round(s/3600)} س` : `${Math.round(s/3600)}h`;
        return lang === 'ar' ? `قبل ${Math.round(s/86400)} يوم` : `${Math.round(s/86400)}d`;
      };
      const load = () => {
        if (!(window.API && window.API.searchEvents)) return;
        window.API.searchEvents({ limit: 8 }).then(d2 => {
          if (!mounted.current || !d2 || !d2.items) return;
          setItems(d2.items.map((e) => {
            const [ic, c] = sevIcon(e.sev, e.kind);
            // stable key from the event timestamp+kind so React doesn't re-mount
            // (and flicker) every poll when the same events come back.
            return { id: e.ts + '-' + (e.cve || e.kind || ''), ic, c,
                     t1: (lang === 'ar' ? (e.text_ar || e.text_en) : (e.text_en || e.text_ar)) || e.kind,
                     t2: [e.asset, e.cve].filter(Boolean).join(' · '),
                     w: rel(e.ts) };
          }));
        });
      };
      load();
      const iv = setInterval(load, 15000);
      return () => { mounted.current = false; clearInterval(iv); };
    }, [lang]);

    return (
      <div className="card glass" data-reveal style={{ '--d': 8 }}>
        <CardHead title={t.sec.activity} icon="pulse"
          right={<StatusPill tone="info" live>{t.misc.live}</StatusPill>} />
        <div className="card-pad" style={{ paddingTop: 4 }}>
          {items.length === 0 ? (
            <div className="muted" style={{ fontSize: 12.5, padding: '14px 4px' }}>
              {lang === 'ar'
                ? 'لا نشاط مسجّل بعد — سيظهر هنا أي حدث حقيقي (فحص، حادثة، دخول، حظر).'
                : 'No recorded activity yet — real events (scans, incidents, logins, blocks) will appear here.'}
            </div>
          ) : items.map(a => (
            <div className="act" key={a.id}>
              <span className="ai" style={{ color: a.c, background: `color-mix(in srgb, ${a.c} 15%, transparent)` }}><Icon name={a.ic} size={16} /></span>
              <div className="at"><div className="t1">{a.t1}</div><div className="t2">{a.t2}</div></div>
              <span className="when">{a.w}</span>
            </div>
          ))}
        </div>
      </div>
    );
  }

  /* ---------------- LIVE METRICS SECTION ---------------- */
  function LiveSection({ t, lang, d }) {
    const cd = (d && d.cards) || {};
    const s = (d && d.series) || {};
    const cpu = cd.cpu || {}, ram = cd.ram || {}, thr = cd.threat || {}, tr = cd.traffic || {};
    const estimated = d && d.estimated;
    const dash = '—';
    // never draw a fake flat baseline — if real series data hasn't arrived yet,
    // pass an empty array so the chart shows a genuine "collecting…" state.
    const sparkOr = (arr) => (arr && arr.length ? arr : []);
    const hasNet = (s.netIn && s.netIn.length) || (s.netOut && s.netOut.length);
    const cards = [
      { icon: 'cpu', color: 'var(--primary)', label: t.cards.cpu, value: cpu.value != null ? cpu.value : dash, unit: cpu.value != null ? (cpu.unit || '%') : '', trendDir: cpu.trendDir, trendText: cpu.trendText || '', spark: sparkOr(s.cpu) },
      { icon: 'mem', color: 'var(--secondary)', label: t.cards.ram, value: ram.value != null ? ram.value : dash, unit: ram.value != null ? (ram.unit || 'GB') : '', trendDir: ram.trendDir, trendText: ram.trendText || '', spark: sparkOr(s.ram) },
      { icon: 'alert', color: 'var(--critical)', label: t.cards.threat, value: thr.value != null ? thr.value : dash, trendDir: thr.trendDir, trendText: thr.trendText || '', spark: sparkOr(s.threat) },
      { icon: 'activity', color: 'var(--sev-low)', label: t.cards.traffic, value: tr.value != null ? tr.value : dash, unit: tr.value != null ? (tr.unit || t.units.mbps) : '', trendDir: tr.trendDir, trendText: tr.trendText || '', spark: sparkOr(s.traffic) },
    ];
    const months = lang === 'ar' ? ['٠٠','٠٤','٠٨','١٢','١٦','٢٠','٢٤'] : ['00','04','08','12','16','20','24'];
    const netIn = sparkOr(s.netIn);
    const netOut = sparkOr(s.netOut);

    return (
      <div className="grid" style={{ gap: 18 }}>
        {estimated ? (
          <div className="card" style={{ padding: '10px 14px', borderColor: 'var(--warning)', background: 'color-mix(in srgb, var(--warning) 8%, transparent)' }}>
            <div className="row gap8" style={{ fontSize: 12.5, color: 'var(--warning)' }}>
              <Icon name="alert" size={15} />
              {lang === 'ar'
                ? 'بيانات CPU/RAM تقديرية — مكتبة psutil غير مثبّتة. نفّذ: pip install psutil ثم أعد التشغيل لقياسات حقيقية.'
                : 'CPU/RAM values are estimated — psutil is not installed. Run: pip install psutil and restart for real readings.'}
            </div>
          </div>
        ) : null}
        <div className="grid" style={{ gridTemplateColumns: 'repeat(4,1fr)' }}>
          {cards.map((c, i) => <StatCard key={i} {...c} lang={lang} reveal={4 + i} live={!estimated} />)}
        </div>
        <div className="grid livecharts" style={{ gridTemplateColumns: '1.5fr 1fr' }}>
          <div className="card glass" data-reveal style={{ '--d': 7 }}>
            <CardHead title={t.sec.net} icon="activity"
              right={<StatusPill tone="info" live>{t.misc.live}</StatusPill>} />
            <div className="card-pad" style={{ paddingTop: 12 }}>
              <div className="row gap16" style={{ marginBottom: 8, fontSize: 12.5 }}>
                <span className="row gap8"><span className="dot" style={{ background: 'var(--sev-low)' }} />{lang==='ar'?'وارد':'Inbound'}</span>
                <span className="row gap8"><span className="dot" style={{ background: 'var(--primary)' }} />{lang==='ar'?'صادر':'Outbound'}</span>
              </div>
              {hasNet ? (
                <AreaChart w={640} h={210} labels={months}
                  series={[{ color: 'var(--sev-low)', data: netIn }, { color: 'var(--primary)', data: netOut }]} />
              ) : (
                <div style={{ height: 210, display: 'grid', placeItems: 'center', color: 'var(--text-3)', fontSize: 13 }}>
                  <div style={{ textAlign: 'center' }}>
                    <Icon name="activity" size={24} style={{ opacity: 0.4 }} />
                    <div style={{ marginTop: 8 }}>{lang === 'ar' ? 'جارٍ جمع بيانات الشبكة الحيّة…' : 'Collecting live network data…'}</div>
                  </div>
                </div>
              )}
            </div>
          </div>
          <LiveStream t={t} lang={lang} d={d} />
        </div>
      </div>
    );
  }

  /* ---------------- ROOT: live SSE stream + report modal + actions ---------------- */
  function Overview({ t, lang }) {
    const [data, setData] = useState(null);
    const [source, setSource] = useState('unknown');
    const [modelLive, setModelLive] = useState(null);   // real Ollama liveness {connected,...}
    const [openReport, setOpenReport] = useState(null);   // report object shown in modal
    const mounted = useRef(true);

    // poll the lightweight liveness endpoint so the indicator is truthful even
    // when the user hasn't asked the model anything (e.g. they just killed Ollama).
    useEffect(() => {
      mounted.current = true;
      let timer = null;
      const ping = () => {
        if (window.API && window.API.modelPing) {
          window.API.modelPing().then(d => { if (mounted.current && d) setModelLive(d); });
        }
      };
      ping();
      timer = setInterval(ping, 15000);
      return () => { if (timer) clearInterval(timer); };
    }, []);

    useEffect(() => {
      mounted.current = true;
      if (!window.API) return;
      // instant, real-time updates over SSE (auto-falls back to polling)
      const handle = window.API.streamConnect(lang, (msg) => {
        if (!mounted.current || !msg) return;
        if (msg.type === 'tick' && msg.data) {
          setData(msg.data);
          setSource(msg.data.source || window.API.source || 'live');
        } else if (msg.type === 'surprise_report' && msg.report_id) {
          // a new real vulnerability triggered a surprise report — surface it
          window.API.getReport(msg.report_id, lang).then(r => { if (r && mounted.current) setOpenReport(r); });
        }
      });
      return () => { mounted.current = false; handle && handle.close(); };
    }, [lang]);

    const onAsk = (q, history) => window.API ? window.API.ask(q, lang, history) : Promise.resolve(null);
    const onAskStream = (q, onDelta, history) => window.API && window.API.askStream
      ? window.API.askStream(q, lang, onDelta, history)
      : Promise.resolve(onAsk(q)).then(r => onDelta((r && r.answer) || ''));
    const onGenerate = () => {
      if (!window.API) return Promise.resolve();
      return window.API.getReports(lang).then(reps => {
        if (reps && reps.length) setData(prev => Object.assign({}, prev || {}, {
          reports: reps.slice(0, 3).map(r => ({ tag: r.title, tone: r.tone, time: '', read: 3, title: r.title, ex: r.summary, id: r.id })),
        }));
      });
    };
    // "Read briefing" — open the full report in a modal
    const onReadReport = (rep) => {
      if (!window.API || !rep) return;
      if (rep.id) window.API.getReport(rep.id, lang).then(full => setOpenReport(full || rep));
      else setOpenReport(rep);
    };

    return (
      <div>
        <AiLoaderHero t={t} lang={lang} d={data} source={source} modelLive={modelLive} onAsk={onAsk} onAskStream={onAskStream} />
        <Reports t={t} lang={lang} d={data} onGenerate={onGenerate} onRead={onReadReport} />
        <LiveSection t={t} lang={lang} d={data} />
        {openReport && <ReportModal t={t} lang={lang} report={openReport} onClose={() => setOpenReport(null)} />}
      </div>
    );
  }

  /* ---------------- REPORT MODAL (Read briefing) ---------------- */
  function ReportModal({ t, lang, report, onClose }) {
    useEffect(() => {
      const onKey = e => { if (e.key === 'Escape') onClose(); };
      window.addEventListener('keydown', onKey);
      return () => window.removeEventListener('keydown', onKey);
    }, []);
    const toneColor = { danger: 'var(--critical)', warning: 'var(--warning)', success: 'var(--success)', info: 'var(--secondary)' };
    const c = toneColor[report.tone] || 'var(--primary)';
    return ReactDOM.createPortal(
      <div onClick={onClose} style={{ position: 'fixed', inset: 0, zIndex: 90, background: 'rgba(8,10,16,0.55)', backdropFilter: 'blur(4px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20, animation: 'fadeIn .2s ease' }}>
        <div onClick={e => e.stopPropagation()} className="glass glass-3" style={{ width: 'min(680px, 100%)', maxHeight: '85vh', overflowY: 'auto', borderRadius: 22, padding: 26 }}>
          <div className="row" style={{ justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 14 }}>
            <div>
              <span className="sev" style={{ color: c, background: `color-mix(in srgb, ${c} 16%, transparent)` }}><span className="dot" style={{ background: c }} />{report.score != null ? `${t.ai.vitals.score} ${report.score}/100` : (lang==='ar'?'تقرير':'Report')}</span>
              <h2 style={{ fontSize: 21, margin: '12px 0 0', letterSpacing: '-0.02em' }}>{report.title}</h2>
            </div>
            <button className="btn btn-ghost btn-sm" onClick={onClose} aria-label="close"><Icon name="x" size={16} sw={2.2} /></button>
          </div>
          <p style={{ color: 'var(--text-2)', fontSize: 14, lineHeight: 1.65, marginBottom: 18 }}>{report.summary}</p>
          {(report.sections || []).map((s, i) => (
            <div key={i} style={{ marginBottom: 16 }}>
              <h4 style={{ fontSize: 13.5, color: 'var(--text-1)', margin: '0 0 5px', fontWeight: 700 }}>{s.h}</h4>
              <p style={{ fontSize: 13, color: 'var(--text-2)', lineHeight: 1.6, margin: 0 }}>{s.b}</p>
            </div>
          ))}
        </div>
      </div>,
      document.body
    );
  }

  window.Overview = Overview;
})();
