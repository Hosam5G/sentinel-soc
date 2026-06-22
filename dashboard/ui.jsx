/* Equilibrium Sentinel — shared UI atoms */
(function () {
  const { Icon } = window;
  const { useState, useEffect, useRef } = React;

  const SEV_COLORS = {
    critical: 'var(--sev-critical)', high: 'var(--sev-high)',
    medium: 'var(--sev-medium)', low: 'var(--sev-low)', info: 'var(--sev-info)',
  };

  function SevPill({ level, label }) {
    const c = SEV_COLORS[level] || 'var(--text-3)';
    return (
      <span className="sev" style={{ color: c, background: `color-mix(in srgb, ${c} 16%, transparent)` }}>
        <span className="dot" style={{ background: c }} />{label}
      </span>
    );
  }

  function StatusPill({ tone = 'success', children, live }) {
    const map = { success: 'var(--success)', warning: 'var(--warning)', danger: 'var(--danger)', info: 'var(--primary)' };
    const c = map[tone];
    return (
      <span className="pill" style={{ color: c, background: `color-mix(in srgb, ${c} 14%, transparent)` }}>
        <span className={'dot' + (live ? ' live' : '')} style={{ background: c }} />{children}
      </span>
    );
  }

  function Trend({ dir, children }) {
    const ic = dir === 'up' ? 'trendUp' : dir === 'down' ? 'trendDown' : 'activity';
    return <span className={'trend ' + dir}><Icon name={ic} size={13} sw={2} />{children}</span>;
  }

  // StatCard: { icon, color, label, value, unit, trendDir, trendText, foot, spark }
  // Premium: monochrome glyph tile on top, label as the title, big number below.
  function StatCard({ icon, color = 'var(--primary)', label, value, unit, trendDir, trendText, foot, spark, lang, reveal, live }) {
    const { Sparkline, CountUp, PIcon } = window;
    const extra = reveal != null ? { 'data-reveal': '', style: { '--d': reveal } } : {};
    return (
      <div className="card stat" {...extra}>
        <div className="top">
          {icon && PIcon && <span className="pico"><PIcon name={icon} size={24} /></span>}
          {trendDir && <span style={{ marginInlineStart: 'auto', fontSize: 12 }}><Trend dir={trendDir}>{trendText}</Trend></span>}
        </div>
        <span className="label">{label}</span>
        <div className="value tnum">{CountUp ? <CountUp value={value} lang={lang} live={live} /> : value}{unit && <span className="unit">{unit}</span>}</div>
        {foot && <div className="foot">{foot}</div>}
        {spark && <div className="spark"><Sparkline data={spark} color={color} w={150} h={54} sw={2.4} /></div>}
      </div>
    );
  }

  function CardHead({ title, sub, right, icon, iconColor }) {
    const { PIcon } = window;
    return (
      <div className="card-head">
        {icon && (PIcon
          ? <span className="pico sm"><PIcon name={icon} size={20} /></span>
          : <span style={{ color: iconColor || 'var(--text-2)' }}><Icon name={icon} size={18} /></span>)}
        <div>
          <h3>{title}</h3>
          {sub && <div className="sub">{sub}</div>}
        </div>
        {right && <div className="spacer" />}
        {right}
      </div>
    );
  }

  function Bar({ value, color = 'var(--primary)', track }) {
    return <div className="bar" style={track ? { background: track } : null}><i style={{ width: Math.min(value,100) + '%', background: color }} /></div>;
  }

  /* ---- "Last updated" relative timestamp (re-renders each minute) ---- */
  function LastUpdated({ ts, lang }) {
    const [, force] = useState(0);
    useEffect(() => { const id = setInterval(() => force(n => n + 1), 30000); return () => clearInterval(id); }, []);
    if (!ts) return null;
    const sec = Math.max(0, Math.round((Date.now() - ts) / 1000));
    let txt;
    if (sec < 10)      txt = lang === 'ar' ? 'الآن' : 'just now';
    else if (sec < 60) txt = lang === 'ar' ? `قبل ${sec} ث` : `${sec}s ago`;
    else if (sec < 3600) {
      const m = Math.round(sec / 60);
      txt = lang === 'ar' ? `قبل ${m} د` : `${m}m ago`;
    } else {
      const h = Math.round(sec / 3600);
      txt = lang === 'ar' ? `قبل ${h} س` : `${h}h ago`;
    }
    return <span className="muted tnum" style={{ fontSize: 11 }} title={new Date(ts).toLocaleString(lang === 'ar' ? 'ar' : 'en')}>{lang === 'ar' ? '🕒 آخر تحديث ' : '🕒 updated '}{txt}</span>;
  }

  /* ---- Inline table-search input (filters rows client-side) ---- */
  function TableSearch({ value, onChange, placeholder, lang }) {
    const ref = useRef(null);
    // press "/" anywhere to focus the nearest table search
    useEffect(() => {
      const onKey = (e) => {
        if (e.key === '/' && !e.ctrlKey && !e.metaKey && !e.altKey) {
          const tag = (document.activeElement && document.activeElement.tagName) || '';
          if (tag === 'INPUT' || tag === 'TEXTAREA') return;
          if (ref.current) { e.preventDefault(); ref.current.focus(); }
        }
      };
      window.addEventListener('keydown', onKey);
      return () => window.removeEventListener('keydown', onKey);
    }, []);
    return (
      <label className="tb-search" style={{ margin: 0, minWidth: 220 }}>
        <Icon name="search" size={14} />
        <input ref={ref} type="text" value={value} onChange={e => onChange(e.target.value)}
          placeholder={placeholder || (lang === 'ar' ? 'ابحث… ( / )' : 'Search… ( / )')} />
        {value ? <button onClick={() => onChange('')} style={{ background: 'transparent', border: 0, color: 'var(--text-3)', cursor: 'pointer', padding: 0 }}><Icon name="x" size={12} /></button> : null}
      </label>
    );
  }

  Object.assign(window, { SevPill, StatusPill, Trend, StatCard, CardHead, Bar, SEV_COLORS, LastUpdated, TableSearch });
})();
