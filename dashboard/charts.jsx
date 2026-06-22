/* Equilibrium Sentinel — lightweight SVG charts. No chart lib. */
(function () {
  const { useMemo } = React;

  // smooth catmull-rom -> cubic bezier path through points [{x,y}]
  function smooth(pts) {
    if (pts.length < 2) return '';
    let d = `M ${pts[0].x} ${pts[0].y}`;
    for (let i = 0; i < pts.length - 1; i++) {
      const p0 = pts[i - 1] || pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = pts[i + 2] || p2;
      const c1x = p1.x + (p2.x - p0.x) / 6, c1y = p1.y + (p2.y - p0.y) / 6;
      const c2x = p2.x - (p3.x - p1.x) / 6, c2y = p2.y - (p3.y - p1.y) / 6;
      d += ` C ${c1x} ${c1y}, ${c2x} ${c2y}, ${p2.x} ${p2.y}`;
    }
    return d;
  }
  function toPts(data, w, h, pad) {
    if (!Array.isArray(data) || data.length === 0) return [];
    const max = Math.max(...data) * 1.12 || 1, min = Math.min(...data, 0);
    const span = max - min || 1;
    const iw = w - pad * 2, ih = h - pad * 2;
    const denom = data.length > 1 ? data.length - 1 : 1;
    return data.map((v, i) => ({
      x: pad + (i / denom) * iw,
      y: pad + ih - ((v - min) / span) * ih,
    }));
  }

  // ---- Sparkline (mini area) ----
  function Sparkline({ data, color = 'var(--primary)', w = 120, h = 44, fill = true, sw = 2 }) {
    const id = useMemo(() => 'sp' + Math.random().toString(36).slice(2, 8), []);
    // guard: empty/short data must not crash (renders a flat baseline instead)
    const safe = Array.isArray(data) && data.length >= 2 ? data : [0, 0];
    const pts = toPts(safe, w, h, 3);
    if (!pts.length) return <svg width="100%" height={h} viewBox={`0 0 ${w} ${h}`} />;
    const line = smooth(pts);
    const area = `${line} L ${pts[pts.length-1].x} ${h} L ${pts[0].x} ${h} Z`;
    return (
      <svg width="100%" height={h} viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" style={{ display: 'block', direction: 'ltr', width: '100%' }}>
        <defs>
          <linearGradient id={id} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity="0.32" />
            <stop offset="100%" stopColor={color} stopOpacity="0" />
          </linearGradient>
        </defs>
        {fill && <path className="chart-area" d={area} fill={`url(#${id})`} />}
        <path className="chart-line" pathLength="1" d={line} fill="none" stroke={color} strokeWidth={sw} strokeLinecap="round" vectorEffect="non-scaling-stroke" />
      </svg>
    );
  }

  // ---- Area chart (multi-series, gridlines, axis labels) ----
  function AreaChart({ series, w = 600, h = 220, labels = [], yTicks = 4, pad = 28 }) {
    // guard: each series must have a usable data array (>=2 points)
    const safeSeries = (Array.isArray(series) ? series : []).map(s => ({
      ...s, data: (Array.isArray(s && s.data) && s.data.length >= 2) ? s.data : [0, 0],
    }));
    if (!safeSeries.length) return <svg width="100%" viewBox={`0 0 ${w} ${h}`} />;
    const series2 = safeSeries;
    const all = series2.flatMap(s => s.data);
    const max = Math.max(...all) * 1.12 || 1;
    const ih = h - pad - 18, iw = w - pad * 2;
    const X = i => pad + (i / (series2[0].data.length - 1)) * iw;
    const Y = v => 14 + ih - (v / max) * ih;
    const ids = series2.map((_, i) => 'ar' + i + Math.random().toString(36).slice(2, 6));
    return (
      <svg width="100%" viewBox={`0 0 ${w} ${h}`} style={{ display: 'block', direction: 'ltr' }} preserveAspectRatio="none">
        <defs>
          {series2.map((s, i) => (
            <linearGradient key={i} id={ids[i]} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={s.color} stopOpacity={s.fill === false ? 0 : 0.22} />
              <stop offset="100%" stopColor={s.color} stopOpacity="0" />
            </linearGradient>
          ))}
        </defs>
        {Array.from({ length: yTicks + 1 }).map((_, i) => {
          const y = 14 + (ih / yTicks) * i;
          return <line key={i} x1={pad} y1={y} x2={w - pad} y2={y} stroke="var(--grid-line)" strokeWidth="1" />;
        })}
        {series2.map((s, si) => {
          const pts = s.data.map((v, i) => ({ x: X(i), y: Y(v) }));
          const line = smooth(pts);
          const area = `${line} L ${pts[pts.length-1].x} ${14+ih} L ${pts[0].x} ${14+ih} Z`;
          return (
            <g key={si} style={{ '--ld': (0.25 + si * 0.18) + 's' }}>
              <path className="chart-area" d={area} fill={`url(#${ids[si]})`} />
              <path className="chart-line" pathLength="1" d={line} fill="none" stroke={s.color} strokeWidth="2.5" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
            </g>
          );
        })}
        {labels.map((l, i) => (
          <text key={i} x={X(i * ((series2[0].data.length - 1) / (labels.length - 1)))} y={h - 2}
            fill="var(--text-3)" fontSize="10.5" textAnchor="middle" fontFamily="var(--font-sans)">{l}</text>
        ))}
      </svg>
    );
  }

  // ---- Bars ----
  function Bars({ data, color = 'var(--secondary)', w = 600, h = 180, labels = [], pad = 28, radius = 4 }) {
    const safe = Array.isArray(data) && data.length ? data : [0];
    const max = Math.max(...safe) * 1.15 || 1;
    const ih = h - pad - 16, iw = w - pad * 2;
    const bw = (iw / safe.length) * 0.56;
    const gap = (iw / safe.length);
    return (
      <svg width="100%" viewBox={`0 0 ${w} ${h}`} style={{ display: 'block', direction: 'ltr' }} preserveAspectRatio="none">
        {[0,1,2,3].map(i => { const y = 14 + (ih/3)*i; return <line key={i} x1={pad} y1={y} x2={w-pad} y2={y} stroke="var(--grid-line)" />; })}
        {safe.map((v, i) => {
          const bh = (v / max) * ih;
          const x = pad + gap * i + (gap - bw) / 2;
          const y = 14 + ih - bh;
          return <rect key={i} x={x} y={y} width={bw} height={Math.max(bh, 2)} rx={radius} fill={color} opacity={0.55 + 0.45 * (v / max)} />;
        })}
        {labels.map((l, i) => (
          <text key={i} x={pad + gap * i + gap / 2} y={h - 1} fill="var(--text-3)" fontSize="10.5" textAnchor="middle">{l}</text>
        ))}
      </svg>
    );
  }

  // ---- Stacked severity bars (timeline) ----
  function StackedBars({ rows, w = 600, h = 180, labels = [], pad = 28 }) {
    // rows: array of { values:[{v,color}] }
    const safe = (Array.isArray(rows) ? rows : []).filter(r => r && Array.isArray(r.values));
    if (!safe.length) return <svg width="100%" viewBox={`0 0 ${w} ${h}`} />;
    const totals = safe.map(r => r.values.reduce((a, b) => a + b.v, 0));
    const max = Math.max(...totals) * 1.15 || 1;
    const ih = h - pad - 16, iw = w - pad * 2;
    const gap = iw / safe.length, bw = gap * 0.5;
    return (
      <svg width="100%" viewBox={`0 0 ${w} ${h}`} style={{ display: 'block', direction: 'ltr' }} preserveAspectRatio="none">
        {[0,1,2,3].map(i => { const y = 14 + (ih/3)*i; return <line key={i} x1={pad} y1={y} x2={w-pad} y2={y} stroke="var(--grid-line)" />; })}
        {safe.map((r, i) => {
          const x = pad + gap * i + (gap - bw) / 2;
          let acc = 0;
          return r.values.map((seg, si) => {
            const segh = (seg.v / max) * ih;
            const y = 14 + ih - acc - segh;
            acc += segh;
            const isTop = si === r.values.length - 1;
            return <rect key={si} x={x} y={y} width={bw} height={Math.max(segh,0)} rx={isTop ? 3 : 0} fill={seg.color} />;
          });
        })}
        {labels.map((l, i) => (
          <text key={i} x={pad + gap * i + gap / 2} y={h - 1} fill="var(--text-3)" fontSize="10.5" textAnchor="middle">{l}</text>
        ))}
      </svg>
    );
  }

  // ---- Donut ----
  function Donut({ segments, size = 120, thickness = 14, gap = 0.02 }) {
    const segs = (segments || []).filter(s => s && s.value > 0);
    const total = segs.reduce((a, s) => a + s.value, 0) || 1;
    const r = (size - thickness) / 2, cx = size / 2, cy = size / 2, C = 2 * Math.PI * r;
    // with only one non-zero segment, drop the gap so it forms a clean ring
    const g = segs.length > 1 ? gap : 0;
    let off = 0;
    return (
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ display: 'block', transform: 'rotate(-90deg)' }}>
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="var(--bg-inset)" strokeWidth={thickness} />
        {segs.map((s, i) => {
          const frac = s.value / total;
          const len = Math.max(C * frac - (C * g), C * 0.01);
          const el = <circle key={i} cx={cx} cy={cy} r={r} fill="none" stroke={s.color} strokeWidth={thickness}
            strokeDasharray={`${len} ${C}`} strokeDashoffset={-off} strokeLinecap="round" />;
          off += C * frac;
          return el;
        })}
      </svg>
    );
  }

  // ---- Score ring (single value 0-100) ----
  function ScoreRing({ value, size = 116, thickness = 10, color = 'var(--primary)', label }) {
    const r = (size - thickness) / 2, cx = size / 2, C = 2 * Math.PI * r;
    const len = (value / 100) * C;
    return (
      <div style={{ position: 'relative', width: size, height: size, flexShrink: 0 }}>
        <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
          <circle cx={cx} cy={cx} r={r} fill="none" stroke="var(--bg-inset)" strokeWidth={thickness} />
          <circle cx={cx} cy={cx} r={r} fill="none" stroke={color} strokeWidth={thickness}
            strokeDasharray={`${len} ${C}`} strokeLinecap="round"
            style={{ transition: 'stroke-dasharray .9s var(--ease-out)' }} />
        </svg>
        <div style={{ position: 'absolute', inset: 0, display: 'grid', placeItems: 'center', textAlign: 'center' }}>
          <div>
            <div className="tnum" style={{ fontSize: size * 0.26, fontWeight: 700, lineHeight: 1, letterSpacing: '-0.02em' }}>{value}</div>
            {label && <div style={{ fontSize: 11, color: 'var(--text-3)', marginTop: 3 }}>{label}</div>}
          </div>
        </div>
      </div>
    );
  }

  Object.assign(window, { Sparkline, AreaChart, Bars, StackedBars, Donut, ScoreRing });
})();
