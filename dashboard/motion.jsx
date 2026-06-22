/* Equilibrium Sentinel — Motion primitives
   Cinematic, Apple-grade micro-motion: count-up numbers, chart draw-in,
   arc gauges that fill, and a reveal orchestrator tied to the boot event.
   Everything waits for `sx-booted` so motion lands AFTER the boot reveal. */
(function () {
  const { useState, useEffect, useRef, useMemo } = React;

  // run a callback once the app has booted (or immediately if already booted)
  function onBoot(cb) {
    if (document.body.classList.contains('booted')) { cb(); return () => {}; }
    const h = () => cb();
    window.addEventListener('sx-booted', h, { once: true });
    return () => window.removeEventListener('sx-booted', h);
  }
  const easeOutCubic = p => 1 - Math.pow(1 - p, 3);
  const reduced = () => window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const AR = ['٠','١','٢','٣','٤','٥','٦','٧','٨','٩'];
  const toArab = s => s.replace(/[0-9]/g, d => AR[+d]);

  // ---- CountUp: animates the numeric part of a display string ----
  function CountUp({ value, dur = 1500, delay = 0, lang, live = false }) {
    const str = String(value);
    const m = str.match(/^([^\d-]*)(-?[\d,]*\.?\d+)(.*)$/);
    const prefix = m ? m[1] : '';
    const numStr = m ? m[2].replace(/,/g, '') : '0';
    const suffix = m ? m[3] : '';
    const target = m ? parseFloat(numStr) : 0;
    const decimals = numStr.includes('.') ? numStr.split('.')[1].length : 0;
    const grouped = m && m[2].includes(',');
    const [n, setN] = useState(live ? target : 0);

    useEffect(() => {
      // live numbers (updated every second) snap straight to the value —
      // no count-from-zero animation, so the current value is always readable.
      if (live || !m || reduced()) { setN(target); return; }
      let raf, startT;
      const off = onBoot(() => {
        const begin = () => {
          startT = performance.now();
          const tick = now => {
            const p = Math.min(1, (now - startT) / dur);
            setN(target * easeOutCubic(p));
            if (p < 1) raf = requestAnimationFrame(tick);
          };
          raf = requestAnimationFrame(tick);
        };
        delay ? setTimeout(begin, delay) : begin();
      });
      return () => { off(); cancelAnimationFrame(raf); };
    }, [value]);

    if (!m) return React.createElement('span', { className: 'tnum' }, lang === 'ar' ? toArab(str) : str);
    let disp = n.toFixed(decimals);
    if (grouped) {
      const [a, b] = disp.split('.');
      disp = (+a).toLocaleString('en-US') + (b ? '.' + b : '');
    }
    if (lang === 'ar') disp = toArab(disp);
    let pre = prefix, suf = suffix;
    if (lang === 'ar') { pre = toArab(pre); suf = toArab(suf); }
    return React.createElement('span', { className: 'tnum' }, pre + disp + suf);
  }

  // ---- ArcGauge: half-ring gauge that fills on boot (UV-index style) ----
  function ArcGauge({ value, max = 100, size = 150, thickness = 13, color = 'var(--primary)', label, sub, lang }) {
    const [p, setP] = useState(0);                 // 0..1 progress of fill
    const r = (size - thickness) / 2;
    const cx = size / 2, cy = size / 2;
    const START = Math.PI * 0.75, SWEEP = Math.PI * 1.5; // 270° arc, bottom gap
    const ptOn = a => [cx + r * Math.cos(a), cy + r * Math.sin(a)];
    const frac = Math.min(1, value / max);
    const arc = (a0, a1) => {
      const [x0, y0] = ptOn(a0), [x1, y1] = ptOn(a1);
      const large = (a1 - a0) > Math.PI ? 1 : 0;
      return `M ${x0} ${y0} A ${r} ${r} 0 ${large} 1 ${x1} ${y1}`;
    };
    useEffect(() => {
      if (reduced()) { setP(frac); return; }
      let raf, st;
      const off = onBoot(() => {
        st = performance.now();
        const tick = now => {
          const t = Math.min(1, (now - st) / 1400);
          setP(frac * easeOutCubic(t));
          if (t < 1) raf = requestAnimationFrame(tick);
        };
        raf = requestAnimationFrame(tick);
      });
      return () => { off(); cancelAnimationFrame(raf); };
    }, [value, max]);

    const cur = (value * (p / (frac || 1)));
    const shown = lang === 'ar' ? toArab(cur.toFixed(cur < 10 ? 2 : 0)) : cur.toFixed(cur < 10 ? 2 : 0);
    return React.createElement('div', { style: { position: 'relative', width: size, height: size } },
      React.createElement('svg', { width: size, height: size, viewBox: `0 0 ${size} ${size}` },
        React.createElement('defs', null,
          React.createElement('linearGradient', { id: 'agk', x1: '0', y1: '0', x2: '1', y2: '1' },
            React.createElement('stop', { offset: '0%', stopColor: 'var(--secondary)' }),
            React.createElement('stop', { offset: '100%', stopColor: color }))),
        React.createElement('path', { d: arc(START, START + SWEEP), fill: 'none', stroke: 'var(--bg-inset-2)', strokeWidth: thickness, strokeLinecap: 'round' }),
        p > 0.001 && React.createElement('path', { d: arc(START, START + SWEEP * p), fill: 'none', stroke: 'url(#agk)', strokeWidth: thickness, strokeLinecap: 'round', style: { filter: 'drop-shadow(0 0 6px ' + 'var(--primary-glow)' + ')' } })),
      React.createElement('div', { style: { position: 'absolute', inset: 0, display: 'grid', placeItems: 'center', textAlign: 'center' } },
        React.createElement('div', null,
          React.createElement('div', { className: 'tnum', style: { fontSize: size * 0.24, fontWeight: 600, lineHeight: 1, letterSpacing: '-0.02em' } }, shown),
          label && React.createElement('div', { style: { fontSize: 11, color: 'var(--text-3)', marginTop: 4 } }, label))));
  }

  Object.assign(window, { CountUp, ArcGauge, onBoot });
})();
