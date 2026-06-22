/* Equilibrium Sentinel — Laptop Core
   A large 3D laptop that boots on load: the lid swings open, then the
   screen powers on showing a live "system" readout. The open + power-on
   sequence is driven by requestAnimationFrame (robust), the on-screen
   telemetry animates via CSS. Replaces the neural/brain centerpiece. */
(function () {
  const { useRef, useEffect } = React;

  function LaptopCore() {
    const lid = useRef(null);
    const screen = useRef(null);
    const glow = useRef(null);

    useEffect(() => {
      const L = lid.current, S = screen.current, G = glow.current;
      if (!L) return;
      const reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
      const OPEN = -3, CLOSED = 90;            // lid angles (deg)
      if (reduce) {
        L.style.transform = `rotateX(${OPEN}deg)`;
        if (S) S.style.opacity = 1;
        return;
      }
      let raf, start;
      const ease = p => 1 - Math.pow(1 - p, 3);
      const DUR = 1600;
      // start closed
      L.style.transform = `rotateX(${CLOSED}deg)`;
      if (S) S.style.opacity = 0;
      const tick = now => {
        if (!start) start = now + 250;          // brief beat before opening
        const p = Math.max(0, Math.min(1, (now - start) / DUR));
        const e = ease(p);
        L.style.transform = `rotateX(${CLOSED + (OPEN - CLOSED) * e}deg)`;
        const pw = Math.max(0, (e - 0.55) / 0.45);   // power on once mostly open
        if (S) S.style.opacity = pw.toFixed(3);
        if (G) G.style.opacity = (pw * 0.9).toFixed(3);
        if (p < 1) raf = requestAnimationFrame(tick);
      };
      raf = requestAnimationFrame(tick);
      return () => cancelAnimationFrame(raf);
    }, []);

    const keys = [];
    for (let r = 0; r < 4; r++) {
      const row = [];
      const n = r === 3 ? 1 : 14;
      for (let i = 0; i < n; i++) row.push(React.createElement('span', { key: i, className: r === 3 ? 'lp-space' : '' }));
      keys.push(React.createElement('div', { className: 'lp-krow', key: r }, row));
    }

    return (
      <div className="laptop-scene">
        <div className="laptop">
          <div className="lp-lid" ref={lid}>
            <div className="lp-screen" ref={screen}>
              <div className="lp-os">
                <div className="lp-os-bar">
                  <span className="lp-tl r" /><span className="lp-tl y" /><span className="lp-tl g" />
                  <b>SENTINEL&nbsp;OS</b>
                  <em className="lp-os-live"><i />ONLINE</em>
                </div>
                <div className="lp-os-body">
                  <div className="lp-os-graph">
                    <svg viewBox="0 0 200 84" preserveAspectRatio="none">
                      <defs>
                        <linearGradient id="lpfill" x1="0" y1="0" x2="0" y2="1">
                          <stop offset="0%" stopColor="var(--primary)" stopOpacity="0.45" />
                          <stop offset="100%" stopColor="var(--primary)" stopOpacity="0" />
                        </linearGradient>
                      </defs>
                      <path d="M0 60 L20 52 L40 56 L60 40 L80 46 L100 30 L120 36 L140 22 L160 30 L180 16 L200 24 L200 84 L0 84 Z" fill="url(#lpfill)" />
                      <path className="lp-line" d="M0 60 L20 52 L40 56 L60 40 L80 46 L100 30 L120 36 L140 22 L160 30 L180 16 L200 24" fill="none" stroke="var(--primary)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                    </svg>
                  </div>
                  <div className="lp-os-side">
                    <div className="lp-eq"><i /><i /><i /><i /><i /></div>
                    <div className="lp-os-readout"><b>99.98%</b><span>UPTIME</span></div>
                  </div>
                </div>
                <div className="lp-os-foot">
                  <span className="lp-chip">CPU 38%</span>
                  <span className="lp-chip">NET 248</span>
                  <span className="lp-chip ok">SECURE</span>
                </div>
              </div>
              <div className="lp-scan" />
              <div className="lp-reflect" />
              <div className="lp-cam" />
            </div>
          </div>
          <div className="lp-base">
            <div className="lp-keyboard">{keys}</div>
            <div className="lp-trackpad" />
            <div className="lp-notch" />
          </div>
          <div className="lp-glow" ref={glow} />
          <div className="lp-shadow" />
        </div>
      </div>
    );
  }

  window.LaptopCore = LaptopCore;
})();
