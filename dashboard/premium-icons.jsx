/* Equilibrium Sentinel — Premium glyph set (SF-Symbols-flavored).
   Filled + duotone geometry, distinct from the thin line set. window.PIcon. */
(function () {
  // Each glyph is raw inner SVG. Default svg fill = currentColor; elements that
  // need a stroke (waveforms, node links, the shield check) set it explicitly.
  const G = {
    // processor — duotone chip body + solid core + pins
    cpu:
      '<rect x="6" y="6" width="12" height="12" rx="3.2" opacity=".48"/>' +
      '<rect x="9.3" y="9.3" width="5.4" height="5.4" rx="1.7"/>' +
      '<rect x="8.6" y="2.6" width="1.6" height="2.8" rx=".8"/><rect x="13.8" y="2.6" width="1.6" height="2.8" rx=".8"/>' +
      '<rect x="8.6" y="18.6" width="1.6" height="2.8" rx=".8"/><rect x="13.8" y="18.6" width="1.6" height="2.8" rx=".8"/>' +
      '<rect x="2.6" y="8.6" width="2.8" height="1.6" rx=".8"/><rect x="2.6" y="13.8" width="2.8" height="1.6" rx=".8"/>' +
      '<rect x="18.6" y="8.6" width="2.8" height="1.6" rx=".8"/><rect x="18.6" y="13.8" width="2.8" height="1.6" rx=".8"/>',
    // memory module — duotone body + solid cells + legs
    mem:
      '<rect x="2.5" y="6.5" width="19" height="10.5" rx="2.4" opacity=".48"/>' +
      '<rect x="6.4" y="9.6" width="1.9" height="4.3" rx=".95"/><rect x="11.05" y="9.6" width="1.9" height="4.3" rx=".95"/><rect x="15.7" y="9.6" width="1.9" height="4.3" rx=".95"/>' +
      '<rect x="5.6" y="17" width="2.4" height="2.7" rx=".7"/><rect x="16" y="17" width="2.4" height="2.7" rx=".7"/>',
    // threat — duotone flame (faint body + solid inner flame)
    flame:
      '<path opacity=".5" d="M12 2.4c2.3 3.1 4.6 5.4 4.6 8.9A4.6 4.6 0 0 1 7.4 11c0-1 .3-1.8.7-2.5C7 10 6 12 6 14.4 6 18.3 8.7 21.6 12 21.6s6-3.3 6-7.2C18 9.4 14.4 6.6 12 2.4Z"/>' +
      '<path d="M12 21.6a3.3 3.3 0 0 0 3.3-3.3c0-1.7-1.4-2.9-2.1-3.8-.6 1.5-2.5 1.9-2.5 3.8A3.3 3.3 0 0 0 12 21.6Z"/>',
    // threat / alert — duotone triangle (faint body + solid mark)
    alert:
      '<path opacity=".5" d="M10.27 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.73 3.86a2 2 0 0 0-3.46 0Z"/>' +
      '<path d="M12 9.2v4.4" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round"/>' +
      '<circle cx="12" cy="16.9" r="1.25"/>',
    // shield — duotone body + crisp check
    shield:
      '<path opacity=".5" d="M12 2.5 5 5.3V11c0 4.6 3 8.2 7 10 4-1.8 7-5.4 7-10V5.3L12 2.5Z"/>' +
      '<path d="M8.7 11.7 11 14l4.4-4.7" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>',
    // network — duotone links + solid nodes
    network:
      '<path opacity=".62" d="M12 6.6v3.9M12 10.5 6.4 16.4M12 10.5 17.6 16.4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>' +
      '<circle cx="12" cy="5" r="2.7"/><circle cx="5.4" cy="18.2" r="2.7"/><circle cx="18.6" cy="18.2" r="2.7"/>',
    // activity / traffic — bold waveform with a faint baseline
    activity:
      '<path opacity=".5" d="M3 16.5h18" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>' +
      '<path d="M3 12.2h3.4l2.1-6.1 4 13.2 2.3-7.1H21" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round"/>',
    // pulse — same family, used for the live feed
    pulse:
      '<path d="M3 12h3.6l1.9-5.4 4 13 2.2-7.6H21" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round"/>',
    // gauge / score — duotone dial + needle
    gauge:
      '<path opacity=".5" d="M4 18a9 9 0 1 1 16 0Z"/>' +
      '<path d="M12 17 16 10.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>' +
      '<circle cx="12" cy="17" r="1.9"/>',
  };

  window.PIcon = function PIcon({ name, size = 20, className = '', style = {} }) {
    const d = G[name];
    if (!d) return window.Icon ? window.Icon({ name, size, className, style }) : null;
    return React.createElement('svg', {
      width: size, height: size, viewBox: '0 0 24 24', fill: 'currentColor',
      className, style, dangerouslySetInnerHTML: { __html: d },
    });
  };
})();
