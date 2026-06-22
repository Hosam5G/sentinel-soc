/* Equilibrium Sentinel — System, Network, Reports, + simple pages */
(function () {
  const R = React;
  const { Icon, PIcon, CardHead, StatCard, SevPill, StatusPill, Bar, ScoreRing, Donut,
          AreaChart, Bars, PageHead } = window;

  /* ---------------- SYSTEM ---------------- */
  function System({ t, lang }) {
    const { useState, useEffect, useRef } = React;
    const [m, setM] = useState(null);
    const mounted = useRef(true);
    useEffect(() => {
      mounted.current = true;
      const load = () => window.API && window.API.getSystemMetrics &&
        window.API.getSystemMetrics().then(d => { if (mounted.current && d) setM(d); });
      load();
      const iv = setInterval(load, 3000);
      return () => { mounted.current = false; clearInterval(iv); };
    }, []);

    const cpu = m ? m.cpu : { pct: 0, cores: '—' };
    const ram = m ? m.ram : { pct: 0, used_gb: 0, total_gb: 0 };
    const disks = m ? m.disks : [];
    const disk0 = disks[0] || { pct: 0, used_gb: 0, total_gb: 0, mount: '—' };
    const procs = m ? m.processes : [];
    const gauges = [
      { l: t.cards.cpu, v: cpu.pct, c: 'var(--primary)', sub: cpu.cores + ' ' + t.units.cores },
      { l: t.cards.ram, v: ram.pct, c: 'var(--secondary)', sub: ram.used_gb + ' / ' + ram.total_gb + ' GB' },
      { l: t.cards.disk, v: disk0.pct, c: 'var(--warning)', sub: disk0.used_gb + ' / ' + disk0.total_gb + ' GB' },
    ];

    return (
      <div>
        <PageHead t={t} lang={lang} title={t.nav.system} sub={t.pageSub.system}
          actions={<span className="row gap16" style={{fontSize:12.5}}>
            <span className="muted">{lang==='ar'?'زمن التشغيل':'Uptime'}: <b style={{color:'var(--text-1)'}}>{m?m.uptime:'—'}</b></span>
            <span className="muted">{lang==='ar'?'متصلون':'Online'}: <b style={{color:'var(--text-1)'}}>{m?m.online_users:0}</b></span>
          </span>} />
        <div className="grid" style={{ gridTemplateColumns: 'repeat(3,1fr)', gap: 16, marginBottom: 20 }}>
          {gauges.map((g, i) => (
            <div className="card card-pad row" key={i} style={{ gap: 18 }}>
              <ScoreRing value={Math.round(g.v)} size={104} thickness={10} color={g.c} label="%" />
              <div>
                <div style={{ fontSize: 15, fontWeight: 600 }}>{g.l}</div>
                <div className="muted" style={{ fontSize: 12.5, marginTop: 5 }}>{g.sub}</div>
                <div style={{ marginTop: 12 }}><StatusPill tone="success" live>{t.misc.live}</StatusPill></div>
              </div>
            </div>
          ))}
        </div>
        <div className="grid" style={{ gridTemplateColumns: '1.5fr 1fr', gap: 20 }}>
          <div className="card">
            <CardHead title={t.cards.procs} icon="cpu" iconColor="var(--secondary)"
              right={<span className="muted" style={{fontSize:12.5}}>{lang==='ar'?'الأعلى استهلاكاً للذاكرة':'Top by memory'}</span>} />
            <table className="tbl">
              <thead><tr><th>{lang==='ar'?'العملية':'Process'}</th><th>CPU %</th><th>{lang==='ar'?'الذاكرة':'Mem'} MB</th><th>PID</th></tr></thead>
              <tbody>
                {procs.length === 0 ? <tr><td colSpan={4} className="muted" style={{padding:14}}>{!m ? (lang==='ar'?'جارٍ القراءة…':'Reading…') : (lang==='ar'?'لا بيانات':'No data')}</td></tr> :
                procs.map((p, i) => (
                  <tr key={i}>
                    <td className="mono" style={{ color: 'var(--text-1)' }}>{p.name}</td>
                    <td><div className="row gap8"><span className="tnum" style={{minWidth:38}}>{p.cpu}</span><div style={{flex:1,minWidth:60}}><Bar value={Math.min(100,p.cpu)} color="var(--primary)" /></div></div></td>
                    <td className="tnum">{p.mem}</td>
                    <td className="mono muted">{p.pid}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="card">
            <CardHead title={lang==='ar'?'الأقراص':'Disks'} icon="server" iconColor="var(--primary)" />
            <div className="card-pad" style={{ paddingTop: 6 }}>
              {disks.length === 0 ? <div className="muted" style={{fontSize:12.5}}>{!m ? (lang==='ar'?'جارٍ القراءة…':'Reading…') : (lang==='ar'?'لا بيانات (قد تتطلب صلاحيات)':'No data (may need permissions)')}</div> :
              disks.map((d, i) => (
                <div key={i} style={{ padding: '10px 0', borderBottom: i<disks.length-1?'1px solid var(--hairline)':'none' }}>
                  <div className="row" style={{ justifyContent: 'space-between', marginBottom: 6 }}>
                    <span className="mono" style={{color:'var(--text-1)'}}>{d.mount}</span>
                    <span className="muted" style={{fontSize:12}}>{d.used_gb} / {d.total_gb} GB</span>
                  </div>
                  <Bar value={d.pct} color={d.pct>85?'var(--critical)':d.pct>70?'var(--warning)':'var(--primary)'} />
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ---- extended hardware monitoring (renders only what's available) ---- */}
        {m && ((m.gpu && m.gpu.length) || (m.io && m.io.length) || m.battery || (m.temps && m.temps.length) || (m.disk_health && m.disk_health.length) || m.services) ? (
          <div className="grid" style={{ gridTemplateColumns: '1fr 1fr', gap: 20, marginTop: 20 }}>

            {m.gpu && m.gpu.length ? (
              <div className="card">
                <CardHead title={lang==='ar'?'كرت الرسوميات (GPU)':'Graphics (GPU)'} icon="cpu" iconColor="var(--secondary)" />
                <div className="card-pad" style={{ paddingTop: 6 }}>
                  {m.gpu.map((g, i) => (
                    <div key={i} style={{ padding:'8px 0', borderBottom: i<m.gpu.length-1?'1px solid var(--hairline)':'none' }}>
                      <div className="row" style={{ justifyContent:'space-between', marginBottom:6 }}>
                        <span style={{ color:'var(--text-1)', fontSize:13 }}>{g.name}</span>
                        <span className="muted" style={{ fontSize:12 }}>{Math.round(g.temp)}°C · {Math.round(g.mem_used)}/{Math.round(g.mem_total)} MB</span>
                      </div>
                      <Bar value={g.util} color={g.util>85?'var(--critical)':'var(--secondary)'} />
                      <div className="muted" style={{ fontSize:11, marginTop:3 }}>{lang==='ar'?'الاستخدام':'Utilization'} {Math.round(g.util)}%</div>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}

            {m.io && m.io.length ? (
              <div className="card">
                <CardHead title={lang==='ar'?'معدّل قراءة/كتابة الأقراص':'Disk I/O rate'} icon="activity" iconColor="var(--primary)"
                  right={<span className="muted" style={{fontSize:11.5}}>MB/s</span>} />
                <div className="card-pad" style={{ paddingTop: 6 }}>
                  {m.io.slice(0,5).map((d, i) => (
                    <div key={i} className="row" style={{ justifyContent:'space-between', padding:'7px 0', borderBottom: i<Math.min(5,m.io.length)-1?'1px solid var(--hairline)':'none' }}>
                      <span className="mono" style={{ color:'var(--text-1)', fontSize:12.5 }}>{d.disk}</span>
                      <span className="row gap12" style={{ fontSize:12 }}>
                        <span style={{ color:'var(--sev-low)' }}>↓ {d.read.toFixed(1)}</span>
                        <span style={{ color:'var(--warning)' }}>↑ {d.write.toFixed(1)}</span>
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}

            {m.temps && m.temps.length ? (
              <div className="card">
                <CardHead title={lang==='ar'?'الحرارة':'Temperatures'} icon="zap" iconColor="var(--warning)" />
                <div className="card-pad" style={{ paddingTop: 6 }}>
                  {m.temps.map((tp, i) => (
                    <div key={i} className="row" style={{ justifyContent:'space-between', padding:'7px 0', borderBottom: i<m.temps.length-1?'1px solid var(--hairline)':'none' }}>
                      <span style={{ color:'var(--text-1)', fontSize:12.5 }}>{tp.label}</span>
                      <span style={{ fontSize:13, fontWeight:600, color: tp.c>=80?'var(--critical)':tp.c>=65?'var(--warning)':'var(--text-1)' }}>{tp.c}°C</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}

            {m.disk_health && m.disk_health.length ? (
              <div className="card">
                <CardHead title={lang==='ar'?'صحّة الأقراص (SMART)':'Disk health (SMART)'} icon="server" iconColor="var(--primary)" />
                <div className="card-pad" style={{ paddingTop: 6 }}>
                  {m.disk_health.map((d, i) => {
                    const ok = String(d.health).toLowerCase()==='healthy' || String(d.health).toLowerCase()==='ok';
                    return (
                      <div key={i} className="row" style={{ justifyContent:'space-between', padding:'7px 0', borderBottom: i<m.disk_health.length-1?'1px solid var(--hairline)':'none' }}>
                        <span style={{ color:'var(--text-1)', fontSize:12.5 }}>{d.name} {d.type?('· '+d.type):''}</span>
                        <StatusPill tone={ok?'success':'danger'} live={ok}>{d.health}</StatusPill>
                      </div>
                    );
                  })}
                </div>
              </div>
            ) : null}

            {m.battery ? (
              <div className="card card-pad row" style={{ gap: 18 }}>
                <ScoreRing value={Math.round(m.battery.percent)} size={88} thickness={9} color={m.battery.percent<20?'var(--critical)':'var(--success)'} label="%" />
                <div>
                  <div style={{ fontSize:15, fontWeight:600 }}>{lang==='ar'?'البطارية':'Battery'}</div>
                  <div className="muted" style={{ fontSize:12.5, marginTop:5 }}>
                    {m.battery.plugged ? (lang==='ar'?'موصولة بالشاحن':'Plugged in') : (lang==='ar'?'تعمل على البطارية':'On battery')}
                  </div>
                  {m.battery.mins_left!=null ? <div className="muted" style={{ fontSize:12, marginTop:3 }}>{lang==='ar'?'يتبقّى ~':'~'} {Math.floor(m.battery.mins_left/60)}h {m.battery.mins_left%60}m</div> : null}
                </div>
              </div>
            ) : null}

            {m.services ? (
              <div className="card card-pad row" style={{ gap: 18 }}>
                <ScoreRing value={m.services.total?Math.round(m.services.running/m.services.total*100):0} size={88} thickness={9} color="var(--primary)" label="%" />
                <div>
                  <div style={{ fontSize:15, fontWeight:600 }}>{lang==='ar'?'خدمات ويندوز':'Windows services'}</div>
                  <div className="muted" style={{ fontSize:12.5, marginTop:5 }}>{m.services.running} {lang==='ar'?'نشطة':'running'} · {m.services.stopped} {lang==='ar'?'متوقّفة':'stopped'}</div>
                  <div className="muted" style={{ fontSize:12, marginTop:3 }}>{lang==='ar'?'الإجمالي':'Total'}: {m.services.total}</div>
                </div>
              </div>
            ) : null}

          </div>
        ) : null}
      </div>
    );
  }
  function Network({ t, lang }) {
    const { useState, useEffect, useRef } = React;
    const [m, setM] = useState(null);
    const [net, setNet] = useState(null);
    const [geo, setGeo] = useState(null);
    const [geoBusy, setGeoBusy] = useState(false);
    const mounted = useRef(true);
    useEffect(() => {
      mounted.current = true;
      const load = () => {
        if (window.API && window.API.getSystemMetrics)
          window.API.getSystemMetrics().then(d => { if (mounted.current && d) setM(d); });
        if (window.API && window.API.getNetworkAnalysis)
          window.API.getNetworkAnalysis().then(d => { if (mounted.current && d) setNet(d); });
        if (window.API && window.API.getGeoIpStatus)
          window.API.getGeoIpStatus().then(d => { if (mounted.current && d) setGeo(d); });
      };
      load();
      const iv = setInterval(load, 5000);
      return () => { mounted.current = false; clearInterval(iv); };
    }, []);
    const doBlock = (ip) => { window.API.blockIp(ip).then(r => { if (r && r.blocklist) setNet(p => Object.assign({}, p, { blocklist: r.blocklist })); }); };
    const doUnblock = (ip) => { window.API.unblockIp(ip).then(r => setNet(p => Object.assign({}, p, { blocklist: (r && r.blocklist) || [] }))); };
    const downloadGeo = () => {
      setGeoBusy(true);
      window.API.updateGeoIp(true).then(r => {
        setGeoBusy(false);
        window.API.getGeoIpStatus().then(d => d && setGeo(d));
      });
    };

    const conns = m ? m.connections : { established: 0, listening: 0, ports: [] };
    const ser = m ? m.series : {};
    const traffic = m && ser.traffic && ser.traffic.length ? ser.traffic[ser.traffic.length-1] : 0;
    const netIn = (ser.netIn && ser.netIn.length) ? ser.netIn : [0];
    const netOut = (ser.netOut && ser.netOut.length) ? ser.netOut : [0];
    const ports = conns.ports || [];

    return (
      <div>
        <PageHead t={t} lang={lang} title={t.nav.network} sub={t.pageSub.network}
          actions={<StatusPill tone="success" live>{t.status.healthy}</StatusPill>} />
        <div className="grid" style={{ gridTemplateColumns: 'repeat(3,1fr)', gap: 16, marginBottom: 20 }}>
          <StatCard icon="activity" color="var(--sev-low)" label={t.cards.traffic} value={String(traffic)} unit={t.units.mbps} spark={ser.traffic && ser.traffic.length ? ser.traffic : null} />
          <StatCard icon="lock" color="var(--warning)" label={t.cards.ports} value={String(conns.listening)} foot={<span>{t.units.open}</span>} />
          <StatCard icon="wifi" color="var(--primary)" label={lang==='ar'?'اتصالات نشطة':'Active connections'} value={String(conns.established)} />
        </div>
        <div className="grid" style={{ gridTemplateColumns: '1fr', gap: 20 }}>
          <div className="card">
            <CardHead title={t.sec.net} icon="activity" iconColor="var(--sev-low)"
              right={<div className="row gap16" style={{fontSize:12.5}}>
                <span className="row gap8"><span className="dot" style={{background:'var(--sev-low)'}}/>{lang==='ar'?'وارد':'Inbound'}</span>
                <span className="row gap8"><span className="dot" style={{background:'var(--primary)'}}/>{lang==='ar'?'صادر':'Outbound'}</span></div>} />
            <div className="card-pad" style={{ paddingTop: 12 }}>
              <AreaChart w={900} h={200} labels={[]}
                series={[{ color:'var(--sev-low)', data: netIn },{ color:'var(--primary)', data: netOut }]} />
            </div>
          </div>
        </div>
        <div className="grid" style={{ gridTemplateColumns: '1fr', gap: 20, marginTop: 20 }}>
          <div className="card">
            <CardHead title={lang==='ar'?'المنافذ المستمعة':'Listening ports'} icon="lock" iconColor="var(--warning)"
              right={<span className="muted" style={{fontSize:12.5}}>{ports.length} {t.units.open}</span>} />
            <div className="card-pad" style={{ display:'flex', flexWrap:'wrap', gap: 10 }}>
              {ports.length === 0 ? <span className="muted" style={{fontSize:12.5}}>{lang==='ar'?'لا منافذ مستمعة مكتشفة':'No listening ports detected'}</span> :
              ports.map(p => (
                <span key={p} className="mono" style={{ padding:'8px 12px', borderRadius:10, background:'var(--bg-inset)', border:'1px solid var(--hairline)', fontSize:13, color:'var(--text-1)' }}>:{p}</span>
              ))}
            </div>
          </div>
        </div>

        {net ? (
          <div className="grid" style={{ gridTemplateColumns: '1.4fr 1fr', gap: 20, marginTop: 20 }}>
            <div className="card">
              <CardHead title={lang==='ar'?'الاتصالات حسب الوجهة':'Connections by remote host'} icon="globe" iconColor="var(--primary)"
                right={<span className="muted" style={{fontSize:12}}>{net.distinct_remotes} {lang==='ar'?'وجهة':'remotes'}{net.firewall_rules!=null?(' · '+net.firewall_rules+(lang==='ar'?' قاعدة جدار':' fw rules')):''}</span>} />
              <div className="card-pad" style={{ paddingTop: 4 }}>
                {(net.remotes||[]).length===0 ? <div className="muted" style={{fontSize:12.5}}>{lang==='ar'?'لا اتصالات نشطة (قد تتطلّب صلاحيات مدير)':'No active connections (may need admin)'}</div> :
                (net.remotes||[]).map((r,i) => (
                  <div key={i} className="row" style={{ justifyContent:'space-between', padding:'7px 0', borderBottom: i<net.remotes.length-1?'1px solid var(--hairline)':'none', fontSize:12.5 }}>
                    <span className="row gap8">
                      <span className="mono" style={{color:'var(--text-1)'}}>{r.ip}</span>
                      <span className="muted" style={{fontSize:11}}>{r.class}</span>
                    </span>
                    <span className="row gap8">
                      <span className="muted tnum">{r.count}</span>
                      {r.class!=='private' ? <button className="btn btn-ghost btn-sm" onClick={()=>doBlock(r.ip)} title={lang==='ar'?'حظر':'Block'}><Icon name="x" size={12}/></button> : null}
                    </span>
                  </div>
                ))}
                {(net.anomalies||[]).length ? (
                  <div style={{ marginTop:10, padding:'8px 10px', borderRadius:8, background:'color-mix(in srgb, var(--warning) 12%, transparent)', fontSize:12 }}>
                    ⚠ {lang==='ar'?'شذوذ: وجهة بعدد اتصالات مرتفع':'Anomaly: a remote host with unusually many connections'} — {net.anomalies.map(a=>a.ip).join(', ')}
                  </div>
                ) : null}
              </div>
            </div>
            <div className="card">
              <CardHead title={lang==='ar'?'قائمة الحظر':'IP blocklist'} icon="lock" iconColor="var(--critical)" />
              <div className="card-pad" style={{ paddingTop: 6 }}>
                {(net.blocklist||[]).length===0 ? <div className="muted" style={{fontSize:12.5}}>{lang==='ar'?'لا عناوين محظورة':'No blocked addresses'}</div> :
                (net.blocklist||[]).map((ip,i) => (
                  <div key={i} className="row" style={{ justifyContent:'space-between', padding:'6px 0', fontSize:12.5 }}>
                    <span className="mono" style={{color:'var(--text-1)'}}>{ip}</span>
                    <button className="btn btn-ghost btn-sm" onClick={()=>doUnblock(ip)}>{lang==='ar'?'رفع':'Remove'}</button>
                  </div>
                ))}
                {(net.blocked_hits||[]).length ? <div style={{marginTop:8, color:'var(--critical)', fontSize:12}}>⚠ {lang==='ar'?'اتصالات نشطة لعناوين محظورة:':'Active connections to blocked IPs:'} {net.blocked_hits.join(', ')}</div> : null}
              </div>
            </div>
          </div>
        ) : null}

        {geo ? (
          <div className="card" style={{ marginTop: 20 }}>
            <CardHead title={lang==='ar'?'قاعدة بيانات الدولة (بحث محلي)':'Country DB (local lookup)'} icon="globe" iconColor="var(--secondary)"
              right={<span className="row gap8" style={{fontSize:12}}>
                {geo.loaded ? <StatusPill tone="success" live>{lang==='ar'?'مُحمّلة':'Loaded'}</StatusPill>
                            : <StatusPill tone="warning">{lang==='ar'?'غير مُحمّلة':'Not loaded'}</StatusPill>}
                {!geo.offline ? <button className="btn btn-ghost btn-sm" onClick={downloadGeo} disabled={geoBusy}>
                  <Icon name={geoBusy?'refresh':'download'} size={13}/>
                  {geoBusy ? (lang==='ar'?'جارٍ…':'Working…') : (geo.loaded ? (lang==='ar'?'تحديث':'Update') : (lang==='ar'?'تنزيل':'Download'))}
                </button> : null}
              </span>} />
            <div className="card-pad" style={{ paddingTop: 8 }}>
              <div className="muted" style={{ fontSize: 11.5, marginBottom: 8, lineHeight: 1.7 }}>
                🔒 {lang==='ar'
                  ? 'البحث الجغرافي يتم بالكامل على جهازك من ملف CSV محلي. عنوان IP لا يغادر الجهاز إطلاقاً. التنزيل لمرة واحدة فقط (مجهول، بلا حساب) من مرآة GitHub عامة.'
                  : 'Country lookup happens entirely on this machine from a local CSV. No IP is ever sent anywhere. The one-time download is anonymous (no account) from a public GitHub mirror.'}
              </div>
              <div className="muted" style={{ fontSize: 11 }}>
                {geo.loaded ? <>📊 {geo.ranges.toLocaleString()} {lang==='ar'?'نطاق IP محمّل في الذاكرة':'IP ranges in memory'}</> : null}
                {geo.offline ? <span style={{ color: 'var(--warning)', display: 'block', marginTop: 4 }}>{lang==='ar'?'الوضع غير المتصل مُفعّل — التنزيل معطّل.':'Offline mode on — download disabled.'}</span> : null}
                <div style={{ marginTop: 4 }}>{geo.attribution}</div>
              </div>
            </div>
          </div>
        ) : null}
      </div>
    );
  }

  /* ---------------- REPORTS ---------------- */
  function Reports({ t, lang }) {
    const { useState, useEffect, useRef } = React;
    const [reports, setReports] = useState(null);
    const [open, setOpen] = useState(null);
    const [digest, setDigest] = useState(null);
    const mounted = useRef(true);
    useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);

    const load = () => {
      if (window.API && window.API.getReports)
        window.API.getReports(lang).then(list => { if (mounted.current && list) setReports(list); });
      if (window.API && window.API.getWeeklyDigest)
        window.API.getWeeklyDigest().then(d => { if (mounted.current && d) setDigest(d); });
    };
    useEffect(() => { load(); }, [lang]);

    // open a report requested from the Alerts page (deep-link)
    useEffect(() => {
      const pending = window.__sxOpenReport;
      if (pending) {
        window.__sxOpenReport = null;
        if (window.API && window.API.getReport) window.API.getReport(pending, lang).then(full => { if (full) setOpen(full); });
      }
    }, []);

    const toneColor = { danger:'var(--critical)', warning:'var(--warning)', success:'var(--success)', info:'var(--secondary)' };
    const periodName = {
      daily: lang==='ar'?'يومي':'Daily', weekly: lang==='ar'?'أسبوعي':'Weekly',
      monthly: lang==='ar'?'شهري':'Monthly', yearly: lang==='ar'?'سنوي':'Annual',
      scan: lang==='ar'?'فحص ملف':'File scan', surprise: lang==='ar'?'تنبيه':'Incident',
    };
    const list = reports || [];
    const fmt = ts => { try { return new Date(ts).toLocaleString(lang==='ar'?'ar-EG':'en-US',{dateStyle:'medium',timeStyle:'short'}); } catch(e){ return ''; } };

    const openReport = (r) => {
      if (r.sections) { setOpen(r); return; }
      if (window.API && window.API.getReport) window.API.getReport(r.id, lang).then(full => setOpen(full || r));
      else setOpen(r);
    };
    const [pdfBusy, setPdfBusy] = useState(null);
    const [pdfErr, setPdfErr] = useState('');
    const [template, setTemplate] = useState('cmar');
    const [templates, setTemplates] = useState([
      { id: 'cmar',       title_en: 'Malware Analysis (CMAR)',  title_ar: 'تحليل البرمجيات الخبيثة (CMAR)' },
      { id: 'executive',  title_en: 'Executive Briefing',       title_ar: 'إحاطة تنفيذية' },
      { id: 'incident',   title_en: 'Incident Response',        title_ar: 'الاستجابة للحادث' },
      { id: 'compliance', title_en: 'Compliance Audit',         title_ar: 'تدقيق الامتثال' },
    ]);
    useEffect(() => {
      if (window.API && window.API.getReportTemplates)
        window.API.getReportTemplates().then(list => { if (list && list.length) setTemplates(list); });
    }, []);
    const download = (r) => {
      // download the professional PDF directly (no print dialog)
      if (window.API && window.API.downloadReportPdf) {
        window.API.downloadReportPdf(r.id, lang, 'sentinel-report-' + (r.period || r.id) + '.pdf');
      } else if (window.API && window.API.openReportPrint) {
        window.API.openReportPrint(r.id, lang, template);
      }
    };
    const [genBusy, setGenBusy] = useState(false);
    const [period, setPeriod] = useState('status');
    const periods = [
      { id: 'status',  ar: 'تقرير حالة فوري', en: 'Instant status' },
      { id: 'daily',   ar: 'يومي',  en: 'Daily' },
      { id: 'weekly',  ar: 'أسبوعي', en: 'Weekly' },
      { id: 'monthly', ar: 'شهري',  en: 'Monthly' },
      { id: 'yearly',  ar: 'سنوي',  en: 'Annual' },
    ];
    const generatePdf = () => {
      if (!(window.API && window.API.generatePeriodReport)) return;
      setGenBusy(true); setPdfErr('');
      window.API.generatePeriodReport(period, lang, template).then(rep => {
        setGenBusy(false);
        if (rep && rep.id) {
          load();
          setOpen(rep);
          if (template && template !== 'status' && window.API.openReportPrint) {
            setTimeout(() => window.API.openReportPrint(rep.id, lang, template), 300);
          }
        } else {
          setPdfErr(lang === 'ar'
            ? 'تعذّر توليد التقرير. تأكّد أنك سجّلت الدخول وأن الخادم يعمل، ثم حدّث الصفحة (Ctrl+Shift+R).'
            : 'Could not generate the report. Make sure you are signed in and the server is running, then hard-refresh (Ctrl+Shift+R).');
        }
      }).catch(() => {
        setGenBusy(false);
        setPdfErr(lang === 'ar' ? 'خطأ في الاتصال بالخادم.' : 'Server connection error.');
      });
    };

    return (
      <div>
        <PageHead t={t} lang={lang} title={t.nav.reports} sub={t.pageSub.reports}
          actions={<>
            <select className="tb-search" style={{ padding: '6px 10px', fontSize: 12.5 }} value={period} onChange={e => setPeriod(e.target.value)} title={lang==='ar'?'الفترة':'Period'}>
              {periods.map(p => <option key={p.id} value={p.id}>{lang === 'ar' ? p.ar : p.en}</option>)}
            </select>
            <select className="tb-search" style={{ padding: '6px 10px', fontSize: 12.5 }} value={template} onChange={e => setTemplate(e.target.value)} title={lang==='ar'?'القالب':'Template'}>
              {templates.map(tt => <option key={tt.id} value={tt.id}>{lang === 'ar' ? tt.title_ar : tt.title_en}</option>)}
            </select>
            <button className="btn btn-ghost" onClick={load}><Icon name="refresh" size={15} />{lang==='ar'?'تحديث':'Refresh'}</button>
            <button className="btn btn-primary" onClick={generatePdf} disabled={genBusy}>
              <Icon name={genBusy ? 'refresh' : 'report'} size={15} sw={2} />
              {genBusy ? (lang==='ar'?'جارٍ التوليد…':'Generating…') : (lang==='ar'?'توليد تقرير':'Generate Report')}
            </button></>} />
        {digest && digest.summary ? (
          <div className="card" style={{ marginBottom: 20, borderColor: 'color-mix(in srgb, var(--primary) 35%, transparent)' }}>
            <div className="card-pad">
              <div className="row" style={{ justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                <div style={{ fontWeight: 700, fontSize: 14 }}>
                  <Icon name="activity" size={15} /> {lang==='ar' ? 'الملخّص الأسبوعي الذكي' : 'Smart Weekly Digest'}
                </div>
                <span className="muted" style={{ fontSize: 11 }}>{lang==='ar'?'آخر ٧ أيام':'last 7 days'}</span>
              </div>
              <div style={{ fontSize: 13, lineHeight: 1.8, color: 'var(--text-1)', marginBottom: digest.stats ? 12 : 0 }}>
                {digest.summary}
              </div>
              {digest.stats ? (
                <div className="grid" style={{ gridTemplateColumns: 'repeat(4,1fr)', gap: 10 }}>
                  {[
                    { k: lang==='ar'?'أحداث':'Events', v: digest.stats.total_events ?? digest.stats.events ?? 0 },
                    { k: lang==='ar'?'تهديدات':'Threats', v: digest.stats.threats ?? digest.stats.critical ?? 0, c: 'var(--critical)' },
                    { k: lang==='ar'?'عمليات عزل':'Isolations', v: digest.stats.isolations ?? 0, c: 'var(--warning)' },
                    { k: lang==='ar'?'فحوصات':'Scans', v: digest.stats.scans ?? 0, c: 'var(--primary)' },
                  ].map((s, i) => (
                    <div key={i} style={{ padding: '8px 10px', background: 'rgba(255,255,255,0.04)', borderRadius: 8, textAlign: 'center' }}>
                      <div style={{ fontWeight: 700, fontSize: 19, color: s.c || 'var(--text-1)' }}>{s.v}</div>
                      <div className="muted" style={{ fontSize: 10.5 }}>{s.k}</div>
                    </div>
                  ))}
                </div>
              ) : null}
            </div>
          </div>
        ) : null}
        <div className="grid" style={{ gridTemplateColumns: 'repeat(3,1fr)', gap: 16, marginBottom: 20 }}>
          <div className="card card-pad"><div className="muted" style={{fontSize:12.5,marginBottom:8}}>{t.reports.generated}</div><div className="value tnum" style={{fontSize:30,fontWeight:700}}>{list.length}</div><div className="muted" style={{fontSize:12,marginTop:4}}>{lang==='ar'?'متاحة الآن':'available now'}</div></div>
          <div className="card card-pad"><div className="muted" style={{fontSize:12.5,marginBottom:8}}>{lang==='ar'?'تقارير الفحص':'Scan reports'}</div><div className="value tnum" style={{fontSize:30,fontWeight:700,color:'var(--primary)'}}>{list.filter(r=>r.period==='scan').length}</div><div className="muted" style={{fontSize:12,marginTop:4}}>{lang==='ar'?'من ملفات مرفوعة':'from uploads'}</div></div>
          <div className="card"><CardHead title={t.reports.summary} /><div className="card-pad" style={{paddingTop:10}}>
            {(() => {
              const byType = {};
              list.forEach(r => { byType[r.period] = (byType[r.period]||0)+1; });
              const rows = Object.keys(byType);
              if (!rows.length) return <div className="muted" style={{fontSize:12.5}}>{lang==='ar'?'لا تقارير بعد':'No reports yet'}</div>;
              const max = Math.max.apply(null, rows.map(k=>byType[k]));
              const nm = {daily:lang==='ar'?'يومي':'Daily',weekly:lang==='ar'?'أسبوعي':'Weekly',monthly:lang==='ar'?'شهري':'Monthly',yearly:lang==='ar'?'سنوي':'Annual',scan:lang==='ar'?'فحص':'Scan',status:lang==='ar'?'حالة':'Status',surprise:lang==='ar'?'حادثة':'Incident'};
              return <div style={{display:'flex',flexDirection:'column',gap:8}}>
                {rows.map(k => <div key={k} className="row gap8" style={{alignItems:'center'}}>
                  <span className="muted" style={{fontSize:11.5,minWidth:54}}>{nm[k]||k}</span>
                  <span style={{flex:1,height:8,background:'var(--bg-inset)',borderRadius:5,overflow:'hidden'}}>
                    <span style={{display:'block',height:'100%',width:(byType[k]/max*100)+'%',background:'var(--primary)',borderRadius:5}} /></span>
                  <span className="tnum" style={{fontSize:12,fontWeight:600,minWidth:18,textAlign:'center'}}>{byType[k]}</span>
                </div>)}
              </div>;
            })()}
          </div></div>
        </div>
        <div className="card">
          <CardHead title={t.nav.reports} icon="report" iconColor="var(--warning)" />
          {pdfErr && <div className="card-pad" style={{ paddingTop: 12, paddingBottom: 0, color: 'var(--critical)', fontSize: 12.5 }}>⚠ {pdfErr}</div>}
          <table className="tbl">
            <thead><tr><th>{t.reports.name}</th><th>{t.reports.period}</th><th>{lang==='ar'?'التاريخ':'Date'}</th><th></th></tr></thead>
            <tbody>
              {list.length === 0 && <tr><td colSpan={4} className="muted" style={{padding:'18px',textAlign:'center'}}>{lang==='ar'?'لا تقارير بعد — ارفع ملفاً عبر Scan Now':'No reports yet — upload a file via Scan Now'}</td></tr>}
              {list.map((r,i) => {
                const c = toneColor[r.tone] || 'var(--primary)';
                return (
                  <tr key={r.id || i}>
                    <td><span className="row gap12" onClick={() => openReport(r)} style={{cursor:'pointer'}}>
                      <span style={{width:34,height:34,borderRadius:9,display:'grid',placeItems:'center',color:c,background:`color-mix(in srgb, ${c} 15%, transparent)`}}><Icon name="report" size={16}/></span>
                      <span style={{color:'var(--text-1)',fontWeight:500}}>{r.title}</span></span></td>
                    <td><span className="sev" style={{color:c,background:`color-mix(in srgb, ${c} 14%, transparent)`}}><span className="dot" style={{background:c}} />{periodName[r.period] || r.period}</span></td>
                    <td className="mono muted">{fmt(r.ts)}</td>
                    <td><div className="row gap8" style={{justifyContent:'flex-end'}}>
                      <button className="btn btn-ghost btn-sm" onClick={() => openReport(r)}><Icon name="eye" size={14} />{lang==='ar'?'فتح':'Open'}</button>
                      <button className="btn btn-primary btn-sm" onClick={() => download(r)}>
                        <Icon name="download" size={14} />
                        {lang==='ar'?'تحميل PDF':'Download PDF'}
                      </button>
                    </div></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        {open && <ReportModalRP lang={lang} report={open} onClose={() => setOpen(null)} />}
      </div>
    );
  }

  function ReportModalRP({ lang, report, onClose }) {
    const { useEffect } = React;
    useEffect(() => { const k = e => { if (e.key==='Escape') onClose(); }; window.addEventListener('keydown',k); return () => window.removeEventListener('keydown',k); }, []);
    const toneColor = { danger:'var(--critical)', warning:'var(--warning)', success:'var(--success)', info:'var(--secondary)' };
    const c = toneColor[report.tone] || 'var(--primary)';
    return ReactDOM.createPortal(
      <div onClick={onClose} style={{ position:'fixed', inset:0, zIndex:120, background:'rgba(8,10,16,0.55)', backdropFilter:'blur(4px)', display:'flex', alignItems:'center', justifyContent:'center', padding:20 }}>
        <div onClick={e => e.stopPropagation()} className="glass glass-3" style={{ width:'min(680px,100%)', maxHeight:'85vh', overflowY:'auto', borderRadius:22, padding:26 }}>
          <div className="row" style={{ justifyContent:'space-between', alignItems:'flex-start', marginBottom:14 }}>
            <div>
              <span className="sev" style={{ color:c, background:`color-mix(in srgb, ${c} 16%, transparent)` }}><span className="dot" style={{ background:c }} />{report.score != null ? `${lang==='ar'?'الدرجة':'Score'} ${report.score}/100` : (lang==='ar'?'تقرير':'Report')}</span>
              <h2 style={{ fontSize:21, margin:'12px 0 0', letterSpacing:'-0.02em' }}>{report.title}</h2>
            </div>
            <button className="btn btn-ghost btn-sm" onClick={onClose} aria-label="close"><Icon name="x" size={16} sw={2.2} /></button>
          </div>
          <p style={{ color:'var(--text-2)', fontSize:14, lineHeight:1.65, marginBottom:18 }}>{report.summary}</p>
          {(report.sections || []).map((sec,i) => (
            <div key={i} style={{ marginBottom:16 }}>
              <h4 style={{ fontSize:13.5, color:'var(--text-1)', margin:'0 0 5px', fontWeight:700 }}>{sec.h}</h4>
              <p style={{ fontSize:13, color:'var(--text-2)', lineHeight:1.6, margin:0, whiteSpace:'pre-wrap' }}>{sec.b}</p>
            </div>
          ))}
        </div>
      </div>,
      document.body
    );
  }

  /* ---------------- SIMPLE PAGES ---------------- */
  function Simple({ t, lang, route }) {
    const map = {
      alerts: { ic: 'bell', c: 'var(--warning)' },
      devices: { ic: 'devices', c: 'var(--primary)' },
      settings: { ic: 'settings', c: 'var(--text-2)' },
      profile: { ic: 'user', c: 'var(--secondary)' },
    };
    const m = map[route] || map.settings;
    return (
      <div>
        <PageHead t={t} lang={lang} title={t.nav[route]} sub={lang==='ar'?'هذه الصفحة جزء من نظام التصميم':'Part of the design system'} />
        <div className="card card-pad" style={{ display:'grid', placeItems:'center', minHeight: 340, textAlign:'center' }}>
          <div>
            <span style={{ width:64,height:64,borderRadius:18,display:'grid',placeItems:'center',margin:'0 auto 16px',color:m.c,background:`color-mix(in srgb, ${m.c} 14%, transparent)` }}><Icon name={m.ic} size={30} /></span>
            <div style={{ fontSize: 17, fontWeight: 600 }}>{t.nav[route]}</div>
            <div className="muted" style={{ fontSize: 13.5, marginTop: 6, maxWidth: 360 }}>{lang==='ar'?'مساحة مخصّصة لهذه الواجهة ضمن نظام تصميم سنتينل — جاهزة للتوسعة.':'A dedicated surface within the Sentinel design system — ready to extend.'}</div>
          </div>
        </div>
      </div>
    );
  }

  Object.assign(window, { System, Network, Reports, Simple });
})();
