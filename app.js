/* ============================================================
   SCOPELOCK v2 — Passive Recon Dashboard
   Semua request memakai API publik / CORS proxy read-only.
   Tidak ada fungsi exploitation (SQLi/XSS payload injection dsb).
   ============================================================ */

const state = {
  target: '',
  activeTab: 'overview',
  log: [],
  scanStartedAt: null,
  lastScanDuration: null, // ms
  lastScanAt: null,
  results: {
    headers: null,
    subdomains: null,
    tech: null,
    wayback: null,
    robots: null,
    jsrecon: null,
    endpoints: null,
    secrets: null,
    api: null,
    cors: null,
    shots: null,
    favicon: null,
    asn: null,
    sources: null,
    subLive: null,   // { host: { alive:bool, status:number|null } }
    checklist: {}
  },
  filters: {
    secretsSev: new Set(['critical','high','medium']),
    assetsLevel: new Set(['critical','high','medium','low']),
    endpointsQuery: '',
    endpointsCat: new Set(['api','admin','auth','graphql','other']),
    graphLevel: new Set(['critical','high','medium','low']),
  },
  workspaces: [],
  compareA: null, // workspace id or 'current'
  compareB: null,
  _mem: {} // in-memory fallback store when localStorage is unavailable
};

const TABS = [
  { id:'overview',   label:'Overview' },
  { id:'headers',    label:'Security Headers', n:'01' },
  { id:'subdomains', label:'Subdomains',       n:'02' },
  { id:'graph',      label:'Peta Subdomain',   n:'02b' },
  { id:'tech',       label:'Tech',             n:'03' },
  { id:'wayback',    label:'Wayback',          n:'04' },
  { id:'robots',     label:'Robots / Sitemap', n:'05' },
  { id:'jsrecon',    label:'JS Analyzer',      n:'06' },
  { id:'endpoints',  label:'Endpoints',        n:'07' },
  { id:'secrets',    label:'Secret Scanner',   n:'08' },
  { id:'api',        label:'API & GraphQL',    n:'09' },
  { id:'cors',       label:'CORS Checker',     n:'10' },
  { id:'shots',      label:'Screenshot Gallery', n:'11' },
  { id:'favicon',    label:'Favicon Hash',     n:'12' },
  { id:'asn',        label:'ASN & IP',         n:'13' },
  { id:'sources',    label:'Sumber Recon',     n:'14' },
  { id:'assets',     label:'Prioritas Aset',   n:'15' },
  { id:'stats',      label:'Ringkasan Statistik', n:'16' },
  { id:'checklist',  label:'Checklist',        n:'17' },
  { id:'workspace',  label:'Workspace',        n:'18' },
  { id:'compare',    label:'Split Compare',    n:'19' },
];

const MOBILE_TABS = [
  { id:'overview',   label:'Overview',   ic:'▦' },
  { id:'headers',    label:'Headers',    ic:'🛡' },
  { id:'subdomains', label:'Subdomains', ic:'◈' },
  { id:'graph',      label:'Peta',       ic:'◉' },
  { id:'more',       label:'More',       ic:'⋯' },
];

const PROXY = 'https://api.allorigins.win/raw?url=';

/* ---------- persistent storage (localStorage with in-memory fallback) ---------- */
const Store = {
  get(key, fallback){
    try{
      const raw = localStorage.getItem(key);
      return raw!==null ? JSON.parse(raw) : (fallback!==undefined?fallback:null);
    }catch(e){
      return state._mem[key] !== undefined ? state._mem[key] : (fallback!==undefined?fallback:null);
    }
  },
  set(key, val){
    try{ localStorage.setItem(key, JSON.stringify(val)); }
    catch(e){ state._mem[key] = val; }
  }
};

/* ---------- theme ---------- */
function toggleTheme(){
  const isLight = document.body.getAttribute('data-theme') === 'light';
  document.body.setAttribute('data-theme', isLight ? '' : 'light');
  document.querySelectorAll('#themeLabel').forEach(el=> el.textContent = isLight ? 'Mode Gelap' : 'Mode Terang');
}

/* ---------- utility quick links ---------- */
function openUtility(kind){
  const domain = state.target || normalizeDomain(document.getElementById('targetInput').value) || '';
  if(!domain){ alert('Masukkan domain target dulu.'); return; }
  const urls = {
    dns: `https://mxtoolbox.com/DNSLookup.aspx?domain=${domain}`,
    whois: `https://who.is/whois/${domain}`,
    ssl: `https://www.ssllabs.com/ssltest/analyze.html?d=${domain}`,
  };
  window.open(urls[kind], '_blank');
}

function normalizeDomain(input){
  let v = (input||'').trim();
  v = v.replace(/^https?:\/\//,'').replace(/\/.*$/,'');
  return v;
}

function log(tag, msg){
  const time = new Date().toLocaleTimeString('id-ID', {hour12:false});
  state.log.push({time, tag, msg});
  renderLogIfVisible();
}
function clearLog(){ state.log = []; renderLogIfVisible(); }

function tagClass(tag){
  return {info:'tag-info', ok:'tag-ok', warn:'tag-warn', err:'tag-err'}[tag] || 'tag-info';
}

function renderLogIfVisible(){
  const box = document.getElementById('liveLog');
  if(!box) return;
  box.innerHTML = state.log.map(e =>
    `<div class="l"><span class="t">[${e.time}]</span><span class="${tagClass(e.tag)}">${e.msg}</span></div>`
  ).join('') + `<div class="l"><span class="cursor"></span></div>`;
  box.scrollTop = box.scrollHeight;
}

/* ---------- fetch helpers ---------- */
async function fetchViaProxy(url){
  const res = await fetch(PROXY + encodeURIComponent(url));
  if(!res.ok) throw new Error('HTTP ' + res.status);
  return res;
}
async function fetchDirect(url){
  const res = await fetch(url);
  if(!res.ok) throw new Error('HTTP ' + res.status);
  return res;
}

/* =========================================================
   NAV / TABS RENDER
   ========================================================= */
function switchTab(id){
  if(id === 'more'){ openMoreSheet(); return; }
  state.activeTab = id;
  document.querySelectorAll('.nav-item[data-nav]').forEach(el=>{
    el.classList.toggle('active', el.getAttribute('data-nav')===id);
  });
  renderTabstrip();
  renderBottomNav();
  renderContent();
}

function renderTabstrip(){
  const el = document.getElementById('tabstrip');
  el.innerHTML = TABS.map(t=>`
    <div class="tabchip ${state.activeTab===t.id?'active':''}" onclick="switchTab('${t.id}')">${t.n?t.n+' · ':''}${t.label}</div>
  `).join('');
}

function renderBottomNav(){
  const el = document.getElementById('bottomNav');
  const mainIds = MOBILE_TABS.map(t=>t.id);
  const activeIsMore = !mainIds.includes(state.activeTab) && state.activeTab !== 'overview';
  el.innerHTML = MOBILE_TABS.map(t=>{
    const active = t.id==='more' ? activeIsMore : state.activeTab===t.id;
    return `<button class="bn-item ${active?'active':''}" onclick="switchTab('${t.id}')"><span class="ic">${t.ic}</span>${t.label}</button>`;
  }).join('');
}

function openMoreSheet(){
  const opts = ['wayback','robots','jsrecon','endpoints','secrets','api','cors','shots','favicon','asn','sources','assets','stats','checklist','workspace','compare','about'];
  const labels = {
    wayback:'Wayback URLs', robots:'Robots / Sitemap', jsrecon:'JS Analyzer', endpoints:'Endpoint Extractor',
    secrets:'Secret Scanner', api:'API & GraphQL', cors:'CORS Checker', shots:'Screenshot Gallery',
    favicon:'Favicon Hash', asn:'ASN & IP', sources:'Sumber Recon', assets:'Prioritas Aset',
    stats:'Ringkasan Statistik', checklist:'Checklist & Report', workspace:'Workspace', compare:'Split Compare',
    about:'Tentang'
  };
  const choice = prompt('Buka modul lain:\n' + opts.map((o,i)=>`${i+1}. ${labels[o]}`).join('\n') + '\n\nKetik nomor:');
  const idx = parseInt(choice,10)-1;
  if(opts[idx]) switchTab(opts[idx]);
}

/* =========================================================
   STAT CARDS
   ========================================================= */
function sparkPath(seed){
  // deterministic decorative sparkline
  let pts = [];
  let v = 10 + (seed%7);
  for(let i=0;i<12;i++){
    v += ((seed*(i+3))%5) - 2;
    v = Math.max(3, Math.min(22, v));
    pts.push(v);
  }
  const w=100,h=26;
  const step = w/(pts.length-1);
  return pts.map((p,i)=>`${(i*step).toFixed(1)},${(h-p).toFixed(1)}`).join(' ');
}

function renderStatCards(){
  const r = state.results;
  const scorePct = r.headers && !r.headers.error ? r.headers.pct : 0;
  const subCount = r.subdomains && !r.subdomains.error ? r.subdomains.count : '-';
  const httpStatus = r.headers && !r.headers.error ? (r.headers.status || 200) : '-';
  const techCount = r.tech && !r.tech.error ? r.tech.found.length : '-';
  const lastScan = state.lastScanAt ? 'Baru saja' : 'Belum pernah';
  const dur = state.lastScanDuration ? fmtDuration(state.lastScanDuration) : '—';

  document.getElementById('statRow').innerHTML = `
    <div class="stat-card score-card">
      <div class="score-ring" style="--pct:${scorePct}; width:56px;height:56px;"><div class="in" style="width:44px;height:44px;font-size:13px;">${scorePct}</div></div>
      <div>
        <div class="lbl">Security Score</div>
        <div class="val">${scorePct}<small>/100</small></div>
        <div class="sub">${scorePct>=70?'Good':scorePct>=40?'Cukup':scorePct>0?'Lemah':'—'}</div>
      </div>
    </div>
    <div class="stat-card">
      <div class="lbl">Subdomains</div>
      <div class="val">${subCount}</div>
      <div class="sub" style="color:var(--muted);">Ditemukan</div>
      <svg class="spark" viewBox="0 0 100 26" preserveAspectRatio="none"><polyline points="${sparkPath(3)}" fill="none" stroke="var(--accent-2)" stroke-width="2"/></svg>
    </div>
    <div class="stat-card">
      <div class="lbl">HTTP Status</div>
      <div class="val">${httpStatus}</div>
      <div class="sub" style="color:var(--muted);">${httpStatus===200?'OK':httpStatus==='-'?'—':'Cek'}</div>
      <svg class="spark" viewBox="0 0 100 26" preserveAspectRatio="none"><polyline points="${sparkPath(5)}" fill="none" stroke="var(--ok)" stroke-width="2"/></svg>
    </div>
    <div class="stat-card">
      <div class="lbl">Technologies</div>
      <div class="val">${techCount}</div>
      <div class="sub" style="color:var(--muted);">Teridentifikasi</div>
      <svg class="spark" viewBox="0 0 100 26" preserveAspectRatio="none"><polyline points="${sparkPath(7)}" fill="none" stroke="var(--accent)" stroke-width="2"/></svg>
    </div>
    <div class="stat-card">
      <div class="lbl">Last Scan</div>
      <div class="val" style="font-size:16px;">${lastScan}</div>
      <div class="sub" style="color:var(--warn);">${dur}</div>
      <svg class="spark" viewBox="0 0 100 26" preserveAspectRatio="none"><polyline points="${sparkPath(9)}" fill="none" stroke="var(--warn)" stroke-width="2"/></svg>
    </div>
  `;
}

function fmtDuration(ms){
  const s = Math.round(ms/1000);
  const m = Math.floor(s/60);
  const r = s%60;
  return m>0 ? `${m}m ${r}s` : `${r}s`;
}

/* =========================================================
   RIGHT COLUMN — quick actions / checklist donut / risk summary
   ========================================================= */
function renderRightCol(){
  const domain = state.target || '(belum diisi)';
  const r = state.results;
  const checkedCount = Object.values(r.checklist).filter(Boolean).length;
  const pct = Math.round((checkedCount/OWASP_LIST.length)*100);

  const sevTotals = {critical:0, high:0, medium:0};
  const sevChecked = {critical:0, high:0, medium:0};
  OWASP_LIST.forEach(item=>{
    sevTotals[item.severity]++;
    if(r.checklist[item.id]) sevChecked[item.severity]++;
  });
  const sevColor = {critical:'var(--danger)', high:'var(--warn)', medium:'#B8E28C'};
  const sevLabel = {critical:'Critical', high:'High', medium:'Medium'};

  document.getElementById('rightCol').innerHTML = `
    <div class="panel">
      <h2>Quick Actions</h2>
      <p class="sub">Target: <b style="color:var(--text)">${domain}</b></p>
      <div class="qa-list">
        <div class="qa-btn" onclick="copyTarget()"><span class="ic">⎘</span>Copy Target</div>
        <div class="qa-btn" onclick="openInBrowser()"><span class="ic">↗</span>Open in Browser</div>
        <div class="qa-btn" onclick="viewSource()"><span class="ic">&lt;/&gt;</span>View Source</div>
        <div class="qa-btn" onclick="openUtility('ssl')"><span class="ic">🔒</span>Check SSL</div>
        <div class="qa-btn" onclick="openUtility('dns')"><span class="ic">◎</span>DNS Lookup</div>
      </div>
    </div>

    <div class="panel">
      <h2>Checklist Progress</h2>
      <div class="donut-wrap">
        <div class="donut" style="--pct:${pct}"><div class="in"><b>${checkedCount}/${OWASP_LIST.length}</b><span>Selesai</span></div></div>
        <div class="legend">
          <div class="li"><span class="sw" style="background:var(--ok);"></span>Dicentang: ${checkedCount}</div>
          <div class="li"><span class="sw" style="background:var(--line-solid);"></span>Pending: ${OWASP_LIST.length-checkedCount}</div>
        </div>
      </div>
      <p class="sub vall" style="margin-top:12px; margin-bottom:0;" onclick="switchTab('checklist')">Lihat checklist →</p>
    </div>

    <div class="panel">
      <h2>Risk Breakdown</h2>
      <p class="sub">Kategori OWASP yang sudah dicentang, per tingkat severity</p>
      ${['critical','high','medium'].map(s=>`
        <div class="risk-row">
          <div class="lab"><span class="sw" style="background:${sevColor[s]}"></span>${sevLabel[s]}</div>
          <div class="cnt">${sevChecked[s]}/${sevTotals[s]}</div>
        </div>
      `).join('')}
      <p class="sub vall" style="margin-top:10px; margin-bottom:0;" onclick="switchTab('checklist')">Detail →</p>
    </div>
  `;
}

function copyTarget(){
  if(!state.target){ alert('Belum ada target.'); return; }
  navigator.clipboard.writeText(state.target);
  log('info', 'Target disalin ke clipboard.');
}
function openInBrowser(){
  if(!state.target){ alert('Belum ada target.'); return; }
  window.open(`https://${state.target}`, '_blank');
}
function viewSource(){
  if(!state.target){ alert('Belum ada target.'); return; }
  window.open(`view-source:https://${state.target}`, '_blank');
}

/* =========================================================
   01 — SECURITY HEADERS ANALYZER
   ========================================================= */
const HEADER_CHECKS = [
  { key:'content-security-policy', name:'Content-Security-Policy', weight:20, tip:'Mencegah XSS dengan membatasi sumber script/style yang boleh dijalankan.' },
  { key:'strict-transport-security', name:'Strict-Transport-Security', weight:15, tip:'Memaksa koneksi HTTPS, mencegah downgrade attack.' },
  { key:'x-frame-options', name:'X-Frame-Options', weight:12, tip:'Mencegah clickjacking lewat iframe.' },
  { key:'x-content-type-options', name:'X-Content-Type-Options', weight:10, tip:'Mencegah MIME sniffing.' },
  { key:'referrer-policy', name:'Referrer-Policy', weight:8, tip:'Kontrol data referrer yang dikirim ke situs lain.' },
  { key:'permissions-policy', name:'Permissions-Policy', weight:8, tip:'Membatasi akses fitur browser (kamera, lokasi, dll).' },
  { key:'x-xss-protection', name:'X-XSS-Protection', weight:5, tip:'Legacy header, browser modern sudah pakai CSP.' },
  { key:'cross-origin-opener-policy', name:'Cross-Origin-Opener-Policy', weight:7, tip:'Isolasi browsing context, mitigasi Spectre-class attack.' },
  { key:'cross-origin-resource-policy', name:'Cross-Origin-Resource-Policy', weight:7, tip:'Kontrol resource cross-origin bisa diakses siapa.' },
  { key:'cache-control', name:'Cache-Control', weight:8, tip:'Penting untuk halaman sensitif agar tidak ter-cache.' },
];

async function runHeaders(){
  const domain = state.target;
  if(!domain) return;
  log('info', `Fetching headers untuk https://${domain} ...`);
  try{
    const res = await fetchViaProxy(`https://${domain}`);
    const headers = {};
    res.headers.forEach((v,k)=> headers[k.toLowerCase()] = v);

    let score = 0, maxScore = 0;
    const checks = HEADER_CHECKS.map(c=>{
      maxScore += c.weight;
      const present = !!headers[c.key];
      if(present) score += c.weight;
      return { ...c, present, value: headers[c.key] || null };
    });

    state.results.headers = {
      domain, checks, status: res.status,
      pct: Math.round((score/maxScore)*100),
      raw: headers,
      fetchedAt: new Date().toLocaleString('id-ID')
    };
    log('ok', `Header berhasil diambil. Skor keamanan: ${state.results.headers.pct}%`);
  }catch(e){
    log('err', `Gagal fetch header: ${e.message}. Proxy publik mungkin sedang limit — coba lagi beberapa saat.`);
    state.results.headers = { error: e.message, domain };
  }
  renderStatCards();
  if(state.activeTab==='headers' || state.activeTab==='overview') renderContent();
}

function renderHeadersPanel(compact){
  const r = state.results.headers;
  const checksToShow = r && !r.error ? (compact ? r.checks.slice(0,6) : r.checks) : [];
  return `
  <div class="panel">
    <h2>Security Headers ${r && !r.error ? `<span style="font-weight:400;font-size:12px;color:var(--muted)">${r.checks.filter(c=>c.present).length} / ${r.checks.length}</span>`:''}</h2>
    <p class="sub">Cek HTTP response header keamanan pada target (pasif, read-only)</p>
    ${!r ? `<div class="empty">Masukkan domain di atas lalu klik "Scan Semua", atau <button class="btn-sec" onclick="runHeaders()">jalankan tool ini saja</button></div>` : ''}
    ${r && r.error ? `<div class="empty">Error: ${r.error}</div>` : ''}
    ${r && !r.error ? `
      ${compact ? '' : `
      <div class="score-wrap">
        <div class="score-ring" style="--pct:${r.pct}"><div class="in">${r.pct}%</div></div>
        <div class="score-txt">Target: <b>${r.domain}</b><br>Diambil: ${r.fetchedAt}<br>Skor dihitung dari 10 header keamanan standar OWASP.</div>
      </div>`}
      ${checksToShow.map(c=>`
        <div class="row">
          <div class="k">${c.name}${compact?'':`<br><small style="color:#5b636b">${c.tip}</small>`}</div>
          <div class="v"><span class="pill ${c.present?'ok':'bad'}">${c.present?'Present':'Missing'}</span></div>
        </div>
      `).join('')}
      ${compact ? `<p class="sub vall" style="margin-top:10px;margin-bottom:0;" onclick="switchTab('headers')">View full report →</p>` : ''}
    ` : ''}
  </div>`;
}

/* =========================================================
   02 — SUBDOMAIN ENUMERATION (crt.sh Certificate Transparency)
   ========================================================= */
async function runSubdomains(){
  const domain = state.target;
  if(!domain) return;
  log('info', `Query Certificate Transparency logs (crt.sh) untuk *.${domain} ...`);
  try{
    const res = await fetchViaProxy(`https://crt.sh/?q=%25.${domain}&output=json`);
    const text = await res.text();
    let data;
    try{ data = JSON.parse(text); }
    catch{ data = JSON.parse('[' + text.trim().split('\n').join(',') + ']'); }

    const set = new Set();
    data.forEach(entry=>{
      String(entry.name_value||'').split('\n').forEach(n=>{
        n = n.trim().toLowerCase();
        if(n && !n.startsWith('*') && n.endsWith(domain)) set.add(n);
      });
    });
    const subs = Array.from(set).sort();
    state.results.subdomains = { domain, subs, count: subs.length, fetchedAt: new Date().toLocaleString('id-ID') };
    log('ok', `Ditemukan ${subs.length} subdomain unik dari certificate logs.`);
  }catch(e){
    log('err', `Gagal query crt.sh: ${e.message}`);
    state.results.subdomains = { error: e.message, domain };
  }
  renderStatCards();
  if(state.activeTab==='subdomains' || state.activeTab==='overview') renderContent();
}

function renderSubdomainsPanel(compact){
  const r = state.results.subdomains;
  const list = r && !r.error ? (compact ? r.subs.slice(0,5) : r.subs) : [];
  const live = state.results.subLive;
  return `
  <div class="panel">
    <h2>Subdomains ${r && !r.error ? `<span style="font-weight:400;font-size:12px;color:var(--muted)">${r.count}</span>` : ''}</h2>
    <p class="sub">Sumber: Certificate Transparency logs via crt.sh (100% pasif). Lihat juga tab <b style="color:var(--text)" class="vall" onclick="switchTab('graph')">Peta Subdomain →</b></p>
    ${!r ? `<div class="empty">Belum ada data. <button class="btn-sec" onclick="runSubdomains()">Jalankan enumerasi</button></div>` : ''}
    ${r && r.error ? `<div class="empty">Error: ${r.error}</div>` : ''}
    ${r && !r.error ? `
      ${!compact ? `<button class="btn-sec" style="margin-bottom:12px;" onclick="runLiveCheck()">◉ Cek host aktif (maks ${LIVE_CHECK_LIMIT})</button>` : ''}
      <div class="table-scroll">
        <table>
          <thead><tr><th>#</th><th>Subdomain</th><th></th></tr></thead>
          <tbody>
            ${list.map((s,i)=>`<tr><td style="color:var(--muted)">${i+1}</td><td>${live && live[s] ? `<span class="live-dot ${live[s].alive?'up':'down'}"></span>`:''}${s}</td><td><a href="https://${s}" target="_blank" class="arrow">↗</a></td></tr>`).join('')}
          </tbody>
        </table>
      </div>
      ${compact ? `<p class="sub vall" style="margin-top:10px;margin-bottom:0;" onclick="switchTab('subdomains')">View all →</p>` :
        `<button class="btn-sec" style="margin-top:10px;" onclick="copySubdomains()">Copy semua ke clipboard</button>`}
    ` : ''}
  </div>`;
}

function copySubdomains(){
  const r = state.results.subdomains;
  if(!r || !r.subs) return;
  navigator.clipboard.writeText(r.subs.join('\n'));
  log('info', 'Daftar subdomain disalin ke clipboard.');
}

/* =========================================================
   02b — SUBDOMAIN RELATIONSHIP GRAPH (network view)
   ========================================================= */
const GRAPH_COLORS = { critical:'#FF5C7A', high:'#FFC24B', medium:'#B8E28C', low:'#33D6C0', root:'#8B7CFF' };

function toggleGraphLevel(level){
  const s = state.filters.graphLevel;
  if(s.has(level)) s.delete(level); else s.add(level);
  renderContent();
}

function showGraphDetail(name, level, tagsStr){
  const box = document.getElementById('graphDetailBox');
  if(!box) return;
  const tags = tagsStr ? tagsStr.split('|').filter(Boolean) : [];
  box.classList.add('show');
  box.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:10px;">
      <div>
        <b style="color:var(--text); word-break:break-all;">${name}</b>
        <div style="margin-top:4px;">${tags.length ? tags.map(t=>`<span class="src-badge">${t}</span>`).join('') : '<span class="src-badge">tidak ada sinyal tambahan</span>'}</div>
      </div>
      <span class="sev ${level}" style="margin-top:0; flex-shrink:0;">${level}</span>
    </div>
    <a href="https://${name}" target="_blank" class="arrow" style="display:inline-block; margin-top:8px; font-size:11px;">Buka host ↗</a>
  `;
}

function renderGraphPanel(){
  const r = state.results.subdomains;
  const domain = state.target;
  if(!r || r.error || !domain){
    return `
    <div class="panel">
      <h2>Peta Subdomain</h2>
      <p class="sub">Visualisasi hubungan antar subdomain sebagai graph — node dihubungkan ke domain utama dan diwarnai berdasarkan tingkat prioritas</p>
      <div class="empty">Jalankan <button class="btn-sec" onclick="runSubdomains()">Subdomain Enum</button> dulu untuk membangun peta.</div>
    </div>`;
  }
  const assets = computeAssetPriority();
  const byName = {}; assets.forEach(a=> byName[a.name]=a);
  const nodes = r.subs.slice(0,80).map(s=> byName[s] || { name:s, level:'low', tags:[] });
  const filtered = nodes.filter(n=>state.filters.graphLevel.has(n.level));

  const W = 760, H = 560, cx = W/2, cy = H/2;
  const ringCount = Math.min(4, Math.max(1, Math.ceil(filtered.length/14)));
  const perRing = Math.ceil(filtered.length / ringCount) || 1;

  let edges = '', nodesSvg = '';
  filtered.forEach((n,i)=>{
    const ring = Math.floor(i/perRing);
    const idxInRing = i % perRing;
    const countInRing = Math.min(perRing, filtered.length - ring*perRing);
    const radius = 60 + ring*((Math.min(W,H)/2 - 70) / ringCount);
    const angle = (idxInRing / countInRing) * Math.PI * 2 + ring*0.35;
    const x = cx + radius * Math.cos(angle);
    const y = cy + radius * Math.sin(angle);
    const color = GRAPH_COLORS[n.level] || GRAPH_COLORS.low;
    const r_ = 5 + Math.min(6, n.tags.length*1.6);
    const label = n.name.length > 22 ? n.name.slice(0,20)+'…' : n.name;
    edges += `<line class="graph-edge" x1="${cx}" y1="${cy}" x2="${x.toFixed(1)}" y2="${y.toFixed(1)}" stroke="${color}" stroke-opacity="0.35"/>`;
    nodesSvg += `
      <g class="graph-node" onclick="showGraphDetail('${n.name.replace(/'/g,"\\'")}','${n.level}','${n.tags.join('|').replace(/'/g,"\\'")}')">
        <circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="${r_}" fill="${color}"><title>${n.name} — ${n.level}</title></circle>
        <text x="${x.toFixed(1)}" y="${(y + r_ + 11).toFixed(1)}" font-size="9" text-anchor="middle">${label}</text>
      </g>`;
  });

  const counts = {critical:0,high:0,medium:0,low:0};
  nodes.forEach(n=>counts[n.level]++);

  return `
  <div class="panel">
    <h2>Peta Subdomain <span style="font-weight:400;font-size:12px;color:var(--muted)">${filtered.length} / ${nodes.length} ditampilkan</span></h2>
    <p class="sub">Setiap node adalah subdomain, terhubung ke domain utama di tengah. Warna = tingkat prioritas dari modul Prioritas Aset. Klik node untuk detail, klik chip untuk filter.</p>
    <div class="filter-row">
      ${['critical','high','medium','low'].map(s=>`
        <span class="chip ${s} ${state.filters.graphLevel.has(s)?'on '+s:''}" onclick="toggleGraphLevel('${s}')">
          <span class="cdot"></span>${s} (${counts[s]})
        </span>`).join('')}
    </div>
    <div class="graph-wrap">
      <svg viewBox="0 0 ${W} ${H}" xmlns="http://www.w3.org/2000/svg">
        ${edges}
        <circle cx="${cx}" cy="${cy}" r="16" fill="${GRAPH_COLORS.root}"><title>${domain} (root)</title></circle>
        <text x="${cx}" y="${cy+30}" font-size="10.5" text-anchor="middle" font-weight="700">${domain}</text>
        ${nodesSvg}
      </svg>
      <div class="graph-legend">
        <div class="li"><span class="sw" style="background:${GRAPH_COLORS.root}"></span>Domain utama</div>
        <div class="li"><span class="sw" style="background:${GRAPH_COLORS.critical}"></span>Critical</div>
        <div class="li"><span class="sw" style="background:${GRAPH_COLORS.high}"></span>High</div>
        <div class="li"><span class="sw" style="background:${GRAPH_COLORS.medium}"></span>Medium</div>
        <div class="li"><span class="sw" style="background:${GRAPH_COLORS.low}"></span>Low</div>
      </div>
    </div>
    <div class="graph-detail" id="graphDetailBox"></div>
  </div>`;
}

/* =========================================================
   03 — TECH FINGERPRINT
   ========================================================= */
const TECH_SIGNATURES = [
  { name:'WordPress', pattern:/wp-content|wp-includes/i, category:'CMS' },
  { name:'Shopify', pattern:/cdn\.shopify\.com|Shopify\.theme/i, category:'E-commerce' },
  { name:'React', pattern:/react(-dom)?\.production|data-reactroot|__REACT_DEVTOOLS/i, category:'Frontend Framework' },
  { name:'Vue.js', pattern:/vue\.js|__vue__|data-v-/i, category:'Frontend Framework' },
  { name:'Next.js', pattern:/__NEXT_DATA__|_next\/static/i, category:'Frontend Framework' },
  { name:'Angular', pattern:/ng-version|angular\.js/i, category:'Frontend Framework' },
  { name:'jQuery', pattern:/jquery(-|\.)[\d\.]*\.js/i, category:'Library' },
  { name:'Bootstrap', pattern:/bootstrap(\.min)?\.css/i, category:'CSS Framework' },
  { name:'Tailwind CSS', pattern:/tailwind/i, category:'CSS Framework' },
  { name:'Cloudflare', pattern:/cloudflare/i, category:'CDN/Security', headerOnly:true },
  { name:'Nginx', pattern:/nginx/i, category:'Web Server', headerOnly:true },
  { name:'Apache', pattern:/apache/i, category:'Web Server', headerOnly:true },
  { name:'PHP', pattern:/x-powered-by:\s*php/i, category:'Backend', headerOnly:true },
  { name:'Google Analytics', pattern:/googletagmanager\.com|google-analytics\.com/i, category:'Analytics' },
  { name:'Google Tag Manager', pattern:/gtm\.js/i, category:'Analytics' },
  { name:'Stripe', pattern:/js\.stripe\.com/i, category:'Payment' },
  { name:'reCAPTCHA', pattern:/recaptcha/i, category:'Security' },
  { name:'Cloudflare Turnstile', pattern:/challenges\.cloudflare\.com\/turnstile/i, category:'Security' },
  { name:'Webpack', pattern:/webpackJsonp|__webpack_require__/i, category:'Build Tool' },
  { name:'Vite', pattern:/\/@vite\/client|vite\.svg/i, category:'Build Tool' },
];

async function runTech(){
  const domain = state.target;
  if(!domain) return;
  log('info', `Mengambil HTML & header untuk fingerprinting teknologi ...`);
  try{
    const res = await fetchViaProxy(`https://${domain}`);
    const html = await res.text();
    const headerStr = Array.from(res.headers.entries()).map(([k,v])=>`${k}: ${v}`).join('\n');
    const combined = html + '\n' + headerStr;
    const found = TECH_SIGNATURES.filter(sig => sig.pattern.test(combined));
    state.results.tech = { domain, found, fetchedAt: new Date().toLocaleString('id-ID') };
    log('ok', `Terdeteksi ${found.length} teknologi dari pattern matching.`);
  }catch(e){
    log('err', `Gagal fingerprint: ${e.message}`);
    state.results.tech = { error: e.message, domain };
  }
  renderStatCards();
  if(state.activeTab==='tech' || state.activeTab==='overview') renderContent();
}

function renderTechPanel(compact){
  const r = state.results.tech;
  const list = r && r.found ? (compact ? r.found.slice(0,6) : r.found) : [];
  const grouped = {};
  if(!compact && r && r.found){ r.found.forEach(t=>{ grouped[t.category] = grouped[t.category]||[]; grouped[t.category].push(t); }); }
  return `
  <div class="panel">
    <h2>Technologies ${r && !r.error ? `<span style="font-weight:400;font-size:12px;color:var(--muted)">${r.found.length}</span>` : ''}</h2>
    <p class="sub">Pattern matching pada HTML source &amp; response header</p>
    ${!r ? `<div class="empty">Belum ada data. <button class="btn-sec" onclick="runTech()">Jalankan fingerprint</button></div>` : ''}
    ${r && r.error ? `<div class="empty">Error: ${r.error}</div>` : ''}
    ${r && !r.error && r.found.length===0 ? `<div class="empty">Tidak ada signature yang cocok.</div>` : ''}
    ${r && !r.error && r.found.length>0 ? (
      compact
      ? list.map(t=>`<div class="row"><div class="k">${t.name}</div><div class="v"><span class="pill info">${t.category}</span></div></div>`).join('')
      : Object.entries(grouped).map(([cat,items])=>`
          <p class="sub" style="margin:14px 0 6px; color:var(--accent-2); text-transform:uppercase; font-size:10.5px; letter-spacing:.5px;">${cat}</p>
          ${items.map(t=>`<div class="row"><div class="k">${t.name}</div><div class="v"><span class="pill info">Detected</span></div></div>`).join('')}
        `).join('')
    ) : ''}
    ${compact && r && !r.error && r.found.length>0 ? `<p class="sub vall" style="margin-top:10px;margin-bottom:0;" onclick="switchTab('tech')">View all technologies →</p>` : ''}
  </div>`;
}

/* =========================================================
   04 — WAYBACK MACHINE URL DISCOVERY
   ========================================================= */
async function runWayback(){
  const domain = state.target;
  if(!domain) return;
  log('info', `Query Wayback Machine CDX API untuk URL historis *.${domain} ...`);
  try{
    const url = `https://web.archive.org/cdx/search/cdx?url=${domain}/*&output=json&collapse=urlkey&limit=500&fl=original,timestamp,statuscode,mimetype`;
    const res = await fetchDirect(url);
    const data = await res.json();
    const rows = data.slice(1);
    const interesting = rows.filter(r=>{
      const u = r[0].toLowerCase();
      return /\.(json|xml|env|bak|old|sql|zip|log|config|yml|yaml)$|\/(api|admin|backup|debug|test|internal|staging|\.git|\.svn)\//.test(u);
    });
    state.results.wayback = { domain, total: rows.length, interesting, sample: rows.slice(0,300), fetchedAt: new Date().toLocaleString('id-ID') };
    log('ok', `${rows.length} URL historis ditemukan, ${interesting.length} di antaranya berpotensi menarik.`);
  }catch(e){
    log('err', `Gagal query Wayback: ${e.message}`);
    state.results.wayback = { error: e.message, domain };
  }
  if(state.activeTab==='wayback' || state.activeTab==='overview') renderContent();
}

function renderWaybackPanel(compact){
  const r = state.results.wayback;
  const list = r && !r.error ? (r.interesting.length ? r.interesting : r.sample) : [];
  const shown = compact ? list.slice(0,5) : null;
  return `
  <div class="panel">
    <h2>Wayback ${r && !r.error ? `<span style="font-weight:400;font-size:12px;color:var(--muted)">${r.total} URL</span>` : ''}</h2>
    <p class="sub">URL historis dari archive.org — sering nemu endpoint lama</p>
    ${!r ? `<div class="empty">Belum ada data. <button class="btn-sec" onclick="runWayback()">Jalankan discovery</button></div>` : ''}
    ${r && r.error ? `<div class="empty">Error: ${r.error}</div>` : ''}
    ${r && !r.error ? (
      compact ? `
        <p class="sub" style="text-transform:uppercase; font-size:10px; color:var(--warn);">Top URLs</p>
        <div class="table-scroll" style="max-height:180px;">
          <table><tbody>${shown.map(row=>`<tr><td>${row[0]}</td></tr>`).join('')}</tbody></table>
        </div>
        <p class="sub vall" style="margin-top:10px;margin-bottom:0;" onclick="switchTab('wayback')">View all →</p>
      ` : `
        <p class="sub">${r.total} URL total tercatat · <b style="color:var(--warn)">${r.interesting.length}</b> pola menarik · ${r.fetchedAt}</p>
        ${r.interesting.length ? `
          <p class="sub" style="color:var(--warn); text-transform:uppercase; font-size:10px;">Berpotensi Menarik</p>
          <div class="table-scroll" style="margin-bottom:16px;">
            <table><tbody>${r.interesting.slice(0,100).map(row=>`<tr><td>${row[0]}</td><td style="color:var(--muted); white-space:nowrap;">${row[2]||''}</td></tr>`).join('')}</tbody></table>
          </div>` : ''}
        <p class="sub" style="text-transform:uppercase; font-size:10px;">Sample URL Lainnya</p>
        <div class="table-scroll">
          <table><tbody>${r.sample.slice(0,80).map(row=>`<tr><td>${row[0]}</td></tr>`).join('')}</tbody></table>
        </div>
      `
    ) : ''}
  </div>`;
}

/* =========================================================
   05 — ROBOTS.TXT / SITEMAP.XML PARSER
   ========================================================= */
async function runRobots(){
  const domain = state.target;
  if(!domain) return;
  log('info', `Mengambil robots.txt & sitemap.xml ...`);
  const result = { domain, robots:null, sitemapUrls:[], disallowed:[], fetchedAt:new Date().toLocaleString('id-ID') };
  try{
    const res = await fetchViaProxy(`https://${domain}/robots.txt`);
    const text = await res.text();
    result.robots = text;
    result.disallowed = text.split('\n').filter(l=>l.trim().toLowerCase().startsWith('disallow')).map(l=>l.split(':').slice(1).join(':').trim()).filter(Boolean);
    const sitemapLines = text.split('\n').filter(l=>l.toLowerCase().startsWith('sitemap:'));
    result.sitemapUrls = sitemapLines.map(l=>l.split(':').slice(1).join(':').trim());
    log('ok', `robots.txt ditemukan: ${result.disallowed.length} Disallow rule, ${result.sitemapUrls.length} sitemap.`);
  }catch(e){
    log('warn', `robots.txt tidak ditemukan/gagal diakses: ${e.message}`);
  }
  if(result.sitemapUrls.length===0){ result.sitemapUrls.push(`https://${domain}/sitemap.xml`); }
  try{
    const smRes = await fetchViaProxy(result.sitemapUrls[0]);
    const smText = await smRes.text();
    const locs = Array.from(smText.matchAll(/<loc>(.*?)<\/loc>/g)).map(m=>m[1]);
    result.sitemapEntries = locs.slice(0,200);
    log('ok', `Sitemap berhasil di-parse: ${locs.length} URL.`);
  }catch(e){
    log('warn', `Sitemap tidak dapat diakses: ${e.message}`);
    result.sitemapEntries = [];
  }
  state.results.robots = result;
  if(state.activeTab==='robots') renderContent();
}

function renderRobotsPanel(){
  const r = state.results.robots;
  return `
  <div class="panel">
    <h2>Robots.txt / Sitemap</h2>
    <p class="sub">Baca aturan crawler &amp; daftar URL resmi</p>
    ${!r ? `<div class="empty">Belum ada data. <button class="btn-sec" onclick="runRobots()">Ambil robots.txt &amp; sitemap</button></div>` : `
      <p class="sub" style="text-transform:uppercase; font-size:10px; color:var(--accent-2);">Disallow Rules (${r.disallowed.length})</p>
      ${r.disallowed.length ? `<div class="table-scroll" style="max-height:180px; margin-bottom:14px;"><table><tbody>${r.disallowed.map(d=>`<tr><td>${d}</td><td><a class="arrow" href="https://${r.domain}${d}" target="_blank">↗</a></td></tr>`).join('')}</tbody></table></div>` : `<div class="empty" style="padding:10px 0;">Tidak ada / tidak terbaca</div>`}
      <p class="sub" style="text-transform:uppercase; font-size:10px; color:var(--accent-2);">Sitemap Entries (${(r.sitemapEntries||[]).length})</p>
      ${r.sitemapEntries && r.sitemapEntries.length ? `<div class="table-scroll"><table><tbody>${r.sitemapEntries.slice(0,80).map(u=>`<tr><td>${u}</td></tr>`).join('')}</tbody></table></div>` : `<div class="empty" style="padding:10px 0;">Sitemap tidak ditemukan</div>`}
    `}
  </div>`;
}

/* =========================================================
   06 — JS ANALYZER (discover JS files + fetch content)
   ========================================================= */
async function discoverJsFiles(domain){
  const urls = new Set();
  try{
    const res = await fetchViaProxy(`https://${domain}`);
    const html = await res.text();
    Array.from(html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)).forEach(m=>{
      let u = m[1];
      if(u.startsWith('//')) u = 'https:' + u;
      else if(u.startsWith('/')) u = `https://${domain}${u}`;
      else if(!/^https?:\/\//i.test(u)) u = `https://${domain}/${u}`;
      urls.add(u);
    });
  }catch(e){ log('warn', `Gagal ambil HTML untuk cari <script src>: ${e.message}`); }
  const wb = state.results.wayback;
  if(wb && !wb.error){
    (wb.sample||[]).concat(wb.interesting||[]).forEach(row=>{
      if(/\.js(\?.*)?$/i.test(row[0])) urls.add(row[0]);
    });
  }
  return Array.from(urls).slice(0,20);
}

async function runJSRecon(){
  const domain = state.target;
  if(!domain) return;
  log('info', `Mencari file JavaScript yang dimuat oleh ${domain} ...`);
  const fileList = await discoverJsFiles(domain);
  const files = [];
  for(const url of fileList){
    try{
      const res = await fetchViaProxy(url);
      const content = await res.text();
      files.push({ url, size: content.length, content });
    }catch(e){
      files.push({ url, size:0, content:'', error: e.message });
    }
  }
  state.results.jsrecon = { domain, files, fetchedAt: new Date().toLocaleString('id-ID') };
  log('ok', `${files.filter(f=>!f.error).length}/${files.length} file JS berhasil diambil untuk dianalisis.`);
  // otomatis jalankan endpoint extractor & secret scanner dari hasil yang sama
  extractEndpoints();
  scanSecrets();
  if(['jsrecon','endpoints','secrets','overview'].includes(state.activeTab)) renderContent();
}

function renderJSPanel(compact){
  const r = state.results.jsrecon;
  const list = r ? (compact ? r.files.slice(0,5) : r.files) : [];
  return `
  <div class="panel">
    <h2>JS Analyzer ${r ? `<span style="font-weight:400;font-size:12px;color:var(--muted)">${r.files.length} file</span>` : ''}</h2>
    <p class="sub">Kumpulkan file JS dari &lt;script src&gt; halaman utama + hasil Wayback</p>
    ${!r ? `<div class="empty">Belum ada data. <button class="btn-sec" onclick="runJSRecon()">Jalankan JS Analyzer</button></div>` : ''}
    ${r ? `
      <div class="table-scroll" style="${compact?'max-height:180px;':''}">
        <table><thead><tr><th>File</th><th>Ukuran</th><th></th></tr></thead><tbody>
          ${list.map(f=>`<tr><td>${f.url}</td><td style="color:var(--muted);white-space:nowrap;">${f.error?'error':(f.size/1024).toFixed(1)+' KB'}</td><td><a class="arrow" href="${f.url}" target="_blank">↗</a></td></tr>`).join('')}
        </tbody></table>
      </div>
      ${compact ? `<p class="sub vall" style="margin-top:10px;margin-bottom:0;" onclick="switchTab('jsrecon')">View all →</p>` : `<p class="sub" style="margin-top:12px;">Endpoint &amp; secret di dalam file-file ini otomatis dianalisis di tab <b style="color:var(--text)">Endpoints</b> dan <b style="color:var(--text)">Secret Scanner</b>.</p>`}
    ` : ''}
  </div>`;
}

/* =========================================================
   07 — ENDPOINT EXPLORER (extraction + kategori + parameter + konteks)
   ========================================================= */
const ENDPOINT_CATS = [
  { id:'auth',    re:/\/(auth|login|logout|signin|signup|register|password|token|oauth|sso)/i },
  { id:'admin',   re:/\/(admin|internal|dashboard|manage|backoffice)/i },
  { id:'graphql', re:/\/(graphql|gql)/i },
  { id:'api',     re:/\/(api|v[0-9]|rest)/i },
];
function categorizeEndpoint(p){
  for(const c of ENDPOINT_CATS){ if(c.re.test(p)) return c.id; }
  return 'other';
}
function extractParams(p){
  const qIdx = p.indexOf('?');
  if(qIdx===-1) return [];
  try{
    const qs = p.slice(qIdx+1);
    return Array.from(new Set(qs.split('&').map(pair=>pair.split('=')[0]).filter(Boolean)));
  }catch(e){ return []; }
}
function findContext(content, needle){
  const i = content.indexOf(needle);
  if(i===-1) return '';
  const start = Math.max(0, i-40);
  const end = Math.min(content.length, i+needle.length+40);
  return (start>0?'…':'') + content.slice(start,end).replace(/\s+/g,' ') + (end<content.length?'…':'');
}

function extractEndpoints(){
  const r = state.results.jsrecon;
  if(!r) return;
  const found = new Set();
  const pathRe = /["'`](\/(?:api|v[0-9]|admin|internal|graphql|auth|user|users|account|upload|download|config|settings|dashboard|payment|order|orders|search|webhook|callback)[a-zA-Z0-9_\-\/.?=&%]{0,100})["'`]/gi;
  const urlRe = /https?:\/\/[a-zA-Z0-9_\-.]+\.[a-zA-Z]{2,}(?:\/[a-zA-Z0-9_\-\/.%?=&]{0,120})?/g;
  r.files.forEach(f=>{
    if(!f.content) return;
    Array.from(f.content.matchAll(pathRe)).forEach(m=>found.add(JSON.stringify({p:m[1], src:f.url})));
    Array.from(f.content.matchAll(urlRe)).forEach(m=>{
      if(m[0].includes(r.domain)) found.add(JSON.stringify({p:m[0], src:f.url}));
    });
  });
  const list = Array.from(found).map(s=>JSON.parse(s));
  const dedup = [];
  const seen = new Set();
  const allParams = new Set();
  list.forEach(item=>{
    if(seen.has(item.p)) return;
    seen.add(item.p);
    const file = r.files.find(f=>f.url===item.src);
    const params = extractParams(item.p);
    params.forEach(pn=>allParams.add(pn));
    dedup.push({
      p: item.p, src: item.src,
      cat: categorizeEndpoint(item.p),
      params,
      context: file && file.content ? findContext(file.content, item.p) : ''
    });
  });
  state.results.endpoints = {
    domain: r.domain, list: dedup, params: Array.from(allParams),
    fetchedAt: new Date().toLocaleString('id-ID')
  };
  log('ok', `${dedup.length} kandidat endpoint & ${allParams.size} parameter unik diekstrak dari JS.`);
}

function filteredEndpoints(){
  const r = state.results.endpoints;
  if(!r) return [];
  const q = (state.filters.endpointsQuery||'').toLowerCase();
  return r.list.filter(e=>
    state.filters.endpointsCat.has(e.cat) &&
    (!q || e.p.toLowerCase().includes(q) || e.src.toLowerCase().includes(q))
  );
}

function onEndpointSearch(val){
  state.filters.endpointsQuery = val;
  renderEndpointsListOnly();
}
function toggleEndpointCat(cat){
  const s = state.filters.endpointsCat;
  if(s.has(cat)) s.delete(cat); else s.add(cat);
  renderContent();
}
function renderEndpointsListOnly(){
  const box = document.getElementById('endpointsListBox');
  if(!box) return;
  const list = filteredEndpoints();
  box.innerHTML = renderEndpointRows(list, false);
}
function renderEndpointRows(list, compact){
  if(list.length===0) return `<div class="empty">Tidak ada endpoint yang cocok dengan filter/pencarian saat ini.</div>`;
  const rows = compact ? list.slice(0,5) : list;
  return `
  <div class="table-scroll" style="${compact?'max-height:180px;':'max-height:420px;'}">
    <table><thead><tr><th>Endpoint</th><th>Kategori</th><th>Param</th><th>Sumber</th></tr></thead><tbody>
      ${rows.map(e=>`
        <tr title="${e.context ? e.context.replace(/"/g,'&quot;') : ''}">
          <td style="word-break:break-all;">${e.p}</td>
          <td><span class="pill ${e.cat==='admin'||e.cat==='auth'?'bad':e.cat==='graphql'?'warn':'info'}">${e.cat}</span></td>
          <td style="color:var(--muted); font-size:10.5px;">${e.params.length ? e.params.join(', ') : '—'}</td>
          <td style="color:var(--muted); font-size:10.5px;">${e.src.split('/').pop()}</td>
        </tr>`).join('')}
    </tbody></table>
  </div>`;
}

function renderEndpointsPanel(compact){
  const r = state.results.endpoints;
  const catCounts = { api:0, admin:0, auth:0, graphql:0, other:0 };
  if(r) r.list.forEach(e=>catCounts[e.cat]++);
  const list = r ? filteredEndpoints() : [];
  return `
  <div class="panel">
    <h2>Endpoint Explorer ${r ? `<span style="font-weight:400;font-size:12px;color:var(--muted)">${r.list.length} total · ${r.params.length} parameter unik</span>` : ''}</h2>
    <p class="sub">Path &amp; URL yang disebut di dalam kode JS, dikategorikan otomatis, lengkap parameter &amp; konteks kemunculan</p>
    ${!r ? `<div class="empty">Jalankan <button class="btn-sec" onclick="runJSRecon()">JS Analyzer</button> dulu untuk mengekstrak endpoint.</div>` : ''}
    ${r ? `
      ${compact ? '' : `
      <div class="search-wrap">
        <span>🔎</span>
        <input type="text" placeholder="Cari endpoint atau nama file sumber..." value="${state.filters.endpointsQuery||''}" oninput="onEndpointSearch(this.value)">
      </div>
      <div class="filter-row">
        ${['api','admin','auth','graphql','other'].map(c=>`
          <span class="chip neutral ${state.filters.endpointsCat.has(c)?'on neutral':''}" onclick="toggleEndpointCat('${c}')">
            <span class="cdot"></span>${c} (${catCounts[c]})
          </span>`).join('')}
      </div>`}
      <div id="endpointsListBox">${renderEndpointRows(list, compact)}</div>
      ${compact ? `<p class="sub vall" style="margin-top:10px;margin-bottom:0;" onclick="switchTab('endpoints')">View all →</p>` : `<button class="btn-sec" style="margin-top:10px;" onclick="copyEndpoints()">Copy semua ke clipboard</button>`}
    ` : ''}
  </div>`;
}

function copyEndpoints(){
  const r = state.results.endpoints;
  if(!r) return;
  navigator.clipboard.writeText(filteredEndpoints().map(e=>e.p).join('\n'));
  log('info', 'Daftar endpoint (sesuai filter aktif) disalin ke clipboard.');
}

/* =========================================================
   08 — SECRET SCANNER
   ========================================================= */
const SECRET_PATTERNS = [
  { name:'AWS Access Key ID',       re:/AKIA[0-9A-Z]{16}/g,                              sev:'critical' },
  { name:'Google API Key',          re:/AIza[0-9A-Za-z\-_]{35}/g,                         sev:'high' },
  { name:'Stripe Live Secret Key',  re:/sk_live_[0-9a-zA-Z]{16,}/g,                       sev:'critical' },
  { name:'Slack Token',             re:/xox[baprs]-[0-9A-Za-z-]{10,}/g,                   sev:'high' },
  { name:'Firebase URL',            re:/[a-z0-9-]+\.firebaseio\.com/g,                    sev:'medium' },
  { name:'JWT Token',               re:/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, sev:'medium' },
  { name:'Generic Bearer Token',    re:/[Bb]earer\s+[A-Za-z0-9\-_.=]{15,}/g,              sev:'medium' },
  { name:'Private Key Block',       re:/-----BEGIN (RSA |EC )?PRIVATE KEY-----/g,         sev:'critical' },
  { name:'Hardcoded Password Var',  re:/(password|passwd|pwd)\s*[:=]\s*["'][^"'\s]{4,}["']/gi, sev:'high' },
  { name:'Hardcoded Secret/API Key Var', re:/(secret|api[_-]?key|access[_-]?token)\s*[:=]\s*["'][A-Za-z0-9\-_]{10,}["']/gi, sev:'high' },
];

function redact(s){
  if(s.length<=10) return s;
  return s.slice(0,6) + '…' + s.slice(-4);
}

function scanSecrets(){
  const r = state.results.jsrecon;
  if(!r) return;
  const findings = [];
  r.files.forEach(f=>{
    if(!f.content) return;
    SECRET_PATTERNS.forEach(pat=>{
      const matches = f.content.match(pat.re);
      if(matches){
        matches.slice(0,10).forEach(m=>findings.push({ type:pat.name, sev:pat.sev, snippet: redact(m), src: f.url }));
      }
    });
  });
  state.results.secrets = { domain: r.domain, findings, fetchedAt: new Date().toLocaleString('id-ID') };
  log(findings.length ? 'warn' : 'ok', `${findings.length} indikasi secret ditemukan di file JS (perlu verifikasi manual, rawan false-positive).`);
}

function toggleSecretSev(sev){
  const s = state.filters.secretsSev;
  if(s.has(sev)) s.delete(sev); else s.add(sev);
  renderContent();
}
function renderSecretsPanel(compact){
  const r = state.results.secrets;
  const filtered = r ? r.findings.filter(f=>state.filters.secretsSev.has(f.sev)) : [];
  const list = compact ? filtered.slice(0,4) : filtered;
  const counts = {critical:0, high:0, medium:0};
  if(r) r.findings.forEach(f=> counts[f.sev]!==undefined && counts[f.sev]++);
  return `
  <div class="panel">
    <h2>Secret Scanner ${r ? `<span style="font-weight:400;font-size:12px;color:var(--muted)">${filtered.length} / ${r.findings.length}</span>` : ''}</h2>
    <p class="sub">Pattern matching untuk kredensial/token yang ter-hardcode di JS. Bisa false-positive — verifikasi manual sebelum dilaporkan.</p>
    ${!r ? `<div class="empty">Jalankan <button class="btn-sec" onclick="runJSRecon()">JS Analyzer</button> dulu untuk memindai secret.</div>` : ''}
    ${r && !compact ? `
    <div class="filter-row">
      ${['critical','high','medium'].map(s=>`
        <span class="chip ${s} ${state.filters.secretsSev.has(s)?'on '+s:''}" onclick="toggleSecretSev('${s}')">
          <span class="cdot"></span>${s} (${counts[s]})
        </span>`).join('')}
    </div>` : ''}
    ${r && filtered.length===0 ? `<div class="empty">${r.findings.length===0?'Tidak ada indikasi secret ditemukan. 👍':'Tidak ada temuan pada severity yang dipilih.'}</div>` : ''}
    ${r && filtered.length>0 ? list.map(f=>`
      <div class="check-item" style="cursor:default;">
        <div style="width:100%;">
          <div class="ti">${f.type}</div>
          <div class="de">Sumber: ${f.src.split('/').pop()}</div>
          <div class="snippet">${f.snippet}</div>
          <span class="sev ${f.sev}">${f.sev}</span>
        </div>
      </div>`).join('') : ''}
    ${compact && filtered.length>4 ? `<p class="sub vall" style="margin-top:4px;margin-bottom:0;" onclick="switchTab('secrets')">View all →</p>` : ''}
  </div>`;
}

/* =========================================================
   09 — API DISCOVERY + GRAPHQL DETECTION
   ========================================================= */
const API_PATHS = ['/api','/api/v1','/api/v2','/api/v3','/rest','/v1','/v2','/api/health','/api/status','/swagger.json','/swagger-ui','/openapi.json','/.well-known/openapi.json'];
const GRAPHQL_PATHS = ['/graphql','/api/graphql','/graphql/console','/v1/graphql','/gql'];

async function probePath(domain, path){
  try{
    const res = await fetchViaProxy(`https://${domain}${path}`);
    const text = await res.text();
    return { path, status: res.status, ok: res.status < 400, snippet: text.slice(0,120) };
  }catch(e){
    return { path, status: null, ok:false, error: e.message };
  }
}

async function runAPIDiscovery(){
  const domain = state.target;
  if(!domain) return;
  log('info', `Probing path API umum & endpoint GraphQL di ${domain} ...`);
  const apiResults = [];
  for(const p of API_PATHS){ apiResults.push(await probePath(domain, p)); }
  const graphqlResults = [];
  for(const p of GRAPHQL_PATHS){ graphqlResults.push(await probePath(domain, p)); }
  const apiFound = apiResults.filter(r=>r.ok);
  const graphqlFound = graphqlResults.filter(r=> r.ok && /query|graphql|typename/i.test(r.snippet||''));
  state.results.api = { domain, apiResults, graphqlResults, apiFound, graphqlFound, fetchedAt: new Date().toLocaleString('id-ID') };
  log('ok', `${apiFound.length} path API merespons, ${graphqlFound.length} indikasi endpoint GraphQL aktif.`);
  if(state.activeTab==='api' || state.activeTab==='overview') renderContent();
}

function renderAPIPanel(compact){
  const r = state.results.api;
  return `
  <div class="panel">
    <h2>API &amp; GraphQL Discovery</h2>
    <p class="sub">Probe pasif ke path API &amp; GraphQL yang umum dipakai (GET saja, tanpa payload)</p>
    ${!r ? `<div class="empty">Belum ada data. <button class="btn-sec" onclick="runAPIDiscovery()">Jalankan discovery</button></div>` : ''}
    ${r ? `
      <p class="sub" style="text-transform:uppercase; font-size:10px; color:var(--accent-2);">Path API Merespons (${r.apiFound.length})</p>
      ${r.apiFound.length ? `<div class="table-scroll" style="margin-bottom:14px;"><table><tbody>${r.apiFound.map(x=>`<tr><td>${x.path}</td><td><span class="pill ok">${x.status}</span></td></tr>`).join('')}</tbody></table></div>` : `<div class="empty" style="padding:8px 0;">Tidak ada path yang merespons OK</div>`}
      <p class="sub" style="text-transform:uppercase; font-size:10px; color:var(--warn);">GraphQL Endpoint Aktif (${r.graphqlFound.length})</p>
      ${r.graphqlFound.length ? `<div class="table-scroll"><table><tbody>${r.graphqlFound.map(x=>`<tr><td>${x.path}</td><td><span class="pill warn">${x.status}</span></td></tr>`).join('')}</tbody></table></div>` : `<div class="empty" style="padding:8px 0;">Tidak terdeteksi endpoint GraphQL</div>`}
      ${!compact ? `<p class="sub" style="margin-top:14px;">Catatan: deteksi ini pasif (GET request biasa). Untuk introspection query &amp; pengujian mendalam, gunakan tool manual seperti GraphQL Voyager / Burp Suite pada endpoint yang scope-nya sudah diizinkan.</p>` : ''}
    ` : ''}
  </div>`;
}

/* =========================================================
   10 — CORS MISCONFIGURATION CHECKER
   ========================================================= */
async function runCORS(){
  const domain = state.target;
  if(!domain) return;
  log('info', `Mengecek header CORS di response ${domain} ...`);
  try{
    const res = await fetchViaProxy(`https://${domain}`);
    const acao = res.headers.get('access-control-allow-origin');
    const acac = res.headers.get('access-control-allow-credentials');
    const issues = [];
    if(acao === '*' && acac === 'true') issues.push({ sev:'critical', msg:'ACAO "*" dikombinasikan dengan ACAC "true" — kombinasi ini seharusnya ditolak browser, tapi kalau server benar-benar mengirim keduanya, itu misconfiguration serius.' });
    else if(acao === '*') issues.push({ sev:'low', msg:'ACAO "*" — akses publik, wajar untuk API publik tapi periksa apakah endpoint ini seharusnya publik.' });
    else if(acao) issues.push({ sev:'medium', msg:`ACAO diset ke origin spesifik: "${acao}" — perlu diuji manual apakah server me-reflect origin arbitrary (kirim Origin custom via curl/Burp, bandingkan responsnya).` });
    else issues.push({ sev:'low', msg:'Tidak ada header Access-Control-Allow-Origin pada request GET biasa ke root. Endpoint API spesifik (bukan root) mungkin punya konfigurasi berbeda — cek satu-satu.' });
    state.results.cors = { domain, acao, acac, issues, fetchedAt: new Date().toLocaleString('id-ID') };
    log('ok', `Pengecekan CORS selesai — ${issues.length} catatan.`);
  }catch(e){
    log('err', `Gagal cek CORS: ${e.message}`);
    state.results.cors = { error: e.message, domain };
  }
  if(state.activeTab==='cors' || state.activeTab==='overview') renderContent();
}

function renderCORSPanel(){
  const r = state.results.cors;
  return `
  <div class="panel">
    <h2>CORS Misconfiguration Checker</h2>
    <p class="sub">Observasi header CORS pasif. Origin-reflection testing aktif butuh tool manual (browser tidak bisa spoof header Origin).</p>
    ${!r ? `<div class="empty">Belum ada data. <button class="btn-sec" onclick="runCORS()">Cek header CORS</button></div>` : ''}
    ${r && r.error ? `<div class="empty">Error: ${r.error}</div>` : ''}
    ${r && !r.error ? `
      <div class="row"><div class="k">Access-Control-Allow-Origin</div><div class="v">${r.acao || '(tidak ada)'}</div></div>
      <div class="row"><div class="k">Access-Control-Allow-Credentials</div><div class="v">${r.acac || '(tidak ada)'}</div></div>
      ${r.issues.map(i=>`<div class="check-item" style="cursor:default; margin-top:10px;"><div><div class="de">${i.msg}</div><span class="sev ${i.sev}">${i.sev}</span></div></div>`).join('')}
    ` : ''}
  </div>`;
}

/* =========================================================
   11 — SUBDOMAIN SCREENSHOT GALLERY (via WordPress mshots)
   ========================================================= */
const LIVE_CHECK_LIMIT = 20;

async function checkHostLive(host){
  try{
    const res = await fetchViaProxy(`https://${host}`);
    return { alive: res.status < 400, status: res.status };
  }catch(e){
    return { alive: false, status: null };
  }
}

async function runLiveCheck(){
  const domain = state.target;
  if(!domain) return;
  const subsAll = state.results.subdomains && !state.results.subdomains.error ? state.results.subdomains.subs : [];
  const candidates = [domain, ...subsAll.filter(s=>s!==domain)].slice(0, LIVE_CHECK_LIMIT);
  log('info', `Mengecek status aktif untuk ${candidates.length} host (dibatasi agar tidak membebani proxy publik)...`);
  const subLive = state.results.subLive || {};
  for(const host of candidates){
    subLive[host] = await checkHostLive(host);
  }
  state.results.subLive = subLive;
  const aliveCount = Object.values(subLive).filter(v=>v.alive).length;
  log('ok', `${aliveCount}/${candidates.length} host merespons aktif (status &lt; 400).`);
  if(['subdomains','shots','overview'].includes(state.activeTab)) renderContent();
  return subLive;
}

async function runScreenshots(){
  const domain = state.target;
  if(!domain) return;
  if(!state.results.subLive){
    log('info', 'Belum ada data status aktif — menjalankan pengecekan host dulu sebelum screenshot...');
    await runLiveCheck();
  }
  const subsAll = state.results.subdomains && !state.results.subdomains.error ? state.results.subdomains.subs : [];
  const pool = [domain, ...subsAll.filter(s=>s!==domain)];
  const live = state.results.subLive || {};
  const activeOnly = pool.filter(h => live[h] ? live[h].alive : true); // host belum dicek dianggap tetap ditampilkan
  const targets = activeOnly.slice(0,12);
  state.results.shots = { domain, targets, fetchedAt: new Date().toLocaleString('id-ID') };
  log('ok', `Menyiapkan ${targets.length} screenshot untuk host yang terdeteksi aktif (via mshots.wordpress.com, gratis & tanpa API key).`);
  if(state.activeTab==='shots') renderContent();
}

function renderScreenshotsPanel(){
  const r = state.results.shots;
  const live = state.results.subLive;
  return `
  <div class="panel">
    <h2>Subdomain Screenshot Gallery</h2>
    <p class="sub">Preview visual tiap host <b style="color:var(--text)">yang terdeteksi aktif</b> (HTTP respons &lt; 400) — bantu prioritaskan target mana yang punya panel admin/UI menarik. Screenshot via layanan publik mshots (WordPress).</p>
    ${!live ? `<div class="empty">Belum ada pengecekan status host. <button class="btn-sec" onclick="runScreenshots()">Cek host aktif &amp; buat galeri</button></div>` : ''}
    ${live && !r ? `<div class="empty">Belum ada galeri. <button class="btn-sec" onclick="runScreenshots()">Buat galeri</button></div>` : ''}
    ${r ? `
    <p class="sub" style="margin-bottom:10px;">${r.targets.length} host aktif dari ${Object.keys(live||{}).length} yang dicek · <span class="vall" onclick="runScreenshots()">refresh galeri</span></p>
    <div class="shot-grid">
      ${r.targets.map(t=>`
        <div class="shot-card">
          <img loading="lazy" src="https://s.wordpress.com/mshots/v1/${encodeURIComponent('https://'+t)}?w=400" alt="${t}">
          <div class="cap"><span class="live-dot up"></span>${t}</div>
        </div>`).join('')}
    </div>` : ''}
  </div>`;
}

/* =========================================================
   12 — FAVICON HASH (Shodan-style mmh3, untuk http.favicon.hash search)
   ========================================================= */
function mmh3_32(key, seed){
  seed = seed || 0;
  const c1 = 0xcc9e2d51, c2 = 0x1b873593;
  let h1 = seed >>> 0;
  const len = key.length;
  const nBlocks = Math.floor(len/4);
  for(let i=0;i<nBlocks;i++){
    let k1 = (key.charCodeAt(i*4) & 0xff) |
             ((key.charCodeAt(i*4+1) & 0xff) << 8) |
             ((key.charCodeAt(i*4+2) & 0xff) << 16) |
             ((key.charCodeAt(i*4+3) & 0xff) << 24);
    k1 = Math.imul(k1, c1); k1 = (k1 << 15) | (k1 >>> 17); k1 = Math.imul(k1, c2);
    h1 ^= k1; h1 = (h1 << 13) | (h1 >>> 19); h1 = (Math.imul(h1, 5) + 0xe6546b64) | 0;
  }
  let k1 = 0;
  const tailIdx = nBlocks*4;
  const rem = len & 3;
  if(rem === 3) k1 ^= (key.charCodeAt(tailIdx+2) & 0xff) << 16;
  if(rem >= 2) k1 ^= (key.charCodeAt(tailIdx+1) & 0xff) << 8;
  if(rem >= 1){
    k1 ^= (key.charCodeAt(tailIdx) & 0xff);
    k1 = Math.imul(k1, c1); k1 = (k1 << 15) | (k1 >>> 17); k1 = Math.imul(k1, c2);
    h1 ^= k1;
  }
  h1 ^= len;
  h1 ^= h1 >>> 16; h1 = Math.imul(h1, 0x85ebca6b);
  h1 ^= h1 >>> 13; h1 = Math.imul(h1, 0xc2b2ae35);
  h1 ^= h1 >>> 16;
  return h1 | 0; // signed 32-bit, sama seperti output mmh3.hash() Python
}

function base64PyStyle(b64){
  // replikasi python base64.encodestring(): newline tiap 76 karakter + newline penutup
  let out = '';
  for(let i=0;i<b64.length;i+=76){ out += b64.slice(i,i+76) + '\n'; }
  return out;
}

async function runFavicon(){
  const domain = state.target;
  if(!domain) return;
  log('info', `Mengambil favicon.ico dari ${domain} ...`);
  try{
    const res = await fetchViaProxy(`https://${domain}/favicon.ico`);
    const buf = await res.arrayBuffer();
    if(buf.byteLength === 0) throw new Error('favicon.ico kosong / tidak ditemukan');
    const bytes = new Uint8Array(buf);
    let binary = '';
    for(let i=0;i<bytes.length;i++) binary += String.fromCharCode(bytes[i]);
    const b64 = btoa(binary);
    const pyB64 = base64PyStyle(b64);
    const hash = mmh3_32(pyB64, 0);
    state.results.favicon = { domain, hash, size: bytes.length, fetchedAt: new Date().toLocaleString('id-ID') };
    log('ok', `Favicon hash: ${hash} (kompatibel dengan pencarian http.favicon.hash di Shodan/Censys).`);
  }catch(e){
    log('warn', `Gagal ambil favicon: ${e.message}`);
    state.results.favicon = { error: e.message, domain };
  }
  if(state.activeTab==='favicon') renderContent();
}

function renderFaviconPanel(){
  const r = state.results.favicon;
  return `
  <div class="panel">
    <h2>Favicon Hash</h2>
    <p class="sub">Hash mmh3 dari favicon.ico — kompatibel dengan format pencarian http.favicon.hash di Shodan, berguna untuk cari aset lain dengan favicon sama (misal instance internal/staging).</p>
    ${!r ? `<div class="empty">Belum ada data. <button class="btn-sec" onclick="runFavicon()">Hitung favicon hash</button></div>` : ''}
    ${r && r.error ? `<div class="empty">Error: ${r.error}</div>` : ''}
    ${r && !r.error ? `
      <div class="row"><div class="k">Favicon Hash (mmh3)</div><div class="v" style="font-family:'JetBrains Mono',monospace; font-weight:700;">${r.hash}</div></div>
      <div class="row"><div class="k">Ukuran File</div><div class="v">${r.size} byte</div></div>
      <a class="qa-btn" style="margin-top:12px;" target="_blank" href="https://www.shodan.io/search?query=http.favicon.hash%3A${r.hash}"><span class="ic">↗</span>Cari hash ini di Shodan</a>
    ` : ''}
  </div>`;
}

/* =========================================================
   13 — ASN & IP VISUALIZATION (DNS-over-HTTPS + ipwho.is)
   ========================================================= */
async function runASN(){
  const domain = state.target;
  if(!domain) return;
  log('info', `Resolve IP untuk ${domain} via DNS-over-HTTPS ...`);
  try{
    const dnsRes = await fetchDirect(`https://dns.google/resolve?name=${domain}&type=A`);
    const dnsData = await dnsRes.json();
    const ip = dnsData.Answer ? dnsData.Answer.find(a=>a.type===1)?.data : null;
    if(!ip) throw new Error('Tidak ada A record ditemukan');
    log('info', `IP: ${ip} — mengambil info ASN/organisasi ...`);
    const geoRes = await fetchDirect(`https://ipwho.is/${ip}`);
    const geo = await geoRes.json();
    state.results.asn = {
      domain, ip,
      asn: geo.connection?.asn, org: geo.connection?.org || geo.connection?.isp,
      country: geo.country, city: geo.city, region: geo.region,
      fetchedAt: new Date().toLocaleString('id-ID')
    };
    log('ok', `ASN AS${geo.connection?.asn} — ${geo.connection?.org || geo.connection?.isp} (${geo.country}).`);
  }catch(e){
    log('err', `Gagal resolve ASN/IP: ${e.message}`);
    state.results.asn = { error: e.message, domain };
  }
  if(state.activeTab==='asn' || state.activeTab==='overview') renderContent();
}

function renderASNPanel(){
  const r = state.results.asn;
  return `
  <div class="panel">
    <h2>ASN &amp; IP Visualization</h2>
    <p class="sub">Resolve via Google DNS-over-HTTPS, lalu lookup ASN/organisasi via ipwho.is (100% pasif, tanpa API key)</p>
    ${!r ? `<div class="empty">Belum ada data. <button class="btn-sec" onclick="runASN()">Resolve IP &amp; ASN</button></div>` : ''}
    ${r && r.error ? `<div class="empty">Error: ${r.error}</div>` : ''}
    ${r && !r.error ? `
      <div class="row"><div class="k">IP Address</div><div class="v">${r.ip}</div></div>
      <div class="row"><div class="k">ASN</div><div class="v">AS${r.asn||'-'}</div></div>
      <div class="row"><div class="k">Organisasi / ISP</div><div class="v">${r.org||'-'}</div></div>
      <div class="row"><div class="k">Negara</div><div class="v">${r.country||'-'}</div></div>
      <div class="row"><div class="k">Kota/Region</div><div class="v">${[r.city,r.region].filter(Boolean).join(', ')||'-'}</div></div>
      <a class="qa-btn" style="margin-top:12px;" target="_blank" href="https://www.shodan.io/host/${r.ip}"><span class="ic">↗</span>Lihat host ini di Shodan</a>
    ` : ''}
  </div>`;
}

/* =========================================================
   14 — SUMBER RECON TAMBAHAN (Common Crawl + AlienVault OTX)
   digabung ke daftar subdomain & wayback yang sudah ada
   ========================================================= */
async function runSources(){
  const domain = state.target;
  if(!domain) return;
  log('info', `Query Common Crawl, AlienVault OTX, GitHub &amp; urlscan.io untuk ${domain} ...`);
  const sources = { domain, commoncrawl: [], otxSubdomains: [], otxUrls: [], github: [], urlscan: [], fetchedAt: new Date().toLocaleString('id-ID'), errors: [] };

  try{
    const ccRes = await fetchDirect(`https://index.commoncrawl.org/CC-MAIN-2024-51-index?url=${domain}/*&output=json&limit=200`);
    const ccText = await ccRes.text();
    const lines = ccText.trim().split('\n').filter(Boolean);
    sources.commoncrawl = lines.map(l=>{ try{ return JSON.parse(l).url; }catch{ return null; } }).filter(Boolean);
    log('ok', `Common Crawl: ${sources.commoncrawl.length} URL ditemukan.`);
  }catch(e){
    sources.errors.push('Common Crawl: ' + e.message);
    log('warn', `Common Crawl gagal/limit index kadaluarsa: ${e.message}`);
  }

  try{
    const otxRes = await fetchDirect(`https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns`);
    const otxData = await otxRes.json();
    const hosts = new Set();
    (otxData.passive_dns||[]).forEach(r=>{ if(r.hostname) hosts.add(r.hostname.toLowerCase()); });
    sources.otxSubdomains = Array.from(hosts);
    log('ok', `AlienVault OTX passive DNS: ${sources.otxSubdomains.length} host ditemukan.`);
  }catch(e){
    sources.errors.push('AlienVault OTX: ' + e.message);
    log('warn', `AlienVault OTX gagal diakses: ${e.message}`);
  }

  try{
    // Pencarian repository publik (bukan code search, agar tidak butuh token auth)
    const ghRes = await fetchDirect(`https://api.github.com/search/repositories?q=${encodeURIComponent('"'+domain+'"')}+in:readme,description&per_page=15`);
    const ghData = await ghRes.json();
    sources.github = (ghData.items||[]).map(it=>({ name: it.full_name, url: it.html_url, desc: it.description||'' }));
    log('ok', `GitHub: ${sources.github.length} repo publik menyebut domain ini.`);
  }catch(e){
    sources.errors.push('GitHub: ' + e.message);
    log('warn', `GitHub search gagal/rate-limit (unauthenticated, 10 req/menit): ${e.message}`);
  }

  try{
    const usRes = await fetchDirect(`https://urlscan.io/api/v1/search/?q=domain:${domain}&size=50`);
    const usData = await usRes.json();
    sources.urlscan = (usData.results||[]).map(it=>({ url: it.page && it.page.url, ip: it.page && it.page.ip, scannedAt: it.task && it.task.time }));
    log('ok', `urlscan.io: ${sources.urlscan.length} hasil scan publik ditemukan.`);
  }catch(e){
    sources.errors.push('urlscan.io: ' + e.message);
    log('warn', `urlscan.io gagal diakses: ${e.message}`);
  }

  // merge ke subdomain list yang sudah ada supaya makin lengkap
  if(state.results.subdomains && !state.results.subdomains.error){
    const set = new Set(state.results.subdomains.subs);
    sources.otxSubdomains.forEach(h=>{ if(h.endsWith(domain)) set.add(h); });
    sources.urlscan.forEach(u=>{ try{ const h = new URL(u.url).hostname.toLowerCase(); if(h.endsWith(domain)) set.add(h); }catch(e){} });
    state.results.subdomains.subs = Array.from(set).sort();
    state.results.subdomains.count = state.results.subdomains.subs.length;
  }

  state.results.sources = sources;
  log('ok', `Agregasi sumber selesai — ${sources.commoncrawl.length + sources.otxSubdomains.length + sources.github.length + sources.urlscan.length} data tambahan dari 4 sumber.`);
  renderStatCards();
  if(state.activeTab==='sources' || state.activeTab==='overview' || state.activeTab==='subdomains') renderContent();
}

function renderSourcesPanel(){
  const r = state.results.sources;
  return `
  <div class="panel">
    <h2>Sumber Recon Tambahan</h2>
    <p class="sub">Agregasi dari beberapa sumber pasif publik (Wayback, crt.sh, Common Crawl, AlienVault OTX, GitHub, urlscan.io) — hasil digabung otomatis ke daftar Subdomains</p>
    <div style="margin-bottom:14px;">
      <span class="src-badge">crt.sh <b>${state.results.subdomains && !state.results.subdomains.error ? state.results.subdomains.count : 0}</b></span>
      <span class="src-badge">Wayback <b>${state.results.wayback && !state.results.wayback.error ? state.results.wayback.total : 0}</b></span>
      <span class="src-badge">Common Crawl <b>${r ? r.commoncrawl.length : 0}</b></span>
      <span class="src-badge">AlienVault OTX <b>${r ? r.otxSubdomains.length : 0}</b></span>
      <span class="src-badge">GitHub <b>${r ? r.github.length : 0}</b></span>
      <span class="src-badge">urlscan.io <b>${r ? r.urlscan.length : 0}</b></span>
    </div>
    ${!r ? `<div class="empty">Belum ada data. <button class="btn-sec" onclick="runSources()">Jalankan agregasi sumber</button></div>` : ''}
    ${r && r.errors.length ? `<p class="sub" style="color:var(--warn);">${r.errors.join(' · ')}</p>` : ''}
    ${r ? `
      <p class="sub" style="text-transform:uppercase; font-size:10px; color:var(--accent-2);">AlienVault OTX — Passive DNS Hosts</p>
      ${r.otxSubdomains.length ? `<div class="table-scroll" style="max-height:180px; margin-bottom:14px;"><table><tbody>${r.otxSubdomains.slice(0,50).map(h=>`<tr><td>${h}</td></tr>`).join('')}</tbody></table></div>` : `<div class="empty" style="padding:8px 0;">Tidak ada data</div>`}
      <p class="sub" style="text-transform:uppercase; font-size:10px; color:var(--accent-2);">GitHub — Repo Publik yang Menyebut Domain</p>
      ${r.github.length ? `<div class="table-scroll" style="max-height:180px; margin-bottom:14px;"><table><tbody>${r.github.map(g=>`<tr><td><a href="${g.url}" target="_blank" class="arrow">${g.name}</a><br><small style="color:var(--muted)">${g.desc||''}</small></td></tr>`).join('')}</tbody></table></div>` : `<div class="empty" style="padding:8px 0;">Tidak ada data / rate-limit GitHub tercapai</div>`}
      <p class="sub" style="text-transform:uppercase; font-size:10px; color:var(--accent-2);">urlscan.io — Hasil Scan Publik</p>
      ${r.urlscan.length ? `<div class="table-scroll" style="max-height:180px; margin-bottom:14px;"><table><tbody>${r.urlscan.slice(0,50).map(u=>`<tr><td>${u.url||'-'}</td><td style="color:var(--muted); font-size:10.5px;">${u.ip||''}</td></tr>`).join('')}</tbody></table></div>` : `<div class="empty" style="padding:8px 0;">Tidak ada data</div>`}
      <p class="sub" style="text-transform:uppercase; font-size:10px; color:var(--accent-2);">Common Crawl — Sample URL</p>
      ${r.commoncrawl.length ? `<div class="table-scroll" style="max-height:180px;"><table><tbody>${r.commoncrawl.slice(0,50).map(u=>`<tr><td>${u}</td></tr>`).join('')}</tbody></table></div>` : `<div class="empty" style="padding:8px 0;">Tidak ada data / index Common Crawl mungkin sudah berganti versi</div>`}
    ` : ''}
  </div>`;
}

/* =========================================================
   15 — DASHBOARD STATISTIK & PRIORITAS ASET
   ========================================================= */
function computeAssetPriority(){
  const r = state.results;
  const subs = r.subdomains && !r.subdomains.error ? r.subdomains.subs : [];
  const interestingWords = /admin|staging|dev|test|internal|api|beta|uat|debug|backup|vpn|jenkins|grafana|kibana|portal/i;
  return subs.map(s=>{
    let score = 0; const tags = [];
    if(interestingWords.test(s)){ score += 2; tags.push('nama menarik'); }
    if(r.wayback && !r.wayback.error && r.wayback.interesting.some(row=>row[0].includes(s))){ score += 2; tags.push('ada di wayback menarik'); }
    if(r.endpoints && r.endpoints.list.some(e=>e.src.includes(s) || e.p.includes(s))){ score += 1; tags.push('terhubung endpoint'); }
    if(r.secrets && r.secrets.findings.some(f=>f.src.includes(s))){ score += 3; tags.push('indikasi secret'); }
    const level = score>=4 ? 'critical' : score>=2 ? 'high' : score>=1 ? 'medium' : 'low';
    return { name:s, score, level, tags };
  }).sort((a,b)=>b.score-a.score);
}

function toggleAssetLevel(level){
  const s = state.filters.assetsLevel;
  if(s.has(level)) s.delete(level); else s.add(level);
  renderContent();
}
function renderAssetsPanel(){
  const assets = computeAssetPriority();
  const counts = { critical:0, high:0, medium:0, low:0 };
  assets.forEach(a=>counts[a.level]++);
  const filtered = assets.filter(a=>state.filters.assetsLevel.has(a.level));
  return `
  <div class="panel">
    <h2>Prioritas Aset</h2>
    <p class="sub">Skoring otomatis tiap subdomain berdasar nama menarik, kemunculan di Wayback, endpoint terkait, dan indikasi secret — bantu tentukan mana yang diuji lebih dulu</p>
    ${assets.length===0 ? `<div class="empty">Belum ada subdomain. Jalankan Subdomain Enum dulu.</div>` : `
      <div class="filter-row">
        ${['critical','high','medium','low'].map(s=>`
          <span class="chip ${s} ${state.filters.assetsLevel.has(s)?'on '+s:''}" onclick="toggleAssetLevel('${s}')">
            <span class="cdot"></span>${s} (${counts[s]})
          </span>`).join('')}
      </div>
      ${filtered.length===0 ? `<div class="empty">Tidak ada aset pada level yang dipilih.</div>` : ''}
      ${filtered.slice(0,60).map(a=>`
        <div class="asset-row">
          <div class="nm">${a.name}
            <div class="tags">${a.tags.map(t=>`<span class="src-badge">${t}</span>`).join('')}</div>
          </div>
          <span class="sev ${a.level}" style="margin-top:0;">${a.level}</span>
        </div>`).join('')}
    `}
  </div>`;
}

/* =========================================================
   16 — RINGKASAN STATISTIK
   ========================================================= */
function computeStats(){
  const r = state.results;
  const hostTotal = (r.subdomains && !r.subdomains.error ? r.subdomains.count : 0) + (state.target ? 1 : 0);
  const liveTotal = r.subLive ? Object.values(r.subLive).filter(v=>v.alive).length : 0;
  const endpointTotal = r.endpoints ? r.endpoints.list.length : 0;
  const paramTotal = r.endpoints ? r.endpoints.params.length : 0;
  const jsTotal = r.jsrecon ? r.jsrecon.files.length : 0;
  const secretTotal = r.secrets ? r.secrets.findings.length : 0;
  const techTotal = r.tech && !r.tech.error ? r.tech.found.length : 0;
  const apiTotal = r.api ? r.api.apiFound.length : 0;
  const graphqlTotal = r.api ? r.api.graphqlFound.length : 0;
  const waybackTotal = r.wayback && !r.wayback.error ? r.wayback.total : 0;
  return { hostTotal, liveTotal, endpointTotal, paramTotal, jsTotal, secretTotal, techTotal, apiTotal, graphqlTotal, waybackTotal };
}

function renderStatsPanel(){
  const s = computeStats();
  if(!state.target){
    return `<div class="panel"><h2>Ringkasan Statistik</h2><p class="sub">Belum ada target. Jalankan scan dulu untuk melihat ringkasan.</p></div>`;
  }
  const cards = [
    { n:s.hostTotal, l:'Total Host' },
    { n:s.liveTotal, l:'Host Aktif' },
    { n:s.endpointTotal, l:'Total Endpoint' },
    { n:s.paramTotal, l:'Total Parameter' },
    { n:s.jsTotal, l:'Total File JS' },
    { n:s.secretTotal, l:'Indikasi Secret' },
    { n:s.techTotal, l:'Teknologi' },
    { n:s.waybackTotal, l:'URL Wayback' },
    { n:s.apiTotal, l:'Path API Aktif' },
    { n:s.graphqlTotal, l:'GraphQL Aktif' },
  ];
  return `
  <div class="panel">
    <h2>Ringkasan Statistik</h2>
    <p class="sub">Rekap angka penting dari seluruh modul recon untuk target <b style="color:var(--text)">${state.target}</b></p>
    <div class="statmini-grid">
      ${cards.map(c=>`<div class="statmini"><div class="n">${c.n}</div><div class="l">${c.l}</div></div>`).join('')}
    </div>
    <p class="sub" style="margin-top:14px;">Jalankan modul yang belum di-scan (JS Analyzer, Sumber Recon, API Discovery, dsb) agar angka di atas makin lengkap.</p>
  </div>`;
}

/* =========================================================
   06 — OWASP CHECKLIST + REPORT BUILDER
   ========================================================= */
const OWASP_LIST = [
  { id:1, title:'Broken Access Control', desc:'Cek apakah endpoint sensitif bisa diakses tanpa otorisasi yang benar (IDOR, privilege escalation).', severity:'critical' },
  { id:2, title:'Cryptographic Failures', desc:'Data sensitif dikirim/simpan tanpa enkripsi memadai, cek HTTPS & cipher yang dipakai.', severity:'high' },
  { id:3, title:'Injection (SQLi/NoSQLi/Command)', desc:'Input field perlu diuji validasi & sanitasi — gunakan Burp Suite/ZAP untuk testing terkontrol.', severity:'critical' },
  { id:4, title:'Insecure Design', desc:'Cek alur bisnis (contoh: reset password, checkout) untuk celah logika.', severity:'high' },
  { id:5, title:'Security Misconfiguration', desc:'Default credential, error verbose, direktori terbuka, header yang salah konfigurasi.', severity:'high' },
  { id:6, title:'Vulnerable & Outdated Components', desc:'Cek versi library dari tech fingerprint terhadap CVE database (nvd.nist.gov).', severity:'high' },
  { id:7, title:'Identification & Authentication Failures', desc:'Session handling, rate limiting login, kebijakan password lemah.', severity:'critical' },
  { id:8, title:'Software & Data Integrity Failures', desc:'CI/CD pipeline, auto-update tanpa verifikasi signature.', severity:'medium' },
  { id:9, title:'Security Logging & Monitoring Failures', desc:'Apakah aktivitas mencurigakan tercatat & termonitor.', severity:'medium' },
  { id:10, title:'Server-Side Request Forgery (SSRF)', desc:'Fitur yang menerima URL dari user (webhook, image fetch) berpotensi SSRF.', severity:'high' },
];

function toggleCheck(id){
  state.results.checklist[id] = !state.results.checklist[id];
  renderContent();
  renderRightCol();
}

function renderChecklistPanel(){
  const r = state.results;
  const checkedCount = Object.values(r.checklist).filter(Boolean).length;
  return `
  <div class="panel">
    <h2>OWASP Top 10 (2021) Checklist</h2>
    <p class="sub">Panduan area yang perlu diuji manual — centang kategori yang relevan/berhasil ditemukan</p>
    ${OWASP_LIST.map(item=>`
      <div class="check-item" onclick="toggleCheck(${item.id})">
        <input type="checkbox" ${r.checklist[item.id]?'checked':''} onclick="event.stopPropagation(); toggleCheck(${item.id})">
        <div>
          <div class="ti">${item.title}</div>
          <div class="de">${item.desc}</div>
          <span class="sev ${item.severity}">${item.severity}</span>
        </div>
      </div>
    `).join('')}
  </div>
  <div class="panel">
    <h2>Report Builder</h2>
    <p class="sub">Rangkum hasil recon jadi laporan siap-edit untuk submission</p>
    <div class="row"><div class="k">Target</div><div class="v">${state.target||'-'}</div></div>
    <div class="row"><div class="k">Header Score</div><div class="v">${r.headers && !r.headers.error ? r.headers.pct+'%' : '-'}</div></div>
    <div class="row"><div class="k">Subdomain Ditemukan</div><div class="v">${r.subdomains && !r.subdomains.error ? r.subdomains.count : '-'}</div></div>
    <div class="row"><div class="k">Tech Terdeteksi</div><div class="v">${r.tech && !r.tech.error ? r.tech.found.length : '-'}</div></div>
    <div class="row"><div class="k">URL Wayback Menarik</div><div class="v">${r.wayback && !r.wayback.error ? r.wayback.interesting.length : '-'}</div></div>
    <div class="row"><div class="k">Endpoint dari JS</div><div class="v">${r.endpoints ? r.endpoints.list.length : '-'}</div></div>
    <div class="row"><div class="k">Indikasi Secret</div><div class="v">${r.secrets ? r.secrets.findings.length : '-'}</div></div>
    <div class="row"><div class="k">GraphQL Aktif</div><div class="v">${r.api ? r.api.graphqlFound.length : '-'}</div></div>
    <div class="row"><div class="k">Favicon Hash</div><div class="v">${r.favicon && !r.favicon.error ? r.favicon.hash : '-'}</div></div>
    <div class="row"><div class="k">ASN</div><div class="v">${r.asn && !r.asn.error ? 'AS'+r.asn.asn+' — '+(r.asn.org||'') : '-'}</div></div>
    <div class="row"><div class="k">Kategori OWASP Dicentang</div><div class="v">${checkedCount}/10</div></div>
    <button class="btn-sec" style="width:100%; margin-top:14px;" onclick="downloadReport()">⬇ Download Laporan (.txt)</button>
  </div>
  <div class="panel">
    <h2>Lanjut ke Exploitation? Belajar di Tempat yang Tepat</h2>
    <p class="sub">Recon cuma langkah awal. Untuk menguji &amp; mengeksploitasi celah secara aman dan legal, latihan di lab yang memang didesain untuk itu:</p>
    <div class="learn-links">
      <a href="https://portswigger.net/web-security" target="_blank"><span>PortSwigger Web Security Academy<br><small>Lab gratis untuk XSS, SQLi, SSRF, auth bypass, dll</small></span><span class="arrow">↗</span></a>
      <a href="https://owasp.org/www-project-top-ten/" target="_blank"><span>OWASP Top 10<br><small>Referensi resmi kategori kerentanan paling umum</small></span><span class="arrow">↗</span></a>
      <a href="https://tryhackme.com" target="_blank"><span>TryHackMe<br><small>Room berpandu untuk pentesting, mulai dari nol</small></span><span class="arrow">↗</span></a>
      <a href="https://hackerone.com/hacktivity" target="_blank"><span>HackerOne Hacktivity<br><small>Baca disclosed report asli untuk belajar pola pikir hunter berpengalaman</small></span><span class="arrow">↗</span></a>
      <a href="https://portswigger.net/burp/communitydownload" target="_blank"><span>Burp Suite Community<br><small>Tool utama untuk intercept &amp; test request secara manual dan terkontrol</small></span><span class="arrow">↗</span></a>
    </div>
  </div>`;
}

function downloadReport(){
  const r = state.results;
  const checked = OWASP_LIST.filter(i=>r.checklist[i.id]);
  const s = computeStats();
  const lines = [
`RECON REPORT — SCOPELOCK`,
`================================`,
`Target       : ${state.target}`,
`Generated    : ${new Date().toLocaleString('id-ID')}`,
``,
`0. RINGKASAN STATISTIK`,
`   Total Host        : ${s.hostTotal}`,
`   Host Aktif        : ${s.liveTotal}`,
`   Total Endpoint    : ${s.endpointTotal}`,
`   Total Parameter   : ${s.paramTotal}`,
`   Total File JS     : ${s.jsTotal}`,
`   Indikasi Secret   : ${s.secretTotal}`,
`   Teknologi         : ${s.techTotal}`,
`   URL Wayback       : ${s.waybackTotal}`,
``,
`1. SECURITY HEADERS`,
r.headers && !r.headers.error ? `   Score: ${r.headers.pct}%\n` + r.headers.checks.map(c=>`   - ${c.name}: ${c.present?'OK':'MISSING'}`).join('\n') : `   Belum dijalankan / error`,
``,
`2. SUBDOMAINS (${r.subdomains && !r.subdomains.error ? r.subdomains.count : 0})`,
r.subdomains && !r.subdomains.error ? r.subdomains.subs.map(s=>`   - ${s}`).join('\n') : '   Belum dijalankan / error',
``,
`3. TECH STACK`,
r.tech && !r.tech.error ? r.tech.found.map(t=>`   - ${t.name} (${t.category})`).join('\n') : '   Belum dijalankan / error',
``,
`4. WAYBACK — URL MENARIK`,
r.wayback && !r.wayback.error ? r.wayback.interesting.slice(0,50).map(row=>`   - ${row[0]}`).join('\n') : '   Belum dijalankan / error',
``,
`5. ROBOTS / SITEMAP`,
r.robots ? `   Disallow rules: ${r.robots.disallowed.length}\n   Sitemap entries: ${(r.robots.sitemapEntries||[]).length}` : '   Belum dijalankan',
``,
`6. ENDPOINT DARI JS ANALYSIS (${r.endpoints ? r.endpoints.list.length : 0})`,
r.endpoints && r.endpoints.list.length ? r.endpoints.list.slice(0,50).map(e=>`   - ${e.p}`).join('\n') : '   Belum dijalankan / tidak ada',
``,
`7. SECRET SCANNER (${r.secrets ? r.secrets.findings.length : 0} indikasi — VERIFIKASI MANUAL)`,
r.secrets && r.secrets.findings.length ? r.secrets.findings.map(f=>`   - [${f.sev.toUpperCase()}] ${f.type} (${f.snippet}) — sumber: ${f.src}`).join('\n') : '   Belum dijalankan / tidak ada',
``,
`8. API & GRAPHQL DISCOVERY`,
r.api ? `   Path API aktif: ${r.api.apiFound.map(x=>x.path).join(', ')||'-'}\n   GraphQL aktif: ${r.api.graphqlFound.map(x=>x.path).join(', ')||'-'}` : '   Belum dijalankan',
``,
`9. CORS CHECK`,
r.cors && !r.cors.error ? `   ACAO: ${r.cors.acao||'-'}\n   ACAC: ${r.cors.acac||'-'}\n` + r.cors.issues.map(i=>`   - [${i.sev.toUpperCase()}] ${i.msg}`).join('\n') : '   Belum dijalankan',
``,
`10. FAVICON HASH & ASN`,
`   Favicon hash (mmh3): ${r.favicon && !r.favicon.error ? r.favicon.hash : '-'}`,
`   ASN: ${r.asn && !r.asn.error ? 'AS'+r.asn.asn+' — '+(r.asn.org||'')+' ('+r.asn.country+')' : '-'}`,
``,
`11. OWASP TOP 10 — AREA UNTUK DIUJI MANUAL`,
checked.length ? checked.map(c=>`   - [${c.severity.toUpperCase()}] ${c.title}: ${c.desc}`).join('\n') : '   Belum ada kategori dicentang',
``,
`CATATAN:`,
`- Laporan ini hasil recon PASIF. Tidak ada exploitation yang dilakukan otomatis.`,
`- Sebelum submit ke program bug bounty, verifikasi manual tiap temuan dan sertakan:`,
`  proof of concept, steps to reproduce, impact assessment, saran remediasi.`,
`- Pastikan target ada dalam scope resmi program sebelum melakukan testing lanjutan.`,
  ].join('\n');

  const blob = new Blob([lines], {type:'text/plain'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = `recon_report_${state.target || 'target'}_${Date.now()}.txt`;
  a.click();
  URL.revokeObjectURL(url);
  log('info', 'Laporan berhasil di-download.');
}

/* =========================================================
   WORKSPACE — simpan & kelola beberapa target
   ========================================================= */
const WS_KEY = 'scopelock_workspaces_v1';

function loadWorkspaces(){
  state.workspaces = Store.get(WS_KEY, []) || [];
  return state.workspaces;
}
function persistWorkspaces(){
  Store.set(WS_KEY, state.workspaces);
}
function saveWorkspace(nameOverride){
  if(!state.target){ alert('Belum ada target aktif untuk disimpan. Isi domain & jalankan scan dulu.'); return; }
  loadWorkspaces();
  const name = nameOverride || state.target;
  const id = 'ws_' + Date.now();
  state.workspaces.unshift({
    id, name, target: state.target,
    savedAt: new Date().toLocaleString('id-ID'),
    results: JSON.parse(JSON.stringify(state.results, (k,v)=> v instanceof Set ? Array.from(v) : v))
  });
  persistWorkspaces();
  log('ok', `Workspace "${name}" disimpan (${state.workspaces.length} total tersimpan).`);
  if(state.activeTab==='workspace') renderContent();
}
function deleteWorkspace(id){
  loadWorkspaces();
  state.workspaces = state.workspaces.filter(w=>w.id!==id);
  persistWorkspaces();
  renderContent();
}
function loadWorkspace(id){
  loadWorkspaces();
  const ws = state.workspaces.find(w=>w.id===id);
  if(!ws) return;
  state.target = ws.target;
  state.results = JSON.parse(JSON.stringify(ws.results));
  if(!state.results.checklist) state.results.checklist = {};
  document.getElementById('targetInput').value = ws.target;
  log('ok', `Workspace "${ws.name}" dimuat sebagai target aktif.`);
  switchTab('overview');
  renderStatCards();
}
function renderWorkspaceInputSave(){
  saveWorkspace(document.getElementById('wsNameInput').value.trim() || undefined);
  document.getElementById('wsNameInput').value = '';
}
function renderWorkspacePanel(){
  loadWorkspaces();
  return `
  <div class="panel">
    <h2>Workspace <span style="font-weight:400;font-size:12px;color:var(--muted)">${state.workspaces.length} target tersimpan</span></h2>
    <p class="sub">Simpan hasil recon beberapa target sekaligus, lalu muat kembali kapan saja. Disimpan di browser kamu (localStorage) — tidak dikirim ke server mana pun.</p>
    <div class="ws-save-row">
      <input id="wsNameInput" type="text" placeholder="Nama workspace (opsional, default nama domain)">
      <button class="btn-primary" style="padding:0 16px; border-radius:8px;" onclick="renderWorkspaceInputSave()">⎘ Simpan Target Saat Ini</button>
    </div>
    ${state.workspaces.length===0 ? `<div class="empty">Belum ada workspace tersimpan. Jalankan scan pada sebuah domain, lalu klik "Simpan Target Saat Ini".</div>` : ''}
    ${state.workspaces.map(w=>`
      <div class="ws-item">
        <div class="info">
          <div class="nm">${w.name}</div>
          <div class="meta">${w.target} · disimpan ${w.savedAt} · ${w.results.subdomains && !w.results.subdomains.error ? w.results.subdomains.count : 0} subdomain</div>
        </div>
        <div class="acts">
          <button onclick="loadWorkspace('${w.id}')">Muat</button>
          <button class="danger" onclick="if(confirm('Hapus workspace ini?')) deleteWorkspace('${w.id}')">Hapus</button>
        </div>
      </div>`).join('')}
  </div>`;
}

/* =========================================================
   SPLIT-SCREEN COMPARE — bandingkan 2 hasil recon berdampingan
   ========================================================= */
function compareOptionsHtml(selectedId){
  loadWorkspaces();
  const opts = [`<option value="">— pilih —</option>`];
  if(state.target) opts.push(`<option value="current" ${selectedId==='current'?'selected':''}>Sesi aktif: ${state.target}</option>`);
  state.workspaces.forEach(w=> opts.push(`<option value="${w.id}" ${selectedId===w.id?'selected':''}>${w.name} (${w.target})</option>`));
  return opts.join('');
}
function getCompareSnapshot(id){
  if(!id) return null;
  if(id==='current') return { name: state.target, target: state.target, results: state.results };
  loadWorkspaces();
  const ws = state.workspaces.find(w=>w.id===id);
  return ws ? { name: ws.name, target: ws.target, results: ws.results } : null;
}
function onCompareChange(which, val){
  if(which==='a') state.compareA = val || null;
  else state.compareB = val || null;
  renderContent();
}
function statRow(label, a, b){
  return `<div class="row"><div class="k">${label}</div><div class="v">${a}</div></div>`;
}
function renderCompareColumn(snap){
  if(!snap) return `<div class="split-col"><div class="empty">Pilih target untuk dibandingkan.</div></div>`;
  const r = snap.results;
  const subs = r.subdomains && !r.subdomains.error ? r.subdomains.count : 0;
  return `
    <div class="split-col">
      <h3>${snap.name}</h3>
      <div class="row"><div class="k">Header Score</div><div class="v">${r.headers && !r.headers.error ? r.headers.pct+'%' : '-'}</div></div>
      <div class="row"><div class="k">Subdomain</div><div class="v">${subs}</div></div>
      <div class="row"><div class="k">Teknologi</div><div class="v">${r.tech && !r.tech.error ? r.tech.found.length : '-'}</div></div>
      <div class="row"><div class="k">File JS</div><div class="v">${r.jsrecon ? r.jsrecon.files.length : '-'}</div></div>
      <div class="row"><div class="k">Endpoint</div><div class="v">${r.endpoints ? r.endpoints.list.length : '-'}</div></div>
      <div class="row"><div class="k">Indikasi Secret</div><div class="v">${r.secrets ? r.secrets.findings.length : '-'}</div></div>
      <div class="row"><div class="k">GraphQL Aktif</div><div class="v">${r.api ? r.api.graphqlFound.length : '-'}</div></div>
    </div>`;
}
function renderCompareDiff(snapA, snapB){
  if(!snapA || !snapB) return '';
  const subsA = new Set(snapA.results.subdomains && !snapA.results.subdomains.error ? snapA.results.subdomains.subs : []);
  const subsB = new Set(snapB.results.subdomains && !snapB.results.subdomains.error ? snapB.results.subdomains.subs : []);
  const onlyA = Array.from(subsA).filter(s=>!subsB.has(s));
  const onlyB = Array.from(subsB).filter(s=>!subsA.has(s));
  return `
  <div class="panel" style="margin-top:14px;">
    <h2>Selisih Subdomain</h2>
    <p class="sub">Subdomain yang hanya muncul di salah satu target — berguna untuk memantau perubahan infrastruktur antar waktu, atau membandingkan dua target berbeda</p>
    <div class="mini-grid">
      <div>
        <p class="sub" style="text-transform:uppercase; font-size:10px;">Hanya di ${snapA.name} (${onlyA.length})</p>
        <div class="table-scroll" style="max-height:200px;"><table><tbody>${onlyA.slice(0,100).map(s=>`<tr><td>${s}</td></tr>`).join('') || '<tr><td class="empty">—</td></tr>'}</tbody></table></div>
      </div>
      <div>
        <p class="sub" style="text-transform:uppercase; font-size:10px;">Hanya di ${snapB.name} (${onlyB.length})</p>
        <div class="table-scroll" style="max-height:200px;"><table><tbody>${onlyB.slice(0,100).map(s=>`<tr><td>${s}</td></tr>`).join('') || '<tr><td class="empty">—</td></tr>'}</tbody></table></div>
      </div>
    </div>
  </div>`;
}
function renderComparePanel(){
  const snapA = getCompareSnapshot(state.compareA);
  const snapB = getCompareSnapshot(state.compareB);
  return `
  <div class="panel">
    <h2>Split Compare</h2>
    <p class="sub">Bandingkan dua hasil recon berdampingan — sesi aktif saat ini atau workspace yang sudah disimpan. Berguna untuk membandingkan sebelum/sesudah, atau dua target berbeda.</p>
    <div class="compare-pickers">
      <select onchange="onCompareChange('a', this.value)">${compareOptionsHtml(state.compareA)}</select>
      <select onchange="onCompareChange('b', this.value)">${compareOptionsHtml(state.compareB)}</select>
    </div>
    <div class="split-view">
      ${renderCompareColumn(snapA)}
      ${renderCompareColumn(snapB)}
    </div>
  </div>
  ${renderCompareDiff(snapA, snapB)}`;
}

/* =========================================================
   OVERVIEW / ABOUT
   ========================================================= */
function renderOverview(){
  const r = state.results;
  return `
    <div class="mini-grid">
      <div class="panel">
        <h2>Target Information</h2>
        <div class="row"><div class="k">Domain</div><div class="v">${state.target || '-'}</div></div>
        <div class="row"><div class="k">Status</div><div class="v"><span class="pill ${state.target?'ok':'bad'}">${state.target?'Live':'Belum diisi'}</span></div></div>
        <div class="row"><div class="k">HTTP Status</div><div class="v">${r.headers && !r.headers.error ? r.headers.status||200 : '-'}</div></div>
        <div class="row"><div class="k">Subdomain Terdeteksi</div><div class="v">${r.subdomains && !r.subdomains.error ? r.subdomains.count : '-'}</div></div>
        <div class="row"><div class="k">Terakhir Update</div><div class="v">${state.lastScanAt ? 'Baru saja' : '-'}</div></div>
      </div>
      ${renderHeadersPanel(true)}
    </div>
    <div class="mini-grid" style="margin-top:16px;">
      ${renderTechPanel(true)}
      ${renderSubdomainsPanel(true)}
    </div>
    <div class="mini-grid" style="margin-top:16px;">
      ${renderWaybackPanel(true)}
      ${renderJSPanel(true)}
    </div>
    <div style="margin-top:16px;">
      ${renderStatsPanel()}
    </div>
    <div style="margin-top:16px;">
      ${renderAssetsPanel()}
    </div>
  `;
}

function renderAbout(){
  return `
  <div class="panel">
    <h2>Tentang SCOPELOCK</h2>
    <p class="sub">Passive Recon Dashboard untuk workflow bug bounty</p>
    <p style="font-size:12.5px; color:var(--muted); line-height:1.7;">
      SCOPELOCK menjalankan recon <b style="color:var(--text)">100% pasif</b> — hanya membaca data publik (HTTP header, Certificate Transparency logs, Wayback Machine, robots.txt/sitemap.xml). Tidak ada permintaan yang melakukan exploitation, brute force, atau injection. Semua proses berjalan langsung di browser kamu.
    </p>
  </div>`;
}

/* ---------- renderer registry ---------- */
function renderContent(){
  const leftEl = document.getElementById('leftCol');
  const map = {
    overview: renderOverview,
    headers: ()=>renderHeadersPanel(false),
    subdomains: ()=>renderSubdomainsPanel(false),
    graph: renderGraphPanel,
    tech: ()=>renderTechPanel(false),
    wayback: ()=>renderWaybackPanel(false),
    robots: renderRobotsPanel,
    jsrecon: ()=>renderJSPanel(false),
    endpoints: ()=>renderEndpointsPanel(false),
    secrets: ()=>renderSecretsPanel(false),
    api: ()=>renderAPIPanel(false),
    cors: renderCORSPanel,
    shots: renderScreenshotsPanel,
    favicon: renderFaviconPanel,
    asn: renderASNPanel,
    sources: renderSourcesPanel,
    assets: renderAssetsPanel,
    stats: renderStatsPanel,
    checklist: renderChecklistPanel,
    workspace: renderWorkspacePanel,
    compare: renderComparePanel,
    about: renderAbout,
  };
  leftEl.innerHTML = (map[state.activeTab] || renderOverview)();
  renderRightCol();
  renderLogIfVisible();
}

/* ---------- run all ---------- */
async function runAll(){
  const raw = document.getElementById('targetInput').value;
  const domain = normalizeDomain(raw);
  if(!domain){ alert('Masukkan domain target dulu, contoh: example.com'); return; }
  state.target = domain;
  state.log = [];
  state.scanStartedAt = Date.now();
  const btn = document.getElementById('runAllBtn');
  btn.disabled = true; btn.textContent = 'Scanning...';

  log('info', `=== Mulai recon pasif untuk ${domain} ===`);
  switchTab('overview');
  await runHeaders();
  await runSubdomains();
  await runTech();
  await runWayback();
  await runRobots();
  await runJSRecon();
  await runAPIDiscovery();
  await runCORS();
  await runFavicon();
  await runASN();
  await runSources();
  await runScreenshots();
  log('ok', `=== Recon selesai. Cek tab Prioritas Aset, Ringkasan Statistik & Checklist untuk rangkuman. ===`);

  state.lastScanDuration = Date.now() - state.scanStartedAt;
  state.lastScanAt = Date.now();
  btn.disabled = false; btn.textContent = '▶ Scan Semua';
  renderStatCards();
  renderContent();
}

/* =========================================================
   KEYBOARD SHORTCUTS
   ========================================================= */
function toggleShortcutsModal(force){
  const el = document.getElementById('shortcutsModal');
  const show = force !== undefined ? force : !el.classList.contains('show');
  el.classList.toggle('show', show);
}
function quickSaveWorkspace(){
  if(!state.target){ log('warn', 'Isi & scan domain dulu sebelum menyimpan ke workspace.'); return; }
  saveWorkspace();
}
function shiftTab(dir){
  const ids = TABS.map(t=>t.id);
  const idx = ids.indexOf(state.activeTab);
  const next = ids[(idx + dir + ids.length) % ids.length];
  switchTab(next);
}
document.addEventListener('keydown', (e)=>{
  const typing = ['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName);
  if(e.key === 'Escape'){ toggleShortcutsModal(false); if(typing) document.activeElement.blur(); return; }
  if(typing) return;
  if(e.key === '/'){ e.preventDefault(); document.getElementById('targetInput').focus(); return; }
  if(e.key === '?'){ toggleShortcutsModal(); return; }
  const k = e.key.toLowerCase();
  if(k === 'r'){ e.preventDefault(); runAll(); }
  else if(k === ']'){ shiftTab(1); }
  else if(k === '['){ shiftTab(-1); }
  else if(k === 's'){ quickSaveWorkspace(); }
  else if(k === 'w'){ switchTab('workspace'); }
  else if(k === 'g'){ switchTab('graph'); }
  else if(k === 'e'){ downloadReport(); }
  else if(k === 't'){ toggleTheme(); }
});

/* ---------- init ---------- */
loadWorkspaces();
renderTabstrip();
renderBottomNav();
renderStatCards();
renderContent();
document.querySelector('.nav-item[data-nav="overview"]').classList.add('active');
