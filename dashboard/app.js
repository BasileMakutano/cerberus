// Cerberus Dashboard — app.js
// All views, API calls, pipeline control, settings.

const API = '';  // same origin — Flask serves both dashboard and API
const REFRESH_MS = 30000;

const PORT_MAP = {
  21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP', 53:'DNS', 80:'HTTP',
  110:'POP3', 135:'RPC', 139:'NetBIOS', 143:'IMAP', 443:'HTTPS',
  445:'SMB', 1433:'MSSQL', 1521:'Oracle', 2181:'Zookeeper',
  3306:'MySQL', 3389:'RDP', 5432:'PostgreSQL', 5900:'VNC',
  6379:'Redis', 8080:'HTTP-Alt', 8443:'HTTPS-Alt', 8888:'Jupyter',
  9200:'Elasticsearch', 27017:'MongoDB'
};

const MONITORED_PORTS = [21,22,23,25,53,80,110,135,139,143,443,445,
  1433,1521,2181,3306,3389,5432,5900,6379,8080,8443,8888,9200,27017];

// ── State ─────────────────────────────────────────────────────────────────────
let allAlerts    = [];
let currentView  = 'overview';
let alertPage    = 1;
let alertFilter  = 'all';
let alertSearch  = '';
let settings     = {};
let cycleNum     = 1;
const PAGE_SIZE  = 15;

// ── Boot ──────────────────────────────────────────────────────────────────────
async function boot() {
  await Promise.all([fetchStatus(), fetchAlerts()]);
  renderCurrentView();
  setInterval(periodicRefresh, REFRESH_MS);
}

async function periodicRefresh() {
  await Promise.all([fetchStatus(), fetchAlerts()]);
  renderCurrentView();
}

// ── API calls ─────────────────────────────────────────────────────────────────
async function fetchStatus() {
  try {
    const r = await fetch(`${API}/api/status`);
    const d = await r.json();
    settings = d.settings || {};
    updateTopbar(d);
  } catch(e) {
    setStatusError();
  }
}

async function fetchAlerts() {
  try {
    const r = await fetch(`${API}/api/alerts?t=` + Date.now());
    allAlerts = await r.json();
    updateBadge();
    document.getElementById('lastSync').textContent =
      'Last sync: ' + new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'});
  } catch(e) { allAlerts = []; }
}

async function apiPost(endpoint, body={}) {
  const r = await fetch(`${API}${endpoint}`, {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify(body)
  });
  return r.json();
}

// ── Topbar ────────────────────────────────────────────────────────────────────
function updateTopbar(status) {
  const dot  = document.getElementById('statusDot');
  const txt  = document.getElementById('statusText');
  const tgt  = document.getElementById('targetPill');
  const sfDb = document.getElementById('sfDb');
  const sfEngine = document.getElementById('sfEngine');
  const sfModels = document.getElementById('sfModels');

  if (status.db_connected) {
    dot.classList.remove('err');
    txt.textContent = 'Active';
    sfDb.style.color = 'var(--low)';
    sfDb.textContent = 'Connected';
  } else {
    dot.classList.add('err');
    txt.textContent = 'DB Error';
    sfDb.style.color = 'var(--high)';
    sfDb.textContent = 'Disconnected';
  }

  sfEngine.textContent = 'Running';
  sfEngine.style.color = 'var(--low)';
  sfModels.textContent = (status.models_trained || 0) + ' models';

  const ip = status.settings?.target_ip || '—';
  tgt.textContent = 'Target: ' + ip;

  cycleNum = Math.max(1, Math.ceil((status.alerts_count || 0) / 5));
  document.getElementById('sfCycle').textContent = 'CYCLE: #' + cycleNum;
}

function setStatusError() {
  document.getElementById('statusDot').classList.add('err');
  document.getElementById('statusText').textContent = 'Offline';
}

function updateBadge() {
  const unacked = allAlerts.filter(a => !a.acknowledged).length;
  document.getElementById('sidebarBadge').textContent = unacked;
}

// ── Navigation ────────────────────────────────────────────────────────────────
function showView(view) {
  currentView = view;
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const navEl = document.getElementById('nav-' + view);
  if (navEl) navEl.classList.add('active');
  document.querySelectorAll('#mainContent > div').forEach(d => d.style.display = 'none');
  const viewEl = document.getElementById('view-' + view);
  if (viewEl) viewEl.style.display = '';
  renderCurrentView();
}

function renderCurrentView() {
  const fns = {
    overview: renderOverview,
    alerts:   renderAlertsView,
    ports:    renderPortsView,
    baselines:renderBaselinesView,
    pipeline: renderPipelineView,
    cyclelog: renderCycleLogView,
    settings: renderSettingsView,
  };
  if (fns[currentView]) fns[currentView]();
}

// ══════════════════════════════════════════════════════════════════════════════
//  VIEW: OVERVIEW
// ══════════════════════════════════════════════════════════════════════════════
function renderOverview() {
  const el     = document.getElementById('view-overview');
  const total  = allAlerts.length;
  const high   = allAlerts.filter(a => a.severity==='HIGH').length;
  const med    = allAlerts.filter(a => a.severity==='MEDIUM').length;
  const unacked= allAlerts.filter(a => !a.acknowledged).length;
  const conf   = allAlerts.filter(a => a.confirmed).length;
  const recent = [...allAlerts].sort((a,b) => new Date(b.timestamp)-new Date(a.timestamp)).slice(0,7);

  el.innerHTML = `
    <div class="stat-row">
      <div class="stat-card">
        <div class="stat-top"><div class="stat-lbl">Total Alerts</div><div class="stat-chip chip-info">${conf} confirmed</div></div>
        <div class="stat-val c-accent">${total}</div>
        <div class="stat-sub">${unacked} unacknowledged</div>
      </div>
      <div class="stat-card">
        <div class="stat-top"><div class="stat-lbl">High Severity</div><div class="stat-chip chip-high">HIGH</div></div>
        <div class="stat-val c-high">${high}</div>
        <div class="stat-sub">Requires immediate review</div>
      </div>
      <div class="stat-card">
        <div class="stat-top"><div class="stat-lbl">Medium Severity</div><div class="stat-chip chip-med">MED</div></div>
        <div class="stat-val c-med">${med}</div>
        <div class="stat-sub">Within investigation threshold</div>
      </div>
      <div class="stat-card">
        <div class="stat-top"><div class="stat-lbl">Ports Monitored</div><div class="stat-chip chip-ok">OK</div></div>
        <div class="stat-val c-info">25</div>
        <div class="stat-sub">${new Set(allAlerts.map(a=>a.port)).size} with alerts</div>
      </div>
    </div>

    <div class="mid-row">
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">▲ Recent Alerts
            <span class="stat-chip chip-high" style="margin-left:.5rem">${unacked} unacked</span>
          </div>
          <button class="filter-btn" onclick="showView('alerts')">View all →</button>
        </div>
        <table class="alert-table">
          <thead><tr><th>Severity</th><th>Port</th><th>Description</th><th>Timestamp</th><th>Action</th></tr></thead>
          <tbody>${recent.length ? recent.map(buildAlertRow).join('') : '<tr class="empty-row"><td colspan="5">No alerts yet — run a detection cycle.</td></tr>'}</tbody>
        </table>
      </div>

      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">↻ Last Cycle Summary</div>
          <span style="font-family:var(--mono);font-size:.65rem;color:var(--text-dim)">#${cycleNum}</span>
        </div>
        <div class="cycle-grid">
          <div class="cycle-cell"><div class="cycle-lbl">Duration</div><div class="cycle-val">5m 00s</div></div>
          <div class="cycle-cell"><div class="cycle-lbl">Scan Time</div><div class="cycle-val">${new Date().toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})} UTC</div></div>
          <div class="cycle-cell"><div class="cycle-lbl">Total Alerts</div><div class="cycle-val">${total}</div></div>
          <div class="cycle-cell"><div class="cycle-lbl">Ports Scanned</div><div class="cycle-val">25</div></div>
          <div class="cycle-cell"><div class="cycle-lbl">High Severity</div><div class="cycle-val c-high">${high}</div></div>
          <div class="cycle-cell"><div class="cycle-lbl">Confirmed</div><div class="cycle-val c-med">${conf}</div></div>
          <div class="cycle-cell"><div class="cycle-lbl">Acknowledged</div><div class="cycle-val c-low">${total - unacked}</div></div>
          <div class="cycle-cell"><div class="cycle-lbl">Unresolved</div><div class="cycle-val">${unacked}</div></div>
        </div>
        <div class="cycle-note">↻ ${total > 0 ? `Cycle #${cycleNum} — ${high} high alerts, ${unacked} unresolved.` : 'No data yet. Run a pipeline cycle from the Pipeline view.'}</div>
      </div>
    </div>

    <div class="bottom-row">
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">≡ Port Activity vs Baseline</div>
          <span style="font-size:.65rem;color:var(--text-dim)">Current cycle #${cycleNum}</span>
        </div>
        <div class="bar-legend">
          <div class="legend-item"><div class="legend-swatch base"></div> Baseline</div>
          <div class="legend-item"><div class="legend-swatch curr"></div> Current</div>
        </div>
        <div class="bar-chart">${buildBarChart()}</div>
      </div>
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">↗ Alerts / Last 7 Cycles</div>
          <span style="font-size:.65rem;color:var(--text-dim)">Current: #${cycleNum}</span>
        </div>
        <div class="spark-wrap"><svg class="spark-svg" id="sparkSvg" viewBox="0 0 400 120" preserveAspectRatio="none"></svg></div>
        <div class="spark-label">
          <span class="spark-sub" id="sparkSub">—</span>
          <span class="spark-trend" id="sparkTrend">—</span>
        </div>
      </div>
    </div>`;

  buildSparkline();
}

function buildBarChart() {
  const counts = {};
  allAlerts.forEach(a => { counts[a.port] = (counts[a.port]||0)+1; });
  let ports = Object.keys(counts).map(Number).sort((a,b)=>counts[b]-counts[a]).slice(0,6);
  if (!ports.length) ports = [443,22,8080,53,25,80];
  const max = Math.max(...ports.map(p=>counts[p]||0), 1);
  return ports.map(port => {
    const count = counts[port]||0;
    const baseW = 40;
    const currW = Math.max(3, Math.round((count/max)*95));
    const ratio = count > 0 ? (currW/baseW).toFixed(1)+'×' : '0×';
    const cls   = currW > baseW*1.5 ? 'crit' : currW > baseW*1.1 ? 'warn' : 'ok';
    return `<div class="bar-row">
      <span class="bar-port">${PORT_MAP[port]||port} :${port}</span>
      <div class="bar-track">
        <div class="bar-base" style="width:${baseW}%"></div>
        <div class="bar-curr ${cls}" style="width:${currW}%"></div>
      </div>
      <span class="bar-label ${cls}">${ratio}</span>
    </div>`;
  }).join('');
}

function buildSparkline() {
  const svg    = document.getElementById('sparkSvg');
  if (!svg) return;
  const now    = Date.now();
  const bktMs  = 10*60*1000;
  const bkts   = Array(7).fill(0);
  allAlerts.forEach(a => {
    const age = now - new Date(a.timestamp).getTime();
    const idx = Math.min(6, Math.floor(age/bktMs));
    bkts[6-idx]++;
  });
  const max   = Math.max(...bkts, 1);
  const W=400, H=100, px=10, py=10;
  const step  = (W-px*2)/6;
  const pts   = bkts.map((v,i) => [px+i*step, py+(1-v/max)*(H-py*2)]);
  const line  = pts.map((p,i)=>(i===0?'M':'L')+p[0].toFixed(1)+','+p[1].toFixed(1)).join(' ');
  const area  = line+` L${pts[6][0]},${H} L${pts[0][0]},${H} Z`;
  const lbls  = Array(7).fill(0).map((_,i)=>{
    const c = Math.max(1, cycleNum-(6-i));
    return `<text class="spark-axis" x="${(px+i*step).toFixed(0)}" y="${H+14}" text-anchor="middle">#${c}</text>`;
  }).join('');
  svg.innerHTML = `<defs><linearGradient id="sg" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0%" stop-color="#7c6cf0" stop-opacity=".35"/>
    <stop offset="100%" stop-color="#7c6cf0" stop-opacity="0"/>
  </linearGradient></defs>
  <path d="${area}" fill="url(#sg)"/>
  <path d="${line}" fill="none" stroke="#7c6cf0" stroke-width="2" stroke-linejoin="round"/>
  ${pts.map(p=>`<circle cx="${p[0].toFixed(1)}" cy="${p[1].toFixed(1)}" r="3" fill="#7c6cf0"/>`).join('')}
  ${lbls}`;
  const total = allAlerts.length;
  const sub = document.getElementById('sparkSub');
  const trnd = document.getElementById('sparkTrend');
  if (sub)  sub.textContent  = `avg ${total?(total/7).toFixed(1):'0'} alerts/cycle over last 7 cycles`;
  if (trnd) trnd.textContent = bkts[6] > (total/7) ? `↑ +${bkts[6]} this cycle` : '→ Stable';
}

// ══════════════════════════════════════════════════════════════════════════════
//  VIEW: ALERTS (full table with search, filter, pagination)
// ══════════════════════════════════════════════════════════════════════════════
function renderAlertsView() {
  const el = document.getElementById('view-alerts');

  const filtered = allAlerts.filter(a => {
    if (alertFilter === 'confirmed' && !a.confirmed) return false;
    if (alertFilter === 'HIGH'   && a.severity !== 'HIGH')   return false;
    if (alertFilter === 'MEDIUM' && a.severity !== 'MEDIUM') return false;
    if (alertFilter === 'LOW'    && a.severity !== 'LOW')    return false;
    if (alertSearch) {
      const q = alertSearch.toLowerCase();
      return (a.ip||'').includes(q) || String(a.port).includes(q) ||
             (a.layer1_trigger||'').toLowerCase().includes(q) ||
             (a.service||'').toLowerCase().includes(q);
    }
    return true;
  }).sort((a,b) => new Date(b.timestamp)-new Date(a.timestamp));

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  if (alertPage > totalPages) alertPage = totalPages;
  const page = filtered.slice((alertPage-1)*PAGE_SIZE, alertPage*PAGE_SIZE);

  el.innerHTML = `
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">▲ All Alerts <span style="font-family:var(--mono);font-size:.65rem;color:var(--text-dim);margin-left:.5rem">${filtered.length} results</span></div>
        <button class="danger-btn" onclick="clearAlerts()">Clear All</button>
      </div>
      <div class="filter-bar">
        <button class="filter-btn ${alertFilter==='all'?'active':''}"       onclick="setAlertFilter('all')">All</button>
        <button class="filter-btn ${alertFilter==='confirmed'?'active':''}" onclick="setAlertFilter('confirmed')">Confirmed</button>
        <button class="filter-btn ${alertFilter==='HIGH'?'active':''}"      onclick="setAlertFilter('HIGH')">High</button>
        <button class="filter-btn ${alertFilter==='MEDIUM'?'active':''}"    onclick="setAlertFilter('MEDIUM')">Medium</button>
        <button class="filter-btn ${alertFilter==='LOW'?'active':''}"       onclick="setAlertFilter('LOW')">Low</button>
        <input class="search-input" type="text" placeholder="Search IP, port, trigger…"
               value="${alertSearch}" oninput="setAlertSearch(this.value)">
      </div>
      <table class="alert-table">
        <thead><tr>
          <th>Severity</th><th>Port</th><th>IP</th><th>Trigger</th>
          <th>L2 Score</th><th>Confirmed</th><th>Timestamp</th><th>Ack</th>
        </tr></thead>
        <tbody>${page.length ? page.map(buildAlertRowFull).join('') :
          '<tr class="empty-row"><td colspan="8">No alerts match this filter.</td></tr>'}</tbody>
      </table>
      <div class="pagination">
        <span class="page-info">Page ${alertPage} of ${totalPages} — ${filtered.length} alerts</span>
        ${Array.from({length:totalPages},(_,i)=>
          `<button class="page-btn ${alertPage===i+1?'active':''}" onclick="setAlertPage(${i+1})">${i+1}</button>`
        ).join('')}
      </div>
    </div>`;
}

function buildAlertRow(a) {
  return `<tr>
    <td><span class="sev-badge sev-${a.severity}">${a.severity}</span></td>
    <td><span class="port-mono">:${a.port}</span></td>
    <td><span class="desc-text">${describeAlert(a)}</span></td>
    <td><span class="ts-text">${fmtTime(a.timestamp)}</span></td>
    <td><button class="ack-btn ${a.acknowledged?'done':''}"
          onclick="ackAlert('${a.alert_id}',this)">${a.acknowledged?'✓':'Ack'}</button></td>
  </tr>`;
}

function buildAlertRowFull(a) {
  const score = a.layer2_score != null ? a.layer2_score.toFixed(4) : 'NO MODEL';
  return `<tr>
    <td><span class="sev-badge sev-${a.severity}">${a.severity}</span></td>
    <td><span class="port-mono">:${a.port}</span></td>
    <td><span style="font-family:var(--mono);font-size:.7rem;color:var(--text-sec)">${a.ip||'—'}</span></td>
    <td><span style="font-family:var(--mono);font-size:.65rem;color:var(--text-dim)">${a.layer1_trigger||'—'}</span></td>
    <td><span style="font-family:var(--mono);font-size:.68rem;color:${a.layer2_score != null ? 'var(--med)':'var(--text-dim)'}">${score}</span></td>
    <td>${a.confirmed
      ? '<span style="font-family:var(--mono);font-size:.6rem;color:var(--low)">✓ YES</span>'
      : '<span style="font-family:var(--mono);font-size:.6rem;color:var(--text-dim)">L1 only</span>'}</td>
    <td><span class="ts-text">${fmtTime(a.timestamp)}</span></td>
    <td><button class="ack-btn ${a.acknowledged?'done':''}"
          onclick="ackAlert('${a.alert_id}',this)">${a.acknowledged?'✓':'Ack'}</button></td>
  </tr>`;
}

function setAlertFilter(f) { alertFilter = f; alertPage = 1; renderAlertsView(); }
function setAlertSearch(v) { alertSearch = v; alertPage = 1; renderAlertsView(); }
function setAlertPage(p)   { alertPage = p; renderAlertsView(); }

async function clearAlerts() {
  if (!confirm('Clear all alerts? This cannot be undone.')) return;
  await fetch(`${API}/api/alerts`, {method:'DELETE'});
  allAlerts = [];
  updateBadge();
  renderAlertsView();
}

// ══════════════════════════════════════════════════════════════════════════════
//  VIEW: PORTS
// ══════════════════════════════════════════════════════════════════════════════
async function renderPortsView() {
  const el = document.getElementById('view-ports');
  el.innerHTML = `<div class="panel"><div class="panel-header"><div class="panel-title">⬡ Monitored Ports</div><span class="panel-sub">25 critical ports — live status from alert data</span></div><div class="ports-grid" id="portsGrid">Loading…</div></div>`;

  const alertedPorts = {};
  allAlerts.forEach(a => {
    if (!alertedPorts[a.port] || severityRank(a.severity) > severityRank(alertedPorts[a.port].severity)) {
      alertedPorts[a.port] = a;
    }
  });

  // Also try to pull live port data from DB via API
  let dbPorts = {};
  try {
    const r = await fetch(`${API}/api/db/ports`);
    const rows = await r.json();
    rows.forEach(row => { dbPorts[row.port] = row; });
  } catch(e) {}

  const grid = document.getElementById('portsGrid');
  if (!grid) return;

  grid.innerHTML = MONITORED_PORTS.map(port => {
    const alert  = alertedPorts[port];
    const dbRow  = dbPorts[port];
    const cls    = alert ? (alert.severity==='HIGH'?'alerted':'warned') : 'clean';
    const dotCls = alert ? (alert.severity==='HIGH'?'alerted':'warned') : (dbRow?'clean':'unknown');
    return `<div class="port-card ${cls}">
      <div class="port-card-top">
        <span class="port-num">${port}</span>
        <span class="port-dot ${dotCls}"></span>
      </div>
      <div class="port-svc">${PORT_MAP[port]||'Unknown'}</div>
      <div class="port-stat" style="margin-top:.4rem">
        ${dbRow ? `${dbRow.observations} observations · ${dbRow.unique_ips} IP(s)` : 'No live data'}
      </div>
      ${alert ? `<div class="port-stat" style="margin-top:.3rem;color:${alert.severity==='HIGH'?'var(--high)':'var(--med)'}">
        ${alert.layer1_trigger} — ${fmtTime(alert.timestamp)}
      </div>` : ''}
      ${dbRow ? `<div class="port-stat" style="margin-top:.2rem">Last: ${fmtTime(dbRow.last_seen)}</div>` : ''}
    </div>`;
  }).join('');
}

function severityRank(s) { return {HIGH:3,MEDIUM:2,LOW:1}[s]||0; }

// ══════════════════════════════════════════════════════════════════════════════
//  VIEW: BASELINES
// ══════════════════════════════════════════════════════════════════════════════
async function renderBaselinesView() {
  const el = document.getElementById('view-baselines');
  el.innerHTML = `<div class="panel"><div class="panel-header"><div class="panel-title">≈ Statistical Baselines</div><span class="panel-sub">From models/baselines.json — built by Phase 4b</span></div><div style="padding:1rem;color:var(--text-dim);font-size:.75rem">Loading…</div></div>`;

  try {
    const r  = await fetch(`${API}/api/baselines`);
    const bl = await r.json();

    const rows = Object.entries(bl).map(([key, b]) => {
      const port  = b.port ?? key;
      const len   = b.length || {};
      const proto = b.protocol || {};
      const conf  = b.confidence || '—';
      const obs   = b.total_observations || 0;
      const confCls = conf==='HIGH'?'HIGH':conf==='MEDIUM'?'MED':'LOW';
      return `<tr>
        <td style="color:var(--accent)">${port === -1 ? 'ICMP/ARP' : ':'+port}</td>
        <td>${PORT_MAP[port]||'—'}</td>
        <td><span class="conf-chip conf-${confCls}">${conf}</span></td>
        <td>${obs.toLocaleString()}</td>
        <td>${len.available ? len.mean?.toFixed(1)??'—' : 'N/A'}</td>
        <td>${len.available ? `[${len.lower??'—'} – ${len.upper?.toFixed(0)??'—'}]` : 'N/A'}</td>
        <td>${proto.dominant||'—'}</td>
        <td>${formatSources(b.source_composition)}</td>
      </tr>`;
    }).join('');

    el.innerHTML = `
      <div class="panel">
        <div class="panel-header">
          <div class="panel-title">≈ Statistical Baselines</div>
          <span class="panel-sub">${Object.keys(bl).length} ports profiled</span>
        </div>
        <table class="baseline-table">
          <thead><tr>
            <th>Port</th><th>Service</th><th>Confidence</th><th>Observations</th>
            <th>Mean Length</th><th>Length Range</th><th>Protocol</th><th>Sources</th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  } catch(e) {
    el.innerHTML = `<div class="empty-state">Could not load baselines.json — run Phase 4b first.</div>`;
  }
}

function formatSources(src) {
  if (!src) return '—';
  return Object.entries(src).map(([k,v])=>`${k}:${v}`).join(', ');
}

// ══════════════════════════════════════════════════════════════════════════════
//  VIEW: PIPELINE
// ══════════════════════════════════════════════════════════════════════════════
const PHASES = [
  { id:'scan',       icon:'📡', name:'Scan',       desc:'Run nmap_scan.sh via sudo — scans 25 ports on target' },
  { id:'parser',     icon:'📂', name:'Parser',      desc:'Ingest nmap XML + ss logs into SQLite' },
  { id:'profiler',   icon:'🧠', name:'Profiler',    desc:'Rebuild behavioural port profiles (Phase 4a)' },
  { id:'baseline',   icon:'📊', name:'Baseline',    desc:'Rebuild statistical baselines (Phase 4b)' },
  { id:'detector',   icon:'🤖', name:'Detector',    desc:'Retrain Isolation Forest models — 26 ports (slow)' },
  { id:'correlator', icon:'🔗', name:'Correlator',  desc:'Run Layer 1 + 2 correlation on recent observations' },
  { id:'alerter',    icon:'🔔', name:'Alerter',     desc:'Write confirmed threat events to alerts.json' },
];

let pipelineRunning = false;
let consoleLines    = ['[Cerberus] Pipeline console ready. Run a phase or a full cycle.', ''];

function renderPipelineView() {
  const el = document.getElementById('view-pipeline');
  el.innerHTML = `
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">▶ Pipeline Control</div>
        <span class="panel-sub">All phases run in-process — no terminal required</span>
      </div>
      <div class="pipeline-grid">
        <div>
          <div style="padding:.75rem 1rem .25rem">
            <button class="run-full-btn" id="runFullBtn" onclick="runFullCycle()">▶ Run Full Cycle</button>
          </div>
          <div style="padding:.25rem 1rem .5rem;font-size:.65rem;color:var(--text-dim);font-family:var(--mono)">
            — or run individual phases —
          </div>
          <div class="phase-list" id="phaseList">
            ${PHASES.map(p => `
              <button class="phase-btn" id="phasebtn-${p.id}" onclick="runPhase('${p.id}')">
                <span class="phase-btn-icon">${p.icon}</span>
                <span class="phase-btn-info">
                  <div class="phase-btn-name">${p.name}</div>
                  <div class="phase-btn-desc">${p.desc}</div>
                </span>
                <span class="phase-btn-status" id="phasestatus-${p.id}">—</span>
              </button>`).join('')}
          </div>
        </div>
        <div class="console-wrap" style="padding:1rem 1rem 1rem 0">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:.5rem">
            <span style="font-size:.65rem;letter-spacing:.1em;text-transform:uppercase;color:var(--text-dim)">Console Output</span>
            <button class="filter-btn" onclick="clearConsole()">Clear</button>
          </div>
          <div class="console-box" id="consoleBox">${renderConsole()}</div>
        </div>
      </div>
    </div>`;
}

function renderConsole() {
  return consoleLines.map(line => {
    if (line.startsWith('[+]') || line.startsWith('[✓]')) return `<div class="console-line-ok">${esc(line)}</div>`;
    if (line.startsWith('[!]') || line.startsWith('[✗]')) return `<div class="console-line-err">${esc(line)}</div>`;
    if (line.startsWith('[*]') || line.startsWith('[→]')) return `<div class="console-line-info">${esc(line)}</div>`;
    if (line.startsWith('[~]')) return `<div class="console-line-warn">${esc(line)}</div>`;
    return `<div>${esc(line)}</div>`;
  }).join('');
}

function consolePrint(lines) {
  if (typeof lines === 'string') lines = lines.split('\n');
  consoleLines.push(...lines);
  if (consoleLines.length > 500) consoleLines = consoleLines.slice(-400);
  const box = document.getElementById('consoleBox');
  if (box) { box.innerHTML = renderConsole(); box.scrollTop = box.scrollHeight; }
}

function clearConsole() {
  consoleLines = [];
  const box = document.getElementById('consoleBox');
  if (box) box.innerHTML = '';
}

function setPhaseStatus(id, status, dur) {
  const el = document.getElementById('phasestatus-'+id);
  const btn = document.getElementById('phasebtn-'+id);
  if (!el || !btn) return;
  btn.classList.remove('running','success','fail');
  if (status === 'running') { el.textContent = '…'; btn.classList.add('running'); }
  else if (status === 'ok') { el.textContent = dur+'s ✓'; btn.classList.add('success'); }
  else { el.textContent = 'failed ✗'; btn.classList.add('fail'); }
}

async function runPhase(id) {
  if (pipelineRunning) return;
  pipelineRunning = true;
  setPhaseStatus(id, 'running');
  consolePrint([`[→] Running ${id}…`]);

  try {
    const result = await apiPost(`/api/run/${id}`);
    handlePhaseResult(result, id);
  } catch(e) {
    consolePrint([`[!] Request failed: ${e.message}`]);
    setPhaseStatus(id, 'fail');
  }
  pipelineRunning = false;
}

async function runFullCycle() {
  if (pipelineRunning) return;
  pipelineRunning = true;
  const btn = document.getElementById('runFullBtn');
  if (btn) { btn.disabled = true; btn.textContent = '⏳ Running…'; }
  consolePrint(['', '[→] Starting full cycle: scan → parse → correlate → alert', '']);

  try {
    const result = await apiPost('/api/run/full-cycle');
    if (result.steps) {
      result.steps.forEach(step => handlePhaseResult(step, step.phase));
    }
    if (result.completed) {
      consolePrint(['', '[✓] Full cycle complete. Refreshing alert data…']);
      await fetchAlerts();
      renderCurrentView();
    } else {
      consolePrint([`[!] Cycle stopped at: ${result.stopped_at}`]);
    }
  } catch(e) {
    consolePrint([`[!] Full cycle request failed: ${e.message}`]);
  }

  if (btn) { btn.disabled = false; btn.textContent = '▶ Run Full Cycle'; }
  pipelineRunning = false;
}

function handlePhaseResult(result, id) {
  const dur = result.duration_sec ?? '?';
  if (result.success) {
    setPhaseStatus(id, 'ok', dur);
    consolePrint([`[+] ${id} completed in ${dur}s`]);
    if (result.output) consolePrint(result.output.trim().split('\n'));
  } else {
    setPhaseStatus(id, 'fail', dur);
    consolePrint([`[!] ${id} failed after ${dur}s`]);
    if (result.error) consolePrint(result.error.trim().split('\n').slice(0,10));
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  VIEW: CYCLE LOG
// ══════════════════════════════════════════════════════════════════════════════
async function renderCycleLogView() {
  const el = document.getElementById('view-cyclelog');
  el.innerHTML = `
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">↻ Cycle Log</div>
        <span class="panel-sub">logs/recon.log + logs/correlation.log</span>
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:0">
        <div style="border-right:1px solid var(--border)">
          <div style="padding:.6rem 1rem;border-bottom:1px solid var(--border-dim);font-size:.65rem;letter-spacing:.1em;text-transform:uppercase;color:var(--text-dim)">Recon Log (nmap)</div>
          <div class="cycle-log-box" id="reconLog">Loading…</div>
        </div>
        <div>
          <div style="padding:.6rem 1rem;border-bottom:1px solid var(--border-dim);font-size:.65rem;letter-spacing:.1em;text-transform:uppercase;color:var(--text-dim)">Correlation Log</div>
          <div class="cycle-log-box" id="corrLog">Loading…</div>
        </div>
      </div>
    </div>`;

  try {
    const [r1, r2] = await Promise.all([
      fetch(`${API}/api/logs/recon`),
      fetch(`${API}/api/logs/correlation`)
    ]);
    const d1 = await r1.json();
    const d2 = await r2.json();
    const reconEl = document.getElementById('reconLog');
    const corrEl  = document.getElementById('corrLog');
    if (reconEl) reconEl.textContent = d1.log || '(empty — run a scan first)';
    if (corrEl)  corrEl.textContent  = d2.log || '(empty — run correlator first)';
    if (reconEl) reconEl.scrollTop = reconEl.scrollHeight;
    if (corrEl)  corrEl.scrollTop  = corrEl.scrollHeight;
  } catch(e) {
    const reconEl = document.getElementById('reconLog');
    const corrEl  = document.getElementById('corrLog');
    if (reconEl) reconEl.textContent = 'Could not load log.';
    if (corrEl)  corrEl.textContent  = 'Could not load log.';
  }
}

// ══════════════════════════════════════════════════════════════════════════════
//  VIEW: SETTINGS
// ══════════════════════════════════════════════════════════════════════════════
async function renderSettingsView() {
  const el = document.getElementById('view-settings');

  // Load current settings from server
  let s = settings;
  try {
    const r = await fetch(`${API}/api/settings`);
    s = await r.json();
    settings = s;
  } catch(e) {}

  el.innerHTML = `
    <div class="panel">
      <div class="panel-header">
        <div class="panel-title">≡ Settings</div>
        <span class="panel-sub">Changes to Target IP are written permanently to scripts/nmap_scan.sh</span>
      </div>
      <div class="settings-grid">
        <div class="settings-section">
          <div style="font-size:.65rem;letter-spacing:.12em;text-transform:uppercase;color:var(--text-dim);padding-bottom:.25rem;border-bottom:1px solid var(--border-dim);margin-bottom:.25rem">Scan Configuration</div>

          <div class="field-group">
            <div class="field-label">Target IP Address</div>
            <input class="field-input" id="setTargetIp" type="text"
                   value="${s.target_ip||''}" placeholder="e.g. 192.168.100.100">
            <div class="field-hint">Written permanently to scripts/nmap_scan.sh so cron also uses the new IP.</div>
          </div>

          <div class="field-group">
            <div class="field-label">Scan Interval (minutes)</div>
            <input class="field-input" id="setScanInterval" type="number" min="1" max="60"
                   value="${s.scan_interval||5}">
            <div class="field-hint">Saved for future cron setup runs; existing cron jobs keep their current schedule.</div>
          </div>

          <div class="field-group">
            <div class="field-row">
              <div>
                <div class="field-label">Confirmed-only Alerts</div>
                <div class="field-hint" style="margin-top:.2rem">Only write alerts where both Layer 1 and Layer 2 agree.</div>
              </div>
              <label class="toggle">
                <input type="checkbox" id="setConfirmedOnly" ${s.confirmed_only?'checked':''}>
                <span class="toggle-slider"></span>
              </label>
            </div>
          </div>

          <div class="field-group">
            <div class="field-label">Correlation Look-back Window (minutes)</div>
            <input class="field-input" id="setLookback" type="number" min="5" max="1440"
                   value="${s.lookback_minutes||60}">
            <div class="field-hint">How far back the correlator looks for observations on each run.</div>
          </div>

          <button class="save-btn" onclick="saveSettings()">Save Settings</button>
          <div class="settings-feedback" id="settingsFeedback"></div>
        </div>

        <div class="settings-section">
          <div style="font-size:.65rem;letter-spacing:.12em;text-transform:uppercase;color:var(--text-dim);padding-bottom:.25rem;border-bottom:1px solid var(--border-dim);margin-bottom:.25rem">System Information</div>

          <div class="field-group">
            <div class="field-label">Project</div>
            <div style="font-family:var(--mono);font-size:.72rem;color:var(--text-sec)">Cerberus — Network Threat Detection</div>
          </div>
          <div class="field-group">
            <div class="field-label">Student</div>
            <div style="font-family:var(--mono);font-size:.72rem;color:var(--text-sec)">Basile Makutano Musavuli (171470)</div>
          </div>
          <div class="field-group">
            <div class="field-label">Supervisor</div>
            <div style="font-family:var(--mono);font-size:.72rem;color:var(--text-sec)">Mr. Elisha Edwine</div>
          </div>
          <div class="field-group">
            <div class="field-label">Institution</div>
            <div style="font-family:var(--mono);font-size:.72rem;color:var(--text-sec)">Strathmore University — BSc CNS Year 3</div>
          </div>
          <div class="field-group">
            <div class="field-label">Version</div>
            <div style="font-family:var(--mono);font-size:.72rem;color:var(--text-sec)">v2.4.1 — © 2026 Cerberus Security</div>
          </div>

          <div style="margin-top:1rem;padding-top:1rem;border-top:1px solid var(--border-dim)">
            <div style="font-size:.65rem;letter-spacing:.12em;text-transform:uppercase;color:var(--high);margin-bottom:.75rem">Danger Zone</div>
            <button class="danger-btn" onclick="clearAlerts()" style="width:100%;margin-bottom:.5rem">
              Clear All Alerts
            </button>
            <div class="field-hint" style="margin-top:.25rem">Permanently deletes logs/alerts.json. Cannot be undone.</div>
          </div>
        </div>
      </div>
    </div>`;
}

async function saveSettings() {
  const fb = document.getElementById('settingsFeedback');
  fb.textContent = 'Saving…';
  fb.style.color = 'var(--text-dim)';

  const payload = {
    target_ip:       document.getElementById('setTargetIp').value.trim(),
    scan_interval:   parseInt(document.getElementById('setScanInterval').value),
    confirmed_only:  document.getElementById('setConfirmedOnly').checked,
    lookback_minutes:parseInt(document.getElementById('setLookback').value),
  };

  try {
    const r = await fetch(`${API}/api/settings`, {
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    });
    const d = await r.json();
    if (d.success) {
      settings = d.settings;
      fb.textContent = d.script_updated
        ? '✓ Saved — target IP written to nmap_scan.sh'
        : '✓ Settings saved';
      fb.style.color = 'var(--low)';
      document.getElementById('targetPill').textContent = 'Target: ' + settings.target_ip;
    } else {
      const details = d.fields ? ' — ' + Object.values(d.fields).join(' ') : '';
      fb.textContent = '✗ Save failed: ' + (d.error||'unknown error') + details;
      fb.style.color = 'var(--high)';
    }
  } catch(e) {
    fb.textContent = '✗ Network error — is the server running?';
    fb.style.color = 'var(--high)';
  }
}

// ── Shared helpers ────────────────────────────────────────────────────────────
async function ackAlert(id, btn) {
  const a = allAlerts.find(x => x.alert_id === id);
  if (!a || a.acknowledged) return;

  const previous = btn.textContent;
  btn.textContent = '…';
  btn.disabled = true;

  try {
    const r = await fetch(`${API}/api/alerts/${encodeURIComponent(id)}/ack`, {
      method:'PATCH',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({acknowledged:true})
    });
    const d = await r.json();
    if (!r.ok || !d.success) throw new Error(d.error || 'Ack failed');
    a.acknowledged = true;
    btn.textContent = '✓';
    btn.classList.add('done');
    updateBadge();
  } catch(e) {
    btn.textContent = previous;
    consolePrint?.([`[!] Could not acknowledge alert: ${e.message}`]);
  } finally {
    btn.disabled = false;
  }
}

function describeAlert(a) {
  const svc = PORT_MAP[a.port] || `port ${a.port}`;
  return {
    UNKNOWN_PORT:    'Unknown port exposure detected',
    WRONG_SERVICE:   `${svc} running unexpected service`,
    UNKNOWN_IP:      `Unrecognised IP ${a.ip} on ${svc}`,
    FREQUENCY_SPIKE: `${svc} traffic spike above baseline`,
    WRONG_PROTOCOL:  `Protocol mismatch on ${svc}`,
    NEW_VERSION:     `New version detected on ${svc}`,
  }[a.layer1_trigger] || `Anomaly on ${svc} — ${a.layer1_trigger}`;
}

function fmtTime(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'});
}

function esc(str) {
  return String(str)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── Start ─────────────────────────────────────────────────────────────────────
boot();
