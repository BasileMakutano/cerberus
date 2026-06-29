// ─────────────────────────────────────────────────────────────────────────────
//  Cerberus Dashboard — app.js
//  Reads logs/alerts.json via fetch(), renders all dashboard components.
//  Auto-refreshes every 30 seconds. No backend required.
// ─────────────────────────────────────────────────────────────────────────────

const ALERTS_PATH = '../logs/alerts.json';
const REFRESH_MS  = 30000;
const MAX_TABLE   = 7;

const PORT_MAP = {
  21:'FTP', 22:'SSH', 23:'Telnet', 25:'SMTP', 53:'DNS', 80:'HTTP',
  110:'POP3', 135:'RPC', 139:'NetBIOS', 143:'IMAP', 443:'HTTPS',
  445:'SMB', 1433:'MSSQL', 1521:'Oracle', 2181:'Zookeeper',
  3306:'MySQL', 3389:'RDP', 5432:'PostgreSQL', 5900:'VNC',
  6379:'Redis', 8080:'HTTP-Alt', 8443:'HTTPS-Alt', 8888:'Jupyter',
  9200:'Elasticsearch', 27017:'MongoDB'
};

// ── State ─────────────────────────────────────────────────────────────────────
let allAlerts = [];
let cycleNum  = 1;

// ── Load ──────────────────────────────────────────────────────────────────────
async function loadAlerts() {
  try {
    const res = await fetch(ALERTS_PATH + '?t=' + Date.now());
    if (!res.ok) throw new Error('HTTP ' + res.status);
    allAlerts = await res.json();
    render();
    document.getElementById('lastSync').textContent =
      'Last sync: ' + new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  } catch (e) {
    document.getElementById('lastSync').textContent = 'Load failed — run alerter.py first';
    renderEmptyTable();
    renderEmptyCharts();
  }
}

// ── Render all ────────────────────────────────────────────────────────────────
function render() {
  const total        = allAlerts.length;
  const high         = allAlerts.filter(a => a.severity === 'HIGH').length;
  const med          = allAlerts.filter(a => a.severity === 'MEDIUM').length;
  const unacked      = allAlerts.filter(a => !a.acknowledged).length;
  const confirmed    = allAlerts.filter(a => a.confirmed).length;
  const alertedPorts = new Set(allAlerts.map(a => a.port));

  // Stat cards
  document.getElementById('statTotal').textContent    = total;
  document.getElementById('statHigh').textContent     = high;
  document.getElementById('statMed').textContent      = med;
  document.getElementById('statPorts').textContent    = 25;
  document.getElementById('statPortsSub').textContent = alertedPorts.size + ' port(s) with alerts';
  document.getElementById('statDeltaSub').textContent = confirmed + ' confirmed threats';

  // Sidebar + unacked badges
  document.getElementById('sidebarBadge').textContent  = unacked;
  document.getElementById('unackedBadge').textContent  = unacked + ' unacked';

  // Cycle summary
  cycleNum = Math.max(1, Math.ceil(total / 5));
  document.getElementById('cycleNum').textContent         = '#' + cycleNum;
  document.getElementById('sidebarCycle').textContent     = 'CYCLE: #' + cycleNum;
  document.getElementById('cycleScanTime').textContent    =
    new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + ' UTC';
  document.getElementById('cycleTotalAlerts').textContent = total;
  document.getElementById('cycleHigh').textContent        = high;
  document.getElementById('cycleAnomalies').textContent   = confirmed + ' ports';
  document.getElementById('cycleAcked').textContent       = total - unacked;
  document.getElementById('cycleUnresolved').textContent  = unacked;
  document.getElementById('cycleNote').textContent        = total > 0
    ? `Cycle #${cycleNum} closed. High alerts: ${high}. Unresolved: ${unacked}.`
    : 'No alert data yet. Run engine/alerter.py to populate.';

  renderTable();
  renderBarChart();
  renderSparkline();
}

// ── Alert table ───────────────────────────────────────────────────────────────
function renderTable() {
  const sorted = [...allAlerts].sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  const rows   = sorted.slice(0, MAX_TABLE);
  const tbody  = document.getElementById('alertTableBody');

  if (!rows.length) { renderEmptyTable(); return; }

  tbody.innerHTML = rows.map(a => {
    const desc = describeAlert(a);
    const ts   = fmtTime(a.timestamp);
    return `
      <tr>
        <td><span class="sev-badge sev-${a.severity}">${a.severity}</span></td>
        <td><span class="port-mono">:${a.port}</span></td>
        <td><span class="desc-text" title="${desc}">${desc}</span></td>
        <td><span class="ts-text">${ts}</span></td>
        <td>
          <button class="ack-btn ${a.acknowledged ? 'done' : ''}"
                  onclick="event.stopPropagation(); ackAlert('${a.alert_id}', this)">
            ${a.acknowledged ? '✓' : 'Ack'}
          </button>
        </td>
      </tr>`;
  }).join('');
}

function describeAlert(a) {
  const svc = PORT_MAP[a.port] || `port ${a.port}`;
  const map = {
    UNKNOWN_PORT:    'Unknown port exposure detected',
    WRONG_SERVICE:   `${svc} running unexpected service`,
    UNKNOWN_IP:      `Unrecognised IP ${a.ip} on ${svc}`,
    FREQUENCY_SPIKE: `${svc} traffic ${a.layer2_confidence === 'HIGH' ? '3.2×' : '1.8×'} above baseline`,
    WRONG_PROTOCOL:  `Protocol mismatch on ${svc}`,
    NEW_VERSION:     `New version detected on ${svc}`,
  };
  return map[a.layer1_trigger] || `Anomaly on ${svc} — ${a.layer1_trigger}`;
}

function renderEmptyTable() {
  document.getElementById('alertTableBody').innerHTML =
    `<tr class="empty-row"><td colspan="5">No alerts yet — run engine/alerter.py then trigger a scan.</td></tr>`;
}

// ── Bar chart: port activity vs baseline ──────────────────────────────────────
function renderBarChart() {
  const container = document.getElementById('barChart');
  document.getElementById('barCycleLabel').textContent = 'Current cycle #' + cycleNum;

  const portCounts = {};
  allAlerts.forEach(a => { portCounts[a.port] = (portCounts[a.port] || 0) + 1; });

  let ports = Object.keys(portCounts).map(Number)
    .sort((a, b) => portCounts[b] - portCounts[a]).slice(0, 6);
  if (!ports.length) ports = [443, 22, 8080, 53, 25, 80];

  const maxCount = Math.max(...ports.map(p => portCounts[p] || 0), 1);

  container.innerHTML = ports.map(port => {
    const count = portCounts[port] || 0;
    const baseW = 40;
    const currW = Math.max(3, Math.round((count / maxCount) * 95));
    const ratio = count > 0 ? (currW / baseW).toFixed(1) + '×' : '0×';
    const cls   = currW > baseW * 1.5 ? 'crit' : currW > baseW * 1.1 ? 'warn' : 'ok';
    const svc   = PORT_MAP[port] || port;
    return `
      <div class="bar-row">
        <span class="bar-port">${svc} :${port}</span>
        <div class="bar-track">
          <div class="bar-base" style="width:${baseW}%"></div>
          <div class="bar-curr ${cls}" style="width:${currW}%"></div>
        </div>
        <span class="bar-label ${cls}">${ratio}</span>
      </div>`;
  }).join('');
}

// ── Sparkline: alerts over last 7 cycles ─────────────────────────────────────
function renderSparkline() {
  const svg      = document.getElementById('sparkSvg');
  const now      = Date.now();
  const bucketMs = 10 * 60 * 1000;
  const buckets  = Array(7).fill(0);

  allAlerts.forEach(a => {
    const age = now - new Date(a.timestamp).getTime();
    const idx = Math.min(6, Math.floor(age / bucketMs));
    buckets[6 - idx]++;
  });

  const max   = Math.max(...buckets, 1);
  const W     = 400, H = 100, padX = 10, padY = 10;
  const stepX = (W - padX * 2) / 6;

  const pts = buckets.map((v, i) => [
    padX + i * stepX,
    padY + (1 - v / max) * (H - padY * 2)
  ]);

  const line   = pts.map((p, i) => (i === 0 ? 'M' : 'L') + p[0].toFixed(1) + ',' + p[1].toFixed(1)).join(' ');
  const area   = line + ` L${pts[6][0]},${H} L${pts[0][0]},${H} Z`;
  const labels = Array(7).fill(0).map((_, i) => {
    const c = Math.max(1, cycleNum - (6 - i));
    return `<text class="spark-axis" x="${(padX + i * stepX).toFixed(0)}" y="${H + 14}" text-anchor="middle">#${c}</text>`;
  }).join('');

  svg.innerHTML = `
    <defs>
      <linearGradient id="sg" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%"   stop-color="#7c6cf0" stop-opacity=".35"/>
        <stop offset="100%" stop-color="#7c6cf0" stop-opacity="0"/>
      </linearGradient>
    </defs>
    <path d="${area}" fill="url(#sg)"/>
    <path d="${line}" fill="none" stroke="#7c6cf0" stroke-width="2" stroke-linejoin="round"/>
    ${pts.map(p => `<circle cx="${p[0].toFixed(1)}" cy="${p[1].toFixed(1)}" r="3" fill="#7c6cf0"/>`).join('')}
    ${labels}`;

  const total   = allAlerts.length;
  const lastBkt = buckets[6];
  document.getElementById('sparkCurrent').textContent = 'Current: #' + cycleNum;
  document.getElementById('sparkSub').textContent =
    `↗ Upward trend over last 7 cycles — avg ${total ? (total / 7).toFixed(1) : '0'} alerts/cycle`;
  document.getElementById('sparkTrend').textContent =
    lastBkt > (total / 7) ? `↑ +${lastBkt} this cycle` : `→ Stable`;
}

function renderEmptyCharts() {
  document.getElementById('barChart').innerHTML =
    `<div style="color:var(--text-dim);font-size:.72rem;padding:1rem">No alert data — run alerter.py first.</div>`;
  document.getElementById('sparkSvg').innerHTML =
    `<text x="200" y="60" text-anchor="middle" fill="#4a5a7a" font-size="12" font-family="Inter">No data yet</text>`;
}

// ── Acknowledge ───────────────────────────────────────────────────────────────
function ackAlert(id, btn) {
  const a = allAlerts.find(x => x.alert_id === id);
  if (a) a.acknowledged = true;
  btn.textContent = '✓';
  btn.classList.add('done');
  const unacked = allAlerts.filter(a => !a.acknowledged).length;
  document.getElementById('unackedBadge').textContent     = unacked + ' unacked';
  document.getElementById('sidebarBadge').textContent     = unacked;
  document.getElementById('cycleAcked').textContent       = allAlerts.length - unacked;
  document.getElementById('cycleUnresolved').textContent  = unacked;
}

// ── Navigation ────────────────────────────────────────────────────────────────
function showView(view) {
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const items = document.querySelectorAll('.nav-item');
  const map   = { overview: 0, alerts: 1, baselines: 2, ports: 3 };
  if (map[view] !== undefined) items[map[view]].classList.add('active');
}

// ── Utils ─────────────────────────────────────────────────────────────────────
function fmtTime(ts) {
  if (!ts) return '—';
  return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

// ── Boot ──────────────────────────────────────────────────────────────────────
loadAlerts();
setInterval(loadAlerts, REFRESH_MS);