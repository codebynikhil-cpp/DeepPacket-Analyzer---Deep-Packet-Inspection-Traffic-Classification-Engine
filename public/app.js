// ── Nav ─────────────────────────────────────────────────
function setNav(el) {
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    el.classList.add('active');
}

// ── Toast ─────────────────────────────────────────────────
function showToast(msg, type = 'success') {
    const t = document.createElement('div');
    t.className = 'toast toast-' + type;
    t.textContent = msg;
    document.body.appendChild(t);
    setTimeout(() => t.classList.add('show'), 10);
    setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.remove(), 300); }, 3000);
}

// ── Protocol Donut ───────────────────────────────────────
let protoChart = null;

// ── Throughput Line Chart ─────────────────────────────────
let lineChart   = null;
let ppsHistory  = [];
let timeLabels  = [];
let prevPackets = 0;

function initLineChart() {
    const ctx = document.getElementById('throughputChart').getContext('2d');
    const gradient = ctx.createLinearGradient(0, 0, 0, 300);
    gradient.addColorStop(0, 'rgba(59,130,246,0.25)');
    gradient.addColorStop(1, 'rgba(59,130,246,0.0)');

    lineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: timeLabels,
            datasets: [{
                label: 'Packets/sec',
                data: ppsHistory,
                borderColor: '#3b82f6',
                backgroundColor: gradient,
                borderWidth: 2,
                pointRadius: 0,
                pointHoverRadius: 5,
                pointHoverBackgroundColor: '#3b82f6',
                fill: true,
                tension: 0.45
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 300 },
            interaction: { mode: 'index', intersect: false },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#111827',
                    titleFont: { family: 'Inter', size: 12 },
                    bodyFont: { family: 'Inter', size: 13, weight: '600' },
                    padding: 10, cornerRadius: 7, displayColors: false,
                    callbacks: {
                        title: items => items[0].label,
                        label: item  => `${item.raw} pkts/s`
                    }
                }
            },
            scales: {
                x: { grid: { display: false, drawBorder: false }, ticks: { display: false } },
                y: {
                    grid: { color: '#f3f4f6', drawBorder: false },
                    beginAtZero: true,
                    ticks: { font: { family: 'Inter', size: 11 }, color: '#9ca3af', maxTicksLimit: 5 }
                }
            }
        }
    });
}

function updateLineChart(currentPackets) {
    const pps = Math.max(0, currentPackets - prevPackets);
    prevPackets = currentPackets;
    const now = new Date().toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'});
    timeLabels.push(now);
    ppsHistory.push(pps);
    if (timeLabels.length > 60) { timeLabels.shift(); ppsHistory.shift(); }
    if (lineChart) lineChart.update();
}

function renderProto(protocols, total) {
    const tcp  = protocols?.TCP  || 0;
    const udp  = protocols?.UDP  || 0;
    const icmp = protocols?.ICMP || 0;
    const ipv6 = protocols?.IPv6 || 0;
    const rest = Math.max(0, total - tcp - udp - icmp - ipv6);

    const colors = ['#3b82f6','#8b5cf6','#f59e0b','#10b981','#e5e7eb'];
    const labels = ['TCP','UDP','ICMP','IPv6','Other'];
    const values = [tcp, udp, icmp, ipv6, rest];

    const ctx = document.getElementById('protoChart').getContext('2d');
    if (protoChart) { protoChart.data.datasets[0].data = values; protoChart.update(); }
    else {
        protoChart = new Chart(ctx, {
            type: 'doughnut',
            data: { labels, datasets:[{ data:values, backgroundColor:colors, borderColor:'#fff', borderWidth:3, hoverOffset:6 }] },
            options: {
                cutout:'72%', maintainAspectRatio:true, animation:{animateRotate:true},
                plugins:{ legend:{display:false}, tooltip:{callbacks:{label:c=>` ${c.label}: ${c.raw} pkts`}} }
            }
        });
    }

    const stats = document.getElementById('protoStats');
    stats.innerHTML = labels.map((l,i) => {
        if (values[i] === 0) return '';
        const pct = total > 0 ? ((values[i]/total)*100).toFixed(1) : '0.0';
        return `<div class="proto-row">
            <div class="proto-dot" style="background:${colors[i]}"></div>
            <div class="proto-name">${l}</div>
            <div class="proto-count">${values[i]} pkts</div>
            <div class="proto-pct">${pct}%</div>
        </div>`;
    }).join('');
}

// ── Application Table ────────────────────────────────────
const APP_COLORS = ['#3b82f6','#8b5cf6','#10b981','#f59e0b','#ef4444','#06b6d4','#ec4899','#84cc16','#f97316','#6366f1','#14b8a6','#a855f7','#f43f5e','#0ea5e9','#78716c','#a3e635'];

function renderApps(apps) {
    const tbody = document.getElementById('appsTbody');
    const badge = document.getElementById('appBadge');
    if (!apps || !Object.keys(apps).length) {
        tbody.innerHTML = '<tr><td colspan="5" class="log-empty">No application data</td></tr>';
        return;
    }
    const entries = Object.entries(apps).sort((a,b)=>b[1]-a[1]);
    const tot = entries.reduce((s,[,v])=>s+v,0);
    badge.textContent = `${entries.length} apps detected`;
    tbody.innerHTML = entries.map(([name,count],i)=>{
        const pct = tot>0 ? ((count/tot)*100).toFixed(1) : '0.0';
        const col = APP_COLORS[i % APP_COLORS.length];
        return `<tr>
            <td class="rank">${String(i+1).padStart(2,'0')}</td>
            <td class="app-name">${name}</td>
            <td class="conn-n">${count}</td>
            <td class="pct-n">${pct}%</td>
            <td><div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${col}"></div></div></td>
        </tr>`;
    }).join('');
}

function renderDomains(domains) {
    const tbody = document.getElementById('domainsTbody');
    const badge = document.getElementById('domainBadge');
    if (!tbody) return;
    if (!domains || !Object.keys(domains).length) {
        tbody.innerHTML = '<tr><td colspan="5" class="log-empty">No domain data captured yet</td></tr>';
        if (badge) badge.textContent = '0 domains';
        return;
    }
    const entries = Object.entries(domains).sort((a,b)=>b[1]-a[1]);
    const tot = entries.reduce((s,[,v])=>s+v,0);
    if (badge) badge.textContent = `${entries.length} domain(s) observed`;
    tbody.innerHTML = entries.map(([name,count],i)=>{
        const pct = tot>0 ? ((count/tot)*100).toFixed(1) : '0.0';
        const col = APP_COLORS[(i + 3) % APP_COLORS.length];
        return `<tr>
            <td class="rank">${String(i+1).padStart(2,'0')}</td>
            <td class="app-name" style="font-family:monospace;font-size:13px">${name}</td>
            <td class="conn-n">${count}</td>
            <td class="pct-n">${pct}%</td>
            <td><div class="bar-track"><div class="bar-fill" style="width:${pct}%;background:${col}"></div></div></td>
        </tr>`;
    }).join('');
}

function renderFlows(flows) {
    const tbody = document.getElementById('flowsTbody');
    const badge = document.getElementById('flowsBadge');
    if (!tbody) return;
    if (!flows || !flows.length) {
        tbody.innerHTML = '<tr><td colspan="9" class="log-empty">Waiting for connection flows...</td></tr>';
        return;
    }
    if (badge) badge.textContent = `${flows.length} recent flow(s)`;
    // Render most recent flows at top
    const reversed = [...flows].reverse();
    tbody.innerHTML = reversed.map(f => {
        const isDrop = f.policy === 'DROP';
        const polBadge = isDrop ? '<span class="log-badge" style="background:#ef4444;color:#fff">DROP</span>' : '<span class="log-badge" style="background:#10b981;color:#fff">FORWARD</span>';
        const enfBadge = f.enforcement.includes('WFP ACTIVE') ? '<span style="color:#10b981;font-weight:600">WFP ACTIVE</span>' : '<span style="color:#9ca3af">MONITOR</span>';
        return `<tr>
            <td style="color:#9ca3af;font-size:12px">${f.time}</td>
            <td style="font-family:monospace;font-size:12px">${f.src_ip}:${f.src_port}</td>
            <td style="font-family:monospace;font-size:12px">${f.dst_ip}:${f.dst_port}</td>
            <td><span class="log-badge b-dns" style="font-size:10px">${f.protocol}</span></td>
            <td style="font-family:monospace;font-size:12px;font-weight:500">${f.domain}</td>
            <td style="font-weight:600">${f.application}</td>
            <td><span style="font-size:11px;background:#f3f4f6;padding:2px 6px;border-radius:4px">${f.method}</span></td>
            <td>${polBadge}</td>
            <td style="font-size:11.5px">${enfBadge}</td>
        </tr>`;
    }).join('');
}

async function fetchHealth() {
    try {
        const r = await fetch('/health');
        if (!r.ok) return;
        const data = await r.json();
        renderHealth(data.websites);
    } catch(e) {}
}

function renderHealth(websites) {
    const grid = document.getElementById('healthGrid');
    if (!grid || !websites) return;

    grid.innerHTML = Object.values(websites).map(site => {
        let stateClass = 'green';
        let stateText = site.state;
        let latencyText = site.latency_ms ? `${site.latency_ms} ms` : (site.reason || '—');

        if (site.state === 'BLOCKED BY POLICY') {
            stateClass = 'red';
            stateText = 'BLOCKED BY POLICY';
            latencyText = 'Firewall active';
        } else if (site.state === 'DOWN') {
            stateClass = 'red';
            stateText = 'DOWN';
        }

        return `<div class="kpi" style="padding:14px">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
                <span style="font-weight:700;font-size:14px">${site.name}</span>
                <span style="font-size:10px;text-transform:uppercase;background:#f3f4f6;padding:2px 6px;border-radius:4px;color:#6b7280">${site.category || 'web'}</span>
            </div>
            <div class="kpi-val ${stateClass}" style="font-size:15px;font-weight:700">${stateText}</div>
            <div class="kpi-sub" style="display:flex;justify-content:space-between;margin-top:4px">
                <span>${site.domain}</span>
                <span style="font-weight:600">${latencyText}</span>
            </div>
        </div>`;
    }).join('');
}

// ── DNS List ─────────────────────────────────────────────
function renderDns(dns) {
    const ul = document.getElementById('dnsList');
    document.getElementById('dnsPill').textContent = dns?.length || 0;
    if (!dns?.length) { ul.innerHTML='<div class="log-empty">No DNS queries captured</div>'; return; }
    ul.innerHTML = dns.map(d=>`<li class="log-li"><span class="log-badge b-dns">DNS</span><span class="log-txt">${d}</span></li>`).join('');
}

// ── HTTP List ────────────────────────────────────────────
function renderHttp(http) {
    const ul = document.getElementById('httpList');
    document.getElementById('httpPill').textContent = http?.length || 0;
    if (!http?.length) { ul.innerHTML='<div class="log-empty">No HTTP captured</div>'; return; }
    ul.innerHTML = http.map(r=>{
        const m = r.split(' ')[0];
        const u = r.substring(r.indexOf(' ')+1);
        const bc = m==='POST'?'b-post':'b-get';
        return `<li class="log-li"><span class="log-badge ${bc}">${m}</span><span class="log-txt">${u}</span></li>`;
    }).join('');
}

// ── Alerts ───────────────────────────────────────────────
function renderAlerts(alerts) {
    const n = alerts?.length || 0;
    document.getElementById('alertsBadge').textContent = `${n} event${n!==1?'s':''}`;
    document.getElementById('kpiAlerts').textContent = n;
    const navBadge = document.getElementById('alertNavBadge');
    navBadge.style.display = n>0 ? 'inline' : 'none';
    navBadge.textContent = n;

    const empty = document.getElementById('alertsEmpty');
    const tbl   = document.getElementById('alertsTbl');
    const tbody = document.getElementById('alertsTbody');
    const kpi   = document.getElementById('kpiAlertCard');
    const sub   = document.getElementById('kpiAlertSub');
    const kpiV  = document.getElementById('kpiAlerts');

    if (n===0) {
        empty.style.display='flex'; tbl.style.display='none';
        kpiV.className='kpi-val green'; sub.textContent='✓ System clean';
    } else {
        empty.style.display='none'; tbl.style.display='table';
        kpiV.className='kpi-val red'; sub.textContent='⚠ Requires attention';
        tbody.innerHTML = alerts.map(a=>`
            <tr>
                <td><span style="background:#fef2f2;color:#ef4444;border:1px solid #fecaca;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700">CRITICAL</span></td>
                <td style="font-weight:500">${a}</td>
                <td style="color:#9ca3af">Unresolved</td>
            </tr>`).join('');
    }
}

// ── Rules UI ─────────────────────────────────────────────
async function loadRules() {
    try {
        const r = await fetch('/rules');
        const rules = await r.json();
        renderRules(rules);
    } catch(e) { console.warn('Rules API error',e); }
}

function renderRuleList(ulId, pillId, items, type) {
    const ul = document.getElementById(ulId);
    document.getElementById(pillId).textContent = items?.length || 0;
    if (!items?.length) { ul.innerHTML='<div class="rule-empty">No rules defined</div>'; return; }
    ul.innerHTML = items.map(v=>`
        <li class="rule-item">
            <span>${v}</span>
            <button class="btn-del" onclick="deleteRule('${type}','${v}')">Remove</button>
        </li>`).join('');
}

function renderRules(rules) {
    const total = (rules.blocked_domains?.length||0) + (rules.blocked_ips?.length||0) + (rules.blocked_apps?.length||0) + (rules.blocked_ports?.length||0);
    document.getElementById('rulesBadge').textContent = `${total} active rule${total!==1?'s':''}`;
    renderRuleList('domainRules','domainPill', rules.blocked_domains, 'domain');
    renderRuleList('ipRules',    'ipPill',     rules.blocked_ips,     'ip');
    renderRuleList('appRules',   'appPill',    rules.blocked_apps,    'app');
    renderRuleList('portRules',  'portPill',   rules.blocked_ports,   'port');
}

async function addRule() {
    const type  = document.getElementById('ruleType').value;
    const value = document.getElementById('ruleValue').value.trim();
    if (!value) { showToast('Please enter a value to block', 'error'); return; }

    try {
        const r = await fetch('/rules', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type, value })
        });
        const data = await r.json();
        if (data.success) {
            renderRules(data.rules);
            document.getElementById('ruleValue').value = '';
            showToast(`✓ Blocked ${type}: ${value}`);
            if (type === 'domain' || type === 'ip') {
                setTimeout(() => showToast('Note: Re-open browser tab/app for block to affect active connections', 'info'), 1500);
            }
            fetchHealth();
        } else {
            showToast('Failed to save rule: ' + (data.error || 'unknown error'), 'error');
        }
    } catch(e) {
        showToast('Cannot reach server. Is node server.js running?', 'error');
        console.error('addRule error:', e);
    }
}

async function deleteRule(type, value) {
    try {
        const r = await fetch('/rules', {
            method: 'DELETE',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type, value })
        });
        const data = await r.json();
        if (data.success) {
            renderRules(data.rules);
            showToast(`✓ Unblocked ${type}: ${value}`);
            fetchHealth();
        }
    } catch(e) {
        showToast('Cannot reach server', 'error');
    }
}

// ── Main Update ──────────────────────────────────────────
function updateDashboard(data) {
    const total = data.packets || 0;
    const bytes = data.bytes   || 0;
    const mode  = data.mode    || 'offline';
    const src   = data.source_name || 'pcap';
    const protectReq = data.protection_requested || false;

    const modeText = document.getElementById('modeText');
    if (modeText) {
        if (mode === 'live') {
            const protTag = protectReq ? ' · <span style="color:#10b981">PROTECT ON</span>' : ' · <span style="color:#f59e0b">MONITOR ONLY</span>';
            modeText.innerHTML = `<span style="color:#10b981">LIVE ●</span> ${src}${protTag}`;
        } else {
            modeText.innerHTML = `<span style="color:#6366f1">OFFLINE 📄</span> ${src}`;
        }
    }

    document.getElementById('kpiPackets').textContent = total.toLocaleString();
    document.getElementById('kpiBytes').textContent = bytes >= 1048576
        ? (bytes/1048576).toFixed(2)+' MB'
        : bytes >= 1024 ? (bytes/1024).toFixed(2)+' KB' : bytes+' B';
    document.getElementById('kpiConns').textContent   = (data.connections ?? '—').toLocaleString();
    document.getElementById('kpiDropped').textContent = (data.dropped    ?? 0).toLocaleString();
    
    if (document.getElementById('kpiCapDrops')) {
        document.getElementById('kpiCapDrops').textContent = (data.capture_drops ?? 0).toLocaleString();
    }
    if (document.getElementById('kpiProcDrops')) {
        document.getElementById('kpiProcDrops').textContent = (data.processing_drops ?? 0).toLocaleString();
    }

    const wfp = data.wfp;
    if (document.getElementById('kpiWfpStatus')) {
        const wfpEl  = document.getElementById('kpiWfpStatus');
        const wfpSub = document.getElementById('kpiWfpSub');
        if (wfp && wfp.active) {
            wfpEl.className = 'kpi-val green';
            wfpEl.textContent = 'ACTIVE';
            wfpSub.textContent = `Protection ON · ${wfp.total_filters} kernel filter(s)`;
        } else if (protectReq) {
            wfpEl.className = 'kpi-val red';
            wfpEl.textContent = 'NO ADMIN';
            wfpSub.textContent = 'Run terminal as Admin for WFP';
        } else {
            wfpEl.className = 'kpi-val';
            wfpEl.textContent = 'OFF';
            wfpSub.textContent = 'Protection OFF (Monitor Mode)';
        }
    }

    document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
    document.getElementById('statusText').textContent = (mode === 'live' ? 'Live Capture · ' : 'Offline PCAP · ') + new Date().toLocaleTimeString();

    renderProto(data.protocols, total);
    updateLineChart(total);
    renderApps(data.applications);
    renderDomains(data.domains);
    renderFlows(data.flows);
    renderDns(data.dns);
    renderHttp(data.http);
    renderAlerts(data.alerts);
}

// ── Polling ──────────────────────────────────────────────
async function fetchData() {
    try {
        const r = await fetch('/data');
        if (r.ok) updateDashboard(await r.json());
    } catch(e) {
        document.getElementById('statusText').textContent = 'API unreachable';
    }
}

loadRules();
initLineChart();
fetchData();
fetchHealth();
setInterval(fetchData, 500);   // 500ms fast polling for live streaming metrics
setInterval(fetchHealth, 8000); // 8s periodic health check updates
setInterval(loadRules, 5000);   // refresh rules every 5s

