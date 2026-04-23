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
        }
    } catch(e) {
        showToast('Cannot reach server', 'error');
    }
}

// ── Main Update ──────────────────────────────────────────
function updateDashboard(data) {
    const total = data.packets || 0;
    const bytes = data.bytes   || 0;
    const tcp   = data.protocols?.TCP  || 0;
    const udp   = data.protocols?.UDP  || 0;

    document.getElementById('kpiPackets').textContent = total.toLocaleString();
    document.getElementById('kpiBytes').textContent = bytes >= 1048576
        ? (bytes/1048576).toFixed(2)+' MB'
        : bytes >= 1024 ? (bytes/1024).toFixed(2)+' KB' : bytes+' B';
    document.getElementById('kpiConns').textContent   = (data.connections ?? '—').toLocaleString();
    document.getElementById('kpiDropped').textContent = (data.dropped    ?? 0).toLocaleString();
    document.getElementById('lastUpdate').textContent = new Date().toLocaleTimeString();
    document.getElementById('statusText').textContent = 'Live · ' + new Date().toLocaleTimeString();

    renderProto(data.protocols, total);
    renderApps(data.applications);
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
fetchData();
setInterval(fetchData, 1000);
setInterval(loadRules, 5000);  // refresh rules every 5s
