const express = require('express');
const cors    = require('cors');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const PORT = 3000;

const DATA_FILE  = path.join(__dirname, 'output.json');
const RULES_FILE = path.join(__dirname, 'rules.json');

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── helpers ──────────────────────────────────────────────
function readJson(file, fallback) {
    try {
        let content = fs.readFileSync(file, 'utf8');
        try {
            return JSON.parse(content);
        } catch (e) {
            // Fix unescaped Windows backslashes (e.g. \Device\NPF_...)
            content = content.replace(/\\(?!["\\/bfnrtu])/g, '\\\\');
            return JSON.parse(content);
        }
    } catch {
        return fallback;
    }
}

function writeJson(file, data) {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// ── GET /data ─────────────────────────────────────────────
app.get('/data', (req, res) => {
    const data = readJson(DATA_FILE, { error: 'output.json not found' });
    res.json(data);
});

// ── GET /mode ─────────────────────────────────────────────
app.get('/mode', (req, res) => {
    const data = readJson(DATA_FILE, {});
    res.json({
        mode: data.mode || 'offline',
        source_name: data.source_name || 'pcap',
        capture_drops: data.capture_drops || 0,
        processing_drops: data.processing_drops || 0
    });
});

// ── GET /rules ────────────────────────────────────────────
app.get('/rules', (req, res) => {
    const rules = readJson(RULES_FILE, {
        blocked_ips: [], blocked_domains: [],
        blocked_apps: [], blocked_ports: []
    });
    res.json(rules);
});

function touchReloadFlag() {
    try {
        fs.writeFileSync(path.join(__dirname, 'rules_reload.flag'), 'reload');
    } catch (e) {
        console.warn('Failed to write rules_reload.flag', e);
    }
}

// ── POST /rules ───────────────────────────────────────────
// Body: { type: "ip"|"domain"|"app"|"port", value: "..." }
app.post('/rules', (req, res) => {
    const { type, value } = req.body;
    if (!type || !value) return res.status(400).json({ error: 'type and value required' });

    const rules = readJson(RULES_FILE, {
        blocked_ips: [], blocked_domains: [],
        blocked_apps: [], blocked_ports: []
    });

    const keyMap = { ip: 'blocked_ips', domain: 'blocked_domains',
                     app: 'blocked_apps', port: 'blocked_ports' };
    const key = keyMap[type];
    if (!key) return res.status(400).json({ error: 'Invalid rule type' });

    const v = type === 'port' ? parseInt(value) : value.trim();
    if (!rules[key].includes(v)) rules[key].push(v);

    writeJson(RULES_FILE, rules);
    touchReloadFlag();
    res.json({ success: true, rules });
});

// ── DELETE /rules ─────────────────────────────────────────
// Body: { type, value }
app.delete('/rules', (req, res) => {
    const { type, value } = req.body;
    const rules = readJson(RULES_FILE, {
        blocked_ips: [], blocked_domains: [],
        blocked_apps: [], blocked_ports: []
    });

    const keyMap = { ip: 'blocked_ips', domain: 'blocked_domains',
                     app: 'blocked_apps', port: 'blocked_ports' };
    const key = keyMap[type];
    if (!key) return res.status(400).json({ error: 'Invalid rule type' });

    const v = type === 'port' ? parseInt(value) : value;
    rules[key] = rules[key].filter(x => x !== v);

    writeJson(RULES_FILE, rules);
    touchReloadFlag();
    res.json({ success: true, rules });
});


const https = require('https');
const http  = require('http');

const CRITICAL_FILE = path.join(__dirname, 'critical_websites.json');

// ── GET /critical-websites ────────────────────────────────
app.get('/critical-websites', (req, res) => {
    const data = readJson(CRITICAL_FILE, { websites: [] });
    res.json(data);
});

// ── Health checker cache ──────────────────────────────────
let healthCache = {};
let lastHealthCheck = 0;

function checkUrlHealth(targetUrl, timeoutMs = 4000) {
    return new Promise((resolve) => {
        const start = Date.now();
        const client = targetUrl.startsWith('https') ? https : http;
        const req = client.get(targetUrl, { timeout: timeoutMs, headers: { 'User-Agent': 'DeepPacket-HealthChecker/1.0' } }, (resp) => {
            const elapsed = Date.now() - start;
            resp.resume(); // consume response data to free up memory
            resolve({ status: 'UP', latency_ms: elapsed, code: resp.statusCode });
        });
        req.on('timeout', () => {
            req.destroy();
            resolve({ status: 'DOWN', latency_ms: null, reason: 'timeout' });
        });
        req.on('error', (err) => {
            resolve({ status: 'DOWN', latency_ms: null, reason: err.code || err.message });
        });
    });
}

// ── GET /health ───────────────────────────────────────────
app.get('/health', async (req, res) => {
    const rules = readJson(RULES_FILE, { blocked_domains: [] });
    const blockedDomains = rules.blocked_domains || [];
    const critData = readJson(CRITICAL_FILE, { websites: [] });
    const websites = critData.websites || [];

    const now = Date.now();
    // Cache health probes for 10 seconds
    if (now - lastHealthCheck < 10000 && Object.keys(healthCache).length > 0) {
        return res.json(healthCache);
    }

    const results = {};
    for (const site of websites) {
        const primaryDomain = site.domains[0].replace('*.', '');
        
        // Check if blocked by policy
        const isBlocked = blockedDomains.some(bd => {
            const cleanBd = bd.replace('*.', '').toLowerCase();
            return primaryDomain.toLowerCase() === cleanBd || primaryDomain.toLowerCase().endsWith('.' + cleanBd);
        });

        if (isBlocked) {
            results[site.name] = {
                name: site.name,
                domain: primaryDomain,
                category: site.category,
                state: 'BLOCKED BY POLICY',
                latency_ms: null,
                last_checked: new Date().toLocaleTimeString()
            };
        } else {
            const probe = await checkUrlHealth(`https://${primaryDomain}`);
            results[site.name] = {
                name: site.name,
                domain: primaryDomain,
                category: site.category,
                state: probe.status,
                latency_ms: probe.latency_ms,
                reason: probe.reason || (probe.code ? `HTTP ${probe.code}` : ''),
                last_checked: new Date().toLocaleTimeString()
            };
        }
    }

    healthCache = { last_updated: new Date().toISOString(), websites: results };
    lastHealthCheck = now;
    res.json(healthCache);
});

app.listen(PORT, () => {
    console.log(`📡 Packet Analyzer Server Running!`);
    console.log(`👉 UI Dashboard : http://localhost:${PORT}/`);
    console.log(`👉 API Data     : http://localhost:${PORT}/data`);
    console.log(`👉 Rules API    : http://localhost:${PORT}/rules`);
    console.log(`👉 Health API   : http://localhost:${PORT}/health`);
});

