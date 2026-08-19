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
    res.json({ success: true, rules });
});

app.listen(PORT, () => {
    console.log(`📡 Packet Analyzer Server Running!`);
    console.log(`👉 UI Dashboard : http://localhost:${PORT}/`);
    console.log(`👉 API Data     : http://localhost:${PORT}/data`);
    console.log(`👉 Rules API    : http://localhost:${PORT}/rules`);
});
