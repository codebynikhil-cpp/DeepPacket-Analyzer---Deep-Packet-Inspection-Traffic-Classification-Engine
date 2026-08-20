# DeepPacket Analyzer

A real-time C++17 Deep Packet Inspection (DPI) engine for live network traffic capture, classification, and enforcement — paired with an interactive web dashboard.

---

## What It Does

- **Live packet capture** via Npcap (Windows) on any network interface
- **Offline PCAP analysis** for pre-recorded captures
- **Deep packet inspection**: DNS, HTTP Host, TLS ClientHello (SNI), QUIC Initial
- **Generic domain detection**: any domain seen in DNS responses is tracked — no hardcoded lists required
- **Connection tracking**: 5-tuple flows with state machine (NEW → ESTABLISHED → CLASSIFIED)
- **Application classification**: maps SNI/host to application name (YouTube, GitHub, Discord, etc.) with fallback to raw domain
- **FastPath**: caches per-flow classification decisions to skip re-inspection of established flows
- **Rule engine**: block/allow by IP, port, domain (with `*.wildcard.com` support), or application type
- **WFP enforcement** (Windows): installs kernel-level Windows Filtering Platform filters for actual network blocking
- **Monitor mode**: captures and classifies traffic without installing any kernel filters
- **Protect mode**: same as monitor but also installs WFP filters when block rules are active
- **Live web dashboard**: real-time throughput, protocol breakdown, top applications, DNS queries, recent connection flows, security alerts
- **Critical website health monitor**: configurable list of websites probed via HTTPS with latency reporting
- **Reference-counted WFP filters**: overlapping domain + IP rules share one kernel filter; filter removed only when last rule is deleted
- **Dynamic rule reload**: edit `rules.json` at runtime — no restart required
- **Fail-safe shutdown**: dynamic WFP session auto-removes all kernel filters on clean exit or crash

---

## Architecture

```text
Npcap / PCAP File
       │
       ▼
 PacketQueue (lock-free producer-consumer, 10k capacity)
       │
       ├── Producer Thread (Npcap callback → raw packet)
       │
       └── Consumer Thread
              │
              ├── PacketParser (Ethernet → IP → TCP/UDP → payload)
              ├── FastPath (cached flow decisions)
              ├── DPI Engine
              │     ├── TLS SNI extractor
              │     ├── QUIC Initial parser
              │     ├── HTTP Host parser
              │     └── DNS parser (query + response + TTL)
              ├── ConnectionTracker
              │     ├── DNS → IP correlation (with TTL expiry)
              │     ├── Application classification
              │     └── Flow recording (last 100 connections)
              ├── RuleManager (IP / port / domain / app rules)
              └── WFP Enforcement (kernel filters, protect mode only)

Telemetry Thread (500ms interval)
       └── output.json (read by Node.js server → dashboard)

Node.js Server (port 3000)
       ├── GET  /data           → live stats
       ├── GET  /rules          → current rules
       ├── POST /rules/block-ip
       ├── POST /rules/block-domain
       ├── POST /rules/block-port
       ├── DELETE /rules/...    → remove rules
       ├── GET  /health         → critical website probe
       └── GET  /               → dashboard UI
```

---

## Requirements

| Requirement | Notes |
|---|---|
| Windows 10/11 | WFP enforcement is Windows-only |
| [Npcap](https://npcap.com/#download) | Install with "WinPcap API-compatible mode" checked |
| CMake 3.16+ | Build system |
| Visual Studio 2022 (MSVC) | C++17 compiler |
| Node.js 18+ | Dashboard server |
| Administrator | Required only for `--protect` mode (WFP) and live capture |

---

## Build

```powershell
# Configure
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release

# Build
cmake --build build --config Release

# Install Node.js dependencies (first time only)
npm install
```

---

## Run

### 1. List network interfaces
```powershell
.\build\PacketInspector.exe --list-interfaces
```

### 2. Start the web dashboard server
```powershell
npm start
```
Open **http://localhost:3000** in your browser.

### 3. Monitor mode (no WFP, no elevation required for Npcap-permitted users)
```powershell
.\build\PacketInspector.exe --interface 6
```

### 4. Protect mode (WFP enforcement active — requires Administrator)
```powershell
# Run PowerShell as Administrator
.\build\PacketInspector.exe --interface 6 --protect
```

### 5. Offline PCAP analysis
```powershell
.\build\PacketInspector.exe --pcap capture.pcap output_filtered.pcap
```

---

## Operating Modes

| Flag | WFP | Effect |
|---|---|---|
| `--interface <id>` | OFF | Monitor only — classifies and logs traffic, installs no kernel filters |
| `--interface <id> --protect` | ON | Monitor + enforcement — block rules take effect as real kernel WFP filters |

> **Note:** Already-established TCP connections are not retroactively dropped when a block rule is added. The block applies to **new** connection attempts only. To fully block an active connection, close the browser tab and ensure a new connection is initiated after the rule is in place.

---

## Block Rules (via REST API or rules.json)

```bash
# Block an IP
curl -X POST http://localhost:3000/rules/block-ip   -H "Content-Type: application/json" -d '{"ip":"1.2.3.4"}'

# Block a domain (wildcards supported)
curl -X POST http://localhost:3000/rules/block-domain -H "Content-Type: application/json" -d '{"domain":"*.example.com"}'

# Block a port
curl -X POST http://localhost:3000/rules/block-port  -H "Content-Type: application/json" -d '{"port":4444}'

# Remove a rule
curl -X DELETE http://localhost:3000/rules/unblock-domain -H "Content-Type: application/json" -d '{"domain":"*.example.com"}'
```

Rules are saved to `rules.json` and reloaded dynamically (no restart needed).

---

## Critical Website Health Monitor

Configure `critical_websites.json` to list websites to probe:

```json
{
  "sites": [
    { "name": "GitHub", "url": "https://github.com", "domains": ["github.com"] },
    { "name": "Coursera", "url": "https://www.coursera.org", "domains": ["coursera.org"] }
  ]
}
```

Results available at `GET /health`.

---

## Configuration Files

| File | Purpose | Committed |
|---|---|---|
| `rules.json` | Persisted block rules (IP, domain, port, app) | Yes (default empty) |
| `critical_websites.json` | Sites to health-probe | Yes |
| `output.json` | Runtime telemetry output (gitignored) | No |

---

## Telemetry Output

While running, `output.json` is written every 500ms and includes:

```json
{
  "packets": 21189,
  "processing_drops": 0,
  "max_queue_depth": 388,
  "packets_pushed": 21189,
  "packets_popped": 21189,
  "mode": "live",
  "protection_requested": false,
  "applications": { "GitHub": 23, "YouTube": 4, "Discord": 8 },
  "domains": { "github.com": 23, "youtube.com": 4 },
  "flows": [ ... ],
  "wfp": { "active": false, "status": "NOT INITIALIZED", "ip_filters": 0 }
}
```

---

## Known Limitations

- **WFP requires Administrator**: `--protect` mode silently falls back to monitor mode if not elevated. Check `wfp.status` in `output.json`.
- **Established connections**: block rules apply only to new connections. Existing TCP sessions are not terminated.
- **Domain→IP mapping depends on DNS observation**: if a DNS response for a domain was not captured before a block rule was added, the IP filter cannot be installed until the next DNS resolution is observed.
- **DNS TTL expiry**: cached IP→domain mappings expire per DNS TTL. After expiry, connections revert to IP-only classification until the next DNS resolution is observed.
- **QUIC/GQUIC**: QUIC SNI extraction works on standard QUIC Initial packets. Obfuscated or proprietary QUIC variants may not yield an SNI.
- **Windows only**: WFP enforcement is Windows-specific. The capture engine (Npcap/libpcap) and DPI pipeline work cross-platform, but WFP code is `#ifdef _WIN32` guarded.

---

## Windows Setup

See [WINDOWS_SETUP.md](WINDOWS_SETUP.md) for step-by-step Npcap installation, Visual Studio configuration, and CMake setup.
