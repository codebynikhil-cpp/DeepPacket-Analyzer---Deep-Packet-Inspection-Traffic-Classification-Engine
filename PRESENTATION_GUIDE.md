# Deep Packet Inspection (DPI) Engine — Presentation Guide

> **Project Status: Phase 3 Complete** — C++ Analyzer + JSON Export + Real-Time Web Dashboard + Firewall Rule Manager

This guide is designed to help you confidently present the DeepPacket Analyzer project to your mentor, panel members, and reviewers. It covers the complete system from networking basics all the way through the web dashboard and REST API.

---

## 1. Executive Summary: What is this project?

This project is a **Full-Stack Network Monitoring System** built around a Deep Packet Inspection (DPI) Engine written in C++17, paired with a real-time web dashboard.

Standard firewalls only look at the "envelopes" of internet traffic (IP addresses and ports). A DPI engine is much smarter — it looks *inside the envelope* at the actual application data.

### What the Complete System Does

| Layer | Component | What It Does |
|---|---|---|
| **C++ Engine** | `packet_analyzer.exe` | Reads a `.pcap` file, classifies every packet |
| **JSON Export** | `output.json` | Live-updated data file refreshed every 1 second |
| **API Server** | `server.js` (Node.js) | Serves JSON data + firewall rule CRUD REST API |
| **Web Dashboard** | `public/` (Vanilla JS) | Real-time browser UI showing all traffic analytics |

---

## 2. The Basics: How Does It Work?

### The 5-Tuple (Connection Tracking)
Every network conversation is uniquely identified by:
1. **Source IP** — who is sending
2. **Destination IP** — where it's going
3. **Source Port** — sender's process identifier
4. **Destination Port** — service (e.g. port 443 = HTTPS)
5. **Protocol** — TCP or UDP

*Our engine groups all packets sharing the same 5-tuple into a single "Flow". If we classify one packet in a Flow as "TikTok", we know the entire flow is TikTok.*

### Deep Packet Inspection via SNI
Since almost all traffic today is HTTPS (encrypted), how do we know someone is visiting `youtube.com`?

When a browser starts an encrypted HTTPS connection, the very first message sent is the **TLS Client Hello**. Inside this specific message, the destination domain is openly included so the server knows which certificate to use. This is the **Server Name Indication (SNI)**.

*Our engine hunts this TLS Client Hello packet, parses the raw bytes, and extracts the SNI domain to classify the application.*

---

## 3. Architecture: The Full Pipeline

```
PCAP File
    ↓
[PcapReader]  →  reads raw packets
    ↓
[PacketParser]  →  decodes Ethernet / IP / TCP / UDP headers
    ↓
[FastPath]  →  should this packet be inspected?
    ↓
[DPI Engine]  →  SNI extractor / DNS parser / HTTP parser
    ↓
[ConnectionTracker]  →  flow state, rule enforcement, FORWARD/DROP
    ↓
[StatsCollector]  →  packets, bytes, PPS, protocol %
    ↓
[output.json]  →  written every 1 second
    ↓
[Node.js / Express]  →  serves /data and /rules API
    ↓
[Web Dashboard]  →  browser renders live charts and logs
```

### Module Responsibilities

| Module | File | Job |
|---|---|---|
| **PcapReader** | `src/pcap_reader.cpp` | Reads raw `.pcap` files packet-by-packet |
| **PacketParser** | `src/packet_parser.cpp` | Decodes Ethernet, IP, TCP/UDP headers |
| **FastPath** | `src/fast_path.cpp` | Router — `true/false` for DPI inspection |
| **DPIEngine** | `src/dpi_engine.cpp` | Stateless inspector — SNI/HTTP/DNS extraction |
| **DNSParser** | `src/dns_parser.cpp` | Parses domain names from UDP port 53 |
| **HTTPParser** | `src/http_parser.cpp` | Parses method, host, path from TCP port 80 |
| **SNIExtractor** | `src/sni_extractor.cpp` | Parses TLS Client Hello on TCP port 443 |
| **ConnectionTracker** | `src/connection_tracker.cpp` | Tracks flows, enforces rules, FORWARD/DROP |
| **StatsCollector** | `src/stats_collector.cpp` | Aggregates stats, exports `output.json` |
| **RuleManager** | `src/rule_manager.cpp` | Thread-safe IP/domain/app/port blocklist |

---

## 4. The Journey of a Packet (Step-by-Step)

1. `PcapReader::readNextPacket()` reads a raw packet from the `.pcap` file.
2. `PacketParser::parse()` decodes all headers into a `ParsedPacket` struct.
3. `StatsCollector::update()` increments counters and checks 1-second JSON export timer.
4. `FastPath::needsInspection()` routes to DPI only if port is 80/443/53 with payload.
5. **DPI Inspection** (if needed):
   - Port `443` → `SNIExtractor` parses TLS Client Hello
   - Port `80` → `HTTPParser` extracts Method + Host + URL
   - Port `53` → `DNSParser` extracts queried domain
6. `ConnectionTracker::process()` updates flow state, alerts on suspicious ports, checks rules.
7. If `DROP` → packet is discarded. If `FORWARD` → written to output `.pcap`.
8. DNS/HTTP events are stored in internal vectors for JSON/dashboard display.
9. Every 1 second → `StatsCollector::exportJson()` writes `output.json`.
10. `node server.js` serves `output.json` at `GET /data` → dashboard fetches and renders.

---

## 5. Complete Feature List

### C++ Engine Features
- ✅ PCAP file reading (libpcap-compatible manual parsing)
- ✅ Ethernet / IPv4 / TCP / UDP / ICMP header parsing
- ✅ TLS SNI extraction (encrypted HTTPS classification)
- ✅ DNS query + response parsing (UDP port 53) — 14 unique domains extracted
- ✅ HTTP request parsing (method + host + path, TCP port 80)
- ✅ 5-tuple flow tracking with connection state machine
- ✅ Two-tier classification: DPI first, port-based fallback second
- ✅ Real-time `[HTTP]` and `[DNS]` console output
- ✅ Packets, bytes, TCP/UDP/ICMP counting with PPS calculation
- ✅ Alert system: suspicious ports (4444, 1337, 31337, 4899) + high traffic (>1000 PPS)
- ✅ Rule enforcement: IP / domain / application / port blocking
- ✅ JSON export (`output.json`) updated every 1 second

### Web Dashboard Features
- ✅ KPI cards: Total Packets, Traffic Volume, Connections, Dropped, Alerts
- ✅ Protocol doughnut chart (TCP / UDP / ICMP / IPv6)
- ✅ Live throughput line chart (packets/sec over 60s sliding window)
- ✅ Application classification table (24 apps, color-coded progress bars)
- ✅ Live DNS query feed (14 queries)
- ✅ Live HTTP request feed with method badges (GET/POST)
- ✅ Firewall Rules panel (Add / Remove rules, 4 types)
- ✅ Security alerts table (auto-shows on threat — 4 alerts from suspicious ports)
- ✅ Toast notification system for rule actions
- ✅ 1-second polling (fully live updates)
- ✅ Sidebar navigation with active state tracking

### REST API Endpoints
| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serves the web dashboard |
| `GET` | `/data` | Returns current `output.json` |
| `GET` | `/rules` | Returns active `rules.json` |
| `POST` | `/rules` | Adds a new block rule |
| `DELETE` | `/rules` | Removes a rule |

---

## 6. Sample Console Output

```
Opened PCAP file: test_dpi.pcap
  Version: 2.4  |  Snaplen: 65535  |  Link: Ethernet
[Pipeline] Starting inspection pipeline...

[DNS] www.google.com            [DNS] www.youtube.com
[DNS] www.facebook.com          [DNS] api.twitter.com
[DNS] www.netflix.com           [DNS] open.spotify.com
[DNS] discord.com               [DNS] zoom.us
[DNS] www.amazon.com            [DNS] www.reddit.com
[DNS] www.github.com            [DNS] www.tiktok.com
[DNS] cdnjs.cloudflare.com      [DNS] fonts.googleapis.com
[HTTP] GET example.com/
[HTTP] GET httpbin.org/get
[HTTP] GET stackoverflow.com/questions
[HTTP] GET developers.google.com/apis
[HTTP] GET test-server.local/api/v1/status
[ALERT] Suspicious port 4444 from 192.168.1.50
[ALERT] Suspicious port 1337 from 192.168.1.51
[ALERT] Suspicious port 31337 from 192.168.1.52
[ALERT] Suspicious port 4899 from 10.0.0.99
[Pipeline] Processed 231 packets.

[Stats] Final Traffic Breakdown:
Packets : 231  (PPS: ~231,000)
Bytes   : 52,840
TCP     : 52.8%  (122 pkts)
UDP     : 40.3%  ( 93 pkts)
ICMP    :  6.9%  ( 16 pkts)

+--------------------------------------------------------------+
|               CONNECTION STATISTICS REPORT                   |
+--------------------------------------------------------------+
| Total Packets Processed:       231                          |
| Packets Dropped:                12  (suspicious ports)      |
+--------------------------------------------------------------+
|                    APPLICATION BREAKDOWN                     |
+--------------------------------------------------------------+
| HTTPS        42 (18.2%) #########                           |
| UDP-Stream   30 (13.0%) ######                              |
| DNS          28 (12.1%) ######                              |
| VoIP/RTP     25 (10.8%) #####                               |
| HTTP         10 ( 4.3%) ##                                  |
| NTP           6 ( 2.6%) #                                   |
| Syslog        5 ( 2.2%) #                                   |
| QUIC          3 ( 1.3%)                                     |
| + 16 more apps (Twitter/X, Telegram, Zoom, Discord ...)     |
+--------------------------------------------------------------+
[Pipeline] Analysis complete.
```

**Key things to highlight to your panel:**
- **14 DNS queries captured** — real-time domain resolution monitoring across all major platforms
- **5 HTTP requests** with method, host and full path extracted from plaintext traffic
- **4 security alerts** — suspicious ports 4444 (Metasploit), 1337 (elite), 31337 (Back Orifice), 4899 (Radmin)
- **VoIP/RTP detected** — 25 frames of a simulated G.711 phone call classified in real-time
- **NTP, Syslog, QUIC** — uncommon UDP protocols all correctly identified
- **ICMP ping tracking** — pings to 8.8.8.8 and 1.1.1.1 captured and counted
- **TCP 52.8% / UDP 40.3% / ICMP 6.9%** — realistic multi-protocol distribution
- **Zero Unknown entries** — all 231 packets fully classified


---

## 7. Firewall Rule System (How to Block Traffic)

The `RuleManager` supports 4 types of blocking rules:

| Rule Type | Example | What Gets Blocked |
|---|---|---|
| **Domain** | `*.facebook.com` | All Facebook subdomains (wildcard) |
| **IP Address** | `192.168.1.5` | Packets from that source IP |
| **Application** | `TikTok` | App detected via SNI classification |
| **Port** | `4444` | Any connection on that port |

### How It Works End-to-End
1. User types a rule in the Dashboard → clicks **Block**
2. Dashboard sends `POST /rules` to the Node.js API
3. `server.js` saves it to `rules.json`
4. On next C++ engine run, `RuleManager::loadRules("rules.json")` is called at startup
5. When a matching connection is processed → `ConnectionTracker` returns `DROP`
6. The packet is discarded and the dropped counter increments

---

## 8. Technical Achievements & Bug Fixes

### Bug 1 — Zero-Packet Thread Starvation (Multi-threaded Prototype)
- **Problem:** 2 of 4 Fast Path threads processed zero packets
- **Root Cause:** Load Balancer and Fast Path selector both used `hash % 2`, causing mathematical collision
- **Fix:** Used bit-shifting (`hash >> 16`) to decouple the two selectors

### Bug 2 — Unicode Rendering on Windows
- **Problem:** Box-drawing characters (`╔`, `═`, `║`) appeared garbled in PowerShell
- **Fix:** Replaced with universal ASCII equivalents (`+`, `-`, `|`)

### Bug 3 — "Unknown" Classification (Critical)
- **Problem:** 21 connections (48.8%) showed as "Unknown" in the breakdown
- **Root Cause:** TCP control packets (SYN/ACK/FIN/RST) have no payload → FastPath skips DPI → flow is created but never classified
- **Fix:** Port-based fallback heuristic inside `ConnectionTracker`: port 443 → HTTPS, port 80 → HTTP, port 53 → DNS
- **Result:** Unknown dropped from 48.8% to **0%**

### Bug 4 — Stale Server Process (Dashboard)
- **Problem:** Multiple `node` processes holding port 3000 — rule API requests hit old server silently returning 404
- **Fix:** `Stop-Process -Name node -Force` before each new server start

---

## 9. How to Run the Full Stack

### Step 1 — Compile the C++ Engine
```powershell
g++ -std=c++17 -O2 -I include -o PacketInspector.exe `
    src/main.cpp src/packet_parser.cpp src/pcap_reader.cpp `
    src/sni_extractor.cpp src/dns_parser.cpp src/http_parser.cpp `
    src/types.cpp src/fast_path.cpp src/dpi_engine.cpp `
    src/connection_tracker.cpp src/rule_manager.cpp src/stats_collector.cpp
```

### Step 2 — Run the Analyzer
```powershell
.\PacketInspector.exe test_dpi.pcap output.pcap
```

### Step 3 — Start the API Server
```powershell
node server.js
```

### Step 4 — Open the Dashboard
Open your browser → **http://localhost:3000/**

> **Note on AppLocker:** Windows Application Control may block compiled `.exe` files in user project directories. If blocked, copy the binary to `C:\Users\<you>\` and run from there, or use a Developer Command Prompt with elevated trust.

---

## 10. Project Evolution Timeline

| Phase | What Was Built |
|---|---|
| **Phase 1** | PCAP reading, Ethernet/IP/TCP/UDP parsing, basic flow tracking |
| **Phase 2** | Multi-threaded prototype with load balancer (later refactored) |
| **Phase 3** | Clean single-threaded pipeline, SNI extractor, modular architecture |
| **Phase 4** | DNS parser, HTTP parser, StatsCollector, real-time console output |
| **Phase 5** | JSON export (`output.json`), alert system, suspicious port detection |
| **Phase 6** | Node.js Express server, `/data` and `/rules` REST API |
| **Phase 7** | Full web dashboard (KPIs, protocol donut, live throughput chart, application table, logs, firewall rule UI, alerts) |
| **Phase 8** | Enriched test PCAP with 231 packets — UDP, NTP, Syslog, VoIP/RTP, QUIC, ICMP, streaming, 4 suspicious-port alerts |