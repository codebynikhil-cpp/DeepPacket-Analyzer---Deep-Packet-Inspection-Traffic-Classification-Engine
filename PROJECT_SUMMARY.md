# DeepPacket Analyzer — Project Summary

> A high-performance real-time network traffic analysis and Deep Packet Inspection (DPI) engine built with modern C++17, libpcap/Npcap, Node.js REST API, and a vanilla JavaScript interactive web dashboard.

---

## 📌 System Architecture

```text
PCAP FILE ────────┐
                  │
                  ▼
             Packet Source (PcapFileSource / LiveCaptureSource)
                  │
LIVE INTERFACE ───┘
                  │
                  ▼
             Packet Parser (Ethernet / IPv4 / IPv6 / TCP / UDP / ICMP)
                  │
                  ▼
          Connection Tracker (5-Tuple Flow Management & State Tracking)
                  │
                  ▼
             Fast Path (Heuristic & Cached Decision Acceleration)
                  │
                  ▼
              DPI Engine
                  │
          ┌───────┼────────┐
          ▼       ▼        ▼
         DNS     HTTP    TLS/SNI
          └───────┼────────┘
                  ▼
          Rule / Firewall (IP, Domain, Application, Port Rules)
                  │
                  ▼
          Statistics Engine (In-Memory Metrics & Periodic JSON Snapshots)
                  │
                  ▼
             Node.js API (REST Endpoints & Rule Management)
                  │
                  ▼
          Web Dashboard (Live Throughput, Top Apps, Protocols, Security Alerts)
```

---

## 🔬 Evolution & Core Phases

### Phase 1 — Low-Level Protocol Parsing & Flow Tracking
- Custom zero-dependency PCAP reader for binary packet decoding.
- Bitwise header parsers for Ethernet, IPv4, IPv6, TCP, UDP, and ICMP.
- 5-tuple flow identification (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`).

### Phase 2 — Deep Packet Inspection (DPI)
- **TLS Client Hello & SNI Extraction**: Parses raw TLS records and handshake extensions to extract plaintext domain names from HTTPS traffic before session encryption.
- **Application Classification**: Categorizes traffic into 16+ services (YouTube, Netflix, TikTok, Discord, Zoom, Twitter/X, Spotify, Telegram, GitHub, Google, Amazon, Facebook, etc.).
- **DNS Parser** (`include/dns_parser.h`): Parses UDP port 53 DNS queries using RFC 1035 label decompression.
- **HTTP Parser** (`include/http_parser.h`): Extracts request methods (GET, POST), Host headers, and URL paths.
- **Fast-Path Engine**: Caches classification decisions by 5-tuple to eliminate redundant payload parsing on established flows.

### Phase 3 — Stateful Firewall & Rule Engine
- **RuleManager** (`include/rule_manager.h`): Real-time blocking engine matching on 4 criteria:
  1. Source IP addresses
  2. Wildcard domain names (e.g., `*.facebook.com`)
  3. Identified applications (e.g., `TikTok`)
  4. Suspicious destination ports (e.g., `4444`, `1337`)
- Thread-safe rule management with persistent `rules.json` synchronization.

### Phase 4 — Real-Time Live Capture & Multi-Threading
- **Polymorphic Packet Source**: Unified `PacketSource` abstraction supporting both `PcapFileSource` and `LiveCaptureSource`.
- **Dynamic libpcap / Npcap Loader**: `pcap_wrapper.h` dynamically binds to `wpcap.dll` on Windows or `libpcap.so` on Linux at runtime, providing native fallback.
- **Producer-Consumer Architecture**:
  - Dedicated **Capture Thread** pulls packets from interface without dropping.
  - Thread-safe bounded **PacketQueue** (10,000 capacity) prevents memory exhaustion.
  - Dedicated **Worker Thread** processes packets through the DPI and connection tracking pipeline.
  - Tracks `capture_drops` (kernel/driver level) and `processing_drops` (queue full).
- **Graceful Shutdown**: Intercepts `SIGINT` (Ctrl+C) / `SIGTERM`, breaks capture loops, drains queues, prints final statistics, and exits cleanly.

### Phase 5 — Real-Time Statistics & REST Backend
- **In-Memory StatsCollector**: High-performance metric tracking with periodic snapshotting (every 500ms) to `output.json` without per-packet disk I/O overhead.
- **Node.js Express Server** (`server.js`):
  - `GET /data`: Serves real-time traffic statistics.
  - `GET /mode`: Returns current execution mode (`live` vs `offline`), active device, and drop counters.
  - `GET /rules`, `POST /rules`, `DELETE /rules`: Dynamic CRUD API for firewall filtering.

### Phase 6 — Interactive Web Dashboard
- Vanilla HTML5 / CSS3 / JavaScript frontend located in `public/` (zero build step required):
  - **Live Mode Badge**: Distinct `LIVE ●` vs `OFFLINE 📄` indicator.
  - **Throughput History Chart**: Real-time packets/sec (PPS) timeline using Chart.js.
  - **Protocol Distribution**: Donut chart with TCP, UDP, ICMP, and IPv6 breakdowns.
  - **Application Breakdown**: Ranked distribution bar charts for classified traffic.
  - **Live Feeds**: Real-time streams of captured DNS queries and HTTP URLs.
  - **Security Alerts**: Immediate visual alerts for high traffic anomalies and suspicious port activities.
  - **Interactive Firewall Rules Manager**: Add and remove blocking rules on the fly.

---

## 📁 Repository Structure

```
DeepPacket-Analyzer/
│
├── include/                    # C++ Header Files
│   ├── connection_tracker.h    # 5-tuple flow management & state
│   ├── dns_parser.h            # RFC 1035 DNS query extractor
│   ├── dpi_engine.h            # L7 protocol inspector
│   ├── fast_path.h             # Inspection router & flow caching
│   ├── http_parser.h           # HTTP method & host extractor
│   ├── live_capture_source.h   # Live interface capture engine
│   ├── packet_parser.h         # L2-L4 header decoding
│   ├── packet_queue.h          # Thread-safe bounded packet queue
│   ├── packet_source.h         # Base abstraction & interface enumeration
│   ├── pcap_file_source.h      # Offline PCAP source wrapper
│   ├── pcap_reader.h           # Low-level binary PCAP parser
│   ├── pcap_wrapper.h          # Dynamic runtime loader for libpcap/Npcap
│   ├── platform.h              # Cross-platform socket definitions
│   ├── rule_manager.h          # Multi-criteria firewall rule engine
│   ├── sni_extractor.h         # TLS Client Hello & SNI extractor
│   ├── stats_collector.h       # In-memory metrics & periodic exporter
│   └── types.h                 # Protocol & packet data structures
│
├── src/                        # C++ Implementation Files
│   ├── connection_tracker.cpp
│   ├── dns_parser.cpp
│   ├── dpi_engine.cpp
│   ├── fast_path.cpp
│   ├── http_parser.cpp
│   ├── live_capture_source.cpp
│   ├── main.cpp                # CLI orchestrator & multi-threaded runner
│   ├── packet_parser.cpp
│   ├── packet_source.cpp
│   ├── pcap_reader.cpp
│   ├── rule_manager.cpp
│   ├── sni_extractor.cpp
│   ├── stats_collector.cpp
│   └── types.cpp
│
├── public/                     # Frontend Web Dashboard
│   ├── index.html              # Modern glassmorphism UI layout
│   ├── style.css               # Clean dark-mode inspired styling
│   └── app.js                  # Chart.js integration & live polling
│
├── server.js                   # Node.js REST API & static file server
├── rules.json                  # Persistent firewall rules storage
├── output.json                 # Real-time traffic snapshot file
├── CMakeLists.txt              # Cross-platform CMake build configuration
├── package.json                # Node.js project manifest
├── test_dpi.pcap               # Sample test packet capture
├── README.md                   # Comprehensive user & developer guide
└── PROJECT_SUMMARY.md          # High-level architecture summary
```

---

## ⚡ Execution Modes & CLI Reference

### 1. List Available Network Interfaces
```bash
./PacketInspector --list-interfaces
```

### 2. Live Capture Mode
```bash
# By interface index:
./PacketInspector --interface 1

# By interface name (Linux/macOS):
sudo ./PacketInspector --interface eth0
```

### 3. Offline PCAP Mode
```bash
./PacketInspector --pcap test_dpi.pcap filtered_output.pcap
```

### 4. Web Dashboard
```bash
npm install
npm start
# Visit http://localhost:3000
```

---

## 🛡️ Rule Management Capabilities

| Rule Type | Scope | Example Syntax |
|---|---|---|
| **IP Address** | Source IP blocking | `192.168.1.100` |
| **Domain** | Wildcard domain blocking | `*.facebook.com`, `ads.*` |
| **Application** | L7 protocol/service blocking | `TikTok`, `BitTorrent`, `YouTube` |
| **Port** | Transport port blocking | `4444`, `1337`, `8080` |

---

## 🚀 Performance Benchmarks

- **PCAP Processing Speed**: >50,000 packets/second.
- **Memory Footprint**: <25 MB typical runtime memory.
- **Queue Buffering**: Bounded at 10,000 packets with zero-allocation drops under extreme burst loads.
- **Export Latency**: Non-blocking in-memory counter aggregation with configurable 500ms snapshots.
