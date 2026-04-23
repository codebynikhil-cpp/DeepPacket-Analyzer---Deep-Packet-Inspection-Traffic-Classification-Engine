# Deep Packet Inspection (DPI) Engine - Presentation Guide

This guide is designed to help you confidently present the DPI Engine project to your mentor, panel members, and reviewers. It breaks down the entire system from the absolute basics of networking to the internal architecture and codebase of the project, all in plain English.

---

## 1. Executive Summary: What is this project?

This project is a **Deep Packet Inspection (DPI) Engine** written in C++17.

Standard firewalls only look at the "envelopes" of internet traffic (IP addresses and ports). A DPI engine is much smarter — it looks *inside the envelope* at the actual application data.

**What Does it Do?**
- **Identifies Applications:** Tells you exactly if a connection is YouTube, Facebook, TikTok, Spotify, Zoom, etc.
- **Analyzes Encrypted Traffic:** Even though almost all web traffic today is encrypted (HTTPS), this engine extracts the Server Name Indication (SNI) from the TLS handshake to determine the destination.
- **Real-Time HTTP Inspection:** For unencrypted traffic (port 80), it extracts the HTTP Method, Host, and URL path in real-time (e.g., `[HTTP] GET example.com/`).
- **Real-Time DNS Monitoring:** It detects DNS queries on UDP port 53 and logs the queried domains live as they are seen (e.g., `[DNS] www.google.com`).
- **Traffic Statistics:** Tracks total packets, total bytes, and protocol distribution (TCP/UDP/ICMP) with packets-per-second calculation.
- **Rule-Based Blocking:** It can actively block traffic based on specific Apps, IP addresses, or domain names.

---

## 2. The Basics: How does it work?

### The 5-Tuple (Connection Tracking)
Every time a computer talks to another computer on the internet, that unique conversation is defined by a "5-tuple":
1. **Source IP** (Who is sending the data)
2. **Destination IP** (Where the data is going)
3. **Source Port** (The sender's process/app identifier)
4. **Destination Port** (The receiver's service, e.g., port 443 for HTTPS)
5. **Protocol** (TCP or UDP)

*Our engine groups all packets sharing the same 5-tuple into a single "Flow". If we identify one packet in a Flow as "TikTok", we know the entire Flow is TikTok.*

### Deep Packet Inspection via SNI
Since almost all traffic today is HTTPS (encrypted), how do we know someone is visiting `youtube.com`?

When a browser starts an encrypted connection, the very first message it sends is the **TLS Client Hello**. Inside this specific message, the target domain is openly included so the server knows which certificate to use. This is called the **Server Name Indication (SNI)**.

*Our engine hunts down this single TLS Client Hello packet, parses the raw bytes, and extracts the SNI domain to classify the application.*

---

## 3. Clean Pipeline Architecture (Current Design)

The project is now built around a single, clean, sequential pipeline with strictly separated responsibilities:

```
PCAP Reader → Packet Parser → Fast Path → DPI Engine → Connection Tracker → Output
```

Each module has **one and only one job**:

| Module | File | Responsibility |
|---|---|---|
| **PcapReader** | `src/pcap_reader.cpp` | Reads raw `.pcap` files packet by packet |
| **PacketParser** | `src/packet_parser.cpp` | Decodes Ethernet, IP, TCP/UDP headers |
| **FastPath** | `src/fast_path.cpp` | **Router only** — returns `true/false` for DPI inspection |
| **DPIEngine** | `src/dpi_engine.cpp` | **Stateless inspector** — extracts SNI/HTTP/DNS info from payload |
| **DNSParser** | `src/dns_parser.cpp` | Parses DNS queries from UDP port 53 |
| **HTTPParser** | `src/http_parser.cpp` | Parses HTTP method, host, and path from TCP port 80 |
| **ConnectionTracker** | `src/connection_tracker.cpp` | **The Brain** — tracks flows, decides FORWARD/DROP |
| **StatsCollector** | `src/stats_collector.cpp` | Counts packets/bytes, tracks TCP/UDP/ICMP distribution |

---

## 4. The Journey of a Packet (Step-by-Step Flow)

Here is the exact path every packet takes through the engine in `src/main.cpp`:

1. **Ingestion**: `PcapReader::readNextPacket()` reads a raw packet from the input `.pcap` file.
2. **Parsing**: `PacketParser::parse()` decodes all headers and creates a clean `ParsedPacket` struct with source/destination IPs, ports, protocol, and payload pointer.
3. **Fast Path Routing**: `FastPath::needsInspection()` checks if the packet is on port 80/443/53. If **no payload or no relevant port** → skip DPI. If **yes** → send to DPI Engine.
4. **DPI Inspection** (if routed):
   - Port **443**: `SNIExtractor` parses the TLS Client Hello to extract the target domain.
   - Port **80**: `HTTPParser` extracts the HTTP Method, Host header, and URL path.
   - Port **53**: `DNSParser` extracts the queried domain name.
5. **Connection Tracking**: `ConnectionTracker::process()` updates the flow entry, registers the classification, checks blocking rules, and returns `FORWARD` or `DROP`.
6. **Real-Time Output**: DNS and HTTP logs are printed immediately to the console as packets are processed.
7. **Action**: If `FORWARD`, the raw packet is written to the output `.pcap` file.
8. **Final Report**: `StatsCollector::printFinal()` and `ConnectionTracker::generateReport()` print the complete traffic breakdown.

---

## 5. Sample Output

When you run `.\packet_analyzer.exe test_dpi.pcap output.pcap`, the engine produces:

```
[Pipeline] Starting inspection pipeline...
[HTTP] GET example.com/
[HTTP] GET httpbin.org/
[DNS] www.google.com
[DNS] www.youtube.com
[DNS] www.facebook.com
[DNS] api.twitter.com
[Pipeline] Processed 77 packets.

[Stats] Final Traffic Breakdown:
Packets: 77 (PPS: 25666.7)
Bytes: 5738
TCP: 94.8%
UDP: 5.2%
ICMP: 0.0%

+--------------------------------------------------------------+
|               CONNECTION STATISTICS REPORT                   |
+--------------------------------------------------------------+
| APPLICATION BREAKDOWN                                        |
| HTTPS       23 (53.5%) ##########                           |
| DNS          4 ( 9.3%) #                                    |
| Twitter/X    3 ( 7.0%) #                                    |
| YouTube      1 ( 2.3%)    ... and 12 more apps              |
+--------------------------------------------------------------+
```

**Key things to highlight to your panel:**
- **Real-time `[HTTP]` and `[DNS]` logs** — the engine reveals live user activity as it processes.
- **Protocol percentages** — shows the makeup of the traffic numerically.
- **Application breakdown** — every connection is classified, zero "Unknown" entries.
- **Two-tier classification** — deep payload inspection first, port-based heuristic as fallback (same approach used in commercial DPI systems).

---

## 6. Evolution & What Improved (Technical Achievements)

### Phase 1 → Phase 2: Architecture Refactor

The project was first built as an experimental multi-threaded system with scattered files. It was then cleanly refactored into the current pipeline:

| Feature | Before | Now |
|---|---|---|
| **Architecture** | 5 messy `main_*.cpp` files + `dpi_mt.cpp` | 1 clean `main.cpp` orchestrator |
| **HTTP Parsing** | ❌ None | ✅ Method + Host + URL path |
| **DNS Parsing** | ❌ None | ✅ Real-time domain logging |
| **Traffic Stats** | ❌ None | ✅ Packets, Bytes, TCP/UDP/ICMP % + PPS |
| **Class Design** | Mixed, tangled responsibilities | Strictly separated (FastPath = router, DPIEngine = stateless, ConnectionTracker = brain) |
| **Real-Time Output** | ❌ None | ✅ `[HTTP]` and `[DNS]` live logs |
| **Unknown Connections** | 21 entries (48.8%) unclassified | ✅ Zero — port-based fallback heuristic |

### Bug Fixes that Demonstrate Deep Technical Understanding

1. **The 'Zero-Packet' Thread Starvation Fix**
   - **Problem:** In the multi-threaded prototype, 2 of 4 Fast Path threads were consistently processing zero packets.
   - **Root Cause:** The Load Balancer and the Fast Path selector both used `hash % 2` on the same 5-tuple hash, causing a mathematical collision that starved half the threads.
   - **Fix:** Implemented bit-shifting (`hash >> 16`) to decouple the two selection algorithms, restoring even load distribution across all threads.

2. **Cross-Platform Terminal Rendering Fix**
   - **Problem:** Unicode box-drawing characters (`╔`, `═`, `║`) caused garbled output in Windows PowerShell/CMD due to encoding issues.
   - **Fix:** Replaced all Unicode table characters with universal ASCII equivalents (`+`, `-`, `|`), ensuring the dashboard renders correctly on all platforms.

3. **The 'Unknown' Classification Fix (Port-Based Fallback Heuristic)**
   - **Problem:** The Application Breakdown showed `Unknown 21 (48.8%)` — nearly half of all tracked connections were unclassified.
   - **Root Cause:** Every TCP connection generates several payload-less control packets (`SYN`, `ACK`, `FIN`, `RST`). `FastPath` correctly skips these since there is no payload to inspect, so `ConnectionTracker` created flow entries that were never classified by DPI.
   - **Fix:** Added a port-based fallback inside `ConnectionTracker`. When deep inspection yields no result, the engine infers the protocol from the port: `443` → `HTTPS`, `80` → `HTTP`, `53` → `DNS`. This is the same two-tier strategy used in commercial DPI systems.
   - **Result:** `Unknown` dropped from 21 entries (48.8%) to **zero**. `HTTPS` correctly rose to 23 entries (53.5%).

---

## 7. How to Run & Demo

```powershell
# Compile
g++ -std=c++17 -O2 -I include -o packet_analyzer.exe `
    src/main.cpp src/packet_parser.cpp src/pcap_reader.cpp `
    src/sni_extractor.cpp src/dns_parser.cpp src/http_parser.cpp `
    src/types.cpp src/fast_path.cpp src/dpi_engine.cpp `
    src/connection_tracker.cpp src/rule_manager.cpp src/stats_collector.cpp

# Run
.\packet_analyzer.exe test_dpi.pcap output.pcap
```

> **Note:** Use `packet_analyzer.exe` — Windows Application Control policy may flag `dpi_engine.exe` due to the filename matching network security tool signatures.