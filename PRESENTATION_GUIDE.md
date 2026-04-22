# Deep Packet Inspection (DPI) Engine - Presentation Guide

This guide is designed to help you confidently present the DPI Engine project to your mentor. It breaks down the entire system from the absolute basics of networking to the internal architecture and codebase of the project, all in plain English.

---

## 1. Executive Summary: What is this project?
This project is a **Deep Packet Inspection (DPI) Engine**. 
Standard firewalls only look at the "envelopes" of internet traffic (IP addresses and ports). A DPI engine is much smarter; it looks *inside the envelope* at the actual application data.

**What Does it Do?**
*   **Identifies Applications:** Tells you exactly if a connection is YouTube, Facebook, TikTok, Spotify, etc.
*   **Analyzes Encrypted Traffic:** Even though almost all web traffic today is encrypted (HTTPS), this engine outsmarts that by intercepting the very first "handshake" packet and extracting the Server Name Indication (SNI) to figure out where the user is going.
*   **Rule-Based Blocking:** It can actively block traffic based on specific Apps, IP addresses, or domain names.
*   **Highly Performant:** The project includes both an easy-to-understand simple version (`dpi_simple.exe`) and an advanced multi-threaded version (`dpi_engine.exe`) that uses load balancers and fast-path processing threads.

---

## 2. The Basics: How does it work?

To understand the project, one must understand how modern web traffic works.

### The 5-Tuple (Connection Tracking)
Every time a computer talks to another computer on the internet, that unique conversation is defined by a "5-tuple":
1.  **Source IP** (Who is sending the data)
2.  **Destination IP** (Where the data is going)
3.  **Source Port** (The sender's process/app identifier)
4.  **Destination Port** (The receiver's service, e.g., port 443 for HTTPS)
5.  **Protocol** (TCP or UDP)

*Our engine groups all packets that share the identical 5-tuple into a single "Flow". If we identify one packet in a Flow as "TikTok", we know the entire Flow is TikTok. If we block it, we drop every packet in that Flow.*

### Deep Packet Inspection via SNI
Since almost all traffic today is HTTPS (meaning the data is securely encrypted), how do we know someone is visiting `youtube.com`?

When a browser starts an encrypted connection to a server, the very first networking message it sends is called the **TLS Client Hello**. Inside this specific message, the unencrypted target domain is openly sent so the server knows which security certificate it needs to provide. This open text is called the **Server Name Indication (SNI)**.

*Our engine specifically hunts down this single TLS Client Hello packet, parses the raw hexadecimal bytes, and extracts the SNI domain to classify the application so we can make routing or blocking decisions.*

---

## 3. What is in the Codebase?

The project is structured elegantly using C++17, cleanly separating the system into specific modules:

*   **`src/pcap_reader.cpp`**: The data ingester. It reads the raw network capture files (`.pcap`) packet by packet.
*   **`src/packet_parser.cpp`**: The decoder. It strips away the complex Ethernet, IP, and TCP headers to find the core payload inside the packet.
*   **`src/sni_extractor.cpp` / `types.cpp`**: The brain of the inspection. It takes the payload, validates if it's a TLS or HTTP connection, and extracts the raw domain string name.
*   **`src/main_working.cpp`**: The simple, single-threaded orchestrator. It glues everything together, applying our custom blocking rules, and prints the final status to the console.
*   **`src/dpi_mt.cpp` / `dpi_engine.cpp`**: The advanced, multi-threaded version. This utilizes Load Balancers and Fast Path processing threads connected via thread-safe queues to handle massive amounts of network traffic in parallel.

---

## 4. The Journey of a Packet (Step-by-Step Flow)

If your mentor asks how the code runs, here is the exact chronological path a packet takes through the `main_working.cpp` engine:

1.  **Ingestion**: `PcapReader` reads a raw byte from the `.pcap` input file.
2.  **Parsing**: `PacketParser` decodes the Ethernet headers, IPv4 headers, and TCP/UDP headers to create our clean `ParsedPacket` structure.
3.  **Flow Tracking**: The system creates a 5-tuple hash and assigns the packet to a specific connection `Flow`.
4.  **Extraction**: 
    *   If the packet is on port 443 (HTTPS), `SNIExtractor` parses the TLS headers to find the SNI domain (e.g., `www.tiktok.com`).
    *   The domain string is then mapped to our internal application ID (e.g., `AppType::TIKTOK`).
5.  **Rule Enforcement**: The engine checks the `BlockingRules` class. If the App, IP, or Domain is currently on our blacklist, the flow is marked as `blocked = true`.
6.  **Action**: 
    *   If blocked, the packet is `Dropped` and completely ignored.
    *   If allowed, the packet is `Forwarded` and permanently written to the output `.pcap` file.
7.  **Reporting**: A clean, universally compatible ASCII report is generated showing total packets, active flows, and a histogram breakdown of the network traffic.

---

## 5. Demonstrating the Output Effectively

When you run `.\dpi_simple.exe test_dpi.pcap output.pcap` in front of your mentor, the engine will proudly output a beautifully formatted report. Point out the following details:

*   **Total Packets vs Forwarded**: Shows exactly how many packets were processed and allowed through compared to how many were dropped.
*   **Active Flows**: Shows how many distinct computer-to-computer connections were tracked simultaneously by the engine.
*   **Application Breakdown**: A visual histogram representation of the network footprint (e.g., 50% HTTPS, 5% DNS, 1.3% TikTok).
*   **Detected Domains**: A direct mapping showing precisely which website URLs the previously mysterious `.pcap` file was communicating with.

*(**Pro Tip for your Presentation:** You can use the `--block-app YouTube` flag in your demonstration command to show packets actively being dropped and excluded from the output file!)*

---

## 6. Recent Architecture & Stability Bug Fixes (To impress the Panel)

If panel members or reviewers ask about the technical challenges you conquered or specific deep architectural fixes you handled, highlight these recent engineering feats:

1. **The 'Zero-Packet' Hashing Collision Fix (Multi-threading)**
    *   **The Problem:** During testing of the new multi-threaded architecture (`dpi_mt.cpp`), we noticed 2 of our Fast Path (FP) threads were processing exactly zero packets while the others were overworked.
    *   **The Cause:** Both the Load Balancer (LB) and the internal Fast Path selector were using the exact same modulo logic (`hash % 2`) on the connection's 5-tuple. This created a severe mathematical collision where all traffic mapped identically, completely starving half of our processing threads.
    *   **The Fix:** We updated the internal load balancing engine to utilize bit-shifting during FP selection (specifically `(hash_val >> 16) % num_fps_`). By leveraging the upper bits of the hash, we completely decoupled the mapping logic, restoring perfect load distribution across all parallel processing threads and maximizing CPU utilization.

2. **Cross-Platform Terminal Dashboard Rendering**
    *   **The Problem:** The reporting module originally utilized hardcoded UTF-8/Unicode box drawing characters (`╔`, `═`, etc.). When running the executable natively via standard Windows PowerShell or CMD, these 3-byte unicode characters caused massive encoding errors, artificial wrapping, overlapping rows, and visually garbled text.
    *   **The Fix:** We proactively refactored all live dashboard string formatting layers across `dpi_mt.cpp` and `connection_tracker.cpp` to use robust, universally-compatible ASCII table components (`+`, `-`, `|`). The DPI engine dashboard is now guaranteed to render perfectly on strict Windows configurations, Linux, and macOS without sacrificing the dynamic visualization.
