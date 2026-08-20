#include "packet_source.h"
#include "pcap_file_source.h"
#include "live_capture_source.h"
#include "packet_queue.h"
#include "packet_parser.h"
#include "fast_path.h"
#include "dpi_engine.h"
#include "connection_tracker.h"
#include "stats_collector.h"
#include "wfp_enforcement.h"

#include <iostream>
#include <fstream>
#include <cstring>
#include <memory>
#include <thread>
#include <csignal>
#include <atomic>

using namespace DPI;
using namespace PacketAnalyzer;

// Global shutdown flag for SIGINT/SIGTERM handling
static std::atomic<bool> g_running{true};
static PacketQueue* g_active_queue = nullptr;
static LiveCaptureSource* g_live_source = nullptr;

void signalHandler(int signum) {
    std::cout << "\n[System] Signal (" << signum << ") received. Shutting down cleanly..." << std::endl;
    g_running = false;
    if (g_active_queue) {
        g_active_queue->stop();
    }
    if (g_live_source) {
        g_live_source->stopCapture();
    }
}

class OutputWriter {
public:
    OutputWriter(const std::string& filename) {
        if (!filename.empty()) {
            outFile.open(filename, std::ios::binary);
            PcapGlobalHeader hdr;
            outFile.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
        }
    }
    void writePacket(const RawPacket& raw) {
        if (!outFile.is_open()) return;
        outFile.write(reinterpret_cast<const char*>(&raw.header), sizeof(raw.header));
        outFile.write(reinterpret_cast<const char*>(raw.data.data()), raw.data.size());
    }
    void close() {
        if (outFile.is_open()) outFile.close();
    }
private:
    std::ofstream outFile;
};

void printUsage(const char* progName) {
    std::cout << "\n=== DeepPacket Analyzer & DPI Engine ===" << std::endl;
    std::cout << "Usage Modes:" << std::endl;
    std::cout << "  1. List Interfaces:   " << progName << " --list-interfaces" << std::endl;
    std::cout << "  2. Live Capture:      " << progName << " --interface <eth0|wlan0|1> [--protect]" << std::endl;
    std::cout << "  3. Offline PCAP:      " << progName << " --pcap <input.pcap> [output.pcap]" << std::endl;
    std::cout << "  4. Legacy Positional: " << progName << " <input.pcap> [output.pcap]\n" << std::endl;
}

int main(int argc, char* argv[]) {
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);

    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    std::string mode = "";
    std::string input_arg = "";
    std::string output_arg = "";
    bool enable_wfp = false;

    // Argument parsing
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--list-interfaces" || arg == "-l") {
            auto ifaces = PacketSource::listInterfaces();
            std::cout << "\n=== Available Network Interfaces ===" << std::endl;
            if (ifaces.empty()) {
                std::cout << "No interfaces found or Npcap/libpcap unavailable." << std::endl;
            } else {
                for (const auto& iface : ifaces) {
                    std::cout << "  [" << iface.index << "] " << iface.name << std::endl;
                    std::cout << "      " << iface.description << std::endl;
                }
            }
            std::cout << std::endl;
            return 0;
        } else if (arg == "--pcap" || arg == "-p") {
            mode = "pcap";
            if (i + 1 < argc) input_arg = argv[++i];
        } else if (arg == "--interface" || arg == "-i") {
            mode = "interface";
            if (i + 1 < argc) input_arg = argv[++i];
        } else if (arg == "--protect") {
            enable_wfp = true;
        } else if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            return 0;
        } else if (input_arg.empty()) {
            input_arg = arg;
        } else if (output_arg.empty()) {
            output_arg = arg;
        }
    }

    if (mode.empty()) {
        if (!input_arg.empty()) {
            mode = "pcap";
        } else {
            printUsage(argv[0]);
            return 1;
        }
    }

    std::unique_ptr<PacketSource> source;
    if (mode == "interface") {
        auto live_src = std::make_unique<LiveCaptureSource>(input_arg);
        g_live_source = live_src.get();
        source = std::move(live_src);
    } else {
        source = std::make_unique<PcapFileSource>(input_arg);
    }

    if (!source->open()) {
        std::cerr << "[Error] Failed to open packet source: " << input_arg << std::endl;
        return 1;
    }

    OutputWriter output(output_arg);
    FastPath fast_path;
    DPIEngine dpi_engine;
    ConnectionTracker connection_tracker;

    // Initialize WFP enforcement ONLY if --protect was explicitly requested
    WfpEnforcement wfp;
    if (enable_wfp) {
        if (wfp.initialize()) {
            connection_tracker.setEnforcement(&wfp);
        }
    }

    connection_tracker.getRuleManager().loadRules("rules.json");
    if (wfp.isActive()) {
        connection_tracker.reinstallWfpRules();
    }

    StatsCollector stats;
    stats.setMode(source->getMode(), source->getSourceName());
    stats.setWfpEnforcement(&wfp);
    stats.setProtectionRequested(enable_wfp);


    std::cout << "[Pipeline] Starting DPI inspection pipeline (" 
              << source->getMode() << " mode: " << source->getSourceName() << ")..." << std::endl;

    // Background thread for hot-reloading rules when rules_reload.flag exists
    std::thread rulesReloadThread([&]() {
        while (g_running) {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            std::ifstream flagFile("rules_reload.flag");
            if (flagFile.is_open()) {
                flagFile.close();
                std::remove("rules_reload.flag");
                std::cout << "[RuleManager] Hot-reloading rules from rules.json...\n";
                connection_tracker.getRuleManager().clearAll();
                connection_tracker.getRuleManager().loadRules("rules.json");
                if (wfp.isActive()) {
                    connection_tracker.reinstallWfpRules();
                }
            }
        }
    });

    if (source->isLive()) {
        // --- LIVE CAPTURE PRODUCER-CONSUMER MULTITHREADED PIPELINE ---
        PacketQueue queue(10000);
        g_active_queue = &queue;
        stats.setPacketQueue(&queue);


        // Producer Thread: Captures raw packets & pushes to queue
        std::thread producerThread([&]() {
            while (g_running) {
                RawPacket pkt;
                if (!source->getNextPacket(pkt)) {
                    if (!g_running) break;
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    continue;
                }
                // Push non-empty packets into queue
                if (pkt.header.incl_len > 0) {
                    queue.push(std::move(pkt));
                }
            }
            queue.stop();
        });

        // Consumer Thread: Pops packets & runs DPI analysis
        std::thread consumerThread([&]() {
            while (g_running || queue.size() > 0) {
                RawPacket raw_pkt;
                if (!queue.pop(raw_pkt, std::chrono::milliseconds(100))) {
                    if (!g_running && queue.size() == 0) break;
                    continue;
                }

                ParsedPacket parsed_pkt;
                if (!PacketParser::parse(raw_pkt, parsed_pkt)) continue;

                stats.update(raw_pkt, parsed_pkt);

                std::optional<AppClassification> classification = std::nullopt;
                if (fast_path.needsInspection(parsed_pkt)) {
                    classification = dpi_engine.inspect(parsed_pkt);
                }

                PacketAction action = connection_tracker.process(parsed_pkt, classification);
                if (action == PacketAction::FORWARD && !output_arg.empty()) {
                    output.writePacket(raw_pkt);
                }
            }
        });

        // Telemetry Exporter Thread: Periodically writes telemetry to output.json every 500ms
        std::thread telemetryThread([&]() {
            while (g_running) {
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
                stats.checkAndPrint(connection_tracker.getDnsQueries(),
                                    connection_tracker.getHttpRequests(),
                                    connection_tracker.getAlerts(),
                                    connection_tracker.getApplicationStats(),
                                    connection_tracker.getDomainStats(),
                                    connection_tracker.getRecentFlows(),
                                    connection_tracker.getConnectionsCount(),
                                    connection_tracker.getDroppedCount(),
                                    source->getCaptureDrops(),
                                    queue.getProcessingDrops(),
                                    500);
            }
        });

        if (producerThread.joinable()) producerThread.join();
        if (consumerThread.joinable()) consumerThread.join();
        if (telemetryThread.joinable()) telemetryThread.join();


        stats.printFinal(connection_tracker.getDnsQueries(),
                         connection_tracker.getHttpRequests(),
                         connection_tracker.getAlerts(),
                         connection_tracker.getApplicationStats(),
                         connection_tracker.getDomainStats(),
                         connection_tracker.getRecentFlows(),
                         connection_tracker.getConnectionsCount(),
                         connection_tracker.getDroppedCount(),
                         source->getCaptureDrops(),
                         queue.getProcessingDrops());

    } else {
        // --- OFFLINE PCAP SEQUENTIAL PIPELINE ---
        size_t packet_count = 0;
        RawPacket raw_pkt;

        while (g_running && source->getNextPacket(raw_pkt)) {
            packet_count++;

            ParsedPacket parsed_pkt;
            if (!PacketParser::parse(raw_pkt, parsed_pkt)) continue;

            stats.update(raw_pkt, parsed_pkt);

            std::optional<AppClassification> classification = std::nullopt;
            if (fast_path.needsInspection(parsed_pkt)) {
                classification = dpi_engine.inspect(parsed_pkt);
            }

            PacketAction action = connection_tracker.process(parsed_pkt, classification);
            if (action == PacketAction::FORWARD && !output_arg.empty()) {
                output.writePacket(raw_pkt);
            }

            stats.checkAndPrint(connection_tracker.getDnsQueries(),
                                connection_tracker.getHttpRequests(),
                                connection_tracker.getAlerts(),
                                connection_tracker.getApplicationStats(),
                                connection_tracker.getDomainStats(),
                                connection_tracker.getRecentFlows(),
                                connection_tracker.getConnectionsCount(),
                                connection_tracker.getDroppedCount());
        }

        stats.printFinal(connection_tracker.getDnsQueries(),
                         connection_tracker.getHttpRequests(),
                         connection_tracker.getAlerts(),
                         connection_tracker.getApplicationStats(),
                         connection_tracker.getDomainStats(),
                         connection_tracker.getRecentFlows(),
                         connection_tracker.getConnectionsCount(),
                         connection_tracker.getDroppedCount());
    }

    g_running = false; // ensure hot-reload thread wakes and exits cleanly
    if (rulesReloadThread.joinable()) rulesReloadThread.join();


    source->close();
    output.close();
    connection_tracker.generateReport();
    wfp.shutdown();

    std::cout << "[Pipeline] Analysis complete. Clean shutdown successful." << std::endl;
    return 0;
}

