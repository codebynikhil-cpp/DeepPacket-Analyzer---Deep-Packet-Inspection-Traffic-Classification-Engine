#include "pcap_reader.h"
#include "packet_parser.h"
#include "fast_path.h"
#include "dpi_engine.h"
#include "connection_tracker.h"
#include "stats_collector.h"
#include <iostream>
#include <fstream>
#include <cstring>

using namespace DPI;
using namespace PacketAnalyzer;

// Simple custom output writer to replicate OutputWriter inside main for clean loop
class OutputWriter {
public:
    OutputWriter(const std::string& filename) {
        outFile.open(filename, std::ios::binary);
        // Write PCAP Header
        PcapGlobalHeader hdr;
        outFile.write(reinterpret_cast<const char*>(&hdr), sizeof(hdr));
    }
    void writePacket(const RawPacket& raw) {
        if (!outFile.is_open()) return;
        outFile.write(reinterpret_cast<const char*>(&raw.header), sizeof(raw.header));
        outFile.write(reinterpret_cast<const char*>(raw.data.data()), raw.data.size());
    }
    void close() { outFile.close(); }
private:
    std::ofstream outFile;
};

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: " << argv[0] << " <input.pcap> <output.pcap>\n";
        return 1;
    }

    PcapReader reader;
    if (!reader.open(argv[1])) {
        std::cerr << "Failed to open input PCAP.\n";
        return 1;
    }
    
    OutputWriter output(argv[2]);
    
    FastPath fast_path;
    DPIEngine dpi_engine;
    ConnectionTracker connection_tracker;
    StatsCollector stats;

    // Optional: add some blocks to verify RuleManager logic
    // connection_tracker.getRuleManager().blockApp(AppType::YOUTUBE);

    std::cout << "[Pipeline] Starting inspection pipeline...\n";

    // --- PIPELINE LOOP ---
    size_t packet_count = 0;
    RawPacket raw_pkt;
    while (reader.readNextPacket(raw_pkt)) {
        packet_count++;
        
        // 1. Packet Parser
        ParsedPacket parsed_pkt;
        if (!PacketParser::parse(raw_pkt, parsed_pkt)) continue; 
        
        // Update stats
        stats.update(raw_pkt, parsed_pkt);
        stats.checkAndPrint(connection_tracker.getDnsQueries(), connection_tracker.getHttpRequests(), connection_tracker.getAlerts(), connection_tracker.getApplicationStats());
        
        // 2. Fast Path Routing & DPI Inspection
        std::optional<AppClassification> classification = std::nullopt;
        if (fast_path.needsInspection(parsed_pkt)) {
            classification = dpi_engine.inspect(parsed_pkt);
        }

        // 3. Connection Tracker (The Brain)
        PacketAction action = connection_tracker.process(parsed_pkt, classification);

        // 4. Output
        if (action == PacketAction::FORWARD) {
            output.writePacket(raw_pkt);
        }
    }

    // Cleanup & Reporting
    reader.close();
    output.close();
    
    std::cout << "[Pipeline] Processed " << packet_count << " packets.\n";
    stats.printFinal(connection_tracker.getDnsQueries(), connection_tracker.getHttpRequests(), connection_tracker.getAlerts(), connection_tracker.getApplicationStats());
    connection_tracker.generateReport();
    std::cout << "[Pipeline] Analysis complete.\n";

    return 0;
}
