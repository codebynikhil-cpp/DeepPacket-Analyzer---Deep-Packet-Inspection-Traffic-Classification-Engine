#ifndef STATS_COLLECTOR_H
#define STATS_COLLECTOR_H

#include "pcap_reader.h"
#include "packet_parser.h"
#include <chrono>
#include <cstdint>
#include <map>
#include <vector>
#include <string>

namespace DPI {

class StatsCollector {
public:
    StatsCollector();

    void update(const PacketAnalyzer::RawPacket& raw, const PacketAnalyzer::ParsedPacket& parsed);
    void checkAndPrint(const std::vector<std::string>& dns, const std::vector<std::string>& http, const std::vector<std::string>& tracker_alerts, const std::map<std::string, size_t>& apps, size_t connections = 0, size_t dropped = 0);
    void printFinal(const std::vector<std::string>& dns, const std::vector<std::string>& http, const std::vector<std::string>& tracker_alerts, const std::map<std::string, size_t>& apps, size_t connections = 0, size_t dropped = 0);

private:
    uint64_t total_packets_ = 0;
    uint64_t total_bytes_ = 0;
    
    uint64_t tcp_packets_ = 0;
    uint64_t udp_packets_ = 0;
    uint64_t icmp_packets_ = 0;
    uint64_t other_packets_ = 0;
    
    uint64_t interval_packets_ = 0;
    
    std::chrono::steady_clock::time_point last_print_time_;
    std::chrono::steady_clock::time_point start_time_;
    
    std::vector<std::string> local_alerts_;
    
    void printMetrics(double pps);
    void exportJson(const std::string& filename, const std::vector<std::string>& dns, const std::vector<std::string>& http, const std::vector<std::string>& alerts, const std::map<std::string, size_t>& apps, size_t connections = 0, size_t dropped = 0);
};

} // namespace DPI

#endif // STATS_COLLECTOR_H
