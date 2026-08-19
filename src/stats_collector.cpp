#include "stats_collector.h"
#include <iostream>
#include <iomanip>
#include <fstream>

namespace DPI {

StatsCollector::StatsCollector() {
    start_time_ = std::chrono::steady_clock::now();
    last_print_time_ = start_time_;
}

void StatsCollector::update(const PacketAnalyzer::RawPacket& raw, const PacketAnalyzer::ParsedPacket& parsed) {
    total_packets_++;
    interval_packets_++;
    total_bytes_ += raw.header.orig_len; // Using original packet length from PCAP header
    
    if (parsed.has_ip) {
        if (parsed.protocol == 6 || parsed.has_tcp) { // TCP
            tcp_packets_++;
        } else if (parsed.protocol == 17 || parsed.has_udp) { // UDP
            udp_packets_++;
        } else if (parsed.protocol == 1) { // ICMP
            icmp_packets_++;
        } else {
            other_packets_++;
        }
    } else {
        other_packets_++;
    }
}

void StatsCollector::printMetrics(double pps) {
    double tcp_pct = total_packets_ > 0 ? (100.0 * tcp_packets_ / total_packets_) : 0.0;
    double udp_pct = total_packets_ > 0 ? (100.0 * udp_packets_ / total_packets_) : 0.0;
    double icmp_pct = total_packets_ > 0 ? (100.0 * icmp_packets_ / total_packets_) : 0.0;

    std::cout << "\nPackets: " << total_packets_ << " (PPS: " << std::fixed << std::setprecision(1) << pps << ")\n";
    std::cout << "Bytes: " << total_bytes_ << "\n";
    std::cout << "TCP: " << std::fixed << std::setprecision(1) << tcp_pct << "%\n";
    std::cout << "UDP: " << std::fixed << std::setprecision(1) << udp_pct << "%\n";
    std::cout << "ICMP: " << std::fixed << std::setprecision(1) << icmp_pct << "%\n";
}

void StatsCollector::exportJson(const std::string& filename, const std::vector<std::string>& dns, const std::vector<std::string>& http, const std::vector<std::string>& alerts, const std::map<std::string, size_t>& apps, size_t connections, size_t dropped) {
    std::ofstream out(filename);
    if (!out.is_open()) return;
    
    out << "{\n";
    out << "  \"packets\": " << total_packets_ << ",\n";
    out << "  \"bytes\": " << total_bytes_ << ",\n";
    out << "  \"connections\": " << connections << ",\n";
    out << "  \"dropped\": " << dropped << ",\n";
    out << "  \"protocols\": { \"TCP\": " << tcp_packets_ << ", \"UDP\": " << udp_packets_ << " },\n";
    
    out << "  \"applications\": {";
    size_t app_idx = 0;
    for (const auto& kv : apps) {
        out << "\"" << kv.first << "\": " << kv.second;
        if (app_idx < apps.size() - 1) out << ", ";
        app_idx++;
    }
    out << "},\n";
    
    out << "  \"dns\": [";
    for(size_t i = 0; i < dns.size(); ++i) {
        // Simple escaping for JSON
        out << "\"" << dns[i] << "\"";
        if (i < dns.size() - 1) out << ", ";
    }
    out << "],\n";
    
    out << "  \"http\": [";
    for(size_t i = 0; i < http.size(); ++i) {
        out << "\"" << http[i] << "\"";
        if (i < http.size() - 1) out << ", ";
    }
    out << "],\n";
    
    out << "  \"alerts\": [";
    for(size_t i = 0; i < alerts.size(); ++i) {
        out << "\"" << alerts[i] << "\"";
        if (i < alerts.size() - 1) out << ", ";
    }
    out << "]\n";
    
    out << "}\n";
    out.close();
}

void StatsCollector::checkAndPrint(const std::vector<std::string>& dns, const std::vector<std::string>& http, const std::vector<std::string>& tracker_alerts, const std::map<std::string, size_t>& apps, size_t connections, size_t dropped) {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_print_time_).count();
    
    if (elapsed >= 1000) { // 1 second elapsed
        double pps = (interval_packets_ * 1000.0) / elapsed;
        printMetrics(pps);
        
        if (pps > 1000.0) {
            std::string msg = "High traffic detected";
            std::cout << "[ALERT] " << msg << " (" << std::fixed << std::setprecision(1) << pps << " pps)\n";
            if (local_alerts_.size() < 10) {
                local_alerts_.push_back(msg);
            }
        }
        
        std::vector<std::string> combined_alerts = tracker_alerts;
        combined_alerts.insert(combined_alerts.end(), local_alerts_.begin(), local_alerts_.end());
        
        exportJson("output.json", dns, http, combined_alerts, apps, connections, dropped);
        
        last_print_time_ = now;
        interval_packets_ = 0;
    }
}

void StatsCollector::printFinal(const std::vector<std::string>& dns, const std::vector<std::string>& http, const std::vector<std::string>& tracker_alerts, const std::map<std::string, size_t>& apps, size_t connections, size_t dropped) {
    auto now = std::chrono::steady_clock::now();
    auto elapsed_total = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time_).count();
    
    double avg_pps = 0.0;
    if (elapsed_total > 0) {
        avg_pps = (total_packets_ * 1000.0) / elapsed_total;
    }
    
    std::cout << "\n[Stats] Final Traffic Breakdown:\n";
    printMetrics(avg_pps);
    
    std::vector<std::string> combined_alerts = tracker_alerts;
    combined_alerts.insert(combined_alerts.end(), local_alerts_.begin(), local_alerts_.end());
    
    exportJson("output.json", dns, http, combined_alerts, apps, connections, dropped);
}

} // namespace DPI
