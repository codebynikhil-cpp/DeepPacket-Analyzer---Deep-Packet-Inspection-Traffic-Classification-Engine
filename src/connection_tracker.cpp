#include "connection_tracker.h"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <sstream>

namespace DPI {

std::map<std::string, size_t> ConnectionTracker::getApplicationStats() const {
    std::map<std::string, size_t> stats;
    for (const auto& pair : connections_) {
        stats[appTypeToString(pair.second.app_type)]++;
    }
    return stats;
}

ConnectionTracker::ConnectionTracker() {
}

Connection* ConnectionTracker::getOrCreateConnection(const FiveTuple& tuple) {
    auto it = connections_.find(tuple);
    if (it != connections_.end()) {
        return &it->second;
    }
    
    Connection conn;
    conn.tuple = tuple;
    conn.state = ConnectionState::NEW;
    auto result = connections_.emplace(tuple, std::move(conn));
    return &result.first->second;
}

PacketAction ConnectionTracker::process(const PacketAnalyzer::ParsedPacket& pkt,
                                        const std::optional<AppClassification>& classification) {
    if (!pkt.has_ip) return PacketAction::FORWARD;
    total_seen_++;
    
    FiveTuple tuple;
    tuple.src_ip = pkt.src_ip_num;
    tuple.dst_ip = pkt.dest_ip_num;
    tuple.src_port = pkt.src_port;
    tuple.dst_port = pkt.dest_port;
    tuple.protocol = pkt.protocol;
    
    Connection* conn = getOrCreateConnection(tuple);
    
    // Check for suspicious ports once per new connection
    if (conn->state == ConnectionState::NEW) {
        if (pkt.src_port == 4444 || pkt.dest_port == 4444) {
            std::string msg = "Suspicious port 4444";
            std::cout << "[ALERT] " << msg << "\n";
            alerts_.push_back(msg);
        }
        if (pkt.src_port == 1337 || pkt.dest_port == 1337) {
            std::string msg = "Suspicious port 1337";
            std::cout << "[ALERT] " << msg << "\n";
            alerts_.push_back(msg);
        }
    }

    // If DPI classified it, apply the full classification
    if (classification.has_value() && conn->state != ConnectionState::CLASSIFIED) {
        conn->app_type = classification->app;
        conn->sni = classification->sni_or_host;
        conn->state = ConnectionState::CLASSIFIED;
        
        // Output DNS in real-time as requested
        if (conn->app_type == AppType::DNS && !conn->sni.empty()) {
            std::cout << "[DNS] " << conn->sni << "\n";
            dns_queries_.push_back(conn->sni);
        }
        
        // Output HTTP in real-time as requested
        if (!classification->http_method.empty()) {
            std::string req = classification->http_method + " " + classification->sni_or_host + classification->http_path;
            std::cout << "[HTTP] " << req << "\n";
            http_requests_.push_back(req);
        }
    }
    // Fallback: classify by well-known port if still UNKNOWN
    // Covers payload-less TCP packets (SYN/ACK/FIN) on known ports
    else if (conn->app_type == AppType::UNKNOWN) {
        uint16_t port = std::min(pkt.src_port, pkt.dest_port); // use the well-known side
        if (pkt.dest_port == 443 || pkt.src_port == 443) {
            conn->app_type = AppType::HTTPS;
        } else if (pkt.dest_port == 80 || pkt.src_port == 80) {
            conn->app_type = AppType::HTTP;
        } else if (pkt.dest_port == 53 || pkt.src_port == 53) {
            conn->app_type = AppType::DNS;
        }
    }
    
    // Check Rules dynamically (IP, App, Domain, Port)
    if (rule_manager_.shouldBlock(pkt.src_ip_num, pkt.dest_port, conn->app_type, conn->sni).has_value() ||
        rule_manager_.isPortBlocked(pkt.src_port) ||
        rule_manager_.isPortBlocked(pkt.dest_port) ||
        rule_manager_.isIPBlocked(pkt.dest_ip_num)) {
        conn->action = PacketAction::DROP;
    }
    
    if (conn->action == PacketAction::DROP) {
        dropped_count_++;
    }
    
    return conn->action;
}

void ConnectionTracker::generateReport() {
    std::unordered_map<AppType, size_t> app_distribution;
    for (const auto& pair : connections_) {
        app_distribution[pair.second.app_type]++;
    }

    std::cout << "\n+--------------------------------------------------------------+\n";
    std::cout << "|               CONNECTION STATISTICS REPORT                   |\n";
    std::cout << "+--------------------------------------------------------------+\n";
    std::cout << "| Total Packets Processed:" << std::setw(10) << total_seen_ << "                          |\n";
    std::cout << "| Packets Dropped:        " << std::setw(10) << dropped_count_ << "                          |\n";
    std::cout << "+--------------------------------------------------------------+\n";
    std::cout << "|                    APPLICATION BREAKDOWN                     |\n";
    std::cout << "+--------------------------------------------------------------+\n";
    
    std::vector<std::pair<AppType, size_t>> sorted_apps(app_distribution.begin(), app_distribution.end());
    std::sort(sorted_apps.begin(), sorted_apps.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
    
    size_t total_conns = connections_.size();
    for (const auto& pair : sorted_apps) {
        double pct = total_conns > 0 ? (100.0 * pair.second / total_conns) : 0;
        int bar = static_cast<int>(pct / 5);
        std::string bar_str(bar, '#');
        std::cout << "| " << std::setw(15) << std::left << appTypeToString(pair.first)
                  << std::setw(8) << std::right << pair.second
                  << " (" << std::fixed << std::setprecision(1) << std::setw(5) << pct << "%) "
                  << std::setw(19) << std::left << bar_str << " |\n";
    }
    std::cout << "+--------------------------------------------------------------+\n";
}

} // namespace DPI
