#include "connection_tracker.h"
#include "dns_parser.h"
#include "types.h"
#include "wfp_enforcement.h"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <sstream>
#include <fstream>
#include <ctime>

namespace DPI {

// Helper to format a domain name into a clean display title
static std::string formatDomainAsApp(const std::string& domain) {
    if (domain.empty()) return "";
    
    std::string s = domain;
    size_t colon = s.find(':');
    if (colon != std::string::npos) s = s.substr(0, colon);

    if (s.rfind("www.", 0) == 0) s = s.substr(4);

    return s;
}

void ConnectionTracker::loadCriticalWebsites(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) return;

    critical_websites_.clear();
    std::string line;
    std::string current_name = "";
    std::vector<std::string> current_domains;

    while (std::getline(file, line)) {
        size_t name_pos = line.find("\"name\":");
        if (name_pos != std::string::npos) {
            if (!current_name.empty() && !current_domains.empty()) {
                critical_websites_.push_back({current_name, current_domains});
                current_domains.clear();
            }
            size_t q1 = line.find('"', name_pos + 7);
            if (q1 != std::string::npos) {
                size_t q2 = line.find('"', q1 + 1);
                if (q2 != std::string::npos) {
                    current_name = line.substr(q1 + 1, q2 - q1 - 1);
                }
            }
        }
        size_t dom_pos = line.find("\"domains\":");
        if (dom_pos != std::string::npos || (line.find('"') != std::string::npos && !current_name.empty())) {
            size_t start = 0;
            while (true) {
                size_t q1 = line.find('"', start);
                if (q1 == std::string::npos) break;
                size_t q2 = line.find('"', q1 + 1);
                if (q2 == std::string::npos) break;
                std::string item = line.substr(q1 + 1, q2 - q1 - 1);
                if (item != "name" && item != "domains" && item != "category" && item != "websites" && !item.empty()) {
                    current_domains.push_back(item);
                }
                start = q2 + 1;
            }
        }
    }
    if (!current_name.empty() && !current_domains.empty()) {
        critical_websites_.push_back({current_name, current_domains});
    }
    file.close();
}

std::string ConnectionTracker::resolveAppName(const std::string& domain) const {
    if (domain.empty()) return "UNKNOWN";

    // 1. Match configured critical websites registry
    for (const auto& cw : critical_websites_) {
        for (const auto& pat : cw.second) {
            if (WfpEnforcement::domainMatches(domain, pat)) {
                return cw.first;
            }
        }
    }

    // 2. Match known AppType enum table
    AppType at = sniToAppType(domain);
    if (at != AppType::UNKNOWN && at != AppType::HTTPS && at != AppType::HTTP && at != AppType::TLS && at != AppType::QUIC && at != AppType::DNS) {
        return appTypeToString(at);
    }

    // 3. Fallback: formatted domain as application title
    return formatDomainAsApp(domain);
}

std::map<std::string, size_t> ConnectionTracker::getApplicationStats() const {
    std::map<std::string, size_t> stats;
    for (const auto& pair : connections_) {
        const auto& conn = pair.second;
        if (!conn.app_name.empty() && conn.app_name != "UNKNOWN") {
            stats[conn.app_name]++;
        } else if (!conn.sni.empty()) {
            stats[resolveAppName(conn.sni)]++;
        } else {
            stats[appTypeToString(conn.app_type)]++;
        }
    }
    return stats;
}

std::map<std::string, size_t> ConnectionTracker::getDomainStats() const {
    std::map<std::string, size_t> stats;
    for (const auto& pair : connections_) {
        const auto& conn = pair.second;
        if (!conn.sni.empty()) {
            stats[conn.sni]++;
        }
    }
    return stats;
}

ConnectionTracker::ConnectionTracker() {
    loadCriticalWebsites("critical_websites.json");
}

void ConnectionTracker::setEnforcement(WfpEnforcement* enforcement) {
    enforcement_ = enforcement;
    rule_manager_.setEnforcement(enforcement);
}

void ConnectionTracker::reinstallWfpRules() {
    std::unordered_map<uint32_t, std::string> plain_ip_domain;
    auto now = std::chrono::steady_clock::now();
    for (const auto& kv : ip_to_domain_) {
        if (kv.second.expires_at > now) {
            plain_ip_domain[kv.first] = kv.second.domain;
        }
    }
    rule_manager_.reinstallAllWfpRules(plain_ip_domain);
}

void ConnectionTracker::learnDnsMapping(const std::string& domain, uint32_t ip, uint32_t ttl) {
    if (ip == 0 || domain.empty()) return;
    if (ttl == 0) ttl = 300; // minimum default 5 min
    auto expires = std::chrono::steady_clock::now() + std::chrono::seconds(ttl);
    ip_to_domain_[ip] = { domain, ttl, expires };
    ip_to_app_[ip]    = sniToAppType(domain);
    if (enforcement_) {
        enforcement_->onNewDnsMapping(domain, ip);
    }
}

std::string ConnectionTracker::lookupDomainForIP(uint32_t ip) {
    auto it = ip_to_domain_.find(ip);
    if (it != ip_to_domain_.end()) {
        if (it->second.expires_at > std::chrono::steady_clock::now()) {
            return it->second.domain;
        }
    }
    return "";
}

Connection* ConnectionTracker::getOrCreateConnection(const FiveTuple& tuple) {
    auto it = connections_.find(tuple);
    if (it != connections_.end()) {
        return &it->second;
    }
    auto rev_it = connections_.find(tuple.reverse());
    if (rev_it != connections_.end()) {
        return &rev_it->second;
    }
    
    Connection conn;
    conn.tuple = tuple;
    conn.state = ConnectionState::NEW;
    conn.first_seen = std::chrono::steady_clock::now();
    conn.last_seen = conn.first_seen;
    auto result = connections_.emplace(tuple, std::move(conn));
    return &result.first->second;
}

static std::string ipNumToString(uint32_t ip) {
    std::ostringstream ss;
    ss << ((ip >> 0) & 0xFF) << "."
       << ((ip >> 8) & 0xFF) << "."
       << ((ip >> 16) & 0xFF) << "."
       << ((ip >> 24) & 0xFF);
    return ss.str();
}

static std::string getNowTimestamp() {
    auto t = std::time(nullptr);
    auto tm = *std::localtime(&t);
    std::ostringstream oss;
    oss << std::put_time(&tm, "%H:%M:%S");
    return oss.str();
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
    conn->last_seen = std::chrono::steady_clock::now();
    
    // Check for suspicious ports once per new connection
    if (conn->state == ConnectionState::NEW) {
        if (pkt.src_port == 4444 || pkt.dest_port == 4444) {
            std::string msg = "Suspicious port 4444";
            alerts_.push_back(msg);
        }
        if (pkt.src_port == 1337 || pkt.dest_port == 1337) {
            std::string msg = "Suspicious port 1337";
            alerts_.push_back(msg);
        }
    }

    // 1. Structured Inspection Priority: TLS SNI > HTTP Host > QUIC SNI > DNS
    if (classification.has_value()) {
        if (!classification->sni_or_host.empty()) {
            conn->sni = classification->sni_or_host;
            conn->app_type = classification->app;
            conn->app_name = resolveAppName(conn->sni);
            
            if (pkt.has_tcp && (pkt.src_port == 443 || pkt.dest_port == 443)) {
                conn->detection_method = "TLS SNI";
            } else if (pkt.has_tcp && (pkt.src_port == 80 || pkt.dest_port == 80)) {
                conn->detection_method = "HTTP Host";
            } else if (pkt.has_udp && (pkt.src_port == 443 || pkt.dest_port == 443)) {
                conn->detection_method = "QUIC SNI";
            } else if (pkt.has_udp && (pkt.src_port == 53 || pkt.dest_port == 53)) {
                conn->detection_method = "DNS Query";
            }
            conn->state = ConnectionState::CLASSIFIED;
        } else if (conn->app_type == AppType::UNKNOWN) {
            conn->app_type = classification->app;
            conn->detection_method = "Protocol Header";
            conn->state = ConnectionState::CLASSIFIED;
        }
        
        // Process DNS payload responses & learn IP mappings with TTL
        if ((pkt.src_port == 53 || pkt.dest_port == 53) && pkt.payload_data) {
            if (conn->app_type == AppType::DNS && !conn->sni.empty()) {
                dns_queries_.push_back(conn->sni);
            }
            auto answers = DNSParser::extractAnswers(pkt.payload_data, pkt.payload_length);
            for (const auto& ans : answers) {
                learnDnsMapping(ans.domain, ans.ip, ans.ttl);
                if (!ans.domain.empty()) {
                    bool already = false;
                    for (const auto& q : dns_queries_) {
                        if (q == ans.domain) { already = true; break; }
                    }
                    if (!already) {
                        dns_queries_.push_back(ans.domain);
                    }
                }
            }
        }
        
        // Output HTTP requests in real-time list
        if (!classification->http_method.empty()) {
            std::string req = classification->http_method + " " + classification->sni_or_host + classification->http_path;
            http_requests_.push_back(req);
        }
    }

    // 2. DNS Correlation Fallback (if no SNI was directly extracted on this packet)
    if (conn->sni.empty()) {
        std::string resolved = lookupDomainForIP(tuple.dst_ip);
        if (resolved.empty()) resolved = lookupDomainForIP(tuple.src_ip);
        if (!resolved.empty()) {
            conn->sni = resolved;
            conn->app_name = resolveAppName(resolved);
            conn->detection_method = "DNS Correlation";
            conn->state = ConnectionState::CLASSIFIED;
        } else if (conn->app_type == AppType::UNKNOWN) {
            if (pkt.dest_port == 443 || pkt.src_port == 443) {
                conn->app_type = pkt.has_udp ? AppType::QUIC : AppType::HTTPS;
                conn->detection_method = "Port 443";
            } else if (pkt.dest_port == 80 || pkt.src_port == 80) {
                conn->app_type = AppType::HTTP;
                conn->detection_method = "Port 80";
            } else if (pkt.dest_port == 53 || pkt.src_port == 53) {
                conn->app_type = AppType::DNS;
                conn->detection_method = "Port 53";
            }
        }
    }
    
    // Check Rules dynamically (IP, App, Domain, Port)
    bool blocked = false;
    if (rule_manager_.shouldBlock(pkt.src_ip_num, pkt.dest_port, conn->app_type, conn->sni).has_value() ||
        rule_manager_.isPortBlocked(pkt.src_port) ||
        rule_manager_.isPortBlocked(pkt.dest_port) ||
        rule_manager_.isIPBlocked(pkt.dest_ip_num) ||
        rule_manager_.isDomainBlocked(conn->sni)) {
        conn->action = PacketAction::DROP;
        blocked = true;
    } else {
        conn->action = PacketAction::FORWARD;
    }
    
    if (conn->action == PacketAction::DROP) {
        dropped_count_++;
    }

    // Record flow for Dashboard recent-flows table once per new connection
    if (conn->state == ConnectionState::NEW) {
        FlowRecord rec;
        rec.timestamp = getNowTimestamp();
        rec.src_ip = ipNumToString(tuple.src_ip);
        rec.src_port = tuple.src_port;
        rec.dst_ip = ipNumToString(tuple.dst_ip);
        rec.dst_port = tuple.dst_port;
        rec.protocol = (tuple.protocol == 6) ? "TCP" : (tuple.protocol == 17) ? "UDP" : "ICMP";
        rec.domain = conn->sni.empty() ? "UNKNOWN" : conn->sni;
        rec.application = conn->app_name.empty() ? resolveAppName(conn->sni) : conn->app_name;
        rec.method = conn->detection_method;
        rec.policy = blocked ? "DROP" : "FORWARD";
        rec.enforcement = (enforcement_ && enforcement_->isActive()) ? "WFP ACTIVE" : "MONITOR ONLY";

        recent_flows_.push_back(std::move(rec));
        if (recent_flows_.size() > 100) {
            recent_flows_.erase(recent_flows_.begin());
        }
        conn->state = ConnectionState::ESTABLISHED;
    }

    
    return conn->action;
}

void ConnectionTracker::generateReport() {
    std::map<std::string, size_t> app_distribution = getApplicationStats();

    std::cout << "\n+--------------------------------------------------------------+\n";
    std::cout << "|               CONNECTION STATISTICS REPORT                   |\n";
    std::cout << "+--------------------------------------------------------------+\n";
    std::cout << "| Total Packets Processed:" << std::setw(10) << total_seen_ << "                          |\n";
    std::cout << "| Packets Dropped:        " << std::setw(10) << dropped_count_ << "                          |\n";
    std::cout << "+--------------------------------------------------------------+\n";
    std::cout << "|                    APPLICATION BREAKDOWN                     |\n";
    std::cout << "+--------------------------------------------------------------+\n";
    
    std::vector<std::pair<std::string, size_t>> sorted_apps(app_distribution.begin(), app_distribution.end());
    std::sort(sorted_apps.begin(), sorted_apps.end(), [](const auto& a, const auto& b) { return a.second > b.second; });
    
    size_t total_conns = connections_.size();
    for (const auto& pair : sorted_apps) {
        double pct = total_conns > 0 ? (100.0 * pair.second / total_conns) : 0;
        int bar = static_cast<int>(pct / 5);
        std::string bar_str(bar, '#');
        std::string display_name = pair.first;
        if (display_name.length() > 20) {
            display_name = display_name.substr(0, 17) + "...";
        }
        std::cout << "| " << std::setw(20) << std::left << display_name
                  << std::setw(8) << std::right << pair.second
                  << " (" << std::fixed << std::setprecision(1) << std::setw(5) << pct << "%) "
                  << std::setw(14) << std::left << bar_str << " |\n";
    }
    std::cout << "+--------------------------------------------------------------+\n";
}

} // namespace DPI

