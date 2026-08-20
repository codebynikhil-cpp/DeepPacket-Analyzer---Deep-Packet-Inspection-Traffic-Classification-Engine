#ifndef CONNECTION_TRACKER_H
#define CONNECTION_TRACKER_H

#include "types.h"
#include "packet_parser.h"
#include "rule_manager.h"
#include <unordered_map>
#include <vector>
#include <map>
#include <string>

namespace DPI {

class WfpEnforcement;

class ConnectionTracker {
public:
    ConnectionTracker();
    
    // Tracks flow and Decides FORWARD / DROP
    PacketAction process(const PacketAnalyzer::ParsedPacket& pkt,
                         const std::optional<AppClassification>& classification);

    // Outputs the active connections and statistical histogram
    void generateReport();
    
    // Access rule manager to configure blocks
    RuleManager& getRuleManager() { return rule_manager_; }

    void setEnforcement(WfpEnforcement* enforcement);
    void reinstallWfpRules();

    const std::vector<std::string>& getDnsQueries() const { return dns_queries_; }
    const std::vector<std::string>& getHttpRequests() const { return http_requests_; }
    const std::vector<std::string>& getAlerts() const { return alerts_; }
    const std::vector<FlowRecord>& getRecentFlows() const { return recent_flows_; }
    std::map<std::string, size_t> getApplicationStats() const;
    std::map<std::string, size_t> getDomainStats() const;
    size_t getConnectionsCount() const { return connections_.size(); }
    size_t getDroppedCount() const { return dropped_count_; }

    // Resolve app name from domain (using critical_websites registry if matched)
    std::string resolveAppName(const std::string& domain) const;
    void loadCriticalWebsites(const std::string& filename = "critical_websites.json");

    struct DnsEntry {
        std::string domain;
        uint32_t    ttl = 300;
        std::chrono::steady_clock::time_point expires_at;
    };

private:
    std::unordered_map<FiveTuple, Connection, FiveTupleHash> connections_;
    std::vector<FlowRecord> recent_flows_;
    std::vector<std::string> dns_queries_;
    std::vector<std::string> http_requests_;
    std::vector<std::string> alerts_;
    RuleManager rule_manager_;
    WfpEnforcement* enforcement_ = nullptr;
    
    // IP -> domain cache built from DNS responses with TTL expiration
    std::unordered_map<uint32_t, DnsEntry> ip_to_domain_;
    std::unordered_map<uint32_t, AppType>  ip_to_app_;
    
    // Critical websites registry loaded from JSON: name -> list of wildcard patterns
    std::vector<std::pair<std::string, std::vector<std::string>>> critical_websites_;
    
    size_t total_seen_ = 0;
    size_t dropped_count_ = 0;
    
    Connection* getOrCreateConnection(const FiveTuple& tuple);
    void learnDnsMapping(const std::string& domain, uint32_t ip, uint32_t ttl = 300);
    std::string lookupDomainForIP(uint32_t ip);
};

} // namespace DPI

#endif // CONNECTION_TRACKER_H

