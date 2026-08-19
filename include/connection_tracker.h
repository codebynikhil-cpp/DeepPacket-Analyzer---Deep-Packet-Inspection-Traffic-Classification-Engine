#ifndef CONNECTION_TRACKER_H
#define CONNECTION_TRACKER_H

#include "types.h"
#include "packet_parser.h"
#include "rule_manager.h"
#include <unordered_map>
#include <vector>
#include <map>

namespace DPI {

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

    const std::vector<std::string>& getDnsQueries() const { return dns_queries_; }
    const std::vector<std::string>& getHttpRequests() const { return http_requests_; }
    const std::vector<std::string>& getAlerts() const { return alerts_; }
    std::map<std::string, size_t> getApplicationStats() const;
    size_t getConnectionsCount() const { return connections_.size(); }
    size_t getDroppedCount() const { return dropped_count_; }


private:
    std::unordered_map<FiveTuple, Connection, FiveTupleHash> connections_;
    std::vector<std::string> dns_queries_;
    std::vector<std::string> http_requests_;
    std::vector<std::string> alerts_;
    RuleManager rule_manager_;
    
    size_t total_seen_ = 0;
    size_t dropped_count_ = 0;
    
    Connection* getOrCreateConnection(const FiveTuple& tuple);
};

} // namespace DPI

#endif // CONNECTION_TRACKER_H
