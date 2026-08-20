#ifndef DNS_PARSER_H
#define DNS_PARSER_H

#include <cstdint>
#include <string>
#include <optional>
#include <vector>

namespace DPI {

struct DnsAnswer {
    std::string domain;   // The queried hostname
    uint32_t    ip;       // Resolved IPv4 (0 if not A record)
    uint32_t    ttl = 300; // TTL in seconds (default 300)
};


class DNSParser {
public:
    // Extract queried domain from DNS request (UDP 53)
    static std::optional<std::string> extractQuery(const uint8_t* payload, size_t length);
    
    // Check if this is a DNS query (not response)
    static bool isDNSQuery(const uint8_t* payload, size_t length);
    
    // Extract A-record answers from DNS response (builds IP->domain mappings)
    static std::vector<DnsAnswer> extractAnswers(const uint8_t* payload, size_t length);
    
    // Helper: skip a DNS name field, returns new offset or 0 on error
    static size_t skipName(const uint8_t* payload, size_t length, size_t offset);
};

} // namespace DPI

#endif // DNS_PARSER_H
