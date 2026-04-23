#ifndef DNS_PARSER_H
#define DNS_PARSER_H

#include <cstdint>
#include <string>
#include <optional>

namespace DPI {

class DNSParser {
public:
    // Extract queried domain from DNS request (UDP 53)
    static std::optional<std::string> extractQuery(const uint8_t* payload, size_t length);
    
    // Check if this is a DNS query (not response)
    static bool isDNSQuery(const uint8_t* payload, size_t length);
};

} // namespace DPI

#endif // DNS_PARSER_H
