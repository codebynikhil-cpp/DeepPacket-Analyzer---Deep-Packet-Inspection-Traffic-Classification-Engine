#include "dns_parser.h"

namespace DPI {

bool DNSParser::isDNSQuery(const uint8_t* payload, size_t length) {
    if (length < 12) return false;
    
    // Check QR bit (byte 2, bit 7) - should be 0 for query
    uint8_t flags = payload[2];
    if (flags & 0x80) return false;
    
    // Check QDCOUNT (bytes 4-5) - should be > 0
    uint16_t qdcount = (static_cast<uint16_t>(payload[4]) << 8) | payload[5];
    if (qdcount == 0) return false;
    
    return true;
}

std::optional<std::string> DNSParser::extractQuery(const uint8_t* payload, size_t length) {
    if (!isDNSQuery(payload, length)) {
        return std::nullopt;
    }
    
    // DNS query starts at byte 12
    size_t offset = 12;
    std::string domain;
    
    while (offset < length) {
        uint8_t label_length = payload[offset];
        
        if (label_length == 0) {
            break;
        }
        
        if (label_length > 63) {
            break; // Compression pointer or invalid
        }
        
        offset++;
        if (offset + label_length > length) break;
        
        if (!domain.empty()) {
            domain += '.';
        }
        domain += std::string(reinterpret_cast<const char*>(payload + offset), label_length);
        offset += label_length;
    }
    
    return domain.empty() ? std::nullopt : std::optional<std::string>(domain);
}

} // namespace DPI
