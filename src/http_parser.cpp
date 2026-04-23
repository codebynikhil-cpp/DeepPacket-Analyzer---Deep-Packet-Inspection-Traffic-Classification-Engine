#include "http_parser.h"
#include <cstring>
#include <algorithm>

namespace DPI {

bool HTTPParser::isHTTPRequest(const uint8_t* payload, size_t length) {
    if (length < 4) return false;
    const char* methods[] = {"GET ", "POST", "PUT ", "HEAD", "DELE", "PATC", "OPTI"};
    for (const char* method : methods) {
        if (std::memcmp(payload, method, 4) == 0) {
            return true;
        }
    }
    return false;
}

std::optional<HTTPInfo> HTTPParser::extract(const uint8_t* payload, size_t length) {
    if (!isHTTPRequest(payload, length)) {
        return std::nullopt;
    }
    
    HTTPInfo info;
    
    // Parse First Line: METHOD PATH HTTP/1.1\r\n
    size_t line_end = 0;
    while (line_end < length && payload[line_end] != '\r' && payload[line_end] != '\n') {
        line_end++;
    }
    
    if (line_end > 0) {
        std::string first_line(reinterpret_cast<const char*>(payload), line_end);
        size_t sp1 = first_line.find(' ');
        if (sp1 != std::string::npos) {
            info.method = first_line.substr(0, sp1);
            size_t sp2 = first_line.find(' ', sp1 + 1);
            if (sp2 != std::string::npos) {
                info.path = first_line.substr(sp1 + 1, sp2 - sp1 - 1);
            }
        }
    }
    
    // Search for "Host: " header
    const char* host_header = "Host: ";
    const size_t host_header_len = 6;
    
    for (size_t i = 0; i + host_header_len < length; i++) {
        // Case-insensitive check "host:"
        if ((payload[i] == 'H' || payload[i] == 'h') &&
            (payload[i+1] == 'o' || payload[i+1] == 'O') &&
            (payload[i+2] == 's' || payload[i+2] == 'S') &&
            (payload[i+3] == 't' || payload[i+3] == 'T') &&
            payload[i+4] == ':') {
            
            size_t start = i + 5;
            while (start < length && (payload[start] == ' ' || payload[start] == '\t')) {
                start++;
            }
            
            size_t end = start;
            while (end < length && payload[end] != '\r' && payload[end] != '\n') {
                end++;
            }
            
            if (end > start) {
                std::string host(reinterpret_cast<const char*>(payload + start), end - start);
                size_t colon_pos = host.find(':'); // remove port
                if (colon_pos != std::string::npos) {
                    host = host.substr(0, colon_pos);
                }
                info.host = host;
                break;
            }
        }
    }
    
    if (!info.method.empty()) {
        return info;
    }
    
    return std::nullopt;
}

} // namespace DPI
