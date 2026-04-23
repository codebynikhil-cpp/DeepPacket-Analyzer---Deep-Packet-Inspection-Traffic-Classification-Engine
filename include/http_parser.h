#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H

#include <cstdint>
#include <string>
#include <optional>

namespace DPI {

struct HTTPInfo {
    std::string method;
    std::string host;
    std::string path;
};

class HTTPParser {
public:
    // Extract Method, Host, and Path from HTTP request payload safely
    static std::optional<HTTPInfo> extract(const uint8_t* payload, size_t length);
    static bool isHTTPRequest(const uint8_t* payload, size_t length);
};

} // namespace DPI

#endif // HTTP_PARSER_H
