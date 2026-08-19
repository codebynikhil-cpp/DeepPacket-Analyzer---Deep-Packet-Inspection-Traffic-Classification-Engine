#include "dpi_engine.h"
#include "sni_extractor.h"
#include "dns_parser.h"
#include "http_parser.h"

namespace DPI {

AppClassification DPIEngine::inspect(const PacketAnalyzer::ParsedPacket& pkt) {
    AppClassification result;
    
    if (pkt.payload_length == 0 || !pkt.payload_data) {
        return result; 
    }

    if (pkt.has_tcp) {
        if (pkt.src_port == 443 || pkt.dest_port == 443) {
            auto sniOpt = SNIExtractor::extract(pkt.payload_data, pkt.payload_length);
            if (sniOpt) {
                result.sni_or_host = *sniOpt;
                result.app = sniToAppType(result.sni_or_host);
                if (result.app == AppType::UNKNOWN) result.app = AppType::HTTPS;
                return result;
            }
            
            // Substring heuristic scan for TLS Client Hello handshakes
            std::string payload_str(reinterpret_cast<const char*>(pkt.payload_data), std::min<size_t>(pkt.payload_length, 1024));
            if (payload_str.find("wikipedia.org") != std::string::npos || payload_str.find("wikimedia.org") != std::string::npos) {
                result.sni_or_host = "wikipedia.org";
                result.app = AppType::WIKIPEDIA;
                return result;
            }
            if (payload_str.find("reddit.com") != std::string::npos || payload_str.find("redd.it") != std::string::npos) {
                result.sni_or_host = "reddit.com";
                result.app = AppType::REDDIT;
                return result;
            }
            if (payload_str.find("youtube.com") != std::string::npos || payload_str.find("googlevideo.com") != std::string::npos || payload_str.find("ytimg") != std::string::npos) {
                result.sni_or_host = "youtube.com";
                result.app = AppType::YOUTUBE;
                return result;
            }
            if (payload_str.find("openai.com") != std::string::npos || payload_str.find("chatgpt.com") != std::string::npos) {
                result.sni_or_host = "chatgpt.com";
                result.app = AppType::OPENAI;
                return result;
            }
            if (payload_str.find("leetcode.com") != std::string::npos) {
                result.sni_or_host = "leetcode.com";
                result.app = AppType::LEETCODE;
                return result;
            }
            if (payload_str.find("linkedin.com") != std::string::npos) {
                result.sni_or_host = "linkedin.com";
                result.app = AppType::LINKEDIN;
                return result;
            }
            if (payload_str.find("stackoverflow.com") != std::string::npos) {
                result.sni_or_host = "stackoverflow.com";
                result.app = AppType::STACKOVERFLOW;
                return result;
            }
        } 
        else if (pkt.src_port == 80 || pkt.dest_port == 80) {
            auto httpOpt = HTTPParser::extract(pkt.payload_data, pkt.payload_length);
            if (httpOpt) {
                result.sni_or_host = httpOpt->host;
                result.http_method = httpOpt->method;
                result.http_path = httpOpt->path;
                result.app = sniToAppType(result.sni_or_host);
                if (result.app == AppType::UNKNOWN) result.app = AppType::HTTP;
                return result;
            }
        }
    } 
    else if (pkt.has_udp) {
        if (pkt.src_port == 53 || pkt.dest_port == 53) {
            auto dnsOpt = DNSParser::extractQuery(pkt.payload_data, pkt.payload_length);
            if (dnsOpt) {
                result.sni_or_host = *dnsOpt;
                result.app = sniToAppType(result.sni_or_host);
                if (result.app == AppType::UNKNOWN) result.app = AppType::DNS;
                return result;
            }
        }
        else if (pkt.src_port == 443 || pkt.dest_port == 443) {
            // QUIC / HTTP/3 traffic (e.g. YouTube, Google, Cloudflare)
            auto sniOpt = QUICSNIExtractor::extract(pkt.payload_data, pkt.payload_length);
            if (sniOpt) {
                result.sni_or_host = *sniOpt;
                result.app = sniToAppType(result.sni_or_host);
                if (result.app == AppType::UNKNOWN) result.app = AppType::YOUTUBE;
                return result;
            }
            
            // Substring scan for QUIC initial packets
            std::string payload_str(reinterpret_cast<const char*>(pkt.payload_data), std::min<size_t>(pkt.payload_length, 1024));
            if (payload_str.find("googlevideo") != std::string::npos || payload_str.find("youtube") != std::string::npos || payload_str.find("ytimg") != std::string::npos) {
                result.sni_or_host = "youtube.com";
                result.app = AppType::YOUTUBE;
                return result;
            }
            if (payload_str.find("wikipedia") != std::string::npos) {
                result.sni_or_host = "wikipedia.org";
                result.app = AppType::WIKIPEDIA;
                return result;
            }
            if (payload_str.find("reddit") != std::string::npos) {
                result.sni_or_host = "reddit.com";
                result.app = AppType::REDDIT;
                return result;
            }
            
            // All other UDP 443 video streams default to YouTube / QUIC
            result.app = AppType::YOUTUBE;
            return result;
        }
    }
    
    return result;
}

} // namespace DPI
