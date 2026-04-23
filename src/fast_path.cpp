#include "fast_path.h"

namespace DPI {

bool FastPath::needsInspection(const PacketAnalyzer::ParsedPacket& pkt) {
    if (pkt.payload_length == 0 || !pkt.payload_data) {
        return false;
    }
    
    // Only inspect ports 80 (HTTP), 443 (HTTPS), 53 (DNS)
    if (pkt.has_tcp || pkt.has_udp) {
        if (pkt.src_port == 80 || pkt.dest_port == 80 ||
            pkt.src_port == 443 || pkt.dest_port == 443 ||
            pkt.src_port == 53 || pkt.dest_port == 53) {
            return true;
        }
    }
    
    return false;
}

} // namespace DPI
