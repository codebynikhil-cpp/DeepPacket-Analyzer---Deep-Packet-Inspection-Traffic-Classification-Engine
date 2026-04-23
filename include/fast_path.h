#ifndef FAST_PATH_H
#define FAST_PATH_H

#include "packet_parser.h"

namespace DPI {

class FastPath {
public:
    // Only router logic: Needs DPI inspection if payload is present and ports are HTTP/HTTPS/DNS
    bool needsInspection(const PacketAnalyzer::ParsedPacket& pkt);
};

} // namespace DPI

#endif // FAST_PATH_H
