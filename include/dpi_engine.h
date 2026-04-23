#ifndef DPI_ENGINE_H
#define DPI_ENGINE_H

#include "packet_parser.h"
#include "types.h"

namespace DPI {

class DPIEngine {
public:
    // Pure stateless payload inspector
    AppClassification inspect(const PacketAnalyzer::ParsedPacket& pkt);
};

} // namespace DPI

#endif // DPI_ENGINE_H
