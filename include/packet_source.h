#ifndef PACKET_SOURCE_H
#define PACKET_SOURCE_H

#include "pcap_reader.h"
#include <string>
#include <vector>
#include <memory>

namespace PacketAnalyzer {

struct InterfaceInfo {
    std::string name;
    std::string description;
    int index;
};

// Abstract base class for packet sources (PCAP file or Live Network Interface)
class PacketSource {
public:
    virtual ~PacketSource() = default;

    virtual bool open() = 0;
    virtual void close() = 0;
    virtual bool getNextPacket(RawPacket& packet) = 0;

    virtual std::string getSourceName() const = 0;
    virtual std::string getMode() const = 0; // "offline" or "live"
    virtual bool isLive() const = 0;
    virtual uint64_t getCaptureDrops() const { return 0; }

    static std::vector<InterfaceInfo> listInterfaces();
};

} // namespace PacketAnalyzer

#endif // PACKET_SOURCE_H
