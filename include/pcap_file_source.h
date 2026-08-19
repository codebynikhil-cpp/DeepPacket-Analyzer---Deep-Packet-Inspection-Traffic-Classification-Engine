#ifndef PCAP_FILE_SOURCE_H
#define PCAP_FILE_SOURCE_H

#include "packet_source.h"
#include "pcap_reader.h"

namespace PacketAnalyzer {

class PcapFileSource : public PacketSource {
public:
    explicit PcapFileSource(const std::string& filename)
        : filename_(filename) {}

    bool open() override {
        return reader_.open(filename_);
    }

    void close() override {
        reader_.close();
    }

    bool getNextPacket(RawPacket& packet) override {
        return reader_.readNextPacket(packet);
    }

    std::string getSourceName() const override { return filename_; }
    std::string getMode() const override { return "offline"; }
    bool isLive() const override { return false; }

private:
    std::string filename_;
    PcapReader reader_;
};

} // namespace PacketAnalyzer

#endif // PCAP_FILE_SOURCE_H
