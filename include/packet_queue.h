#ifndef PACKET_QUEUE_H
#define PACKET_QUEUE_H

#include "pcap_reader.h"
#include <queue>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <chrono>

namespace PacketAnalyzer {

class PacketQueue {
public:
    explicit PacketQueue(size_t max_capacity = 10000)
        : max_capacity_(max_capacity) {}

    bool push(RawPacket&& packet) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (stopped_) return false;

        if (queue_.size() >= max_capacity_) {
            processing_drops_++;
            return false; // Queue full - drop packet & increment metric
        }

        queue_.push(std::move(packet));
        packets_pushed_++;
        size_t current_size = queue_.size();
        if (current_size > max_queue_depth_) {
            max_queue_depth_ = current_size;
        }
        cv_.notify_one();
        return true;
    }

    bool pop(RawPacket& packet, std::chrono::milliseconds timeout = std::chrono::milliseconds(100)) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (queue_.empty()) {
            cv_.wait_for(lock, timeout, [this] { return !queue_.empty() || stopped_; });
        }

        if (stopped_ && queue_.empty()) {
            return false;
        }

        if (queue_.empty()) {
            return false;
        }

        packet = std::move(queue_.front());
        queue_.pop();
        packets_popped_++;
        return true;
    }

    void stop() {
        std::unique_lock<std::mutex> lock(mutex_);
        stopped_ = true;
        cv_.notify_all();
    }

    size_t size() const {
        std::unique_lock<std::mutex> lock(mutex_);
        return queue_.size();
    }

    uint64_t getProcessingDrops() const {
        return processing_drops_.load();
    }

    size_t getMaxQueueDepth() const {
        std::unique_lock<std::mutex> lock(mutex_);
        return max_queue_depth_;
    }

    uint64_t getPacketsPushed() const {
        return packets_pushed_.load();
    }

    uint64_t getPacketsPopped() const {
        return packets_popped_.load();
    }

    bool isStopped() const {
        return stopped_.load();
    }

private:
    size_t max_capacity_;
    std::queue<RawPacket> queue_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::atomic<bool> stopped_{false};
    std::atomic<uint64_t> processing_drops_{0};
    std::atomic<uint64_t> packets_pushed_{0};
    std::atomic<uint64_t> packets_popped_{0};
    size_t max_queue_depth_{0};
};

} // namespace PacketAnalyzer


#endif // PACKET_QUEUE_H
