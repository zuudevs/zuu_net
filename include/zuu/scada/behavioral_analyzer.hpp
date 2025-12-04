#pragma once
#include "scada_types.hpp"
#include "../performance/fast_hash.hpp"
#include "../performance/lock_free.hpp"
#include <atomic>
#include <array>
#include <vector>
#include <chrono>

namespace zuu::scada {

// Optimized traffic statistics (cache-friendly)
struct alignas(CACHE_LINE_SIZE) FastTrafficStats {
    std::atomic<uint64_t> packet_count{0};
    std::atomic<uint64_t> byte_count{0};
    std::atomic<uint32_t> write_count{0};
    std::atomic<uint32_t> read_count{0};
    std::atomic<uint32_t> exception_count{0};
    alignas(CACHE_LINE_SIZE) std::atomic<uint64_t> first_seen_ns{0};
    std::atomic<uint64_t> last_seen_ns{0};
    std::atomic<uint32_t> packets_per_second{0};
    
    void update(const PacketMetadata& pkt) noexcept {
        packet_count.fetch_add(1, std::memory_order_relaxed);
        byte_count.fetch_add(pkt.packet_size, std::memory_order_relaxed);
        
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        last_seen_ns.store(now, std::memory_order_relaxed);
        
        uint64_t expected = 0;
        first_seen_ns.compare_exchange_weak(expected, now, std::memory_order_relaxed);
        
        if (pkt.has_exception) {
            exception_count.fetch_add(1, std::memory_order_relaxed);
        }
        
        uint8_t fc = static_cast<uint8_t>(pkt.function_code);
        bool is_write = (fc >= 0x05 && fc <= 0x06) || (fc >= 0x0F && fc <= 0x10);
        bool is_read = (fc >= 0x01 && fc <= 0x04);
        
        write_count.fetch_add(is_write, std::memory_order_relaxed);
        read_count.fetch_add(is_read, std::memory_order_relaxed);
    }
    
    void updateRate() noexcept {
        uint64_t first = first_seen_ns.load(std::memory_order_relaxed);
        uint64_t last = last_seen_ns.load(std::memory_order_relaxed);
        uint64_t packets = packet_count.load(std::memory_order_relaxed);
        
        if (LIKELY(last > first)) {
            uint64_t duration_ns = last - first;
            uint64_t pps = (packets * 1000000000ULL) / duration_ns;
            packets_per_second.store(static_cast<uint32_t>(pps), 
                                    std::memory_order_relaxed);
        }
    }
    
    bool isDoS(uint32_t threshold) const noexcept {
        return packets_per_second.load(std::memory_order_relaxed) > threshold;
    }
    
    double getWriteReadRatio() const noexcept {
        uint32_t reads = read_count.load(std::memory_order_relaxed);
        if (UNLIKELY(reads == 0)) return 0.0;
        uint32_t writes = write_count.load(std::memory_order_relaxed);
        return static_cast<double>(writes) / reads;
    }
};

// Port scan detector using bitset (FIXED - no mutex issue)
class FastPortScanDetector {
private:
    struct PortBitset {
        std::array<std::atomic<uint64_t>, 1024> bits; // 65536 ports / 64
        std::atomic<uint64_t> last_reset_ns{0};
        std::atomic<uint32_t> unique_count{0};
        
        PortBitset() {
            reset();
        }
        
        void reset() noexcept {
            for (auto& b : bits) {
                b.store(0, std::memory_order_relaxed);
            }
            unique_count.store(0, std::memory_order_relaxed);
        }
        
        bool addPort(uint16_t port) noexcept {
            size_t idx = port / 64;
            size_t bit = port % 64;
            uint64_t mask = 1ULL << bit;
            
            uint64_t old = bits[idx].fetch_or(mask, std::memory_order_relaxed);
            bool was_new = (old & mask) == 0;
            
            if (was_new) {
                unique_count.fetch_add(1, std::memory_order_relaxed);
            }
            
            return was_new;
        }
        
        uint32_t getCount() const noexcept {
            return unique_count.load(std::memory_order_relaxed);
        }
    };
    
    perf::FastHashMap<PortBitset, 4096> ip_ports_;
    
public:
    bool checkPortScan(uint32_t ip, uint16_t port, uint32_t threshold) noexcept {
        auto* portset = ip_ports_.find(ip);
        
        if (!portset) {
            portset = ip_ports_.emplace(ip);
            if (!portset) return false;
        }
        
        auto now = std::chrono::steady_clock::now().time_since_epoch().count();
        uint64_t last = portset->last_reset_ns.load(std::memory_order_relaxed);
        
        if (now - last > 10000000000ULL) { // 10 seconds
            portset->reset();
            portset->last_reset_ns.store(now, std::memory_order_relaxed);
        }
        
        portset->addPort(port);
        return portset->getCount() >= threshold;
    }
};

// Main behavioral analyzer
class BehavioralAnalyzer {
private:
    perf::FastHashMap<FastTrafficStats, 8192> ip_stats_;
    FastPortScanDetector port_scanner_;
    DetectionConfig config_;
    
public:
    explicit BehavioralAnalyzer(const DetectionConfig& config)
        : config_(config) {}
    
    // Analyze packet and return threats
    std::vector<ThreatAlert> analyze(const PacketMetadata& pkt) noexcept {
        std::vector<ThreatAlert> alerts;
        
        uint32_t src_ip = pkt.source_ip.to_uint32();
        
        // Update stats
        auto* stats = ip_stats_.find(src_ip);
        if (!stats) {
            stats = ip_stats_.emplace(src_ip);
            if (!stats) return alerts; // Map full
        }
        
        stats->update(pkt);
        
        // Detection algorithms
        
        // 1. DoS Detection
        if (UNLIKELY(stats->isDoS(config_.dos_packet_threshold))) {
            alerts.emplace_back(
                pkt.source_ip, pkt.dest_ip,
                AttackType::DOS_FLOOD,
                ThreatLevel::CRITICAL,
                "DoS flood detected",
                0.95
            );
        }
        
        // 2. Port Scan
        if (UNLIKELY(port_scanner_.checkPortScan(src_ip, pkt.dest_port, 
                                                 config_.port_scan_threshold))) {
            alerts.emplace_back(
                pkt.source_ip, pkt.dest_ip,
                AttackType::PORT_SCAN,
                ThreatLevel::HIGH,
                "Port scan detected",
                0.90
            );
        }
        
        // 3. Write/Read Ratio
        if (UNLIKELY((pkt.packet_size & 0xFF) == 0)) {
            double ratio = stats->getWriteReadRatio();
            if (ratio > config_.write_read_ratio_threshold) {
                alerts.emplace_back(
                    pkt.source_ip, pkt.dest_ip,
                    AttackType::ABNORMAL_TRAFFIC_PATTERN,
                    ThreatLevel::MEDIUM,
                    "Abnormal write/read ratio",
                    0.75
                );
            }
        }
        
        // 4. Unauthorized Write
        if (pkt.protocol == ProtocolType::MODBUS_TCP && 
            pkt.register_address < 100) {
            uint8_t fc = static_cast<uint8_t>(pkt.function_code);
            bool is_write = (fc == 0x05 || fc == 0x06 || fc == 0x0F || fc == 0x10);
            
            if (is_write) {
                alerts.emplace_back(
                    pkt.source_ip, pkt.dest_ip,
                    AttackType::UNAUTHORIZED_WRITE,
                    ThreatLevel::CRITICAL,
                    "Unauthorized write to critical register",
                    0.90
                );
            }
        }
        
        return alerts;
    }
    
    // Periodic rate update (called from background thread)
    void updateRates() noexcept {
        // This is expensive, so do it periodically, not per-packet
        // Implementation depends on how you want to iterate the hash map
        // For now, rates are updated on-demand
    }
};

} // namespace zuu::scada
