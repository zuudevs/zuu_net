#pragma once

#include "scada_types.hpp"
#include "modbus_parser.hpp"
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <deque>
#include <algorithm>
#include <cmath>
#include <mutex>
#include <shared_mutex>

namespace zuu::scada {

    // Statistical baseline untuk behavioral analysis
    struct BehavioralBaseline {
        double mean_packet_size = 0.0;
        double stddev_packet_size = 0.0;
        double mean_packets_per_second = 0.0;
        double mean_bytes_per_second = 0.0;
        double typical_write_read_ratio = 0.0;
        
        uint32_t sample_count = 0;
        bool is_trained = false;
        
        static constexpr uint32_t MIN_SAMPLES_FOR_TRAINING = 1000;
        
        void update(const TrafficStats& stats) noexcept {
            if (sample_count < MIN_SAMPLES_FOR_TRAINING) {
                // Learning phase - accumulate statistics
                mean_packet_size = (mean_packet_size * sample_count + stats.avg_packet_size) / (sample_count + 1);
                mean_packets_per_second = (mean_packets_per_second * sample_count + stats.packets_per_second) / (sample_count + 1);
                mean_bytes_per_second = (mean_bytes_per_second * sample_count + stats.bytes_per_second) / (sample_count + 1);
                typical_write_read_ratio = (typical_write_read_ratio * sample_count + stats.write_read_ratio) / (sample_count + 1);
                
                sample_count++;
                
                if (sample_count >= MIN_SAMPLES_FOR_TRAINING) {
                    is_trained = true;
                }
            }
        }
        
        // Calculate z-score (how many std deviations from mean)
        double getPacketSizeZScore(double packet_size) const noexcept {
            if (stddev_packet_size <= 0.0) return 0.0;
            return std::abs(packet_size - mean_packet_size) / stddev_packet_size;
        }
    };

    // Time-series sliding window for pattern detection
    template<typename T>
    class SlidingWindow {
    private:
        std::deque<T> window_;
        size_t max_size_;
        mutable std::shared_mutex mutex_;
        
    public:
        explicit SlidingWindow(size_t max_size) : max_size_(max_size) {}
        
        void push(T value) {
            std::unique_lock lock(mutex_);
            window_.push_back(std::move(value));
            if (window_.size() > max_size_) {
                window_.pop_front();
            }
        }
        
        size_t size() const {
            std::shared_lock lock(mutex_);
            return window_.size();
        }
        
        bool empty() const {
            std::shared_lock lock(mutex_);
            return window_.empty();
        }
        
        template<typename Func>
        void forEach(Func&& func) const {
            std::shared_lock lock(mutex_);
            for (const auto& item : window_) {
                func(item);
            }
        }
        
        std::vector<T> snapshot() const {
            std::shared_lock lock(mutex_);
            return std::vector<T>(window_.begin(), window_.end());
        }
        
        void clear() {
            std::unique_lock lock(mutex_);
            window_.clear();
        }
    };

    // Port scan detection using sliding window
    class PortScanDetector {
    private:
        struct PortAccess {
            using TimePoint = std::chrono::system_clock::time_point;
            TimePoint timestamp;
            uint16_t port;
        };
        
        std::unordered_map<uint32_t, SlidingWindow<PortAccess>> ip_port_history_;
        mutable std::shared_mutex mutex_;
        
        static constexpr size_t WINDOW_SIZE = 100;
        
    public:
        PortScanDetector() = default;
        
        bool checkPortScan(const net::ipv4& source_ip, uint16_t port, 
                          const DetectionConfig& config) {
            std::unique_lock lock(mutex_);
            
            uint32_t ip_key = source_ip.to_uint32();
            auto& window = ip_port_history_[ip_key];
            
            if (window.size() == 0) {
                window = SlidingWindow<PortAccess>(WINDOW_SIZE);
            }
            
            auto now = std::chrono::system_clock::now();
            window.push({now, port});
            
            // Count unique ports in time window
            std::unordered_set<uint16_t> unique_ports;
            auto cutoff = now - config.port_scan_window;
            
            window.forEach([&](const PortAccess& access) {
                if (access.timestamp >= cutoff) {
                    unique_ports.insert(access.port);
                }
            });
            
            return unique_ports.size() >= config.port_scan_threshold;
        }
        
        void cleanup(std::chrono::seconds max_age) {
            std::unique_lock lock(mutex_);
            auto now = std::chrono::system_clock::now();
            auto cutoff = now - max_age;
            
            for (auto it = ip_port_history_.begin(); it != ip_port_history_.end();) {
                bool has_recent = false;
                it->second.forEach([&](const PortAccess& access) {
                    if (access.timestamp >= cutoff) {
                        has_recent = true;
                    }
                });
                
                if (!has_recent) {
                    it = ip_port_history_.erase(it);
                } else {
                    ++it;
                }
            }
        }
    };

    // Main Behavioral Analyzer
    class BehavioralAnalyzer {
    private:
        // Per-IP traffic statistics
        std::unordered_map<uint32_t, TrafficStats> ip_stats_;
        std::unordered_map<uint32_t, BehavioralBaseline> ip_baselines_;
        
        // Recent packets for pattern analysis
        SlidingWindow<PacketMetadata> recent_packets_;
        
        // Specialized detectors
        PortScanDetector port_scan_detector_;
        
        // Thread safety
        mutable std::shared_mutex stats_mutex_;
        
        DetectionConfig config_;
        
        static constexpr size_t RECENT_PACKETS_WINDOW = 10000;
        
    public:
        explicit BehavioralAnalyzer(const DetectionConfig& config)
            : recent_packets_(RECENT_PACKETS_WINDOW)
            , config_(config)
        {}
        
        // Analyze packet and return threats
        std::vector<ThreatAlert> analyze(const PacketMetadata& packet) {
            std::vector<ThreatAlert> alerts;
            
            // Update statistics
            updateStats(packet);
            
            // Store recent packet
            recent_packets_.push(packet);
            
            // Run detection algorithms
            checkDoSFlood(packet, alerts);
            checkPortScan(packet, alerts);
            checkAbnormalTraffic(packet, alerts);
            checkSuspiciousFunctionCode(packet, alerts);
            checkMalformedPacket(packet, alerts);
            checkUnauthorizedWrite(packet, alerts);
            
            return alerts;
        }
        
        // Get statistics for an IP
        std::optional<TrafficStats> getStats(const net::ipv4& ip) const {
            std::shared_lock lock(stats_mutex_);
            auto it = ip_stats_.find(ip.to_uint32());
            if (it != ip_stats_.end()) {
                return it->second;
            }
            return std::nullopt;
        }
        
        // Get all active IPs
        std::vector<net::ipv4> getActiveIPs() const {
            std::shared_lock lock(stats_mutex_);
            std::vector<net::ipv4> ips;
            ips.reserve(ip_stats_.size());
            for (const auto& [ip_int, _] : ip_stats_) {
                ips.push_back(net::ipv4(ip_int));
            }
            return ips;
        }
        
        // Periodic cleanup
        void cleanup(std::chrono::minutes max_age) {
            auto now = std::chrono::system_clock::now();
            auto cutoff = now - max_age;
            
            std::unique_lock lock(stats_mutex_);
            for (auto it = ip_stats_.begin(); it != ip_stats_.end();) {
                if (it->second.last_seen < cutoff) {
                    ip_baselines_.erase(it->first);
                    it = ip_stats_.erase(it);
                } else {
                    ++it;
                }
            }
            
            port_scan_detector_.cleanup(std::chrono::duration_cast<std::chrono::seconds>(max_age));
        }
        
    private:
        void updateStats(const PacketMetadata& packet) {
            std::unique_lock lock(stats_mutex_);
            
            uint32_t ip_key = packet.source_ip.to_uint32();
            auto& stats = ip_stats_[ip_key];
            stats.update(packet);
            
            // Update baseline (learning)
            auto& baseline = ip_baselines_[ip_key];
            baseline.update(stats);
        }
        
        void checkDoSFlood(const PacketMetadata& packet, std::vector<ThreatAlert>& alerts) {
            std::shared_lock lock(stats_mutex_);
            auto it = ip_stats_.find(packet.source_ip.to_uint32());
            if (it == ip_stats_.end()) return;
            
            const auto& stats = it->second;
            
            // Check packet rate
            if (stats.packets_per_second > config_.dos_packet_threshold) {
                alerts.emplace_back(
                    packet.source_ip,
                    packet.dest_ip,
                    AttackType::DOS_FLOOD,
                    ThreatLevel::CRITICAL,
                    "Excessive packet rate detected: " + std::to_string(stats.packets_per_second) + " pps",
                    0.95
                );
            }
            
            // Check byte rate
            if (stats.bytes_per_second > config_.dos_byte_threshold) {
                alerts.emplace_back(
                    packet.source_ip,
                    packet.dest_ip,
                    AttackType::DOS_FLOOD,
                    ThreatLevel::CRITICAL,
                    "Excessive bandwidth usage: " + std::to_string(stats.bytes_per_second / 1'000'000.0) + " MB/s",
                    0.95
                );
            }
        }
        
        void checkPortScan(const PacketMetadata& packet, std::vector<ThreatAlert>& alerts) {
            if (port_scan_detector_.checkPortScan(packet.source_ip, packet.dest_port, config_)) {
                alerts.emplace_back(
                    packet.source_ip,
                    packet.dest_ip,
                    AttackType::PORT_SCAN,
                    ThreatLevel::HIGH,
                    "Port scanning activity detected",
                    0.90
                );
            }
        }
        
        void checkAbnormalTraffic(const PacketMetadata& packet, std::vector<ThreatAlert>& alerts) {
            std::shared_lock lock(stats_mutex_);
            
            uint32_t ip_key = packet.source_ip.to_uint32();
            auto baseline_it = ip_baselines_.find(ip_key);
            if (baseline_it == ip_baselines_.end() || !baseline_it->second.is_trained) {
                return;  // Not enough data yet
            }
            
            auto stats_it = ip_stats_.find(ip_key);
            if (stats_it == ip_stats_.end()) return;
            
            const auto& baseline = baseline_it->second;
            const auto& stats = stats_it->second;
            
            // Check write/read ratio anomaly
            if (stats.write_read_ratio > config_.write_read_ratio_threshold &&
                stats.write_read_ratio > baseline.typical_write_read_ratio * 3.0) {
                alerts.emplace_back(
                    packet.source_ip,
                    packet.dest_ip,
                    AttackType::ABNORMAL_TRAFFIC_PATTERN,
                    ThreatLevel::MEDIUM,
                    "Abnormal write/read ratio: " + std::to_string(stats.write_read_ratio),
                    0.75
                );
            }
            
            // Check exception rate
            auto duration = std::chrono::duration<double>(stats.last_seen - stats.first_seen).count();
            if (duration > 60.0) {  // At least 1 minute of data
                double exceptions_per_minute = (stats.exception_count / duration) * 60.0;
                if (exceptions_per_minute > config_.exception_rate_threshold) {
                    alerts.emplace_back(
                        packet.source_ip,
                        packet.dest_ip,
                        AttackType::ABNORMAL_TRAFFIC_PATTERN,
                        ThreatLevel::MEDIUM,
                        "High exception rate: " + std::to_string(exceptions_per_minute) + " per minute",
                        0.80
                    );
                }
            }
        }
        
        void checkSuspiciousFunctionCode(const PacketMetadata& packet, std::vector<ThreatAlert>& alerts) {
            if (packet.protocol != ProtocolType::MODBUS_TCP) return;
            
            // Some function codes are rarely used and could indicate attacks
            uint8_t fc = static_cast<uint8_t>(packet.function_code);
            if (fc > 0x18 && fc < 0x80) {  // Reserved/unused codes
                alerts.emplace_back(
                    packet.source_ip,
                    packet.dest_ip,
                    AttackType::SUSPICIOUS_FUNCTION_CODE,
                    ThreatLevel::MEDIUM,
                    "Suspicious Modbus function code: 0x" + std::to_string(fc),
                    0.70
                );
            }
        }
        
        void checkMalformedPacket(const PacketMetadata& packet, std::vector<ThreatAlert>& alerts) {
            if (packet.is_malformed) {
                alerts.emplace_back(
                    packet.source_ip,
                    packet.dest_ip,
                    AttackType::MALFORMED_PACKET,
                    ThreatLevel::MEDIUM,
                    "Malformed protocol packet detected",
                    0.85
                );
            }
        }
        
        void checkUnauthorizedWrite(const PacketMetadata& packet, std::vector<ThreatAlert>& alerts) {
            if (packet.protocol != ProtocolType::MODBUS_TCP) return;
            
            // Check if this is a write operation
            bool is_write = false;
            switch (packet.function_code) {
                case ModbusFunctionCode::WRITE_SINGLE_COIL:
                case ModbusFunctionCode::WRITE_SINGLE_REGISTER:
                case ModbusFunctionCode::WRITE_MULTIPLE_COILS:
                case ModbusFunctionCode::WRITE_MULTIPLE_REGISTERS:
                    is_write = true;
                    break;
                default:
                    break;
            }
            
            if (!is_write) return;
            
            // Check if IP is in whitelist
            bool is_whitelisted = std::find(
                config_.whitelisted_ips.begin(),
                config_.whitelisted_ips.end(),
                packet.source_ip
            ) != config_.whitelisted_ips.end();
            
            if (!is_whitelisted) {
                // Check if writing to critical registers (example: 0-99 are critical)
                if (packet.register_address < 100) {
                    alerts.emplace_back(
                        packet.source_ip,
                        packet.dest_ip,
                        AttackType::UNAUTHORIZED_WRITE,
                        ThreatLevel::CRITICAL,
                        "Unauthorized write to critical register " + std::to_string(packet.register_address),
                        0.90
                    );
                }
            }
        }
    };

} // namespace zuu::scada
