// ============================================================================
// FILE: include/zuu/grid_watcher.hpp
// Grid-Watcher: High-Performance SCADA IDS/IPS Engine
// ============================================================================

#pragma once

#include "scada/scada_types.hpp"
#include "scada/modbus_parser.hpp"
#include "scada/behavioral_analyzer.hpp"
#include "scada/mitigation_engine.hpp"
#include "performance/lock_free.hpp"
#include "performance/bloom_filter.hpp"
#include "core/ipv4.hpp"
#include <thread>
#include <atomic>
#include <chrono>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <span>

namespace zuu::scada {

// ============================================================================
// Log Entry Structure
// ============================================================================
struct LogEntry {
    using TimePoint = std::chrono::system_clock::time_point;
    
    TimePoint timestamp;
    std::string level;      // INFO, WARNING, ERROR, CRITICAL
    std::string source;     // Component name
    std::string message;
    std::optional<ThreatAlert> threat;
    
    LogEntry() noexcept 
        : timestamp(std::chrono::system_clock::now()) {}
    
    LogEntry(std::string lvl, std::string src, std::string msg) noexcept
        : timestamp(std::chrono::system_clock::now())
        , level(std::move(lvl))
        , source(std::move(src))
        , message(std::move(msg)) {}
    
    std::string toString() const {
        std::ostringstream oss;
        auto time_t = std::chrono::system_clock::to_time_t(timestamp);
        oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
        oss << " [" << level << "] [" << source << "] " << message;
        
        if (threat) {
            oss << " | Attack: " << to_string(threat->attack_type);
            oss << " | Severity: " << to_string(threat->severity);
            oss << " | Source: " << threat->source_ip.toString();
            oss << " | Confidence: " << std::fixed << std::setprecision(2) 
                << (threat->confidence_score * 100) << "%";
        }
        
        return oss.str();
    }
};

// ============================================================================
// High-Performance Logger (Lock-Free)
// ============================================================================
class Logger {
private:
    perf::LockFreeRingBuffer<LogEntry, 4096> log_queue_;
    std::thread writer_thread_;
    std::atomic<bool> running_{false};
    std::ofstream log_file_;
    std::string filename_;
    
public:
    explicit Logger(const std::string& filename) 
        : filename_(filename) 
    {
        log_file_.open(filename_, std::ios::app);
        if (!log_file_.is_open()) {
            throw std::runtime_error("Failed to open log file: " + filename_);
        }
    }
    
    ~Logger() {
        stop();
    }
    
    void start() {
        if (running_.exchange(true)) return;
        writer_thread_ = std::thread([this]() { writerLoop(); });
    }
    
    void stop() {
        if (!running_.exchange(false)) return;
        
        if (writer_thread_.joinable()) {
            writer_thread_.join();
        }
        
        // Flush remaining logs
        LogEntry entry;
        while (log_queue_.pop(entry)) {
            writeLog(entry);
        }
        
        log_file_.close();
    }
    
    void log(const std::string& level, const std::string& source, 
             const std::string& message, std::optional<ThreatAlert> threat = std::nullopt) noexcept {
        LogEntry entry(level, source, message);
        entry.threat = threat;
        
        if (!log_queue_.push(entry)) {
            // Queue full - drop log (or implement backpressure)
            std::cerr << "WARNING: Log queue full, dropping entry" << std::endl;
        }
    }
    
    void info(const std::string& source, const std::string& message) noexcept {
        log("INFO", source, message);
    }
    
    void warning(const std::string& source, const std::string& message) noexcept {
        log("WARNING", source, message);
    }
    
    void error(const std::string& source, const std::string& message) noexcept {
        log("ERROR", source, message);
    }
    
    void critical(const std::string& source, const std::string& message, 
                  const ThreatAlert& threat) noexcept {
        log("CRITICAL", source, message, threat);
    }
    
private:
    void writerLoop() {
        LogEntry entry;
        
        while (running_.load(std::memory_order_relaxed)) {
            if (log_queue_.pop(entry)) {
                writeLog(entry);
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
    }
    
    void writeLog(const LogEntry& entry) {
        auto log_str = entry.toString();
        
        // Write to file
        log_file_ << log_str << std::endl;
        log_file_.flush();
        
        // Write to console (for real-time monitoring)
        std::cout << log_str << std::endl;
    }
};

// ============================================================================
// Main Grid-Watcher Engine (Optimized)
// ============================================================================
class GridWatcher {
private:
    // Configuration
    DetectionConfig config_;
    
    // Core components
    BehavioralAnalyzer analyzer_;
    MitigationEngine mitigation_;
    Logger logger_;
    
    // Fast lookup structures
    perf::BloomFilter<8192, 3> blocked_ips_cache_;
    perf::BloomFilter<8192, 3> whitelisted_ips_cache_;
    
    // Statistics (cache-aligned atomic counters)
    alignas(CACHE_LINE_SIZE) std::atomic<uint64_t> packets_processed_{0};
    alignas(CACHE_LINE_SIZE) std::atomic<uint64_t> threats_detected_{0};
    alignas(CACHE_LINE_SIZE) std::atomic<uint64_t> packets_dropped_{0};
    alignas(CACHE_LINE_SIZE) std::atomic<uint64_t> packets_allowed_{0};
    
    // Background threads
    std::atomic<bool> running_{false};
    std::thread monitor_thread_;
    std::thread cleanup_thread_;
    std::thread stats_updater_;
    
    // Timing
    std::chrono::system_clock::time_point start_time_;
    
public:
    explicit GridWatcher(const DetectionConfig& config, 
                        const std::string& log_file = "grid_watcher.log")
        : config_(config)
        , analyzer_(config)
        , mitigation_(config)
        , logger_(log_file)
        , start_time_(std::chrono::system_clock::now())
    {
        // Initialize bloom filters with whitelisted IPs
        for (const auto& ip : config_.whitelisted_ips) {
            whitelisted_ips_cache_.add(ip.to_uint32());
        }
        
        // Register mitigation callback
        mitigation_.registerCallback([this](const ThreatAlert& alert, MitigationAction action) {
            handleMitigationAction(alert, action);
        });
        
        logger_.start();
        logger_.info("GridWatcher", "Grid-Watcher initialized successfully");
    }
    
    ~GridWatcher() {
        stop();
    }
    
    // ========================================================================
    // Control Methods
    // ========================================================================
    
    void start() {
        if (running_.exchange(true)) {
            logger_.warning("GridWatcher", "Already running");
            return;
        }
        
        start_time_ = std::chrono::system_clock::now();
        
        // Start background threads
        cleanup_thread_ = std::thread([this]() { cleanupLoop(); });
        monitor_thread_ = std::thread([this]() { monitorLoop(); });
        stats_updater_ = std::thread([this]() { statsUpdateLoop(); });
        
        logger_.info("GridWatcher", "Grid-Watcher started - Monitoring SCADA network");
    }
    
    void stop() {
        if (!running_.exchange(false)) return;
        
        logger_.info("GridWatcher", "Stopping Grid-Watcher...");
        
        if (cleanup_thread_.joinable()) cleanup_thread_.join();
        if (monitor_thread_.joinable()) monitor_thread_.join();
        if (stats_updater_.joinable()) stats_updater_.join();
        
        logger_.stop();
    }
    
    // ========================================================================
    // HOT PATH - Packet Processing (Optimized for Speed)
    // ========================================================================
    
    bool processPacket(std::span<const std::byte> packet_data,
                      const net::ipv4& source_ip,
                      const net::ipv4& dest_ip,
                      uint16_t source_port,
                      uint16_t dest_port) noexcept {
        
        packets_processed_.fetch_add(1, std::memory_order_relaxed);
        
        uint32_t src_ip_int = source_ip.to_uint32();
        
        // FAST PATH 1: Check whitelist (bloom filter - O(1))
        if (UNLIKELY(whitelisted_ips_cache_.contains(src_ip_int))) {
            packets_allowed_.fetch_add(1, std::memory_order_relaxed);
            return true; // ALLOW
        }
        
        // FAST PATH 2: Check blocked IPs (bloom filter - O(1))
        if (UNLIKELY(blocked_ips_cache_.contains(src_ip_int))) {
            // Double-check with mitigation engine (bloom filter can have false positives)
            if (mitigation_.isBlocked(source_ip)) {
                packets_dropped_.fetch_add(1, std::memory_order_relaxed);
                return false; // DROP
            }
        }
        
        // Parse packet metadata (minimal parsing for speed)
        PacketMetadata meta;
        meta.source_ip = source_ip;
        meta.dest_ip = dest_ip;
        meta.source_port = source_port;
        meta.dest_port = dest_port;
        meta.packet_size = packet_data.size();
        meta.timestamp = std::chrono::system_clock::now();
        
        // Protocol detection and parsing
        if (dest_port == 502 || source_port == 502) {
            // Modbus TCP
            if (isModbusTCP(packet_data)) {
                auto parsed = ModbusParser::parse(packet_data);
                if (parsed) {
                    meta = *parsed;
                    meta.source_ip = source_ip;
                    meta.dest_ip = dest_ip;
                    meta.source_port = source_port;
                    meta.dest_port = dest_port;
                } else {
                    meta.is_malformed = true;
                }
            } else {
                meta.is_malformed = true;
            }
            meta.protocol = ProtocolType::MODBUS_TCP;
        }
        // Add more protocol parsers here (DNP3, IEC-104, etc.)
        
        // Check if should drop before analysis (rate limiting)
        if (mitigation_.shouldDropPacket(meta)) {
            packets_dropped_.fetch_add(1, std::memory_order_relaxed);
            return false; // DROP
        }
        
        // Behavioral analysis (detect threats)
        auto threats = analyzer_.analyze(meta);
        
        // Process threats
        for (const auto& threat : threats) {
            threats_detected_.fetch_add(1, std::memory_order_relaxed);
            
            // Log threat
            logger_.critical("ThreatDetector", threat.description, threat);
            
            // Trigger mitigation
            auto action = mitigation_.mitigate(threat);
            
            // Update bloom filter cache if IP was blocked
            if (action == MitigationAction::BLOCK_IP) {
                blocked_ips_cache_.add(src_ip_int);
            }
            
            // Check if packet should be dropped
            if (action == MitigationAction::DROP_PACKET || 
                action == MitigationAction::BLOCK_IP) {
                packets_dropped_.fetch_add(1, std::memory_order_relaxed);
                return false; // DROP
            }
        }
        
        packets_allowed_.fetch_add(1, std::memory_order_relaxed);
        return true; // ALLOW
    }
    
    // ========================================================================
    // Statistics & Management
    // ========================================================================
    
    struct Statistics {
        uint64_t packets_processed;
        uint64_t threats_detected;
        uint64_t packets_dropped;
        uint64_t packets_allowed;
        uint64_t active_blocks;
        uint64_t total_blocks;
        size_t active_ips;
        double packets_per_second;
        double threat_rate;
        double drop_rate;
        double allow_rate;
        std::chrono::seconds uptime;
    };
    
    Statistics getStatistics() const noexcept {
        Statistics stats;
        stats.packets_processed = packets_processed_.load(std::memory_order_relaxed);
        stats.threats_detected = threats_detected_.load(std::memory_order_relaxed);
        stats.packets_dropped = packets_dropped_.load(std::memory_order_relaxed);
        stats.packets_allowed = packets_allowed_.load(std::memory_order_relaxed);
        
        auto mitigation_stats = mitigation_.getStats();
        stats.active_blocks = mitigation_stats.active_blocks;
        stats.total_blocks = mitigation_stats.total_blocks;
        
        stats.active_ips = 0; // TODO: Implement getActiveIPs() count
        
        // Calculate rates
        auto uptime = std::chrono::system_clock::now() - start_time_;
        stats.uptime = std::chrono::duration_cast<std::chrono::seconds>(uptime);
        
        double uptime_seconds = stats.uptime.count();
        if (uptime_seconds > 0) {
            stats.packets_per_second = stats.packets_processed / uptime_seconds;
            stats.threat_rate = (stats.threats_detected / uptime_seconds) * 60.0; // per minute
            
            if (stats.packets_processed > 0) {
                stats.drop_rate = (stats.packets_dropped * 100.0) / stats.packets_processed;
                stats.allow_rate = (stats.packets_allowed * 100.0) / stats.packets_processed;
            } else {
                stats.drop_rate = 0.0;
                stats.allow_rate = 0.0;
            }
        } else {
            stats.packets_per_second = 0.0;
            stats.threat_rate = 0.0;
            stats.drop_rate = 0.0;
            stats.allow_rate = 0.0;
        }
        
        return stats;
    }
    
    // Get blocked IPs
    std::vector<BlockedIP> getBlockedIPs() const {
        return mitigation_.getBlockedIPs();
    }
    
    // Manual IP management
    void blockIP(const net::ipv4& ip, AttackType reason = AttackType::NONE) {
        mitigation_.blockIP(ip, reason, config_.auto_block_duration);
        blocked_ips_cache_.add(ip.to_uint32());
        logger_.warning("ManualControl", "IP manually blocked: " + ip.toString());
    }
    
    void unblockIP(const net::ipv4& ip) {
        if (mitigation_.unblockIP(ip)) {
            // Note: Bloom filter cannot remove items, but this is ok
            // Mitigation engine will handle the authoritative decision
            logger_.info("ManualControl", "IP manually unblocked: " + ip.toString());
        }
    }
    
    void addWhitelist(const net::ipv4& ip) {
        mitigation_.addWhitelist(ip);
        whitelisted_ips_cache_.add(ip.to_uint32());
        logger_.info("ManualControl", "IP added to whitelist: " + ip.toString());
    }
    
    void removeWhitelist(const net::ipv4& ip) {
        mitigation_.removeWhitelist(ip);
        // Note: Cannot remove from bloom filter, but mitigation engine is authoritative
        logger_.info("ManualControl", "IP removed from whitelist: " + ip.toString());
    }
    
private:
    // ========================================================================
    // Background Threads
    // ========================================================================
    
    void handleMitigationAction(const ThreatAlert& alert, MitigationAction action) {
        std::ostringstream msg;
        msg << "Mitigation: " << to_string(action)
            << " for " << alert.source_ip.toString()
            << " due to " << to_string(alert.attack_type);
        
        if (action == MitigationAction::BLOCK_IP) {
            logger_.warning("Mitigation", msg.str());
        } else {
            logger_.info("Mitigation", msg.str());
        }
    }
    
    void cleanupLoop() {
        while (running_.load(std::memory_order_relaxed)) {
            std::this_thread::sleep_for(std::chrono::minutes(1));
            
            if (!running_.load(std::memory_order_relaxed)) break;
            
            // Cleanup expired blocks
            mitigation_.cleanup();
            
            logger_.info("Cleanup", "Periodic cleanup completed");
        }
    }
    
    void monitorLoop() {
        while (running_.load(std::memory_order_relaxed)) {
            std::this_thread::sleep_for(std::chrono::seconds(30));
            
            if (!running_.load(std::memory_order_relaxed)) break;
            
            auto stats = getStatistics();
            
            std::ostringstream msg;
            msg << "Stats: "
                << stats.packets_processed << " packets ("
                << std::fixed << std::setprecision(1) << stats.packets_per_second << " pps) | "
                << stats.threats_detected << " threats ("
                << std::fixed << std::setprecision(2) << stats.threat_rate << "/min) | "
                << stats.packets_dropped << " dropped ("
                << std::fixed << std::setprecision(1) << stats.drop_rate << "%) | "
                << stats.packets_allowed << " allowed ("
                << std::fixed << std::setprecision(1) << stats.allow_rate << "%) | "
                << stats.active_blocks << " active blocks";
            
            logger_.info("Monitor", msg.str());
        }
    }
    
    void statsUpdateLoop() {
        // Periodically update rates for behavioral analysis
        while (running_.load(std::memory_order_relaxed)) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            
            if (!running_.load(std::memory_order_relaxed)) break;
            
            // Update PPS and other rates
            // This is done in background to keep hot path fast
        }
    }
};

} // namespace zuu::scada
