#pragma once

#include "scada/scada_types.hpp"
#include "scada/modbus_parser.hpp"
#include "scada/behavioral_analyzer.hpp"
#include "scada/mitigation_engine.hpp"
#include "core/tcp_socket.hpp"
#include <thread>
#include <atomic>
#include <queue>
#include <condition_variable>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <iostream>

namespace zuu::scada {

    // Log entry untuk audit trail
    struct LogEntry {
        using TimePoint = std::chrono::system_clock::time_point;
        
        TimePoint timestamp;
        std::string level;  // INFO, WARNING, ERROR, CRITICAL
        std::string source;
        std::string message;
        std::optional<ThreatAlert> threat;
        
        std::string toString() const {
            std::ostringstream oss;
            auto time_t = std::chrono::system_clock::to_time_t(timestamp);
            oss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
            oss << " [" << level << "] ";
            oss << "[" << source << "] ";
            oss << message;
            
            if (threat) {
                oss << " | Attack: " << to_string(threat->attack_type);
                oss << " | Severity: " << to_string(threat->severity);
                oss << " | Source: " << threat->source_ip;
                oss << " | Confidence: " << std::fixed << std::setprecision(2) 
                    << (threat->confidence_score * 100) << "%";
            }
            
            return oss.str();
        }
    };

    // Thread-safe logger
    class Logger {
    private:
        std::queue<LogEntry> log_queue_;
        std::mutex queue_mutex_;
        std::condition_variable cv_;
        std::thread writer_thread_;
        std::atomic<bool> running_{true};
        std::ofstream log_file_;
        
    public:
        explicit Logger(const std::string& filename) {
            log_file_.open(filename, std::ios::app);
            if (!log_file_.is_open()) {
                throw std::runtime_error("Failed to open log file: " + filename);
            }
            
            // Start writer thread
            writer_thread_ = std::thread([this]() { writerLoop(); });
        }
        
        ~Logger() {
            running_ = false;
            cv_.notify_all();
            if (writer_thread_.joinable()) {
                writer_thread_.join();
            }
            log_file_.close();
        }
        
        void log(const std::string& level, const std::string& source, 
                const std::string& message, std::optional<ThreatAlert> threat = std::nullopt) {
            LogEntry entry;
            entry.timestamp = std::chrono::system_clock::now();
            entry.level = level;
            entry.source = source;
            entry.message = message;
            entry.threat = threat;
            
            {
                std::lock_guard lock(queue_mutex_);
                log_queue_.push(std::move(entry));
            }
            cv_.notify_one();
            
            // Also print to console for real-time monitoring
            std::cout << entry.toString() << std::endl;
        }
        
        void info(const std::string& source, const std::string& message) {
            log("INFO", source, message);
        }
        
        void warning(const std::string& source, const std::string& message) {
            log("WARNING", source, message);
        }
        
        void error(const std::string& source, const std::string& message) {
            log("ERROR", source, message);
        }
        
        void critical(const std::string& source, const std::string& message, 
                     const ThreatAlert& threat) {
            log("CRITICAL", source, message, threat);
        }
        
    private:
        void writerLoop() {
            while (running_) {
                std::unique_lock lock(queue_mutex_);
                cv_.wait(lock, [this]() { return !log_queue_.empty() || !running_; });
                
                while (!log_queue_.empty()) {
                    auto entry = log_queue_.front();
                    log_queue_.pop();
                    lock.unlock();
                    
                    // Write to file
                    log_file_ << entry.toString() << std::endl;
                    log_file_.flush();
                    
                    lock.lock();
                }
            }
        }
    };

    // Main Grid-Watcher Engine
    class GridWatcher {
    private:
        DetectionConfig config_;
        BehavioralAnalyzer analyzer_;
        MitigationEngine mitigation_;
        Logger logger_;
        
        std::atomic<bool> running_{false};
        std::atomic<uint64_t> packets_processed_{0};
        std::atomic<uint64_t> threats_detected_{0};
        std::atomic<uint64_t> packets_dropped_{0};
        
        std::thread monitor_thread_;
        std::thread cleanup_thread_;
        
        using TimePoint = std::chrono::system_clock::time_point;
        TimePoint start_time_;
        
    public:
        explicit GridWatcher(const DetectionConfig& config, const std::string& log_file = "grid_watcher.log")
            : config_(config)
            , analyzer_(config)
            , mitigation_(config)
            , logger_(log_file)
            , start_time_(std::chrono::system_clock::now())
        {
            // Register mitigation callback
            mitigation_.registerCallback([this](const ThreatAlert& alert, MitigationAction action) {
                handleMitigationAction(alert, action);
            });
            
            logger_.info("GridWatcher", "Grid-Watcher initialized successfully");
        }
        
        ~GridWatcher() {
            stop();
        }
        
        // Start monitoring
        void start() {
            if (running_) {
                logger_.warning("GridWatcher", "Already running");
                return;
            }
            
            running_ = true;
            start_time_ = std::chrono::system_clock::now();
            
            // Start background threads
            cleanup_thread_ = std::thread([this]() { cleanupLoop(); });
            monitor_thread_ = std::thread([this]() { monitorLoop(); });
            
            logger_.info("GridWatcher", "Grid-Watcher started - Monitoring SCADA network");
        }
        
        // Stop monitoring
        void stop() {
            if (!running_) return;
            
            running_ = false;
            
            if (cleanup_thread_.joinable()) {
                cleanup_thread_.join();
            }
            if (monitor_thread_.joinable()) {
                monitor_thread_.join();
            }
            
            logger_.info("GridWatcher", "Grid-Watcher stopped");
        }
        
        // Process incoming packet (main entry point)
        bool processPacket(std::span<const std::byte> packet_data, 
                          const net::ipv4& source_ip,
                          const net::ipv4& dest_ip,
                          uint16_t source_port,
                          uint16_t dest_port) {
            
            packets_processed_++;
            
            // Parse packet based on protocol
            std::optional<PacketMetadata> metadata;
            
            // Detect protocol by port
            if (dest_port == 502 || source_port == 502) {
                // Modbus TCP
                if (isModbusTCP(packet_data)) {
                    metadata = ModbusParser::parse(packet_data);
                }
            }
            // Add more protocol parsers here (DNP3, IEC-104, etc.)
            
            if (!metadata) {
                // Unknown or malformed packet
                metadata = PacketMetadata();
                metadata->is_malformed = true;
            }
            
            // Fill in network info
            metadata->source_ip = source_ip;
            metadata->dest_ip = dest_ip;
            metadata->source_port = source_port;
            metadata->dest_port = dest_port;
            metadata->packet_size = packet_data.size();
            
            // Check if should drop before analysis
            if (mitigation_.shouldDropPacket(*metadata)) {
                packets_dropped_++;
                return false;  // DROP
            }
            
            // Behavioral analysis
            auto threats = analyzer_.analyze(*metadata);
            
            // Process threats
            for (const auto& threat : threats) {
                threats_detected_++;
                
                // Log threat
                logger_.critical("ThreatDetector", 
                               threat.description,
                               threat);
                
                // Trigger mitigation
                auto action = mitigation_.mitigate(threat);
                
                // Check if packet should be dropped
                if (action == MitigationAction::DROP_PACKET || 
                    action == MitigationAction::BLOCK_IP) {
                    packets_dropped_++;
                    return false;  // DROP
                }
            }
            
            return true;  // ALLOW
        }
        
        // Get real-time statistics
        struct Statistics {
            uint64_t packets_processed;
            uint64_t threats_detected;
            uint64_t packets_dropped;
            uint64_t active_blocks;
            uint64_t total_blocks;
            size_t active_ips;
            double packets_per_second;
            double threat_rate;
            double drop_rate;
            std::chrono::seconds uptime;
        };
        
        Statistics getStatistics() const {
            Statistics stats;
            stats.packets_processed = packets_processed_;
            stats.threats_detected = threats_detected_;
            stats.packets_dropped = packets_dropped_;
            
            auto mitigation_stats = mitigation_.getStats();
            stats.active_blocks = mitigation_stats.active_blocks;
            stats.total_blocks = mitigation_stats.total_blocks;
            
            stats.active_ips = analyzer_.getActiveIPs().size();
            
            // Calculate rates
            auto uptime = std::chrono::system_clock::now() - start_time_;
            stats.uptime = std::chrono::duration_cast<std::chrono::seconds>(uptime);
            
            double uptime_seconds = stats.uptime.count();
            if (uptime_seconds > 0) {
                stats.packets_per_second = packets_processed_ / uptime_seconds;
                stats.threat_rate = (threats_detected_ / uptime_seconds) * 60.0;  // per minute
                stats.drop_rate = (packets_dropped_ * 100.0) / std::max(packets_processed_.load(), 1ULL);
            } else {
                stats.packets_per_second = 0.0;
                stats.threat_rate = 0.0;
                stats.drop_rate = 0.0;
            }
            
            return stats;
        }
        
        // Get active IPs
        std::vector<net::ipv4> getActiveIPs() const {
            return analyzer_.getActiveIPs();
        }
        
        // Get traffic stats for an IP
        std::optional<TrafficStats> getIPStats(const net::ipv4& ip) const {
            return analyzer_.getStats(ip);
        }
        
        // Get blocked IPs
        std::vector<BlockedIP> getBlockedIPs() const {
            return mitigation_.getBlockedIPs();
        }
        
        // Manual controls
        void blockIP(const net::ipv4& ip, AttackType reason = AttackType::NONE) {
            mitigation_.blockIP(ip, reason, config_.auto_block_duration);
            logger_.warning("ManualControl", "IP manually blocked: " + ip.toString());
        }
        
        void unblockIP(const net::ipv4& ip) {
            if (mitigation_.unblockIP(ip)) {
                logger_.info("ManualControl", "IP manually unblocked: " + ip.toString());
            }
        }
        
        void addWhitelist(const net::ipv4& ip) {
            mitigation_.addWhitelist(ip);
            logger_.info("ManualControl", "IP added to whitelist: " + ip.toString());
        }
        
        void removeWhitelist(const net::ipv4& ip) {
            mitigation_.removeWhitelist(ip);
            logger_.info("ManualControl", "IP removed from whitelist: " + ip.toString());
        }
        
    private:
        void handleMitigationAction(const ThreatAlert& alert, MitigationAction action) {
            std::ostringstream msg;
            msg << "Mitigation action taken: " << to_string(action)
                << " for " << alert.source_ip.toString()
                << " due to " << to_string(alert.attack_type);
            
            if (action == MitigationAction::BLOCK_IP) {
                logger_.warning("Mitigation", msg.str());
            } else {
                logger_.info("Mitigation", msg.str());
            }
        }
        
        // Background cleanup loop
        void cleanupLoop() {
            while (running_) {
                std::this_thread::sleep_for(std::chrono::minutes(1));
                
                if (!running_) break;
                
                // Cleanup expired blocks
                mitigation_.cleanup();
                
                // Cleanup old traffic stats
                analyzer_.cleanup(std::chrono::hours(24));
                
                logger_.info("Cleanup", "Periodic cleanup completed");
            }
        }
        
        // Background monitoring loop (print stats)
        void monitorLoop() {
            while (running_) {
                std::this_thread::sleep_for(std::chrono::seconds(30));
                
                if (!running_) break;
                
                auto stats = getStatistics();
                
                std::ostringstream msg;
                msg << "Stats: "
                    << stats.packets_processed << " packets ("
                    << std::fixed << std::setprecision(1) << stats.packets_per_second << " pps) | "
                    << stats.threats_detected << " threats ("
                    << std::fixed << std::setprecision(2) << stats.threat_rate << "/min) | "
                    << stats.packets_dropped << " dropped ("
                    << std::fixed << std::setprecision(1) << stats.drop_rate << "%) | "
                    << stats.active_blocks << " active blocks | "
                    << stats.active_ips << " active IPs";
                
                logger_.info("Monitor", msg.str());
            }
        }
    };

} // namespace zuu::scada