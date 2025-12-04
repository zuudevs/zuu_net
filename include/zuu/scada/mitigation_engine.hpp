#pragma once

#include "scada_types.hpp"
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <mutex>
#include <shared_mutex>
#include <chrono>
#include <functional>

#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <sys/socket.h>
#endif

namespace zuu::scada {

    // Mitigation action types
    enum class MitigationAction : uint8_t {
        NONE = 0,
        LOG_ONLY = 1,
        RATE_LIMIT = 2,
        BLOCK_IP = 3,
        DROP_PACKET = 4,
        ALERT_ADMIN = 5,
        QUARANTINE = 6
    };

    // Blocked IP entry
    struct BlockedIP {
        using TimePoint = std::chrono::system_clock::time_point;
        
        net::ipv4 ip;
        TimePoint blocked_at;
        TimePoint expires_at;
        AttackType reason;
        uint32_t violation_count;
        bool permanent;
        
        BlockedIP() noexcept
            : blocked_at(std::chrono::system_clock::now())
            , expires_at(blocked_at + std::chrono::hours(1))
            , reason(AttackType::NONE)
            , violation_count(0)
            , permanent(false)
        {}
        
        BlockedIP(const net::ipv4& addr, AttackType attack, std::chrono::minutes duration) noexcept
            : ip(addr)
            , blocked_at(std::chrono::system_clock::now())
            , expires_at(blocked_at + duration)
            , reason(attack)
            , violation_count(1)
            , permanent(false)
        {}
        
        bool isExpired() const noexcept {
            if (permanent) return false;
            return std::chrono::system_clock::now() >= expires_at;
        }
        
        void extend(std::chrono::minutes duration) noexcept {
            violation_count++;
            expires_at = std::chrono::system_clock::now() + duration;
            
            // After 5 violations, make it permanent
            if (violation_count >= 5) {
                permanent = true;
            }
        }
    };

    // Rate limiter per IP
    class RateLimiter {
    private:
        struct RateInfo {
            using TimePoint = std::chrono::system_clock::time_point;
            uint32_t packet_count;
            TimePoint window_start;
        };
        
        std::unordered_map<uint32_t, RateInfo> ip_rates_;
        mutable std::shared_mutex mutex_;
        
        uint32_t max_packets_per_second_;
        
    public:
        explicit RateLimiter(uint32_t max_pps) 
            : max_packets_per_second_(max_pps) 
        {}
        
        bool shouldBlock(const net::ipv4& ip) {
            std::unique_lock lock(mutex_);
            
            uint32_t ip_key = ip.to_uint32();
            auto now = std::chrono::system_clock::now();
            auto& info = ip_rates_[ip_key];
            
            // Reset window if expired
            auto window_duration = std::chrono::duration_cast<std::chrono::seconds>(
                now - info.window_start
            );
            
            if (window_duration.count() >= 1) {
                info.packet_count = 0;
                info.window_start = now;
            }
            
            info.packet_count++;
            
            return info.packet_count > max_packets_per_second_;
        }
        
        void reset(const net::ipv4& ip) {
            std::unique_lock lock(mutex_);
            ip_rates_.erase(ip.to_uint32());
        }
        
        void cleanup(std::chrono::seconds max_age) {
            std::unique_lock lock(mutex_);
            auto now = std::chrono::system_clock::now();
            
            for (auto it = ip_rates_.begin(); it != ip_rates_.end();) {
                auto age = std::chrono::duration_cast<std::chrono::seconds>(
                    now - it->second.window_start
                );
                if (age > max_age) {
                    it = ip_rates_.erase(it);
                } else {
                    ++it;
                }
            }
        }
    };

    // Mitigation callback types
    using MitigationCallback = std::function<void(const ThreatAlert&, MitigationAction)>;
    using PacketFilterCallback = std::function<bool(const PacketMetadata&)>;

    // Main Mitigation Engine
    class MitigationEngine {
    private:
        // Blocked IPs
        std::unordered_map<uint32_t, BlockedIP> blocked_ips_;
        mutable std::shared_mutex blocked_mutex_;
        
        // Whitelisted IPs (never block these)
        std::unordered_set<uint32_t> whitelisted_ips_;
        mutable std::shared_mutex whitelist_mutex_;
        
        // Rate limiter
        RateLimiter rate_limiter_;
        
        // Callbacks for notifications
        std::vector<MitigationCallback> mitigation_callbacks_;
        std::mutex callback_mutex_;
        
        DetectionConfig config_;
        
        // Statistics
        struct Stats {
            uint64_t total_blocks = 0;
            uint64_t total_packets_dropped = 0;
            uint64_t total_rate_limited = 0;
            uint64_t active_blocks = 0;
        } stats_;
        mutable std::shared_mutex stats_mutex_;
        
    public:
        explicit MitigationEngine(const DetectionConfig& config)
            : rate_limiter_(config.dos_packet_threshold)
            , config_(config)
        {
            // Initialize whitelist
            for (const auto& ip : config.whitelisted_ips) {
                addWhitelist(ip);
            }
        }
        
        // Process threat alert and take action
        MitigationAction mitigate(const ThreatAlert& alert) {
            // Check if IP is whitelisted
            if (isWhitelisted(alert.source_ip)) {
                return MitigationAction::LOG_ONLY;
            }
            
            MitigationAction action = determineAction(alert);
            
            // Execute action
            switch (action) {
                case MitigationAction::BLOCK_IP:
                    blockIP(alert.source_ip, alert.attack_type, config_.auto_block_duration);
                    incrementStat([](Stats& s) { s.total_blocks++; s.active_blocks++; });
                    break;
                    
                case MitigationAction::RATE_LIMIT:
                    // Rate limiting is checked per-packet
                    break;
                    
                case MitigationAction::DROP_PACKET:
                    incrementStat([](Stats& s) { s.total_packets_dropped++; });
                    break;
                    
                default:
                    break;
            }
            
            // Notify callbacks
            notifyCallbacks(alert, action);
            
            return action;
        }
        
        // Check if packet should be dropped
        bool shouldDropPacket(const PacketMetadata& packet) {
            // Check if IP is blocked
            if (isBlocked(packet.source_ip)) {
                incrementStat([](Stats& s) { s.total_packets_dropped++; });
                return true;
            }
            
            // Check rate limit
            if (rate_limiter_.shouldBlock(packet.source_ip)) {
                incrementStat([](Stats& s) { s.total_rate_limited++; });
                return true;
            }
            
            return false;
        }
        
        // Manually block an IP
        void blockIP(const net::ipv4& ip, AttackType reason, std::chrono::minutes duration) {
            std::unique_lock lock(blocked_mutex_);
            
            uint32_t ip_key = ip.to_uint32();
            
            // Check if already blocked
            auto it = blocked_ips_.find(ip_key);
            if (it != blocked_ips_.end()) {
                // Extend existing block
                it->second.extend(duration);
            } else {
                // New block
                if (blocked_ips_.size() >= config_.max_concurrent_blocks) {
                    // Remove oldest non-permanent block
                    removeOldestBlock();
                }
                
                blocked_ips_.emplace(ip_key, BlockedIP(ip, reason, duration));
            }
        }
        
        // Unblock an IP
        bool unblockIP(const net::ipv4& ip) {
            std::unique_lock lock(blocked_mutex_);
            
            auto erased = blocked_ips_.erase(ip.to_uint32());
            if (erased > 0) {
                incrementStat([](Stats& s) { s.active_blocks--; });
                rate_limiter_.reset(ip);
                return true;
            }
            return false;
        }
        
        // Check if IP is blocked
        bool isBlocked(const net::ipv4& ip) const {
            std::shared_lock lock(blocked_mutex_);
            auto it = blocked_ips_.find(ip.to_uint32());
            return it != blocked_ips_.end() && !it->second.isExpired();
        }
        
        // Whitelist management
        void addWhitelist(const net::ipv4& ip) {
            std::unique_lock lock(whitelist_mutex_);
            whitelisted_ips_.insert(ip.to_uint32());
        }
        
        void removeWhitelist(const net::ipv4& ip) {
            std::unique_lock lock(whitelist_mutex_);
            whitelisted_ips_.erase(ip.to_uint32());
        }
        
        bool isWhitelisted(const net::ipv4& ip) const {
            std::shared_lock lock(whitelist_mutex_);
            return whitelisted_ips_.count(ip.to_uint32()) > 0;
        }
        
        // Get list of blocked IPs
        std::vector<BlockedIP> getBlockedIPs() const {
            std::shared_lock lock(blocked_mutex_);
            std::vector<BlockedIP> result;
            result.reserve(blocked_ips_.size());
            for (const auto& [_, blocked] : blocked_ips_) {
                if (!blocked.isExpired()) {
                    result.push_back(blocked);
                }
            }
            return result;
        }
        
        // Register callback for mitigation actions
        void registerCallback(MitigationCallback callback) {
            std::lock_guard lock(callback_mutex_);
            mitigation_callbacks_.push_back(std::move(callback));
        }
        
        // Get statistics
        Stats getStats() const {
            std::shared_lock lock(stats_mutex_);
            return stats_;
        }
        
        // Periodic cleanup of expired blocks
        void cleanup() {
            std::unique_lock lock(blocked_mutex_);
            
            for (auto it = blocked_ips_.begin(); it != blocked_ips_.end();) {
                if (it->second.isExpired()) {
                    it = blocked_ips_.erase(it);
                    incrementStat([](Stats& s) { s.active_blocks--; });
                } else {
                    ++it;
                }
            }
            
            rate_limiter_.cleanup(std::chrono::minutes(5));
        }
        
    private:
        MitigationAction determineAction(const ThreatAlert& alert) const {
            // Critical threats get immediate block
            if (alert.severity == ThreatLevel::CRITICAL) {
                return MitigationAction::BLOCK_IP;
            }
            
            // High threats get rate limited first
            if (alert.severity == ThreatLevel::HIGH) {
                switch (alert.attack_type) {
                    case AttackType::DOS_FLOOD:
                    case AttackType::PORT_SCAN:
                        return MitigationAction::BLOCK_IP;
                    default:
                        return MitigationAction::RATE_LIMIT;
                }
            }
            
            // Medium threats get rate limited
            if (alert.severity == ThreatLevel::MEDIUM) {
                return MitigationAction::RATE_LIMIT;
            }
            
            // Low threats only logged
            return MitigationAction::LOG_ONLY;
        }
        
        void notifyCallbacks(const ThreatAlert& alert, MitigationAction action) {
            std::lock_guard lock(callback_mutex_);
            for (const auto& callback : mitigation_callbacks_) {
                try {
                    callback(alert, action);
                } catch (...) {
                    // Silent fail - don't let callback errors crash the engine
                }
            }
        }
        
        void removeOldestBlock() {
            // Find oldest non-permanent block
            auto oldest = blocked_ips_.end();
            for (auto it = blocked_ips_.begin(); it != blocked_ips_.end(); ++it) {
                if (!it->second.permanent) {
                    if (oldest == blocked_ips_.end() || 
                        it->second.blocked_at < oldest->second.blocked_at) {
                        oldest = it;
                    }
                }
            }
            
            if (oldest != blocked_ips_.end()) {
                blocked_ips_.erase(oldest);
                incrementStat([](Stats& s) { s.active_blocks--; });
            }
        }
        
        template<typename Func>
        void incrementStat(Func&& func) {
            std::unique_lock lock(stats_mutex_);
            func(stats_);
        }
    };

    // Helper: Convert mitigation action to string
    inline const char* to_string(MitigationAction action) noexcept {
        switch (action) {
            case MitigationAction::LOG_ONLY: return "LOG_ONLY";
            case MitigationAction::RATE_LIMIT: return "RATE_LIMIT";
            case MitigationAction::BLOCK_IP: return "BLOCK_IP";
            case MitigationAction::DROP_PACKET: return "DROP_PACKET";
            case MitigationAction::ALERT_ADMIN: return "ALERT_ADMIN";
            case MitigationAction::QUARANTINE: return "QUARANTINE";
            default: return "NONE";
        }
    }

} // namespace zuu::scada