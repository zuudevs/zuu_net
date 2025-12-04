#pragma once

#include <cstdint>
#include <string>
#include <chrono>
#include "../core/ipv4.hpp"

namespace zuu::scada {

    // SCADA Protocol Types
    enum class ProtocolType : uint8_t {
        MODBUS_TCP = 1,
        DNP3 = 2,
        IEC_104 = 3,
        OPC_UA = 4,
        UNKNOWN = 0xFF
    };

    // Function Codes untuk Modbus (Most Common in SCADA)
    enum class ModbusFunctionCode : uint8_t {
        READ_COILS = 0x01,
        READ_DISCRETE_INPUTS = 0x02,
        READ_HOLDING_REGISTERS = 0x03,
        READ_INPUT_REGISTERS = 0x04,
        WRITE_SINGLE_COIL = 0x05,
        WRITE_SINGLE_REGISTER = 0x06,
        WRITE_MULTIPLE_COILS = 0x0F,
        WRITE_MULTIPLE_REGISTERS = 0x10,
        EXCEPTION = 0x80  // High bit set = exception
    };

    // Severity levels untuk threat
    enum class ThreatLevel : uint8_t {
        INFO = 0,
        LOW = 1,
        MEDIUM = 2,
        HIGH = 3,
        CRITICAL = 4
    };

    // Attack types yang akan dideteksi
    enum class AttackType : uint8_t {
        NONE = 0,
        PORT_SCAN = 1,
        DOS_FLOOD = 2,
        MODBUS_COMMAND_INJECTION = 3,
        UNAUTHORIZED_WRITE = 4,
        ABNORMAL_TRAFFIC_PATTERN = 5,
        SUSPICIOUS_FUNCTION_CODE = 6,
        MALFORMED_PACKET = 7,
        REPLAY_ATTACK = 8,
        MAN_IN_THE_MIDDLE = 9,
        BRUTE_FORCE = 10
    };

    // Packet metadata untuk analisis
    struct PacketMetadata {
        using TimePoint = std::chrono::system_clock::time_point;
        
        TimePoint timestamp;
        net::ipv4 source_ip;
        net::ipv4 dest_ip;
        uint16_t source_port;
        uint16_t dest_port;
        ProtocolType protocol;
        size_t packet_size;
        
        // Modbus specific
        uint16_t transaction_id;
        uint8_t unit_id;
        ModbusFunctionCode function_code;
        uint16_t register_address;
        uint16_t register_count;
        
        // Flags
        bool is_response;
        bool has_exception;
        bool is_malformed;
        
        PacketMetadata() noexcept 
            : timestamp(std::chrono::system_clock::now())
            , source_port(0)
            , dest_port(0)
            , protocol(ProtocolType::UNKNOWN)
            , packet_size(0)
            , transaction_id(0)
            , unit_id(0)
            , function_code(static_cast<ModbusFunctionCode>(0))
            , register_address(0)
            , register_count(0)
            , is_response(false)
            , has_exception(false)
            , is_malformed(false)
        {}
    };

    // Traffic statistics per IP
    struct TrafficStats {
        using TimePoint = std::chrono::system_clock::time_point;
        
        uint64_t packet_count;
        uint64_t byte_count;
        uint64_t request_count;
        uint64_t response_count;
        uint64_t exception_count;
        uint64_t write_operations;
        uint64_t read_operations;
        
        TimePoint first_seen;
        TimePoint last_seen;
        
        // Behavioral metrics
        double packets_per_second;
        double bytes_per_second;
        double avg_packet_size;
        double write_read_ratio;
        
        TrafficStats() noexcept
            : packet_count(0)
            , byte_count(0)
            , request_count(0)
            , response_count(0)
            , exception_count(0)
            , write_operations(0)
            , read_operations(0)
            , first_seen(std::chrono::system_clock::now())
            , last_seen(std::chrono::system_clock::now())
            , packets_per_second(0.0)
            , bytes_per_second(0.0)
            , avg_packet_size(0.0)
            , write_read_ratio(0.0)
        {}
        
        void update(const PacketMetadata& pkt) noexcept {
            packet_count++;
            byte_count += pkt.packet_size;
            last_seen = pkt.timestamp;
            
            if (pkt.is_response) {
                response_count++;
            } else {
                request_count++;
            }
            
            if (pkt.has_exception) {
                exception_count++;
            }
            
            // Count write vs read operations
            switch (pkt.function_code) {
                case ModbusFunctionCode::WRITE_SINGLE_COIL:
                case ModbusFunctionCode::WRITE_SINGLE_REGISTER:
                case ModbusFunctionCode::WRITE_MULTIPLE_COILS:
                case ModbusFunctionCode::WRITE_MULTIPLE_REGISTERS:
                    write_operations++;
                    break;
                case ModbusFunctionCode::READ_COILS:
                case ModbusFunctionCode::READ_DISCRETE_INPUTS:
                case ModbusFunctionCode::READ_HOLDING_REGISTERS:
                case ModbusFunctionCode::READ_INPUT_REGISTERS:
                    read_operations++;
                    break;
                default:
                    break;
            }
            
            // Update metrics
            auto duration = std::chrono::duration<double>(last_seen - first_seen).count();
            if (duration > 0.0) {
                packets_per_second = packet_count / duration;
                bytes_per_second = byte_count / duration;
            }
            
            if (packet_count > 0) {
                avg_packet_size = static_cast<double>(byte_count) / packet_count;
            }
            
            if (read_operations > 0) {
                write_read_ratio = static_cast<double>(write_operations) / read_operations;
            }
        }
    };

    // Threat alert yang akan di-generate
    struct ThreatAlert {
        using TimePoint = std::chrono::system_clock::time_point;
        
        TimePoint timestamp;
        net::ipv4 source_ip;
        net::ipv4 dest_ip;
        AttackType attack_type;
        ThreatLevel severity;
        std::string description;
        double confidence_score;  // 0.0 - 1.0
        bool auto_mitigated;
        
        ThreatAlert() noexcept
            : timestamp(std::chrono::system_clock::now())
            , attack_type(AttackType::NONE)
            , severity(ThreatLevel::INFO)
            , confidence_score(0.0)
            , auto_mitigated(false)
        {}
        
        ThreatAlert(const net::ipv4& src, const net::ipv4& dst, 
                   AttackType type, ThreatLevel level, 
                   std::string_view desc, double confidence) noexcept
            : timestamp(std::chrono::system_clock::now())
            , source_ip(src)
            , dest_ip(dst)
            , attack_type(type)
            , severity(level)
            , description(desc)
            , confidence_score(confidence)
            , auto_mitigated(false)
        {}
    };

    // Configuration untuk detection thresholds
    struct DetectionConfig {
        // Port scan detection
        uint32_t port_scan_threshold = 10;  // ports per second
        std::chrono::seconds port_scan_window{10};
        
        // DoS detection
        uint32_t dos_packet_threshold = 1000;  // packets per second
        uint64_t dos_byte_threshold = 10'000'000;  // 10MB per second
        std::chrono::seconds dos_window{5};
        
        // Behavioral anomaly
        double write_read_ratio_threshold = 5.0;  // Suspicious if > 5:1
        uint32_t exception_rate_threshold = 10;  // exceptions per minute
        double packet_size_deviation_threshold = 3.0;  // std deviations
        
        // Whitelist/Blacklist
        std::vector<net::ipv4> whitelisted_ips;
        std::vector<net::ipv4> blacklisted_ips;
        std::vector<uint16_t> monitored_ports{502, 20000};  // Modbus, DNP3
        
        // Auto-mitigation settings
        bool auto_block_enabled = true;
        std::chrono::minutes auto_block_duration{60};
        uint32_t max_concurrent_blocks = 1000;
        
        DetectionConfig() = default;
    };

    // String conversion helpers
    inline const char* to_string(ProtocolType type) noexcept {
        switch (type) {
            case ProtocolType::MODBUS_TCP: return "MODBUS/TCP";
            case ProtocolType::DNP3: return "DNP3";
            case ProtocolType::IEC_104: return "IEC-104";
            case ProtocolType::OPC_UA: return "OPC-UA";
            default: return "UNKNOWN";
        }
    }

    inline const char* to_string(AttackType type) noexcept {
        switch (type) {
            case AttackType::PORT_SCAN: return "Port Scan";
            case AttackType::DOS_FLOOD: return "DoS Flood";
            case AttackType::MODBUS_COMMAND_INJECTION: return "Modbus Command Injection";
            case AttackType::UNAUTHORIZED_WRITE: return "Unauthorized Write";
            case AttackType::ABNORMAL_TRAFFIC_PATTERN: return "Abnormal Traffic Pattern";
            case AttackType::SUSPICIOUS_FUNCTION_CODE: return "Suspicious Function Code";
            case AttackType::MALFORMED_PACKET: return "Malformed Packet";
            case AttackType::REPLAY_ATTACK: return "Replay Attack";
            case AttackType::MAN_IN_THE_MIDDLE: return "MITM Attack";
            case AttackType::BRUTE_FORCE: return "Brute Force";
            default: return "Unknown";
        }
    }

    inline const char* to_string(ThreatLevel level) noexcept {
        switch (level) {
            case ThreatLevel::INFO: return "INFO";
            case ThreatLevel::LOW: return "LOW";
            case ThreatLevel::MEDIUM: return "MEDIUM";
            case ThreatLevel::HIGH: return "HIGH";
            case ThreatLevel::CRITICAL: return "CRITICAL";
            default: return "UNKNOWN";
        }
    }

    inline const char* to_string(ModbusFunctionCode code) noexcept {
        switch (code) {
            case ModbusFunctionCode::READ_COILS: return "READ_COILS";
            case ModbusFunctionCode::READ_DISCRETE_INPUTS: return "READ_DISCRETE_INPUTS";
            case ModbusFunctionCode::READ_HOLDING_REGISTERS: return "READ_HOLDING_REGISTERS";
            case ModbusFunctionCode::READ_INPUT_REGISTERS: return "READ_INPUT_REGISTERS";
            case ModbusFunctionCode::WRITE_SINGLE_COIL: return "WRITE_SINGLE_COIL";
            case ModbusFunctionCode::WRITE_SINGLE_REGISTER: return "WRITE_SINGLE_REGISTER";
            case ModbusFunctionCode::WRITE_MULTIPLE_COILS: return "WRITE_MULTIPLE_COILS";
            case ModbusFunctionCode::WRITE_MULTIPLE_REGISTERS: return "WRITE_MULTIPLE_REGISTERS";
            case ModbusFunctionCode::EXCEPTION: return "EXCEPTION";
            default: return "UNKNOWN";
        }
    }

} // namespace zuu::scada
