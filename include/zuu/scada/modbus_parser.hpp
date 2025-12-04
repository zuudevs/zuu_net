#pragma once

#include "scada_types.hpp"
#include <span>
#include <optional>
#include <cstring>

namespace zuu::scada {

    // Modbus TCP Header (7 bytes)
    struct ModbusTCPHeader {
        uint16_t transaction_id;  // For matching request/response
        uint16_t protocol_id;      // Always 0x0000 for Modbus
        uint16_t length;           // Remaining bytes
        uint8_t unit_id;           // Slave address
        
        static constexpr size_t SIZE = 7;
        
        bool isValid() const noexcept {
            return protocol_id == 0 && length > 0 && length < 256;
        }
    } __attribute__((packed));

    // Modbus PDU (Protocol Data Unit)
    struct ModbusPDU {
        uint8_t function_code;
        // Data follows (variable length)
        
        bool isException() const noexcept {
            return (function_code & 0x80) != 0;
        }
        
        ModbusFunctionCode getFunctionCode() const noexcept {
            return static_cast<ModbusFunctionCode>(function_code & 0x7F);
        }
    } __attribute__((packed));

    // Modbus Parser Class
    class ModbusParser {
    private:
        static constexpr size_t MIN_PACKET_SIZE = ModbusTCPHeader::SIZE + 1;  // Header + FC
        static constexpr size_t MAX_PACKET_SIZE = 260;  // Max Modbus TCP size
        
    public:
        // Parse Modbus TCP packet
        static std::optional<PacketMetadata> parse(std::span<const std::byte> data) noexcept {
            if (data.size() < MIN_PACKET_SIZE || data.size() > MAX_PACKET_SIZE) {
                return std::nullopt;
            }
            
            PacketMetadata meta;
            meta.protocol = ProtocolType::MODBUS_TCP;
            meta.packet_size = data.size();
            
            try {
                // Parse MBAP Header (Modbus Application Protocol)
                ModbusTCPHeader header;
                std::memcpy(&header, data.data(), ModbusTCPHeader::SIZE);
                
                // Convert from network byte order (big-endian)
                header.transaction_id = ntohs(header.transaction_id);
                header.protocol_id = ntohs(header.protocol_id);
                header.length = ntohs(header.length);
                
                // Validate header
                if (!header.isValid()) {
                    meta.is_malformed = true;
                    return meta;
                }
                
                meta.transaction_id = header.transaction_id;
                meta.unit_id = header.unit_id;
                
                // Parse PDU
                if (data.size() < ModbusTCPHeader::SIZE + 1) {
                    meta.is_malformed = true;
                    return meta;
                }
                
                ModbusPDU pdu;
                std::memcpy(&pdu, data.data() + ModbusTCPHeader::SIZE, sizeof(pdu.function_code));
                
                meta.has_exception = pdu.isException();
                meta.function_code = pdu.getFunctionCode();
                
                // Parse function-specific data
                if (!meta.has_exception && data.size() >= ModbusTCPHeader::SIZE + 3) {
                    parseData(data.subspan(ModbusTCPHeader::SIZE + 1), meta);
                }
                
                // Determine if request or response
                meta.is_response = isLikelyResponse(meta, data);
                
                return meta;
                
            } catch (...) {
                meta.is_malformed = true;
                return meta;
            }
        }
        
    private:
        static void parseData(std::span<const std::byte> data, PacketMetadata& meta) noexcept {
            try {
                switch (meta.function_code) {
                    case ModbusFunctionCode::READ_COILS:
                    case ModbusFunctionCode::READ_DISCRETE_INPUTS:
                    case ModbusFunctionCode::READ_HOLDING_REGISTERS:
                    case ModbusFunctionCode::READ_INPUT_REGISTERS:
                        if (data.size() >= 4) {
                            // Read: Address(2) + Count(2)
                            uint16_t addr, count;
                            std::memcpy(&addr, data.data(), 2);
                            std::memcpy(&count, data.data() + 2, 2);
                            meta.register_address = ntohs(addr);
                            meta.register_count = ntohs(count);
                        }
                        break;
                        
                    case ModbusFunctionCode::WRITE_SINGLE_COIL:
                    case ModbusFunctionCode::WRITE_SINGLE_REGISTER:
                        if (data.size() >= 2) {
                            // Write single: Address(2) + Value(2)
                            uint16_t addr;
                            std::memcpy(&addr, data.data(), 2);
                            meta.register_address = ntohs(addr);
                            meta.register_count = 1;
                        }
                        break;
                        
                    case ModbusFunctionCode::WRITE_MULTIPLE_COILS:
                    case ModbusFunctionCode::WRITE_MULTIPLE_REGISTERS:
                        if (data.size() >= 5) {
                            // Write multiple: Address(2) + Count(2) + ByteCount(1) + Values
                            uint16_t addr, count;
                            std::memcpy(&addr, data.data(), 2);
                            std::memcpy(&count, data.data() + 2, 2);
                            meta.register_address = ntohs(addr);
                            meta.register_count = ntohs(count);
                        }
                        break;
                        
                    default:
                        break;
                }
            } catch (...) {
                // Silent fail for parsing
            }
        }
        
        static bool isLikelyResponse(const PacketMetadata& meta, std::span<const std::byte> data) noexcept {
            // Exception responses are always responses
            if (meta.has_exception) {
                return true;
            }
            
            // Response packets are usually shorter and have different structures
            switch (meta.function_code) {
                case ModbusFunctionCode::READ_COILS:
                case ModbusFunctionCode::READ_DISCRETE_INPUTS:
                case ModbusFunctionCode::READ_HOLDING_REGISTERS:
                case ModbusFunctionCode::READ_INPUT_REGISTERS:
                    // Response has: FC(1) + ByteCount(1) + Data
                    // Request has: FC(1) + Address(2) + Count(2)
                    return data.size() > ModbusTCPHeader::SIZE + 2;
                    
                case ModbusFunctionCode::WRITE_SINGLE_COIL:
                case ModbusFunctionCode::WRITE_SINGLE_REGISTER:
                    // Echo request, ambiguous - use heuristic
                    return false;
                    
                case ModbusFunctionCode::WRITE_MULTIPLE_COILS:
                case ModbusFunctionCode::WRITE_MULTIPLE_REGISTERS:
                    // Response: FC(1) + Address(2) + Count(2)
                    // Request: FC(1) + Address(2) + Count(2) + ByteCount(1) + Data
                    return data.size() <= ModbusTCPHeader::SIZE + 5;
                    
                default:
                    return false;
            }
        }
        
        static uint16_t ntohs(uint16_t netshort) noexcept {
            #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
            return __builtin_bswap16(netshort);
            #else
            return netshort;
            #endif
        }
    };

    // Quick validation without full parsing
    inline bool isModbusTCP(std::span<const std::byte> data) noexcept {
        if (data.size() < ModbusTCPHeader::SIZE) {
            return false;
        }
        
        // Check protocol ID (bytes 2-3 should be 0x0000)
        return data[2] == std::byte{0} && data[3] == std::byte{0};
    }

    // Extract function code quickly
    inline std::optional<ModbusFunctionCode> extractFunctionCode(std::span<const std::byte> data) noexcept {
        if (data.size() < ModbusTCPHeader::SIZE + 1) {
            return std::nullopt;
        }
        
        uint8_t fc = static_cast<uint8_t>(data[ModbusTCPHeader::SIZE]);
        return static_cast<ModbusFunctionCode>(fc & 0x7F);
    }

} // namespace zuu::scada
