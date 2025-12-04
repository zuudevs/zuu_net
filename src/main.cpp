// ============================================================================
// FILE: src/main.cpp
// Grid-Watcher Demo & Benchmark
// ============================================================================

#include "zuu/grid_watcher.hpp"
#include <iostream>
#include <iomanip>
#include <random>
#include <csignal>
#include <memory>

using namespace zuu;

// Global instance for signal handler
std::unique_ptr<scada::GridWatcher> g_watcher;

void signalHandler(int signum) {
    std::cout << "\n\n=== Shutting down Grid-Watcher ===\n";
    if (g_watcher) {
        g_watcher->stop();
    }
    exit(signum);
}

// ============================================================================
// Packet Generation Helpers
// ============================================================================

std::vector<std::byte> createModbusPacket(uint16_t transaction_id, 
                                          uint8_t unit_id,
                                          uint8_t function_code, 
                                          uint16_t address, 
                                          uint16_t count) {
    std::vector<std::byte> packet;
    
    // MBAP Header (7 bytes)
    packet.push_back(std::byte(transaction_id >> 8));
    packet.push_back(std::byte(transaction_id & 0xFF));
    packet.push_back(std::byte(0x00));  // Protocol ID (always 0x0000)
    packet.push_back(std::byte(0x00));
    packet.push_back(std::byte(0x00));  // Length MSB
    packet.push_back(std::byte(0x06));  // Length LSB (6 bytes following)
    packet.push_back(std::byte(unit_id));
    
    // PDU (Protocol Data Unit)
    packet.push_back(std::byte(function_code));
    packet.push_back(std::byte(address >> 8));
    packet.push_back(std::byte(address & 0xFF));
    packet.push_back(std::byte(count >> 8));
    packet.push_back(std::byte(count & 0xFF));
    
    return packet;
}

// ============================================================================
// Attack Simulation Scenarios
// ============================================================================

void simulateNormalTraffic(scada::GridWatcher& watcher, int count = 10) {
    std::cout << "\n=== Simulating Normal SCADA Traffic ===\n";
    
    net::ipv4 plc_ip({192, 168, 1, 100});      // PLC
    net::ipv4 scada_master_ip({192, 168, 1, 10}); // SCADA Master
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> addr_dist(100, 1000);  // Normal register range
    std::uniform_int_distribution<> count_dist(1, 10);
    
    for (int i = 0; i < count; ++i) {
        // Normal read operations
        auto packet = createModbusPacket(
            i + 1,                  // Transaction ID
            1,                      // Unit ID
            0x03,                   // Function: Read Holding Registers
            addr_dist(gen),         // Random address
            count_dist(gen)         // Random count
        );
        
        bool allowed = watcher.processPacket(
            packet, 
            scada_master_ip, 
            plc_ip, 
            5000 + i, 
            502
        );
        
        if (!allowed) {
            std::wcout << "  ⚠️  Packet #" << i << " was dropped!\n";
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    std::wcout << "✓ Normal traffic simulation completed\n";
}

void simulatePortScan(scada::GridWatcher& watcher) {
    std::cout << "\n=== Simulating Port Scan Attack ===\n";
    
    net::ipv4 attacker_ip({10, 0, 0, 50});      // External attacker
    net::ipv4 target_ip({192, 168, 1, 100});    // Target PLC
    
    // Rapidly scan multiple ports
    int dropped = 0;
    for (uint16_t port = 500; port < 520; ++port) {
        auto packet = createModbusPacket(1, 1, 0x03, 0, 1);
        
        bool allowed = watcher.processPacket(
            packet, 
            attacker_ip, 
            target_ip, 
            50000, 
            port
        );
        
        if (!allowed) dropped++;
        
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    
    std::wcout << "✓ Port scan simulation completed (" << dropped << " packets dropped)\n";
}

void simulateDoSAttack(scada::GridWatcher& watcher) {
    std::cout << "\n=== Simulating DoS Flood Attack ===\n";
    
    net::ipv4 attacker_ip({10, 0, 0, 66});      // Attacker
    net::ipv4 target_ip({192, 168, 1, 100});    // Target PLC
    
    // Flood with packets (no delay)
    int dropped = 0;
    for (int i = 0; i < 2000; ++i) {
        auto packet = createModbusPacket(i, 1, 0x03, 0, 1);
        
        bool allowed = watcher.processPacket(
            packet, 
            attacker_ip, 
            target_ip, 
            60000, 
            502
        );
        
        if (!allowed) dropped++;
        
        // Minimal delay to simulate flood
        if (i % 100 == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    
    std::wcout << "✓ DoS attack simulation completed (" << dropped << " packets dropped)\n";
}

void simulateUnauthorizedWrite(scada::GridWatcher& watcher) {
    std::cout << "\n=== Simulating Unauthorized Write Attack ===\n";
    
    net::ipv4 attacker_ip({203, 0, 113, 45});   // External attacker
    net::ipv4 plc_ip({192, 168, 1, 100});       // Target PLC
    
    // Try to write to critical registers (0-99)
    int dropped = 0;
    for (int i = 0; i < 10; ++i) {
        auto packet = createModbusPacket(
            100 + i,                // Transaction ID
            1,                      // Unit ID
            0x10,                   // Function: Write Multiple Registers
            i * 10,                 // Critical address (0-90)
            1                       // Count
        );
        
        bool allowed = watcher.processPacket(
            packet, 
            attacker_ip, 
            plc_ip, 
            40000 + i, 
            502
        );
        
        if (!allowed) dropped++;
        
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    
    std::cout << "✓ Unauthorized write simulation completed (" << dropped << " packets dropped)\n";
}

void simulateMalformedPackets(scada::GridWatcher& watcher) {
    std::cout << "\n=== Simulating Malformed Packets ===\n";
    
    net::ipv4 attacker_ip({198, 51, 100, 88});  // Attacker
    net::ipv4 target_ip({192, 168, 1, 100});    // Target PLC
    
    int dropped = 0;
    for (int i = 0; i < 5; ++i) {
        // Create malformed Modbus packet (wrong protocol ID)
        std::vector<std::byte> malformed = {
            std::byte(0x00), std::byte(0x01),  // Transaction ID
            std::byte(0xFF), std::byte(0xFF),  // WRONG Protocol ID (should be 0x0000)
            std::byte(0x00), std::byte(0x06),  // Length
            std::byte(0x01),                   // Unit ID
            std::byte(0x03),                   // Function code
            std::byte(0x00), std::byte(0x00),  // Address
            std::byte(0x00), std::byte(0x01)   // Count
        };
        
        bool allowed = watcher.processPacket(
            malformed, 
            attacker_ip, 
            target_ip, 
            30000 + i, 
            502
        );
        
        if (!allowed) dropped++;
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    std::wcout << "✓ Malformed packets simulation completed (" << dropped << " packets dropped)\n";
}

// ============================================================================
// Statistics Display
// ============================================================================

void printStatistics(const scada::GridWatcher& watcher) {
    std::cout << "\n" << std::string(80, '=') << "\n";
    std::cout << "                     GRID-WATCHER STATISTICS\n";
    std::cout << std::string(80, '=') << "\n";
    
    auto stats = watcher.getStatistics();
    
    std::cout << std::left << std::setw(35) << "Uptime:" 
              << stats.uptime.count() << " seconds\n";
    std::cout << std::left << std::setw(35) << "Packets Processed:" 
              << stats.packets_processed << "\n";
    std::cout << std::left << std::setw(35) << "Packets Per Second:" 
              << std::fixed << std::setprecision(2) << stats.packets_per_second << "\n";
    std::cout << std::left << std::setw(35) << "Packets Allowed:" 
              << stats.packets_allowed << " (" 
              << std::fixed << std::setprecision(1) << stats.allow_rate << "%)\n";
    std::cout << std::left << std::setw(35) << "Packets Dropped:" 
              << stats.packets_dropped << " (" 
              << std::fixed << std::setprecision(1) << stats.drop_rate << "%)\n";
    std::cout << std::left << std::setw(35) << "Threats Detected:" 
              << stats.threats_detected << "\n";
    std::cout << std::left << std::setw(35) << "Threat Rate (per min):" 
              << std::fixed << std::setprecision(2) << stats.threat_rate << "\n";
    std::cout << std::left << std::setw(35) << "Active IP Blocks:" 
              << stats.active_blocks << "\n";
    std::cout << std::left << std::setw(35) << "Total Blocks (lifetime):" 
              << stats.total_blocks << "\n";
    
    std::cout << "\n" << std::string(80, '-') << "\n";
    std::cout << "BLOCKED IPs:\n";
    std::cout << std::string(80, '-') << "\n";
    
    auto blocked = watcher.getBlockedIPs();
    if (blocked.empty()) {
        std::cout << "  (none)\n";
    } else {
        for (const auto& block : blocked) {
            std::cout << "  • " << block.ip.toString()
                      << " - Reason: " << scada::to_string(block.reason)
                      << " - Violations: " << block.violation_count;
            if (block.permanent) {
                std::cout << " [PERMANENT]";
            }
            std::cout << "\n";
        }
    }
    
    std::cout << std::string(80, '=') << "\n\n";
}

// ============================================================================
// Main Function
// ============================================================================

int main() {
    std::wcout << R"(
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                               ║
    ║              GRID-WATCHER: SCADA Security System              ║
    ║        Real-time Monitoring & Mitigation for SCADA Networks   ║
    ║                                                               ║
    ║  • Ultra-Low-Latency Native C++ Implementation                ║
    ║  • Behavioral Analysis & Anomaly Detection                    ║
    ║  • Automated Threat Mitigation                                ║
    ║  • Lock-Free High-Performance Architecture                    ║
    ║                                                               ║
    ╚═══════════════════════════════════════════════════════════════╝
    )" << std::endl;
    
    // Setup signal handler for graceful shutdown
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    try {
        // ====================================================================
        // Configure Detection Parameters
        // ====================================================================
        scada::DetectionConfig config;
        
        // DoS thresholds
        config.dos_packet_threshold = 500;         // 500 packets/sec
        config.dos_byte_threshold = 5'000'000;     // 5 MB/sec
        config.dos_window = std::chrono::seconds(5);
        
        // Port scan detection
        config.port_scan_threshold = 10;           // 10 unique ports
        config.port_scan_window = std::chrono::seconds(10);
        
        // Behavioral anomalies
        config.write_read_ratio_threshold = 3.0;   // 3:1 write/read ratio
        config.exception_rate_threshold = 10;      // 10 exceptions/min
        
        // Auto-mitigation
        config.auto_block_enabled = true;
        config.auto_block_duration = std::chrono::minutes(30);
        config.max_concurrent_blocks = 1000;
        
        // Whitelist trusted SCADA master (won't be blocked)
        config.whitelisted_ips.push_back(net::ipv4({192, 168, 1, 10}));
        
        // Monitored ports
        config.monitored_ports = {502, 20000};  // Modbus, DNP3
        
        // ====================================================================
        // Initialize Grid-Watcher
        // ====================================================================
        std::cout << "Initializing Grid-Watcher...\n";
        g_watcher = std::make_unique<scada::GridWatcher>(
            config, 
            "grid_watcher_demo.log"
        );
        
        std::cout << "Starting Grid-Watcher...\n";
        g_watcher->start();
        
        std::wcout << "\n✓ Grid-Watcher is now monitoring the SCADA network\n";
        std::cout << "  Press Ctrl+C to stop\n\n";
        
        // Wait for initialization
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        // ====================================================================
        // Run Attack Simulation Scenarios
        // ====================================================================
        std::cout << "\n" << std::string(80, '=') << "\n";
        std::cout << "Starting Attack Simulation Scenarios\n";
        std::cout << std::string(80, '=') << "\n";
        
        // Scenario 1: Normal traffic (establish baseline)
        simulateNormalTraffic(*g_watcher, 50);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        printStatistics(*g_watcher);
        
        // Scenario 2: Port scan attack
        simulatePortScan(*g_watcher);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        printStatistics(*g_watcher);
        
        // Scenario 3: DoS flood attack
        simulateDoSAttack(*g_watcher);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        printStatistics(*g_watcher);
        
        // Scenario 4: Unauthorized write attempt
        simulateUnauthorizedWrite(*g_watcher);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        printStatistics(*g_watcher);
        
        // Scenario 5: Malformed packets
        simulateMalformedPackets(*g_watcher);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        printStatistics(*g_watcher);
        
        // Scenario 6: Recovery with normal traffic
        std::cout << "\n=== System Recovery: Normal Traffic Resumed ===\n";
        simulateNormalTraffic(*g_watcher, 30);
        std::this_thread::sleep_for(std::chrono::seconds(2));
        
        // ====================================================================
        // Final Statistics
        // ====================================================================
        std::cout << "\n" << std::string(80, '=') << "\n";
        std::cout << "              FINAL DEMONSTRATION RESULTS\n";
        std::cout << std::string(80, '=') << "\n";
        printStatistics(*g_watcher);
        
        std::wcout << "\n✓ Demonstration completed successfully!\n";
        std::cout << "  Check 'grid_watcher_demo.log' for detailed logs\n";
        std::cout << "\n  Press Ctrl+C to exit or wait 10 seconds...\n";
        
        std::this_thread::sleep_for(std::chrono::seconds(10));
        
        // Graceful shutdown
        g_watcher->stop();
        
    } catch (const std::exception& e) {
        std::wcerr << "\n❌ FATAL ERROR: " << e.what() << "\n";
        return 1;
    }
    
    std::cout << "\n=== Grid-Watcher Shutdown Complete ===\n";
    return 0;
}
