#include <iostream>
#include <chrono>
#include <exception>
#include "zuu/core/tcp_socket.hpp"

using namespace zuu::net;
using namespace std::chrono_literals;

int main() {
    try {
        std::cout << "=== Secure Socket Demo ===\n\n";

        // 1. Buat socket dengan error handling
        std::cout << "1. Creating socket...\n";
        TcpSocket client;
        
        if (!client.isValid()) {
            std::cerr << "Failed to create socket!\n";
            return 1;
        }
        std::cout << "   ✓ Socket created successfully\n\n";

        // 2. Configure socket untuk keamanan & performa
        std::cout << "2. Configuring socket...\n";
        
        // Set timeout untuk mencegah hang
        client.setTimeout(5s); // 5 detik timeout untuk receive
        client.setTimeout(3s, false); // 3 detik untuk send
        std::cout << "   ✓ Timeout set (5s recv, 3s send)\n";
        
        // Enable TCP_NODELAY untuk low latency
        client.setTcpNoDelay(true);
        std::cout << "   ✓ TCP_NODELAY enabled\n";
        
        // Set buffer size untuk performa
        client.setBufferSize(8192); // 8KB receive buffer
        client.setBufferSize(8192, false); // 8KB send buffer
        std::cout << "   ✓ Buffer size set to 8KB\n\n";

        // 3. Validasi target address
        std::cout << "3. Validating target address...\n";
        ipv4 target_ip({8, 8, 8, 8});
        
        if (!target_ip.isValid()) {
            std::cerr << "Invalid IP address!\n";
            return 1;
        }
        
        if (target_ip.isPrivate()) {
            std::cout << "   ⚠ Warning: Connecting to private IP\n";
        }
        
        std::cout << "   Target: " << target_ip << "\n";
        std::cout << "   Type: " << (target_ip.isLoopback() ? "Loopback" : 
                                      target_ip.isMulticast() ? "Multicast" :
                                      target_ip.isPrivate() ? "Private" : "Public") << "\n\n";

        // 4. Connect dengan error handling
        SocketAddress target(target_ip, 53); // Google DNS
        std::cout << "4. Connecting to " << target << "...\n";
        
        try {
            client.connect(target);
            std::cout << "   ✓ Connection established!\n\n";
        } catch (const std::system_error& e) {
            std::cerr << "   ✗ Connection failed: " << e.what() << "\n";
            std::cerr << "   Error code: " << e.code() << "\n";
            return 1;
        }

        // 5. Get connection info
        std::cout << "5. Connection information:\n";
        auto local_addr = client.getLocalAddress();
        auto remote_addr = client.getRemoteAddress();
        
        if (local_addr) {
            std::cout << "   Local:  " << *local_addr << "\n";
        }
        if (remote_addr) {
            std::cout << "   Remote: " << *remote_addr << "\n";
        }
        std::cout << "\n";

        // 6. Test send dengan validasi
        std::cout << "6. Testing send operation...\n";
        std::string test_message = "Hello, DNS!";
        
        try {
            size_t sent = client.send(test_message);
            std::cout << "   ✓ Sent " << sent << " bytes\n";
            
            // Pastikan semua data terkirim
            if (sent < test_message.size()) {
                std::cout << "   ⚠ Warning: Partial send (" << sent << "/" 
                         << test_message.size() << " bytes)\n";
            }
        } catch (const std::exception& e) {
            std::cerr << "   ✗ Send failed: " << e.what() << "\n";
        }
        std::cout << "\n";

        // 7. Test receive dengan timeout
        std::cout << "7. Testing receive operation (5s timeout)...\n";
        try {
            auto response = client.receive(512); // Max 512 bytes
            
            if (response) {
                std::cout << "   ✓ Received " << response->size() << " bytes\n";
                
                // Sanitize output (jangan print raw binary)
                std::cout << "   Data preview: [";
                for (size_t i = 0; i < std::min(response->size(), size_t{16}); ++i) {
                    std::cout << std::hex << static_cast<int>(static_cast<unsigned char>((*response)[i])) << " ";
                }
                std::cout << std::dec << "...]\n";
            } else {
                std::cout << "   ⚠ No data received (timeout or closed)\n";
            }
        } catch (const std::exception& e) {
            std::cerr << "   ✗ Receive failed: " << e.what() << "\n";
        }
        std::cout << "\n";

        // 8. Cleanup
        std::cout << "8. Closing connection...\n";
        client.close();
        std::cout << "   ✓ Connection closed safely\n\n";

        std::cout << "=== Demo completed successfully ===\n";
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "\n❌ FATAL ERROR: " << e.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "\n❌ UNKNOWN FATAL ERROR\n";
        return 1;
    }
}