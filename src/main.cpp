#include <iostream>
#include "zuu/core/tcp_socket.hpp" // Sesuaikan path include-nya

using namespace zuu::net ;

int main() {
    try {
        std::cout << "Membuat socket...\n";
        zuu::net::TcpSocket client;

        // Kita coba connect ke Google DNS (8.8.8.8:53)
        // 8.8.8.8 = 8, 8, 8, 8
        zuu::net::SocketAddress target(ipv4({8, 8, 8, 8}), 53);

        std::cout << "Mencoba connect ke " << target << "...\n";
        client.connect(target);

        std::cout << "BERHASIL! Koneksi terhubung.\n";
        std::cout << "Socket otomatis ditutup saat keluar scope.\n";
        
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << "\n";
    }

    return 0;
}