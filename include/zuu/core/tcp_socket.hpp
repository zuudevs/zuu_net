#pragma once

#include "socket_base.hpp"
#include "socket_address.hpp"
#include <string>
#include <vector>

namespace zuu::net {

    class TcpSocket : public BaseSocket {
    public:
        TcpSocket() {
            // Minta OS bikin socket IPv4 (PF_INET) tipe Stream/TCP (SOCK_STREAM)
            // Fungsi create() ini warisan dari BaseSocket
            create(PF_INET, SOCK_STREAM, IPPROTO_TCP);
        }

        // Fungsi buat nelfon server
        void connect(const SocketAddress& remoteAddress) {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            
            // KONVERSI PENTING!
            // Port & IP harus diubah ke Network Byte Order (Big Endian)
            // htons = Host TO Network Short (buat Port 16-bit)
            // htonl = Host TO Network Long (buat IP 32-bit)
            
            addr.sin_port = htons(remoteAddress.getPort());
            
            // Kita ambil integer IP-nya, lalu pastikan urutan bytenya benar buat jaringan
            addr.sin_addr.s_addr = htonl(remoteAddress.getAddress().to_uint32());

            // Panggil API connect() punya OS
            // Kita cast sockaddr_in* jadi sockaddr* karena itu standar C jadul
            if (::connect(handle_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
                // Kalau gagal (return -1), kita lempar error
                throw std::runtime_error("Gagal connect ke " + 
                    remoteAddress.getAddress().toString() + ":" + 
                    std::to_string(remoteAddress.getPort()));
            }
        }

        // Kirim data string
        void send(const std::string& data) {
            if (data.empty()) return;

            // send() return jumlah byte yang terkirim
            int sent = ::send(handle_, data.c_str(), static_cast<int>(data.size()), 0);
            if (sent == SOCKET_ERROR) {
                throw std::runtime_error("Gagal mengirim data");
            }
        }

        // Terima data (Blocking)
        // Kita butuh buffer sementara
        std::string receive(size_t bufferSize = 4096) {
            std::vector<char> buffer(bufferSize);
            
            int bytesReceived = ::recv(handle_, buffer.data(), static_cast<int>(bufferSize), 0);
            
            if (bytesReceived == SOCKET_ERROR) {
                throw std::runtime_error("Gagal menerima data");
            }
            
            if (bytesReceived == 0) {
                // Return 0 artinya server nutup telepon (Disconnect)
                return {}; 
            }

            return std::string(buffer.data(), bytesReceived);
        }
    };

} // namespace zuu::net