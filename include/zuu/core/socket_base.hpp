#pragma once

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    using SocketHandle = SOCKET;
#else
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    using SocketHandle = int;
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
#endif

#include <stdexcept>
#include "socket_address.hpp"

namespace zuu::net {

    // [CLASS PENTING] 
    // Ini SATPAM-nya library kamu. Dia mastiin WSAStartup dipanggil.
    struct Context {
        Context() {
            #ifdef _WIN32
            WSADATA wsaData;
            if (::WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
                throw std::runtime_error("WSAStartup Gagal! Cek linkermu.");
            }
            #endif
        }

        ~Context() {
            #ifdef _WIN32
            ::WSACleanup();
            #endif
        }
    };

    // Base Class untuk semua jenis socket (TCP/UDP)
    class BaseSocket {
    protected:
        SocketHandle handle_ { INVALID_SOCKET };

    public:
        BaseSocket() = default;

        // [RULE NO. 1] Socket TIDAK BOLEH di-copy! 
        // Bayangin 1 gagang telepon dipegang 2 orang, rebutan ngomong nanti.
        BaseSocket(const BaseSocket&) = delete;
        BaseSocket& operator=(const BaseSocket&) = delete;

        // [RULE NO. 2] Socket BOLEH dipindah tangan (Move Semantics)
        BaseSocket(BaseSocket&& other) noexcept : handle_(other.handle_) {
            other.handle_ = INVALID_SOCKET;
        }

        BaseSocket& operator=(BaseSocket&& other) noexcept {
            if (this != &other) {
                close(); // Tutup yang lama dulu kalau ada
                handle_ = other.handle_;
                other.handle_ = INVALID_SOCKET;
            }
            return *this;
        }

        virtual ~BaseSocket() {
            close(); // Pastikan telepon ditutup pas object hancur
        }

        // Fungsi sakral buat nutup koneksi
        void close() {
            if (handle_ != INVALID_SOCKET) {
                #ifdef _WIN32
                ::closesocket(handle_);
                #else
                ::close(handle_);
                #endif
                handle_ = INVALID_SOCKET;
            }
        }

        // Getter buat handle asli (Hati-hati makainya)
        SocketHandle getHandle() const { return handle_; }
        
        // Cek apakah socket ini hidup
        bool isValid() const { return handle_ != INVALID_SOCKET; }
        
        // Operator bool biar bisa di-if: if (socket) { ... }
        explicit operator bool() const { return isValid(); }

    protected:
        // Helper buat bikin socket (TCP/UDP)
        void create(int family, int type, int protocol) {
            // Pastikan Context sudah nyala (WSAStartup)
            static Context ctx; 
            
            close(); // Jaga-jaga kalau ada sisa
            handle_ = ::socket(family, type, protocol);
            
            if (handle_ == INVALID_SOCKET) {
                throw std::runtime_error("Gagal membuat socket dari OS.");
            }
        }
    };

} // namespace zuu::net
