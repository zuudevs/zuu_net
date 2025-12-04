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
    #include <fcntl.h>
    #include <sys/time.h>
    using SocketHandle = int;
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
#endif

#ifdef max 
	#undef max
#endif
#ifdef min 
	#undef min
#endif

#include <stdexcept>
#include <chrono>
#include <system_error>
#include <limits>
#include "socket_address.hpp"

namespace zuu::net {

    // Thread-safe Context dengan reference counting
    struct Context {
        Context() {
            #ifdef _WIN32
            WSADATA wsaData;
            if (::WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
                throw std::system_error(
                    ::WSAGetLastError(), 
                    std::system_category(),
                    "WSAStartup failed"
                );
            }
            #endif
        }

        ~Context() noexcept {
            #ifdef _WIN32
            ::WSACleanup();
            #endif
        }

        // Prevent copying
        Context(const Context&) = delete;
        Context& operator=(const Context&) = delete;
    };

    // Error handling yang lebih baik
    inline std::string getLastSocketError() {
        #ifdef _WIN32
        return std::system_category().message(::WSAGetLastError());
        #else
        return std::system_category().message(errno);
        #endif
    }

    // Base Class untuk semua jenis socket (TCP/UDP)
    class BaseSocket {
    protected:
        SocketHandle handle_ { INVALID_SOCKET };
        bool blocking_ { true };

    public:
        BaseSocket() = default;

        // Socket TIDAK BOLEH di-copy
        BaseSocket(const BaseSocket&) = delete;
        BaseSocket& operator=(const BaseSocket&) = delete;

        // Move semantics yang aman
        BaseSocket(BaseSocket&& other) noexcept 
            : handle_(other.handle_)
            , blocking_(other.blocking_) 
        {
            other.handle_ = INVALID_SOCKET;
        }

        BaseSocket& operator=(BaseSocket&& other) noexcept {
            if (this != &other) {
                close();
                handle_ = other.handle_;
                blocking_ = other.blocking_;
                other.handle_ = INVALID_SOCKET;
            }
            return *this;
        }

        virtual ~BaseSocket() noexcept {
            close();
        }

        // Tutup koneksi dengan proper error handling
        void close() noexcept {
            if (handle_ != INVALID_SOCKET) {
                #ifdef _WIN32
                ::shutdown(handle_, SD_BOTH); // Graceful shutdown
                ::closesocket(handle_);
                #else
                ::shutdown(handle_, SHUT_RDWR);
                ::close(handle_);
                #endif
                handle_ = INVALID_SOCKET;
            }
        }

        SocketHandle getHandle() const noexcept { return handle_; }
        bool isValid() const noexcept { return handle_ != INVALID_SOCKET; }
        explicit operator bool() const noexcept { return isValid(); }

        // Set socket ke non-blocking mode (PENTING untuk performa)
        void setNonBlocking(bool enable) {
            if (!isValid()) {
                throw std::runtime_error("Socket not initialized");
            }

            #ifdef _WIN32
            u_long mode = enable ? 1 : 0;
            if (::ioctlsocket(handle_, FIONBIO, &mode) != 0) {
                throw std::system_error(
                    ::WSAGetLastError(),
                    std::system_category(),
                    "Failed to set non-blocking mode"
                );
            }
            #else
            int flags = ::fcntl(handle_, F_GETFL, 0);
            if (flags == -1) {
                throw std::system_error(
                    errno,
                    std::system_category(),
                    "Failed to get socket flags"
                );
            }
            
            flags = enable ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
            if (::fcntl(handle_, F_SETFL, flags) == -1) {
                throw std::system_error(
                    errno,
                    std::system_category(),
                    "Failed to set non-blocking mode"
                );
            }
            #endif

            blocking_ = !enable;
        }

        // Set timeout untuk operasi (CRITICAL untuk keamanan)
        void setTimeout(std::chrono::milliseconds timeout, bool receive = true) {
            if (!isValid()) {
                throw std::runtime_error("Socket not initialized");
            }

            #ifdef _WIN32
            DWORD ms = static_cast<DWORD>(timeout.count());
            int optname = receive ? SO_RCVTIMEO : SO_SNDTIMEO;
            if (::setsockopt(handle_, SOL_SOCKET, optname, 
                           reinterpret_cast<const char*>(&ms), sizeof(ms)) != 0) {
                throw std::system_error(
                    ::WSAGetLastError(),
                    std::system_category(),
                    "Failed to set timeout"
                );
            }
            #else
            struct timeval tv;
            tv.tv_sec = timeout.count() / 1000;
            tv.tv_usec = (timeout.count() % 1000) * 1000;
            int optname = receive ? SO_RCVTIMEO : SO_SNDTIMEO;
            if (::setsockopt(handle_, SOL_SOCKET, optname, &tv, sizeof(tv)) != 0) {
                throw std::system_error(
                    errno,
                    std::system_category(),
                    "Failed to set timeout"
                );
            }
            #endif
        }

        // Enable TCP_NODELAY untuk mengurangi latency
        void setTcpNoDelay(bool enable) {
            if (!isValid()) {
                throw std::runtime_error("Socket not initialized");
            }

            int flag = enable ? 1 : 0;
            if (::setsockopt(handle_, IPPROTO_TCP, TCP_NODELAY,
                           reinterpret_cast<const char*>(&flag), sizeof(flag)) != 0) {
                throw std::system_error(
                    #ifdef _WIN32
                    ::WSAGetLastError(),
                    #else
                    errno,
                    #endif
                    std::system_category(),
                    "Failed to set TCP_NODELAY"
                );
            }
        }

        // Set buffer size untuk performa
        void setBufferSize(size_t size, bool receive = true) {
            if (!isValid()) {
                throw std::runtime_error("Socket not initialized");
            }

            // Validasi ukuran buffer
            if (size == 0 || size > std::numeric_limits<int>::max()) {
                throw std::invalid_argument("Invalid buffer size");
            }

            int bufsize = static_cast<int>(size);
            int optname = receive ? SO_RCVBUF : SO_SNDBUF;
            
            if (::setsockopt(handle_, SOL_SOCKET, optname,
                           reinterpret_cast<const char*>(&bufsize), sizeof(bufsize)) != 0) {
                throw std::system_error(
                    #ifdef _WIN32
                    ::WSAGetLastError(),
                    #else
                    errno,
                    #endif
                    std::system_category(),
                    "Failed to set buffer size"
                );
            }
        }

        // Reuse address (berguna saat development)
        void setReuseAddress(bool enable) {
            if (!isValid()) {
                throw std::runtime_error("Socket not initialized");
            }

            int flag = enable ? 1 : 0;
            if (::setsockopt(handle_, SOL_SOCKET, SO_REUSEADDR,
                           reinterpret_cast<const char*>(&flag), sizeof(flag)) != 0) {
                throw std::system_error(
                    #ifdef _WIN32
                    ::WSAGetLastError(),
                    #else
                    errno,
                    #endif
                    std::system_category(),
                    "Failed to set SO_REUSEADDR"
                );
            }
        }

    protected:
        void create(int family, int type, int protocol) {
            static Context ctx;
            
            close();
            handle_ = ::socket(family, type, protocol);
            
            if (handle_ == INVALID_SOCKET) {
                throw std::system_error(
                    #ifdef _WIN32
                    ::WSAGetLastError(),
                    #else
                    errno,
                    #endif
                    std::system_category(),
                    "Failed to create socket"
                );
            }

            // Default settings untuk keamanan
            try {
                setTimeout(std::chrono::seconds(30)); // 30s timeout default
                setTcpNoDelay(true); // Low latency
            } catch (...) {
                close();
                throw;
            }
        }
    };

} // namespace zuu::net
