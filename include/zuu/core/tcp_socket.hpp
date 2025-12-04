#pragma once

#include "socket_base.hpp"
#include "socket_address.hpp"
#include <string>
#include <vector>
#include <span>
#include <optional>
#include <algorithm>
#include <cstring>

namespace zuu::net {

    class TcpSocket : public BaseSocket {
    private:
        static constexpr size_t MAX_BUFFER_SIZE = 64 * 1024; // 64KB max
        static constexpr size_t DEFAULT_BUFFER_SIZE = 4096;

    public:
        TcpSocket() {
            create(PF_INET, SOCK_STREAM, IPPROTO_TCP);
        }

        // Connect dengan validasi address
        void connect(const SocketAddress& remoteAddress) {
            if (!isValid()) {
                throw std::runtime_error("Socket not initialized");
            }

            // Validasi port (0 tidak valid untuk connect)
            if (remoteAddress.getPort() == 0) {
                throw std::invalid_argument("Invalid port number: 0");
            }

            sockaddr_in addr{};
            std::memset(&addr, 0, sizeof(addr)); // Zero-initialize untuk keamanan
            
            addr.sin_family = AF_INET;
            addr.sin_port = htons(remoteAddress.getPort());
            addr.sin_addr.s_addr = htonl(remoteAddress.getAddress().to_uint32());

            if (::connect(handle_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
                int error_code;
                #ifdef _WIN32
                error_code = ::WSAGetLastError();
                #else
                error_code = errno;
                #endif
                
                throw std::system_error(
                    error_code,
                    std::system_category(),
                    "Failed to connect to " + remoteAddress.toString()
                );
            }
        }

        // Kirim data dengan bounds checking
        size_t send(std::string_view data) {
            if (data.empty()) {
                return 0;
            }

            if (!isValid()) {
                throw std::runtime_error("Socket not valid");
            }

            // Validasi ukuran data
            if (data.size() > std::numeric_limits<int>::max()) {
                throw std::invalid_argument("Data too large to send");
            }

            int sent = ::send(
                handle_, 
                data.data(), 
                static_cast<int>(data.size()), 
                0
            );
            
            if (sent == SOCKET_ERROR) {
                throw std::system_error(
                    #ifdef _WIN32
                    ::WSAGetLastError(),
                    #else
                    errno,
                    #endif
                    std::system_category(),
                    "Failed to send data"
                );
            }

            return static_cast<size_t>(sent);
        }

        // Kirim binary data dengan type safety
        size_t send(std::span<const std::byte> data) {
            if (data.empty()) {
                return 0;
            }

            if (!isValid()) {
                throw std::runtime_error("Socket not valid");
            }

            if (data.size() > std::numeric_limits<int>::max()) {
                throw std::invalid_argument("Data too large to send");
            }

            int sent = ::send(
                handle_,
                reinterpret_cast<const char*>(data.data()),
                static_cast<int>(data.size()),
                0
            );

            if (sent == SOCKET_ERROR) {
                throw std::system_error(
                    #ifdef _WIN32
                    ::WSAGetLastError(),
                    #else
                    errno,
                    #endif
                    std::system_category(),
                    "Failed to send data"
                );
            }

            return static_cast<size_t>(sent);
        }

        // Send all data (loop hingga semua terkirim)
        void sendAll(std::string_view data) {
            size_t total_sent = 0;
            while (total_sent < data.size()) {
                size_t sent = send(data.substr(total_sent));
                if (sent == 0) {
                    throw std::runtime_error("Connection closed during send");
                }
                total_sent += sent;
            }
        }

        // Receive dengan bounds checking dan buffer overflow protection
        std::optional<std::string> receive(size_t bufferSize = DEFAULT_BUFFER_SIZE) {
            if (!isValid()) {
                throw std::runtime_error("Socket not valid");
            }

            // Batasi ukuran buffer untuk keamanan
            if (bufferSize == 0) {
                throw std::invalid_argument("Buffer size must be greater than 0");
            }
            if (bufferSize > MAX_BUFFER_SIZE) {
                bufferSize = MAX_BUFFER_SIZE;
            }

            // Gunakan vector untuk automatic memory management
            std::vector<char> buffer(bufferSize);
            
            int bytesReceived = ::recv(
                handle_, 
                buffer.data(), 
                static_cast<int>(bufferSize), 
                0
            );
            
            if (bytesReceived == SOCKET_ERROR) {
                #ifdef _WIN32
                int err = ::WSAGetLastError();
                if (err == WSAETIMEDOUT || err == WSAEWOULDBLOCK) {
                    return std::nullopt; // Timeout bukan error
                }
                #else
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return std::nullopt; // Non-blocking, no data
                }
                #endif
                
                throw std::system_error(
                    #ifdef _WIN32
                    err,
                    #else
                    errno,
                    #endif
                    std::system_category(),
                    "Failed to receive data"
                );
            }
            
            if (bytesReceived == 0) {
                return std::nullopt; // Connection closed
            }

            // PENTING: Hanya copy data yang benar-benar diterima
            return std::string(buffer.data(), static_cast<size_t>(bytesReceived));
        }

        // Receive binary data
        std::optional<std::vector<std::byte>> receiveBinary(size_t bufferSize = DEFAULT_BUFFER_SIZE) {
            if (!isValid()) {
                throw std::runtime_error("Socket not valid");
            }

            if (bufferSize == 0) {
                throw std::invalid_argument("Buffer size must be greater than 0");
            }
            if (bufferSize > MAX_BUFFER_SIZE) {
                bufferSize = MAX_BUFFER_SIZE;
            }

            std::vector<std::byte> buffer(bufferSize);
            
            int bytesReceived = ::recv(
                handle_,
                reinterpret_cast<char*>(buffer.data()),
                static_cast<int>(bufferSize),
                0
            );
            
            if (bytesReceived == SOCKET_ERROR) {
                #ifdef _WIN32
                int err = ::WSAGetLastError();
                if (err == WSAETIMEDOUT || err == WSAEWOULDBLOCK) {
                    return std::nullopt;
                }
                #else
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    return std::nullopt;
                }
                #endif
                
                throw std::system_error(
                    #ifdef _WIN32
                    err,
                    #else
                    errno,
                    #endif
                    std::system_category(),
                    "Failed to receive data"
                );
            }
            
            if (bytesReceived == 0) {
                return std::nullopt;
            }

            buffer.resize(static_cast<size_t>(bytesReceived));
            return buffer;
        }

        // Receive hingga delimiter ditemukan (untuk protokol text-based)
        std::optional<std::string> receiveUntil(
            const std::string& delimiter, 
            size_t maxSize = MAX_BUFFER_SIZE
        ) {
            if (!isValid()) {
                throw std::runtime_error("Socket not valid");
            }

            if (delimiter.empty()) {
                throw std::invalid_argument("Delimiter cannot be empty");
            }

            std::string result;
            result.reserve(DEFAULT_BUFFER_SIZE);

            while (result.size() < maxSize) {
                auto data = receive(1); // Read byte by byte (inefficient tapi aman)
                if (!data || data->empty()) {
                    if (result.empty()) {
                        return std::nullopt;
                    }
                    break;
                }

                result += (*data)[0];

                // Check jika sudah ada delimiter
                if (result.size() >= delimiter.size()) {
                    if (result.substr(result.size() - delimiter.size()) == delimiter) {
                        return result;
                    }
                }
            }

            if (result.size() >= maxSize) {
                throw std::runtime_error("Received data exceeded maximum size");
            }

            return result.empty() ? std::nullopt : std::optional<std::string>(result);
        }

        // Get remote address (peer info)
        std::optional<SocketAddress> getRemoteAddress() const {
            if (!isValid()) {
                return std::nullopt;
            }

            sockaddr_in addr{};
            socklen_t len = sizeof(addr);
            
            if (::getpeername(handle_, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
                return std::nullopt;
            }

            return SocketAddress(
                ipv4(ntohl(addr.sin_addr.s_addr)),
                ntohs(addr.sin_port)
            );
        }

        // Get local address
        std::optional<SocketAddress> getLocalAddress() const {
            if (!isValid()) {
                return std::nullopt;
            }

            sockaddr_in addr{};
            socklen_t len = sizeof(addr);
            
            if (::getsockname(handle_, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
                return std::nullopt;
            }

            return SocketAddress(
                ipv4(ntohl(addr.sin_addr.s_addr)),
                ntohs(addr.sin_port)
            );
        }
    };

} // namespace zuu::net
