#pragma once

#include "ipv4.hpp"
namespace zuu::net {

	class SocketAddress {
	private :
		uint16_t port_ {} ;
		ipv4 address_ {} ;

	public :
		constexpr SocketAddress() noexcept = default ;
		constexpr SocketAddress(const SocketAddress&) noexcept = default ;
		constexpr SocketAddress(SocketAddress&&) noexcept = default ;
		constexpr SocketAddress& operator=(const SocketAddress&) noexcept = default ;
		constexpr SocketAddress& operator=(SocketAddress&&) noexcept = default ;
		constexpr std::strong_ordering operator<=>(const SocketAddress&) const noexcept = default ;
		constexpr ~SocketAddress() noexcept = default ;

		constexpr SocketAddress(const ipv4& address, uint16_t port) noexcept
		 : port_(port), address_(address) {}

		constexpr const ipv4& getAddress() const noexcept { return address_ ; }
		constexpr ipv4& getAddress() noexcept { return address_ ; }
		constexpr const uint16_t& getPort() const noexcept { return port_ ; }
		constexpr uint16_t& getPort() noexcept { return port_ ; }

		constexpr void setAddress(const ipv4& address) noexcept { address_ = address ; }
		constexpr void setPort(uint16_t port) noexcept { port_ = port ; }

		constexpr std::string toString() const noexcept {
			return std::format("{}:{}", address_.toString(), port_) ;
		}

		friend inline std::ostream& operator<<(std::ostream& os, const SocketAddress& address) noexcept {
			os << address.address_ << ':' << address.port_ ;
			return os ;
		}
	} ;

} // namespace zuu::net
