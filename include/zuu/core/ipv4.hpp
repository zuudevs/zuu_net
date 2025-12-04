#pragma once

#include <algorithm>
#include <format>
#include <ostream>
#include "../meta/arithmetic.hpp"
#include "../utils/convert.hpp"

namespace zuu::net {
	class ipv4 {
	public :
		using elem = uint8_t ;
		using pointer = uint8_t* ;
		using const_pointer = const uint8_t* ;
		using reference = uint8_t* ;
		using const_reference = const uint8_t* ;
		static constexpr std::size_t capacity = 4 ;

	private :
		elem data_[capacity] {} ;

	public :
		constexpr ipv4() noexcept = default ;
		constexpr ipv4(const ipv4&) noexcept = default ;
		constexpr ipv4(ipv4&&) noexcept = default ;
		constexpr ipv4& operator=(const ipv4&) noexcept = default ;
		constexpr ipv4& operator=(ipv4&&) noexcept = default ;
		constexpr bool operator==(const ipv4&) const noexcept = default ;
		constexpr bool operator!=(const ipv4&) const noexcept = default ;
		constexpr ~ipv4() noexcept = default ;

		constexpr explicit ipv4(uint32_t address) noexcept {
			for (std::size_t i = 0; i < capacity; i++) {
                data_[i] = static_cast<uint8_t>(address >> ((capacity - 1 - i) * 8)) ;
            }
		}

		constexpr ipv4(const uint8_t* address, std::size_t len) noexcept { 
			std::copy(
				address, 
				address + std::min(len, capacity), 
				data_
			) ; 
		}

		template <std::size_t N>
		requires (meta::less_equal<N, capacity>::value)
		constexpr ipv4(const uint8_t (&address)[N]) noexcept {
			std::copy(
				address, 
				address + N, 
				data_
			) ; 
		}

		template <std::size_t N>
		requires (meta::less_equal<N, capacity>::value)
		constexpr ipv4& operator=(const uint8_t (&address)[N]) noexcept {
			std::copy(
				address, 
				address + N, 
				data_
			) ; 
			return *this ;
		}

		constexpr auto operator<=>(const ipv4& o) const noexcept { 
			return to_uint32() <=> o.to_uint32() ; 
		}

		constexpr explicit operator uint32_t() const noexcept { return to_uint32() ; }

		constexpr uint32_t to_uint32() const noexcept { 
			return util::from_array<uint32_t, std::endian::big>(data_) ; 
		}

		constexpr const_pointer data() const noexcept { return data_ ; }
		constexpr pointer data() noexcept { return data_ ; }
		constexpr const_pointer begin() const noexcept { return data_ ; }
		constexpr const_pointer end() const noexcept { return data_ + capacity; }
		constexpr pointer begin() noexcept { return data_ ; }
		constexpr pointer end() noexcept { return data_ + capacity; }

		constexpr ipv4 network_address(uint32_t mask) noexcept { return ipv4(to_uint32() & mask) ; }
		constexpr ipv4 broadcast_address(uint32_t mask) noexcept { return ipv4(to_uint32() | ~mask) ; }

		constexpr auto host_range(uint32_t mask) noexcept {
			struct host_range_t {
				ipv4 first ;
				ipv4 last ;
			} ;

			return host_range_t{
				network_address(mask) + 1,
				broadcast_address(mask) - 1
			} ;
		}

		constexpr ipv4 operator|(const ipv4& o) const noexcept {
			return ipv4{to_uint32() | o.to_uint32()} ;
		}

		constexpr ipv4 operator&(const ipv4& o) const noexcept {
			return ipv4{to_uint32() & o.to_uint32()} ;
		}

		constexpr ipv4 operator^(const ipv4& o) const noexcept {
			return ipv4{to_uint32() ^ o.to_uint32()} ;
		}

		constexpr ipv4 operator~() const noexcept {
			return ipv4{~to_uint32()} ;
		}

		constexpr ipv4 operator|(uint32_t o) noexcept {
			return ipv4{to_uint32() | o} ;
		}

		constexpr ipv4 operator&(uint32_t o) noexcept {
			return ipv4{to_uint32() & o} ;
		}

		constexpr ipv4 operator^(uint32_t o) noexcept {
			return ipv4{to_uint32() ^ o} ;
		}

		constexpr ipv4& operator|=(const ipv4& o) noexcept {
			*this = *this | o ;
			return *this ;
		}

		constexpr ipv4& operator&=(const ipv4& o) noexcept {
			*this = *this & o ;
			return *this ;
		}

		constexpr ipv4& operator^=(const ipv4& o) noexcept {
			*this = *this ^ o ;
			return *this ;
		}

		constexpr ipv4& operator|=(uint32_t o) noexcept {
			*this = *this | o ;
			return *this ;
		}

		constexpr ipv4& operator&=(uint32_t o) noexcept {
			*this = *this & o ;
			return *this ;
		}

		constexpr ipv4& operator^=(uint32_t o) noexcept {
			*this = *this ^ o ;
			return *this ;
		}

		template <std::integral Val>
		constexpr ipv4 operator+(Val val) const noexcept {
			return ipv4{to_uint32() + static_cast<uint32_t>(val)} ;
		}

		template <std::integral Val>
		constexpr ipv4 operator-(Val val) const noexcept {
			return ipv4{to_uint32() - static_cast<uint32_t>(val)} ;
		}

		template <std::integral Val>
		constexpr ipv4& operator+=(Val val) noexcept {
			*this = *this + val ;
			return *this ;
		}

		template <std::integral Val>
		constexpr ipv4& operator-=(Val val) noexcept {
			*this = *this - val ;
			return *this ;
		}

		constexpr ipv4& operator++() noexcept {
			*this += 1 ;
			return *this ;
		}

		constexpr ipv4 operator++(int) noexcept {
			auto r = *this ;
			*this += 1 ;
			return r ;
		}

		std::string toString() const noexcept {
			return std::format("{}.{}.{}.{}", data_[0], data_[1], data_[2], data_[3]) ;
		}

		friend inline std::ostream& operator<<(std::ostream& os, const ipv4& address) noexcept {
			for(auto& octet : address) {
				if (&octet != (address.end() - 1)) os << static_cast<uint32_t>(octet) << '.' ;
				else os << static_cast<uint32_t>(octet) ;
			}
			return os ;
		}
	} ;

} // namespace zuu::net
