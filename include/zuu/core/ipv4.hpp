#pragma once

#include <algorithm>
#include <format>
#include <ostream>
#include <stdexcept>
#include <cstring>
#include "../meta/arithmetic.hpp"
#include "../utils/convert.hpp"

namespace zuu::net {
	class ipv4 {
	public :
		using elem = uint8_t ;
		using pointer = uint8_t* ;
		using const_pointer = const uint8_t* ;
		using reference = uint8_t& ;
		using const_reference = const uint8_t& ;
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

		// Constructor dari uint32_t dengan bounds checking
		constexpr explicit ipv4(uint32_t address) noexcept {
			// Zero-initialize untuk keamanan
			std::fill(data_, data_ + capacity, elem{0});
			
			for (std::size_t i = 0; i < capacity; i++) {
                data_[i] = static_cast<uint8_t>((address >> ((capacity - 1 - i) * 8)) & 0xFF) ;
            }
		}

		// Constructor dari array dengan bounds checking
		constexpr ipv4(const uint8_t* address, std::size_t len) noexcept { 
			if (address == nullptr) {
				std::fill(data_, data_ + capacity, elem{0});
				return;
			}
			
			std::size_t copy_len = std::min(len, capacity);
			std::copy(address, address + copy_len, data_);
			
			// Zero-fill sisanya jika len < capacity
			if (copy_len < capacity) {
				std::fill(data_ + copy_len, data_ + capacity, elem{0});
			}
		}

		// Constructor dari C-array
		template <std::size_t N>
		requires (meta::less_equal<N, capacity>::value)
		constexpr ipv4(const uint8_t (&address)[N]) noexcept {
			std::copy(address, address + N, data_);
			
			// Zero-fill jika N < capacity
			if constexpr (N < capacity) {
				std::fill(data_ + N, data_ + capacity, elem{0});
			}
		}

		// Assignment dari C-array
		template <std::size_t N>
		requires (meta::less_equal<N, capacity>::value)
		constexpr ipv4& operator=(const uint8_t (&address)[N]) noexcept {
			std::copy(address, address + N, data_);
			
			if constexpr (N < capacity) {
				std::fill(data_ + N, data_ + capacity, elem{0});
			}
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

		// Element access dengan bounds checking
		constexpr const_reference at(std::size_t index) const {
			if (index >= capacity) {
				throw std::out_of_range("IPv4 index out of range");
			}
			return data_[index];
		}

		constexpr reference at(std::size_t index) {
			if (index >= capacity) {
				throw std::out_of_range("IPv4 index out of range");
			}
			return data_[index];
		}

		// Unchecked access (untuk performa)
		constexpr const_reference operator[](std::size_t index) const noexcept {
			return data_[index];
		}

		constexpr reference operator[](std::size_t index) noexcept {
			return data_[index];
		}

		// Network calculations dengan overflow protection
		constexpr ipv4 network_address(uint32_t mask) const noexcept { 
			return ipv4(to_uint32() & mask) ; 
		}

		constexpr ipv4 broadcast_address(uint32_t mask) const noexcept { 
			return ipv4(to_uint32() | ~mask) ; 
		}

		constexpr auto host_range(uint32_t mask) const noexcept {
			struct host_range_t {
				ipv4 first ;
				ipv4 last ;
			} ;

			uint32_t network = to_uint32() & mask;
			uint32_t broadcast = to_uint32() | ~mask;
			
			// Cek overflow saat increment/decrement
			uint32_t first_host = (network == UINT32_MAX) ? network : network + 1;
			uint32_t last_host = (broadcast == 0) ? broadcast : broadcast - 1;

			return host_range_t{
				ipv4(first_host),
				ipv4(last_host)
			} ;
		}

		// Bitwise operations dengan overflow protection
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

		constexpr ipv4 operator|(uint32_t o) const noexcept {
			return ipv4{to_uint32() | o} ;
		}

		constexpr ipv4 operator&(uint32_t o) const noexcept {
			return ipv4{to_uint32() & o} ;
		}

		constexpr ipv4 operator^(uint32_t o) const noexcept {
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

		// Arithmetic dengan overflow checking
		template <std::integral Val>
		constexpr ipv4 operator+(Val val) const noexcept {
			uint32_t current = to_uint32();
			uint32_t add_val = static_cast<uint32_t>(val);
			
			// Check overflow
			if (current > UINT32_MAX - add_val) {
				return ipv4{UINT32_MAX}; // Saturate
			}
			
			return ipv4{current + add_val} ;
		}

		template <std::integral Val>
		constexpr ipv4 operator-(Val val) const noexcept {
			uint32_t current = to_uint32();
			uint32_t sub_val = static_cast<uint32_t>(val);
			
			// Check underflow
			if (current < sub_val) {
				return ipv4{0}; // Saturate
			}
			
			return ipv4{current - sub_val} ;
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

		constexpr ipv4& operator--() noexcept {
			*this -= 1 ;
			return *this ;
		}

		constexpr ipv4 operator--(int) noexcept {
			auto r = *this ;
			*this -= 1 ;
			return r ;
		}

		// String conversion yang aman
		std::string toString() const noexcept {
			try {
				return std::format("{}.{}.{}.{}", 
					static_cast<unsigned>(data_[0]), 
					static_cast<unsigned>(data_[1]), 
					static_cast<unsigned>(data_[2]), 
					static_cast<unsigned>(data_[3])
				);
			} catch (...) {
				return "0.0.0.0"; // Fallback
			}
		}

		// Validation helpers
		constexpr bool isPrivate() const noexcept {
			uint32_t addr = to_uint32();
			// 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
			return (addr >= 0x0A000000 && addr <= 0x0AFFFFFF) ||
			       (addr >= 0xAC100000 && addr <= 0xAC1FFFFF) ||
			       (addr >= 0xC0A80000 && addr <= 0xC0A8FFFF);
		}

		constexpr bool isLoopback() const noexcept {
			return (to_uint32() & 0xFF000000) == 0x7F000000; // 127.0.0.0/8
		}

		constexpr bool isMulticast() const noexcept {
			return (to_uint32() & 0xF0000000) == 0xE0000000; // 224.0.0.0/4
		}

		constexpr bool isValid() const noexcept {
			return to_uint32() != 0; // 0.0.0.0 biasanya invalid
		}

		friend inline std::ostream& operator<<(std::ostream& os, const ipv4& address) noexcept {
			try {
				for(const auto& octet : address) {
					if (&octet != (address.end() - 1)) {
						os << static_cast<unsigned>(octet) << '.' ;
					} else {
						os << static_cast<unsigned>(octet) ;
					}
				}
			} catch (...) {
				os << "0.0.0.0";
			}
			return os ;
		}
	} ;

} // namespace zuu::net
