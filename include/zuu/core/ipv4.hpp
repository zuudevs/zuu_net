#pragma once

#include <algorithm>
#include <cstdint>
#include <cstddef>
#include "../meta/concepts.hpp"
#include "../utils/cvt.hpp"
#include "../utils/clamp.hpp"

namespace zuu::net {

	template <std::integral Val>
	[[nodiscard]] inline constexpr uint32_t CreateSubnetMask(Val prefix_length) noexcept {
		uint32_t len = util::clamp{}(static_cast<uint32_t>(prefix_length), 0u, 32u);
		return (len == 0) ? 0 : (0xFFFFFFFF << (32 - len));
	}

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

		constexpr explicit ipv4(uint32_t data) noexcept {
			for (std::size_t i = 0; i < capacity; i++) {
				data_[i] = static_cast<uint8_t>(data >> (i * 8)) ;
			}
		}

		constexpr ipv4(const uint8_t* data, std::size_t len) noexcept { 
			std::copy(
				data, 
				data + std::min(len, capacity), 
				data_
			) ; 
		}

		template <std::size_t N>
		requires (meta::less_equal<N, capacity>::value)
		constexpr ipv4(const uint8_t (&data)[N]) noexcept {
			std::copy(
				data, 
				data + N, 
				data_
			) ; 
		}

		template <std::size_t N>
		requires (meta::less_equal<N, capacity>::value)
		constexpr ipv4& operator=(const uint8_t (&data)[N]) noexcept {
			std::copy(
				data, 
				data + N, 
				data_
			) ; 
			return *this ;
		}

		constexpr auto operator<=>(const ipv4& o) const noexcept {
			return util::from_array<uint32_t>(data_) <=> util::from_array<uint32_t>(o.data_) ;
		}

		constexpr explicit operator uint32_t() const noexcept {
			return util::from_array<uint32_t>(data_) ;
		}

		constexpr uint32_t to_uint32() const noexcept {
			return util::from_array<uint32_t>(data_) ;
		}

		constexpr const_pointer data() const noexcept { return data_ ; }
		constexpr pointer data() noexcept { return data_ ; }
		constexpr const_pointer begin() const noexcept { return data_ ; }
		constexpr const_pointer end() const noexcept { return data_ + capacity; }
		constexpr pointer begin() noexcept { return data_ ; }
		constexpr pointer end() noexcept { return data_ + capacity; }

		constexpr ipv4 network_address(uint32_t mask) noexcept {
			return ipv4(util::from_array<uint32_t>(data_) & mask) ;
		}

		constexpr ipv4 broadcast_address(uint32_t mask) noexcept {
			return ipv4(util::from_array<uint32_t>(data_) | ~mask) ;
		}

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
			return ipv4{
				util::from_array<uint32_t>(data_) | 
				util::from_array<uint32_t>(o.data_)
			} ;
		}

		constexpr ipv4 operator&(const ipv4& o) const noexcept {
			return ipv4{
				util::from_array<uint32_t>(data_) & 
				util::from_array<uint32_t>(o.data_)
			} ;
		}

		constexpr ipv4 operator^(const ipv4& o) const noexcept {
			return ipv4{
				util::from_array<uint32_t>(data_) ^ 
				util::from_array<uint32_t>(o.data_)
			} ;
		}

		constexpr ipv4 operator~() const noexcept {
			return ipv4{
				~util::from_array<uint32_t>(data_)
			} ;
		}

		constexpr ipv4 operator|(uint32_t o) noexcept {
			return ipv4{
				util::from_array<uint32_t>(data_) | o 
			} ;
		}

		constexpr ipv4 operator&(uint32_t o) noexcept {
			return ipv4{
				util::from_array<uint32_t>(data_) & o 
			} ;
		}

		constexpr ipv4 operator^(uint32_t o) noexcept {
			return ipv4{
				util::from_array<uint32_t>(data_) ^ o 
			} ;
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
			return ipv4{
				util::from_array<uint32_t>(data_) + static_cast<uint32_t>(val)
			} ;
		}

		template <std::integral Val>
		constexpr ipv4 operator-(Val val) const noexcept {
			return ipv4{
				util::from_array<uint32_t>(data_) - static_cast<uint32_t>(val)
			} ;
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
	} ;

} // namespace zuu::net
