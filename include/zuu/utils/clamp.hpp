#pragma once

#include "../meta/concepts.hpp"

namespace zuu::util {

	struct clamp {
		template <meta::arithmetic Val, meta::arithmetic Min, meta::arithmetic Max>
		constexpr auto operator()(Val val, Min min, Max max) const noexcept {
			return (
				val < static_cast<Val>(min) ? 
				static_cast<Val>(min) : (
					val > static_cast<Val>(max) ? 
					static_cast<Val>(max) : val
				)
			) ;
		}

		template <std::unsigned_integral Val, std::unsigned_integral Max>
		constexpr auto operator()(Val val, Max max) const noexcept {
			return (
				val > static_cast<Val>(max) ? 
				static_cast<Val>(max) : val
			) ;
		}
	} ;

} // namespace zuu::util
