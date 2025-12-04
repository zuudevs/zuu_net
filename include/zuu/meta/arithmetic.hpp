#pragma once 

#include <concepts>
#include <type_traits>

namespace zuu::meta {

	template <typename T>
	concept arithmetic = std::is_arithmetic_v<T> ;

	template <auto, auto>
    struct less : std::false_type {} ;

    template <std::integral auto Vx, std::integral auto Vy>
    struct less<Vx, Vy> : std::bool_constant<(Vx < Vy)> {} ;

	template <std::floating_point auto Vx, std::floating_point auto Vy>
    struct less<Vx, Vy> : std::bool_constant<(Vx < Vy)> {} ;

	template <auto, auto>
    struct less_equal : std::false_type {} ;

    template <std::integral auto Vx, std::integral auto Vy>
    struct less_equal<Vx, Vy> : std::bool_constant<(Vx <= Vy)> {} ;

	template <std::floating_point auto Vx, std::floating_point auto Vy>
    struct less_equal<Vx, Vy> : std::bool_constant<(Vx <= Vy)> {} ;

	template <auto, auto>
    struct greater : std::false_type {} ;

    template <std::integral auto Vx, std::integral auto Vy>
    struct greater<Vx, Vy> : std::bool_constant<(Vx > Vy)> {} ;

	template <std::floating_point auto Vx, std::floating_point auto Vy>
    struct greater<Vx, Vy> : std::bool_constant<(Vx > Vy)> {} ;

	template <auto, auto>
    struct greater_equal : std::false_type {} ;

    template <std::integral auto Vx, std::integral auto Vy>
    struct greater_equal<Vx, Vy> : std::bool_constant<(Vx >= Vy)> {} ;

	template <std::floating_point auto Vx, std::floating_point auto Vy>
    struct greater_equal<Vx, Vy> : std::bool_constant<(Vx >= Vy)> {} ;

    // Variable templates
    template <auto Vx, auto Vy>
    constexpr bool less_v = less<Vx, Vy>::value ;

    template <auto Vx, auto Vy>
    constexpr bool less_equal_v = less_equal<Vx, Vy>::value ;

    template <auto Vx, auto Vy>
    constexpr bool greater_v = greater<Vx, Vy>::value ;

    template <auto Vx, auto Vy>
    constexpr bool greater_equal_v = greater_equal<Vx, Vy>::value;

	template <auto Vx, auto Vy>
	concept less_than = less<Vx, Vy>::value ;

	template <auto Vx, auto Vy>
	concept less_equal_than = less_equal<Vx, Vy>::value ;

	template <auto Vx, auto Vy>
	concept greater_than = greater<Vx, Vy>::value ;

	template <auto Vx, auto Vy>
	concept greater_equal_than = greater_equal<Vx, Vy>::value ;
    
} // namespace zuu::meta
