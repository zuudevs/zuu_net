#pragma once

#include <bit>
#include <concepts>
#include "../meta/concepts.hpp"

namespace zuu::util {
    template <std::integral To, std::endian Order = std::endian::native, std::integral From, std::size_t N>
    requires (meta::less_equal_v<sizeof(From) * N, sizeof(To)>)
    constexpr To from_array(const From(&data)[N]) noexcept {
        To result {0};
        
        for (std::size_t i = 0; i < N; i++) {
            using UFrom = std::make_unsigned_t<From>;
            std::size_t shift_amount;

            if constexpr (Order == std::endian::little) {
                shift_amount = i * sizeof(From) * 8;
            } else {
                shift_amount = (N - 1 - i) * sizeof(From) * 8;
            }

            result |= static_cast<To>(static_cast<UFrom>(data[i])) << shift_amount;
        }
        return result;
    }
}