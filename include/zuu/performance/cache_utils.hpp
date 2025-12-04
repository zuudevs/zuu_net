#pragma once
#include <cstddef>

namespace zuu::perf {

// Prefetch data into cache
inline void prefetch(const void* addr) noexcept {
#ifdef __GNUC__
    __builtin_prefetch(addr, 0, 3);
#endif
}

// Ensure cache line alignment
template<typename T>
constexpr size_t cache_aligned_size() noexcept {
    constexpr size_t cache_line = 64;
    return ((sizeof(T) + cache_line - 1) / cache_line) * cache_line;
}

} // namespace zuu::perf
