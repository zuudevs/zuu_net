#pragma once
#include <array>
#include <atomic>
#include <cstdint>

namespace zuu::perf {

// Space-efficient probabilistic set membership test
template<size_t NumBits = 8192, size_t NumHashes = 3>
class BloomFilter {
private:
    static constexpr size_t NUM_WORDS = NumBits / 64;
    std::array<std::atomic<uint64_t>, NUM_WORDS> bits_;
    
    static constexpr uint32_t hash1(uint32_t x) noexcept {
        return (x * 2654435761u) % NumBits;
    }
    
    static constexpr uint32_t hash2(uint32_t x) noexcept {
        return (x * 2246822519u) % NumBits;
    }
    
    static constexpr uint32_t hash3(uint32_t x) noexcept {
        return (x * 3266489917u) % NumBits;
    }
    
    void setBit(size_t bit) noexcept {
        size_t word = bit / 64;
        size_t offset = bit % 64;
        bits_[word].fetch_or(1ULL << offset, std::memory_order_relaxed);
    }
    
    bool testBit(size_t bit) const noexcept {
        size_t word = bit / 64;
        size_t offset = bit % 64;
        return (bits_[word].load(std::memory_order_relaxed) & (1ULL << offset)) != 0;
    }
    
public:
    BloomFilter() {
        clear();
    }
    
    void add(uint32_t value) noexcept {
        setBit(hash1(value));
        setBit(hash2(value));
        setBit(hash3(value));
    }
    
    bool contains(uint32_t value) const noexcept {
        return testBit(hash1(value)) && 
               testBit(hash2(value)) && 
               testBit(hash3(value));
    }
    
    void clear() noexcept {
        for (auto& word : bits_) {
            word.store(0, std::memory_order_relaxed);
        }
    }
};

} // namespace zuu::perf
