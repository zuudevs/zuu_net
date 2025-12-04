#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <new>

namespace zuu::perf {

// Fast hash map with open addressing (fixed size, no allocation)
template<typename Value, size_t Capacity>
class FastHashMap {
private:
    struct Entry {
        uint32_t key;
        alignas(alignof(Value)) std::byte value_storage[sizeof(Value)];
        bool occupied;
        
        Entry() : key(0), occupied(false) {}
        
        Value* value() noexcept {
            return reinterpret_cast<Value*>(value_storage);
        }
        
        const Value* value() const noexcept {
            return reinterpret_cast<const Value*>(value_storage);
        }
    };
    
    std::array<Entry, Capacity> table_;
    size_t size_{0};
    
    static constexpr uint32_t hash(uint32_t key) noexcept {
        // MurmurHash3 finalizer
        key ^= key >> 16;
        key *= 0x85ebca6b;
        key ^= key >> 13;
        key *= 0xc2b2ae35;
        key ^= key >> 16;
        return key % Capacity;
    }
    
public:
    FastHashMap() = default;
    
    ~FastHashMap() {
        for (auto& entry : table_) {
            if (entry.occupied) {
                entry.value()->~Value();
            }
        }
    }
    
    // Non-copyable due to placement new
    FastHashMap(const FastHashMap&) = delete;
    FastHashMap& operator=(const FastHashMap&) = delete;
    
    Value* find(uint32_t key) noexcept {
        uint32_t idx = hash(key);
        
        for (size_t probe = 0; probe < Capacity; ++probe) {
            auto& entry = table_[(idx + probe) % Capacity];
            
            if (!entry.occupied) {
                return nullptr;
            }
            
            if (entry.key == key) {
                return entry.value();
            }
        }
        
        return nullptr;
    }
    
    const Value* find(uint32_t key) const noexcept {
        return const_cast<FastHashMap*>(this)->find(key);
    }
    
    template<typename... Args>
    Value* emplace(uint32_t key, Args&&... args) noexcept {
        if (size_ >= Capacity * 0.75) {
            return nullptr; // Too full (maintain performance)
        }
        
        uint32_t idx = hash(key);
        
        for (size_t probe = 0; probe < Capacity; ++probe) {
            auto& entry = table_[(idx + probe) % Capacity];
            
            if (!entry.occupied) {
                entry.key = key;
                new (entry.value_storage) Value(std::forward<Args>(args)...);
                entry.occupied = true;
                size_++;
                return entry.value();
            }
            
            if (entry.key == key) {
                return entry.value(); // Already exists
            }
        }
        
        return nullptr; // Should not happen if load factor check works
    }
    
    size_t size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }
};

} // namespace zuu::perf
