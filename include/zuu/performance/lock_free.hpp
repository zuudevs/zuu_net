#pragma once

#include <atomic>
#include <array>
#include <cstddef>
#include <optional>

// Compiler hints
#ifdef __GNUC__
#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
#else
#define LIKELY(x)   (x)
#define UNLIKELY(x) (x)
#endif

#define CACHE_LINE_SIZE 64

namespace zuu::perf {

// Lock-free ring buffer (SPSC - Single Producer Single Consumer)
template<typename T, size_t Capacity>
class alignas(CACHE_LINE_SIZE) LockFreeRingBuffer {
private:
    std::array<T, Capacity> buffer_;
    alignas(CACHE_LINE_SIZE) std::atomic<size_t> write_idx_{0};
    alignas(CACHE_LINE_SIZE) std::atomic<size_t> read_idx_{0};
    
public:
    bool push(const T& item) noexcept {
        size_t current_write = write_idx_.load(std::memory_order_relaxed);
        size_t next_write = (current_write + 1) % Capacity;
        
        if (UNLIKELY(next_write == read_idx_.load(std::memory_order_acquire))) {
            return false; // Full
        }
        
        buffer_[current_write] = item;
        write_idx_.store(next_write, std::memory_order_release);
        return true;
    }
    
    bool pop(T& item) noexcept {
        size_t current_read = read_idx_.load(std::memory_order_relaxed);
        
        if (UNLIKELY(current_read == write_idx_.load(std::memory_order_acquire))) {
            return false; // Empty
        }
        
        item = buffer_[current_read];
        read_idx_.store((current_read + 1) % Capacity, std::memory_order_release);
        return true;
    }
    
    bool empty() const noexcept {
        return read_idx_.load(std::memory_order_acquire) == 
               write_idx_.load(std::memory_order_acquire);
    }
    
    size_t size() const noexcept {
        size_t write = write_idx_.load(std::memory_order_acquire);
        size_t read = read_idx_.load(std::memory_order_acquire);
        return (write >= read) ? (write - read) : (Capacity - read + write);
    }
};

// Lock-free stack (for object pooling)
template<typename T, size_t Capacity>
class LockFreeStack {
private:
    std::array<T, Capacity> buffer_;
    std::atomic<size_t> top_{0};
    
public:
    bool push(const T& item) noexcept {
        size_t current = top_.load(std::memory_order_relaxed);
        
        if (UNLIKELY(current >= Capacity)) {
            return false;
        }
        
        buffer_[current] = item;
        top_.store(current + 1, std::memory_order_release);
        return true;
    }
    
    std::optional<T> pop() noexcept {
        size_t current = top_.load(std::memory_order_relaxed);
        
        if (UNLIKELY(current == 0)) {
            return std::nullopt;
        }
        
        top_.store(current - 1, std::memory_order_release);
        return buffer_[current - 1];
    }
};

} // namespace zuu::perf