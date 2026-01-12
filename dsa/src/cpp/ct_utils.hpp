/**
 * Shared Constant-Time Utilities for Side-Channel Resistance
 *
 * These functions are designed to execute in constant time regardless of
 * input values, preventing timing-based side-channel attacks.
 *
 * Used by ML-KEM, ML-DSA, and SLH-DSA implementations.
 *
 * IMPORTANT: These implementations use volatile and memory barriers to
 * prevent compiler optimization of constant-time properties. For production
 * use, verification with tools like ctgrind or dudect is recommended.
 */

#ifndef CT_UTILS_HPP
#define CT_UTILS_HPP

#include <cstdint>
#include <cstddef>
#include <vector>
#include <span>

namespace ct {

/**
 * Compiler memory barrier to prevent reordering.
 */
inline void barrier() noexcept {
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif
}

/**
 * Constant-time conditional select for bytes.
 *
 * Returns a if condition is true (non-zero), b otherwise.
 * Executes in constant time regardless of condition value.
 */
[[nodiscard]] inline uint8_t select_u8(uint8_t a, uint8_t b, bool condition) noexcept {
    volatile uint8_t mask = static_cast<uint8_t>(-static_cast<int8_t>(condition));
    barrier();
    return static_cast<uint8_t>((a & mask) | (b & ~mask));
}

/**
 * Constant-time conditional select for 32-bit integers.
 */
[[nodiscard]] inline uint32_t select_u32(uint32_t a, uint32_t b, bool condition) noexcept {
    volatile uint32_t mask = static_cast<uint32_t>(-static_cast<int32_t>(condition));
    barrier();
    return (a & mask) | (b & ~mask);
}

/**
 * Constant-time conditional select for 64-bit integers.
 */
[[nodiscard]] inline uint64_t select_u64(uint64_t a, uint64_t b, bool condition) noexcept {
    volatile uint64_t mask = static_cast<uint64_t>(-static_cast<int64_t>(condition));
    barrier();
    return (a & mask) | (b & ~mask);
}

/**
 * Constant-time byte array comparison.
 *
 * Returns true if arrays are equal, false otherwise.
 * Always examines all bytes regardless of where differences occur.
 */
[[nodiscard]] inline bool equal(
    std::span<const uint8_t> a,
    std::span<const uint8_t> b) noexcept {

    // Use XOR of sizes to avoid early return on size mismatch
    // This is constant-time because we always process min(a.size(), b.size()) bytes
    size_t size_diff = a.size() ^ b.size();

    volatile uint8_t diff = 0;
    size_t len = (a.size() < b.size()) ? a.size() : b.size();

    for (size_t i = 0; i < len; ++i) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }

    barrier();

    // Return false if sizes differ OR if any byte differs
    return (size_diff == 0) && (diff == 0);
}

/**
 * Constant-time conditional select for byte vectors.
 *
 * Returns a copy of 'a' if condition is true, 'b' otherwise.
 * Vectors must have the same size.
 */
[[nodiscard]] inline std::vector<uint8_t> select_bytes(
    std::span<const uint8_t> a,
    std::span<const uint8_t> b,
    bool condition) noexcept {

    size_t len = a.size();
    std::vector<uint8_t> result(len);

    volatile uint8_t mask = static_cast<uint8_t>(-static_cast<int8_t>(condition));
    barrier();

    for (size_t i = 0; i < len; ++i) {
        result[i] = static_cast<uint8_t>((a[i] & mask) | (b[i] & ~mask));
    }

    barrier();
    return result;
}

/**
 * Constant-time memory zeroing.
 *
 * Securely zeros memory, preventing compiler from optimizing it away.
 */
inline void zero(std::span<uint8_t> data) noexcept {
    volatile uint8_t* ptr = data.data();
    for (size_t i = 0; i < data.size(); ++i) {
        ptr[i] = 0;
    }
    barrier();
}

/**
 * Constant-time less-than comparison for unsigned integers.
 *
 * Returns 1 if a < b, 0 otherwise. Constant time.
 */
[[nodiscard]] inline uint32_t lt_u32(uint32_t a, uint32_t b) noexcept {
    return (a - b) >> 31;
}

/**
 * Constant-time greater-than-or-equal comparison.
 *
 * Returns 1 if a >= b, 0 otherwise. Constant time.
 */
[[nodiscard]] inline uint32_t ge_u32(uint32_t a, uint32_t b) noexcept {
    return 1 - lt_u32(a, b);
}

/**
 * Secure zeroization for int32_t vectors.
 * Used for polynomial coefficient arrays.
 */
inline void zero_poly(std::vector<int32_t>& data) noexcept {
    volatile int32_t* ptr = data.data();
    for (size_t i = 0; i < data.size(); ++i) {
        ptr[i] = 0;
    }
    barrier();
}

/**
 * Secure zeroization for vector of int32_t vectors.
 * Used for polynomial vector arrays.
 */
inline void zero_polyvec(std::vector<std::vector<int32_t>>& data) noexcept {
    for (auto& poly : data) {
        zero_poly(poly);
    }
}

/**
 * RAII wrapper for secure byte vector.
 * Automatically zeros memory on destruction.
 */
class SecureBytes {
public:
    SecureBytes() = default;
    explicit SecureBytes(size_t size) : data_(size, 0) {}
    SecureBytes(const uint8_t* begin, const uint8_t* end) : data_(begin, end) {}
    template<typename Iter>
    SecureBytes(Iter begin, Iter end) : data_(begin, end) {}

    ~SecureBytes() {
        if (!data_.empty()) {
            zero(data_);
        }
    }

    // Move operations
    SecureBytes(SecureBytes&& other) noexcept : data_(std::move(other.data_)) {
        other.data_.clear();
    }
    SecureBytes& operator=(SecureBytes&& other) noexcept {
        if (this != &other) {
            if (!data_.empty()) {
                zero(data_);
            }
            data_ = std::move(other.data_);
            other.data_.clear();
        }
        return *this;
    }

    // Disable copy
    SecureBytes(const SecureBytes&) = delete;
    SecureBytes& operator=(const SecureBytes&) = delete;

    // Accessors
    [[nodiscard]] uint8_t* data() noexcept { return data_.data(); }
    [[nodiscard]] const uint8_t* data() const noexcept { return data_.data(); }
    [[nodiscard]] size_t size() const noexcept { return data_.size(); }
    [[nodiscard]] bool empty() const noexcept { return data_.empty(); }
    [[nodiscard]] uint8_t& operator[](size_t i) noexcept { return data_[i]; }
    [[nodiscard]] const uint8_t& operator[](size_t i) const noexcept { return data_[i]; }

    // Container operations
    void resize(size_t n) { data_.resize(n); }
    void push_back(uint8_t v) { data_.push_back(v); }
    void insert(std::vector<uint8_t>::iterator pos,
                std::vector<uint8_t>::const_iterator first,
                std::vector<uint8_t>::const_iterator last) {
        data_.insert(pos, first, last);
    }
    void clear() {
        zero(data_);
        data_.clear();
    }

    // Iterator support
    [[nodiscard]] auto begin() noexcept { return data_.begin(); }
    [[nodiscard]] auto end() noexcept { return data_.end(); }
    [[nodiscard]] auto begin() const noexcept { return data_.begin(); }
    [[nodiscard]] auto end() const noexcept { return data_.end(); }

    // Conversion to span
    [[nodiscard]] operator std::span<uint8_t>() noexcept { return data_; }
    [[nodiscard]] operator std::span<const uint8_t>() const noexcept { return data_; }

    // Release ownership (caller must handle zeroization)
    [[nodiscard]] std::vector<uint8_t> release() noexcept {
        std::vector<uint8_t> result = std::move(data_);
        data_.clear();
        return result;
    }

private:
    std::vector<uint8_t> data_;
};

} // namespace ct

#endif // CT_UTILS_HPP
