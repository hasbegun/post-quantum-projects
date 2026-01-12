/**
 * Constant-Time Utilities for Side-Channel Resistance
 *
 * These functions are designed to execute in constant time regardless of
 * input values, preventing timing-based side-channel attacks.
 *
 * IMPORTANT: These implementations assume the compiler does not optimize
 * away the constant-time properties. For production use, consider:
 * - Using compiler barriers
 * - Verifying with tools like ctgrind or dudect
 * - Using platform-specific intrinsics where available
 */

#ifndef SLHDSA_CT_UTILS_HPP
#define SLHDSA_CT_UTILS_HPP

#include <cstdint>
#include <cstddef>
#include <vector>
#include <span>
#include <cstring>

namespace slhdsa {
namespace ct {

/**
 * Constant-time conditional select for bytes.
 *
 * Returns a if condition is true (non-zero), b otherwise.
 * Executes in constant time regardless of condition value.
 */
[[nodiscard]] inline uint8_t ct_select_u8(uint8_t a, uint8_t b, bool condition) noexcept {
    // Convert bool to all-ones or all-zeros mask
    // Using volatile and memory barrier to prevent compiler optimization
    volatile uint8_t mask = static_cast<uint8_t>(-static_cast<int8_t>(condition));
    uint8_t m = mask;  // Read volatile value
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif
    return static_cast<uint8_t>((a & m) | (b & ~m));
}

/**
 * Constant-time conditional select for 32-bit integers.
 */
[[nodiscard]] inline uint32_t ct_select_u32(uint32_t a, uint32_t b, bool condition) noexcept {
    volatile uint32_t mask = static_cast<uint32_t>(-static_cast<int32_t>(condition));
    uint32_t m = mask;  // Read volatile value
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif
    return (a & m) | (b & ~m);
}

/**
 * Constant-time conditional select for 64-bit integers.
 */
[[nodiscard]] inline uint64_t ct_select_u64(uint64_t a, uint64_t b, bool condition) noexcept {
    volatile uint64_t mask = static_cast<uint64_t>(-static_cast<int64_t>(condition));
    uint64_t m = mask;  // Read volatile value
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif
    return (a & m) | (b & ~m);
}

/**
 * Constant-time conditional copy.
 *
 * Copies src to dst if condition is true, otherwise dst unchanged.
 * Both branches execute the same operations.
 */
inline void ct_copy_conditional(
    std::span<uint8_t> dst,
    std::span<const uint8_t> src,
    bool condition) noexcept {

    volatile uint8_t mask = static_cast<uint8_t>(-static_cast<int8_t>(condition));
    uint8_t m = mask;  // Read volatile value
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif
    size_t len = (dst.size() < src.size()) ? dst.size() : src.size();

    for (size_t i = 0; i < len; ++i) {
        dst[i] = static_cast<uint8_t>((src[i] & m) | (dst[i] & ~m));
    }
}

/**
 * Constant-time conditional select for byte vectors.
 *
 * Returns a copy of 'a' if condition is true, 'b' otherwise.
 * Both vectors must have the same size.
 */
[[nodiscard]] inline std::vector<uint8_t> ct_select_bytes(
    std::span<const uint8_t> a,
    std::span<const uint8_t> b,
    bool condition) noexcept {

    size_t len = a.size();
    std::vector<uint8_t> result(len);

    volatile uint8_t mask = static_cast<uint8_t>(-static_cast<int8_t>(condition));
    uint8_t m = mask;  // Read volatile value
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif

    for (size_t i = 0; i < len; ++i) {
        result[i] = static_cast<uint8_t>((a[i] & m) | (b[i] & ~m));
    }

    return result;
}

/**
 * Constant-time byte array comparison.
 *
 * Returns true if arrays are equal, false otherwise.
 * Always examines all bytes regardless of where differences occur.
 *
 * NOTE: Size mismatch is checked first as sizes are not considered secret.
 * The byte comparison is constant-time for equal-sized arrays.
 */
[[nodiscard]] inline bool ct_equal(
    std::span<const uint8_t> a,
    std::span<const uint8_t> b) noexcept {

    if (a.size() != b.size()) {
        return false;  // Size mismatch is not secret data
    }

    volatile uint8_t diff = 0;

    for (size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<uint8_t>(a[i] ^ b[i]);
    }

    // Memory barrier to prevent reordering
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif

    return diff == 0;
}

/**
 * Constant-time conditional swap.
 *
 * Swaps contents of a and b if condition is true.
 * Both vectors must have the same size.
 */
inline void ct_swap_conditional(
    std::span<uint8_t> a,
    std::span<uint8_t> b,
    bool condition) noexcept {

    volatile uint8_t mask = static_cast<uint8_t>(-static_cast<int8_t>(condition));
    uint8_t m = mask;  // Read volatile value
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif
    size_t len = a.size();

    for (size_t i = 0; i < len; ++i) {
        uint8_t diff = static_cast<uint8_t>((a[i] ^ b[i]) & m);
        a[i] ^= diff;
        b[i] ^= diff;
    }
}

/**
 * Constant-time less-than comparison for unsigned integers.
 *
 * Returns 1 if a < b, 0 otherwise. Constant time.
 */
[[nodiscard]] inline uint32_t ct_lt_u32(uint32_t a, uint32_t b) noexcept {
    // (a - b) will have high bit set if a < b (due to underflow)
    return (a - b) >> 31;
}

/**
 * Constant-time greater-than-or-equal comparison.
 *
 * Returns 1 if a >= b, 0 otherwise. Constant time.
 */
[[nodiscard]] inline uint32_t ct_ge_u32(uint32_t a, uint32_t b) noexcept {
    return 1 - ct_lt_u32(a, b);
}

/**
 * Constant-time check if value is in range [low, high).
 *
 * Returns 1 if low <= val < high, 0 otherwise.
 */
[[nodiscard]] inline uint32_t ct_in_range_u32(uint32_t val, uint32_t low, uint32_t high) noexcept {
    return ct_ge_u32(val, low) & ct_lt_u32(val, high);
}

/**
 * Constant-time memory zeroing.
 *
 * Securely zeros memory, preventing compiler from optimizing it away.
 */
inline void ct_zero(std::span<uint8_t> data) noexcept {
    volatile uint8_t* ptr = data.data();
    for (size_t i = 0; i < data.size(); ++i) {
        ptr[i] = 0;
    }
}

/**
 * Constant-time concatenation with conditional ordering.
 *
 * If condition is true: result = a || b
 * If condition is false: result = b || a
 *
 * Both orderings are computed and the result is selected.
 * This version avoids conditional branches by computing both orderings.
 */
[[nodiscard]] inline std::vector<uint8_t> ct_concat_conditional(
    std::span<const uint8_t> a,
    std::span<const uint8_t> b,
    bool a_first) noexcept {

    size_t a_len = a.size();
    size_t b_len = b.size();
    size_t total_len = a_len + b_len;

    // Compute both possible orderings
    std::vector<uint8_t> result_ab(total_len);  // a || b
    std::vector<uint8_t> result_ba(total_len);  // b || a

    // Build a || b
    for (size_t i = 0; i < a_len; ++i) {
        result_ab[i] = a[i];
    }
    for (size_t i = 0; i < b_len; ++i) {
        result_ab[a_len + i] = b[i];
    }

    // Build b || a
    for (size_t i = 0; i < b_len; ++i) {
        result_ba[i] = b[i];
    }
    for (size_t i = 0; i < a_len; ++i) {
        result_ba[b_len + i] = a[i];
    }

    // Constant-time select between the two results
    volatile uint8_t mask = static_cast<uint8_t>(-static_cast<int8_t>(a_first));
    uint8_t m = mask;  // Read volatile value
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif

    std::vector<uint8_t> result(total_len);
    for (size_t i = 0; i < total_len; ++i) {
        // Select result_ab if a_first is true (mask = 0xFF)
        // Select result_ba if a_first is false (mask = 0x00)
        result[i] = static_cast<uint8_t>((result_ab[i] & m) | (result_ba[i] & ~m));
    }

    return result;
}

/**
 * Compiler memory barrier to prevent reordering.
 */
inline void ct_barrier() noexcept {
#if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
    _ReadWriteBarrier();
#endif
}

} // namespace ct
} // namespace slhdsa

#endif // SLHDSA_CT_UTILS_HPP
