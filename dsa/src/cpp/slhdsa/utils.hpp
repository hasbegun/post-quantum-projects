/**
 * SLH-DSA Utility Functions (FIPS 205 Section 4)
 *
 * Core conversion and utility functions used throughout the implementation.
 */

#ifndef SLHDSA_UTILS_HPP
#define SLHDSA_UTILS_HPP

#include <cstdint>
#include <cstddef>
#include <vector>
#include <span>
#include <array>
#include <stdexcept>

namespace slhdsa {

/**
 * Algorithm 1: toInt(X, n)
 *
 * Converts a byte string X of length n to a non-negative integer.
 * Uses big-endian byte order.
 */
[[nodiscard]] inline uint64_t toInt(std::span<const uint8_t> x) noexcept {
    uint64_t total = 0;
    for (auto b : x) {
        total = (total << 8) | b;
    }
    return total;
}

/**
 * Algorithm 2: toByte(x, n)
 *
 * Converts a non-negative integer x to a byte string of length n.
 * Uses big-endian byte order.
 */
[[nodiscard]] inline std::vector<uint8_t> toByte(uint64_t x, size_t n) {
    std::vector<uint8_t> result(n);
    for (size_t i = n; i > 0; --i) {
        result[i - 1] = static_cast<uint8_t>(x & 0xff);
        x >>= 8;
    }
    return result;
}

/**
 * toByte into existing buffer
 */
inline void toByteInto(uint64_t x, std::span<uint8_t> out) noexcept {
    for (size_t i = out.size(); i > 0; --i) {
        out[i - 1] = static_cast<uint8_t>(x & 0xff);
        x >>= 8;
    }
}

/**
 * Algorithm 3: base_2b(X, b, out_len)
 *
 * Computes the base-2^b representation of X.
 *
 * Args:
 *   x: Input byte string
 *   b: Number of bits per output element
 *   out_len: Number of output elements
 *
 * Returns:
 *   Vector of out_len integers, each in range [0, 2^b - 1]
 */
[[nodiscard]] inline std::vector<uint32_t> base_2b(
    std::span<const uint8_t> x, size_t b, size_t out_len) {

    std::vector<uint32_t> result;
    result.reserve(out_len);

    uint64_t in_bits = 0;
    size_t bits = 0;
    uint32_t mask = (1u << b) - 1;

    size_t byte_idx = 0;
    for (size_t i = 0; i < out_len; ++i) {
        while (bits < b) {
            in_bits = (in_bits << 8) | x[byte_idx++];
            bits += 8;
        }
        bits -= b;
        result.push_back(static_cast<uint32_t>((in_bits >> bits) & mask));
    }

    return result;
}

/**
 * Ceiling division
 */
[[nodiscard]] constexpr size_t cdiv(size_t a, size_t b) noexcept {
    return (a + b - 1) / b;
}

/**
 * XOR two byte spans of equal length
 */
[[nodiscard]] inline std::vector<uint8_t> xor_bytes(
    std::span<const uint8_t> a, std::span<const uint8_t> b) {

    if (a.size() != b.size()) {
        throw std::invalid_argument("XOR: byte spans must have equal length");
    }

    std::vector<uint8_t> result(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        result[i] = a[i] ^ b[i];
    }
    return result;
}

/**
 * XOR into destination buffer
 */
inline void xor_bytes_into(
    std::span<const uint8_t> a,
    std::span<const uint8_t> b,
    std::span<uint8_t> out) noexcept {

    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = a[i] ^ b[i];
    }
}

/**
 * Concatenate multiple byte vectors
 */
template<typename... Args>
[[nodiscard]] std::vector<uint8_t> concat(Args&&... args) {
    std::vector<uint8_t> result;
    size_t total_size = (... + args.size());
    result.reserve(total_size);
    (result.insert(result.end(), args.begin(), args.end()), ...);
    return result;
}

/**
 * Append bytes to vector
 */
inline void append(std::vector<uint8_t>& dest, std::span<const uint8_t> src) {
    dest.insert(dest.end(), src.begin(), src.end());
}

/**
 * Generate cryptographically secure random bytes
 * (Implementation in utils.cpp)
 */
[[nodiscard]] std::vector<uint8_t> random_bytes(size_t n);

/**
 * Copy bytes from source to destination
 */
inline void copy_bytes(std::span<uint8_t> dest, std::span<const uint8_t> src) {
    std::copy(src.begin(), src.end(), dest.begin());
}

/**
 * Extract slice from vector (similar to Python slice)
 */
[[nodiscard]] inline std::vector<uint8_t> slice(
    std::span<const uint8_t> data, size_t start, size_t end) {
    return std::vector<uint8_t>(data.begin() + start, data.begin() + end);
}

/**
 * Create span from portion of vector
 */
[[nodiscard]] inline std::span<const uint8_t> subspan(
    std::span<const uint8_t> data, size_t offset, size_t count) {
    return data.subspan(offset, count);
}

} // namespace slhdsa

#endif // SLHDSA_UTILS_HPP
