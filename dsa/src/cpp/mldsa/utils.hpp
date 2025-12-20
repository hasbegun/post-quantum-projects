/**
 * Utility functions for ML-DSA implementation
 * Based on FIPS 204 Algorithms 9-20
 */

#ifndef MLDSA_UTILS_HPP
#define MLDSA_UTILS_HPP

#include "params.hpp"
#include <cstdint>
#include <vector>
#include <array>
#include <span>
#include <optional>
#include <algorithm>
#include <cstring>

// Forward declare OpenSSL types
extern "C" {
    struct evp_md_ctx_st;
    typedef struct evp_md_ctx_st EVP_MD_CTX;
}

namespace mldsa {

/**
 * Reduce x modulo q to range [0, q)
 */
[[nodiscard]] inline constexpr int32_t mod_q(int64_t x) noexcept {
    int32_t r = static_cast<int32_t>(x % Q);
    if (r < 0) r += Q;
    return r;
}

/**
 * Reduce x modulo q to centered range (-q/2, q/2]
 */
[[nodiscard]] inline constexpr int32_t mod_pm(int32_t x) noexcept {
    int32_t r = mod_q(x);
    if (r > Q / 2) r -= Q;
    return r;
}

/**
 * Algorithm 9: IntegerToBits
 * Convert integer x to bit array of length alpha (LSB first)
 */
inline void integer_to_bits(uint32_t x, int alpha, std::vector<uint8_t>& out) {
    out.reserve(out.size() + alpha);
    for (int i = 0; i < alpha; ++i) {
        out.push_back(x & 1);
        x >>= 1;
    }
}

/**
 * Algorithm 10: BitsToInteger
 * Convert bit array to integer (LSB first)
 */
[[nodiscard]] inline uint32_t bits_to_integer(std::span<const uint8_t> bits) noexcept {
    uint32_t x = 0;
    for (size_t i = bits.size(); i > 0; --i) {
        x = (x << 1) | bits[i - 1];
    }
    return x;
}

/**
 * Algorithm 11: BitsToBytes
 * Convert bit array to byte array
 */
[[nodiscard]] inline std::vector<uint8_t> bits_to_bytes(std::span<const uint8_t> bits) {
    size_t c = bits.size() / 8;
    std::vector<uint8_t> z(c);
    for (size_t i = 0; i < c; ++i) {
        z[i] = static_cast<uint8_t>(bits_to_integer(bits.subspan(i * 8, 8)));
    }
    return z;
}

/**
 * Algorithm 12: BytesToBits
 * Convert byte array to bit array
 */
[[nodiscard]] inline std::vector<uint8_t> bytes_to_bits(std::span<const uint8_t> z) {
    std::vector<uint8_t> bits;
    bits.reserve(z.size() * 8);
    for (uint8_t byte : z) {
        for (int i = 0; i < 8; ++i) {
            bits.push_back((byte >> i) & 1);
        }
    }
    return bits;
}

/**
 * Algorithm 13: CoefFromThreeBytes
 * Extract coefficient from three bytes (for rejection sampling)
 */
[[nodiscard]] inline std::optional<int32_t> coef_from_three_bytes(
    uint8_t b0, uint8_t b1, uint8_t b2) noexcept {
    int32_t z = b0 + 256 * b1 + 65536 * (b2 & 0x7F);
    if (z < Q) {
        return z;
    }
    return std::nullopt;  // Rejection
}

/**
 * Algorithm 14: CoefFromHalfByte
 * Extract coefficient from half byte (for eta-bounded sampling)
 */
[[nodiscard]] inline std::optional<int32_t> coef_from_half_byte(
    uint8_t b, int eta) noexcept {
    if (eta == 2) {
        if (b < 15) {
            return 2 - static_cast<int32_t>(b % 5);
        }
        return std::nullopt;
    } else if (eta == 4) {
        if (b < 9) {
            return 4 - static_cast<int32_t>(b);
        }
        return std::nullopt;
    }
    return std::nullopt;
}

/**
 * Algorithm 15: SimpleBitPack
 * Pack array of unsigned integers into bytes
 */
[[nodiscard]] inline std::vector<uint8_t> simple_bit_pack(
    std::span<const int32_t> w, int b) {
    std::vector<uint8_t> bits;
    bits.reserve(w.size() * b);
    for (int32_t coef : w) {
        integer_to_bits(static_cast<uint32_t>(coef), b, bits);
    }
    return bits_to_bytes(bits);
}

/**
 * Algorithm 16: SimpleBitUnpack
 * Unpack bytes to array of unsigned integers
 */
[[nodiscard]] inline std::vector<int32_t> simple_bit_unpack(
    std::span<const uint8_t> z, int b) {
    auto bits = bytes_to_bits(z);
    std::vector<int32_t> w;
    w.reserve(N);
    for (size_t i = 0; i < N; ++i) {
        w.push_back(static_cast<int32_t>(
            bits_to_integer(std::span(bits).subspan(b * i, b))));
    }
    return w;
}

/**
 * Algorithm 17: BitPack
 * Pack array of signed integers into bytes
 */
[[nodiscard]] inline std::vector<uint8_t> bit_pack(
    std::span<const int32_t> w, int32_t a, int32_t b) {
    int32_t range = a + b;
    int bitlen = 0;
    while ((1 << bitlen) <= range) ++bitlen;

    std::vector<uint8_t> bits;
    bits.reserve(w.size() * bitlen);
    for (int32_t coef : w) {
        integer_to_bits(static_cast<uint32_t>(b - coef), bitlen, bits);
    }
    return bits_to_bytes(bits);
}

/**
 * Algorithm 18: BitUnpack
 * Unpack bytes to array of signed integers
 */
[[nodiscard]] inline std::vector<int32_t> bit_unpack(
    std::span<const uint8_t> z, int32_t a, int32_t b) {
    int32_t range = a + b;
    int bitlen = 0;
    while ((1 << bitlen) <= range) ++bitlen;

    auto bits = bytes_to_bits(z);
    std::vector<int32_t> w;
    w.reserve(N);
    for (size_t i = 0; i < N; ++i) {
        int32_t val = static_cast<int32_t>(
            bits_to_integer(std::span(bits).subspan(bitlen * i, bitlen)));
        w.push_back(b - val);
    }
    return w;
}

/**
 * Algorithm 19: HintBitPack
 * Pack hint polynomial vector into bytes
 */
[[nodiscard]] inline std::vector<uint8_t> hint_bit_pack(
    const std::vector<std::vector<int32_t>>& h, int omega, int k) {
    std::vector<uint8_t> y(omega + k, 0);
    size_t idx = 0;
    for (int i = 0; i < k; ++i) {
        for (size_t j = 0; j < N; ++j) {
            if (h[i][j] == 1) {
                y[idx++] = static_cast<uint8_t>(j);
            }
        }
        y[omega + i] = static_cast<uint8_t>(idx);
    }
    return y;
}

/**
 * Algorithm 20: HintBitUnpack
 * Unpack bytes to hint polynomial vector
 */
[[nodiscard]] inline std::optional<std::vector<std::vector<int32_t>>> hint_bit_unpack(
    std::span<const uint8_t> y, int omega, int k) {
    std::vector<std::vector<int32_t>> h(k, std::vector<int32_t>(N, 0));
    size_t idx = 0;

    for (int i = 0; i < k; ++i) {
        size_t end = y[omega + i];
        if (end < idx || end > static_cast<size_t>(omega)) {
            return std::nullopt;  // Malformed hint
        }

        size_t first = idx;
        while (idx < end) {
            if (idx > first && y[idx] <= y[idx - 1]) {
                return std::nullopt;  // Indices must be strictly increasing
            }
            h[i][y[idx]] = 1;
            ++idx;
        }
    }

    if (k > 0 && idx != y[omega + k - 1]) {
        return std::nullopt;
    }
    return h;
}

/**
 * Compute infinity norm (max absolute value) of polynomial
 */
[[nodiscard]] inline int32_t infinity_norm(std::span<const int32_t> w) noexcept {
    int32_t max_val = 0;
    for (int32_t c : w) {
        int32_t abs_c = (c < 0) ? -c : c;
        if (abs_c > max_val) max_val = abs_c;
    }
    return max_val;
}

/**
 * Compute infinity norm of vector of polynomials
 */
[[nodiscard]] inline int32_t infinity_norm_vec(
    const std::vector<std::vector<int32_t>>& v) noexcept {
    int32_t max_val = 0;
    for (const auto& poly : v) {
        int32_t norm = infinity_norm(poly);
        if (norm > max_val) max_val = norm;
    }
    return max_val;
}

/**
 * SHAKE128 XOF stream class
 */
class SHAKE128Stream {
public:
    explicit SHAKE128Stream(std::span<const uint8_t> data);
    ~SHAKE128Stream();

    SHAKE128Stream(const SHAKE128Stream&) = delete;
    SHAKE128Stream& operator=(const SHAKE128Stream&) = delete;
    SHAKE128Stream(SHAKE128Stream&&) noexcept;
    SHAKE128Stream& operator=(SHAKE128Stream&&) noexcept;

    std::vector<uint8_t> read(size_t n);

private:
    EVP_MD_CTX* ctx_ = nullptr;
    std::vector<uint8_t> buffer_;
    size_t total_read_ = 0;
    std::vector<uint8_t> seed_;
    bool finalized_ = false;
};

/**
 * SHAKE256 XOF stream class
 */
class SHAKE256Stream {
public:
    explicit SHAKE256Stream(std::span<const uint8_t> data);
    ~SHAKE256Stream();

    SHAKE256Stream(const SHAKE256Stream&) = delete;
    SHAKE256Stream& operator=(const SHAKE256Stream&) = delete;
    SHAKE256Stream(SHAKE256Stream&&) noexcept;
    SHAKE256Stream& operator=(SHAKE256Stream&&) noexcept;

    std::vector<uint8_t> read(size_t n);

private:
    EVP_MD_CTX* ctx_ = nullptr;
    std::vector<uint8_t> buffer_;
    size_t total_read_ = 0;
    std::vector<uint8_t> seed_;
    bool finalized_ = false;
};

/**
 * SHAKE128 XOF function
 */
[[nodiscard]] std::vector<uint8_t> shake128_xof(
    std::span<const uint8_t> data, size_t output_len);

/**
 * SHAKE256 XOF function
 */
[[nodiscard]] std::vector<uint8_t> shake256_xof(
    std::span<const uint8_t> data, size_t output_len);

/**
 * Generate cryptographically secure random bytes
 */
[[nodiscard]] std::vector<uint8_t> random_bytes(size_t n);

} // namespace mldsa

#endif // MLDSA_UTILS_HPP
