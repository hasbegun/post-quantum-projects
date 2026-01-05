/**
 * Compression Functions for ML-KEM
 * Based on FIPS 203 Algorithms 12-13
 */

#ifndef MLKEM_COMPRESS_HPP
#define MLKEM_COMPRESS_HPP

#include "params.hpp"
#include "ntt.hpp"
#include <vector>
#include <cstdint>

namespace mlkem {

/**
 * Algorithm 12: Compress_d
 * Compress a coefficient from [0, q) to [0, 2^d)
 *
 * Compress_d(x) = round((2^d / q) * x) mod 2^d
 */
[[nodiscard]] inline int16_t compress(int16_t x, int d) {
    // Ensure x is in [0, q)
    x = cond_sub_q(x);
    if (x < 0) x += Q;

    // Compute round((2^d * x) / q)
    // = floor((2^d * x + q/2) / q)
    uint32_t t = static_cast<uint32_t>(x);
    t <<= d;
    t += Q / 2;
    t /= Q;

    // Reduce modulo 2^d
    return static_cast<int16_t>(t & ((1 << d) - 1));
}

/**
 * Algorithm 13: Decompress_d
 * Decompress a coefficient from [0, 2^d) to [0, q)
 *
 * Decompress_d(y) = round((q / 2^d) * y)
 */
[[nodiscard]] inline int16_t decompress(int16_t y, int d) {
    // Compute round((q * y) / 2^d)
    // = floor((q * y + 2^(d-1)) / 2^d)
    uint32_t t = static_cast<uint32_t>(y) * Q;
    t += 1 << (d - 1);
    t >>= d;

    return static_cast<int16_t>(t);
}

/**
 * Compress all coefficients of a polynomial
 */
[[nodiscard]] inline Poly poly_compress(const Poly& a, int d) {
    Poly c{};
    for (size_t i = 0; i < N; ++i) {
        c[i] = compress(a[i], d);
    }
    return c;
}

/**
 * Decompress all coefficients of a polynomial
 */
[[nodiscard]] inline Poly poly_decompress(const Poly& a, int d) {
    Poly c{};
    for (size_t i = 0; i < N; ++i) {
        c[i] = decompress(a[i], d);
    }
    return c;
}

/**
 * Compress vector of polynomials
 */
[[nodiscard]] inline PolyVec vec_compress(const PolyVec& v, int d) {
    PolyVec result;
    result.reserve(v.size());
    for (const auto& p : v) {
        result.push_back(poly_compress(p, d));
    }
    return result;
}

/**
 * Decompress vector of polynomials
 */
[[nodiscard]] inline PolyVec vec_decompress(const PolyVec& v, int d) {
    PolyVec result;
    result.reserve(v.size());
    for (const auto& p : v) {
        result.push_back(poly_decompress(p, d));
    }
    return result;
}

} // namespace mlkem

#endif // MLKEM_COMPRESS_HPP
