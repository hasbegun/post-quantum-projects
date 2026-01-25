/**
 * AVX2-optimized NTT for ML-DSA
 *
 * SIMD-accelerated Number Theoretic Transform using Intel AVX2.
 * ML-DSA uses 32-bit coefficients with q = 8380417.
 *
 * Based on techniques from:
 * - CRYSTALS-Dilithium reference implementation
 * - "High-speed ML-KEM and ML-DSA on Intel Processors"
 */

#ifndef MLDSA_NTT_AVX2_HPP
#define MLDSA_NTT_AVX2_HPP

#include "params.hpp"
#include "ntt.hpp"
#include "../common/simd_detect.hpp"
#include <array>
#include <cstdint>

#if SIMD_AVX2_COMPILED
#include <immintrin.h>
#endif

namespace mldsa {
namespace avx2 {

#if SIMD_AVX2_COMPILED

// Constants for Montgomery reduction
// q = 8380417 = 2^23 - 2^13 + 1
// R = 2^32
// q^(-1) mod R = 58728449
constexpr int32_t QINV = 58728449;
constexpr int64_t R = 4294967296LL;

/**
 * Montgomery reduction for 64-bit -> 32-bit
 * Returns a * R^(-1) mod q where R = 2^32
 */
inline int32_t montgomery_reduce_64(int64_t a) noexcept {
    int32_t t = static_cast<int32_t>(a) * QINV;
    int64_t u = static_cast<int64_t>(t) * Q;
    int64_t result = (a - u) >> 32;
    return static_cast<int32_t>(result);
}

/**
 * AVX2 Montgomery multiplication for 8 packed int32 values
 * Returns (a * b) mod q in Montgomery form
 */
inline __m256i montgomery_mul_avx2(__m256i a, __m256i b) noexcept {
    // For 32-bit, we need to compute a*b mod q
    // AVX2 doesn't have 32x32->64 multiply for all elements
    // So we use a hybrid approach: process 4 elements at a time

    // Extract low and high 128-bit lanes
    __m128i a_lo = _mm256_castsi256_si128(a);
    __m128i a_hi = _mm256_extracti128_si256(a, 1);
    __m128i b_lo = _mm256_castsi256_si128(b);
    __m128i b_hi = _mm256_extracti128_si256(b, 1);

    // Multiply with 64-bit results
    __m256i prod_lo = _mm256_mul_epi32(
        _mm256_cvtepi32_epi64(a_lo),
        _mm256_cvtepi32_epi64(b_lo));
    __m256i prod_hi = _mm256_mul_epi32(
        _mm256_cvtepi32_epi64(a_hi),
        _mm256_cvtepi32_epi64(b_hi));

    // Montgomery reduction for each product
    // This is complex for AVX2, so we extract and process
    alignas(32) int64_t prods[8];
    _mm256_store_si256(reinterpret_cast<__m256i*>(&prods[0]), prod_lo);
    _mm256_store_si256(reinterpret_cast<__m256i*>(&prods[4]), prod_hi);

    alignas(32) int32_t results[8];
    for (int i = 0; i < 8; ++i) {
        results[i] = montgomery_reduce_64(prods[i]);
    }

    return _mm256_load_si256(reinterpret_cast<const __m256i*>(results));
}

/**
 * AVX2 modular reduction mod q
 * Reduces values to range [0, q)
 */
inline __m256i reduce_avx2(__m256i a) noexcept {
    const __m256i q = _mm256_set1_epi32(Q);
    const __m256i zero = _mm256_setzero_si256();

    // Subtract q
    __m256i t = _mm256_sub_epi32(a, q);

    // If t < 0, add q back (using arithmetic right shift for sign)
    __m256i mask = _mm256_srai_epi32(t, 31);
    __m256i correction = _mm256_and_si256(mask, q);
    return _mm256_add_epi32(t, correction);
}

/**
 * AVX2 Forward NTT for ML-DSA
 *
 * Input: polynomial w with 256 coefficients
 * Output: w_hat in NTT domain
 */
inline void ntt_avx2(Poly& w) noexcept {
    size_t k = 0;

    // Process layers where length >= 8 (can use full AVX2 registers)
    for (size_t length = 128; length >= 8; length >>= 1) {
        for (size_t start = 0; start < N; start += 2 * length) {
            int32_t zeta = NTT_ZETAS[++k];
            __m256i vzeta = _mm256_set1_epi32(zeta);

            for (size_t j = start; j < start + length; j += 8) {
                __m256i a = _mm256_loadu_si256(
                    reinterpret_cast<const __m256i*>(&w[j]));
                __m256i b = _mm256_loadu_si256(
                    reinterpret_cast<const __m256i*>(&w[j + length]));

                // t = zeta * b mod q
                // For simplicity, compute modular product element-wise
                alignas(32) int32_t a_arr[8], b_arr[8], t_arr[8];
                _mm256_store_si256(reinterpret_cast<__m256i*>(a_arr), a);
                _mm256_store_si256(reinterpret_cast<__m256i*>(b_arr), b);

                for (int i = 0; i < 8; ++i) {
                    int64_t prod = static_cast<int64_t>(zeta) * b_arr[i];
                    t_arr[i] = mod_q(prod);
                }

                __m256i t = _mm256_load_si256(
                    reinterpret_cast<const __m256i*>(t_arr));

                // w[j + length] = w[j] - t
                // w[j] = w[j] + t
                __m256i sum = _mm256_add_epi32(a, t);
                __m256i diff = _mm256_sub_epi32(a, t);

                _mm256_storeu_si256(reinterpret_cast<__m256i*>(&w[j]), sum);
                _mm256_storeu_si256(reinterpret_cast<__m256i*>(&w[j + length]), diff);
            }
        }
    }

    // Process remaining layers (length < 8) with scalar code
    for (size_t length = 4; length >= 1; length >>= 1) {
        for (size_t start = 0; start < N; start += 2 * length) {
            int32_t zeta = NTT_ZETAS[++k];
            for (size_t j = start; j < start + length; ++j) {
                int32_t t = mod_q(static_cast<int64_t>(zeta) * w[j + length]);
                w[j + length] = mod_q(w[j] - t);
                w[j] = mod_q(w[j] + t);
            }
        }
    }
}

/**
 * AVX2 Inverse NTT for ML-DSA
 *
 * Input: w_hat in NTT domain
 * Output: w in coefficient representation
 */
inline void ntt_inv_avx2(Poly& w) noexcept {
    constexpr int32_t N_INV = 8347681; // 256^(-1) mod q

    size_t k = 256;

    // Process layers with length < 8 using scalar code
    for (size_t length = 1; length <= 4; length <<= 1) {
        for (size_t start = 0; start < N; start += 2 * length) {
            int32_t zeta = Q - NTT_ZETAS[--k];
            for (size_t j = start; j < start + length; ++j) {
                int32_t t = w[j];
                w[j] = mod_q(t + w[j + length]);
                w[j + length] = mod_q(
                    static_cast<int64_t>(zeta) * (t - w[j + length]));
            }
        }
    }

    // Process layers where length >= 8 using AVX2
    for (size_t length = 8; length <= 128; length <<= 1) {
        for (size_t start = 0; start < N; start += 2 * length) {
            int32_t zeta = Q - NTT_ZETAS[--k];

            for (size_t j = start; j < start + length; j += 8) {
                __m256i a = _mm256_loadu_si256(
                    reinterpret_cast<const __m256i*>(&w[j]));
                __m256i b = _mm256_loadu_si256(
                    reinterpret_cast<const __m256i*>(&w[j + length]));

                // sum = a + b
                __m256i sum = _mm256_add_epi32(a, b);

                // diff = a - b
                __m256i diff = _mm256_sub_epi32(a, b);

                // w[j] = sum mod q
                // w[j+length] = zeta * diff mod q
                alignas(32) int32_t sum_arr[8], diff_arr[8];
                alignas(32) int32_t w_j[8], w_jl[8];
                _mm256_store_si256(reinterpret_cast<__m256i*>(sum_arr), sum);
                _mm256_store_si256(reinterpret_cast<__m256i*>(diff_arr), diff);

                for (int i = 0; i < 8; ++i) {
                    w_j[i] = mod_q(sum_arr[i]);
                    w_jl[i] = mod_q(static_cast<int64_t>(zeta) * diff_arr[i]);
                }

                _mm256_storeu_si256(reinterpret_cast<__m256i*>(&w[j]),
                    _mm256_load_si256(reinterpret_cast<const __m256i*>(w_j)));
                _mm256_storeu_si256(reinterpret_cast<__m256i*>(&w[j + length]),
                    _mm256_load_si256(reinterpret_cast<const __m256i*>(w_jl)));
            }
        }
    }

    // Final scaling by n^(-1)
    for (size_t i = 0; i < N; i += 8) {
        alignas(32) int32_t arr[8];
        for (int j = 0; j < 8; ++j) {
            arr[j] = mod_q(static_cast<int64_t>(N_INV) * w[i + j]);
        }
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(&w[i]),
            _mm256_load_si256(reinterpret_cast<const __m256i*>(arr)));
    }
}

/**
 * AVX2 Pointwise multiplication in NTT domain
 */
inline Poly ntt_multiply_avx2(const Poly& a_hat, const Poly& b_hat) noexcept {
    Poly c_hat{};

    for (size_t i = 0; i < N; i += 8) {
        alignas(32) int32_t result[8];
        for (int j = 0; j < 8; ++j) {
            result[j] = mod_q(static_cast<int64_t>(a_hat[i + j]) * b_hat[i + j]);
        }
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(&c_hat[i]),
            _mm256_load_si256(reinterpret_cast<const __m256i*>(result)));
    }

    return c_hat;
}

/**
 * AVX2 Polynomial addition
 */
inline Poly poly_add_avx2(const Poly& a, const Poly& b) noexcept {
    Poly c{};
    const __m256i q = _mm256_set1_epi32(Q);

    for (size_t i = 0; i < N; i += 8) {
        __m256i va = _mm256_loadu_si256(
            reinterpret_cast<const __m256i*>(&a[i]));
        __m256i vb = _mm256_loadu_si256(
            reinterpret_cast<const __m256i*>(&b[i]));
        __m256i vc = _mm256_add_epi32(va, vb);

        // Reduce mod q
        vc = reduce_avx2(vc);
        _mm256_storeu_si256(reinterpret_cast<__m256i*>(&c[i]), vc);
    }

    return c;
}

/**
 * AVX2 Polynomial subtraction
 */
inline Poly poly_sub_avx2(const Poly& a, const Poly& b) noexcept {
    Poly c{};
    const __m256i q = _mm256_set1_epi32(Q);

    for (size_t i = 0; i < N; i += 8) {
        __m256i va = _mm256_loadu_si256(
            reinterpret_cast<const __m256i*>(&a[i]));
        __m256i vb = _mm256_loadu_si256(
            reinterpret_cast<const __m256i*>(&b[i]));
        __m256i vc = _mm256_sub_epi32(va, vb);

        // Add q if negative
        __m256i mask = _mm256_srai_epi32(vc, 31);
        __m256i correction = _mm256_and_si256(mask, q);
        vc = _mm256_add_epi32(vc, correction);

        _mm256_storeu_si256(reinterpret_cast<__m256i*>(&c[i]), vc);
    }

    return c;
}

#endif // SIMD_AVX2_COMPILED

} // namespace avx2
} // namespace mldsa

#endif // MLDSA_NTT_AVX2_HPP
