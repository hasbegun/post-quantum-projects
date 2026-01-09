/**
 * Number Theoretic Transform (NTT) for ML-KEM
 * Based on FIPS 203 Algorithms 9-10
 *
 * The NTT enables efficient polynomial multiplication in R_q = Z_q[X]/(X^256 + 1)
 * where q = 3329.
 */

#ifndef MLKEM_NTT_HPP
#define MLKEM_NTT_HPP

#include "params.hpp"
#include <vector>
#include <array>

namespace mlkem {

/**
 * Constant-time modular multiplication for NTT
 * Uses Barrett reduction to avoid timing-variable modulo operator
 */
[[nodiscard]] inline int16_t fqmul(int16_t a, int16_t b) noexcept {
    int32_t t = static_cast<int32_t>(a) * b;
    // Use constant-time Barrett reduction for 32-bit values
    return barrett_reduce_32(t);
}

/**
 * Algorithm 9: NTT
 * Number Theoretic Transform
 *
 * Converts a polynomial from coefficient representation to NTT representation.
 * Input: f in R_q (256 coefficients)
 * Output: f_hat in T_q (NTT representation)
 */
[[nodiscard]] inline Poly ntt(Poly f) noexcept {
    size_t k = 1;
    for (size_t len = 128; len >= 2; len >>= 1) {
        for (size_t start = 0; start < N; start += 2 * len) {
            int16_t zeta = NTT_ZETAS[k++];
            for (size_t j = start; j < start + len; ++j) {
                int16_t t = fqmul(zeta, f[j + len]);
                f[j + len] = barrett_reduce(f[j] - t);
                f[j] = barrett_reduce(f[j] + t);
            }
        }
    }
    return f;
}

/**
 * Algorithm 10: NTT^(-1)
 * Inverse Number Theoretic Transform
 *
 * Converts a polynomial from NTT representation back to coefficient representation.
 * Input: f_hat in T_q (NTT representation)
 * Output: f in R_q (256 coefficients)
 */
[[nodiscard]] inline Poly ntt_inv(Poly f_hat) noexcept {
    size_t k = 127;
    for (size_t len = 2; len <= 128; len <<= 1) {
        for (size_t start = 0; start < N; start += 2 * len) {
            int16_t zeta = NTT_ZETAS[k--];
            for (size_t j = start; j < start + len; ++j) {
                int16_t t = f_hat[j];
                f_hat[j] = barrett_reduce(t + f_hat[j + len]);
                f_hat[j + len] = fqmul(zeta, barrett_reduce(f_hat[j + len] - t));
            }
        }
    }

    // Multiply by n^(-1) = 128^(-1) mod q = 3303
    constexpr int16_t n_inv = 3303;
    for (size_t i = 0; i < N; ++i) {
        f_hat[i] = fqmul(n_inv, f_hat[i]);
    }

    return f_hat;
}

/**
 * Algorithm 11: MultiplyNTTs
 * Multiply two polynomials in NTT domain
 *
 * Performs coefficient-wise multiplication in the NTT domain using
 * the base case multiplication for pairs of coefficients.
 */
[[nodiscard]] inline Poly multiply_ntts(const Poly& f_hat, const Poly& g_hat) noexcept {
    Poly h_hat{};

    // Precompute the base case zetas
    // zeta^(2*BitRev7(i) + 1) for i = 0..127
    static const auto base_zetas = []() {
        std::array<int16_t, 128> z{};
        for (size_t i = 0; i < 128; ++i) {
            int exp = 2 * bitrev7(static_cast<uint8_t>(i)) + 1;
            z[i] = static_cast<int16_t>(mod_pow(ZETA, exp, Q));
        }
        return z;
    }();

    for (size_t i = 0; i < N / 2; ++i) {
        int16_t zeta = base_zetas[i];

        // Base case multiplication: (a0 + a1*X) * (b0 + b1*X) mod (X^2 - zeta)
        int16_t a0 = f_hat[2 * i];
        int16_t a1 = f_hat[2 * i + 1];
        int16_t b0 = g_hat[2 * i];
        int16_t b1 = g_hat[2 * i + 1];

        // c0 = a0*b0 + a1*b1*zeta
        // c1 = a0*b1 + a1*b0
        int16_t a0b0 = fqmul(a0, b0);
        int16_t a1b1 = fqmul(a1, b1);
        int16_t a1b1z = fqmul(a1b1, zeta);
        h_hat[2 * i] = barrett_reduce(a0b0 + a1b1z);

        int16_t a0b1 = fqmul(a0, b1);
        int16_t a1b0 = fqmul(a1, b0);
        h_hat[2 * i + 1] = barrett_reduce(a0b1 + a1b0);
    }

    return h_hat;
}

/**
 * Add two polynomials coefficient-wise
 */
[[nodiscard]] inline Poly poly_add(const Poly& a, const Poly& b) noexcept {
    Poly c{};
    for (size_t i = 0; i < N; ++i) {
        c[i] = a[i] + b[i];
    }
    return c;
}

/**
 * Subtract two polynomials coefficient-wise
 */
[[nodiscard]] inline Poly poly_sub(const Poly& a, const Poly& b) noexcept {
    Poly c{};
    for (size_t i = 0; i < N; ++i) {
        c[i] = a[i] - b[i];
    }
    return c;
}

/**
 * Reduce all coefficients modulo q
 */
[[nodiscard]] inline Poly poly_reduce(const Poly& a) noexcept {
    Poly c{};
    for (size_t i = 0; i < N; ++i) {
        c[i] = barrett_reduce(a[i]);
    }
    return c;
}

/**
 * Convert polynomial to canonical form [0, q)
 */
[[nodiscard]] inline Poly poly_to_mont(const Poly& a) noexcept {
    // Montgomery constant: 2^16 mod q = 2285
    constexpr int16_t R_MOD_Q = 2285;
    Poly c{};
    for (size_t i = 0; i < N; ++i) {
        c[i] = montgomery_reduce(static_cast<int32_t>(a[i]) * R_MOD_Q);
    }
    return c;
}

// Vector operations (vectors of polynomials)
using PolyVec = std::vector<Poly>;
using PolyMat = std::vector<PolyVec>;

/**
 * Apply NTT to each polynomial in vector
 */
[[nodiscard]] inline PolyVec vec_ntt(const PolyVec& v) {
    PolyVec result;
    result.reserve(v.size());
    for (const auto& p : v) {
        result.push_back(ntt(p));
    }
    return result;
}

/**
 * Apply inverse NTT to each polynomial in vector
 */
[[nodiscard]] inline PolyVec vec_ntt_inv(const PolyVec& v_hat) {
    PolyVec result;
    result.reserve(v_hat.size());
    for (const auto& p : v_hat) {
        result.push_back(ntt_inv(p));
    }
    return result;
}

/**
 * Add two vectors of polynomials
 */
[[nodiscard]] inline PolyVec vec_add(const PolyVec& a, const PolyVec& b) {
    PolyVec result;
    result.reserve(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        result.push_back(poly_add(a[i], b[i]));
    }
    return result;
}

/**
 * Subtract two vectors of polynomials
 */
[[nodiscard]] inline PolyVec vec_sub(const PolyVec& a, const PolyVec& b) {
    PolyVec result;
    result.reserve(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        result.push_back(poly_sub(a[i], b[i]));
    }
    return result;
}

/**
 * Reduce all coefficients in vector
 */
[[nodiscard]] inline PolyVec vec_reduce(const PolyVec& v) {
    PolyVec result;
    result.reserve(v.size());
    for (const auto& p : v) {
        result.push_back(poly_reduce(p));
    }
    return result;
}

/**
 * Multiply matrix by vector in NTT domain
 * A_hat is k x k matrix of polynomials in NTT form
 * v_hat is length k vector of polynomials in NTT form
 * Result is length k vector of polynomials in NTT form
 */
[[nodiscard]] inline PolyVec mat_vec_mul_ntt(const PolyMat& A_hat, const PolyVec& v_hat) {
    size_t k = A_hat.size();
    PolyVec result;
    result.reserve(k);

    for (size_t i = 0; i < k; ++i) {
        Poly acc{};
        for (size_t j = 0; j < k; ++j) {
            Poly prod = multiply_ntts(A_hat[i][j], v_hat[j]);
            acc = poly_add(acc, prod);
        }
        result.push_back(acc);
    }
    return result;
}

/**
 * Compute inner product of two vectors in NTT domain
 */
[[nodiscard]] inline Poly inner_product_ntt(const PolyVec& a_hat, const PolyVec& b_hat) {
    Poly acc{};
    for (size_t i = 0; i < a_hat.size(); ++i) {
        Poly prod = multiply_ntts(a_hat[i], b_hat[i]);
        acc = poly_add(acc, prod);
    }
    return acc;
}

} // namespace mlkem

#endif // MLKEM_NTT_HPP
