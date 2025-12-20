/**
 * Number Theoretic Transform (NTT) for ML-DSA
 * Based on FIPS 204 Algorithms 33-34
 *
 * The NTT enables efficient polynomial multiplication in R_q.
 */

#ifndef MLDSA_NTT_HPP
#define MLDSA_NTT_HPP

#include "params.hpp"
#include "utils.hpp"
#include <vector>
#include <array>

namespace mldsa {

/**
 * Algorithm 33: NTT
 * Number Theoretic Transform
 *
 * Converts a polynomial from standard representation to NTT domain.
 */
[[nodiscard]] inline Poly ntt(const Poly& w) noexcept {
    Poly w_hat = w;  // Copy input

    size_t k = 0;
    for (size_t length = 128; length >= 1; length /= 2) {
        for (size_t start = 0; start < N; start += 2 * length) {
            ++k;
            int32_t zeta = NTT_ZETAS[k];
            for (size_t j = start; j < start + length; ++j) {
                int64_t t = (static_cast<int64_t>(zeta) * w_hat[j + length]) % Q;
                w_hat[j + length] = mod_q(w_hat[j] - t);
                w_hat[j] = mod_q(w_hat[j] + t);
            }
        }
    }

    return w_hat;
}

/**
 * Algorithm 34: NTT^(-1)
 * Inverse Number Theoretic Transform
 *
 * Converts a polynomial from NTT domain back to standard representation.
 */
[[nodiscard]] inline Poly ntt_inv(const Poly& w_hat) noexcept {
    Poly w = w_hat;  // Copy input

    size_t k = N;
    for (size_t length = 1; length < N; length *= 2) {
        for (size_t start = 0; start < N; start += 2 * length) {
            --k;
            int32_t zeta = Q - NTT_ZETAS[k];  // Negative zeta
            for (size_t j = start; j < start + length; ++j) {
                int32_t t = w[j];
                w[j] = mod_q(t + w[j + length]);
                w[j + length] = mod_q(static_cast<int64_t>(zeta) * (t - w[j + length]));
            }
        }
    }

    // Multiply by n^(-1) = 256^(-1) mod q = 8347681
    constexpr int32_t n_inv = 8347681;
    for (size_t i = 0; i < N; ++i) {
        w[i] = mod_q(static_cast<int64_t>(w[i]) * n_inv);
    }

    return w;
}

/**
 * Multiply two polynomials in NTT domain (point-wise)
 */
[[nodiscard]] inline Poly ntt_multiply(const Poly& a_hat, const Poly& b_hat) noexcept {
    Poly c_hat{};
    for (size_t i = 0; i < N; ++i) {
        c_hat[i] = mod_q(static_cast<int64_t>(a_hat[i]) * b_hat[i]);
    }
    return c_hat;
}

/**
 * Add two polynomials coefficient-wise
 */
[[nodiscard]] inline Poly poly_add(const Poly& a, const Poly& b) noexcept {
    Poly c{};
    for (size_t i = 0; i < N; ++i) {
        c[i] = mod_q(a[i] + b[i]);
    }
    return c;
}

/**
 * Subtract two polynomials coefficient-wise
 */
[[nodiscard]] inline Poly poly_sub(const Poly& a, const Poly& b) noexcept {
    Poly c{};
    for (size_t i = 0; i < N; ++i) {
        c[i] = mod_q(a[i] - b[i]);
    }
    return c;
}

/**
 * Multiply polynomial by scalar
 */
[[nodiscard]] inline Poly poly_scalar_mul(int32_t s, const Poly& a) noexcept {
    Poly c{};
    for (size_t i = 0; i < N; ++i) {
        c[i] = mod_q(static_cast<int64_t>(s) * a[i]);
    }
    return c;
}

/**
 * Negate polynomial
 */
[[nodiscard]] inline Poly poly_negate(const Poly& a) noexcept {
    Poly c{};
    for (size_t i = 0; i < N; ++i) {
        c[i] = mod_q(-a[i]);
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
 * Multiply matrix by vector in NTT domain
 * A_hat is k x l matrix of polynomials in NTT form
 * v_hat is length l vector of polynomials in NTT form
 * Result is length k vector of polynomials in NTT form
 */
[[nodiscard]] inline PolyVec mat_vec_mul_ntt(const PolyMat& A_hat, const PolyVec& v_hat) {
    size_t k = A_hat.size();
    size_t l = v_hat.size();
    PolyVec result;
    result.reserve(k);

    for (size_t i = 0; i < k; ++i) {
        Poly acc{};
        for (size_t j = 0; j < l; ++j) {
            Poly prod = ntt_multiply(A_hat[i][j], v_hat[j]);
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
        Poly prod = ntt_multiply(a_hat[i], b_hat[i]);
        acc = poly_add(acc, prod);
    }
    return acc;
}

} // namespace mldsa

#endif // MLDSA_NTT_HPP
