/**
 * ML-DSA Parameter Sets as defined in FIPS 204
 *
 * This header defines the core constants and parameter sets for ML-DSA
 * digital signature algorithm.
 */

#ifndef MLDSA_PARAMS_HPP
#define MLDSA_PARAMS_HPP

#include <cstdint>
#include <array>
#include <string_view>

namespace mldsa {

// Global constants from FIPS 204
inline constexpr int32_t Q = 8380417;      // Modulus q = 2^23 - 2^13 + 1
inline constexpr size_t N = 256;            // Polynomial degree
inline constexpr int D = 13;                // Dropped bits from t
inline constexpr int32_t ZETA = 1753;       // Primitive 512th root of unity mod q

// Polynomial type
using Poly = std::array<int32_t, N>;

/**
 * Parameter set for ML-DSA
 */
struct Params {
    std::string_view name;
    int k;              // Rows in matrix A
    int l;              // Columns in matrix A
    int eta;            // Secret key coefficient bound
    int tau;            // Number of +/-1 coefficients in challenge
    int beta;           // tau * eta
    int32_t gamma1;     // y coefficient range
    int32_t gamma2;     // Low-order rounding range
    int omega;          // Maximum number of 1s in hint
    int lambda;         // Collision strength (bits)

    [[nodiscard]] constexpr size_t pk_size() const noexcept {
        return 32 + 32 * k * (23 - D);  // rho + t1 encoding
    }

    [[nodiscard]] constexpr size_t sk_size() const noexcept {
        int eta_bits = (eta == 2) ? 3 : 4;
        size_t s1_size = 32 * l * eta_bits;
        size_t s2_size = 32 * k * eta_bits;
        size_t t0_size = 32 * k * D;
        return 32 + 32 + 64 + s1_size + s2_size + t0_size;
    }

    [[nodiscard]] constexpr size_t sig_size() const noexcept {
        size_t c_tilde_size = lambda / 4;
        // gamma1.bit_length() = 18 for 2^17, 20 for 2^19
        int g1_bits = (gamma1 == (1 << 17)) ? 18 : 20;
        size_t z_size = 32 * l * g1_bits;
        size_t h_size = omega + k;
        return c_tilde_size + z_size + h_size;
    }

    [[nodiscard]] constexpr int gamma1_bits() const noexcept {
        // gamma1.bit_length() = 18 for 2^17, 20 for 2^19
        return (gamma1 == (1 << 17)) ? 18 : 20;
    }

    [[nodiscard]] constexpr int eta_bits() const noexcept {
        return (eta == 2) ? 3 : 4;
    }
};

// ML-DSA-44: Security Category 2
inline constexpr Params MLDSA44_PARAMS = {
    .name = "ML-DSA-44",
    .k = 4,
    .l = 4,
    .eta = 2,
    .tau = 39,
    .beta = 78,             // tau * eta
    .gamma1 = 1 << 17,      // 2^17
    .gamma2 = (Q - 1) / 88,
    .omega = 80,
    .lambda = 128,
};

// ML-DSA-65: Security Category 3
inline constexpr Params MLDSA65_PARAMS = {
    .name = "ML-DSA-65",
    .k = 6,
    .l = 5,
    .eta = 4,
    .tau = 49,
    .beta = 196,            // tau * eta
    .gamma1 = 1 << 19,      // 2^19
    .gamma2 = (Q - 1) / 32,
    .omega = 55,
    .lambda = 192,
};

// ML-DSA-87: Security Category 5
inline constexpr Params MLDSA87_PARAMS = {
    .name = "ML-DSA-87",
    .k = 8,
    .l = 7,
    .eta = 2,
    .tau = 60,
    .beta = 120,            // tau * eta
    .gamma1 = 1 << 19,      // 2^19
    .gamma2 = (Q - 1) / 32,
    .omega = 75,
    .lambda = 256,
};

/**
 * Compute 8-bit reversal
 */
[[nodiscard]] constexpr uint8_t bitrev8(uint8_t x) noexcept {
    uint8_t result = 0;
    for (int i = 0; i < 8; ++i) {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    return result;
}

/**
 * Compute modular exponentiation
 */
[[nodiscard]] constexpr int32_t mod_pow(int64_t base, int exp, int32_t mod) noexcept {
    int64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) {
            result = (result * base) % mod;
        }
        exp >>= 1;
        base = (base * base) % mod;
    }
    return static_cast<int32_t>(result);
}

/**
 * Precomputed NTT zetas: zeta^BitRev8(k) for k = 0..255
 */
[[nodiscard]] constexpr std::array<int32_t, N> compute_ntt_zetas() noexcept {
    std::array<int32_t, N> zetas{};
    for (size_t k = 0; k < N; ++k) {
        zetas[k] = mod_pow(ZETA, bitrev8(static_cast<uint8_t>(k)), Q);
    }
    return zetas;
}

inline constexpr auto NTT_ZETAS = compute_ntt_zetas();

} // namespace mldsa

#endif // MLDSA_PARAMS_HPP
