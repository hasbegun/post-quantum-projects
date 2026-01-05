/**
 * ML-KEM Parameter Sets as defined in FIPS 203
 *
 * This header defines the core constants and parameter sets for ML-KEM
 * (Module-Lattice-Based Key-Encapsulation Mechanism).
 */

#ifndef MLKEM_PARAMS_HPP
#define MLKEM_PARAMS_HPP

#include <cstdint>
#include <cstddef>
#include <array>
#include <string_view>

namespace mlkem {

// Global constants from FIPS 203
inline constexpr int32_t Q = 3329;          // Modulus q
inline constexpr size_t N = 256;             // Polynomial degree
inline constexpr int32_t ZETA = 17;          // Primitive 256th root of unity mod q

// Polynomial type
using Poly = std::array<int16_t, N>;

/**
 * Parameter set for ML-KEM
 * Based on FIPS 203 Table 2
 */
struct Params {
    std::string_view name;
    int k;              // Module rank (matrix dimension)
    int eta1;           // CBD parameter for secret/error in keygen
    int eta2;           // CBD parameter for error in encaps
    int du;             // Compression bits for u
    int dv;             // Compression bits for v

    /**
     * Encapsulation key size (bytes)
     * ek = 384*k + 32
     */
    [[nodiscard]] constexpr size_t ek_size() const noexcept {
        return 384 * k + 32;
    }

    /**
     * Decapsulation key size (bytes)
     * dk = 768*k + 96
     */
    [[nodiscard]] constexpr size_t dk_size() const noexcept {
        return 768 * k + 96;
    }

    /**
     * Ciphertext size (bytes)
     * ct = 32*(du*k + dv)
     */
    [[nodiscard]] constexpr size_t ct_size() const noexcept {
        return 32 * (du * k + dv);
    }

    /**
     * Shared secret size (bytes)
     * Always 32 bytes
     */
    [[nodiscard]] constexpr size_t ss_size() const noexcept {
        return 32;
    }
};

// ML-KEM-512: Security Category 1 (128-bit)
inline constexpr Params MLKEM512_PARAMS = {
    .name = "ML-KEM-512",
    .k = 2,
    .eta1 = 3,
    .eta2 = 2,
    .du = 10,
    .dv = 4,
};

// ML-KEM-768: Security Category 3 (192-bit)
inline constexpr Params MLKEM768_PARAMS = {
    .name = "ML-KEM-768",
    .k = 3,
    .eta1 = 2,
    .eta2 = 2,
    .du = 10,
    .dv = 4,
};

// ML-KEM-1024: Security Category 5 (256-bit)
inline constexpr Params MLKEM1024_PARAMS = {
    .name = "ML-KEM-1024",
    .k = 4,
    .eta1 = 2,
    .eta2 = 2,
    .du = 11,
    .dv = 5,
};

/**
 * Compute 7-bit reversal for NTT
 * BitRev7(i) reverses the 7 least significant bits of i
 */
[[nodiscard]] constexpr uint8_t bitrev7(uint8_t x) noexcept {
    uint8_t result = 0;
    for (int i = 0; i < 7; ++i) {
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
    if (base < 0) base += mod;
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
 * Precomputed NTT zetas: zeta^BitRev7(k) mod q for k = 0..127
 * Used in NTT and inverse NTT
 */
[[nodiscard]] constexpr std::array<int16_t, 128> compute_ntt_zetas() noexcept {
    std::array<int16_t, 128> zetas{};
    for (size_t k = 0; k < 128; ++k) {
        zetas[k] = static_cast<int16_t>(mod_pow(ZETA, bitrev7(static_cast<uint8_t>(k)), Q));
    }
    return zetas;
}

inline constexpr auto NTT_ZETAS = compute_ntt_zetas();

/**
 * Montgomery reduction constant
 * R = 2^16, q^(-1) mod R = 62209
 */
inline constexpr int32_t QINV = 62209;  // q^(-1) mod 2^16

/**
 * Montgomery reduction
 * Returns a*R^(-1) mod q where R = 2^16
 */
[[nodiscard]] inline constexpr int16_t montgomery_reduce(int32_t a) noexcept {
    int16_t t = static_cast<int16_t>(a * QINV);
    int32_t u = static_cast<int32_t>(t) * Q;
    int32_t result = (a - u) >> 16;
    return static_cast<int16_t>(result);
}

/**
 * Barrett reduction
 * Returns a mod q for |a| < 2^15 * q
 */
[[nodiscard]] inline constexpr int16_t barrett_reduce(int16_t a) noexcept {
    // v = round(2^26 / q) = 20159
    constexpr int32_t v = 20159;
    int32_t t = (static_cast<int32_t>(v) * a + (1 << 25)) >> 26;
    t = a - t * Q;
    return static_cast<int16_t>(t);
}

/**
 * Conditional subtraction of q
 * If a >= q, returns a - q, else returns a
 */
[[nodiscard]] inline constexpr int16_t cond_sub_q(int16_t a) noexcept {
    a -= Q;
    a += (a >> 15) & Q;
    return a;
}

} // namespace mlkem

#endif // MLKEM_PARAMS_HPP
