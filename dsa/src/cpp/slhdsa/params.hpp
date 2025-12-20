/**
 * SLH-DSA Parameter Sets (FIPS 205 Section 11)
 *
 * Defines all 12 approved parameter sets with their configurations.
 */

#ifndef SLHDSA_PARAMS_HPP
#define SLHDSA_PARAMS_HPP

#include <cstdint>
#include <cstddef>
#include <string_view>
#include <array>

namespace slhdsa {

/**
 * Hash function type
 */
enum class HashType {
    SHA2,
    SHAKE
};

/**
 * SLH-DSA parameter set configuration
 */
struct Params {
    std::string_view name;
    size_t n;           // Security parameter (hash output length in bytes)
    size_t h;           // Total tree height
    size_t d;           // Number of layers in hypertree
    size_t hp;          // Height of each tree (h' = h/d)
    size_t a;           // FORS tree height
    size_t k;           // Number of FORS trees
    size_t lg_w;        // Log2 of Winternitz parameter (always 4, so w=16)
    size_t m;           // Message digest length in bytes
    HashType hash_type; // Hash function family

    // Computed properties
    [[nodiscard]] constexpr size_t w() const noexcept {
        return 1 << lg_w;  // 2^lg_w = 16
    }

    [[nodiscard]] constexpr size_t len1() const noexcept {
        // Number of len1 WOTS+ chains (for message)
        return (8 * n + lg_w - 1) / lg_w;
    }

    [[nodiscard]] constexpr size_t len2() const noexcept {
        // Number of len2 WOTS+ chains (for checksum)
        // len2 = floor(log_w(len1 * (w-1))) + 1
        size_t max_checksum = len1() * (w() - 1);
        size_t result = 1;
        size_t tmp = w();
        while (tmp <= max_checksum) {
            result++;
            tmp *= w();
        }
        return result;
    }

    [[nodiscard]] constexpr size_t len_total() const noexcept {
        return len1() + len2();
    }

    [[nodiscard]] constexpr size_t sig_fors_size() const noexcept {
        // FORS signature size in bytes
        return k * (a + 1) * n;
    }

    [[nodiscard]] constexpr size_t sig_ht_size() const noexcept {
        // Hypertree signature size in bytes
        return (h + d * len_total()) * n;
    }

    [[nodiscard]] constexpr size_t sig_size() const noexcept {
        // Total signature size in bytes (R + SIG_FORS + SIG_HT)
        return n + sig_fors_size() + sig_ht_size();
    }

    [[nodiscard]] constexpr size_t pk_size() const noexcept {
        // Public key size in bytes (PK.seed + PK.root)
        return 2 * n;
    }

    [[nodiscard]] constexpr size_t sk_size() const noexcept {
        // Secret key size in bytes (SK.seed + SK.prf + PK.seed + PK.root)
        return 4 * n;
    }
};

// SHA2-based parameter sets

inline constexpr Params SLH_DSA_SHA2_128s = {
    .name = "SLH-DSA-SHA2-128s",
    .n = 16, .h = 63, .d = 7, .hp = 9, .a = 12, .k = 14,
    .lg_w = 4, .m = 30, .hash_type = HashType::SHA2
};

inline constexpr Params SLH_DSA_SHA2_128f = {
    .name = "SLH-DSA-SHA2-128f",
    .n = 16, .h = 66, .d = 22, .hp = 3, .a = 6, .k = 33,
    .lg_w = 4, .m = 34, .hash_type = HashType::SHA2
};

inline constexpr Params SLH_DSA_SHA2_192s = {
    .name = "SLH-DSA-SHA2-192s",
    .n = 24, .h = 63, .d = 7, .hp = 9, .a = 14, .k = 17,
    .lg_w = 4, .m = 39, .hash_type = HashType::SHA2
};

inline constexpr Params SLH_DSA_SHA2_192f = {
    .name = "SLH-DSA-SHA2-192f",
    .n = 24, .h = 66, .d = 22, .hp = 3, .a = 8, .k = 33,
    .lg_w = 4, .m = 42, .hash_type = HashType::SHA2
};

inline constexpr Params SLH_DSA_SHA2_256s = {
    .name = "SLH-DSA-SHA2-256s",
    .n = 32, .h = 64, .d = 8, .hp = 8, .a = 14, .k = 22,
    .lg_w = 4, .m = 47, .hash_type = HashType::SHA2
};

inline constexpr Params SLH_DSA_SHA2_256f = {
    .name = "SLH-DSA-SHA2-256f",
    .n = 32, .h = 68, .d = 17, .hp = 4, .a = 9, .k = 35,
    .lg_w = 4, .m = 49, .hash_type = HashType::SHA2
};

// SHAKE-based parameter sets

inline constexpr Params SLH_DSA_SHAKE_128s = {
    .name = "SLH-DSA-SHAKE-128s",
    .n = 16, .h = 63, .d = 7, .hp = 9, .a = 12, .k = 14,
    .lg_w = 4, .m = 30, .hash_type = HashType::SHAKE
};

inline constexpr Params SLH_DSA_SHAKE_128f = {
    .name = "SLH-DSA-SHAKE-128f",
    .n = 16, .h = 66, .d = 22, .hp = 3, .a = 6, .k = 33,
    .lg_w = 4, .m = 34, .hash_type = HashType::SHAKE
};

inline constexpr Params SLH_DSA_SHAKE_192s = {
    .name = "SLH-DSA-SHAKE-192s",
    .n = 24, .h = 63, .d = 7, .hp = 9, .a = 14, .k = 17,
    .lg_w = 4, .m = 39, .hash_type = HashType::SHAKE
};

inline constexpr Params SLH_DSA_SHAKE_192f = {
    .name = "SLH-DSA-SHAKE-192f",
    .n = 24, .h = 66, .d = 22, .hp = 3, .a = 8, .k = 33,
    .lg_w = 4, .m = 42, .hash_type = HashType::SHAKE
};

inline constexpr Params SLH_DSA_SHAKE_256s = {
    .name = "SLH-DSA-SHAKE-256s",
    .n = 32, .h = 64, .d = 8, .hp = 8, .a = 14, .k = 22,
    .lg_w = 4, .m = 47, .hash_type = HashType::SHAKE
};

inline constexpr Params SLH_DSA_SHAKE_256f = {
    .name = "SLH-DSA-SHAKE-256f",
    .n = 32, .h = 68, .d = 17, .hp = 4, .a = 9, .k = 35,
    .lg_w = 4, .m = 49, .hash_type = HashType::SHAKE
};

// Array of all parameter sets for iteration
inline constexpr std::array<const Params*, 12> ALL_PARAMS = {
    &SLH_DSA_SHA2_128s, &SLH_DSA_SHA2_128f,
    &SLH_DSA_SHA2_192s, &SLH_DSA_SHA2_192f,
    &SLH_DSA_SHA2_256s, &SLH_DSA_SHA2_256f,
    &SLH_DSA_SHAKE_128s, &SLH_DSA_SHAKE_128f,
    &SLH_DSA_SHAKE_192s, &SLH_DSA_SHAKE_192f,
    &SLH_DSA_SHAKE_256s, &SLH_DSA_SHAKE_256f
};

} // namespace slhdsa

#endif // SLHDSA_PARAMS_HPP
