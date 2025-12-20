/**
 * Encoding and arithmetic functions for ML-DSA
 * Based on FIPS 204 Algorithms 21-32
 */

#ifndef MLDSA_ENCODING_HPP
#define MLDSA_ENCODING_HPP

#include "params.hpp"
#include "utils.hpp"
#include <vector>
#include <tuple>
#include <optional>
#include <span>

namespace mldsa {

/**
 * Algorithm 21: pkEncode
 * Encode public key
 */
[[nodiscard]] inline std::vector<uint8_t> pk_encode(
    std::span<const uint8_t> rho,
    const std::vector<std::vector<int32_t>>& t1,
    const Params& params) {

    std::vector<uint8_t> pk;
    pk.reserve(params.pk_size());

    // Copy rho (32 bytes)
    pk.insert(pk.end(), rho.begin(), rho.end());

    // Encode t1 polynomials
    int bitlen = 23 - D;  // 10 bits per coefficient
    for (int i = 0; i < params.k; ++i) {
        auto packed = simple_bit_pack(t1[i], bitlen);
        pk.insert(pk.end(), packed.begin(), packed.end());
    }

    return pk;
}

/**
 * Algorithm 22: pkDecode
 * Decode public key
 */
[[nodiscard]] inline std::tuple<std::vector<uint8_t>, std::vector<std::vector<int32_t>>>
pk_decode(std::span<const uint8_t> pk, const Params& params) {
    std::vector<uint8_t> rho(pk.begin(), pk.begin() + 32);

    int bitlen = 23 - D;
    size_t bytes_per_poly = 32 * bitlen;

    std::vector<std::vector<int32_t>> t1;
    t1.reserve(params.k);

    size_t offset = 32;
    for (int i = 0; i < params.k; ++i) {
        auto poly = simple_bit_unpack(
            pk.subspan(offset, bytes_per_poly), bitlen);
        t1.push_back(std::move(poly));
        offset += bytes_per_poly;
    }

    return {std::move(rho), std::move(t1)};
}

/**
 * Algorithm 23: skEncode
 * Encode private key
 */
[[nodiscard]] inline std::vector<uint8_t> sk_encode(
    std::span<const uint8_t> rho,
    std::span<const uint8_t> K,
    std::span<const uint8_t> tr,
    const std::vector<std::vector<int32_t>>& s1,
    const std::vector<std::vector<int32_t>>& s2,
    const std::vector<std::vector<int32_t>>& t0,
    const Params& params) {

    std::vector<uint8_t> sk;
    sk.reserve(params.sk_size());

    // rho (32 bytes)
    sk.insert(sk.end(), rho.begin(), rho.end());
    // K (32 bytes)
    sk.insert(sk.end(), K.begin(), K.end());
    // tr (64 bytes)
    sk.insert(sk.end(), tr.begin(), tr.end());

    int eta = params.eta;

    // Encode s1 (l polynomials)
    for (int i = 0; i < params.l; ++i) {
        auto packed = bit_pack(s1[i], eta, eta);
        sk.insert(sk.end(), packed.begin(), packed.end());
    }

    // Encode s2 (k polynomials)
    for (int i = 0; i < params.k; ++i) {
        auto packed = bit_pack(s2[i], eta, eta);
        sk.insert(sk.end(), packed.begin(), packed.end());
    }

    // Encode t0 (k polynomials)
    int32_t d_half = 1 << (D - 1);  // 4096
    for (int i = 0; i < params.k; ++i) {
        auto packed = bit_pack(t0[i], d_half - 1, d_half);
        sk.insert(sk.end(), packed.begin(), packed.end());
    }

    return sk;
}

/**
 * Algorithm 24: skDecode
 * Decode private key
 */
struct DecodedSK {
    std::vector<uint8_t> rho;
    std::vector<uint8_t> K;
    std::vector<uint8_t> tr;
    std::vector<std::vector<int32_t>> s1;
    std::vector<std::vector<int32_t>> s2;
    std::vector<std::vector<int32_t>> t0;
};

[[nodiscard]] inline DecodedSK sk_decode(
    std::span<const uint8_t> sk, const Params& params) {

    DecodedSK result;
    size_t offset = 0;

    // rho (32 bytes)
    result.rho.assign(sk.begin() + offset, sk.begin() + offset + 32);
    offset += 32;

    // K (32 bytes)
    result.K.assign(sk.begin() + offset, sk.begin() + offset + 32);
    offset += 32;

    // tr (64 bytes)
    result.tr.assign(sk.begin() + offset, sk.begin() + offset + 64);
    offset += 64;

    // Calculate bytes per polynomial
    int eta = params.eta;
    int eta_bits = (2 * eta == 4) ? 3 : 4;
    if (eta == 2) eta_bits = 3;
    else if (eta == 4) eta_bits = 4;
    size_t bytes_per_eta_poly = 32 * eta_bits;

    // Decode s1
    result.s1.reserve(params.l);
    for (int i = 0; i < params.l; ++i) {
        auto poly = bit_unpack(
            sk.subspan(offset, bytes_per_eta_poly), eta, eta);
        result.s1.push_back(std::move(poly));
        offset += bytes_per_eta_poly;
    }

    // Decode s2
    result.s2.reserve(params.k);
    for (int i = 0; i < params.k; ++i) {
        auto poly = bit_unpack(
            sk.subspan(offset, bytes_per_eta_poly), eta, eta);
        result.s2.push_back(std::move(poly));
        offset += bytes_per_eta_poly;
    }

    // Decode t0
    int32_t d_half = 1 << (D - 1);
    size_t bytes_per_t0_poly = 32 * D;
    result.t0.reserve(params.k);
    for (int i = 0; i < params.k; ++i) {
        auto poly = bit_unpack(
            sk.subspan(offset, bytes_per_t0_poly), d_half - 1, d_half);
        result.t0.push_back(std::move(poly));
        offset += bytes_per_t0_poly;
    }

    return result;
}

/**
 * Algorithm 25: sigEncode
 * Encode signature
 */
[[nodiscard]] inline std::vector<uint8_t> sig_encode(
    std::span<const uint8_t> c_tilde,
    const std::vector<std::vector<int32_t>>& z,
    const std::vector<std::vector<int32_t>>& h,
    const Params& params) {

    std::vector<uint8_t> sigma;
    sigma.reserve(params.sig_size());

    // c_tilde
    sigma.insert(sigma.end(), c_tilde.begin(), c_tilde.end());

    // Encode z
    int32_t gamma1 = params.gamma1;
    for (int i = 0; i < params.l; ++i) {
        auto packed = bit_pack(z[i], gamma1 - 1, gamma1);
        sigma.insert(sigma.end(), packed.begin(), packed.end());
    }

    // Encode hint
    auto hint_packed = hint_bit_pack(h, params.omega, params.k);
    sigma.insert(sigma.end(), hint_packed.begin(), hint_packed.end());

    return sigma;
}

/**
 * Algorithm 26: sigDecode
 * Decode signature
 */
struct DecodedSig {
    std::vector<uint8_t> c_tilde;
    std::vector<std::vector<int32_t>> z;
    std::vector<std::vector<int32_t>> h;
};

[[nodiscard]] inline std::optional<DecodedSig> sig_decode(
    std::span<const uint8_t> sigma, const Params& params) {

    if (sigma.size() < params.sig_size()) {
        return std::nullopt;
    }

    DecodedSig result;
    size_t offset = 0;

    // Decode c_tilde
    size_t c_tilde_len = params.lambda / 4;
    result.c_tilde.assign(sigma.begin(), sigma.begin() + c_tilde_len);
    offset += c_tilde_len;

    // Decode z
    int32_t gamma1 = params.gamma1;
    int gamma1_bits = params.gamma1_bits();
    size_t bytes_per_z_poly = 32 * gamma1_bits;
    result.z.reserve(params.l);
    for (int i = 0; i < params.l; ++i) {
        auto poly = bit_unpack(
            sigma.subspan(offset, bytes_per_z_poly), gamma1 - 1, gamma1);
        result.z.push_back(std::move(poly));
        offset += bytes_per_z_poly;
    }

    // Decode hint
    size_t hint_len = params.omega + params.k;
    auto h = hint_bit_unpack(sigma.subspan(offset, hint_len), params.omega, params.k);
    if (!h) {
        return std::nullopt;
    }
    result.h = std::move(*h);

    return result;
}

/**
 * Algorithm 27: Power2Round
 * Decompose r into (r1, r0) such that r = r1 * 2^d + r0
 */
[[nodiscard]] inline std::pair<int32_t, int32_t> power2round(int32_t r) noexcept {
    r = mod_q(r);
    // r0 = r mod 2^d (centered)
    int32_t r0 = r & ((1 << D) - 1);
    if (r0 > (1 << (D - 1))) {
        r0 -= (1 << D);
    }
    // r1 = (r - r0) / 2^d
    int32_t r1 = (r - r0) >> D;
    return {r1, r0};
}

/**
 * Algorithm 28: Decompose
 * Decompose r into (r1, r0) for signature scheme
 */
[[nodiscard]] inline std::pair<int32_t, int32_t> decompose(int32_t r, int32_t gamma2) noexcept {
    r = mod_q(r);

    // r0 = r mod (2*gamma2) centered
    int32_t two_gamma2 = 2 * gamma2;
    int32_t r0 = r % two_gamma2;
    if (r0 > gamma2) {
        r0 -= two_gamma2;
    }

    int32_t r1;
    // Handle special case
    if (r - r0 == Q - 1) {
        r1 = 0;
        r0 = r0 - 1;
    } else {
        r1 = (r - r0) / two_gamma2;
    }

    return {r1, r0};
}

/**
 * Algorithm 29: HighBits
 */
[[nodiscard]] inline int32_t high_bits(int32_t r, int32_t gamma2) noexcept {
    auto [r1, r0] = decompose(r, gamma2);
    return r1;
}

/**
 * Algorithm 30: LowBits
 */
[[nodiscard]] inline int32_t low_bits(int32_t r, int32_t gamma2) noexcept {
    auto [r1, r0] = decompose(r, gamma2);
    return r0;
}

/**
 * Algorithm 31: MakeHint
 */
[[nodiscard]] inline int32_t make_hint(int32_t z, int32_t r, int32_t gamma2) noexcept {
    int32_t r1 = high_bits(r, gamma2);
    int32_t v1 = high_bits(mod_q(r + z), gamma2);
    return (r1 != v1) ? 1 : 0;
}

/**
 * Algorithm 32: UseHint
 */
[[nodiscard]] inline int32_t use_hint(int32_t h, int32_t r, int32_t gamma2) noexcept {
    int32_t m = (Q - 1) / (2 * gamma2);
    auto [r1, r0] = decompose(r, gamma2);

    if (h == 1) {
        if (r0 > 0) {
            return (r1 + 1) % m;
        } else {
            return ((r1 - 1) % m + m) % m;
        }
    }
    return r1;
}

// Polynomial-level operations

[[nodiscard]] inline std::pair<std::vector<int32_t>, std::vector<int32_t>>
poly_power2round(std::span<const int32_t> w) {
    std::vector<int32_t> w1(N), w0(N);
    for (size_t i = 0; i < N; ++i) {
        auto [c1, c0] = power2round(w[i]);
        w1[i] = c1;
        w0[i] = c0;
    }
    return {std::move(w1), std::move(w0)};
}

[[nodiscard]] inline std::vector<int32_t> poly_high_bits(
    std::span<const int32_t> w, int32_t gamma2) {
    std::vector<int32_t> result(N);
    for (size_t i = 0; i < N; ++i) {
        result[i] = high_bits(w[i], gamma2);
    }
    return result;
}

[[nodiscard]] inline std::vector<int32_t> poly_low_bits(
    std::span<const int32_t> w, int32_t gamma2) {
    std::vector<int32_t> result(N);
    for (size_t i = 0; i < N; ++i) {
        result[i] = low_bits(w[i], gamma2);
    }
    return result;
}

[[nodiscard]] inline std::pair<std::vector<int32_t>, int> poly_make_hint(
    std::span<const int32_t> z, std::span<const int32_t> r, int32_t gamma2) {
    std::vector<int32_t> h(N);
    int count = 0;
    for (size_t i = 0; i < N; ++i) {
        h[i] = make_hint(z[i], r[i], gamma2);
        count += h[i];
    }
    return {std::move(h), count};
}

[[nodiscard]] inline std::vector<int32_t> poly_use_hint(
    std::span<const int32_t> h, std::span<const int32_t> r, int32_t gamma2) {
    std::vector<int32_t> result(N);
    for (size_t i = 0; i < N; ++i) {
        result[i] = use_hint(h[i], r[i], gamma2);
    }
    return result;
}

// Vector-level operations

[[nodiscard]] inline std::pair<std::vector<std::vector<int32_t>>, std::vector<std::vector<int32_t>>>
vec_power2round(const std::vector<std::vector<int32_t>>& v) {
    std::vector<std::vector<int32_t>> v1, v0;
    v1.reserve(v.size());
    v0.reserve(v.size());
    for (const auto& p : v) {
        auto [p1, p0] = poly_power2round(p);
        v1.push_back(std::move(p1));
        v0.push_back(std::move(p0));
    }
    return {std::move(v1), std::move(v0)};
}

[[nodiscard]] inline std::vector<std::vector<int32_t>> vec_high_bits(
    const std::vector<std::vector<int32_t>>& v, int32_t gamma2) {
    std::vector<std::vector<int32_t>> result;
    result.reserve(v.size());
    for (const auto& p : v) {
        result.push_back(poly_high_bits(p, gamma2));
    }
    return result;
}

[[nodiscard]] inline std::vector<std::vector<int32_t>> vec_low_bits(
    const std::vector<std::vector<int32_t>>& v, int32_t gamma2) {
    std::vector<std::vector<int32_t>> result;
    result.reserve(v.size());
    for (const auto& p : v) {
        result.push_back(poly_low_bits(p, gamma2));
    }
    return result;
}

[[nodiscard]] inline std::pair<std::vector<std::vector<int32_t>>, int> vec_make_hint(
    const std::vector<std::vector<int32_t>>& z,
    const std::vector<std::vector<int32_t>>& r,
    int32_t gamma2) {
    std::vector<std::vector<int32_t>> h;
    h.reserve(z.size());
    int total = 0;
    for (size_t i = 0; i < z.size(); ++i) {
        auto [hi, count] = poly_make_hint(z[i], r[i], gamma2);
        h.push_back(std::move(hi));
        total += count;
    }
    return {std::move(h), total};
}

[[nodiscard]] inline std::vector<std::vector<int32_t>> vec_use_hint(
    const std::vector<std::vector<int32_t>>& h,
    const std::vector<std::vector<int32_t>>& r,
    int32_t gamma2) {
    std::vector<std::vector<int32_t>> result;
    result.reserve(h.size());
    for (size_t i = 0; i < h.size(); ++i) {
        result.push_back(poly_use_hint(h[i], r[i], gamma2));
    }
    return result;
}

} // namespace mldsa

#endif // MLDSA_ENCODING_HPP
