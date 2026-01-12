/**
 * Sampling functions for ML-DSA
 * Based on FIPS 204 Algorithms 35-49
 *
 * SECURITY: Uses constant-time operations to resist timing side-channels.
 */

#ifndef MLDSA_SAMPLING_HPP
#define MLDSA_SAMPLING_HPP

#include "params.hpp"
#include "utils.hpp"
#include "ntt.hpp"
#include "../ct_utils.hpp"
#include <vector>
#include <span>

namespace mldsa {

/**
 * Algorithm 35: SampleInBall - CONSTANT TIME VERSION
 *
 * Sample polynomial with exactly tau +/-1 coefficients.
 *
 * SECURITY: Uses fixed-iteration rejection sampling to prevent timing leaks.
 * Pre-generates random data and processes a constant number of candidates
 * per position using constant-time selection.
 *
 * @param rho Seed for SHAKE256
 * @param tau Number of non-zero coefficients
 * @return Polynomial with exactly tau coefficients in {-1, +1}
 */
[[nodiscard]] inline std::vector<int32_t> sample_in_ball(
    std::span<const uint8_t> rho, int tau) {

    // Maximum rejection sampling iterations per position
    // With MAX_TRIES=16 and worst-case acceptance prob ~0.77 (at i=196),
    // failure probability is ~(0.23)^16 ≈ 10^-10 (negligible)
    constexpr int MAX_TRIES = 16;

    std::vector<int32_t> c(N, 0);
    SHAKE256Stream xof(rho);

    // Use first 8 bytes for sign bits
    auto sign_bytes = xof.read(8);
    uint64_t signs = 0;
    for (int i = 0; i < 8; ++i) {
        signs |= static_cast<uint64_t>(sign_bytes[i]) << (8 * i);
    }

    // Pre-generate all random bytes needed for constant-time processing
    auto random_data = xof.read(tau * MAX_TRIES);

    int k = 0;
    size_t rand_idx = 0;

    for (int i = N - tau; i < static_cast<int>(N); ++i) {
        // Constant-time rejection sampling:
        // Process exactly MAX_TRIES candidates for each position
        uint32_t selected_j = 0;
        uint32_t found = 0;  // 0 = not found, 1 = found

        for (int try_idx = 0; try_idx < MAX_TRIES; ++try_idx) {
            uint32_t candidate = random_data[rand_idx++];

            // is_valid = 1 if candidate <= i (constant-time comparison)
            uint32_t is_valid = ct::ge_u32(static_cast<uint32_t>(i), candidate);

            // Update only if valid AND not yet found (constant-time)
            // accept = is_valid AND NOT found = is_valid * (1 - found)
            uint32_t accept = is_valid & (1 - found);

            // Constant-time selection using arithmetic mask
            // mask = 0 - accept (all zeros if accept=0, all ones if accept=1)
            uint32_t mask = 0 - accept;
            selected_j = (candidate & mask) | (selected_j & ~mask);

            // Update found flag (constant-time OR)
            // Once found is 1, it stays 1
            volatile uint32_t new_found = found | is_valid;
            ct::barrier();
            found = new_found;
        }

        // Fisher-Yates shuffle step with selected_j
        c[i] = c[selected_j];
        c[selected_j] = 1 - 2 * static_cast<int32_t>((signs >> k) & 1);  // +1 or -1
        ++k;
    }

    return c;
}

/**
 * Algorithm 36: RejNTTPoly
 * Sample uniform polynomial in NTT domain using rejection sampling
 */
[[nodiscard]] inline std::vector<int32_t> rej_ntt_poly(std::span<const uint8_t> rho) {
    std::vector<int32_t> a_hat(N);
    SHAKE128Stream xof(rho);
    size_t j = 0;

    while (j < N) {
        auto b = xof.read(3);
        auto coef = coef_from_three_bytes(b[0], b[1], b[2]);
        if (coef) {
            a_hat[j++] = *coef;
        }
    }

    return a_hat;
}

/**
 * Algorithm 37: RejBoundedPoly
 * Sample polynomial with bounded coefficients using rejection sampling
 */
[[nodiscard]] inline std::vector<int32_t> rej_bounded_poly(
    std::span<const uint8_t> rho, int eta) {

    std::vector<int32_t> a(N);
    SHAKE256Stream xof(rho);
    size_t j = 0;

    while (j < N) {
        auto b = xof.read(1);
        uint8_t b0 = b[0] & 0x0F;
        uint8_t b1 = (b[0] >> 4) & 0x0F;

        auto coef0 = coef_from_half_byte(b0, eta);
        if (coef0 && j < N) {
            a[j++] = *coef0;
        }

        auto coef1 = coef_from_half_byte(b1, eta);
        if (coef1 && j < N) {
            a[j++] = *coef1;
        }
    }

    return a;
}

/**
 * Algorithm 38: ExpandA
 * Expand seed to k x l matrix of polynomials in NTT domain
 */
[[nodiscard]] inline PolyMat expand_a(
    std::span<const uint8_t> rho, const Params& params) {

    PolyMat A_hat;
    A_hat.reserve(params.k);

    for (int r = 0; r < params.k; ++r) {
        PolyVec row;
        row.reserve(params.l);
        for (int s = 0; s < params.l; ++s) {
            // Append index bytes to rho
            std::vector<uint8_t> seed(rho.begin(), rho.end());
            seed.push_back(static_cast<uint8_t>(s));
            seed.push_back(static_cast<uint8_t>(r));

            auto a_hat = rej_ntt_poly(seed);
            Poly poly{};
            std::copy(a_hat.begin(), a_hat.end(), poly.begin());
            row.push_back(poly);
        }
        A_hat.push_back(std::move(row));
    }

    return A_hat;
}

/**
 * Algorithm 39: ExpandS
 * Expand seed to secret vectors s1 and s2
 */
[[nodiscard]] inline std::pair<std::vector<std::vector<int32_t>>, std::vector<std::vector<int32_t>>>
expand_s(std::span<const uint8_t> rho, const Params& params) {

    std::vector<std::vector<int32_t>> s1, s2;
    s1.reserve(params.l);
    s2.reserve(params.k);

    for (int r = 0; r < params.l; ++r) {
        std::vector<uint8_t> seed(rho.begin(), rho.end());
        seed.push_back(static_cast<uint8_t>(r & 0xFF));
        seed.push_back(static_cast<uint8_t>(r >> 8));
        s1.push_back(rej_bounded_poly(seed, params.eta));
    }

    for (int r = 0; r < params.k; ++r) {
        int counter = params.l + r;
        std::vector<uint8_t> seed(rho.begin(), rho.end());
        seed.push_back(static_cast<uint8_t>(counter & 0xFF));
        seed.push_back(static_cast<uint8_t>(counter >> 8));
        s2.push_back(rej_bounded_poly(seed, params.eta));
    }

    return {std::move(s1), std::move(s2)};
}

/**
 * Algorithm 40: ExpandMask
 * Expand seed to masking vector y
 */
[[nodiscard]] inline std::vector<std::vector<int32_t>> expand_mask(
    std::span<const uint8_t> rho, int mu, const Params& params) {

    int32_t gamma1 = params.gamma1;
    int gamma1_bits = (gamma1 == (1 << 17)) ? 18 : 20;

    std::vector<std::vector<int32_t>> y;
    y.reserve(params.l);

    for (int r = 0; r < params.l; ++r) {
        int counter = mu + r;
        std::vector<uint8_t> seed(rho.begin(), rho.end());
        seed.push_back(static_cast<uint8_t>(counter & 0xFF));
        seed.push_back(static_cast<uint8_t>((counter >> 8) & 0xFF));

        // Generate bytes for polynomial
        size_t bytes_needed = 32 * gamma1_bits;
        auto v = shake256_xof(seed, bytes_needed);

        // Unpack using BitUnpack
        std::vector<uint8_t> bits;
        bits.reserve(v.size() * 8);
        for (uint8_t byte : v) {
            for (int bit_idx = 0; bit_idx < 8; ++bit_idx) {
                bits.push_back((byte >> bit_idx) & 1);
            }
        }

        std::vector<int32_t> poly(N);
        for (size_t i = 0; i < N; ++i) {
            int32_t val = 0;
            for (int j = 0; j < gamma1_bits; ++j) {
                size_t idx = i * gamma1_bits + j;
                if (idx < bits.size()) {
                    val |= static_cast<int32_t>(bits[idx]) << j;
                }
            }
            poly[i] = gamma1 - val;
        }

        y.push_back(std::move(poly));
    }

    return y;
}

/**
 * H function: SHAKE256 XOF
 */
[[nodiscard]] inline std::vector<uint8_t> h_function(
    std::span<const uint8_t> seed, size_t output_len) {
    return shake256_xof(seed, output_len);
}

/**
 * Encode w1 for challenge hash computation
 */
[[nodiscard]] inline std::vector<uint8_t> w1_encode(
    const std::vector<std::vector<int32_t>>& w1, const Params& params) {

    int32_t gamma2 = params.gamma2;
    std::vector<uint8_t> result;

    if (gamma2 == (Q - 1) / 88) {
        // 6 bits per coefficient
        for (const auto& poly : w1) {
            std::vector<uint8_t> bits;
            bits.reserve(N * 6);
            for (int32_t coef : poly) {
                for (int j = 0; j < 6; ++j) {
                    bits.push_back((coef >> j) & 1);
                }
            }
            // Pack bits to bytes
            for (size_t i = 0; i < bits.size() / 8; ++i) {
                uint8_t byte = 0;
                for (int j = 0; j < 8; ++j) {
                    byte |= bits[i * 8 + j] << j;
                }
                result.push_back(byte);
            }
        }
    } else {
        // gamma2 = (q-1)/32, 4 bits per coefficient
        for (const auto& poly : w1) {
            for (size_t i = 0; i < N; i += 2) {
                uint8_t byte = (poly[i] & 0x0F) | ((poly[i + 1] & 0x0F) << 4);
                result.push_back(byte);
            }
        }
    }

    return result;
}

/**
 * Compute tr = H(pk, 64) = SHAKE256(pk, 64)
 */
[[nodiscard]] inline std::vector<uint8_t> compute_tr(std::span<const uint8_t> pk) {
    return shake256_xof(pk, 64);
}

/**
 * Compute mu = H(tr || M', 64)
 */
[[nodiscard]] inline std::vector<uint8_t> compute_mu(
    std::span<const uint8_t> tr, std::span<const uint8_t> M_prime) {
    std::vector<uint8_t> data(tr.begin(), tr.end());
    data.insert(data.end(), M_prime.begin(), M_prime.end());
    return shake256_xof(data, 64);
}

} // namespace mldsa

#endif // MLDSA_SAMPLING_HPP
