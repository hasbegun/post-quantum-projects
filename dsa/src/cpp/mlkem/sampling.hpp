/**
 * Sampling Functions for ML-KEM
 * Based on FIPS 203 Algorithms 7-8
 */

#ifndef MLKEM_SAMPLING_HPP
#define MLKEM_SAMPLING_HPP

#include "params.hpp"
#include "ntt.hpp"
#include "utils.hpp"
#include <vector>
#include <span>
#include <cstdint>

namespace mlkem {

/**
 * Algorithm 7: SampleNTT
 * Sample polynomial uniformly in NTT domain from XOF stream
 *
 * Uses rejection sampling to generate 256 coefficients uniformly
 * distributed in [0, q). The input stream is SHAKE128(rho || i || j).
 */
[[nodiscard]] inline Poly sample_ntt(SHAKE128Stream& stream) {
    Poly a_hat{};
    size_t j = 0;

    while (j < N) {
        auto bytes = stream.read(3);
        uint16_t d1 = static_cast<uint16_t>(bytes[0]) |
                      (static_cast<uint16_t>(bytes[1] & 0x0F) << 8);
        uint16_t d2 = (static_cast<uint16_t>(bytes[1]) >> 4) |
                      (static_cast<uint16_t>(bytes[2]) << 4);

        if (d1 < Q) {
            a_hat[j++] = static_cast<int16_t>(d1);
        }
        if (d2 < Q && j < N) {
            a_hat[j++] = static_cast<int16_t>(d2);
        }
    }

    return a_hat;
}

/**
 * Algorithm 8: SamplePolyCBD_eta
 * Sample polynomial from centered binomial distribution
 *
 * Each coefficient is sampled as the difference of two binomial samples.
 * For eta=2: coefficients in [-2, 2]
 * For eta=3: coefficients in [-3, 3]
 */
[[nodiscard]] inline Poly sample_poly_cbd(std::span<const uint8_t> b, int eta) {
    Poly f{};

    if (eta == 2) {
        // Each coefficient from 1 byte: sum of 4 bits - sum of 4 bits
        for (size_t i = 0; i < N / 2; ++i) {
            uint8_t t = b[i];

            // First coefficient: bits 0-1 minus bits 4-5 (packed as bits 0,1,4,5)
            int16_t a = static_cast<int16_t>((t & 0x03) + ((t >> 2) & 0x03));
            int16_t b_val = static_cast<int16_t>(((t >> 4) & 0x03) + ((t >> 6) & 0x03));

            // Interpret as: (bit0 + bit1) - (bit2 + bit3) for first coef
            // Actually for CBD_2, we need 4 bytes for 2 coefficients
            // Let me re-read the spec...
        }

        // Correct implementation for eta=2:
        // 64 * eta = 128 bytes for 256 coefficients
        // Each coefficient uses 4 bits (2 for x, 2 for y), so 1 byte per 2 coefficients
        for (size_t i = 0; i < N; ++i) {
            size_t byte_idx = i / 2;
            size_t bit_offset = (i % 2) * 4;

            uint8_t t = (b[byte_idx] >> bit_offset) & 0x0F;
            int16_t x = static_cast<int16_t>((t & 1) + ((t >> 1) & 1));
            int16_t y = static_cast<int16_t>(((t >> 2) & 1) + ((t >> 3) & 1));
            f[i] = x - y;
        }
    } else if (eta == 3) {
        // 64 * eta = 192 bytes for 256 coefficients
        // Each coefficient uses 6 bits (3 for x, 3 for y)
        // 4 coefficients per 3 bytes
        for (size_t i = 0; i < N / 4; ++i) {
            uint32_t t = static_cast<uint32_t>(b[3 * i]) |
                        (static_cast<uint32_t>(b[3 * i + 1]) << 8) |
                        (static_cast<uint32_t>(b[3 * i + 2]) << 16);

            for (int j = 0; j < 4; ++j) {
                uint8_t a = (t >> (6 * j)) & 0x07;
                uint8_t b_val = (t >> (6 * j + 3)) & 0x07;

                int16_t x = static_cast<int16_t>((a & 1) + ((a >> 1) & 1) + ((a >> 2) & 1));
                int16_t y = static_cast<int16_t>((b_val & 1) + ((b_val >> 1) & 1) + ((b_val >> 2) & 1));

                f[4 * i + j] = x - y;
            }
        }
    }

    return f;
}

/**
 * Expand matrix A from seed rho
 * A is k x k matrix of polynomials in NTT domain
 */
[[nodiscard]] inline PolyMat expand_a(std::span<const uint8_t> rho, int k) {
    PolyMat A_hat;
    A_hat.reserve(k);

    for (int i = 0; i < k; ++i) {
        PolyVec row;
        row.reserve(k);
        for (int j = 0; j < k; ++j) {
            auto stream = xof(rho, static_cast<uint8_t>(j), static_cast<uint8_t>(i));
            row.push_back(sample_ntt(stream));
        }
        A_hat.push_back(std::move(row));
    }

    return A_hat;
}

/**
 * Sample secret vector s from CBD
 * s is length k vector of polynomials with small coefficients
 */
[[nodiscard]] inline PolyVec sample_secret(
    std::span<const uint8_t> sigma, int k, int eta, uint8_t offset = 0) {

    PolyVec s;
    s.reserve(k);

    size_t prf_output_len = 64 * eta;

    for (int i = 0; i < k; ++i) {
        auto bytes = prf(sigma, offset + i, prf_output_len);
        s.push_back(sample_poly_cbd(bytes, eta));
    }

    return s;
}

/**
 * Sample error vector e from CBD
 * e is length k vector of polynomials with small coefficients
 */
[[nodiscard]] inline PolyVec sample_error(
    std::span<const uint8_t> sigma, int k, int eta, uint8_t offset = 0) {

    return sample_secret(sigma, k, eta, offset);
}

} // namespace mlkem

#endif // MLKEM_SAMPLING_HPP
