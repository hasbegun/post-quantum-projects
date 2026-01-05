/**
 * Byte Encoding and Decoding for ML-KEM
 * Based on FIPS 203 Algorithms 4-6
 */

#ifndef MLKEM_ENCODE_HPP
#define MLKEM_ENCODE_HPP

#include "params.hpp"
#include "ntt.hpp"
#include <vector>
#include <span>
#include <cstdint>
#include <stdexcept>

namespace mlkem {

/**
 * Convert coefficient to canonical form [0, q)
 * Handles negative values by adding q
 */
[[nodiscard]] inline int16_t to_positive_mod_q(int16_t a) noexcept {
    // Add Q if negative, then reduce if >= Q
    a += (a >> 15) & Q;
    a -= Q;
    a += (a >> 15) & Q;
    return a;
}

/**
 * Algorithm 4: ByteEncode_d
 * Encode polynomial coefficients to bytes
 *
 * Each coefficient is encoded as d bits (LSB first).
 * For d=12: encodes uncompressed coefficients
 * For d<12: encodes compressed coefficients
 */
[[nodiscard]] inline std::vector<uint8_t> byte_encode(const Poly& f, int d) {
    std::vector<uint8_t> result(32 * d);

    if (d == 12) {
        // Special case for d=12: 2 coefficients per 3 bytes
        // Need to handle negative coefficients (e.g., from CBD sampling)
        for (size_t i = 0; i < N / 2; ++i) {
            uint16_t a = static_cast<uint16_t>(to_positive_mod_q(f[2 * i]));
            uint16_t b = static_cast<uint16_t>(to_positive_mod_q(f[2 * i + 1]));

            result[3 * i] = static_cast<uint8_t>(a);
            result[3 * i + 1] = static_cast<uint8_t>((a >> 8) | (b << 4));
            result[3 * i + 2] = static_cast<uint8_t>(b >> 4);
        }
    } else if (d == 10) {
        // 4 coefficients per 5 bytes
        for (size_t i = 0; i < N / 4; ++i) {
            uint16_t a = static_cast<uint16_t>(f[4 * i]);
            uint16_t b = static_cast<uint16_t>(f[4 * i + 1]);
            uint16_t c = static_cast<uint16_t>(f[4 * i + 2]);
            uint16_t d_coef = static_cast<uint16_t>(f[4 * i + 3]);

            result[5 * i] = static_cast<uint8_t>(a);
            result[5 * i + 1] = static_cast<uint8_t>((a >> 8) | (b << 2));
            result[5 * i + 2] = static_cast<uint8_t>((b >> 6) | (c << 4));
            result[5 * i + 3] = static_cast<uint8_t>((c >> 4) | (d_coef << 6));
            result[5 * i + 4] = static_cast<uint8_t>(d_coef >> 2);
        }
    } else if (d == 11) {
        // 8 coefficients per 11 bytes
        for (size_t i = 0; i < N / 8; ++i) {
            uint16_t t[8];
            for (int j = 0; j < 8; ++j) {
                t[j] = static_cast<uint16_t>(f[8 * i + j]);
            }

            result[11 * i + 0] = static_cast<uint8_t>(t[0]);
            result[11 * i + 1] = static_cast<uint8_t>((t[0] >> 8) | (t[1] << 3));
            result[11 * i + 2] = static_cast<uint8_t>((t[1] >> 5) | (t[2] << 6));
            result[11 * i + 3] = static_cast<uint8_t>(t[2] >> 2);
            result[11 * i + 4] = static_cast<uint8_t>((t[2] >> 10) | (t[3] << 1));
            result[11 * i + 5] = static_cast<uint8_t>((t[3] >> 7) | (t[4] << 4));
            result[11 * i + 6] = static_cast<uint8_t>((t[4] >> 4) | (t[5] << 7));
            result[11 * i + 7] = static_cast<uint8_t>(t[5] >> 1);
            result[11 * i + 8] = static_cast<uint8_t>((t[5] >> 9) | (t[6] << 2));
            result[11 * i + 9] = static_cast<uint8_t>((t[6] >> 6) | (t[7] << 5));
            result[11 * i + 10] = static_cast<uint8_t>(t[7] >> 3);
        }
    } else if (d == 4) {
        // 2 coefficients per byte
        for (size_t i = 0; i < N / 2; ++i) {
            result[i] = static_cast<uint8_t>(f[2 * i] | (f[2 * i + 1] << 4));
        }
    } else if (d == 5) {
        // 8 coefficients per 5 bytes
        for (size_t i = 0; i < N / 8; ++i) {
            uint8_t t[8];
            for (int j = 0; j < 8; ++j) {
                t[j] = static_cast<uint8_t>(f[8 * i + j]);
            }

            result[5 * i + 0] = static_cast<uint8_t>(t[0] | (t[1] << 5));
            result[5 * i + 1] = static_cast<uint8_t>((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
            result[5 * i + 2] = static_cast<uint8_t>((t[3] >> 1) | (t[4] << 4));
            result[5 * i + 3] = static_cast<uint8_t>((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
            result[5 * i + 4] = static_cast<uint8_t>((t[6] >> 2) | (t[7] << 3));
        }
    } else if (d == 1) {
        // 8 coefficients per byte
        for (size_t i = 0; i < N / 8; ++i) {
            uint8_t byte = 0;
            for (int j = 0; j < 8; ++j) {
                byte |= static_cast<uint8_t>((f[8 * i + j] & 1) << j);
            }
            result[i] = byte;
        }
    } else {
        throw std::invalid_argument("Unsupported bit width d=" + std::to_string(d));
    }

    return result;
}

/**
 * Algorithm 5: ByteDecode_d
 * Decode bytes to polynomial coefficients
 *
 * Each coefficient is decoded from d bits (LSB first).
 */
[[nodiscard]] inline Poly byte_decode(std::span<const uint8_t> b, int d) {
    Poly f{};

    if (d == 12) {
        // 2 coefficients per 3 bytes
        for (size_t i = 0; i < N / 2; ++i) {
            f[2 * i] = static_cast<int16_t>(
                (static_cast<uint16_t>(b[3 * i]) |
                 (static_cast<uint16_t>(b[3 * i + 1] & 0x0F) << 8)));
            f[2 * i + 1] = static_cast<int16_t>(
                ((static_cast<uint16_t>(b[3 * i + 1]) >> 4) |
                 (static_cast<uint16_t>(b[3 * i + 2]) << 4)));
        }
    } else if (d == 10) {
        // 4 coefficients per 5 bytes
        for (size_t i = 0; i < N / 4; ++i) {
            f[4 * i] = static_cast<int16_t>(
                (static_cast<uint16_t>(b[5 * i]) |
                 (static_cast<uint16_t>(b[5 * i + 1] & 0x03) << 8)));
            f[4 * i + 1] = static_cast<int16_t>(
                ((static_cast<uint16_t>(b[5 * i + 1]) >> 2) |
                 (static_cast<uint16_t>(b[5 * i + 2] & 0x0F) << 6)));
            f[4 * i + 2] = static_cast<int16_t>(
                ((static_cast<uint16_t>(b[5 * i + 2]) >> 4) |
                 (static_cast<uint16_t>(b[5 * i + 3] & 0x3F) << 4)));
            f[4 * i + 3] = static_cast<int16_t>(
                ((static_cast<uint16_t>(b[5 * i + 3]) >> 6) |
                 (static_cast<uint16_t>(b[5 * i + 4]) << 2)));
        }
    } else if (d == 11) {
        // 8 coefficients per 11 bytes
        for (size_t i = 0; i < N / 8; ++i) {
            f[8 * i + 0] = static_cast<int16_t>(
                (static_cast<uint16_t>(b[11 * i + 0]) |
                 (static_cast<uint16_t>(b[11 * i + 1] & 0x07) << 8)));
            f[8 * i + 1] = static_cast<int16_t>(
                ((static_cast<uint16_t>(b[11 * i + 1]) >> 3) |
                 (static_cast<uint16_t>(b[11 * i + 2] & 0x3F) << 5)));
            f[8 * i + 2] = static_cast<int16_t>(
                ((static_cast<uint16_t>(b[11 * i + 2]) >> 6) |
                 (static_cast<uint16_t>(b[11 * i + 3]) << 2) |
                 (static_cast<uint16_t>(b[11 * i + 4] & 0x01) << 10)));
            f[8 * i + 3] = static_cast<int16_t>(
                ((static_cast<uint16_t>(b[11 * i + 4]) >> 1) |
                 (static_cast<uint16_t>(b[11 * i + 5] & 0x0F) << 7)));
            f[8 * i + 4] = static_cast<int16_t>(
                ((static_cast<uint16_t>(b[11 * i + 5]) >> 4) |
                 (static_cast<uint16_t>(b[11 * i + 6] & 0x7F) << 4)));
            f[8 * i + 5] = static_cast<int16_t>(
                ((static_cast<uint16_t>(b[11 * i + 6]) >> 7) |
                 (static_cast<uint16_t>(b[11 * i + 7]) << 1) |
                 (static_cast<uint16_t>(b[11 * i + 8] & 0x03) << 9)));
            f[8 * i + 6] = static_cast<int16_t>(
                ((static_cast<uint16_t>(b[11 * i + 8]) >> 2) |
                 (static_cast<uint16_t>(b[11 * i + 9] & 0x1F) << 6)));
            f[8 * i + 7] = static_cast<int16_t>(
                ((static_cast<uint16_t>(b[11 * i + 9]) >> 5) |
                 (static_cast<uint16_t>(b[11 * i + 10]) << 3)));
        }
    } else if (d == 4) {
        // 2 coefficients per byte
        for (size_t i = 0; i < N / 2; ++i) {
            f[2 * i] = static_cast<int16_t>(b[i] & 0x0F);
            f[2 * i + 1] = static_cast<int16_t>(b[i] >> 4);
        }
    } else if (d == 5) {
        // 8 coefficients per 5 bytes
        for (size_t i = 0; i < N / 8; ++i) {
            f[8 * i + 0] = static_cast<int16_t>(b[5 * i + 0] & 0x1F);
            f[8 * i + 1] = static_cast<int16_t>(
                ((b[5 * i + 0] >> 5) | ((b[5 * i + 1] & 0x03) << 3)));
            f[8 * i + 2] = static_cast<int16_t>((b[5 * i + 1] >> 2) & 0x1F);
            f[8 * i + 3] = static_cast<int16_t>(
                ((b[5 * i + 1] >> 7) | ((b[5 * i + 2] & 0x0F) << 1)));
            f[8 * i + 4] = static_cast<int16_t>(
                ((b[5 * i + 2] >> 4) | ((b[5 * i + 3] & 0x01) << 4)));
            f[8 * i + 5] = static_cast<int16_t>((b[5 * i + 3] >> 1) & 0x1F);
            f[8 * i + 6] = static_cast<int16_t>(
                ((b[5 * i + 3] >> 6) | ((b[5 * i + 4] & 0x07) << 2)));
            f[8 * i + 7] = static_cast<int16_t>(b[5 * i + 4] >> 3);
        }
    } else if (d == 1) {
        // 8 coefficients per byte
        for (size_t i = 0; i < N / 8; ++i) {
            for (int j = 0; j < 8; ++j) {
                f[8 * i + j] = static_cast<int16_t>((b[i] >> j) & 1);
            }
        }
    } else {
        throw std::invalid_argument("Unsupported bit width d=" + std::to_string(d));
    }

    return f;
}

/**
 * Encode vector of polynomials
 */
[[nodiscard]] inline std::vector<uint8_t> encode_vec(const PolyVec& v, int d) {
    std::vector<uint8_t> result;
    result.reserve(v.size() * 32 * d);
    for (const auto& p : v) {
        auto encoded = byte_encode(p, d);
        result.insert(result.end(), encoded.begin(), encoded.end());
    }
    return result;
}

/**
 * Decode bytes to vector of polynomials
 */
[[nodiscard]] inline PolyVec decode_vec(std::span<const uint8_t> b, int k, int d) {
    PolyVec result;
    result.reserve(k);
    size_t poly_bytes = 32 * d;
    for (int i = 0; i < k; ++i) {
        result.push_back(byte_decode(b.subspan(i * poly_bytes, poly_bytes), d));
    }
    return result;
}

} // namespace mlkem

#endif // MLKEM_ENCODE_HPP
