/**
 * Utility functions for ML-KEM implementation
 * Based on FIPS 203
 */

#ifndef MLKEM_UTILS_HPP
#define MLKEM_UTILS_HPP

#include "params.hpp"
#include <cstdint>
#include <vector>
#include <array>
#include <span>
#include <cstring>

// Forward declare OpenSSL types
extern "C" {
    struct evp_md_ctx_st;
    typedef struct evp_md_ctx_st EVP_MD_CTX;
}

namespace mlkem {

/**
 * Reduce x modulo q to range [0, q)
 */
[[nodiscard]] inline constexpr int16_t mod_q(int32_t x) noexcept {
    int16_t r = static_cast<int16_t>(x % Q);
    if (r < 0) r += Q;
    return r;
}

/**
 * SHA3-256 hash function (H in FIPS 203)
 */
[[nodiscard]] std::vector<uint8_t> sha3_256(std::span<const uint8_t> data);

/**
 * SHA3-512 hash function (G in FIPS 203)
 */
[[nodiscard]] std::vector<uint8_t> sha3_512(std::span<const uint8_t> data);

/**
 * SHAKE128 XOF stream class (XOF in FIPS 203)
 */
class SHAKE128Stream {
public:
    explicit SHAKE128Stream(std::span<const uint8_t> data);
    ~SHAKE128Stream();

    SHAKE128Stream(const SHAKE128Stream&) = delete;
    SHAKE128Stream& operator=(const SHAKE128Stream&) = delete;
    SHAKE128Stream(SHAKE128Stream&&) noexcept;
    SHAKE128Stream& operator=(SHAKE128Stream&&) noexcept;

    std::vector<uint8_t> read(size_t n);

private:
    EVP_MD_CTX* ctx_ = nullptr;
    std::vector<uint8_t> buffer_;
    size_t buffer_pos_ = 0;
    std::vector<uint8_t> seed_;
    bool finalized_ = false;
};

/**
 * SHAKE256 XOF stream class (J and PRF in FIPS 203)
 */
class SHAKE256Stream {
public:
    explicit SHAKE256Stream(std::span<const uint8_t> data);
    ~SHAKE256Stream();

    SHAKE256Stream(const SHAKE256Stream&) = delete;
    SHAKE256Stream& operator=(const SHAKE256Stream&) = delete;
    SHAKE256Stream(SHAKE256Stream&&) noexcept;
    SHAKE256Stream& operator=(SHAKE256Stream&&) noexcept;

    std::vector<uint8_t> read(size_t n);

private:
    EVP_MD_CTX* ctx_ = nullptr;
    std::vector<uint8_t> buffer_;
    size_t buffer_pos_ = 0;
    std::vector<uint8_t> seed_;
    bool finalized_ = false;
};

/**
 * SHAKE128 XOF function
 */
[[nodiscard]] std::vector<uint8_t> shake128(
    std::span<const uint8_t> data, size_t output_len);

/**
 * SHAKE256 XOF function
 */
[[nodiscard]] std::vector<uint8_t> shake256(
    std::span<const uint8_t> data, size_t output_len);

/**
 * Generate cryptographically secure random bytes
 */
[[nodiscard]] std::vector<uint8_t> random_bytes(size_t n);

/**
 * PRF function: SHAKE256(s || b, 64*eta)
 * Used for generating secret polynomials
 */
[[nodiscard]] inline std::vector<uint8_t> prf(
    std::span<const uint8_t> s, uint8_t b, size_t output_len) {
    std::vector<uint8_t> input(s.begin(), s.end());
    input.push_back(b);
    return shake256(input, output_len);
}

/**
 * XOF function: SHAKE128(rho || i || j)
 * Used for generating matrix A
 */
[[nodiscard]] inline SHAKE128Stream xof(
    std::span<const uint8_t> rho, uint8_t i, uint8_t j) {
    std::vector<uint8_t> input(rho.begin(), rho.end());
    input.push_back(i);
    input.push_back(j);
    return SHAKE128Stream(input);
}

/**
 * H function: SHA3-256
 */
[[nodiscard]] inline std::vector<uint8_t> H(std::span<const uint8_t> data) {
    return sha3_256(data);
}

/**
 * G function: SHA3-512
 */
[[nodiscard]] inline std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
G(std::span<const uint8_t> data) {
    auto hash = sha3_512(data);
    std::vector<uint8_t> first(hash.begin(), hash.begin() + 32);
    std::vector<uint8_t> second(hash.begin() + 32, hash.end());
    return {std::move(first), std::move(second)};
}

/**
 * J function: SHAKE256(s, 32)
 * Used for implicit rejection
 */
[[nodiscard]] inline std::vector<uint8_t> J(std::span<const uint8_t> data) {
    return shake256(data, 32);
}

} // namespace mlkem

#endif // MLKEM_UTILS_HPP
