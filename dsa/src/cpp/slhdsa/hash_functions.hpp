/**
 * SLH-DSA Hash Function Instantiations (FIPS 205 Sections 11.1 and 11.2)
 *
 * Implements the hash functions for both SHAKE and SHA2 variants.
 */

#ifndef SLHDSA_HASH_FUNCTIONS_HPP
#define SLHDSA_HASH_FUNCTIONS_HPP

#include "params.hpp"
#include "address.hpp"
#include <vector>
#include <span>
#include <memory>
#include <cstdint>

namespace slhdsa {

/**
 * Abstract base class for SLH-DSA hash function instantiations.
 */
class HashFunctions {
public:
    explicit HashFunctions(const Params& params) : params_(params), n_(params.n) {}
    virtual ~HashFunctions() = default;

    // Prevent copying
    HashFunctions(const HashFunctions&) = delete;
    HashFunctions& operator=(const HashFunctions&) = delete;

    // Allow moving
    HashFunctions(HashFunctions&&) = default;
    HashFunctions& operator=(HashFunctions&&) = default;

    /**
     * H_msg: Hash message to produce m-byte digest
     */
    [[nodiscard]] virtual std::vector<uint8_t> H_msg(
        std::span<const uint8_t> R,
        std::span<const uint8_t> pk_seed,
        std::span<const uint8_t> pk_root,
        std::span<const uint8_t> M) const = 0;

    /**
     * PRF_msg: PRF for randomizing message hash
     */
    [[nodiscard]] virtual std::vector<uint8_t> PRF_msg(
        std::span<const uint8_t> sk_prf,
        std::span<const uint8_t> opt_rand,
        std::span<const uint8_t> M) const = 0;

    /**
     * PRF: PRF for generating secret values
     */
    [[nodiscard]] virtual std::vector<uint8_t> PRF(
        std::span<const uint8_t> pk_seed,
        std::span<const uint8_t> sk_seed,
        const ADRS& adrs) const = 0;

    /**
     * F: Tweakable hash function (single n-byte input)
     */
    [[nodiscard]] virtual std::vector<uint8_t> F(
        std::span<const uint8_t> pk_seed,
        const ADRS& adrs,
        std::span<const uint8_t> M1) const = 0;

    /**
     * H: Tweakable hash function (two n-byte inputs concatenated)
     */
    [[nodiscard]] virtual std::vector<uint8_t> H(
        std::span<const uint8_t> pk_seed,
        const ADRS& adrs,
        std::span<const uint8_t> M2) const = 0;

    /**
     * T_l: Tweakable hash function (l n-byte inputs concatenated)
     */
    [[nodiscard]] virtual std::vector<uint8_t> T_l(
        std::span<const uint8_t> pk_seed,
        const ADRS& adrs,
        std::span<const uint8_t> M_l) const = 0;

    [[nodiscard]] const Params& params() const noexcept { return params_; }
    [[nodiscard]] size_t n() const noexcept { return n_; }

protected:
    const Params& params_;
    size_t n_;
};

/**
 * SHAKE-based hash functions (FIPS 205 Section 11.1)
 *
 * Uses SHAKE256 for all operations.
 */
class SHAKEHashFunctions : public HashFunctions {
public:
    explicit SHAKEHashFunctions(const Params& params);

    [[nodiscard]] std::vector<uint8_t> H_msg(
        std::span<const uint8_t> R,
        std::span<const uint8_t> pk_seed,
        std::span<const uint8_t> pk_root,
        std::span<const uint8_t> M) const override;

    [[nodiscard]] std::vector<uint8_t> PRF_msg(
        std::span<const uint8_t> sk_prf,
        std::span<const uint8_t> opt_rand,
        std::span<const uint8_t> M) const override;

    [[nodiscard]] std::vector<uint8_t> PRF(
        std::span<const uint8_t> pk_seed,
        std::span<const uint8_t> sk_seed,
        const ADRS& adrs) const override;

    [[nodiscard]] std::vector<uint8_t> F(
        std::span<const uint8_t> pk_seed,
        const ADRS& adrs,
        std::span<const uint8_t> M1) const override;

    [[nodiscard]] std::vector<uint8_t> H(
        std::span<const uint8_t> pk_seed,
        const ADRS& adrs,
        std::span<const uint8_t> M2) const override;

    [[nodiscard]] std::vector<uint8_t> T_l(
        std::span<const uint8_t> pk_seed,
        const ADRS& adrs,
        std::span<const uint8_t> M_l) const override;
};

/**
 * SHA2-based hash functions (FIPS 205 Section 11.2)
 *
 * Uses SHA-256 for n=16, SHA-512 for n=24 and n=32.
 */
class SHA2HashFunctions : public HashFunctions {
public:
    explicit SHA2HashFunctions(const Params& params);

    [[nodiscard]] std::vector<uint8_t> H_msg(
        std::span<const uint8_t> R,
        std::span<const uint8_t> pk_seed,
        std::span<const uint8_t> pk_root,
        std::span<const uint8_t> M) const override;

    [[nodiscard]] std::vector<uint8_t> PRF_msg(
        std::span<const uint8_t> sk_prf,
        std::span<const uint8_t> opt_rand,
        std::span<const uint8_t> M) const override;

    [[nodiscard]] std::vector<uint8_t> PRF(
        std::span<const uint8_t> pk_seed,
        std::span<const uint8_t> sk_seed,
        const ADRS& adrs) const override;

    [[nodiscard]] std::vector<uint8_t> F(
        std::span<const uint8_t> pk_seed,
        const ADRS& adrs,
        std::span<const uint8_t> M1) const override;

    [[nodiscard]] std::vector<uint8_t> H(
        std::span<const uint8_t> pk_seed,
        const ADRS& adrs,
        std::span<const uint8_t> M2) const override;

    [[nodiscard]] std::vector<uint8_t> T_l(
        std::span<const uint8_t> pk_seed,
        const ADRS& adrs,
        std::span<const uint8_t> M_l) const override;

private:
    bool use_sha512_;  // true for n=24 or n=32, false for n=16
    size_t block_size_;  // 64 for SHA-256, 128 for SHA-512

    [[nodiscard]] std::vector<uint8_t> mgf1(
        std::span<const uint8_t> seed, size_t length) const;

    [[nodiscard]] std::vector<uint8_t> hmac(
        std::span<const uint8_t> key,
        std::span<const uint8_t> data) const;

    [[nodiscard]] std::vector<uint8_t> hash(
        std::span<const uint8_t> data) const;
};

/**
 * Factory function to get appropriate hash functions for parameter set.
 */
[[nodiscard]] std::unique_ptr<HashFunctions> get_hash_functions(const Params& params);

} // namespace slhdsa

#endif // SLHDSA_HASH_FUNCTIONS_HPP
