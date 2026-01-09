/**
 * ML-KEM Core Implementation
 * Based on FIPS 203 Algorithms 19-21
 *
 * ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism) is a
 * post-quantum key encapsulation mechanism standardized in NIST FIPS 203.
 *
 * This module implements the main ML-KEM operations:
 * - Key Generation (Algorithm 19)
 * - Encapsulation (Algorithm 20)
 * - Decapsulation (Algorithm 21)
 */

#ifndef MLKEM_MLKEM_HPP
#define MLKEM_MLKEM_HPP

#include "params.hpp"
#include "kpke.hpp"
#include "utils.hpp"
#include "../ct_utils.hpp"
#include <tuple>
#include <stdexcept>
#include <span>

namespace mlkem {

/**
 * ML-KEM Key Encapsulation Mechanism
 *
 * Provides key generation, encapsulation, and decapsulation operations
 * based on NIST FIPS 203.
 */
class MLKEM {
public:
    explicit MLKEM(const Params& params) : params_(params) {}

    /**
     * Algorithm 19: ML-KEM.KeyGen
     * Generate encapsulation/decapsulation key pair
     *
     * @param seed Optional 64-byte seed for deterministic generation (d || z)
     * @return (ek, dk) encapsulation key and decapsulation key
     */
    [[nodiscard]] std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    keygen(std::span<const uint8_t> seed = {}) const {
        std::vector<uint8_t> d, z;

        if (seed.empty()) {
            // Generate random seeds
            d = random_bytes(32);
            z = random_bytes(32);
        } else {
            if (seed.size() != 64) {
                throw std::invalid_argument("Seed must be 64 bytes (d || z)");
            }
            d.assign(seed.begin(), seed.begin() + 32);
            z.assign(seed.begin() + 32, seed.end());
        }

        return keygen_internal(d, z);
    }

    /**
     * Algorithm 20: ML-KEM.Encaps
     * Encapsulate to produce shared secret and ciphertext
     *
     * @param ek Encapsulation key
     * @param rand Optional 32-byte randomness for deterministic encapsulation
     * @return (K, c) shared secret and ciphertext
     */
    [[nodiscard]] std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    encaps(std::span<const uint8_t> ek, std::span<const uint8_t> rand = {}) const {
        // Validate encapsulation key size
        if (ek.size() != params_.ek_size()) {
            throw std::invalid_argument("Invalid encapsulation key size");
        }

        std::vector<uint8_t> m;
        if (rand.empty()) {
            m = random_bytes(32);
        } else {
            if (rand.size() != 32) {
                throw std::invalid_argument("Randomness must be 32 bytes");
            }
            m.assign(rand.begin(), rand.end());
        }

        return encaps_internal(ek, m);
    }

    /**
     * Algorithm 21: ML-KEM.Decaps
     * Decapsulate to recover shared secret
     *
     * @param dk Decapsulation key
     * @param c Ciphertext
     * @return K shared secret
     */
    [[nodiscard]] std::vector<uint8_t> decaps(
        std::span<const uint8_t> dk,
        std::span<const uint8_t> c) const {

        // Validate decapsulation key size
        if (dk.size() != params_.dk_size()) {
            throw std::invalid_argument("Invalid decapsulation key size");
        }

        // Validate ciphertext size
        if (c.size() != params_.ct_size()) {
            throw std::invalid_argument("Invalid ciphertext size");
        }

        return decaps_internal(dk, c);
    }

    /**
     * Get the parameter set
     */
    [[nodiscard]] const Params& params() const noexcept { return params_; }

private:
    const Params& params_;

    /**
     * Algorithm 19: ML-KEM.KeyGen_internal
     * Internal key generation algorithm
     */
    [[nodiscard]] std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    keygen_internal(std::span<const uint8_t> d, std::span<const uint8_t> z) const {
        // Step 1-2: Generate K-PKE key pair
        auto [ek_pke, dk_pke] = kpke_keygen(d, params_);

        // Step 3: Compute hash of encapsulation key
        auto h = H(ek_pke);

        // Step 4: Construct encapsulation key (same as ek_pke)
        std::vector<uint8_t> ek = ek_pke;

        // Step 5: Construct decapsulation key: dk = dk_pke || ek || h || z
        std::vector<uint8_t> dk;
        dk.reserve(params_.dk_size());
        dk.insert(dk.end(), dk_pke.begin(), dk_pke.end());
        dk.insert(dk.end(), ek.begin(), ek.end());
        dk.insert(dk.end(), h.begin(), h.end());
        dk.insert(dk.end(), z.begin(), z.end());

        return {std::move(ek), std::move(dk)};
    }

    /**
     * Algorithm 20: ML-KEM.Encaps_internal
     * Internal encapsulation algorithm
     */
    [[nodiscard]] std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    encaps_internal(std::span<const uint8_t> ek, std::span<const uint8_t> m) const {
        // Step 1: Compute hash of encapsulation key
        auto h = H(ek);

        // Step 2: Derive (K, r) = G(m || h)
        std::vector<uint8_t> m_h(m.begin(), m.end());
        m_h.insert(m_h.end(), h.begin(), h.end());
        auto [K, r] = G(m_h);

        // Step 3: Encrypt m under ek using randomness r
        auto c = kpke_encrypt(ek, m, r, params_);

        return {std::move(K), std::move(c)};
    }

    /**
     * Algorithm 21: ML-KEM.Decaps_internal
     * Internal decapsulation algorithm
     */
    [[nodiscard]] std::vector<uint8_t> decaps_internal(
        std::span<const uint8_t> dk,
        std::span<const uint8_t> c) const {

        int k = params_.k;

        // Step 1: Parse decapsulation key
        size_t dk_pke_len = 384 * k;
        size_t ek_pke_len = 384 * k + 32;

        auto dk_pke = dk.subspan(0, dk_pke_len);
        auto ek_pke = dk.subspan(dk_pke_len, ek_pke_len);
        auto h = dk.subspan(dk_pke_len + ek_pke_len, 32);
        auto z = dk.subspan(dk_pke_len + ek_pke_len + 32, 32);

        // Step 2: Decrypt ciphertext
        auto m_prime = kpke_decrypt(dk_pke, c, params_);

        // Step 3: Derive (K_prime, r_prime) = G(m' || h)
        std::vector<uint8_t> m_h(m_prime.begin(), m_prime.end());
        m_h.insert(m_h.end(), h.begin(), h.end());
        auto [K_prime, r_prime] = G(m_h);

        // Step 4: Re-encrypt m' to get c'
        auto c_prime = kpke_encrypt(ek_pke, m_prime, r_prime, params_);

        // Step 5: Compute both possible outputs (constant-time)
        // K_bar = J(z || c) - implicit rejection value
        std::vector<uint8_t> z_c(z.begin(), z.end());
        z_c.insert(z_c.end(), c.begin(), c.end());
        auto K_bar = J(z_c);

        // Step 6: Constant-time comparison and selection
        // Use ct::equal for timing-safe comparison (no early exit)
        bool valid = ct::equal(c, c_prime);

        // Use ct::select_bytes to choose result without branching
        // Returns K_prime if valid, K_bar otherwise
        ct::barrier();
        return ct::select_bytes(K_prime, K_bar, valid);
    }
};

/**
 * ML-KEM-512: Security Category 1 (128-bit)
 */
class MLKEM512 : public MLKEM {
public:
    MLKEM512() : MLKEM(MLKEM512_PARAMS) {}
};

/**
 * ML-KEM-768: Security Category 3 (192-bit)
 */
class MLKEM768 : public MLKEM {
public:
    MLKEM768() : MLKEM(MLKEM768_PARAMS) {}
};

/**
 * ML-KEM-1024: Security Category 5 (256-bit)
 */
class MLKEM1024 : public MLKEM {
public:
    MLKEM1024() : MLKEM(MLKEM1024_PARAMS) {}
};

} // namespace mlkem

#endif // MLKEM_MLKEM_HPP
