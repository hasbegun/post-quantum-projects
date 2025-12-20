/**
 * ML-DSA Core Implementation
 * Based on FIPS 204 Algorithms 1-8
 *
 * This module implements the main ML-DSA operations:
 * - Key Generation (Algorithm 1, 6)
 * - Signing (Algorithm 2, 7)
 * - Verification (Algorithm 3, 8)
 * - HashML-DSA variants (Algorithms 4, 5)
 */

#ifndef MLDSA_MLDSA_HPP
#define MLDSA_MLDSA_HPP

#include "params.hpp"
#include "utils.hpp"
#include "ntt.hpp"
#include "encoding.hpp"
#include "sampling.hpp"
#include <tuple>
#include <stdexcept>
#include <span>

namespace mldsa {

/**
 * ML-DSA Digital Signature Algorithm
 *
 * Provides key generation, signing, and verification operations
 * based on NIST FIPS 204.
 */
class MLDSA {
public:
    explicit MLDSA(const Params& params) : params_(params) {}

    /**
     * Algorithm 1: ML-DSA.KeyGen
     * Generate public/private key pair
     *
     * @param seed Optional 32-byte seed for deterministic generation
     * @return (pk, sk) public and private keys
     */
    [[nodiscard]] std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    keygen(std::span<const uint8_t> seed = {}) const {
        std::vector<uint8_t> xi;
        if (seed.empty()) {
            xi = random_bytes(32);
        } else {
            if (seed.size() != 32) {
                throw std::invalid_argument("Seed must be 32 bytes");
            }
            xi.assign(seed.begin(), seed.end());
        }
        return keygen_internal(xi);
    }

    /**
     * Algorithm 2: ML-DSA.Sign
     * Sign a message
     *
     * @param sk Private key
     * @param message Message to sign
     * @param ctx Context string (max 255 bytes)
     * @param deterministic Use deterministic signing if true
     * @return Signature sigma
     */
    [[nodiscard]] std::vector<uint8_t> sign(
        std::span<const uint8_t> sk,
        std::span<const uint8_t> message,
        std::span<const uint8_t> ctx = {},
        bool deterministic = false) const {

        if (ctx.size() > 255) {
            throw std::invalid_argument("Context string must be at most 255 bytes");
        }

        // Construct M' = (0, |ctx|, ctx, M) for pure ML-DSA
        std::vector<uint8_t> M_prime;
        M_prime.push_back(0);
        M_prime.push_back(static_cast<uint8_t>(ctx.size()));
        M_prime.insert(M_prime.end(), ctx.begin(), ctx.end());
        M_prime.insert(M_prime.end(), message.begin(), message.end());

        // Generate randomness
        std::vector<uint8_t> rnd;
        if (deterministic) {
            rnd.resize(32, 0);
        } else {
            rnd = random_bytes(32);
        }

        return sign_internal(sk, M_prime, rnd);
    }

    /**
     * Algorithm 3: ML-DSA.Verify
     * Verify a signature
     *
     * @param pk Public key
     * @param message Message
     * @param sigma Signature
     * @param ctx Context string (max 255 bytes)
     * @return true if valid, false otherwise
     */
    [[nodiscard]] bool verify(
        std::span<const uint8_t> pk,
        std::span<const uint8_t> message,
        std::span<const uint8_t> sigma,
        std::span<const uint8_t> ctx = {}) const {

        if (ctx.size() > 255) {
            return false;
        }

        // Construct M' = (0, |ctx|, ctx, M) for pure ML-DSA
        std::vector<uint8_t> M_prime;
        M_prime.push_back(0);
        M_prime.push_back(static_cast<uint8_t>(ctx.size()));
        M_prime.insert(M_prime.end(), ctx.begin(), ctx.end());
        M_prime.insert(M_prime.end(), message.begin(), message.end());

        return verify_internal(pk, M_prime, sigma);
    }

    /**
     * Get the parameter set
     */
    [[nodiscard]] const Params& params() const noexcept { return params_; }

private:
    const Params& params_;

    /**
     * Algorithm 6: ML-DSA.KeyGen_internal
     * Internal key generation algorithm
     *
     * Note: FIPS 204 final version uses domain separation by appending
     * k and l parameters to the seed before hashing: H(ξ || k || l)
     */
    [[nodiscard]] std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    keygen_internal(std::span<const uint8_t> xi) const {
        // Step 1: Expand seed to (rho, rho', K) with domain separation
        // FIPS 204: H(ξ || k || l, 1024) where k and l are single bytes
        std::vector<uint8_t> seed_with_params(xi.begin(), xi.end());
        seed_with_params.push_back(static_cast<uint8_t>(params_.k));
        seed_with_params.push_back(static_cast<uint8_t>(params_.l));

        auto expanded = h_function(seed_with_params, 128);
        std::vector<uint8_t> rho(expanded.begin(), expanded.begin() + 32);
        std::vector<uint8_t> rho_prime(expanded.begin() + 32, expanded.begin() + 96);
        std::vector<uint8_t> K(expanded.begin() + 96, expanded.begin() + 128);

        // Step 2: Expand A matrix in NTT domain
        auto A_hat = expand_a(rho, params_);

        // Step 3: Expand secret vectors s1, s2
        auto [s1, s2] = expand_s(rho_prime, params_);

        // Step 4: Compute t = NTT^-1(A_hat * NTT(s1)) + s2
        PolyVec s1_poly;
        s1_poly.reserve(params_.l);
        for (const auto& s : s1) {
            Poly p{};
            std::copy(s.begin(), s.end(), p.begin());
            s1_poly.push_back(p);
        }

        auto s1_hat = vec_ntt(s1_poly);
        auto As1_hat = mat_vec_mul_ntt(A_hat, s1_hat);
        auto As1 = vec_ntt_inv(As1_hat);

        // Convert s2 to PolyVec
        PolyVec s2_poly;
        s2_poly.reserve(params_.k);
        for (const auto& s : s2) {
            Poly p{};
            std::copy(s.begin(), s.end(), p.begin());
            s2_poly.push_back(p);
        }

        auto t = vec_add(As1, s2_poly);

        // Convert t to vector<vector<int32_t>>
        std::vector<std::vector<int32_t>> t_vec;
        t_vec.reserve(params_.k);
        for (const auto& p : t) {
            t_vec.emplace_back(p.begin(), p.end());
        }

        // Step 5: Compress t into (t1, t0) using Power2Round
        auto [t1, t0] = vec_power2round(t_vec);

        // Step 6: Encode public key
        auto pk = pk_encode(rho, t1, params_);

        // Step 7: Compute tr = H(pk)
        auto tr = compute_tr(pk);

        // Step 8: Encode private key
        auto sk = sk_encode(rho, K, tr, s1, s2, t0, params_);

        return {std::move(pk), std::move(sk)};
    }

    /**
     * Algorithm 7: ML-DSA.Sign_internal
     * Internal signing algorithm
     */
    [[nodiscard]] std::vector<uint8_t> sign_internal(
        std::span<const uint8_t> sk,
        std::span<const uint8_t> M_prime,
        std::span<const uint8_t> rnd) const {

        int k = params_.k;
        int l = params_.l;
        int32_t gamma1 = params_.gamma1;
        int32_t gamma2 = params_.gamma2;
        int beta = params_.beta;
        int omega = params_.omega;

        // Step 1: Decode private key
        auto decoded = sk_decode(sk, params_);
        const auto& rho = decoded.rho;
        const auto& K = decoded.K;
        const auto& tr = decoded.tr;
        const auto& s1 = decoded.s1;
        const auto& s2 = decoded.s2;
        const auto& t0 = decoded.t0;

        // Step 2: Compute message representative
        std::vector<uint8_t> tr_Mprime(tr.begin(), tr.end());
        tr_Mprime.insert(tr_Mprime.end(), M_prime.begin(), M_prime.end());
        auto mu = h_function(tr_Mprime, 64);

        // Step 3: Compute rho' for mask generation
        std::vector<uint8_t> K_rnd_mu(K.begin(), K.end());
        K_rnd_mu.insert(K_rnd_mu.end(), rnd.begin(), rnd.end());
        K_rnd_mu.insert(K_rnd_mu.end(), mu.begin(), mu.end());
        auto rho_prime = h_function(K_rnd_mu, 64);

        // Step 4: Precompute NTT forms
        PolyVec s1_poly, s2_poly, t0_poly;
        for (const auto& s : s1) {
            Poly p{}; std::copy(s.begin(), s.end(), p.begin());
            s1_poly.push_back(p);
        }
        for (const auto& s : s2) {
            Poly p{}; std::copy(s.begin(), s.end(), p.begin());
            s2_poly.push_back(p);
        }
        for (const auto& t : t0) {
            Poly p{}; std::copy(t.begin(), t.end(), p.begin());
            t0_poly.push_back(p);
        }

        auto s1_hat = vec_ntt(s1_poly);
        auto s2_hat = vec_ntt(s2_poly);
        auto t0_hat = vec_ntt(t0_poly);
        auto A_hat = expand_a(rho, params_);

        // Step 5: Signing loop (rejection sampling)
        int kappa = 0;
        constexpr int max_attempts = 1000;

        while (kappa < max_attempts) {
            // Step 5a: Generate mask y
            auto y = expand_mask(rho_prime, kappa * l, params_);
            PolyVec y_poly;
            for (const auto& yi : y) {
                Poly p{}; std::copy(yi.begin(), yi.end(), p.begin());
                y_poly.push_back(p);
            }
            auto y_hat = vec_ntt(y_poly);

            // Step 5b: Compute w = A*y
            auto w_hat = mat_vec_mul_ntt(A_hat, y_hat);
            auto w = vec_ntt_inv(w_hat);

            // Convert w to vector<vector<int32_t>>
            std::vector<std::vector<int32_t>> w_vec;
            for (const auto& p : w) {
                w_vec.emplace_back(p.begin(), p.end());
            }

            // Step 5c: Compute w1 (high bits of w)
            auto w1 = vec_high_bits(w_vec, gamma2);

            // Step 5d: Compute challenge
            std::vector<uint8_t> mu_w1(mu.begin(), mu.end());
            auto w1_enc = w1_encode(w1, params_);
            mu_w1.insert(mu_w1.end(), w1_enc.begin(), w1_enc.end());
            auto c_tilde = h_function(mu_w1, params_.lambda / 4);
            auto c = sample_in_ball(c_tilde, params_.tau);
            Poly c_poly{}; std::copy(c.begin(), c.end(), c_poly.begin());
            auto c_hat = ntt(c_poly);

            // Step 5e: Compute z = y + c*s1
            PolyVec cs1_hat;
            for (int i = 0; i < l; ++i) {
                cs1_hat.push_back(ntt_multiply(c_hat, s1_hat[i]));
            }
            auto cs1 = vec_ntt_inv(cs1_hat);
            auto z = vec_add(y_poly, cs1);

            // Step 5f: Compute r0 = LowBits(w - c*s2)
            PolyVec cs2_hat;
            for (int i = 0; i < k; ++i) {
                cs2_hat.push_back(ntt_multiply(c_hat, s2_hat[i]));
            }
            auto cs2 = vec_ntt_inv(cs2_hat);
            auto r = vec_sub(w, cs2);

            // Convert r to vector<vector<int32_t>>
            std::vector<std::vector<int32_t>> r_vec;
            for (const auto& p : r) {
                r_vec.emplace_back(p.begin(), p.end());
            }
            auto r0 = vec_low_bits(r_vec, gamma2);

            // Step 5g: Check bounds
            std::vector<std::vector<int32_t>> z_centered;
            for (const auto& p : z) {
                std::vector<int32_t> centered;
                for (int32_t c : p) {
                    centered.push_back(mod_pm(c));
                }
                z_centered.push_back(std::move(centered));
            }

            std::vector<std::vector<int32_t>> r0_centered;
            for (const auto& p : r0) {
                std::vector<int32_t> centered;
                for (int32_t c : p) {
                    centered.push_back(mod_pm(c));
                }
                r0_centered.push_back(std::move(centered));
            }

            int32_t z_norm = infinity_norm_vec(z_centered);
            int32_t r0_norm = infinity_norm_vec(r0_centered);

            if (z_norm >= gamma1 - beta || r0_norm >= gamma2 - beta) {
                ++kappa;
                continue;
            }

            // Step 5h: Compute hints
            PolyVec ct0_hat;
            for (int i = 0; i < k; ++i) {
                ct0_hat.push_back(ntt_multiply(c_hat, t0_hat[i]));
            }
            auto ct0 = vec_ntt_inv(ct0_hat);

            // ct0_neg = -ct0
            PolyVec ct0_neg;
            for (const auto& p : ct0) {
                Poly neg{};
                for (size_t i = 0; i < N; ++i) {
                    neg[i] = mod_q(-p[i]);
                }
                ct0_neg.push_back(neg);
            }

            // r + ct0
            auto r_plus_ct0 = vec_add(r, ct0);

            // Convert to vector<vector<int32_t>>
            std::vector<std::vector<int32_t>> ct0_neg_vec, r_plus_ct0_vec;
            for (const auto& p : ct0_neg) {
                ct0_neg_vec.emplace_back(p.begin(), p.end());
            }
            for (const auto& p : r_plus_ct0) {
                r_plus_ct0_vec.emplace_back(p.begin(), p.end());
            }

            auto [h, hints_count] = vec_make_hint(ct0_neg_vec, r_plus_ct0_vec, gamma2);

            // Check hint count
            if (hints_count > omega) {
                ++kappa;
                continue;
            }

            // Step 5i: Signature found!
            auto sigma = sig_encode(c_tilde, z_centered, h, params_);
            return sigma;
        }

        throw std::runtime_error("Signing failed: too many rejection attempts");
    }

    /**
     * Algorithm 8: ML-DSA.Verify_internal
     * Internal verification algorithm
     */
    [[nodiscard]] bool verify_internal(
        std::span<const uint8_t> pk,
        std::span<const uint8_t> M_prime,
        std::span<const uint8_t> sigma) const {

        int k = params_.k;
        int32_t gamma1 = params_.gamma1;
        int32_t gamma2 = params_.gamma2;
        int beta = params_.beta;
        int omega = params_.omega;

        // Step 1: Decode public key
        auto [rho, t1] = pk_decode(pk, params_);

        // Step 2: Decode signature
        auto decoded = sig_decode(sigma, params_);
        if (!decoded) {
            return false;
        }
        const auto& c_tilde = decoded->c_tilde;
        const auto& z = decoded->z;
        const auto& h = decoded->h;

        // Step 3: Check z norm
        std::vector<std::vector<int32_t>> z_centered;
        for (const auto& p : z) {
            std::vector<int32_t> centered;
            for (int32_t c : p) {
                centered.push_back(mod_pm(c));
            }
            z_centered.push_back(std::move(centered));
        }
        int32_t z_norm = infinity_norm_vec(z_centered);
        if (z_norm >= gamma1 - beta) {
            return false;
        }

        // Step 4: Check hint count
        int hints_count = 0;
        for (const auto& poly : h) {
            for (int32_t bit : poly) {
                hints_count += bit;
            }
        }
        if (hints_count > omega) {
            return false;
        }

        // Step 5: Expand A matrix
        auto A_hat = expand_a(rho, params_);

        // Step 6: Compute message representative
        auto tr = compute_tr(pk);
        std::vector<uint8_t> tr_Mprime(tr.begin(), tr.end());
        tr_Mprime.insert(tr_Mprime.end(), M_prime.begin(), M_prime.end());
        auto mu = h_function(tr_Mprime, 64);

        // Step 7: Compute c from c_tilde
        auto c = sample_in_ball(c_tilde, params_.tau);
        Poly c_poly{}; std::copy(c.begin(), c.end(), c_poly.begin());
        auto c_hat = ntt(c_poly);

        // Step 8: Compute t1 * 2^d in NTT domain
        std::vector<std::vector<int32_t>> t1_scaled;
        for (const auto& poly : t1) {
            std::vector<int32_t> scaled;
            for (int32_t coef : poly) {
                scaled.push_back(coef << D);
            }
            t1_scaled.push_back(std::move(scaled));
        }

        PolyVec t1_poly;
        for (const auto& t : t1_scaled) {
            Poly p{}; std::copy(t.begin(), t.end(), p.begin());
            t1_poly.push_back(p);
        }
        auto t1_hat = vec_ntt(t1_poly);

        // Step 9: Compute w' = A*z - c*t1*2^d
        PolyVec z_poly;
        for (const auto& zi : z) {
            Poly p{}; std::copy(zi.begin(), zi.end(), p.begin());
            z_poly.push_back(p);
        }
        auto z_hat = vec_ntt(z_poly);
        auto Az_hat = mat_vec_mul_ntt(A_hat, z_hat);

        PolyVec ct1_hat;
        for (int i = 0; i < k; ++i) {
            ct1_hat.push_back(ntt_multiply(c_hat, t1_hat[i]));
        }

        PolyVec w_prime_hat;
        for (int i = 0; i < k; ++i) {
            w_prime_hat.push_back(poly_sub(Az_hat[i], ct1_hat[i]));
        }
        auto w_prime = vec_ntt_inv(w_prime_hat);

        // Convert w_prime to vector<vector<int32_t>>
        std::vector<std::vector<int32_t>> w_prime_vec;
        for (const auto& p : w_prime) {
            w_prime_vec.emplace_back(p.begin(), p.end());
        }

        // Step 10: Use hint to recover w1'
        auto w1_prime = vec_use_hint(h, w_prime_vec, gamma2);

        // Step 11: Compute challenge and compare
        std::vector<uint8_t> mu_w1(mu.begin(), mu.end());
        auto w1_enc = w1_encode(w1_prime, params_);
        mu_w1.insert(mu_w1.end(), w1_enc.begin(), w1_enc.end());
        auto c_tilde_prime = h_function(mu_w1, params_.lambda / 4);

        return c_tilde == c_tilde_prime;
    }
};

/**
 * ML-DSA-44: Security Category 2
 */
class MLDSA44 : public MLDSA {
public:
    MLDSA44() : MLDSA(MLDSA44_PARAMS) {}
};

/**
 * ML-DSA-65: Security Category 3
 */
class MLDSA65 : public MLDSA {
public:
    MLDSA65() : MLDSA(MLDSA65_PARAMS) {}
};

/**
 * ML-DSA-87: Security Category 5
 */
class MLDSA87 : public MLDSA {
public:
    MLDSA87() : MLDSA(MLDSA87_PARAMS) {}
};

} // namespace mldsa

#endif // MLDSA_MLDSA_HPP
