/**
 * Streaming API for Post-Quantum Digital Signatures
 *
 * Implements pre-hash mode (HashML-DSA and HashSLH-DSA) for signing large
 * messages without loading them entirely into memory.
 *
 * FIPS 204 Algorithms 4-5: HashML-DSA
 * FIPS 205 Algorithms 22, 24: HashSLH-DSA
 *
 * Usage:
 *   // Signing
 *   auto signer = pqc::streaming::create_signer("ML-DSA-65", sk);
 *   signer->update(chunk1);
 *   signer->update(chunk2);
 *   auto signature = signer->finalize();
 *
 *   // Verification
 *   auto verifier = pqc::streaming::create_verifier("ML-DSA-65", pk, signature);
 *   verifier->update(chunk1);
 *   verifier->update(chunk2);
 *   bool valid = verifier->finalize();
 */

#ifndef PQC_COMMON_STREAMING_HPP
#define PQC_COMMON_STREAMING_HPP

#include "mldsa/mldsa.hpp"
#include "mldsa/params.hpp"
#include "slhdsa/slh_dsa.hpp"
#include "slhdsa/params.hpp"
#include <openssl/evp.h>
#include <memory>
#include <string>
#include <vector>
#include <span>
#include <stdexcept>
#include <cstring>

namespace pqc::streaming {

// ============================================================================
// Hash Algorithm OIDs (from NIST for pre-hash mode)
// ============================================================================

/**
 * Supported hash algorithms for pre-hash mode
 */
enum class HashAlgorithm {
    SHA256,
    SHA384,
    SHA512,
    SHA3_256,
    SHA3_384,
    SHA3_512,
    SHAKE128,  // With 256-bit output
    SHAKE256   // With 512-bit output
};

/**
 * Get OID bytes for a hash algorithm
 * OIDs from NIST SP 800-185 and RFC 8702
 */
inline std::vector<uint8_t> get_hash_oid(HashAlgorithm alg) {
    switch (alg) {
        case HashAlgorithm::SHA256:
            // 2.16.840.1.101.3.4.2.1
            return {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
        case HashAlgorithm::SHA384:
            // 2.16.840.1.101.3.4.2.2
            return {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02};
        case HashAlgorithm::SHA512:
            // 2.16.840.1.101.3.4.2.3
            return {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03};
        case HashAlgorithm::SHA3_256:
            // 2.16.840.1.101.3.4.2.8
            return {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08};
        case HashAlgorithm::SHA3_384:
            // 2.16.840.1.101.3.4.2.9
            return {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09};
        case HashAlgorithm::SHA3_512:
            // 2.16.840.1.101.3.4.2.10
            return {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a};
        case HashAlgorithm::SHAKE128:
            // 2.16.840.1.101.3.4.2.11
            return {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0b};
        case HashAlgorithm::SHAKE256:
            // 2.16.840.1.101.3.4.2.12
            return {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0c};
        default:
            throw std::invalid_argument("Unknown hash algorithm");
    }
}

/**
 * Get the output size for a hash algorithm
 */
inline size_t get_hash_output_size(HashAlgorithm alg) {
    switch (alg) {
        case HashAlgorithm::SHA256:
        case HashAlgorithm::SHA3_256:
        case HashAlgorithm::SHAKE128:
            return 32;
        case HashAlgorithm::SHA384:
        case HashAlgorithm::SHA3_384:
            return 48;
        case HashAlgorithm::SHA512:
        case HashAlgorithm::SHA3_512:
        case HashAlgorithm::SHAKE256:
            return 64;
        default:
            throw std::invalid_argument("Unknown hash algorithm");
    }
}

/**
 * Get the OpenSSL EVP_MD for a hash algorithm
 */
inline const EVP_MD* get_evp_md(HashAlgorithm alg) {
    switch (alg) {
        case HashAlgorithm::SHA256:
            return EVP_sha256();
        case HashAlgorithm::SHA384:
            return EVP_sha384();
        case HashAlgorithm::SHA512:
            return EVP_sha512();
        case HashAlgorithm::SHA3_256:
            return EVP_sha3_256();
        case HashAlgorithm::SHA3_384:
            return EVP_sha3_384();
        case HashAlgorithm::SHA3_512:
            return EVP_sha3_512();
        case HashAlgorithm::SHAKE128:
            return EVP_shake128();
        case HashAlgorithm::SHAKE256:
            return EVP_shake256();
        default:
            throw std::invalid_argument("Unknown hash algorithm");
    }
}

/**
 * Get hash algorithm name as string
 */
inline std::string get_hash_name(HashAlgorithm alg) {
    switch (alg) {
        case HashAlgorithm::SHA256: return "SHA-256";
        case HashAlgorithm::SHA384: return "SHA-384";
        case HashAlgorithm::SHA512: return "SHA-512";
        case HashAlgorithm::SHA3_256: return "SHA3-256";
        case HashAlgorithm::SHA3_384: return "SHA3-384";
        case HashAlgorithm::SHA3_512: return "SHA3-512";
        case HashAlgorithm::SHAKE128: return "SHAKE128";
        case HashAlgorithm::SHAKE256: return "SHAKE256";
        default: return "Unknown";
    }
}

// ============================================================================
// OpenSSL Hash Context RAII Wrapper
// ============================================================================

class HashContext {
public:
    HashContext(HashAlgorithm alg)
        : alg_(alg)
        , ctx_(EVP_MD_CTX_new())
        , finalized_(false) {
        if (!ctx_) {
            throw std::runtime_error("Failed to create hash context");
        }
        if (EVP_DigestInit_ex(ctx_, get_evp_md(alg), nullptr) != 1) {
            EVP_MD_CTX_free(ctx_);
            throw std::runtime_error("Failed to initialize hash context");
        }
    }

    ~HashContext() {
        if (ctx_) {
            EVP_MD_CTX_free(ctx_);
        }
    }

    // Non-copyable
    HashContext(const HashContext&) = delete;
    HashContext& operator=(const HashContext&) = delete;

    // Movable
    HashContext(HashContext&& other) noexcept
        : alg_(other.alg_)
        , ctx_(other.ctx_)
        , finalized_(other.finalized_) {
        other.ctx_ = nullptr;
    }

    HashContext& operator=(HashContext&& other) noexcept {
        if (this != &other) {
            if (ctx_) EVP_MD_CTX_free(ctx_);
            alg_ = other.alg_;
            ctx_ = other.ctx_;
            finalized_ = other.finalized_;
            other.ctx_ = nullptr;
        }
        return *this;
    }

    void update(std::span<const uint8_t> data) {
        if (finalized_) {
            throw std::runtime_error("Cannot update finalized hash context");
        }
        if (EVP_DigestUpdate(ctx_, data.data(), data.size()) != 1) {
            throw std::runtime_error("Failed to update hash");
        }
    }

    std::vector<uint8_t> finalize() {
        if (finalized_) {
            throw std::runtime_error("Hash context already finalized");
        }
        finalized_ = true;

        size_t output_size = get_hash_output_size(alg_);
        std::vector<uint8_t> digest(output_size);

        // SHAKE variants need special handling
        if (alg_ == HashAlgorithm::SHAKE128 || alg_ == HashAlgorithm::SHAKE256) {
            if (EVP_DigestFinalXOF(ctx_, digest.data(), output_size) != 1) {
                throw std::runtime_error("Failed to finalize SHAKE hash");
            }
        } else {
            unsigned int len = 0;
            if (EVP_DigestFinal_ex(ctx_, digest.data(), &len) != 1) {
                throw std::runtime_error("Failed to finalize hash");
            }
            digest.resize(len);
        }

        return digest;
    }

    HashAlgorithm algorithm() const { return alg_; }

private:
    HashAlgorithm alg_;
    EVP_MD_CTX* ctx_;
    bool finalized_;
};

// ============================================================================
// Streaming Signer Interface
// ============================================================================

/**
 * Abstract interface for streaming signature generation
 */
class StreamingSigner {
public:
    virtual ~StreamingSigner() = default;

    /**
     * Update the hash state with message data
     */
    virtual void update(std::span<const uint8_t> data) = 0;

    /**
     * Finalize and produce the signature
     */
    virtual std::vector<uint8_t> finalize() = 0;

    /**
     * Get the algorithm name
     */
    virtual std::string algorithm_name() const = 0;

    /**
     * Get the hash algorithm used
     */
    virtual HashAlgorithm hash_algorithm() const = 0;
};

/**
 * Abstract interface for streaming signature verification
 */
class StreamingVerifier {
public:
    virtual ~StreamingVerifier() = default;

    /**
     * Update the hash state with message data
     */
    virtual void update(std::span<const uint8_t> data) = 0;

    /**
     * Finalize and verify the signature
     */
    virtual bool finalize() = 0;

    /**
     * Get the algorithm name
     */
    virtual std::string algorithm_name() const = 0;

    /**
     * Get the hash algorithm used
     */
    virtual HashAlgorithm hash_algorithm() const = 0;
};

// ============================================================================
// ML-DSA Streaming Implementation
// ============================================================================

/**
 * HashML-DSA streaming signer (FIPS 204 Algorithm 4)
 */
template<typename MLDSAType>
class MLDSAStreamingSigner : public StreamingSigner {
public:
    MLDSAStreamingSigner(
        const std::vector<uint8_t>& sk,
        HashAlgorithm hash_alg = HashAlgorithm::SHA512,
        std::span<const uint8_t> ctx = {},
        bool deterministic = false)
        : dsa_()
        , sk_(sk)
        , hash_ctx_(hash_alg)
        , ctx_(ctx.begin(), ctx.end())
        , deterministic_(deterministic)
        , finalized_(false) {
        if (ctx_.size() > 255) {
            throw std::invalid_argument("Context string must be at most 255 bytes");
        }
    }

    void update(std::span<const uint8_t> data) override {
        if (finalized_) {
            throw std::runtime_error("Cannot update finalized signer");
        }
        hash_ctx_.update(data);
    }

    std::vector<uint8_t> finalize() override {
        if (finalized_) {
            throw std::runtime_error("Signer already finalized");
        }
        finalized_ = true;

        // Get message digest
        auto ph_M = hash_ctx_.finalize();

        // Get OID for the hash algorithm
        auto oid = get_hash_oid(hash_ctx_.algorithm());

        // Construct M' for HashML-DSA:
        // M' = (0x01, |ctx|, ctx, OID, PH(M))
        // where 0x01 indicates pre-hash mode
        std::vector<uint8_t> M_prime;
        M_prime.push_back(0x01);  // Pre-hash mode
        M_prime.push_back(static_cast<uint8_t>(ctx_.size()));
        M_prime.insert(M_prime.end(), ctx_.begin(), ctx_.end());
        M_prime.insert(M_prime.end(), oid.begin(), oid.end());
        M_prime.insert(M_prime.end(), ph_M.begin(), ph_M.end());

        // Sign using internal method with pre-constructed M'
        // We need to call sign_internal directly, so we access it via the sign method
        // by passing an empty context (already included in M')
        return sign_prehash(M_prime);
    }

    std::string algorithm_name() const override {
        return "Hash" + get_algorithm_base_name();
    }

    HashAlgorithm hash_algorithm() const override {
        return hash_ctx_.algorithm();
    }

private:
    MLDSAType dsa_;
    std::vector<uint8_t> sk_;
    HashContext hash_ctx_;
    std::vector<uint8_t> ctx_;
    bool deterministic_;
    bool finalized_;

    std::string get_algorithm_base_name() const {
        const auto& params = dsa_.params();
        if (params.k == 4 && params.l == 4) return "ML-DSA-44";
        if (params.k == 6 && params.l == 5) return "ML-DSA-65";
        if (params.k == 8 && params.l == 7) return "ML-DSA-87";
        return "ML-DSA-Unknown";
    }

    // Sign with pre-constructed M' (pre-hash message)
    std::vector<uint8_t> sign_prehash(std::span<const uint8_t> M_prime) {
        const auto& params = dsa_.params();

        // Decode private key
        auto decoded = mldsa::sk_decode(sk_, params);
        std::vector<uint8_t> rho = decoded.rho;
        std::vector<uint8_t> K = decoded.K;
        std::vector<uint8_t> tr = decoded.tr;

        // Compute mu = H(tr || M')
        std::vector<uint8_t> tr_Mprime(tr.begin(), tr.end());
        tr_Mprime.insert(tr_Mprime.end(), M_prime.begin(), M_prime.end());
        auto mu = mldsa::h_function(tr_Mprime, 64);

        // Generate randomness
        std::vector<uint8_t> rnd;
        if (deterministic_) {
            rnd.resize(32, 0);
        } else {
            rnd = mldsa::random_bytes(32);
        }

        // Compute rho' for mask generation
        std::vector<uint8_t> K_rnd_mu(K.begin(), K.end());
        K_rnd_mu.insert(K_rnd_mu.end(), rnd.begin(), rnd.end());
        K_rnd_mu.insert(K_rnd_mu.end(), mu.begin(), mu.end());
        std::vector<uint8_t> rho_prime = mldsa::h_function(K_rnd_mu, 64);

        // The rest follows standard ML-DSA signing...
        // For simplicity, we use the sign method with M' directly
        // The sign method expects a message and constructs its own M',
        // but we've already constructed ours, so we need special handling

        // Actually, we need to call sign_internal which takes M' directly
        // But that's private. Instead, we use a workaround:
        // Call sign with an empty message but provide our pre-hash as context
        // This doesn't work because context is limited to 255 bytes and gets its own prefix

        // The cleanest solution: create a temporary message that when passed through
        // the pure mode transformation gives us our M_prime.
        // But M_prime starts with 0x01, and pure mode uses 0x00...

        // Best approach: duplicate the signing logic with M_prime directly
        // This is what FIPS 204 Algorithm 4 requires
        return sign_with_mprime(M_prime, rnd);
    }

    std::vector<uint8_t> sign_with_mprime(std::span<const uint8_t> M_prime, std::span<const uint8_t> rnd) {
        const auto& params = dsa_.params();
        int k = params.k;
        int l = params.l;
        int32_t gamma1 = params.gamma1;
        int32_t gamma2 = params.gamma2;
        int beta = params.beta;
        int omega = params.omega;

        // Decode private key
        auto decoded = mldsa::sk_decode(sk_, params);
        std::vector<uint8_t> rho = decoded.rho;
        std::vector<uint8_t> K = decoded.K;
        std::vector<uint8_t> tr = decoded.tr;
        std::vector<std::vector<int32_t>> s1 = decoded.s1;
        std::vector<std::vector<int32_t>> s2 = decoded.s2;
        std::vector<std::vector<int32_t>> t0 = decoded.t0;

        // Compute message representative
        std::vector<uint8_t> tr_Mprime(tr.begin(), tr.end());
        tr_Mprime.insert(tr_Mprime.end(), M_prime.begin(), M_prime.end());
        auto mu = mldsa::h_function(tr_Mprime, 64);

        // Compute rho'
        std::vector<uint8_t> K_rnd_mu(K.begin(), K.end());
        K_rnd_mu.insert(K_rnd_mu.end(), rnd.begin(), rnd.end());
        K_rnd_mu.insert(K_rnd_mu.end(), mu.begin(), mu.end());
        auto rho_prime = mldsa::h_function(K_rnd_mu, 64);

        // Convert to polynomial vectors
        mldsa::PolyVec s1_poly, s2_poly, t0_poly;
        for (const auto& s : s1) {
            mldsa::Poly p{};
            std::copy(s.begin(), s.end(), p.begin());
            s1_poly.push_back(p);
        }
        for (const auto& s : s2) {
            mldsa::Poly p{};
            std::copy(s.begin(), s.end(), p.begin());
            s2_poly.push_back(p);
        }
        for (const auto& t : t0) {
            mldsa::Poly p{};
            std::copy(t.begin(), t.end(), p.begin());
            t0_poly.push_back(p);
        }

        auto s1_hat = mldsa::vec_ntt(s1_poly);
        auto s2_hat = mldsa::vec_ntt(s2_poly);
        auto t0_hat = mldsa::vec_ntt(t0_poly);
        auto A_hat = mldsa::expand_a(rho, params);

        // Signing loop
        int kappa = 0;
        constexpr int max_attempts = 1000;

        while (kappa < max_attempts) {
            auto y = mldsa::expand_mask(rho_prime, kappa * l, params);
            mldsa::PolyVec y_poly;
            for (const auto& yi : y) {
                mldsa::Poly p{};
                std::copy(yi.begin(), yi.end(), p.begin());
                y_poly.push_back(p);
            }
            auto y_hat = mldsa::vec_ntt(y_poly);

            auto w_hat = mldsa::mat_vec_mul_ntt(A_hat, y_hat);
            auto w = mldsa::vec_ntt_inv(w_hat);

            std::vector<std::vector<int32_t>> w_vec;
            for (const auto& p : w) {
                w_vec.emplace_back(p.begin(), p.end());
            }

            auto w1 = mldsa::vec_high_bits(w_vec, gamma2);

            std::vector<uint8_t> mu_w1(mu.begin(), mu.end());
            auto w1_enc = mldsa::w1_encode(w1, params);
            mu_w1.insert(mu_w1.end(), w1_enc.begin(), w1_enc.end());
            auto c_tilde = mldsa::h_function(mu_w1, params.lambda / 4);
            auto c = mldsa::sample_in_ball(c_tilde, params.tau);
            mldsa::Poly c_poly{};
            std::copy(c.begin(), c.end(), c_poly.begin());
            auto c_hat = mldsa::ntt(c_poly);

            mldsa::PolyVec cs1_hat;
            for (int i = 0; i < l; ++i) {
                cs1_hat.push_back(mldsa::ntt_multiply(c_hat, s1_hat[i]));
            }
            auto cs1 = mldsa::vec_ntt_inv(cs1_hat);
            auto z = mldsa::vec_add(y_poly, cs1);

            mldsa::PolyVec cs2_hat;
            for (int i = 0; i < k; ++i) {
                cs2_hat.push_back(mldsa::ntt_multiply(c_hat, s2_hat[i]));
            }
            auto cs2 = mldsa::vec_ntt_inv(cs2_hat);
            auto r = mldsa::vec_sub(w, cs2);

            std::vector<std::vector<int32_t>> r_vec;
            for (const auto& p : r) {
                r_vec.emplace_back(p.begin(), p.end());
            }
            auto r0 = mldsa::vec_low_bits(r_vec, gamma2);

            std::vector<std::vector<int32_t>> z_centered;
            for (const auto& p : z) {
                std::vector<int32_t> centered;
                for (int32_t coef : p) {
                    centered.push_back(mldsa::mod_pm(coef));
                }
                z_centered.push_back(std::move(centered));
            }

            std::vector<std::vector<int32_t>> r0_centered;
            for (const auto& p : r0) {
                std::vector<int32_t> centered;
                for (int32_t coef : p) {
                    centered.push_back(mldsa::mod_pm(coef));
                }
                r0_centered.push_back(std::move(centered));
            }

            int32_t z_norm = mldsa::infinity_norm_vec(z_centered);
            int32_t r0_norm = mldsa::infinity_norm_vec(r0_centered);

            if (z_norm >= gamma1 - beta || r0_norm >= gamma2 - beta) {
                ++kappa;
                continue;
            }

            mldsa::PolyVec ct0_hat;
            for (int i = 0; i < k; ++i) {
                ct0_hat.push_back(mldsa::ntt_multiply(c_hat, t0_hat[i]));
            }
            auto ct0 = mldsa::vec_ntt_inv(ct0_hat);

            mldsa::PolyVec ct0_neg;
            for (const auto& p : ct0) {
                mldsa::Poly neg{};
                for (size_t i = 0; i < mldsa::N; ++i) {
                    neg[i] = mldsa::mod_q(-p[i]);
                }
                ct0_neg.push_back(neg);
            }

            auto r_plus_ct0 = mldsa::vec_add(r, ct0);

            std::vector<std::vector<int32_t>> ct0_neg_vec, r_plus_ct0_vec;
            for (const auto& p : ct0_neg) {
                ct0_neg_vec.emplace_back(p.begin(), p.end());
            }
            for (const auto& p : r_plus_ct0) {
                r_plus_ct0_vec.emplace_back(p.begin(), p.end());
            }

            auto [h, hints_count] = mldsa::vec_make_hint(ct0_neg_vec, r_plus_ct0_vec, gamma2);

            if (hints_count > omega) {
                ++kappa;
                continue;
            }

            return mldsa::sig_encode(c_tilde, z_centered, h, params);
        }

        throw std::runtime_error("Signing failed: too many rejection attempts");
    }
};

/**
 * HashML-DSA streaming verifier (FIPS 204 Algorithm 5)
 */
template<typename MLDSAType>
class MLDSAStreamingVerifier : public StreamingVerifier {
public:
    MLDSAStreamingVerifier(
        const std::vector<uint8_t>& pk,
        const std::vector<uint8_t>& signature,
        HashAlgorithm hash_alg = HashAlgorithm::SHA512,
        std::span<const uint8_t> ctx = {})
        : dsa_()
        , pk_(pk)
        , signature_(signature)
        , hash_ctx_(hash_alg)
        , ctx_(ctx.begin(), ctx.end())
        , finalized_(false) {
        if (ctx_.size() > 255) {
            throw std::invalid_argument("Context string must be at most 255 bytes");
        }
    }

    void update(std::span<const uint8_t> data) override {
        if (finalized_) {
            throw std::runtime_error("Cannot update finalized verifier");
        }
        hash_ctx_.update(data);
    }

    bool finalize() override {
        if (finalized_) {
            throw std::runtime_error("Verifier already finalized");
        }
        finalized_ = true;

        // Get message digest
        auto ph_M = hash_ctx_.finalize();

        // Get OID for the hash algorithm
        auto oid = get_hash_oid(hash_ctx_.algorithm());

        // Construct M' for HashML-DSA verification
        std::vector<uint8_t> M_prime;
        M_prime.push_back(0x01);  // Pre-hash mode
        M_prime.push_back(static_cast<uint8_t>(ctx_.size()));
        M_prime.insert(M_prime.end(), ctx_.begin(), ctx_.end());
        M_prime.insert(M_prime.end(), oid.begin(), oid.end());
        M_prime.insert(M_prime.end(), ph_M.begin(), ph_M.end());

        return verify_with_mprime(M_prime);
    }

    std::string algorithm_name() const override {
        return "Hash" + get_algorithm_base_name();
    }

    HashAlgorithm hash_algorithm() const override {
        return hash_ctx_.algorithm();
    }

private:
    MLDSAType dsa_;
    std::vector<uint8_t> pk_;
    std::vector<uint8_t> signature_;
    HashContext hash_ctx_;
    std::vector<uint8_t> ctx_;
    bool finalized_;

    std::string get_algorithm_base_name() const {
        const auto& params = dsa_.params();
        if (params.k == 4 && params.l == 4) return "ML-DSA-44";
        if (params.k == 6 && params.l == 5) return "ML-DSA-65";
        if (params.k == 8 && params.l == 7) return "ML-DSA-87";
        return "ML-DSA-Unknown";
    }

    bool verify_with_mprime(std::span<const uint8_t> M_prime) {
        const auto& params = dsa_.params();
        int k = params.k;
        int32_t gamma1 = params.gamma1;
        int32_t gamma2 = params.gamma2;
        int beta = params.beta;
        int omega = params.omega;

        // Decode public key
        auto [rho, t1] = mldsa::pk_decode(pk_, params);

        // Decode signature
        auto decoded = mldsa::sig_decode(signature_, params);
        if (!decoded) {
            return false;
        }

        const auto& c_tilde = decoded->c_tilde;
        const auto& z = decoded->z;
        const auto& h = decoded->h;

        // Check z norm
        std::vector<std::vector<int32_t>> z_centered;
        for (const auto& p : z) {
            std::vector<int32_t> centered;
            for (int32_t coef : p) {
                centered.push_back(mldsa::mod_pm(coef));
            }
            z_centered.push_back(std::move(centered));
        }
        int32_t z_norm = mldsa::infinity_norm_vec(z_centered);
        if (z_norm >= gamma1 - beta) {
            return false;
        }

        // Check hint count
        int hints_count = 0;
        for (const auto& poly : h) {
            for (int32_t bit : poly) {
                hints_count += bit;
            }
        }
        if (hints_count > omega) {
            return false;
        }

        // Expand A matrix
        auto A_hat = mldsa::expand_a(rho, params);

        // Compute message representative with M_prime
        auto tr = mldsa::compute_tr(pk_);
        std::vector<uint8_t> tr_Mprime(tr.begin(), tr.end());
        tr_Mprime.insert(tr_Mprime.end(), M_prime.begin(), M_prime.end());
        auto mu = mldsa::h_function(tr_Mprime, 64);

        // Compute c from c_tilde
        auto c = mldsa::sample_in_ball(c_tilde, params.tau);
        mldsa::Poly c_poly{};
        std::copy(c.begin(), c.end(), c_poly.begin());
        auto c_hat = mldsa::ntt(c_poly);

        // Compute t1 * 2^d
        std::vector<std::vector<int32_t>> t1_scaled;
        for (const auto& poly : t1) {
            std::vector<int32_t> scaled;
            for (int32_t coef : poly) {
                scaled.push_back(coef << mldsa::D);
            }
            t1_scaled.push_back(std::move(scaled));
        }

        mldsa::PolyVec t1_poly;
        for (const auto& t : t1_scaled) {
            mldsa::Poly p{};
            std::copy(t.begin(), t.end(), p.begin());
            t1_poly.push_back(p);
        }
        auto t1_hat = mldsa::vec_ntt(t1_poly);

        // Compute w' = A*z - c*t1*2^d
        mldsa::PolyVec z_poly;
        for (const auto& zi : z) {
            mldsa::Poly p{};
            std::copy(zi.begin(), zi.end(), p.begin());
            z_poly.push_back(p);
        }
        auto z_hat = mldsa::vec_ntt(z_poly);
        auto Az_hat = mldsa::mat_vec_mul_ntt(A_hat, z_hat);

        mldsa::PolyVec ct1_hat;
        for (int i = 0; i < k; ++i) {
            ct1_hat.push_back(mldsa::ntt_multiply(c_hat, t1_hat[i]));
        }

        mldsa::PolyVec w_prime_hat;
        for (int i = 0; i < k; ++i) {
            w_prime_hat.push_back(mldsa::poly_sub(Az_hat[i], ct1_hat[i]));
        }
        auto w_prime = mldsa::vec_ntt_inv(w_prime_hat);

        std::vector<std::vector<int32_t>> w_prime_vec;
        for (const auto& p : w_prime) {
            w_prime_vec.emplace_back(p.begin(), p.end());
        }

        auto w1_prime = mldsa::vec_use_hint(h, w_prime_vec, gamma2);

        // Compute and compare challenge
        std::vector<uint8_t> mu_w1(mu.begin(), mu.end());
        auto w1_enc = mldsa::w1_encode(w1_prime, params);
        mu_w1.insert(mu_w1.end(), w1_enc.begin(), w1_enc.end());
        auto c_tilde_prime = mldsa::h_function(mu_w1, params.lambda / 4);

        return c_tilde == c_tilde_prime;
    }
};

// ============================================================================
// SLH-DSA Streaming Implementation
// ============================================================================

/**
 * HashSLH-DSA streaming signer (FIPS 205 Algorithm 22)
 */
template<const slhdsa::Params& P>
class SLHDSAStreamingSigner : public StreamingSigner {
public:
    SLHDSAStreamingSigner(
        const std::vector<uint8_t>& sk,
        HashAlgorithm hash_alg = HashAlgorithm::SHA512,
        std::span<const uint8_t> ctx = {},
        bool randomize = true)
        : sk_(sk)
        , hash_ctx_(hash_alg)
        , ctx_(ctx.begin(), ctx.end())
        , randomize_(randomize)
        , finalized_(false) {
        if (ctx_.size() > 255) {
            throw std::invalid_argument("Context string must be at most 255 bytes");
        }
    }

    void update(std::span<const uint8_t> data) override {
        if (finalized_) {
            throw std::runtime_error("Cannot update finalized signer");
        }
        hash_ctx_.update(data);
    }

    std::vector<uint8_t> finalize() override {
        if (finalized_) {
            throw std::runtime_error("Signer already finalized");
        }
        finalized_ = true;

        // Get message digest
        auto ph_M = hash_ctx_.finalize();

        // Get OID for the hash algorithm
        auto oid = get_hash_oid(hash_ctx_.algorithm());

        // Construct M' for HashSLH-DSA:
        // M' = (0x01, |ctx|, ctx, OID, PH(M))
        std::vector<uint8_t> M_prime;
        M_prime.push_back(0x01);  // Pre-hash mode
        M_prime.push_back(static_cast<uint8_t>(ctx_.size()));
        M_prime.insert(M_prime.end(), ctx_.begin(), ctx_.end());
        M_prime.insert(M_prime.end(), oid.begin(), oid.end());
        M_prime.insert(M_prime.end(), ph_M.begin(), ph_M.end());

        // Sign with pre-hash message
        return slhdsa::slh_sign_internal(P, M_prime, sk_, randomize_);
    }

    std::string algorithm_name() const override {
        return "Hash" + std::string(P.name);
    }

    HashAlgorithm hash_algorithm() const override {
        return hash_ctx_.algorithm();
    }

private:
    std::vector<uint8_t> sk_;
    HashContext hash_ctx_;
    std::vector<uint8_t> ctx_;
    bool randomize_;
    bool finalized_;
};

/**
 * HashSLH-DSA streaming verifier (FIPS 205 Algorithm 24)
 */
template<const slhdsa::Params& P>
class SLHDSAStreamingVerifier : public StreamingVerifier {
public:
    SLHDSAStreamingVerifier(
        const std::vector<uint8_t>& pk,
        const std::vector<uint8_t>& signature,
        HashAlgorithm hash_alg = HashAlgorithm::SHA512,
        std::span<const uint8_t> ctx = {})
        : pk_(pk)
        , signature_(signature)
        , hash_ctx_(hash_alg)
        , ctx_(ctx.begin(), ctx.end())
        , finalized_(false) {
        if (ctx_.size() > 255) {
            throw std::invalid_argument("Context string must be at most 255 bytes");
        }
    }

    void update(std::span<const uint8_t> data) override {
        if (finalized_) {
            throw std::runtime_error("Cannot update finalized verifier");
        }
        hash_ctx_.update(data);
    }

    bool finalize() override {
        if (finalized_) {
            throw std::runtime_error("Verifier already finalized");
        }
        finalized_ = true;

        // Get message digest
        auto ph_M = hash_ctx_.finalize();

        // Get OID for the hash algorithm
        auto oid = get_hash_oid(hash_ctx_.algorithm());

        // Construct M' for HashSLH-DSA verification
        std::vector<uint8_t> M_prime;
        M_prime.push_back(0x01);  // Pre-hash mode
        M_prime.push_back(static_cast<uint8_t>(ctx_.size()));
        M_prime.insert(M_prime.end(), ctx_.begin(), ctx_.end());
        M_prime.insert(M_prime.end(), oid.begin(), oid.end());
        M_prime.insert(M_prime.end(), ph_M.begin(), ph_M.end());

        // Verify with pre-hash message
        return slhdsa::slh_verify_internal(P, M_prime, signature_, pk_);
    }

    std::string algorithm_name() const override {
        return "Hash" + std::string(P.name);
    }

    HashAlgorithm hash_algorithm() const override {
        return hash_ctx_.algorithm();
    }

private:
    std::vector<uint8_t> pk_;
    std::vector<uint8_t> signature_;
    HashContext hash_ctx_;
    std::vector<uint8_t> ctx_;
    bool finalized_;
};

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Create a streaming signer for the specified algorithm
 *
 * @param algorithm Algorithm name (e.g., "ML-DSA-65", "SLH-DSA-SHAKE-128f")
 * @param sk Secret key
 * @param hash_alg Hash algorithm to use (default: SHA-512)
 * @param ctx Context string (optional, max 255 bytes)
 * @param deterministic_or_randomize For ML-DSA: deterministic mode; For SLH-DSA: randomize mode
 * @return Streaming signer instance
 */
inline std::unique_ptr<StreamingSigner> create_signer(
    const std::string& algorithm,
    const std::vector<uint8_t>& sk,
    HashAlgorithm hash_alg = HashAlgorithm::SHA512,
    std::span<const uint8_t> ctx = {},
    bool deterministic_or_randomize = false) {

    // ML-DSA algorithms
    if (algorithm == "ML-DSA-44") {
        return std::make_unique<MLDSAStreamingSigner<mldsa::MLDSA44>>(
            sk, hash_alg, ctx, deterministic_or_randomize);
    }
    if (algorithm == "ML-DSA-65") {
        return std::make_unique<MLDSAStreamingSigner<mldsa::MLDSA65>>(
            sk, hash_alg, ctx, deterministic_or_randomize);
    }
    if (algorithm == "ML-DSA-87") {
        return std::make_unique<MLDSAStreamingSigner<mldsa::MLDSA87>>(
            sk, hash_alg, ctx, deterministic_or_randomize);
    }

    // SLH-DSA SHA2 algorithms
    if (algorithm == "SLH-DSA-SHA2-128s") {
        return std::make_unique<SLHDSAStreamingSigner<slhdsa::SLH_DSA_SHA2_128s>>(
            sk, hash_alg, ctx, !deterministic_or_randomize);  // Note: inverted for randomize
    }
    if (algorithm == "SLH-DSA-SHA2-128f") {
        return std::make_unique<SLHDSAStreamingSigner<slhdsa::SLH_DSA_SHA2_128f>>(
            sk, hash_alg, ctx, !deterministic_or_randomize);
    }
    if (algorithm == "SLH-DSA-SHA2-192s") {
        return std::make_unique<SLHDSAStreamingSigner<slhdsa::SLH_DSA_SHA2_192s>>(
            sk, hash_alg, ctx, !deterministic_or_randomize);
    }
    if (algorithm == "SLH-DSA-SHA2-192f") {
        return std::make_unique<SLHDSAStreamingSigner<slhdsa::SLH_DSA_SHA2_192f>>(
            sk, hash_alg, ctx, !deterministic_or_randomize);
    }
    if (algorithm == "SLH-DSA-SHA2-256s") {
        return std::make_unique<SLHDSAStreamingSigner<slhdsa::SLH_DSA_SHA2_256s>>(
            sk, hash_alg, ctx, !deterministic_or_randomize);
    }
    if (algorithm == "SLH-DSA-SHA2-256f") {
        return std::make_unique<SLHDSAStreamingSigner<slhdsa::SLH_DSA_SHA2_256f>>(
            sk, hash_alg, ctx, !deterministic_or_randomize);
    }

    // SLH-DSA SHAKE algorithms
    if (algorithm == "SLH-DSA-SHAKE-128s") {
        return std::make_unique<SLHDSAStreamingSigner<slhdsa::SLH_DSA_SHAKE_128s>>(
            sk, hash_alg, ctx, !deterministic_or_randomize);
    }
    if (algorithm == "SLH-DSA-SHAKE-128f") {
        return std::make_unique<SLHDSAStreamingSigner<slhdsa::SLH_DSA_SHAKE_128f>>(
            sk, hash_alg, ctx, !deterministic_or_randomize);
    }
    if (algorithm == "SLH-DSA-SHAKE-192s") {
        return std::make_unique<SLHDSAStreamingSigner<slhdsa::SLH_DSA_SHAKE_192s>>(
            sk, hash_alg, ctx, !deterministic_or_randomize);
    }
    if (algorithm == "SLH-DSA-SHAKE-192f") {
        return std::make_unique<SLHDSAStreamingSigner<slhdsa::SLH_DSA_SHAKE_192f>>(
            sk, hash_alg, ctx, !deterministic_or_randomize);
    }
    if (algorithm == "SLH-DSA-SHAKE-256s") {
        return std::make_unique<SLHDSAStreamingSigner<slhdsa::SLH_DSA_SHAKE_256s>>(
            sk, hash_alg, ctx, !deterministic_or_randomize);
    }
    if (algorithm == "SLH-DSA-SHAKE-256f") {
        return std::make_unique<SLHDSAStreamingSigner<slhdsa::SLH_DSA_SHAKE_256f>>(
            sk, hash_alg, ctx, !deterministic_or_randomize);
    }

    throw std::invalid_argument("Unknown algorithm: " + algorithm);
}

/**
 * Create a streaming verifier for the specified algorithm
 *
 * @param algorithm Algorithm name (e.g., "ML-DSA-65", "SLH-DSA-SHAKE-128f")
 * @param pk Public key
 * @param signature Signature to verify
 * @param hash_alg Hash algorithm used (default: SHA-512)
 * @param ctx Context string (optional, max 255 bytes)
 * @return Streaming verifier instance
 */
inline std::unique_ptr<StreamingVerifier> create_verifier(
    const std::string& algorithm,
    const std::vector<uint8_t>& pk,
    const std::vector<uint8_t>& signature,
    HashAlgorithm hash_alg = HashAlgorithm::SHA512,
    std::span<const uint8_t> ctx = {}) {

    // ML-DSA algorithms
    if (algorithm == "ML-DSA-44") {
        return std::make_unique<MLDSAStreamingVerifier<mldsa::MLDSA44>>(
            pk, signature, hash_alg, ctx);
    }
    if (algorithm == "ML-DSA-65") {
        return std::make_unique<MLDSAStreamingVerifier<mldsa::MLDSA65>>(
            pk, signature, hash_alg, ctx);
    }
    if (algorithm == "ML-DSA-87") {
        return std::make_unique<MLDSAStreamingVerifier<mldsa::MLDSA87>>(
            pk, signature, hash_alg, ctx);
    }

    // SLH-DSA SHA2 algorithms
    if (algorithm == "SLH-DSA-SHA2-128s") {
        return std::make_unique<SLHDSAStreamingVerifier<slhdsa::SLH_DSA_SHA2_128s>>(
            pk, signature, hash_alg, ctx);
    }
    if (algorithm == "SLH-DSA-SHA2-128f") {
        return std::make_unique<SLHDSAStreamingVerifier<slhdsa::SLH_DSA_SHA2_128f>>(
            pk, signature, hash_alg, ctx);
    }
    if (algorithm == "SLH-DSA-SHA2-192s") {
        return std::make_unique<SLHDSAStreamingVerifier<slhdsa::SLH_DSA_SHA2_192s>>(
            pk, signature, hash_alg, ctx);
    }
    if (algorithm == "SLH-DSA-SHA2-192f") {
        return std::make_unique<SLHDSAStreamingVerifier<slhdsa::SLH_DSA_SHA2_192f>>(
            pk, signature, hash_alg, ctx);
    }
    if (algorithm == "SLH-DSA-SHA2-256s") {
        return std::make_unique<SLHDSAStreamingVerifier<slhdsa::SLH_DSA_SHA2_256s>>(
            pk, signature, hash_alg, ctx);
    }
    if (algorithm == "SLH-DSA-SHA2-256f") {
        return std::make_unique<SLHDSAStreamingVerifier<slhdsa::SLH_DSA_SHA2_256f>>(
            pk, signature, hash_alg, ctx);
    }

    // SLH-DSA SHAKE algorithms
    if (algorithm == "SLH-DSA-SHAKE-128s") {
        return std::make_unique<SLHDSAStreamingVerifier<slhdsa::SLH_DSA_SHAKE_128s>>(
            pk, signature, hash_alg, ctx);
    }
    if (algorithm == "SLH-DSA-SHAKE-128f") {
        return std::make_unique<SLHDSAStreamingVerifier<slhdsa::SLH_DSA_SHAKE_128f>>(
            pk, signature, hash_alg, ctx);
    }
    if (algorithm == "SLH-DSA-SHAKE-192s") {
        return std::make_unique<SLHDSAStreamingVerifier<slhdsa::SLH_DSA_SHAKE_192s>>(
            pk, signature, hash_alg, ctx);
    }
    if (algorithm == "SLH-DSA-SHAKE-192f") {
        return std::make_unique<SLHDSAStreamingVerifier<slhdsa::SLH_DSA_SHAKE_192f>>(
            pk, signature, hash_alg, ctx);
    }
    if (algorithm == "SLH-DSA-SHAKE-256s") {
        return std::make_unique<SLHDSAStreamingVerifier<slhdsa::SLH_DSA_SHAKE_256s>>(
            pk, signature, hash_alg, ctx);
    }
    if (algorithm == "SLH-DSA-SHAKE-256f") {
        return std::make_unique<SLHDSAStreamingVerifier<slhdsa::SLH_DSA_SHAKE_256f>>(
            pk, signature, hash_alg, ctx);
    }

    throw std::invalid_argument("Unknown algorithm: " + algorithm);
}

/**
 * Get list of supported streaming algorithms
 */
inline std::vector<std::string> available_streaming_algorithms() {
    return {
        // ML-DSA
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
        // SLH-DSA SHA2
        "SLH-DSA-SHA2-128s",
        "SLH-DSA-SHA2-128f",
        "SLH-DSA-SHA2-192s",
        "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-256s",
        "SLH-DSA-SHA2-256f",
        // SLH-DSA SHAKE
        "SLH-DSA-SHAKE-128s",
        "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHAKE-192s",
        "SLH-DSA-SHAKE-192f",
        "SLH-DSA-SHAKE-256s",
        "SLH-DSA-SHAKE-256f"
    };
}

/**
 * Get list of supported hash algorithms
 */
inline std::vector<HashAlgorithm> available_hash_algorithms() {
    return {
        HashAlgorithm::SHA256,
        HashAlgorithm::SHA384,
        HashAlgorithm::SHA512,
        HashAlgorithm::SHA3_256,
        HashAlgorithm::SHA3_384,
        HashAlgorithm::SHA3_512,
        HashAlgorithm::SHAKE128,
        HashAlgorithm::SHAKE256
    };
}

// ============================================================================
// Convenience Functions for Single-Call Streaming
// ============================================================================

/**
 * Sign a large message using streaming API
 *
 * @param algorithm Algorithm name
 * @param sk Secret key
 * @param message_chunks Message data as vector of chunks
 * @param hash_alg Hash algorithm to use
 * @param ctx Context string (optional)
 * @return Signature
 */
inline std::vector<uint8_t> sign_streaming(
    const std::string& algorithm,
    const std::vector<uint8_t>& sk,
    const std::vector<std::vector<uint8_t>>& message_chunks,
    HashAlgorithm hash_alg = HashAlgorithm::SHA512,
    std::span<const uint8_t> ctx = {}) {

    auto signer = create_signer(algorithm, sk, hash_alg, ctx);
    for (const auto& chunk : message_chunks) {
        signer->update(chunk);
    }
    return signer->finalize();
}

/**
 * Verify a signature using streaming API
 *
 * @param algorithm Algorithm name
 * @param pk Public key
 * @param signature Signature to verify
 * @param message_chunks Message data as vector of chunks
 * @param hash_alg Hash algorithm used
 * @param ctx Context string (optional)
 * @return true if valid, false otherwise
 */
inline bool verify_streaming(
    const std::string& algorithm,
    const std::vector<uint8_t>& pk,
    const std::vector<uint8_t>& signature,
    const std::vector<std::vector<uint8_t>>& message_chunks,
    HashAlgorithm hash_alg = HashAlgorithm::SHA512,
    std::span<const uint8_t> ctx = {}) {

    auto verifier = create_verifier(algorithm, pk, signature, hash_alg, ctx);
    for (const auto& chunk : message_chunks) {
        verifier->update(chunk);
    }
    return verifier->finalize();
}

} // namespace pqc::streaming

#endif // PQC_COMMON_STREAMING_HPP
