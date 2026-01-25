/**
 * Runtime Algorithm Selection Factory
 *
 * Provides a unified runtime interface for selecting PQC algorithms by name.
 * Enables configuration-driven algorithm selection without compile-time types.
 *
 * Usage:
 *   auto dsa = pqc::create_dsa("ML-DSA-65");
 *   auto [pk, sk] = dsa->keygen();
 *   auto sig = dsa->sign(sk, message);
 *   bool valid = dsa->verify(pk, message, sig);
 *
 *   auto kem = pqc::create_kem("ML-KEM-768");
 *   auto [ek, dk] = kem->keygen();
 *   auto [K, ct] = kem->encaps(ek);
 *   auto K2 = kem->decaps(dk, ct);
 */

#ifndef COMMON_ALGORITHM_FACTORY_HPP
#define COMMON_ALGORITHM_FACTORY_HPP

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <stdexcept>

#include "mldsa/mldsa.hpp"
#include "slhdsa/slh_dsa.hpp"
#include "mlkem/mlkem.hpp"

namespace pqc {

// ============================================================================
// Abstract Interfaces
// ============================================================================

/**
 * Abstract interface for digital signature algorithms
 *
 * Provides a uniform API across ML-DSA and SLH-DSA parameter sets.
 * keygen() always returns (public_key, secret_key) regardless of the
 * underlying algorithm's native ordering.
 */
class DigitalSignature {
public:
    virtual ~DigitalSignature() = default;

    /** Algorithm name (e.g., "ML-DSA-65", "SLH-DSA-SHA2-128s") */
    [[nodiscard]] virtual std::string name() const = 0;

    /** FIPS standard identifier (e.g., "FIPS 204", "FIPS 205") */
    [[nodiscard]] virtual std::string standard() const = 0;

    /** Generate a key pair. Returns (public_key, secret_key). */
    [[nodiscard]] virtual std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    keygen() const = 0;

    /** Sign a message with the secret key */
    [[nodiscard]] virtual std::vector<uint8_t> sign(
        std::span<const uint8_t> sk,
        std::span<const uint8_t> message,
        std::span<const uint8_t> ctx = {}) const = 0;

    /** Verify a signature against a public key and message */
    [[nodiscard]] virtual bool verify(
        std::span<const uint8_t> pk,
        std::span<const uint8_t> message,
        std::span<const uint8_t> signature,
        std::span<const uint8_t> ctx = {}) const = 0;

    /** Public key size in bytes */
    [[nodiscard]] virtual size_t public_key_size() const = 0;

    /** Secret key size in bytes */
    [[nodiscard]] virtual size_t secret_key_size() const = 0;

    /** Signature size in bytes */
    [[nodiscard]] virtual size_t signature_size() const = 0;
};

/**
 * Abstract interface for key encapsulation mechanisms
 *
 * Provides a uniform API across ML-KEM parameter sets.
 */
class KeyEncapsulation {
public:
    virtual ~KeyEncapsulation() = default;

    /** Algorithm name (e.g., "ML-KEM-768") */
    [[nodiscard]] virtual std::string name() const = 0;

    /** FIPS standard identifier (e.g., "FIPS 203") */
    [[nodiscard]] virtual std::string standard() const = 0;

    /** Generate key pair. Returns (encapsulation_key, decapsulation_key). */
    [[nodiscard]] virtual std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    keygen() const = 0;

    /** Encapsulate: generate shared secret and ciphertext. Returns (shared_secret, ciphertext). */
    [[nodiscard]] virtual std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    encaps(std::span<const uint8_t> ek) const = 0;

    /** Decapsulate: recover shared secret from ciphertext */
    [[nodiscard]] virtual std::vector<uint8_t> decaps(
        std::span<const uint8_t> dk,
        std::span<const uint8_t> ciphertext) const = 0;

    /** Encapsulation key size in bytes */
    [[nodiscard]] virtual size_t encapsulation_key_size() const = 0;

    /** Decapsulation key size in bytes */
    [[nodiscard]] virtual size_t decapsulation_key_size() const = 0;

    /** Ciphertext size in bytes */
    [[nodiscard]] virtual size_t ciphertext_size() const = 0;

    /** Shared secret size in bytes (always 32 for ML-KEM) */
    [[nodiscard]] virtual size_t shared_secret_size() const = 0;
};

// ============================================================================
// ML-DSA Concrete Implementation
// ============================================================================

namespace detail {

class MLDSAAdapter final : public DigitalSignature {
public:
    explicit MLDSAAdapter(const mldsa::Params& params)
        : impl_(params), params_(params) {}

    [[nodiscard]] std::string name() const override {
        return std::string(params_.name);
    }

    [[nodiscard]] std::string standard() const override {
        return "FIPS 204";
    }

    [[nodiscard]] std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    keygen() const override {
        // MLDSA already returns (pk, sk)
        return impl_.keygen();
    }

    [[nodiscard]] std::vector<uint8_t> sign(
        std::span<const uint8_t> sk,
        std::span<const uint8_t> message,
        std::span<const uint8_t> ctx = {}) const override {
        return impl_.sign(sk, message, ctx);
    }

    [[nodiscard]] bool verify(
        std::span<const uint8_t> pk,
        std::span<const uint8_t> message,
        std::span<const uint8_t> signature,
        std::span<const uint8_t> ctx = {}) const override {
        return impl_.verify(pk, message, signature, ctx);
    }

    [[nodiscard]] size_t public_key_size() const override {
        return params_.pk_size();
    }

    [[nodiscard]] size_t secret_key_size() const override {
        return params_.sk_size();
    }

    [[nodiscard]] size_t signature_size() const override {
        return params_.sig_size();
    }

private:
    mldsa::MLDSA impl_;
    const mldsa::Params& params_;
};

// ============================================================================
// SLH-DSA Concrete Implementation
// ============================================================================

class SLHDSAAdapter final : public DigitalSignature {
public:
    explicit SLHDSAAdapter(const slhdsa::Params& params)
        : params_(params) {}

    [[nodiscard]] std::string name() const override {
        return std::string(params_.name);
    }

    [[nodiscard]] std::string standard() const override {
        return "FIPS 205";
    }

    [[nodiscard]] std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    keygen() const override {
        // slh_keygen returns (sk, pk) - normalize to (pk, sk)
        auto [sk, pk] = slhdsa::slh_keygen(params_);
        return {std::move(pk), std::move(sk)};
    }

    [[nodiscard]] std::vector<uint8_t> sign(
        std::span<const uint8_t> sk,
        std::span<const uint8_t> message,
        std::span<const uint8_t> ctx = {}) const override {
        return slhdsa::slh_sign(params_, message, sk, ctx);
    }

    [[nodiscard]] bool verify(
        std::span<const uint8_t> pk,
        std::span<const uint8_t> message,
        std::span<const uint8_t> signature,
        std::span<const uint8_t> ctx = {}) const override {
        return slhdsa::slh_verify(params_, message, signature, pk, ctx);
    }

    [[nodiscard]] size_t public_key_size() const override {
        return params_.pk_size();
    }

    [[nodiscard]] size_t secret_key_size() const override {
        return params_.sk_size();
    }

    [[nodiscard]] size_t signature_size() const override {
        return params_.sig_size();
    }

private:
    const slhdsa::Params& params_;
};

// ============================================================================
// ML-KEM Concrete Implementation
// ============================================================================

class MLKEMAdapter final : public KeyEncapsulation {
public:
    explicit MLKEMAdapter(const mlkem::Params& params)
        : impl_(params), params_(params) {}

    [[nodiscard]] std::string name() const override {
        return std::string(params_.name);
    }

    [[nodiscard]] std::string standard() const override {
        return "FIPS 203";
    }

    [[nodiscard]] std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    keygen() const override {
        return impl_.keygen();
    }

    [[nodiscard]] std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    encaps(std::span<const uint8_t> ek) const override {
        return impl_.encaps(ek);
    }

    [[nodiscard]] std::vector<uint8_t> decaps(
        std::span<const uint8_t> dk,
        std::span<const uint8_t> ciphertext) const override {
        return impl_.decaps(dk, ciphertext);
    }

    [[nodiscard]] size_t encapsulation_key_size() const override {
        return params_.ek_size();
    }

    [[nodiscard]] size_t decapsulation_key_size() const override {
        return params_.dk_size();
    }

    [[nodiscard]] size_t ciphertext_size() const override {
        return params_.ct_size();
    }

    [[nodiscard]] size_t shared_secret_size() const override {
        return 32;  // Always 32 bytes for ML-KEM
    }

private:
    mlkem::MLKEM impl_;
    const mlkem::Params& params_;
};

} // namespace detail

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Create a digital signature algorithm by name
 *
 * Supported names (case-sensitive):
 *   ML-DSA: "ML-DSA-44", "ML-DSA-65", "ML-DSA-87"
 *   SLH-DSA: "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
 *            "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
 *            "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
 *            "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
 *            "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
 *            "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
 *
 * @param name Algorithm name
 * @return unique_ptr to DigitalSignature implementation
 * @throws std::invalid_argument if name is not recognized
 */
inline std::unique_ptr<DigitalSignature> create_dsa(const std::string& name) {
    // ML-DSA variants
    if (name == "ML-DSA-44")
        return std::make_unique<detail::MLDSAAdapter>(mldsa::MLDSA44_PARAMS);
    if (name == "ML-DSA-65")
        return std::make_unique<detail::MLDSAAdapter>(mldsa::MLDSA65_PARAMS);
    if (name == "ML-DSA-87")
        return std::make_unique<detail::MLDSAAdapter>(mldsa::MLDSA87_PARAMS);

    // SLH-DSA SHA2 variants
    if (name == "SLH-DSA-SHA2-128s")
        return std::make_unique<detail::SLHDSAAdapter>(slhdsa::SLH_DSA_SHA2_128s);
    if (name == "SLH-DSA-SHA2-128f")
        return std::make_unique<detail::SLHDSAAdapter>(slhdsa::SLH_DSA_SHA2_128f);
    if (name == "SLH-DSA-SHA2-192s")
        return std::make_unique<detail::SLHDSAAdapter>(slhdsa::SLH_DSA_SHA2_192s);
    if (name == "SLH-DSA-SHA2-192f")
        return std::make_unique<detail::SLHDSAAdapter>(slhdsa::SLH_DSA_SHA2_192f);
    if (name == "SLH-DSA-SHA2-256s")
        return std::make_unique<detail::SLHDSAAdapter>(slhdsa::SLH_DSA_SHA2_256s);
    if (name == "SLH-DSA-SHA2-256f")
        return std::make_unique<detail::SLHDSAAdapter>(slhdsa::SLH_DSA_SHA2_256f);

    // SLH-DSA SHAKE variants
    if (name == "SLH-DSA-SHAKE-128s")
        return std::make_unique<detail::SLHDSAAdapter>(slhdsa::SLH_DSA_SHAKE_128s);
    if (name == "SLH-DSA-SHAKE-128f")
        return std::make_unique<detail::SLHDSAAdapter>(slhdsa::SLH_DSA_SHAKE_128f);
    if (name == "SLH-DSA-SHAKE-192s")
        return std::make_unique<detail::SLHDSAAdapter>(slhdsa::SLH_DSA_SHAKE_192s);
    if (name == "SLH-DSA-SHAKE-192f")
        return std::make_unique<detail::SLHDSAAdapter>(slhdsa::SLH_DSA_SHAKE_192f);
    if (name == "SLH-DSA-SHAKE-256s")
        return std::make_unique<detail::SLHDSAAdapter>(slhdsa::SLH_DSA_SHAKE_256s);
    if (name == "SLH-DSA-SHAKE-256f")
        return std::make_unique<detail::SLHDSAAdapter>(slhdsa::SLH_DSA_SHAKE_256f);

    throw std::invalid_argument("Unknown DSA algorithm: " + name);
}

/**
 * Create a key encapsulation mechanism by name
 *
 * Supported names (case-sensitive):
 *   "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"
 *
 * @param name Algorithm name
 * @return unique_ptr to KeyEncapsulation implementation
 * @throws std::invalid_argument if name is not recognized
 */
inline std::unique_ptr<KeyEncapsulation> create_kem(const std::string& name) {
    if (name == "ML-KEM-512")
        return std::make_unique<detail::MLKEMAdapter>(mlkem::MLKEM512_PARAMS);
    if (name == "ML-KEM-768")
        return std::make_unique<detail::MLKEMAdapter>(mlkem::MLKEM768_PARAMS);
    if (name == "ML-KEM-1024")
        return std::make_unique<detail::MLKEMAdapter>(mlkem::MLKEM1024_PARAMS);

    throw std::invalid_argument("Unknown KEM algorithm: " + name);
}

/**
 * List all available DSA algorithm names
 */
inline std::vector<std::string> available_dsa_algorithms() {
    return {
        "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
        "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128f",
        "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256f",
        "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
        "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f"
    };
}

/**
 * List all available KEM algorithm names
 */
inline std::vector<std::string> available_kem_algorithms() {
    return {
        "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"
    };
}

/**
 * Check if a DSA algorithm name is supported
 */
inline bool is_dsa_algorithm(const std::string& name) {
    auto algos = available_dsa_algorithms();
    for (const auto& a : algos) {
        if (a == name) return true;
    }
    return false;
}

/**
 * Check if a KEM algorithm name is supported
 */
inline bool is_kem_algorithm(const std::string& name) {
    auto algos = available_kem_algorithms();
    for (const auto& a : algos) {
        if (a == name) return true;
    }
    return false;
}

} // namespace pqc

#endif // COMMON_ALGORITHM_FACTORY_HPP
