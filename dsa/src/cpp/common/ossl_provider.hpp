/**
 * OpenSSL 3.x Provider for Post-Quantum Cryptography
 *
 * Provides OpenSSL 3.x provider integration for ML-DSA, SLH-DSA, and ML-KEM
 * algorithms, allowing existing applications to use PQC through the standard
 * OpenSSL EVP API.
 *
 * Key Features:
 * - OpenSSL 3.x provider interface implementation
 * - EVP_PKEY support for all PQC algorithms
 * - EVP_MD_CTX integration for signing/verification
 * - EVP_PKEY_CTX support for key encapsulation
 * - Algorithm registration with proper NID/OID mapping
 * - Thread-safe operation
 *
 * Supported Algorithms:
 * - ML-DSA-44, ML-DSA-65, ML-DSA-87 (FIPS 204)
 * - All 12 SLH-DSA parameter sets (FIPS 205)
 * - ML-KEM-512, ML-KEM-768, ML-KEM-1024 (FIPS 203)
 *
 * Usage:
 *   // Load the provider
 *   auto provider = pqc::ossl::PQCProvider::create();
 *   provider->load();
 *
 *   // Generate key using EVP API
 *   EVP_PKEY* pkey = nullptr;
 *   EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "ML-DSA-65", nullptr);
 *   EVP_PKEY_keygen_init(ctx);
 *   EVP_PKEY_generate(ctx, &pkey);
 *
 *   // Sign using EVP_DigestSign API
 *   EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
 *   EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, pkey);
 *   EVP_DigestSign(md_ctx, sig, &sig_len, msg, msg_len);
 *
 * Note: This is a simulation of OpenSSL provider integration for testing.
 * Production use requires building as an actual OpenSSL shared library provider.
 */

#ifndef PQC_COMMON_OSSL_PROVIDER_HPP
#define PQC_COMMON_OSSL_PROVIDER_HPP

#include "mldsa/mldsa.hpp"
#include "slhdsa/slh_dsa.hpp"
#include "mlkem/mlkem.hpp"
#include "algorithm_factory.hpp"
#include <memory>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <functional>
#include <cstring>
#include <algorithm>

namespace pqc::ossl {

// ============================================================================
// Error Types
// ============================================================================

/**
 * OpenSSL provider-related errors
 */
class ProviderError : public std::runtime_error {
public:
    enum class Code {
        OK = 0,
        PROVIDER_NOT_LOADED,
        ALGORITHM_NOT_FOUND,
        KEY_GENERATION_FAILED,
        SIGNING_FAILED,
        VERIFICATION_FAILED,
        ENCAPSULATION_FAILED,
        DECAPSULATION_FAILED,
        INVALID_KEY,
        INVALID_SIGNATURE,
        INVALID_CIPHERTEXT,
        CONTEXT_ERROR,
        NOT_INITIALIZED,
        OPERATION_NOT_SUPPORTED,
        GENERAL_ERROR
    };

    ProviderError(Code code, const std::string& message)
        : std::runtime_error(message), code_(code) {}

    Code code() const { return code_; }

private:
    Code code_;
};

// ============================================================================
// Algorithm Information
// ============================================================================

/**
 * Algorithm type classification
 */
enum class AlgorithmType {
    SIGNATURE,      // Digital signature (ML-DSA, SLH-DSA)
    KEM             // Key encapsulation (ML-KEM)
};

/**
 * NIST security level
 */
enum class SecurityLevel {
    LEVEL_1 = 1,    // AES-128 equivalent (ML-KEM-512)
    LEVEL_2 = 2,    // AES-192 equivalent (ML-DSA-44)
    LEVEL_3 = 3,    // AES-192+ equivalent (ML-DSA-65, ML-KEM-768)
    LEVEL_5 = 5     // AES-256 equivalent (ML-DSA-87, ML-KEM-1024)
};

/**
 * Algorithm metadata
 */
struct AlgorithmInfo {
    std::string name;           // Algorithm name (e.g., "ML-DSA-65")
    std::string oid;            // OID string
    AlgorithmType type;         // Signature or KEM
    SecurityLevel level;        // NIST security level
    size_t public_key_size;     // Public key size in bytes
    size_t secret_key_size;     // Secret key size in bytes
    size_t signature_size;      // Signature size (signatures only)
    size_t ciphertext_size;     // Ciphertext size (KEM only)
    size_t shared_secret_size;  // Shared secret size (KEM only)
};

// ============================================================================
// Key Context (simulates EVP_PKEY)
// ============================================================================

/**
 * Key context that mimics OpenSSL EVP_PKEY
 * Holds PQC key material and provides sign/verify/encaps/decaps operations
 */
class KeyContext {
public:
    KeyContext(const std::string& algorithm)
        : algorithm_(algorithm), has_private_(false) {

        // Initialize with algorithm factory
        if (pqc::is_dsa_algorithm(algorithm)) {
            dsa_ = pqc::create_dsa(algorithm);
            type_ = AlgorithmType::SIGNATURE;
        } else if (pqc::is_kem_algorithm(algorithm)) {
            kem_ = pqc::create_kem(algorithm);
            type_ = AlgorithmType::KEM;
        } else {
            throw ProviderError(ProviderError::Code::ALGORITHM_NOT_FOUND,
                "Unknown algorithm: " + algorithm);
        }
    }

    /**
     * Generate a new key pair
     */
    void generate() {
        if (type_ == AlgorithmType::SIGNATURE) {
            auto [pk, sk] = dsa_->keygen();
            public_key_ = std::move(pk);
            secret_key_ = std::move(sk);
        } else {
            auto [pk, sk] = kem_->keygen();
            public_key_ = std::move(pk);
            secret_key_ = std::move(sk);
        }
        has_private_ = true;
    }

    /**
     * Import a public key
     */
    void set_public_key(const std::vector<uint8_t>& key) {
        public_key_ = key;
    }

    /**
     * Import a private key (includes both public and secret)
     */
    void set_private_key(const std::vector<uint8_t>& public_key,
                         const std::vector<uint8_t>& secret_key) {
        public_key_ = public_key;
        secret_key_ = secret_key;
        has_private_ = true;
    }

    /**
     * Get the public key
     */
    const std::vector<uint8_t>& public_key() const {
        return public_key_;
    }

    /**
     * Get the secret key (throws if not available)
     */
    const std::vector<uint8_t>& secret_key() const {
        if (!has_private_) {
            throw ProviderError(ProviderError::Code::INVALID_KEY,
                "No private key available");
        }
        return secret_key_;
    }

    /**
     * Check if private key is available
     */
    bool has_private_key() const {
        return has_private_;
    }

    /**
     * Get algorithm name
     */
    const std::string& algorithm() const {
        return algorithm_;
    }

    /**
     * Get algorithm type
     */
    AlgorithmType type() const {
        return type_;
    }

    /**
     * Sign a message (signature algorithms only)
     */
    std::vector<uint8_t> sign(std::span<const uint8_t> message) const {
        if (type_ != AlgorithmType::SIGNATURE) {
            throw ProviderError(ProviderError::Code::OPERATION_NOT_SUPPORTED,
                "Algorithm does not support signing");
        }
        if (!has_private_) {
            throw ProviderError(ProviderError::Code::INVALID_KEY,
                "No private key for signing");
        }
        return dsa_->sign(secret_key_, message);
    }

    /**
     * Sign with context string
     */
    std::vector<uint8_t> sign(std::span<const uint8_t> message,
                              std::span<const uint8_t> context) const {
        if (type_ != AlgorithmType::SIGNATURE) {
            throw ProviderError(ProviderError::Code::OPERATION_NOT_SUPPORTED,
                "Algorithm does not support signing");
        }
        if (!has_private_) {
            throw ProviderError(ProviderError::Code::INVALID_KEY,
                "No private key for signing");
        }
        return dsa_->sign(secret_key_, message, context);
    }

    /**
     * Verify a signature
     */
    bool verify(std::span<const uint8_t> message,
                std::span<const uint8_t> signature) const {
        if (type_ != AlgorithmType::SIGNATURE) {
            throw ProviderError(ProviderError::Code::OPERATION_NOT_SUPPORTED,
                "Algorithm does not support verification");
        }
        return dsa_->verify(public_key_, message, signature);
    }

    /**
     * Verify with context string
     */
    bool verify(std::span<const uint8_t> message,
                std::span<const uint8_t> signature,
                std::span<const uint8_t> context) const {
        if (type_ != AlgorithmType::SIGNATURE) {
            throw ProviderError(ProviderError::Code::OPERATION_NOT_SUPPORTED,
                "Algorithm does not support verification");
        }
        return dsa_->verify(public_key_, message, signature, context);
    }

    /**
     * Encapsulate (KEM only) - returns (ciphertext, shared_secret)
     */
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encapsulate() const {
        if (type_ != AlgorithmType::KEM) {
            throw ProviderError(ProviderError::Code::OPERATION_NOT_SUPPORTED,
                "Algorithm does not support encapsulation");
        }
        // encaps returns (shared_secret, ciphertext), we return (ciphertext, shared_secret)
        auto [ss, ct] = kem_->encaps(public_key_);
        return {ct, ss};
    }

    /**
     * Decapsulate (KEM only)
     */
    std::vector<uint8_t> decapsulate(std::span<const uint8_t> ciphertext) const {
        if (type_ != AlgorithmType::KEM) {
            throw ProviderError(ProviderError::Code::OPERATION_NOT_SUPPORTED,
                "Algorithm does not support decapsulation");
        }
        if (!has_private_) {
            throw ProviderError(ProviderError::Code::INVALID_KEY,
                "No private key for decapsulation");
        }
        return kem_->decaps(secret_key_, ciphertext);
    }

    /**
     * Get public key size for this algorithm
     */
    size_t public_key_size() const {
        if (type_ == AlgorithmType::SIGNATURE) {
            return dsa_->public_key_size();
        } else {
            return kem_->encapsulation_key_size();
        }
    }

    /**
     * Get secret key size for this algorithm
     */
    size_t secret_key_size() const {
        if (type_ == AlgorithmType::SIGNATURE) {
            return dsa_->secret_key_size();
        } else {
            return kem_->decapsulation_key_size();
        }
    }

    /**
     * Get signature size for this algorithm (signatures only)
     */
    size_t signature_size() const {
        if (type_ != AlgorithmType::SIGNATURE) {
            return 0;
        }
        return dsa_->signature_size();
    }

    /**
     * Get ciphertext size for this algorithm (KEM only)
     */
    size_t ciphertext_size() const {
        if (type_ != AlgorithmType::KEM) {
            return 0;
        }
        return kem_->ciphertext_size();
    }

    /**
     * Get shared secret size for this algorithm (KEM only)
     */
    size_t shared_secret_size() const {
        if (type_ != AlgorithmType::KEM) {
            return 0;
        }
        return kem_->shared_secret_size();
    }

private:
    std::string algorithm_;
    AlgorithmType type_;
    bool has_private_;
    std::vector<uint8_t> public_key_;
    std::vector<uint8_t> secret_key_;
    std::unique_ptr<pqc::DigitalSignature> dsa_;
    std::unique_ptr<pqc::KeyEncapsulation> kem_;
};

// ============================================================================
// Signing Context (simulates EVP_MD_CTX for DigestSign)
// ============================================================================

/**
 * Signing context that mimics OpenSSL EVP_MD_CTX
 * Accumulates message data for signing/verification
 */
class SignContext {
public:
    enum class Mode {
        NONE,
        SIGN,
        VERIFY
    };

    SignContext() : mode_(Mode::NONE), key_(nullptr) {}

    /**
     * Initialize for signing
     */
    void init_sign(std::shared_ptr<KeyContext> key,
                   std::span<const uint8_t> context = {}) {
        if (!key || !key->has_private_key()) {
            throw ProviderError(ProviderError::Code::INVALID_KEY,
                "Valid private key required for signing");
        }
        if (key->type() != AlgorithmType::SIGNATURE) {
            throw ProviderError(ProviderError::Code::OPERATION_NOT_SUPPORTED,
                "Key does not support signing");
        }
        mode_ = Mode::SIGN;
        key_ = key;
        context_.assign(context.begin(), context.end());
        message_.clear();
    }

    /**
     * Initialize for verification
     */
    void init_verify(std::shared_ptr<KeyContext> key,
                     std::span<const uint8_t> context = {}) {
        if (!key) {
            throw ProviderError(ProviderError::Code::INVALID_KEY,
                "Valid key required for verification");
        }
        if (key->type() != AlgorithmType::SIGNATURE) {
            throw ProviderError(ProviderError::Code::OPERATION_NOT_SUPPORTED,
                "Key does not support verification");
        }
        mode_ = Mode::VERIFY;
        key_ = key;
        context_.assign(context.begin(), context.end());
        message_.clear();
    }

    /**
     * Update with message data
     */
    void update(std::span<const uint8_t> data) {
        if (mode_ == Mode::NONE) {
            throw ProviderError(ProviderError::Code::NOT_INITIALIZED,
                "Context not initialized");
        }
        message_.insert(message_.end(), data.begin(), data.end());
    }

    /**
     * Finalize signing and return signature
     */
    std::vector<uint8_t> sign_final() {
        if (mode_ != Mode::SIGN) {
            throw ProviderError(ProviderError::Code::CONTEXT_ERROR,
                "Context not initialized for signing");
        }
        std::vector<uint8_t> result;
        if (context_.empty()) {
            result = key_->sign(message_);
        } else {
            result = key_->sign(message_, context_);
        }
        reset();
        return result;
    }

    /**
     * Finalize verification
     */
    bool verify_final(std::span<const uint8_t> signature) {
        if (mode_ != Mode::VERIFY) {
            throw ProviderError(ProviderError::Code::CONTEXT_ERROR,
                "Context not initialized for verification");
        }
        bool result;
        if (context_.empty()) {
            result = key_->verify(message_, signature);
        } else {
            result = key_->verify(message_, signature, context_);
        }
        reset();
        return result;
    }

    /**
     * One-shot sign (init + update + final)
     */
    std::vector<uint8_t> sign(std::shared_ptr<KeyContext> key,
                              std::span<const uint8_t> message,
                              std::span<const uint8_t> context = {}) {
        init_sign(key, context);
        update(message);
        return sign_final();
    }

    /**
     * One-shot verify (init + update + final)
     */
    bool verify(std::shared_ptr<KeyContext> key,
                std::span<const uint8_t> message,
                std::span<const uint8_t> signature,
                std::span<const uint8_t> context = {}) {
        init_verify(key, context);
        update(message);
        return verify_final(signature);
    }

    /**
     * Get current mode
     */
    Mode mode() const { return mode_; }

    /**
     * Reset context
     */
    void reset() {
        mode_ = Mode::NONE;
        key_.reset();
        message_.clear();
        context_.clear();
    }

private:
    Mode mode_;
    std::shared_ptr<KeyContext> key_;
    std::vector<uint8_t> message_;
    std::vector<uint8_t> context_;
};

// ============================================================================
// KEM Context (simulates EVP_PKEY_CTX for encapsulation)
// ============================================================================

/**
 * KEM context for encapsulation/decapsulation operations
 */
class KemContext {
public:
    enum class Mode {
        NONE,
        ENCAPS,
        DECAPS
    };

    KemContext() : mode_(Mode::NONE), key_(nullptr) {}

    /**
     * Initialize for encapsulation
     */
    void init_encaps(std::shared_ptr<KeyContext> key) {
        if (!key) {
            throw ProviderError(ProviderError::Code::INVALID_KEY,
                "Valid key required for encapsulation");
        }
        if (key->type() != AlgorithmType::KEM) {
            throw ProviderError(ProviderError::Code::OPERATION_NOT_SUPPORTED,
                "Key does not support encapsulation");
        }
        mode_ = Mode::ENCAPS;
        key_ = key;
    }

    /**
     * Initialize for decapsulation
     */
    void init_decaps(std::shared_ptr<KeyContext> key) {
        if (!key || !key->has_private_key()) {
            throw ProviderError(ProviderError::Code::INVALID_KEY,
                "Valid private key required for decapsulation");
        }
        if (key->type() != AlgorithmType::KEM) {
            throw ProviderError(ProviderError::Code::OPERATION_NOT_SUPPORTED,
                "Key does not support decapsulation");
        }
        mode_ = Mode::DECAPS;
        key_ = key;
    }

    /**
     * Perform encapsulation
     * Returns (ciphertext, shared_secret)
     */
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encapsulate() {
        if (mode_ != Mode::ENCAPS) {
            throw ProviderError(ProviderError::Code::CONTEXT_ERROR,
                "Context not initialized for encapsulation");
        }
        return key_->encapsulate();
    }

    /**
     * Perform decapsulation
     */
    std::vector<uint8_t> decapsulate(std::span<const uint8_t> ciphertext) {
        if (mode_ != Mode::DECAPS) {
            throw ProviderError(ProviderError::Code::CONTEXT_ERROR,
                "Context not initialized for decapsulation");
        }
        return key_->decapsulate(ciphertext);
    }

    /**
     * Get current mode
     */
    Mode mode() const { return mode_; }

    /**
     * Reset context
     */
    void reset() {
        mode_ = Mode::NONE;
        key_.reset();
    }

private:
    Mode mode_;
    std::shared_ptr<KeyContext> key_;
};

// ============================================================================
// PQC Provider (simulates OSSL_PROVIDER)
// ============================================================================

/**
 * Main provider class that registers PQC algorithms with OpenSSL-like interface
 */
class PQCProvider {
public:
    /**
     * Create a new PQC provider instance
     */
    static std::unique_ptr<PQCProvider> create() {
        return std::unique_ptr<PQCProvider>(new PQCProvider());
    }

    /**
     * Load the provider (makes algorithms available)
     */
    void load() {
        if (loaded_) {
            return;
        }

        // Register all algorithms
        register_signature_algorithms();
        register_kem_algorithms();

        loaded_ = true;
    }

    /**
     * Unload the provider
     */
    void unload() {
        if (!loaded_) {
            return;
        }

        algorithms_.clear();
        loaded_ = false;
    }

    /**
     * Check if provider is loaded
     */
    bool is_loaded() const {
        return loaded_;
    }

    /**
     * Get provider name
     */
    static std::string name() {
        return "pqc";
    }

    /**
     * Get provider version
     */
    static std::string version() {
        return "1.0.0";
    }

    /**
     * Get list of all registered algorithms
     */
    std::vector<std::string> algorithms() const {
        std::vector<std::string> names;
        names.reserve(algorithms_.size());
        for (const auto& [name, info] : algorithms_) {
            names.push_back(name);
        }
        return names;
    }

    /**
     * Get list of signature algorithms
     */
    std::vector<std::string> signature_algorithms() const {
        std::vector<std::string> names;
        for (const auto& [name, info] : algorithms_) {
            if (info.type == AlgorithmType::SIGNATURE) {
                names.push_back(name);
            }
        }
        return names;
    }

    /**
     * Get list of KEM algorithms
     */
    std::vector<std::string> kem_algorithms() const {
        std::vector<std::string> names;
        for (const auto& [name, info] : algorithms_) {
            if (info.type == AlgorithmType::KEM) {
                names.push_back(name);
            }
        }
        return names;
    }

    /**
     * Check if algorithm is available
     */
    bool has_algorithm(const std::string& name) const {
        return algorithms_.find(name) != algorithms_.end();
    }

    /**
     * Get algorithm information
     */
    const AlgorithmInfo& algorithm_info(const std::string& name) const {
        auto it = algorithms_.find(name);
        if (it == algorithms_.end()) {
            throw ProviderError(ProviderError::Code::ALGORITHM_NOT_FOUND,
                "Algorithm not found: " + name);
        }
        return it->second;
    }

    /**
     * Create a new key context for an algorithm
     * Similar to EVP_PKEY_CTX_new_from_name()
     */
    std::shared_ptr<KeyContext> create_key_context(const std::string& algorithm) {
        if (!loaded_) {
            throw ProviderError(ProviderError::Code::PROVIDER_NOT_LOADED,
                "Provider not loaded");
        }
        if (!has_algorithm(algorithm)) {
            throw ProviderError(ProviderError::Code::ALGORITHM_NOT_FOUND,
                "Algorithm not found: " + algorithm);
        }
        return std::make_shared<KeyContext>(algorithm);
    }

    /**
     * Create a signing context
     * Similar to EVP_MD_CTX_new()
     */
    std::unique_ptr<SignContext> create_sign_context() {
        if (!loaded_) {
            throw ProviderError(ProviderError::Code::PROVIDER_NOT_LOADED,
                "Provider not loaded");
        }
        return std::make_unique<SignContext>();
    }

    /**
     * Create a KEM context
     */
    std::unique_ptr<KemContext> create_kem_context() {
        if (!loaded_) {
            throw ProviderError(ProviderError::Code::PROVIDER_NOT_LOADED,
                "Provider not loaded");
        }
        return std::make_unique<KemContext>();
    }

    /**
     * Generate a key pair for an algorithm
     * Convenience function wrapping key context operations
     */
    std::shared_ptr<KeyContext> generate_keypair(const std::string& algorithm) {
        auto key = create_key_context(algorithm);
        key->generate();
        return key;
    }

    /**
     * Import a public key
     */
    std::shared_ptr<KeyContext> import_public_key(
        const std::string& algorithm,
        std::span<const uint8_t> public_key) {

        auto key = create_key_context(algorithm);
        key->set_public_key(std::vector<uint8_t>(public_key.begin(), public_key.end()));
        return key;
    }

    /**
     * Import a key pair
     */
    std::shared_ptr<KeyContext> import_keypair(
        const std::string& algorithm,
        std::span<const uint8_t> public_key,
        std::span<const uint8_t> secret_key) {

        auto key = create_key_context(algorithm);
        key->set_private_key(
            std::vector<uint8_t>(public_key.begin(), public_key.end()),
            std::vector<uint8_t>(secret_key.begin(), secret_key.end()));
        return key;
    }

private:
    PQCProvider() : loaded_(false) {}

    void register_signature_algorithms() {
        // ML-DSA algorithms (FIPS 204)
        algorithms_["ML-DSA-44"] = {
            "ML-DSA-44",
            "2.16.840.1.101.3.4.3.17",
            AlgorithmType::SIGNATURE,
            SecurityLevel::LEVEL_2,
            1312, 2560, 2420, 0, 0
        };

        algorithms_["ML-DSA-65"] = {
            "ML-DSA-65",
            "2.16.840.1.101.3.4.3.18",
            AlgorithmType::SIGNATURE,
            SecurityLevel::LEVEL_3,
            1952, 4032, 3309, 0, 0
        };

        algorithms_["ML-DSA-87"] = {
            "ML-DSA-87",
            "2.16.840.1.101.3.4.3.19",
            AlgorithmType::SIGNATURE,
            SecurityLevel::LEVEL_5,
            2592, 4896, 4627, 0, 0
        };

        // SLH-DSA algorithms (FIPS 205) - SHA2 variants
        algorithms_["SLH-DSA-SHA2-128f"] = {
            "SLH-DSA-SHA2-128f",
            "2.16.840.1.101.3.4.3.20",
            AlgorithmType::SIGNATURE,
            SecurityLevel::LEVEL_1,
            32, 64, 17088, 0, 0
        };

        algorithms_["SLH-DSA-SHA2-128s"] = {
            "SLH-DSA-SHA2-128s",
            "2.16.840.1.101.3.4.3.21",
            AlgorithmType::SIGNATURE,
            SecurityLevel::LEVEL_1,
            32, 64, 7856, 0, 0
        };

        algorithms_["SLH-DSA-SHA2-192f"] = {
            "SLH-DSA-SHA2-192f",
            "2.16.840.1.101.3.4.3.22",
            AlgorithmType::SIGNATURE,
            SecurityLevel::LEVEL_3,
            48, 96, 35664, 0, 0
        };

        algorithms_["SLH-DSA-SHA2-192s"] = {
            "SLH-DSA-SHA2-192s",
            "2.16.840.1.101.3.4.3.23",
            AlgorithmType::SIGNATURE,
            SecurityLevel::LEVEL_3,
            48, 96, 16224, 0, 0
        };

        algorithms_["SLH-DSA-SHA2-256f"] = {
            "SLH-DSA-SHA2-256f",
            "2.16.840.1.101.3.4.3.24",
            AlgorithmType::SIGNATURE,
            SecurityLevel::LEVEL_5,
            64, 128, 49856, 0, 0
        };

        algorithms_["SLH-DSA-SHA2-256s"] = {
            "SLH-DSA-SHA2-256s",
            "2.16.840.1.101.3.4.3.25",
            AlgorithmType::SIGNATURE,
            SecurityLevel::LEVEL_5,
            64, 128, 29792, 0, 0
        };

        // SLH-DSA algorithms - SHAKE variants
        algorithms_["SLH-DSA-SHAKE-128f"] = {
            "SLH-DSA-SHAKE-128f",
            "2.16.840.1.101.3.4.3.26",
            AlgorithmType::SIGNATURE,
            SecurityLevel::LEVEL_1,
            32, 64, 17088, 0, 0
        };

        algorithms_["SLH-DSA-SHAKE-128s"] = {
            "SLH-DSA-SHAKE-128s",
            "2.16.840.1.101.3.4.3.27",
            AlgorithmType::SIGNATURE,
            SecurityLevel::LEVEL_1,
            32, 64, 7856, 0, 0
        };

        algorithms_["SLH-DSA-SHAKE-192f"] = {
            "SLH-DSA-SHAKE-192f",
            "2.16.840.1.101.3.4.3.28",
            AlgorithmType::SIGNATURE,
            SecurityLevel::LEVEL_3,
            48, 96, 35664, 0, 0
        };

        algorithms_["SLH-DSA-SHAKE-192s"] = {
            "SLH-DSA-SHAKE-192s",
            "2.16.840.1.101.3.4.3.29",
            AlgorithmType::SIGNATURE,
            SecurityLevel::LEVEL_3,
            48, 96, 16224, 0, 0
        };

        algorithms_["SLH-DSA-SHAKE-256f"] = {
            "SLH-DSA-SHAKE-256f",
            "2.16.840.1.101.3.4.3.30",
            AlgorithmType::SIGNATURE,
            SecurityLevel::LEVEL_5,
            64, 128, 49856, 0, 0
        };

        algorithms_["SLH-DSA-SHAKE-256s"] = {
            "SLH-DSA-SHAKE-256s",
            "2.16.840.1.101.3.4.3.31",
            AlgorithmType::SIGNATURE,
            SecurityLevel::LEVEL_5,
            64, 128, 29792, 0, 0
        };
    }

    void register_kem_algorithms() {
        // ML-KEM algorithms (FIPS 203)
        algorithms_["ML-KEM-512"] = {
            "ML-KEM-512",
            "2.16.840.1.101.3.4.4.1",
            AlgorithmType::KEM,
            SecurityLevel::LEVEL_1,
            800, 1632, 0, 768, 32
        };

        algorithms_["ML-KEM-768"] = {
            "ML-KEM-768",
            "2.16.840.1.101.3.4.4.2",
            AlgorithmType::KEM,
            SecurityLevel::LEVEL_3,
            1184, 2400, 0, 1088, 32
        };

        algorithms_["ML-KEM-1024"] = {
            "ML-KEM-1024",
            "2.16.840.1.101.3.4.4.3",
            AlgorithmType::KEM,
            SecurityLevel::LEVEL_5,
            1568, 3168, 0, 1568, 32
        };
    }

    bool loaded_;
    std::map<std::string, AlgorithmInfo> algorithms_;
};

// ============================================================================
// Convenience Functions (EVP-style API)
// ============================================================================

/**
 * Global provider instance (singleton pattern like OpenSSL's default provider)
 */
inline PQCProvider& default_provider() {
    static std::unique_ptr<PQCProvider> provider = PQCProvider::create();
    static std::once_flag init_flag;
    std::call_once(init_flag, []() {
        provider->load();
    });
    return *provider;
}

/**
 * Generate a key pair
 * Similar to EVP_PKEY_keygen()
 */
inline std::shared_ptr<KeyContext> keygen(const std::string& algorithm) {
    return default_provider().generate_keypair(algorithm);
}

/**
 * Sign a message
 * Similar to EVP_DigestSign()
 */
inline std::vector<uint8_t> sign(
    const std::shared_ptr<KeyContext>& key,
    std::span<const uint8_t> message,
    std::span<const uint8_t> context = {}) {

    if (context.empty()) {
        return key->sign(message);
    }
    return key->sign(message, context);
}

/**
 * Verify a signature
 * Similar to EVP_DigestVerify()
 */
inline bool verify(
    const std::shared_ptr<KeyContext>& key,
    std::span<const uint8_t> message,
    std::span<const uint8_t> signature,
    std::span<const uint8_t> context = {}) {

    if (context.empty()) {
        return key->verify(message, signature);
    }
    return key->verify(message, signature, context);
}

/**
 * Encapsulate
 * Returns (ciphertext, shared_secret)
 */
inline std::pair<std::vector<uint8_t>, std::vector<uint8_t>> encapsulate(
    const std::shared_ptr<KeyContext>& key) {
    return key->encapsulate();
}

/**
 * Decapsulate
 */
inline std::vector<uint8_t> decapsulate(
    const std::shared_ptr<KeyContext>& key,
    std::span<const uint8_t> ciphertext) {
    return key->decapsulate(ciphertext);
}

// ============================================================================
// Algorithm Name Mapping (for compatibility)
// ============================================================================

/**
 * Map internal algorithm names to OpenSSL provider names
 */
inline std::string to_provider_name(const std::string& internal_name) {
    // ML-DSA
    if (internal_name == "ML-DSA-44" || internal_name == "mldsa44") return "ML-DSA-44";
    if (internal_name == "ML-DSA-65" || internal_name == "mldsa65") return "ML-DSA-65";
    if (internal_name == "ML-DSA-87" || internal_name == "mldsa87") return "ML-DSA-87";

    // SLH-DSA SHA2
    if (internal_name == "SLH-DSA-SHA2-128f" || internal_name == "slh-sha2-128f")
        return "SLH-DSA-SHA2-128f";
    if (internal_name == "SLH-DSA-SHA2-128s" || internal_name == "slh-sha2-128s")
        return "SLH-DSA-SHA2-128s";
    if (internal_name == "SLH-DSA-SHA2-192f" || internal_name == "slh-sha2-192f")
        return "SLH-DSA-SHA2-192f";
    if (internal_name == "SLH-DSA-SHA2-192s" || internal_name == "slh-sha2-192s")
        return "SLH-DSA-SHA2-192s";
    if (internal_name == "SLH-DSA-SHA2-256f" || internal_name == "slh-sha2-256f")
        return "SLH-DSA-SHA2-256f";
    if (internal_name == "SLH-DSA-SHA2-256s" || internal_name == "slh-sha2-256s")
        return "SLH-DSA-SHA2-256s";

    // SLH-DSA SHAKE
    if (internal_name == "SLH-DSA-SHAKE-128f" || internal_name == "slh-shake-128f")
        return "SLH-DSA-SHAKE-128f";
    if (internal_name == "SLH-DSA-SHAKE-128s" || internal_name == "slh-shake-128s")
        return "SLH-DSA-SHAKE-128s";
    if (internal_name == "SLH-DSA-SHAKE-192f" || internal_name == "slh-shake-192f")
        return "SLH-DSA-SHAKE-192f";
    if (internal_name == "SLH-DSA-SHAKE-192s" || internal_name == "slh-shake-192s")
        return "SLH-DSA-SHAKE-192s";
    if (internal_name == "SLH-DSA-SHAKE-256f" || internal_name == "slh-shake-256f")
        return "SLH-DSA-SHAKE-256f";
    if (internal_name == "SLH-DSA-SHAKE-256s" || internal_name == "slh-shake-256s")
        return "SLH-DSA-SHAKE-256s";

    // ML-KEM
    if (internal_name == "ML-KEM-512" || internal_name == "mlkem512") return "ML-KEM-512";
    if (internal_name == "ML-KEM-768" || internal_name == "mlkem768") return "ML-KEM-768";
    if (internal_name == "ML-KEM-1024" || internal_name == "mlkem1024") return "ML-KEM-1024";

    return internal_name;
}

/**
 * Map OpenSSL provider names to internal algorithm names
 */
inline std::string from_provider_name(const std::string& provider_name) {
    // ML-DSA
    if (provider_name == "ML-DSA-44") return "ML-DSA-44";
    if (provider_name == "ML-DSA-65") return "ML-DSA-65";
    if (provider_name == "ML-DSA-87") return "ML-DSA-87";

    // SLH-DSA SHA2
    if (provider_name == "SLH-DSA-SHA2-128f") return "slh-sha2-128f";
    if (provider_name == "SLH-DSA-SHA2-128s") return "slh-sha2-128s";
    if (provider_name == "SLH-DSA-SHA2-192f") return "slh-sha2-192f";
    if (provider_name == "SLH-DSA-SHA2-192s") return "slh-sha2-192s";
    if (provider_name == "SLH-DSA-SHA2-256f") return "slh-sha2-256f";
    if (provider_name == "SLH-DSA-SHA2-256s") return "slh-sha2-256s";

    // SLH-DSA SHAKE
    if (provider_name == "SLH-DSA-SHAKE-128f") return "slh-shake-128f";
    if (provider_name == "SLH-DSA-SHAKE-128s") return "slh-shake-128s";
    if (provider_name == "SLH-DSA-SHAKE-192f") return "slh-shake-192f";
    if (provider_name == "SLH-DSA-SHAKE-192s") return "slh-shake-192s";
    if (provider_name == "SLH-DSA-SHAKE-256f") return "slh-shake-256f";
    if (provider_name == "SLH-DSA-SHAKE-256s") return "slh-shake-256s";

    // ML-KEM
    if (provider_name == "ML-KEM-512") return "ML-KEM-512";
    if (provider_name == "ML-KEM-768") return "ML-KEM-768";
    if (provider_name == "ML-KEM-1024") return "ML-KEM-1024";

    return provider_name;
}

} // namespace pqc::ossl

#endif // PQC_COMMON_OSSL_PROVIDER_HPP
