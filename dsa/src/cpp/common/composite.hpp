/**
 * Composite Signatures for X.509 PKI
 *
 * Implements composite (hybrid) signatures combining ML-DSA with classical
 * algorithms (ECDSA, Ed25519, Ed448) per draft-ietf-lamps-pq-composite-sigs.
 *
 * Composite signatures provide dual-algorithm security during the PQC
 * transition period. Both signatures must verify for the composite to be valid.
 *
 * Supported combinations:
 *   - MLDSA44-ECDSA-P256-SHA256
 *   - MLDSA44-Ed25519-SHA512
 *   - MLDSA65-ECDSA-P256-SHA512
 *   - MLDSA65-ECDSA-P384-SHA512
 *   - MLDSA65-Ed25519-SHA512
 *   - MLDSA87-ECDSA-P384-SHA512
 *   - MLDSA87-Ed448-SHA512
 *
 * Usage:
 *   auto composite = pqc::create_composite_dsa("MLDSA65-ECDSA-P256");
 *   auto [pk, sk] = composite->keygen();
 *   auto sig = composite->sign(sk, message);
 *   bool valid = composite->verify(pk, message, sig);
 *
 * Reference: draft-ietf-lamps-pq-composite-sigs-13 (October 2025)
 */

#ifndef COMMON_COMPOSITE_HPP
#define COMMON_COMPOSITE_HPP

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>
#include <stdexcept>
#include <cstring>
#include <map>
#include <algorithm>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#include "algorithm_factory.hpp"
#include "mldsa/mldsa.hpp"

namespace pqc {
namespace composite {

// ============================================================================
// OID Definitions (draft-ietf-lamps-pq-composite-sigs-13)
// ============================================================================

namespace oid {
    // Base OID arc: 1.3.6.1.5.5.7.6
    // Note: These are from the draft and may change

    // ML-DSA-44 combinations
    inline const std::string MLDSA44_RSA2048_PSS_SHA256    = "1.3.6.1.5.5.7.6.37";
    inline const std::string MLDSA44_RSA2048_PKCS15_SHA256 = "1.3.6.1.5.5.7.6.38";
    inline const std::string MLDSA44_ECDSA_P256_SHA256     = "1.3.6.1.5.5.7.6.41";
    inline const std::string MLDSA44_Ed25519_SHA512        = "1.3.6.1.5.5.7.6.43";

    // ML-DSA-65 combinations
    inline const std::string MLDSA65_RSA3072_PSS_SHA512    = "1.3.6.1.5.5.7.6.44";
    inline const std::string MLDSA65_ECDSA_P256_SHA512     = "1.3.6.1.5.5.7.6.45";
    inline const std::string MLDSA65_ECDSA_P384_SHA512     = "1.3.6.1.5.5.7.6.46";
    inline const std::string MLDSA65_ECDSA_BRAINPOOLP256R1_SHA512 = "1.3.6.1.5.5.7.6.47";
    inline const std::string MLDSA65_Ed25519_SHA512        = "1.3.6.1.5.5.7.6.48";

    // ML-DSA-87 combinations
    inline const std::string MLDSA87_ECDSA_P384_SHA512     = "1.3.6.1.5.5.7.6.49";
    inline const std::string MLDSA87_ECDSA_BRAINPOOLP384R1_SHA512 = "1.3.6.1.5.5.7.6.50";
    inline const std::string MLDSA87_Ed448_SHA512          = "1.3.6.1.5.5.7.6.51";

    // Map algorithm names to OIDs
    inline const std::map<std::string, std::string> NAME_TO_OID = {
        {"MLDSA44-ECDSA-P256", MLDSA44_ECDSA_P256_SHA256},
        {"MLDSA44-ECDSA-P256-SHA256", MLDSA44_ECDSA_P256_SHA256},
        {"MLDSA44-Ed25519", MLDSA44_Ed25519_SHA512},
        {"MLDSA44-Ed25519-SHA512", MLDSA44_Ed25519_SHA512},
        {"MLDSA65-ECDSA-P256", MLDSA65_ECDSA_P256_SHA512},
        {"MLDSA65-ECDSA-P256-SHA512", MLDSA65_ECDSA_P256_SHA512},
        {"MLDSA65-ECDSA-P384", MLDSA65_ECDSA_P384_SHA512},
        {"MLDSA65-ECDSA-P384-SHA512", MLDSA65_ECDSA_P384_SHA512},
        {"MLDSA65-Ed25519", MLDSA65_Ed25519_SHA512},
        {"MLDSA65-Ed25519-SHA512", MLDSA65_Ed25519_SHA512},
        {"MLDSA87-ECDSA-P384", MLDSA87_ECDSA_P384_SHA512},
        {"MLDSA87-ECDSA-P384-SHA512", MLDSA87_ECDSA_P384_SHA512},
        {"MLDSA87-Ed448", MLDSA87_Ed448_SHA512},
        {"MLDSA87-Ed448-SHA512", MLDSA87_Ed448_SHA512},
    };
} // namespace oid

// ============================================================================
// Classical Algorithm Support
// ============================================================================

enum class ClassicalAlgorithm {
    ECDSA_P256,
    ECDSA_P384,
    Ed25519,
    Ed448
};

namespace detail {

// OpenSSL RAII helpers
struct EVP_PKEY_Deleter {
    void operator()(EVP_PKEY* p) const { if (p) EVP_PKEY_free(p); }
};
struct EVP_PKEY_CTX_Deleter {
    void operator()(EVP_PKEY_CTX* p) const { if (p) EVP_PKEY_CTX_free(p); }
};
struct EVP_MD_CTX_Deleter {
    void operator()(EVP_MD_CTX* p) const { if (p) EVP_MD_CTX_free(p); }
};

using EVP_PKEY_ptr = std::unique_ptr<EVP_PKEY, EVP_PKEY_Deleter>;
using EVP_PKEY_CTX_ptr = std::unique_ptr<EVP_PKEY_CTX, EVP_PKEY_CTX_Deleter>;
using EVP_MD_CTX_ptr = std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_Deleter>;

// Get OpenSSL curve name
inline const char* get_curve_name(ClassicalAlgorithm algo) {
    switch (algo) {
        case ClassicalAlgorithm::ECDSA_P256: return "prime256v1";
        case ClassicalAlgorithm::ECDSA_P384: return "secp384r1";
        case ClassicalAlgorithm::Ed25519:    return "ED25519";
        case ClassicalAlgorithm::Ed448:      return "ED448";
        default: return nullptr;
    }
}

// Get classical public key size
inline size_t get_classical_pk_size(ClassicalAlgorithm algo) {
    switch (algo) {
        case ClassicalAlgorithm::ECDSA_P256: return 65;   // Uncompressed: 0x04 || X (32) || Y (32)
        case ClassicalAlgorithm::ECDSA_P384: return 97;   // Uncompressed: 0x04 || X (48) || Y (48)
        case ClassicalAlgorithm::Ed25519:    return 32;
        case ClassicalAlgorithm::Ed448:      return 57;
        default: return 0;
    }
}

// Get classical secret key size
inline size_t get_classical_sk_size(ClassicalAlgorithm algo) {
    switch (algo) {
        case ClassicalAlgorithm::ECDSA_P256: return 32;
        case ClassicalAlgorithm::ECDSA_P384: return 48;
        case ClassicalAlgorithm::Ed25519:    return 32;
        case ClassicalAlgorithm::Ed448:      return 57;
        default: return 0;
    }
}

// Get classical signature size (maximum for ECDSA)
inline size_t get_classical_sig_size(ClassicalAlgorithm algo) {
    switch (algo) {
        case ClassicalAlgorithm::ECDSA_P256: return 72;   // DER-encoded, variable
        case ClassicalAlgorithm::ECDSA_P384: return 104;  // DER-encoded, variable
        case ClassicalAlgorithm::Ed25519:    return 64;   // Fixed
        case ClassicalAlgorithm::Ed448:      return 114;  // Fixed
        default: return 0;
    }
}

// Check if algorithm is EdDSA
inline bool is_eddsa(ClassicalAlgorithm algo) {
    return algo == ClassicalAlgorithm::Ed25519 || algo == ClassicalAlgorithm::Ed448;
}

// ============================================================================
// Classical Key Generation
// ============================================================================

inline std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
classical_keygen(ClassicalAlgorithm algo) {
    EVP_PKEY_ptr pkey(nullptr);

    if (is_eddsa(algo)) {
        // EdDSA key generation
        EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(
            algo == ClassicalAlgorithm::Ed25519 ? EVP_PKEY_ED25519 : EVP_PKEY_ED448,
            nullptr));
        if (!ctx) throw std::runtime_error("Failed to create EdDSA context");

        if (EVP_PKEY_keygen_init(ctx.get()) <= 0)
            throw std::runtime_error("Failed to init EdDSA keygen");

        EVP_PKEY* raw_pkey = nullptr;
        if (EVP_PKEY_keygen(ctx.get(), &raw_pkey) <= 0)
            throw std::runtime_error("Failed to generate EdDSA key");
        pkey.reset(raw_pkey);
    } else {
        // ECDSA key generation
        EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
        if (!ctx) throw std::runtime_error("Failed to create ECDSA context");

        if (EVP_PKEY_keygen_init(ctx.get()) <= 0)
            throw std::runtime_error("Failed to init ECDSA keygen");

        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_utf8_string(
            OSSL_PKEY_PARAM_GROUP_NAME,
            const_cast<char*>(get_curve_name(algo)), 0);
        params[1] = OSSL_PARAM_construct_end();

        if (EVP_PKEY_CTX_set_params(ctx.get(), params) <= 0)
            throw std::runtime_error("Failed to set ECDSA params");

        EVP_PKEY* raw_pkey = nullptr;
        if (EVP_PKEY_keygen(ctx.get(), &raw_pkey) <= 0)
            throw std::runtime_error("Failed to generate ECDSA key");
        pkey.reset(raw_pkey);
    }

    // Extract public key
    std::vector<uint8_t> pk;
    if (is_eddsa(algo)) {
        size_t pk_len = get_classical_pk_size(algo);
        pk.resize(pk_len);
        if (EVP_PKEY_get_raw_public_key(pkey.get(), pk.data(), &pk_len) <= 0)
            throw std::runtime_error("Failed to extract EdDSA public key");
        pk.resize(pk_len);
    } else {
        // Get uncompressed EC point
        size_t pk_len = 0;
        if (EVP_PKEY_get_octet_string_param(pkey.get(),
            OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &pk_len) <= 0)
            throw std::runtime_error("Failed to get ECDSA public key size");

        pk.resize(pk_len);
        if (EVP_PKEY_get_octet_string_param(pkey.get(),
            OSSL_PKEY_PARAM_PUB_KEY, pk.data(), pk_len, &pk_len) <= 0)
            throw std::runtime_error("Failed to extract ECDSA public key");
    }

    // Extract secret key
    std::vector<uint8_t> sk;
    if (is_eddsa(algo)) {
        size_t sk_len = get_classical_sk_size(algo);
        sk.resize(sk_len);
        if (EVP_PKEY_get_raw_private_key(pkey.get(), sk.data(), &sk_len) <= 0)
            throw std::runtime_error("Failed to extract EdDSA secret key");
        sk.resize(sk_len);
    } else {
        BIGNUM* priv_bn = nullptr;
        if (EVP_PKEY_get_bn_param(pkey.get(), OSSL_PKEY_PARAM_PRIV_KEY, &priv_bn) <= 0)
            throw std::runtime_error("Failed to get ECDSA private key");

        size_t sk_len = get_classical_sk_size(algo);
        sk.resize(sk_len);
        BN_bn2binpad(priv_bn, sk.data(), sk_len);
        BN_free(priv_bn);
    }

    return {pk, sk};
}

// ============================================================================
// Classical Signing
// ============================================================================

inline std::vector<uint8_t> classical_sign(
    ClassicalAlgorithm algo,
    std::span<const uint8_t> sk,
    std::span<const uint8_t> pk,
    std::span<const uint8_t> message)
{
    EVP_PKEY_ptr pkey(nullptr);

    if (is_eddsa(algo)) {
        // Reconstruct EdDSA key from raw bytes
        pkey.reset(EVP_PKEY_new_raw_private_key(
            algo == ClassicalAlgorithm::Ed25519 ? EVP_PKEY_ED25519 : EVP_PKEY_ED448,
            nullptr, sk.data(), sk.size()));
        if (!pkey) throw std::runtime_error("Failed to load EdDSA private key");

        // Sign
        EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new());
        if (!ctx) throw std::runtime_error("Failed to create MD context");

        if (EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) <= 0)
            throw std::runtime_error("Failed to init EdDSA sign");

        size_t sig_len = 0;
        if (EVP_DigestSign(ctx.get(), nullptr, &sig_len, message.data(), message.size()) <= 0)
            throw std::runtime_error("Failed to get EdDSA signature size");

        std::vector<uint8_t> sig(sig_len);
        if (EVP_DigestSign(ctx.get(), sig.data(), &sig_len, message.data(), message.size()) <= 0)
            throw std::runtime_error("Failed to create EdDSA signature");
        sig.resize(sig_len);
        return sig;
    } else {
        // Reconstruct ECDSA key
        EVP_PKEY_CTX_ptr key_ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
        if (!key_ctx) throw std::runtime_error("Failed to create EC context");

        if (EVP_PKEY_fromdata_init(key_ctx.get()) <= 0)
            throw std::runtime_error("Failed to init fromdata");

        OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
        OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
            get_curve_name(algo), 0);
        OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
            pk.data(), pk.size());
        OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY,
            BN_bin2bn(sk.data(), sk.size(), nullptr));

        OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
        EVP_PKEY* raw_pkey = nullptr;
        if (EVP_PKEY_fromdata(key_ctx.get(), &raw_pkey, EVP_PKEY_KEYPAIR, params) <= 0) {
            OSSL_PARAM_free(params);
            OSSL_PARAM_BLD_free(bld);
            throw std::runtime_error("Failed to load ECDSA key");
        }
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(bld);
        pkey.reset(raw_pkey);

        // Sign with appropriate hash
        const EVP_MD* md = (algo == ClassicalAlgorithm::ECDSA_P256) ? EVP_sha256() : EVP_sha384();

        EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new());
        if (!ctx) throw std::runtime_error("Failed to create MD context");

        if (EVP_DigestSignInit(ctx.get(), nullptr, md, nullptr, pkey.get()) <= 0)
            throw std::runtime_error("Failed to init ECDSA sign");

        if (EVP_DigestSignUpdate(ctx.get(), message.data(), message.size()) <= 0)
            throw std::runtime_error("Failed to update ECDSA sign");

        size_t sig_len = 0;
        if (EVP_DigestSignFinal(ctx.get(), nullptr, &sig_len) <= 0)
            throw std::runtime_error("Failed to get ECDSA signature size");

        std::vector<uint8_t> sig(sig_len);
        if (EVP_DigestSignFinal(ctx.get(), sig.data(), &sig_len) <= 0)
            throw std::runtime_error("Failed to create ECDSA signature");
        sig.resize(sig_len);
        return sig;
    }
}

// ============================================================================
// Classical Verification
// ============================================================================

inline bool classical_verify(
    ClassicalAlgorithm algo,
    std::span<const uint8_t> pk,
    std::span<const uint8_t> message,
    std::span<const uint8_t> signature)
{
    EVP_PKEY_ptr pkey(nullptr);

    if (is_eddsa(algo)) {
        pkey.reset(EVP_PKEY_new_raw_public_key(
            algo == ClassicalAlgorithm::Ed25519 ? EVP_PKEY_ED25519 : EVP_PKEY_ED448,
            nullptr, pk.data(), pk.size()));
        if (!pkey) return false;

        EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new());
        if (!ctx) return false;

        if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pkey.get()) <= 0)
            return false;

        return EVP_DigestVerify(ctx.get(), signature.data(), signature.size(),
                                message.data(), message.size()) == 1;
    } else {
        // Reconstruct ECDSA public key
        EVP_PKEY_CTX_ptr key_ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
        if (!key_ctx) return false;

        if (EVP_PKEY_fromdata_init(key_ctx.get()) <= 0) return false;

        OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
        OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
            get_curve_name(algo), 0);
        OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
            pk.data(), pk.size());

        OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
        EVP_PKEY* raw_pkey = nullptr;
        if (EVP_PKEY_fromdata(key_ctx.get(), &raw_pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
            OSSL_PARAM_free(params);
            OSSL_PARAM_BLD_free(bld);
            return false;
        }
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(bld);
        pkey.reset(raw_pkey);

        // Verify with appropriate hash
        const EVP_MD* md = (algo == ClassicalAlgorithm::ECDSA_P256) ? EVP_sha256() : EVP_sha384();

        EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new());
        if (!ctx) return false;

        if (EVP_DigestVerifyInit(ctx.get(), nullptr, md, nullptr, pkey.get()) <= 0)
            return false;

        if (EVP_DigestVerifyUpdate(ctx.get(), message.data(), message.size()) <= 0)
            return false;

        return EVP_DigestVerifyFinal(ctx.get(), signature.data(), signature.size()) == 1;
    }
}

} // namespace detail

// ============================================================================
// Composite Signature Interface
// ============================================================================

/**
 * Abstract interface for composite signature algorithms
 */
class CompositeSignature : public DigitalSignature {
public:
    virtual ~CompositeSignature() = default;

    // Algorithm information
    virtual std::string pqc_algorithm() const = 0;
    virtual std::string classical_algorithm() const = 0;
    virtual std::string composite_oid() const = 0;

    // Component sizes
    virtual size_t pqc_public_key_size() const = 0;
    virtual size_t pqc_secret_key_size() const = 0;
    virtual size_t pqc_signature_size() const = 0;
    virtual size_t classical_public_key_size() const = 0;
    virtual size_t classical_secret_key_size() const = 0;
    virtual size_t classical_signature_max_size() const = 0;

    // Split composite key into components
    virtual std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
        split_public_key(std::span<const uint8_t> composite_pk) const = 0;

    virtual std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
        split_secret_key(std::span<const uint8_t> composite_sk) const = 0;

    // Split composite signature into components
    virtual std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
        split_signature(std::span<const uint8_t> composite_sig) const = 0;
};

// ============================================================================
// Composite Signature Implementation
// ============================================================================

template<typename MLDSAType, ClassicalAlgorithm ClassicalAlgo>
class CompositeSignatureImpl : public CompositeSignature {
public:
    CompositeSignatureImpl(const std::string& name, const std::string& oid_str)
        : name_(name), oid_(oid_str) {}

    std::string name() const override { return name_; }
    std::string standard() const override { return "draft-ietf-lamps-pq-composite-sigs"; }
    std::string pqc_algorithm() const override { return std::string(mldsa_.params().name); }

    std::string classical_algorithm() const override {
        switch (ClassicalAlgo) {
            case ClassicalAlgorithm::ECDSA_P256: return "ECDSA-P256";
            case ClassicalAlgorithm::ECDSA_P384: return "ECDSA-P384";
            case ClassicalAlgorithm::Ed25519:    return "Ed25519";
            case ClassicalAlgorithm::Ed448:      return "Ed448";
            default: return "Unknown";
        }
    }

    std::string composite_oid() const override { return oid_; }

    // Size accessors
    size_t public_key_size() const override {
        return pqc_public_key_size() + classical_public_key_size();
    }

    size_t secret_key_size() const override {
        // sk = pqc_sk || classical_sk || classical_pk
        return pqc_secret_key_size() + classical_secret_key_size() + classical_public_key_size();
    }

    size_t signature_size() const override {
        // Return maximum possible size (ECDSA signatures are variable)
        return pqc_signature_size() + classical_signature_max_size();
    }

    size_t pqc_public_key_size() const override { return mldsa_.params().pk_size(); }
    size_t pqc_secret_key_size() const override { return mldsa_.params().sk_size(); }
    size_t pqc_signature_size() const override { return mldsa_.params().sig_size(); }
    size_t classical_public_key_size() const override {
        return detail::get_classical_pk_size(ClassicalAlgo);
    }
    size_t classical_secret_key_size() const override {
        return detail::get_classical_sk_size(ClassicalAlgo);
    }
    size_t classical_signature_max_size() const override {
        return detail::get_classical_sig_size(ClassicalAlgo);
    }

    // Key generation
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> keygen() const override {
        // Generate ML-DSA keys
        auto [pqc_pk, pqc_sk] = mldsa_.keygen();

        // Generate classical keys
        auto [classical_pk, classical_sk] = detail::classical_keygen(ClassicalAlgo);

        // Concatenate: pk = pqc_pk || classical_pk
        std::vector<uint8_t> composite_pk;
        composite_pk.reserve(pqc_pk.size() + classical_pk.size());
        composite_pk.insert(composite_pk.end(), pqc_pk.begin(), pqc_pk.end());
        composite_pk.insert(composite_pk.end(), classical_pk.begin(), classical_pk.end());

        // Concatenate: sk = pqc_sk || classical_sk || classical_pk
        // We include classical_pk in sk for signing (needed by ECDSA)
        std::vector<uint8_t> composite_sk;
        composite_sk.reserve(pqc_sk.size() + classical_sk.size() + classical_pk.size());
        composite_sk.insert(composite_sk.end(), pqc_sk.begin(), pqc_sk.end());
        composite_sk.insert(composite_sk.end(), classical_sk.begin(), classical_sk.end());
        composite_sk.insert(composite_sk.end(), classical_pk.begin(), classical_pk.end());

        return {composite_pk, composite_sk};
    }

    // Signing
    std::vector<uint8_t> sign(
        std::span<const uint8_t> sk,
        std::span<const uint8_t> message,
        std::span<const uint8_t> ctx = {}) const override
    {
        // Split composite secret key: sk = pqc_sk || classical_sk || classical_pk
        size_t pqc_sk_size = pqc_secret_key_size();
        size_t classical_sk_size = classical_secret_key_size();
        size_t classical_pk_size = classical_public_key_size();

        if (sk.size() < pqc_sk_size + classical_sk_size + classical_pk_size) {
            throw std::runtime_error("Composite secret key too short");
        }

        std::vector<uint8_t> pqc_sk(sk.begin(), sk.begin() + pqc_sk_size);
        std::vector<uint8_t> classical_sk(sk.begin() + pqc_sk_size,
                                          sk.begin() + pqc_sk_size + classical_sk_size);
        std::vector<uint8_t> classical_pk(sk.begin() + pqc_sk_size + classical_sk_size,
                                          sk.begin() + pqc_sk_size + classical_sk_size + classical_pk_size);

        // Generate ML-DSA signature
        auto pqc_sig = mldsa_.sign(pqc_sk, message, ctx);

        // Generate classical signature over the same message
        auto classical_sig = detail::classical_sign(ClassicalAlgo, classical_sk, classical_pk, message);

        // Concatenate: sig = pqc_sig || classical_sig
        std::vector<uint8_t> composite_sig;
        composite_sig.reserve(pqc_sig.size() + classical_sig.size());
        composite_sig.insert(composite_sig.end(), pqc_sig.begin(), pqc_sig.end());
        composite_sig.insert(composite_sig.end(), classical_sig.begin(), classical_sig.end());

        return composite_sig;
    }

    // Verification
    bool verify(
        std::span<const uint8_t> pk,
        std::span<const uint8_t> message,
        std::span<const uint8_t> signature,
        std::span<const uint8_t> ctx = {}) const override
    {
        // Split composite public key
        auto [pqc_pk, classical_pk] = split_public_key(pk);

        // Split composite signature
        auto [pqc_sig, classical_sig] = split_signature(signature);

        // Verify ML-DSA signature
        bool pqc_valid = mldsa_.verify(pqc_pk, message, pqc_sig, ctx);
        if (!pqc_valid) return false;

        // Verify classical signature
        bool classical_valid = detail::classical_verify(ClassicalAlgo, classical_pk, message, classical_sig);

        // Both must verify
        return classical_valid;
    }

    // Split functions
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    split_public_key(std::span<const uint8_t> composite_pk) const override {
        size_t pqc_size = pqc_public_key_size();
        size_t classical_size = classical_public_key_size();

        if (composite_pk.size() < pqc_size + classical_size) {
            throw std::runtime_error("Composite public key too short");
        }

        std::vector<uint8_t> pqc_pk(composite_pk.begin(), composite_pk.begin() + pqc_size);
        std::vector<uint8_t> classical_pk(composite_pk.begin() + pqc_size,
                                          composite_pk.begin() + pqc_size + classical_size);
        return {pqc_pk, classical_pk};
    }

    std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    split_secret_key(std::span<const uint8_t> composite_sk) const override {
        // sk format: pqc_sk || classical_sk || classical_pk
        size_t pqc_size = pqc_secret_key_size();
        size_t classical_size = classical_secret_key_size();

        if (composite_sk.size() < pqc_size + classical_size) {
            throw std::runtime_error("Composite secret key too short");
        }

        // Return just the secret key parts, not the embedded public key
        std::vector<uint8_t> pqc_sk(composite_sk.begin(), composite_sk.begin() + pqc_size);
        std::vector<uint8_t> classical_sk(composite_sk.begin() + pqc_size,
                                          composite_sk.begin() + pqc_size + classical_size);
        return {pqc_sk, classical_sk};
    }

    std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    split_signature(std::span<const uint8_t> composite_sig) const override {
        size_t pqc_size = pqc_signature_size();

        if (composite_sig.size() <= pqc_size) {
            throw std::runtime_error("Composite signature too short");
        }

        std::vector<uint8_t> pqc_sig(composite_sig.begin(), composite_sig.begin() + pqc_size);
        std::vector<uint8_t> classical_sig(composite_sig.begin() + pqc_size, composite_sig.end());
        return {pqc_sig, classical_sig};
    }

private:
    std::string name_;
    std::string oid_;
    MLDSAType mldsa_;

    // Regenerate classical public key from secret key
    std::vector<uint8_t> regenerate_classical_pk(std::span<const uint8_t> sk) const {
        detail::EVP_PKEY_ptr pkey(nullptr);

        if (detail::is_eddsa(ClassicalAlgo)) {
            pkey.reset(EVP_PKEY_new_raw_private_key(
                ClassicalAlgo == ClassicalAlgorithm::Ed25519 ? EVP_PKEY_ED25519 : EVP_PKEY_ED448,
                nullptr, sk.data(), sk.size()));
            if (!pkey) throw std::runtime_error("Failed to load EdDSA key");

            size_t pk_len = detail::get_classical_pk_size(ClassicalAlgo);
            std::vector<uint8_t> pk(pk_len);
            if (EVP_PKEY_get_raw_public_key(pkey.get(), pk.data(), &pk_len) <= 0)
                throw std::runtime_error("Failed to get EdDSA public key");
            pk.resize(pk_len);
            return pk;
        } else {
            // ECDSA - need to compute public key from private
            detail::EVP_PKEY_CTX_ptr key_ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
            if (!key_ctx) throw std::runtime_error("Failed to create EC context");

            if (EVP_PKEY_fromdata_init(key_ctx.get()) <= 0)
                throw std::runtime_error("Failed to init fromdata");

            BIGNUM* priv_bn = BN_bin2bn(sk.data(), sk.size(), nullptr);
            if (!priv_bn) throw std::runtime_error("Failed to create BIGNUM");

            OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
            OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                detail::get_curve_name(ClassicalAlgo), 0);
            OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv_bn);

            OSSL_PARAM* params = OSSL_PARAM_BLD_to_param(bld);
            EVP_PKEY* raw_pkey = nullptr;
            int rc = EVP_PKEY_fromdata(key_ctx.get(), &raw_pkey, EVP_PKEY_KEYPAIR, params);
            OSSL_PARAM_free(params);
            OSSL_PARAM_BLD_free(bld);
            BN_free(priv_bn);

            if (rc <= 0) throw std::runtime_error("Failed to load ECDSA key");
            pkey.reset(raw_pkey);

            // Extract public key
            size_t pk_len = 0;
            if (EVP_PKEY_get_octet_string_param(pkey.get(),
                OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &pk_len) <= 0)
                throw std::runtime_error("Failed to get ECDSA public key size");

            std::vector<uint8_t> pk(pk_len);
            if (EVP_PKEY_get_octet_string_param(pkey.get(),
                OSSL_PKEY_PARAM_PUB_KEY, pk.data(), pk_len, &pk_len) <= 0)
                throw std::runtime_error("Failed to get ECDSA public key");

            return pk;
        }
    }
};

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Create a composite signature algorithm by name
 *
 * Supported names:
 *   - MLDSA44-ECDSA-P256
 *   - MLDSA44-Ed25519
 *   - MLDSA65-ECDSA-P256
 *   - MLDSA65-ECDSA-P384
 *   - MLDSA65-Ed25519
 *   - MLDSA87-ECDSA-P384
 *   - MLDSA87-Ed448
 */
inline std::unique_ptr<CompositeSignature> create_composite_dsa(const std::string& name) {
    // Normalize name
    std::string normalized = name;

    // Find OID
    auto it = oid::NAME_TO_OID.find(normalized);
    if (it == oid::NAME_TO_OID.end()) {
        // Try with SHA suffix removed
        for (const auto& [key, val] : oid::NAME_TO_OID) {
            if (key.find(normalized) == 0 || normalized.find(key) == 0) {
                normalized = key;
                it = oid::NAME_TO_OID.find(normalized);
                break;
            }
        }
    }

    if (it == oid::NAME_TO_OID.end()) {
        throw std::runtime_error("Unknown composite algorithm: " + name);
    }

    const std::string& oid_str = it->second;

    // Create implementation based on algorithm
    if (normalized.find("MLDSA44") == 0) {
        if (normalized.find("ECDSA-P256") != std::string::npos) {
            return std::make_unique<CompositeSignatureImpl<
                mldsa::MLDSA44, ClassicalAlgorithm::ECDSA_P256>>(normalized, oid_str);
        } else if (normalized.find("Ed25519") != std::string::npos) {
            return std::make_unique<CompositeSignatureImpl<
                mldsa::MLDSA44, ClassicalAlgorithm::Ed25519>>(normalized, oid_str);
        }
    } else if (normalized.find("MLDSA65") == 0) {
        if (normalized.find("ECDSA-P384") != std::string::npos) {
            return std::make_unique<CompositeSignatureImpl<
                mldsa::MLDSA65, ClassicalAlgorithm::ECDSA_P384>>(normalized, oid_str);
        } else if (normalized.find("ECDSA-P256") != std::string::npos) {
            return std::make_unique<CompositeSignatureImpl<
                mldsa::MLDSA65, ClassicalAlgorithm::ECDSA_P256>>(normalized, oid_str);
        } else if (normalized.find("Ed25519") != std::string::npos) {
            return std::make_unique<CompositeSignatureImpl<
                mldsa::MLDSA65, ClassicalAlgorithm::Ed25519>>(normalized, oid_str);
        }
    } else if (normalized.find("MLDSA87") == 0) {
        if (normalized.find("ECDSA-P384") != std::string::npos) {
            return std::make_unique<CompositeSignatureImpl<
                mldsa::MLDSA87, ClassicalAlgorithm::ECDSA_P384>>(normalized, oid_str);
        } else if (normalized.find("Ed448") != std::string::npos) {
            return std::make_unique<CompositeSignatureImpl<
                mldsa::MLDSA87, ClassicalAlgorithm::Ed448>>(normalized, oid_str);
        }
    }

    throw std::runtime_error("Unknown composite algorithm: " + name);
}

/**
 * Get list of available composite algorithms
 */
inline std::vector<std::string> available_composite_algorithms() {
    return {
        "MLDSA44-ECDSA-P256",
        "MLDSA44-Ed25519",
        "MLDSA65-ECDSA-P256",
        "MLDSA65-ECDSA-P384",
        "MLDSA65-Ed25519",
        "MLDSA87-ECDSA-P384",
        "MLDSA87-Ed448"
    };
}

/**
 * Check if an algorithm name is a composite algorithm
 */
inline bool is_composite_algorithm(const std::string& name) {
    for (const auto& algo : available_composite_algorithms()) {
        if (name == algo || name.find(algo) == 0) {
            return true;
        }
    }
    return false;
}

/**
 * Get the OID for a composite algorithm
 */
inline std::string get_composite_oid(const std::string& name) {
    auto it = oid::NAME_TO_OID.find(name);
    if (it != oid::NAME_TO_OID.end()) {
        return it->second;
    }
    // Try partial match
    for (const auto& [key, val] : oid::NAME_TO_OID) {
        if (key.find(name) == 0 || name.find(key) == 0) {
            return val;
        }
    }
    throw std::runtime_error("Unknown composite algorithm: " + name);
}

} // namespace composite

// Bring factory function to pqc namespace
using composite::create_composite_dsa;
using composite::available_composite_algorithms;
using composite::is_composite_algorithm;
using composite::get_composite_oid;

} // namespace pqc

#endif // COMMON_COMPOSITE_HPP
