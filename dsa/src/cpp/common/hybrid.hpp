/**
 * Hybrid Cryptography
 *
 * Combines post-quantum algorithms with classical algorithms for
 * defense-in-depth during the PQC transition period.
 *
 * Hybrid Signatures: ML-DSA + ECDSA/Ed25519
 *   - Both signatures must verify for the combined signature to be valid
 *   - Provides security even if one algorithm is compromised
 *
 * Hybrid KEM: ML-KEM + X25519
 *   - Shared secrets are combined using HKDF
 *   - Provides security even if one KEM is compromised
 *
 * Usage:
 *   // Hybrid signature
 *   auto hybrid = pqc::create_hybrid_dsa("ML-DSA-65", "Ed25519");
 *   auto [pk, sk] = hybrid->keygen();
 *   auto sig = hybrid->sign(sk, message);
 *   bool valid = hybrid->verify(pk, message, sig);
 *
 *   // Hybrid KEM
 *   auto hybrid_kem = pqc::create_hybrid_kem("ML-KEM-768", "X25519");
 *   auto [ek, dk] = hybrid_kem->keygen();
 *   auto [K, ct] = hybrid_kem->encaps(ek);
 *   auto K2 = hybrid_kem->decaps(dk, ct);
 */

#ifndef COMMON_HYBRID_HPP
#define COMMON_HYBRID_HPP

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>
#include <stdexcept>
#include <cstring>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#include "algorithm_factory.hpp"

namespace pqc {

// ============================================================================
// Classical Algorithm Enums
// ============================================================================

enum class ClassicalDSA {
    ECDSA_P256,     // NIST P-256 curve
    ECDSA_P384,     // NIST P-384 curve
    Ed25519         // Edwards curve 25519
};

enum class ClassicalKEM {
    X25519,         // Curve25519 ECDH
    ECDH_P256       // NIST P-256 ECDH
};

// ============================================================================
// OpenSSL RAII Wrappers
// ============================================================================

namespace detail {

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

// ============================================================================
// Classical Signature Operations
// ============================================================================

/**
 * Get the OpenSSL curve name for ECDSA
 */
inline const char* get_curve_name(ClassicalDSA algo) {
    switch (algo) {
        case ClassicalDSA::ECDSA_P256: return "prime256v1";
        case ClassicalDSA::ECDSA_P384: return "secp384r1";
        case ClassicalDSA::Ed25519:    return "ED25519";
    }
    throw std::invalid_argument("Unknown classical DSA algorithm");
}

/**
 * Get key sizes for classical DSA
 */
inline std::pair<size_t, size_t> get_classical_dsa_sizes(ClassicalDSA algo) {
    switch (algo) {
        case ClassicalDSA::ECDSA_P256: return {65, 32};   // Uncompressed point, private scalar
        case ClassicalDSA::ECDSA_P384: return {97, 48};
        case ClassicalDSA::Ed25519:    return {32, 32};
    }
    throw std::invalid_argument("Unknown classical DSA algorithm");
}

/**
 * Get max signature size for classical DSA
 */
inline size_t get_classical_sig_size(ClassicalDSA algo) {
    switch (algo) {
        case ClassicalDSA::ECDSA_P256: return 72;   // DER encoded, variable
        case ClassicalDSA::ECDSA_P384: return 104;
        case ClassicalDSA::Ed25519:    return 64;   // Fixed size
    }
    throw std::invalid_argument("Unknown classical DSA algorithm");
}

/**
 * Generate a classical DSA key pair
 */
inline std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
classical_dsa_keygen(ClassicalDSA algo) {
    EVP_PKEY_ptr pkey(nullptr);

    if (algo == ClassicalDSA::Ed25519) {
        EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr));
        if (!ctx) throw std::runtime_error("Failed to create Ed25519 context");
        if (EVP_PKEY_keygen_init(ctx.get()) <= 0)
            throw std::runtime_error("Failed to init Ed25519 keygen");
        EVP_PKEY* tmp = nullptr;
        if (EVP_PKEY_keygen(ctx.get(), &tmp) <= 0)
            throw std::runtime_error("Failed to generate Ed25519 key");
        pkey.reset(tmp);
    } else {
        // ECDSA
        EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
        if (!ctx) throw std::runtime_error("Failed to create EC context");
        if (EVP_PKEY_keygen_init(ctx.get()) <= 0)
            throw std::runtime_error("Failed to init EC keygen");

        const char* curve = get_curve_name(algo);
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(),
                OBJ_txt2nid(curve)) <= 0)
            throw std::runtime_error("Failed to set EC curve");

        EVP_PKEY* tmp = nullptr;
        if (EVP_PKEY_keygen(ctx.get(), &tmp) <= 0)
            throw std::runtime_error("Failed to generate EC key");
        pkey.reset(tmp);
    }

    // Extract public key
    size_t pk_len = 0;
    if (EVP_PKEY_get_raw_public_key(pkey.get(), nullptr, &pk_len) <= 0) {
        // For ECDSA, use different method
        if (algo != ClassicalDSA::Ed25519) {
            // Get EC public key as uncompressed point
            unsigned char* pk_buf = nullptr;
            pk_len = i2o_ECPublicKey(EVP_PKEY_get0_EC_KEY(pkey.get()), &pk_buf);
            if (pk_len == 0) throw std::runtime_error("Failed to export EC public key");
            std::vector<uint8_t> pk(pk_buf, pk_buf + pk_len);
            OPENSSL_free(pk_buf);

            // Get private key
            const BIGNUM* priv_bn = EC_KEY_get0_private_key(
                EVP_PKEY_get0_EC_KEY(pkey.get()));
            size_t sk_len = BN_num_bytes(priv_bn);
            std::vector<uint8_t> sk(sk_len);
            BN_bn2bin(priv_bn, sk.data());

            return {std::move(pk), std::move(sk)};
        }
        throw std::runtime_error("Failed to get public key length");
    }

    std::vector<uint8_t> pk(pk_len);
    if (EVP_PKEY_get_raw_public_key(pkey.get(), pk.data(), &pk_len) <= 0)
        throw std::runtime_error("Failed to export public key");
    pk.resize(pk_len);

    // Extract private key
    size_t sk_len = 0;
    if (EVP_PKEY_get_raw_private_key(pkey.get(), nullptr, &sk_len) <= 0)
        throw std::runtime_error("Failed to get private key length");
    std::vector<uint8_t> sk(sk_len);
    if (EVP_PKEY_get_raw_private_key(pkey.get(), sk.data(), &sk_len) <= 0)
        throw std::runtime_error("Failed to export private key");
    sk.resize(sk_len);

    return {std::move(pk), std::move(sk)};
}

/**
 * Sign with classical DSA
 */
inline std::vector<uint8_t> classical_dsa_sign(
    ClassicalDSA algo,
    std::span<const uint8_t> sk,
    std::span<const uint8_t> message) {

    EVP_PKEY_ptr pkey(nullptr);

    if (algo == ClassicalDSA::Ed25519) {
        pkey.reset(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr,
            sk.data(), sk.size()));
        if (!pkey) throw std::runtime_error("Failed to load Ed25519 private key");
    } else {
        // ECDSA - reconstruct key from private scalar
        const char* curve = get_curve_name(algo);
        int nid = OBJ_txt2nid(curve);

        EC_KEY* ec_key = EC_KEY_new_by_curve_name(nid);
        if (!ec_key) throw std::runtime_error("Failed to create EC key");

        BIGNUM* priv_bn = BN_bin2bn(sk.data(), static_cast<int>(sk.size()), nullptr);
        if (!priv_bn) {
            EC_KEY_free(ec_key);
            throw std::runtime_error("Failed to create private key BIGNUM");
        }

        if (EC_KEY_set_private_key(ec_key, priv_bn) != 1) {
            BN_free(priv_bn);
            EC_KEY_free(ec_key);
            throw std::runtime_error("Failed to set private key");
        }

        // Compute public key from private key
        const EC_GROUP* group = EC_KEY_get0_group(ec_key);
        EC_POINT* pub_point = EC_POINT_new(group);
        EC_POINT_mul(group, pub_point, priv_bn, nullptr, nullptr, nullptr);
        EC_KEY_set_public_key(ec_key, pub_point);
        EC_POINT_free(pub_point);
        BN_free(priv_bn);

        pkey.reset(EVP_PKEY_new());
        EVP_PKEY_assign_EC_KEY(pkey.get(), ec_key);
    }

    EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new());
    if (!ctx) throw std::runtime_error("Failed to create MD context");

    const EVP_MD* md = (algo == ClassicalDSA::Ed25519) ? nullptr :
                       (algo == ClassicalDSA::ECDSA_P256) ? EVP_sha256() : EVP_sha384();

    if (EVP_DigestSignInit(ctx.get(), nullptr, md, nullptr, pkey.get()) <= 0)
        throw std::runtime_error("Failed to init signing");

    size_t sig_len = 0;
    if (algo == ClassicalDSA::Ed25519) {
        if (EVP_DigestSign(ctx.get(), nullptr, &sig_len,
                message.data(), message.size()) <= 0)
            throw std::runtime_error("Failed to get signature length");
    } else {
        if (EVP_DigestSignUpdate(ctx.get(), message.data(), message.size()) <= 0)
            throw std::runtime_error("Failed to update signing");
        if (EVP_DigestSignFinal(ctx.get(), nullptr, &sig_len) <= 0)
            throw std::runtime_error("Failed to get signature length");
    }

    std::vector<uint8_t> sig(sig_len);
    if (algo == ClassicalDSA::Ed25519) {
        if (EVP_DigestSign(ctx.get(), sig.data(), &sig_len,
                message.data(), message.size()) <= 0)
            throw std::runtime_error("Failed to sign");
    } else {
        if (EVP_DigestSignFinal(ctx.get(), sig.data(), &sig_len) <= 0)
            throw std::runtime_error("Failed to sign");
    }
    sig.resize(sig_len);

    return sig;
}

/**
 * Verify with classical DSA
 */
inline bool classical_dsa_verify(
    ClassicalDSA algo,
    std::span<const uint8_t> pk,
    std::span<const uint8_t> message,
    std::span<const uint8_t> signature) {

    EVP_PKEY_ptr pkey(nullptr);

    if (algo == ClassicalDSA::Ed25519) {
        pkey.reset(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
            pk.data(), pk.size()));
        if (!pkey) return false;
    } else {
        // ECDSA - reconstruct key from public point
        const char* curve = get_curve_name(algo);
        int nid = OBJ_txt2nid(curve);

        EC_KEY* ec_key = EC_KEY_new_by_curve_name(nid);
        if (!ec_key) return false;

        const unsigned char* pk_ptr = pk.data();
        if (!o2i_ECPublicKey(&ec_key, &pk_ptr, static_cast<long>(pk.size()))) {
            EC_KEY_free(ec_key);
            return false;
        }

        pkey.reset(EVP_PKEY_new());
        EVP_PKEY_assign_EC_KEY(pkey.get(), ec_key);
    }

    EVP_MD_CTX_ptr ctx(EVP_MD_CTX_new());
    if (!ctx) return false;

    const EVP_MD* md = (algo == ClassicalDSA::Ed25519) ? nullptr :
                       (algo == ClassicalDSA::ECDSA_P256) ? EVP_sha256() : EVP_sha384();

    if (EVP_DigestVerifyInit(ctx.get(), nullptr, md, nullptr, pkey.get()) <= 0)
        return false;

    if (algo == ClassicalDSA::Ed25519) {
        return EVP_DigestVerify(ctx.get(), signature.data(), signature.size(),
                                message.data(), message.size()) == 1;
    } else {
        if (EVP_DigestVerifyUpdate(ctx.get(), message.data(), message.size()) <= 0)
            return false;
        return EVP_DigestVerifyFinal(ctx.get(), signature.data(), signature.size()) == 1;
    }
}

// ============================================================================
// Classical KEM Operations
// ============================================================================

/**
 * Get key sizes for classical KEM
 */
inline std::tuple<size_t, size_t, size_t> get_classical_kem_sizes(ClassicalKEM algo) {
    switch (algo) {
        case ClassicalKEM::X25519:    return {32, 32, 32};  // pk, sk, ct (same as pk for ECDH)
        case ClassicalKEM::ECDH_P256: return {65, 32, 65};  // Uncompressed point
    }
    throw std::invalid_argument("Unknown classical KEM algorithm");
}

/**
 * Generate a classical KEM key pair
 */
inline std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
classical_kem_keygen(ClassicalKEM algo) {
    EVP_PKEY_ptr pkey(nullptr);

    if (algo == ClassicalKEM::X25519) {
        EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr));
        if (!ctx) throw std::runtime_error("Failed to create X25519 context");
        if (EVP_PKEY_keygen_init(ctx.get()) <= 0)
            throw std::runtime_error("Failed to init X25519 keygen");
        EVP_PKEY* tmp = nullptr;
        if (EVP_PKEY_keygen(ctx.get(), &tmp) <= 0)
            throw std::runtime_error("Failed to generate X25519 key");
        pkey.reset(tmp);

        // Extract keys
        size_t pk_len = 32, sk_len = 32;
        std::vector<uint8_t> pk(pk_len), sk(sk_len);
        if (EVP_PKEY_get_raw_public_key(pkey.get(), pk.data(), &pk_len) <= 0)
            throw std::runtime_error("Failed to export X25519 public key");
        if (EVP_PKEY_get_raw_private_key(pkey.get(), sk.data(), &sk_len) <= 0)
            throw std::runtime_error("Failed to export X25519 private key");
        return {std::move(pk), std::move(sk)};
    } else {
        // ECDH with P-256
        EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr));
        if (!ctx) throw std::runtime_error("Failed to create EC context");
        if (EVP_PKEY_keygen_init(ctx.get()) <= 0)
            throw std::runtime_error("Failed to init EC keygen");
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1) <= 0)
            throw std::runtime_error("Failed to set P-256 curve");

        EVP_PKEY* tmp = nullptr;
        if (EVP_PKEY_keygen(ctx.get(), &tmp) <= 0)
            throw std::runtime_error("Failed to generate EC key");
        pkey.reset(tmp);

        // Get public key as uncompressed point
        unsigned char* pk_buf = nullptr;
        size_t pk_len = i2o_ECPublicKey(EVP_PKEY_get0_EC_KEY(pkey.get()), &pk_buf);
        if (pk_len == 0) throw std::runtime_error("Failed to export EC public key");
        std::vector<uint8_t> pk(pk_buf, pk_buf + pk_len);
        OPENSSL_free(pk_buf);

        // Get private key
        const BIGNUM* priv_bn = EC_KEY_get0_private_key(EVP_PKEY_get0_EC_KEY(pkey.get()));
        size_t sk_len = BN_num_bytes(priv_bn);
        std::vector<uint8_t> sk(sk_len);
        BN_bn2bin(priv_bn, sk.data());

        return {std::move(pk), std::move(sk)};
    }
}

/**
 * Perform ECDH and return shared secret
 */
inline std::vector<uint8_t> ecdh_derive(
    ClassicalKEM algo,
    std::span<const uint8_t> sk,
    std::span<const uint8_t> peer_pk) {

    EVP_PKEY_ptr our_key(nullptr);
    EVP_PKEY_ptr peer_key(nullptr);

    if (algo == ClassicalKEM::X25519) {
        our_key.reset(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr,
            sk.data(), sk.size()));
        peer_key.reset(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
            peer_pk.data(), peer_pk.size()));
    } else {
        // ECDH P-256
        EC_KEY* ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        BIGNUM* priv_bn = BN_bin2bn(sk.data(), static_cast<int>(sk.size()), nullptr);
        EC_KEY_set_private_key(ec_key, priv_bn);
        const EC_GROUP* group = EC_KEY_get0_group(ec_key);
        EC_POINT* pub_point = EC_POINT_new(group);
        EC_POINT_mul(group, pub_point, priv_bn, nullptr, nullptr, nullptr);
        EC_KEY_set_public_key(ec_key, pub_point);
        EC_POINT_free(pub_point);
        BN_free(priv_bn);
        our_key.reset(EVP_PKEY_new());
        EVP_PKEY_assign_EC_KEY(our_key.get(), ec_key);

        // Load peer public key
        EC_KEY* peer_ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        const unsigned char* pk_ptr = peer_pk.data();
        o2i_ECPublicKey(&peer_ec, &pk_ptr, static_cast<long>(peer_pk.size()));
        peer_key.reset(EVP_PKEY_new());
        EVP_PKEY_assign_EC_KEY(peer_key.get(), peer_ec);
    }

    if (!our_key || !peer_key)
        throw std::runtime_error("Failed to load keys for ECDH");

    EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new(our_key.get(), nullptr));
    if (!ctx) throw std::runtime_error("Failed to create ECDH context");

    if (EVP_PKEY_derive_init(ctx.get()) <= 0)
        throw std::runtime_error("Failed to init ECDH");
    if (EVP_PKEY_derive_set_peer(ctx.get(), peer_key.get()) <= 0)
        throw std::runtime_error("Failed to set ECDH peer");

    size_t secret_len = 0;
    if (EVP_PKEY_derive(ctx.get(), nullptr, &secret_len) <= 0)
        throw std::runtime_error("Failed to get ECDH secret length");

    std::vector<uint8_t> secret(secret_len);
    if (EVP_PKEY_derive(ctx.get(), secret.data(), &secret_len) <= 0)
        throw std::runtime_error("Failed to derive ECDH secret");
    secret.resize(secret_len);

    return secret;
}

/**
 * HKDF to combine shared secrets
 */
inline std::vector<uint8_t> hkdf_sha256(
    std::span<const uint8_t> ikm,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> info,
    size_t output_len) {

    std::vector<uint8_t> output(output_len);

    EVP_PKEY_CTX_ptr ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    if (!ctx) throw std::runtime_error("Failed to create HKDF context");

    if (EVP_PKEY_derive_init(ctx.get()) <= 0)
        throw std::runtime_error("Failed to init HKDF");
    if (EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) <= 0)
        throw std::runtime_error("Failed to set HKDF hash");

    // Only set salt if non-empty (HKDF uses default salt otherwise)
    if (!salt.empty()) {
        if (EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), salt.data(), static_cast<int>(salt.size())) <= 0)
            throw std::runtime_error("Failed to set HKDF salt");
    }

    if (EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), ikm.data(), static_cast<int>(ikm.size())) <= 0)
        throw std::runtime_error("Failed to set HKDF key");

    // Only set info if non-empty
    if (!info.empty()) {
        if (EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), info.data(), static_cast<int>(info.size())) <= 0)
            throw std::runtime_error("Failed to set HKDF info");
    }

    size_t len = output_len;
    if (EVP_PKEY_derive(ctx.get(), output.data(), &len) <= 0)
        throw std::runtime_error("Failed to derive HKDF output");

    return output;
}

} // namespace detail

// ============================================================================
// Hybrid DSA Interface
// ============================================================================

/**
 * Abstract interface for hybrid digital signature schemes
 */
class HybridDigitalSignature {
public:
    virtual ~HybridDigitalSignature() = default;

    /** Algorithm name (e.g., "ML-DSA-65+Ed25519") */
    [[nodiscard]] virtual std::string name() const = 0;

    /** PQC algorithm component */
    [[nodiscard]] virtual std::string pqc_algorithm() const = 0;

    /** Classical algorithm component */
    [[nodiscard]] virtual std::string classical_algorithm() const = 0;

    /** Generate a key pair. Returns (public_key, secret_key). */
    [[nodiscard]] virtual std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    keygen() const = 0;

    /** Sign a message with the secret key */
    [[nodiscard]] virtual std::vector<uint8_t> sign(
        std::span<const uint8_t> sk,
        std::span<const uint8_t> message,
        std::span<const uint8_t> ctx = {}) const = 0;

    /** Verify a signature */
    [[nodiscard]] virtual bool verify(
        std::span<const uint8_t> pk,
        std::span<const uint8_t> message,
        std::span<const uint8_t> signature,
        std::span<const uint8_t> ctx = {}) const = 0;

    /** Combined public key size */
    [[nodiscard]] virtual size_t public_key_size() const = 0;

    /** Combined secret key size */
    [[nodiscard]] virtual size_t secret_key_size() const = 0;

    /** Combined signature size (max) */
    [[nodiscard]] virtual size_t signature_size() const = 0;
};

/**
 * Abstract interface for hybrid KEM schemes
 */
class HybridKeyEncapsulation {
public:
    virtual ~HybridKeyEncapsulation() = default;

    /** Algorithm name (e.g., "ML-KEM-768+X25519") */
    [[nodiscard]] virtual std::string name() const = 0;

    /** PQC algorithm component */
    [[nodiscard]] virtual std::string pqc_algorithm() const = 0;

    /** Classical algorithm component */
    [[nodiscard]] virtual std::string classical_algorithm() const = 0;

    /** Generate key pair. Returns (encapsulation_key, decapsulation_key). */
    [[nodiscard]] virtual std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    keygen() const = 0;

    /** Encapsulate: Returns (shared_secret, ciphertext). */
    [[nodiscard]] virtual std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    encaps(std::span<const uint8_t> ek) const = 0;

    /** Decapsulate: recover shared secret from ciphertext */
    [[nodiscard]] virtual std::vector<uint8_t> decaps(
        std::span<const uint8_t> dk,
        std::span<const uint8_t> ciphertext) const = 0;

    /** Combined encapsulation key size */
    [[nodiscard]] virtual size_t encapsulation_key_size() const = 0;

    /** Combined decapsulation key size */
    [[nodiscard]] virtual size_t decapsulation_key_size() const = 0;

    /** Combined ciphertext size */
    [[nodiscard]] virtual size_t ciphertext_size() const = 0;

    /** Shared secret size (32 bytes) */
    [[nodiscard]] virtual size_t shared_secret_size() const = 0;
};

// ============================================================================
// Hybrid DSA Implementation
// ============================================================================

namespace detail {

class HybridDSAImpl final : public HybridDigitalSignature {
public:
    HybridDSAImpl(std::unique_ptr<DigitalSignature> pqc, ClassicalDSA classical)
        : pqc_(std::move(pqc)), classical_(classical) {

        auto [cpk, csk] = get_classical_dsa_sizes(classical_);
        classical_pk_size_ = cpk;
        classical_sk_size_ = csk;
        classical_sig_size_ = get_classical_sig_size(classical_);
    }

    [[nodiscard]] std::string name() const override {
        return pqc_->name() + "+" + classical_name();
    }

    [[nodiscard]] std::string pqc_algorithm() const override {
        return pqc_->name();
    }

    [[nodiscard]] std::string classical_algorithm() const override {
        return classical_name();
    }

    [[nodiscard]] std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    keygen() const override {
        // Generate PQC key pair
        auto [pqc_pk, pqc_sk] = pqc_->keygen();

        // Generate classical key pair
        auto [classical_pk, classical_sk] = classical_dsa_keygen(classical_);

        // Concatenate: pk = pqc_pk || classical_pk, sk = pqc_sk || classical_sk
        std::vector<uint8_t> pk;
        pk.reserve(pqc_pk.size() + classical_pk.size());
        pk.insert(pk.end(), pqc_pk.begin(), pqc_pk.end());
        pk.insert(pk.end(), classical_pk.begin(), classical_pk.end());

        std::vector<uint8_t> sk;
        sk.reserve(pqc_sk.size() + classical_sk.size());
        sk.insert(sk.end(), pqc_sk.begin(), pqc_sk.end());
        sk.insert(sk.end(), classical_sk.begin(), classical_sk.end());

        return {std::move(pk), std::move(sk)};
    }

    [[nodiscard]] std::vector<uint8_t> sign(
        std::span<const uint8_t> sk,
        std::span<const uint8_t> message,
        std::span<const uint8_t> ctx = {}) const override {

        size_t pqc_sk_size = pqc_->secret_key_size();
        if (sk.size() < pqc_sk_size + classical_sk_size_) {
            throw std::invalid_argument("Secret key too short");
        }

        auto pqc_sk = sk.subspan(0, pqc_sk_size);
        auto classical_sk = sk.subspan(pqc_sk_size, classical_sk_size_);

        // Sign with both algorithms
        auto pqc_sig = pqc_->sign(pqc_sk, message, ctx);
        auto classical_sig = classical_dsa_sign(classical_, classical_sk, message);

        // Concatenate signatures with length prefix for classical (variable size ECDSA)
        std::vector<uint8_t> combined;
        combined.reserve(pqc_sig.size() + 2 + classical_sig.size());
        combined.insert(combined.end(), pqc_sig.begin(), pqc_sig.end());

        // Store classical sig length as 2-byte big-endian
        combined.push_back(static_cast<uint8_t>(classical_sig.size() >> 8));
        combined.push_back(static_cast<uint8_t>(classical_sig.size() & 0xFF));
        combined.insert(combined.end(), classical_sig.begin(), classical_sig.end());

        return combined;
    }

    [[nodiscard]] bool verify(
        std::span<const uint8_t> pk,
        std::span<const uint8_t> message,
        std::span<const uint8_t> signature,
        std::span<const uint8_t> ctx = {}) const override {

        size_t pqc_pk_size = pqc_->public_key_size();
        size_t pqc_sig_size = pqc_->signature_size();

        if (pk.size() < pqc_pk_size + classical_pk_size_) {
            return false;
        }
        if (signature.size() < pqc_sig_size + 2) {
            return false;
        }

        auto pqc_pk = pk.subspan(0, pqc_pk_size);
        auto classical_pk = pk.subspan(pqc_pk_size, classical_pk_size_);

        auto pqc_sig = signature.subspan(0, pqc_sig_size);
        size_t classical_sig_len = (static_cast<size_t>(signature[pqc_sig_size]) << 8) |
                                    signature[pqc_sig_size + 1];

        if (signature.size() < pqc_sig_size + 2 + classical_sig_len) {
            return false;
        }
        auto classical_sig = signature.subspan(pqc_sig_size + 2, classical_sig_len);

        // Both must verify
        bool pqc_valid = pqc_->verify(pqc_pk, message, pqc_sig, ctx);
        bool classical_valid = classical_dsa_verify(classical_, classical_pk,
                                                     message, classical_sig);

        return pqc_valid && classical_valid;
    }

    [[nodiscard]] size_t public_key_size() const override {
        return pqc_->public_key_size() + classical_pk_size_;
    }

    [[nodiscard]] size_t secret_key_size() const override {
        return pqc_->secret_key_size() + classical_sk_size_;
    }

    [[nodiscard]] size_t signature_size() const override {
        return pqc_->signature_size() + 2 + classical_sig_size_;
    }

private:
    std::unique_ptr<DigitalSignature> pqc_;
    ClassicalDSA classical_;
    size_t classical_pk_size_;
    size_t classical_sk_size_;
    size_t classical_sig_size_;

    std::string classical_name() const {
        switch (classical_) {
            case ClassicalDSA::ECDSA_P256: return "ECDSA-P256";
            case ClassicalDSA::ECDSA_P384: return "ECDSA-P384";
            case ClassicalDSA::Ed25519:    return "Ed25519";
        }
        return "Unknown";
    }
};

// ============================================================================
// Hybrid KEM Implementation
// ============================================================================

class HybridKEMImpl final : public HybridKeyEncapsulation {
public:
    HybridKEMImpl(std::unique_ptr<KeyEncapsulation> pqc, ClassicalKEM classical)
        : pqc_(std::move(pqc)), classical_(classical) {

        auto [cpk, csk, cct] = get_classical_kem_sizes(classical_);
        classical_pk_size_ = cpk;
        classical_sk_size_ = csk;
        classical_ct_size_ = cct;
    }

    [[nodiscard]] std::string name() const override {
        return pqc_->name() + "+" + classical_name();
    }

    [[nodiscard]] std::string pqc_algorithm() const override {
        return pqc_->name();
    }

    [[nodiscard]] std::string classical_algorithm() const override {
        return classical_name();
    }

    [[nodiscard]] std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    keygen() const override {
        // Generate PQC key pair
        auto [pqc_ek, pqc_dk] = pqc_->keygen();

        // Generate classical key pair
        auto [classical_pk, classical_sk] = classical_kem_keygen(classical_);

        // Concatenate: ek = pqc_ek || classical_pk, dk = pqc_dk || classical_sk
        std::vector<uint8_t> ek;
        ek.reserve(pqc_ek.size() + classical_pk.size());
        ek.insert(ek.end(), pqc_ek.begin(), pqc_ek.end());
        ek.insert(ek.end(), classical_pk.begin(), classical_pk.end());

        std::vector<uint8_t> dk;
        dk.reserve(pqc_dk.size() + classical_sk.size());
        dk.insert(dk.end(), pqc_dk.begin(), pqc_dk.end());
        dk.insert(dk.end(), classical_sk.begin(), classical_sk.end());

        return {std::move(ek), std::move(dk)};
    }

    [[nodiscard]] std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
    encaps(std::span<const uint8_t> ek) const override {
        size_t pqc_ek_size = pqc_->encapsulation_key_size();
        if (ek.size() < pqc_ek_size + classical_pk_size_) {
            throw std::invalid_argument("Encapsulation key too short");
        }

        auto pqc_ek = ek.subspan(0, pqc_ek_size);
        auto classical_pk = ek.subspan(pqc_ek_size, classical_pk_size_);

        // Encapsulate with PQC
        auto [pqc_ss, pqc_ct] = pqc_->encaps(pqc_ek);

        // Generate ephemeral classical key and derive shared secret
        auto [eph_pk, eph_sk] = classical_kem_keygen(classical_);
        auto classical_ss = ecdh_derive(classical_, eph_sk, classical_pk);

        // Combine shared secrets using HKDF
        std::vector<uint8_t> combined_ss;
        combined_ss.reserve(pqc_ss.size() + classical_ss.size());
        combined_ss.insert(combined_ss.end(), pqc_ss.begin(), pqc_ss.end());
        combined_ss.insert(combined_ss.end(), classical_ss.begin(), classical_ss.end());

        std::string info_str = "hybrid-kem:" + name();
        std::vector<uint8_t> info(info_str.begin(), info_str.end());
        std::vector<uint8_t> salt;  // Empty salt

        auto shared_secret = hkdf_sha256(combined_ss, salt, info, 32);

        // Ciphertext = pqc_ct || ephemeral_pk
        std::vector<uint8_t> ciphertext;
        ciphertext.reserve(pqc_ct.size() + eph_pk.size());
        ciphertext.insert(ciphertext.end(), pqc_ct.begin(), pqc_ct.end());
        ciphertext.insert(ciphertext.end(), eph_pk.begin(), eph_pk.end());

        return {std::move(shared_secret), std::move(ciphertext)};
    }

    [[nodiscard]] std::vector<uint8_t> decaps(
        std::span<const uint8_t> dk,
        std::span<const uint8_t> ciphertext) const override {

        size_t pqc_dk_size = pqc_->decapsulation_key_size();
        size_t pqc_ct_size = pqc_->ciphertext_size();

        if (dk.size() < pqc_dk_size + classical_sk_size_) {
            throw std::invalid_argument("Decapsulation key too short");
        }
        if (ciphertext.size() < pqc_ct_size + classical_ct_size_) {
            throw std::invalid_argument("Ciphertext too short");
        }

        auto pqc_dk = dk.subspan(0, pqc_dk_size);
        auto classical_sk = dk.subspan(pqc_dk_size, classical_sk_size_);

        auto pqc_ct = ciphertext.subspan(0, pqc_ct_size);
        auto eph_pk = ciphertext.subspan(pqc_ct_size, classical_ct_size_);

        // Decapsulate PQC
        auto pqc_ss = pqc_->decaps(pqc_dk, pqc_ct);

        // Derive classical shared secret
        auto classical_ss = ecdh_derive(classical_, classical_sk, eph_pk);

        // Combine shared secrets using HKDF
        std::vector<uint8_t> combined_ss;
        combined_ss.reserve(pqc_ss.size() + classical_ss.size());
        combined_ss.insert(combined_ss.end(), pqc_ss.begin(), pqc_ss.end());
        combined_ss.insert(combined_ss.end(), classical_ss.begin(), classical_ss.end());

        std::string info_str = "hybrid-kem:" + name();
        std::vector<uint8_t> info(info_str.begin(), info_str.end());
        std::vector<uint8_t> salt;

        return hkdf_sha256(combined_ss, salt, info, 32);
    }

    [[nodiscard]] size_t encapsulation_key_size() const override {
        return pqc_->encapsulation_key_size() + classical_pk_size_;
    }

    [[nodiscard]] size_t decapsulation_key_size() const override {
        return pqc_->decapsulation_key_size() + classical_sk_size_;
    }

    [[nodiscard]] size_t ciphertext_size() const override {
        return pqc_->ciphertext_size() + classical_ct_size_;
    }

    [[nodiscard]] size_t shared_secret_size() const override {
        return 32;  // HKDF output is always 32 bytes
    }

private:
    std::unique_ptr<KeyEncapsulation> pqc_;
    ClassicalKEM classical_;
    size_t classical_pk_size_;
    size_t classical_sk_size_;
    size_t classical_ct_size_;

    std::string classical_name() const {
        switch (classical_) {
            case ClassicalKEM::X25519:    return "X25519";
            case ClassicalKEM::ECDH_P256: return "ECDH-P256";
        }
        return "Unknown";
    }
};

} // namespace detail

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Parse classical DSA algorithm name
 */
inline ClassicalDSA parse_classical_dsa(const std::string& name) {
    if (name == "ECDSA-P256" || name == "P256" || name == "prime256v1")
        return ClassicalDSA::ECDSA_P256;
    if (name == "ECDSA-P384" || name == "P384" || name == "secp384r1")
        return ClassicalDSA::ECDSA_P384;
    if (name == "Ed25519" || name == "ed25519")
        return ClassicalDSA::Ed25519;
    throw std::invalid_argument("Unknown classical DSA: " + name);
}

/**
 * Parse classical KEM algorithm name
 */
inline ClassicalKEM parse_classical_kem(const std::string& name) {
    if (name == "X25519" || name == "x25519")
        return ClassicalKEM::X25519;
    if (name == "ECDH-P256" || name == "P256" || name == "prime256v1")
        return ClassicalKEM::ECDH_P256;
    throw std::invalid_argument("Unknown classical KEM: " + name);
}

/**
 * Create a hybrid digital signature scheme
 *
 * @param pqc_name PQC algorithm name (e.g., "ML-DSA-65")
 * @param classical_name Classical algorithm name (e.g., "Ed25519", "ECDSA-P256")
 * @return unique_ptr to HybridDigitalSignature
 */
inline std::unique_ptr<HybridDigitalSignature> create_hybrid_dsa(
    const std::string& pqc_name,
    const std::string& classical_name) {

    auto pqc = create_dsa(pqc_name);
    auto classical = parse_classical_dsa(classical_name);

    return std::make_unique<detail::HybridDSAImpl>(std::move(pqc), classical);
}

/**
 * Create a hybrid KEM scheme
 *
 * @param pqc_name PQC algorithm name (e.g., "ML-KEM-768")
 * @param classical_name Classical algorithm name (e.g., "X25519")
 * @return unique_ptr to HybridKeyEncapsulation
 */
inline std::unique_ptr<HybridKeyEncapsulation> create_hybrid_kem(
    const std::string& pqc_name,
    const std::string& classical_name) {

    auto pqc = create_kem(pqc_name);
    auto classical = parse_classical_kem(classical_name);

    return std::make_unique<detail::HybridKEMImpl>(std::move(pqc), classical);
}

/**
 * List available classical DSA algorithm names
 */
inline std::vector<std::string> available_classical_dsa() {
    return {"ECDSA-P256", "ECDSA-P384", "Ed25519"};
}

/**
 * List available classical KEM algorithm names
 */
inline std::vector<std::string> available_classical_kem() {
    return {"X25519", "ECDH-P256"};
}

} // namespace pqc

#endif // COMMON_HYBRID_HPP
