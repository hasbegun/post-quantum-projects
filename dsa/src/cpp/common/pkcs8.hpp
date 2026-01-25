/**
 * PKCS#8 and SubjectPublicKeyInfo (SPKI) Key Formats
 *
 * Implements standard key serialization formats for post-quantum algorithms:
 * - PKCS#8 (RFC 5958) for private keys
 * - SubjectPublicKeyInfo (RFC 5280) for public keys
 *
 * OIDs are from NIST CSOR and IETF drafts:
 * - ML-DSA: draft-ietf-lamps-dilithium-certificates
 * - SLH-DSA: draft-ietf-lamps-x509-shbs
 * - ML-KEM: draft-ietf-lamps-kyber-certificates
 *
 * PKCS#8 PrivateKeyInfo structure:
 *   SEQUENCE {
 *     version INTEGER (0),
 *     privateKeyAlgorithm AlgorithmIdentifier,
 *     privateKey OCTET STRING
 *   }
 *
 * SubjectPublicKeyInfo structure:
 *   SEQUENCE {
 *     algorithm AlgorithmIdentifier,
 *     subjectPublicKey BIT STRING
 *   }
 *
 * AlgorithmIdentifier structure:
 *   SEQUENCE {
 *     algorithm OBJECT IDENTIFIER,
 *     parameters ANY DEFINED BY algorithm OPTIONAL
 *   }
 */

#ifndef COMMON_PKCS8_HPP
#define COMMON_PKCS8_HPP

#include "asn1.hpp"
#include "pem.hpp"
#include <cstdint>
#include <vector>
#include <string>
#include <optional>
#include <stdexcept>

namespace pkcs8 {

/**
 * Algorithm identifiers with their OIDs
 * OID arc: 2.16.840.1.101.3.4 (NIST algorithms)
 */
enum class Algorithm {
    // ML-DSA (FIPS 204) - OID arc 2.16.840.1.101.3.4.3.x
    ML_DSA_44,      // 2.16.840.1.101.3.4.3.17
    ML_DSA_65,      // 2.16.840.1.101.3.4.3.18
    ML_DSA_87,      // 2.16.840.1.101.3.4.3.19

    // ML-KEM (FIPS 203) - OID arc 2.16.840.1.101.3.4.4.x
    ML_KEM_512,     // 2.16.840.1.101.3.4.4.1
    ML_KEM_768,     // 2.16.840.1.101.3.4.4.2
    ML_KEM_1024,    // 2.16.840.1.101.3.4.4.3

    // SLH-DSA (FIPS 205) - SHA2 variants (2.16.840.1.101.3.4.3.x)
    SLH_DSA_SHA2_128s,   // 2.16.840.1.101.3.4.3.20
    SLH_DSA_SHA2_128f,   // 2.16.840.1.101.3.4.3.21
    SLH_DSA_SHA2_192s,   // 2.16.840.1.101.3.4.3.22
    SLH_DSA_SHA2_192f,   // 2.16.840.1.101.3.4.3.23
    SLH_DSA_SHA2_256s,   // 2.16.840.1.101.3.4.3.24
    SLH_DSA_SHA2_256f,   // 2.16.840.1.101.3.4.3.25

    // SLH-DSA (FIPS 205) - SHAKE variants (2.16.840.1.101.3.4.3.x)
    SLH_DSA_SHAKE_128s,  // 2.16.840.1.101.3.4.3.26
    SLH_DSA_SHAKE_128f,  // 2.16.840.1.101.3.4.3.27
    SLH_DSA_SHAKE_192s,  // 2.16.840.1.101.3.4.3.28
    SLH_DSA_SHAKE_192f,  // 2.16.840.1.101.3.4.3.29
    SLH_DSA_SHAKE_256s,  // 2.16.840.1.101.3.4.3.30
    SLH_DSA_SHAKE_256f   // 2.16.840.1.101.3.4.3.31
};

/**
 * Get the OID string for an algorithm
 */
inline std::string get_oid(Algorithm alg) {
    switch (alg) {
        // ML-DSA
        case Algorithm::ML_DSA_44:        return "2.16.840.1.101.3.4.3.17";
        case Algorithm::ML_DSA_65:        return "2.16.840.1.101.3.4.3.18";
        case Algorithm::ML_DSA_87:        return "2.16.840.1.101.3.4.3.19";

        // ML-KEM
        case Algorithm::ML_KEM_512:       return "2.16.840.1.101.3.4.4.1";
        case Algorithm::ML_KEM_768:       return "2.16.840.1.101.3.4.4.2";
        case Algorithm::ML_KEM_1024:      return "2.16.840.1.101.3.4.4.3";

        // SLH-DSA SHA2
        case Algorithm::SLH_DSA_SHA2_128s: return "2.16.840.1.101.3.4.3.20";
        case Algorithm::SLH_DSA_SHA2_128f: return "2.16.840.1.101.3.4.3.21";
        case Algorithm::SLH_DSA_SHA2_192s: return "2.16.840.1.101.3.4.3.22";
        case Algorithm::SLH_DSA_SHA2_192f: return "2.16.840.1.101.3.4.3.23";
        case Algorithm::SLH_DSA_SHA2_256s: return "2.16.840.1.101.3.4.3.24";
        case Algorithm::SLH_DSA_SHA2_256f: return "2.16.840.1.101.3.4.3.25";

        // SLH-DSA SHAKE
        case Algorithm::SLH_DSA_SHAKE_128s: return "2.16.840.1.101.3.4.3.26";
        case Algorithm::SLH_DSA_SHAKE_128f: return "2.16.840.1.101.3.4.3.27";
        case Algorithm::SLH_DSA_SHAKE_192s: return "2.16.840.1.101.3.4.3.28";
        case Algorithm::SLH_DSA_SHAKE_192f: return "2.16.840.1.101.3.4.3.29";
        case Algorithm::SLH_DSA_SHAKE_256s: return "2.16.840.1.101.3.4.3.30";
        case Algorithm::SLH_DSA_SHAKE_256f: return "2.16.840.1.101.3.4.3.31";

        default:
            throw std::runtime_error("Unknown algorithm");
    }
}

/**
 * Get algorithm from OID string
 */
inline std::optional<Algorithm> algorithm_from_oid(const std::string& oid) {
    // ML-DSA
    if (oid == "2.16.840.1.101.3.4.3.17") return Algorithm::ML_DSA_44;
    if (oid == "2.16.840.1.101.3.4.3.18") return Algorithm::ML_DSA_65;
    if (oid == "2.16.840.1.101.3.4.3.19") return Algorithm::ML_DSA_87;

    // ML-KEM
    if (oid == "2.16.840.1.101.3.4.4.1") return Algorithm::ML_KEM_512;
    if (oid == "2.16.840.1.101.3.4.4.2") return Algorithm::ML_KEM_768;
    if (oid == "2.16.840.1.101.3.4.4.3") return Algorithm::ML_KEM_1024;

    // SLH-DSA SHA2
    if (oid == "2.16.840.1.101.3.4.3.20") return Algorithm::SLH_DSA_SHA2_128s;
    if (oid == "2.16.840.1.101.3.4.3.21") return Algorithm::SLH_DSA_SHA2_128f;
    if (oid == "2.16.840.1.101.3.4.3.22") return Algorithm::SLH_DSA_SHA2_192s;
    if (oid == "2.16.840.1.101.3.4.3.23") return Algorithm::SLH_DSA_SHA2_192f;
    if (oid == "2.16.840.1.101.3.4.3.24") return Algorithm::SLH_DSA_SHA2_256s;
    if (oid == "2.16.840.1.101.3.4.3.25") return Algorithm::SLH_DSA_SHA2_256f;

    // SLH-DSA SHAKE
    if (oid == "2.16.840.1.101.3.4.3.26") return Algorithm::SLH_DSA_SHAKE_128s;
    if (oid == "2.16.840.1.101.3.4.3.27") return Algorithm::SLH_DSA_SHAKE_128f;
    if (oid == "2.16.840.1.101.3.4.3.28") return Algorithm::SLH_DSA_SHAKE_192s;
    if (oid == "2.16.840.1.101.3.4.3.29") return Algorithm::SLH_DSA_SHAKE_192f;
    if (oid == "2.16.840.1.101.3.4.3.30") return Algorithm::SLH_DSA_SHAKE_256s;
    if (oid == "2.16.840.1.101.3.4.3.31") return Algorithm::SLH_DSA_SHAKE_256f;

    return std::nullopt;
}

/**
 * Get human-readable algorithm name
 */
inline std::string get_algorithm_name(Algorithm alg) {
    switch (alg) {
        case Algorithm::ML_DSA_44:        return "ML-DSA-44";
        case Algorithm::ML_DSA_65:        return "ML-DSA-65";
        case Algorithm::ML_DSA_87:        return "ML-DSA-87";
        case Algorithm::ML_KEM_512:       return "ML-KEM-512";
        case Algorithm::ML_KEM_768:       return "ML-KEM-768";
        case Algorithm::ML_KEM_1024:      return "ML-KEM-1024";
        case Algorithm::SLH_DSA_SHA2_128s: return "SLH-DSA-SHA2-128s";
        case Algorithm::SLH_DSA_SHA2_128f: return "SLH-DSA-SHA2-128f";
        case Algorithm::SLH_DSA_SHA2_192s: return "SLH-DSA-SHA2-192s";
        case Algorithm::SLH_DSA_SHA2_192f: return "SLH-DSA-SHA2-192f";
        case Algorithm::SLH_DSA_SHA2_256s: return "SLH-DSA-SHA2-256s";
        case Algorithm::SLH_DSA_SHA2_256f: return "SLH-DSA-SHA2-256f";
        case Algorithm::SLH_DSA_SHAKE_128s: return "SLH-DSA-SHAKE-128s";
        case Algorithm::SLH_DSA_SHAKE_128f: return "SLH-DSA-SHAKE-128f";
        case Algorithm::SLH_DSA_SHAKE_192s: return "SLH-DSA-SHAKE-192s";
        case Algorithm::SLH_DSA_SHAKE_192f: return "SLH-DSA-SHAKE-192f";
        case Algorithm::SLH_DSA_SHAKE_256s: return "SLH-DSA-SHAKE-256s";
        case Algorithm::SLH_DSA_SHAKE_256f: return "SLH-DSA-SHAKE-256f";
        default: return "Unknown";
    }
}

/**
 * Encode AlgorithmIdentifier
 * For PQC algorithms, parameters are absent (implicit NULL per NIST)
 */
inline std::vector<uint8_t> encode_algorithm_identifier(Algorithm alg) {
    auto oid = asn1::encode_oid(get_oid(alg));
    // PQC algorithms have absent parameters (not NULL)
    return asn1::encode_sequence(oid);
}

/**
 * Encode private key in PKCS#8 format (DER)
 *
 * PKCS#8 PrivateKeyInfo ::= SEQUENCE {
 *   version INTEGER (0),
 *   privateKeyAlgorithm AlgorithmIdentifier,
 *   privateKey OCTET STRING
 * }
 */
inline std::vector<uint8_t> encode_private_key_der(
    Algorithm alg,
    const std::vector<uint8_t>& raw_private_key) {

    auto version = asn1::encode_integer(0);
    auto alg_id = encode_algorithm_identifier(alg);
    auto private_key = asn1::encode_octet_string(raw_private_key);

    auto content = asn1::concat({version, alg_id, private_key});
    return asn1::encode_sequence(content);
}

/**
 * Encode private key in PKCS#8 format (PEM)
 */
inline std::string encode_private_key_pem(
    Algorithm alg,
    const std::vector<uint8_t>& raw_private_key) {

    auto der = encode_private_key_der(alg, raw_private_key);
    return pem::encode(der, "PRIVATE KEY");
}

/**
 * Encode public key in SubjectPublicKeyInfo format (DER)
 *
 * SubjectPublicKeyInfo ::= SEQUENCE {
 *   algorithm AlgorithmIdentifier,
 *   subjectPublicKey BIT STRING
 * }
 */
inline std::vector<uint8_t> encode_public_key_der(
    Algorithm alg,
    const std::vector<uint8_t>& raw_public_key) {

    auto alg_id = encode_algorithm_identifier(alg);
    auto public_key = asn1::encode_bit_string(raw_public_key);

    auto content = asn1::concat({alg_id, public_key});
    return asn1::encode_sequence(content);
}

/**
 * Encode public key in SubjectPublicKeyInfo format (PEM)
 */
inline std::string encode_public_key_pem(
    Algorithm alg,
    const std::vector<uint8_t>& raw_public_key) {

    auto der = encode_public_key_der(alg, raw_public_key);
    return pem::encode(der, "PUBLIC KEY");
}

/**
 * Decoded private key result
 */
struct PrivateKeyInfo {
    Algorithm algorithm;
    std::vector<uint8_t> private_key;
};

/**
 * Decoded public key result
 */
struct SubjectPublicKeyInfo {
    Algorithm algorithm;
    std::vector<uint8_t> public_key;
};

/**
 * Decode private key from PKCS#8 DER format
 */
inline std::optional<PrivateKeyInfo> decode_private_key_der(
    const std::vector<uint8_t>& der) {

    // Parse outer SEQUENCE
    auto outer = asn1::decode_tlv(der.data(), der.size());
    if (!outer || outer->tag != asn1::Tag::SEQUENCE) {
        return std::nullopt;
    }

    const uint8_t* ptr = outer->value.data();
    size_t remaining = outer->value.size();

    // Parse version INTEGER
    auto version = asn1::decode_tlv(ptr, remaining);
    if (!version || version->tag != asn1::Tag::INTEGER) {
        return std::nullopt;
    }
    if (version->value.size() != 1 || version->value[0] != 0) {
        return std::nullopt;  // Only version 0 supported
    }
    ptr += version->total_length;
    remaining -= version->total_length;

    // Parse AlgorithmIdentifier SEQUENCE
    auto alg_id = asn1::decode_tlv(ptr, remaining);
    if (!alg_id || alg_id->tag != asn1::Tag::SEQUENCE) {
        return std::nullopt;
    }

    // Extract OID from AlgorithmIdentifier
    auto oid_tlv = asn1::decode_tlv(alg_id->value.data(), alg_id->value.size());
    if (!oid_tlv || oid_tlv->tag != asn1::Tag::OBJECT_IDENTIFIER) {
        return std::nullopt;
    }
    auto oid_str = asn1::decode_oid(oid_tlv->value);
    if (!oid_str) {
        return std::nullopt;
    }
    auto alg = algorithm_from_oid(*oid_str);
    if (!alg) {
        return std::nullopt;
    }

    ptr += alg_id->total_length;
    remaining -= alg_id->total_length;

    // Parse privateKey OCTET STRING
    auto priv_key = asn1::decode_tlv(ptr, remaining);
    if (!priv_key || priv_key->tag != asn1::Tag::OCTET_STRING) {
        return std::nullopt;
    }

    return PrivateKeyInfo{*alg, priv_key->value};
}

/**
 * Decode private key from PKCS#8 PEM format
 */
inline std::optional<PrivateKeyInfo> decode_private_key_pem(const std::string& pem_data) {
    auto der = pem::decode(pem_data, "PRIVATE KEY");
    if (!der) {
        return std::nullopt;
    }
    return decode_private_key_der(*der);
}

/**
 * Decode public key from SubjectPublicKeyInfo DER format
 */
inline std::optional<SubjectPublicKeyInfo> decode_public_key_der(
    const std::vector<uint8_t>& der) {

    // Parse outer SEQUENCE
    auto outer = asn1::decode_tlv(der.data(), der.size());
    if (!outer || outer->tag != asn1::Tag::SEQUENCE) {
        return std::nullopt;
    }

    const uint8_t* ptr = outer->value.data();
    size_t remaining = outer->value.size();

    // Parse AlgorithmIdentifier SEQUENCE
    auto alg_id = asn1::decode_tlv(ptr, remaining);
    if (!alg_id || alg_id->tag != asn1::Tag::SEQUENCE) {
        return std::nullopt;
    }

    // Extract OID from AlgorithmIdentifier
    auto oid_tlv = asn1::decode_tlv(alg_id->value.data(), alg_id->value.size());
    if (!oid_tlv || oid_tlv->tag != asn1::Tag::OBJECT_IDENTIFIER) {
        return std::nullopt;
    }
    auto oid_str = asn1::decode_oid(oid_tlv->value);
    if (!oid_str) {
        return std::nullopt;
    }
    auto alg = algorithm_from_oid(*oid_str);
    if (!alg) {
        return std::nullopt;
    }

    ptr += alg_id->total_length;
    remaining -= alg_id->total_length;

    // Parse subjectPublicKey BIT STRING
    auto pub_key = asn1::decode_tlv(ptr, remaining);
    if (!pub_key || pub_key->tag != asn1::Tag::BIT_STRING) {
        return std::nullopt;
    }
    auto key_data = asn1::decode_bit_string(pub_key->value);
    if (!key_data) {
        return std::nullopt;
    }

    return SubjectPublicKeyInfo{*alg, *key_data};
}

/**
 * Decode public key from SubjectPublicKeyInfo PEM format
 */
inline std::optional<SubjectPublicKeyInfo> decode_public_key_pem(const std::string& pem_data) {
    auto der = pem::decode(pem_data, "PUBLIC KEY");
    if (!der) {
        return std::nullopt;
    }
    return decode_public_key_der(*der);
}

} // namespace pkcs8

#endif // COMMON_PKCS8_HPP
