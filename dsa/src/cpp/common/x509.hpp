/**
 * X.509 Certificate Support for Post-Quantum Cryptography
 *
 * Implements X.509 v3 certificate generation and parsing for PQC algorithms.
 * Supports self-signed certificates and certificate verification.
 *
 * Certificate structure (RFC 5280):
 *   Certificate ::= SEQUENCE {
 *     tbsCertificate       TBSCertificate,
 *     signatureAlgorithm   AlgorithmIdentifier,
 *     signatureValue       BIT STRING
 *   }
 *
 *   TBSCertificate ::= SEQUENCE {
 *     version         [0] EXPLICIT Version DEFAULT v1,
 *     serialNumber         CertificateSerialNumber,
 *     signature            AlgorithmIdentifier,
 *     issuer               Name,
 *     validity             Validity,
 *     subject              Name,
 *     subjectPublicKeyInfo SubjectPublicKeyInfo
 *   }
 */

#ifndef COMMON_X509_HPP
#define COMMON_X509_HPP

#include "asn1.hpp"
#include "pem.hpp"
#include "pkcs8.hpp"
#include <cstdint>
#include <vector>
#include <string>
#include <optional>
#include <functional>
#include <chrono>
#include <ctime>
#include <random>
#include <map>

namespace x509 {

// ============================================================================
// Distinguished Name (DN)
// ============================================================================

// Standard X.500 attribute type OIDs
namespace oid {
    inline const std::string COMMON_NAME           = "2.5.4.3";
    inline const std::string COUNTRY               = "2.5.4.6";
    inline const std::string LOCALITY               = "2.5.4.7";
    inline const std::string STATE                  = "2.5.4.8";
    inline const std::string ORGANIZATION           = "2.5.4.10";
    inline const std::string ORGANIZATIONAL_UNIT    = "2.5.4.11";
    inline const std::string EMAIL_ADDRESS          = "1.2.840.113549.1.9.1";
} // namespace oid

/**
 * Distinguished Name builder
 * Encodes X.500 Name as SEQUENCE OF RelativeDistinguishedName
 */
struct DistinguishedName {
    std::string common_name;
    std::string country;
    std::string state;
    std::string locality;
    std::string organization;
    std::string organizational_unit;
    std::string email;

    /**
     * Encode a single AttributeTypeAndValue
     */
    static std::vector<uint8_t> encode_atv(
        const std::string& oid_str,
        const std::string& value,
        bool use_utf8 = false) {

        auto oid_encoded = asn1::encode_oid(oid_str);
        auto value_encoded = use_utf8
            ? asn1::encode_utf8_string(value)
            : asn1::encode_printable_string(value);

        return asn1::encode_sequence(asn1::concat({oid_encoded, value_encoded}));
    }

    /**
     * Encode as DER
     */
    std::vector<uint8_t> encode() const {
        std::vector<uint8_t> rdns;

        // Each RDN is a SET containing one AttributeTypeAndValue
        auto add_rdn = [&rdns](const std::string& oid_str,
                                const std::string& value,
                                bool use_utf8 = false) {
            if (!value.empty()) {
                auto atv = encode_atv(oid_str, value, use_utf8);
                auto rdn = asn1::encode_set(atv);
                rdns.insert(rdns.end(), rdn.begin(), rdn.end());
            }
        };

        add_rdn(oid::COUNTRY, country);
        add_rdn(oid::STATE, state);
        add_rdn(oid::LOCALITY, locality);
        add_rdn(oid::ORGANIZATION, organization);
        add_rdn(oid::ORGANIZATIONAL_UNIT, organizational_unit);
        add_rdn(oid::COMMON_NAME, common_name, true);
        add_rdn(oid::EMAIL_ADDRESS, email, true);

        return asn1::encode_sequence(rdns);
    }

    /**
     * Get RFC 4514 string representation (e.g., "CN=Test,O=Org,C=US")
     */
    std::string to_string() const {
        std::string result;
        auto append = [&result](const std::string& key, const std::string& val) {
            if (!val.empty()) {
                if (!result.empty()) result += ", ";
                result += key + "=" + val;
            }
        };
        append("CN", common_name);
        append("O", organization);
        append("OU", organizational_unit);
        append("L", locality);
        append("ST", state);
        append("C", country);
        append("emailAddress", email);
        return result;
    }
};

// ============================================================================
// Time utilities
// ============================================================================

/**
 * Format a time_point as UTCTime string "YYMMDDHHMMSSZ"
 * Used for dates in range 1950-2049
 */
inline std::string format_utc_time(std::chrono::system_clock::time_point tp) {
    auto time = std::chrono::system_clock::to_time_t(tp);
    std::tm tm_buf{};
    gmtime_r(&time, &tm_buf);

    char buf[16];
    std::snprintf(buf, sizeof(buf), "%02d%02d%02d%02d%02d%02dZ",
        tm_buf.tm_year % 100,
        tm_buf.tm_mon + 1,
        tm_buf.tm_mday,
        tm_buf.tm_hour,
        tm_buf.tm_min,
        tm_buf.tm_sec);
    return std::string(buf);
}

/**
 * Format a time_point as GeneralizedTime string "YYYYMMDDHHMMSSZ"
 * Used for dates >= 2050
 */
inline std::string format_generalized_time(std::chrono::system_clock::time_point tp) {
    auto time = std::chrono::system_clock::to_time_t(tp);
    std::tm tm_buf{};
    gmtime_r(&time, &tm_buf);

    char buf[20];
    std::snprintf(buf, sizeof(buf), "%04d%02d%02d%02d%02d%02dZ",
        tm_buf.tm_year + 1900,
        tm_buf.tm_mon + 1,
        tm_buf.tm_mday,
        tm_buf.tm_hour,
        tm_buf.tm_min,
        tm_buf.tm_sec);
    return std::string(buf);
}

/**
 * Encode a time value as UTCTime or GeneralizedTime depending on year
 */
inline std::vector<uint8_t> encode_time(std::chrono::system_clock::time_point tp) {
    auto time = std::chrono::system_clock::to_time_t(tp);
    std::tm tm_buf{};
    gmtime_r(&time, &tm_buf);

    int year = tm_buf.tm_year + 1900;
    if (year >= 2050) {
        return asn1::encode_generalized_time(format_generalized_time(tp));
    } else {
        return asn1::encode_utc_time(format_utc_time(tp));
    }
}

/**
 * Encode Validity period
 */
inline std::vector<uint8_t> encode_validity(
    std::chrono::system_clock::time_point not_before,
    std::chrono::system_clock::time_point not_after) {

    auto nb = encode_time(not_before);
    auto na = encode_time(not_after);
    return asn1::encode_sequence(asn1::concat({nb, na}));
}

// ============================================================================
// Serial Number
// ============================================================================

/**
 * Generate a random 20-byte serial number (per RFC 5280 recommendation)
 */
inline std::vector<uint8_t> generate_serial_number() {
    std::vector<uint8_t> serial(20);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint16_t> dist(0, 255);

    for (auto& b : serial) {
        b = static_cast<uint8_t>(dist(gen));
    }
    // Ensure positive (clear high bit)
    serial[0] &= 0x7F;
    // Ensure non-zero first byte
    if (serial[0] == 0) serial[0] = 0x01;

    return serial;
}

// ============================================================================
// X.509 v3 Extensions
// ============================================================================

/**
 * Encode BasicConstraints extension
 * BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE }
 */
inline std::vector<uint8_t> encode_basic_constraints(bool is_ca, bool critical = true) {
    // Extension value
    std::vector<uint8_t> bc_value;
    if (is_ca) {
        bc_value = asn1::encode_sequence(asn1::encode_boolean(true));
    } else {
        bc_value = asn1::encode_sequence(std::vector<uint8_t>{});
    }

    // Extension ::= SEQUENCE { extnID OID, critical BOOLEAN, extnValue OCTET STRING }
    auto ext_oid = asn1::encode_oid("2.5.29.19");  // id-ce-basicConstraints
    auto ext_critical = critical ? asn1::encode_boolean(true) : std::vector<uint8_t>{};
    auto ext_value = asn1::encode_octet_string(bc_value);

    std::vector<uint8_t> ext_content;
    ext_content.insert(ext_content.end(), ext_oid.begin(), ext_oid.end());
    if (!ext_critical.empty()) {
        ext_content.insert(ext_content.end(), ext_critical.begin(), ext_critical.end());
    }
    ext_content.insert(ext_content.end(), ext_value.begin(), ext_value.end());

    return asn1::encode_sequence(ext_content);
}

/**
 * Encode KeyUsage extension
 * KeyUsage ::= BIT STRING
 */
inline std::vector<uint8_t> encode_key_usage(
    bool digital_signature = true,
    bool key_cert_sign = false,
    bool crl_sign = false,
    bool critical = true) {

    // Build key usage bits
    uint8_t byte0 = 0;
    uint8_t unused_bits = 0;

    if (digital_signature) byte0 |= 0x80;  // bit 0
    if (key_cert_sign)     byte0 |= 0x04;  // bit 5
    if (crl_sign)          byte0 |= 0x02;  // bit 6

    // Count unused bits in last byte
    if (byte0 == 0) {
        unused_bits = 8;
    } else {
        unused_bits = 0;
        uint8_t tmp = byte0;
        while ((tmp & 0x01) == 0) {
            unused_bits++;
            tmp >>= 1;
        }
    }

    // BIT STRING encoding: unused_bits + data
    std::vector<uint8_t> ku_bits = {unused_bits, byte0};
    auto ku_value = asn1::encode_tlv(asn1::Tag::BIT_STRING, ku_bits);

    // Wrap in extension
    auto ext_oid = asn1::encode_oid("2.5.29.15");  // id-ce-keyUsage
    auto ext_critical = critical ? asn1::encode_boolean(true) : std::vector<uint8_t>{};
    auto ext_value = asn1::encode_octet_string(ku_value);

    std::vector<uint8_t> ext_content;
    ext_content.insert(ext_content.end(), ext_oid.begin(), ext_oid.end());
    if (!ext_critical.empty()) {
        ext_content.insert(ext_content.end(), ext_critical.begin(), ext_critical.end());
    }
    ext_content.insert(ext_content.end(), ext_value.begin(), ext_value.end());

    return asn1::encode_sequence(ext_content);
}

/**
 * Encode Extensions wrapper as [3] EXPLICIT SEQUENCE OF Extension
 */
inline std::vector<uint8_t> encode_extensions(
    const std::vector<std::vector<uint8_t>>& extensions) {

    std::vector<uint8_t> ext_seq;
    for (const auto& ext : extensions) {
        ext_seq.insert(ext_seq.end(), ext.begin(), ext.end());
    }
    auto seq = asn1::encode_sequence(ext_seq);
    return asn1::encode_explicit_tag(3, seq);
}

// ============================================================================
// Certificate Builder
// ============================================================================

/**
 * Signing callback type
 * Takes the TBSCertificate DER bytes and returns the signature
 */
using SignCallback = std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)>;

/**
 * Verification callback type
 * Takes (public_key, tbs_data, signature) and returns true if valid
 */
using VerifyCallback = std::function<bool(
    const std::vector<uint8_t>&,
    const std::vector<uint8_t>&,
    const std::vector<uint8_t>&)>;

/**
 * Certificate parameters for building an X.509 v3 certificate
 */
struct CertificateParams {
    pkcs8::Algorithm algorithm;
    std::vector<uint8_t> serial_number;  // If empty, auto-generated
    DistinguishedName issuer;
    DistinguishedName subject;
    std::chrono::system_clock::time_point not_before;
    std::chrono::system_clock::time_point not_after;
    std::vector<uint8_t> public_key;     // Raw public key bytes
    bool is_ca = false;
    bool include_key_usage = true;
};

/**
 * Build the TBSCertificate DER structure
 */
inline std::vector<uint8_t> build_tbs_certificate(const CertificateParams& params) {
    std::vector<uint8_t> tbs;

    // version [0] EXPLICIT Version (v3 = 2)
    auto version = asn1::encode_explicit_tag(0, asn1::encode_integer(2));
    tbs.insert(tbs.end(), version.begin(), version.end());

    // serialNumber
    auto serial = params.serial_number.empty()
        ? generate_serial_number()
        : params.serial_number;
    auto serial_enc = asn1::encode_integer_bytes(serial);
    tbs.insert(tbs.end(), serial_enc.begin(), serial_enc.end());

    // signature AlgorithmIdentifier (same as outer signatureAlgorithm)
    auto alg_id = pkcs8::encode_algorithm_identifier(params.algorithm);
    tbs.insert(tbs.end(), alg_id.begin(), alg_id.end());

    // issuer Name
    auto issuer = params.issuer.encode();
    tbs.insert(tbs.end(), issuer.begin(), issuer.end());

    // validity
    auto validity = encode_validity(params.not_before, params.not_after);
    tbs.insert(tbs.end(), validity.begin(), validity.end());

    // subject Name
    auto subject = params.subject.encode();
    tbs.insert(tbs.end(), subject.begin(), subject.end());

    // subjectPublicKeyInfo
    auto spki = pkcs8::encode_public_key_der(params.algorithm, params.public_key);
    tbs.insert(tbs.end(), spki.begin(), spki.end());

    // extensions [3] EXPLICIT (v3 only)
    std::vector<std::vector<uint8_t>> extensions;

    if (params.include_key_usage) {
        extensions.push_back(encode_basic_constraints(params.is_ca));

        if (params.is_ca) {
            extensions.push_back(
                encode_key_usage(true, true, true));  // CA: sign + certSign + crlSign
        } else {
            extensions.push_back(
                encode_key_usage(true, false, false));  // End-entity: digitalSignature
        }
    }

    if (!extensions.empty()) {
        auto exts = encode_extensions(extensions);
        tbs.insert(tbs.end(), exts.begin(), exts.end());
    }

    return asn1::encode_sequence(tbs);
}

/**
 * Build a complete X.509 certificate (DER)
 *
 * @param params Certificate parameters
 * @param sign_fn Callback that signs the TBSCertificate bytes
 * @return DER-encoded certificate
 */
inline std::vector<uint8_t> build_certificate_der(
    const CertificateParams& params,
    const SignCallback& sign_fn) {

    // Build TBSCertificate
    auto tbs_der = build_tbs_certificate(params);

    // Sign TBSCertificate
    auto signature = sign_fn(tbs_der);

    // Build Certificate
    auto alg_id = pkcs8::encode_algorithm_identifier(params.algorithm);
    auto sig_bits = asn1::encode_bit_string(signature);

    auto cert_content = asn1::concat({tbs_der, alg_id, sig_bits});
    return asn1::encode_sequence(cert_content);
}

/**
 * Build a complete X.509 certificate (PEM)
 */
inline std::string build_certificate_pem(
    const CertificateParams& params,
    const SignCallback& sign_fn) {

    auto der = build_certificate_der(params, sign_fn);
    return pem::encode(der, "CERTIFICATE");
}

// ============================================================================
// Self-Signed Certificate Helpers
// ============================================================================

/**
 * Create a self-signed certificate (DER)
 *
 * @param alg Algorithm identifier
 * @param subject Distinguished Name for both issuer and subject
 * @param public_key Raw public key bytes
 * @param private_key Raw private key bytes (used for signing)
 * @param sign_fn Function that signs data with the private key
 * @param validity_days Number of days the certificate is valid
 * @return DER-encoded self-signed certificate
 */
inline std::vector<uint8_t> create_self_signed_der(
    pkcs8::Algorithm alg,
    const DistinguishedName& subject,
    const std::vector<uint8_t>& public_key,
    const SignCallback& sign_fn,
    int validity_days = 365) {

    auto now = std::chrono::system_clock::now();
    auto expiry = now + std::chrono::hours(24 * validity_days);

    CertificateParams params;
    params.algorithm = alg;
    params.issuer = subject;     // Self-signed: issuer == subject
    params.subject = subject;
    params.not_before = now;
    params.not_after = expiry;
    params.public_key = public_key;
    params.is_ca = true;         // Self-signed certs are typically CA

    return build_certificate_der(params, sign_fn);
}

/**
 * Create a self-signed certificate (PEM)
 */
inline std::string create_self_signed_pem(
    pkcs8::Algorithm alg,
    const DistinguishedName& subject,
    const std::vector<uint8_t>& public_key,
    const SignCallback& sign_fn,
    int validity_days = 365) {

    auto der = create_self_signed_der(alg, subject, public_key, sign_fn, validity_days);
    return pem::encode(der, "CERTIFICATE");
}

// ============================================================================
// Certificate Parsing
// ============================================================================

/**
 * Parsed certificate information
 */
struct Certificate {
    std::vector<uint8_t> tbs_certificate;       // Raw TBSCertificate DER
    pkcs8::Algorithm signature_algorithm;
    std::vector<uint8_t> signature_value;
    std::vector<uint8_t> serial_number;
    std::vector<uint8_t> subject_public_key;     // Raw public key
    pkcs8::Algorithm public_key_algorithm;
    std::vector<uint8_t> full_der;               // Complete certificate DER
};

/**
 * Parse a DER-encoded X.509 certificate
 * Extracts the essential fields for verification
 */
inline std::optional<Certificate> parse_certificate_der(const std::vector<uint8_t>& der) {
    // Parse outer SEQUENCE (Certificate)
    auto cert_seq = asn1::decode_tlv(der.data(), der.size());
    if (!cert_seq || cert_seq->tag != asn1::Tag::SEQUENCE) {
        return std::nullopt;
    }

    const uint8_t* ptr = cert_seq->value.data();
    size_t remaining = cert_seq->value.size();

    Certificate cert;
    cert.full_der = der;

    // Parse TBSCertificate SEQUENCE
    auto tbs = asn1::decode_tlv(ptr, remaining);
    if (!tbs || tbs->tag != asn1::Tag::SEQUENCE) {
        return std::nullopt;
    }
    // Store the complete TBS DER (including tag + length)
    cert.tbs_certificate.assign(ptr, ptr + tbs->total_length);
    ptr += tbs->total_length;
    remaining -= tbs->total_length;

    // Parse signatureAlgorithm
    auto sig_alg = asn1::decode_tlv(ptr, remaining);
    if (!sig_alg || sig_alg->tag != asn1::Tag::SEQUENCE) {
        return std::nullopt;
    }
    // Extract OID
    auto sig_oid = asn1::decode_tlv(sig_alg->value.data(), sig_alg->value.size());
    if (!sig_oid || sig_oid->tag != asn1::Tag::OBJECT_IDENTIFIER) {
        return std::nullopt;
    }
    auto sig_oid_str = asn1::decode_oid(sig_oid->value);
    if (!sig_oid_str) {
        return std::nullopt;
    }
    auto sig_algo = pkcs8::algorithm_from_oid(*sig_oid_str);
    if (!sig_algo) {
        return std::nullopt;
    }
    cert.signature_algorithm = *sig_algo;
    ptr += sig_alg->total_length;
    remaining -= sig_alg->total_length;

    // Parse signatureValue BIT STRING
    auto sig_val = asn1::decode_tlv(ptr, remaining);
    if (!sig_val || sig_val->tag != asn1::Tag::BIT_STRING) {
        return std::nullopt;
    }
    auto sig_data = asn1::decode_bit_string(sig_val->value);
    if (!sig_data) {
        return std::nullopt;
    }
    cert.signature_value = *sig_data;

    // Now parse inside TBSCertificate to extract key fields
    const uint8_t* tbs_ptr = tbs->value.data();
    size_t tbs_remaining = tbs->value.size();

    // version [0] EXPLICIT - skip if present
    if (tbs_remaining > 0 && (tbs_ptr[0] & 0xE0) == 0xA0) {
        auto ver_tag = asn1::decode_tlv(tbs_ptr, tbs_remaining);
        if (ver_tag) {
            tbs_ptr += ver_tag->total_length;
            tbs_remaining -= ver_tag->total_length;
        }
    }

    // serialNumber
    auto serial = asn1::decode_tlv(tbs_ptr, tbs_remaining);
    if (!serial || serial->tag != asn1::Tag::INTEGER) {
        return std::nullopt;
    }
    cert.serial_number = serial->value;
    tbs_ptr += serial->total_length;
    tbs_remaining -= serial->total_length;

    // signature AlgorithmIdentifier - skip
    auto inner_alg = asn1::decode_tlv(tbs_ptr, tbs_remaining);
    if (!inner_alg) return std::nullopt;
    tbs_ptr += inner_alg->total_length;
    tbs_remaining -= inner_alg->total_length;

    // issuer Name - skip
    auto issuer = asn1::decode_tlv(tbs_ptr, tbs_remaining);
    if (!issuer) return std::nullopt;
    tbs_ptr += issuer->total_length;
    tbs_remaining -= issuer->total_length;

    // validity - skip
    auto validity = asn1::decode_tlv(tbs_ptr, tbs_remaining);
    if (!validity) return std::nullopt;
    tbs_ptr += validity->total_length;
    tbs_remaining -= validity->total_length;

    // subject Name - skip
    auto subject = asn1::decode_tlv(tbs_ptr, tbs_remaining);
    if (!subject) return std::nullopt;
    tbs_ptr += subject->total_length;
    tbs_remaining -= subject->total_length;

    // subjectPublicKeyInfo
    auto spki = asn1::decode_tlv(tbs_ptr, tbs_remaining);
    if (!spki || spki->tag != asn1::Tag::SEQUENCE) {
        return std::nullopt;
    }

    // Parse SPKI to get algorithm and key
    auto spki_alg = asn1::decode_tlv(spki->value.data(), spki->value.size());
    if (!spki_alg || spki_alg->tag != asn1::Tag::SEQUENCE) {
        return std::nullopt;
    }
    auto pk_oid = asn1::decode_tlv(spki_alg->value.data(), spki_alg->value.size());
    if (!pk_oid || pk_oid->tag != asn1::Tag::OBJECT_IDENTIFIER) {
        return std::nullopt;
    }
    auto pk_oid_str = asn1::decode_oid(pk_oid->value);
    if (!pk_oid_str) return std::nullopt;
    auto pk_algo = pkcs8::algorithm_from_oid(*pk_oid_str);
    if (!pk_algo) return std::nullopt;
    cert.public_key_algorithm = *pk_algo;

    // Extract public key from BIT STRING
    size_t pk_offset = spki_alg->total_length;
    auto pk_bits = asn1::decode_tlv(
        spki->value.data() + pk_offset,
        spki->value.size() - pk_offset);
    if (!pk_bits || pk_bits->tag != asn1::Tag::BIT_STRING) {
        return std::nullopt;
    }
    auto pk_data = asn1::decode_bit_string(pk_bits->value);
    if (!pk_data) return std::nullopt;
    cert.subject_public_key = *pk_data;

    return cert;
}

/**
 * Parse a PEM-encoded certificate
 */
inline std::optional<Certificate> parse_certificate_pem(const std::string& pem_data) {
    auto der = pem::decode(pem_data, "CERTIFICATE");
    if (!der) {
        return std::nullopt;
    }
    return parse_certificate_der(*der);
}

/**
 * Verify a certificate's signature using a verification callback
 *
 * @param cert Parsed certificate
 * @param verify_fn Callback: (public_key, tbs_data, signature) -> bool
 * @return true if signature is valid
 */
inline bool verify_certificate(
    const Certificate& cert,
    const VerifyCallback& verify_fn) {

    return verify_fn(cert.subject_public_key, cert.tbs_certificate, cert.signature_value);
}

/**
 * Verify a self-signed certificate (uses its own public key)
 */
inline bool verify_self_signed(
    const Certificate& cert,
    const VerifyCallback& verify_fn) {

    return verify_certificate(cert, verify_fn);
}

} // namespace x509

#endif // COMMON_X509_HPP
