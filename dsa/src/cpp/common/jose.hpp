/**
 * JOSE (JSON Object Signing and Encryption) Support for PQC
 *
 * Implements JWS (JSON Web Signature) with post-quantum algorithms.
 * Based on:
 * - RFC 7515: JSON Web Signature (JWS)
 * - RFC 7519: JSON Web Token (JWT)
 * - draft-ietf-cose-dilithium: ML-DSA for JOSE/COSE
 * - draft-ietf-cose-sphincs-plus: SLH-DSA for JOSE/COSE
 *
 * Supported algorithms:
 * - ML-DSA-44, ML-DSA-65, ML-DSA-87 (FIPS 204)
 * - SLH-DSA variants (FIPS 205)
 *
 * Usage:
 *   // Create and sign a JWT
 *   jose::JWSBuilder builder;
 *   builder.set_algorithm("ML-DSA-65")
 *          .set_payload(R"({"sub":"user","exp":1234567890})")
 *          .set_secret_key(sk);
 *   std::string jwt = builder.build();
 *
 *   // Verify a JWT
 *   jose::JWSVerifier verifier(jwt);
 *   bool valid = verifier.verify(pk);
 */

#ifndef COMMON_JOSE_HPP
#define COMMON_JOSE_HPP

#include <algorithm>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include "algorithm_factory.hpp"

namespace jose {

// ============================================================================
// Base64url Encoding (RFC 4648 Section 5)
// ============================================================================

namespace detail {

// Base64url alphabet (URL and filename safe)
inline constexpr char BASE64URL_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Encode binary data to Base64url (no padding)
 */
inline std::string base64url_encode(const std::vector<uint8_t>& data) {
    std::string result;
    result.reserve(((data.size() + 2) / 3) * 4);

    size_t i = 0;
    while (i + 2 < data.size()) {
        uint32_t triple = (static_cast<uint32_t>(data[i]) << 16) |
                         (static_cast<uint32_t>(data[i + 1]) << 8) |
                         static_cast<uint32_t>(data[i + 2]);

        result += BASE64URL_TABLE[(triple >> 18) & 0x3F];
        result += BASE64URL_TABLE[(triple >> 12) & 0x3F];
        result += BASE64URL_TABLE[(triple >> 6) & 0x3F];
        result += BASE64URL_TABLE[triple & 0x3F];

        i += 3;
    }

    // Handle remaining bytes (no padding in base64url)
    if (i + 1 == data.size()) {
        uint32_t val = static_cast<uint32_t>(data[i]) << 16;
        result += BASE64URL_TABLE[(val >> 18) & 0x3F];
        result += BASE64URL_TABLE[(val >> 12) & 0x3F];
    } else if (i + 2 == data.size()) {
        uint32_t val = (static_cast<uint32_t>(data[i]) << 16) |
                      (static_cast<uint32_t>(data[i + 1]) << 8);
        result += BASE64URL_TABLE[(val >> 18) & 0x3F];
        result += BASE64URL_TABLE[(val >> 12) & 0x3F];
        result += BASE64URL_TABLE[(val >> 6) & 0x3F];
    }

    return result;
}

/**
 * Encode string to Base64url
 */
inline std::string base64url_encode(const std::string& str) {
    std::vector<uint8_t> data(str.begin(), str.end());
    return base64url_encode(data);
}

/**
 * Decode Base64url to binary data
 */
inline std::optional<std::vector<uint8_t>> base64url_decode(const std::string& encoded) {
    // Build decode table
    int8_t decode_table[256];
    std::fill(decode_table, decode_table + 256, -1);
    for (int i = 0; i < 64; ++i) {
        decode_table[static_cast<uint8_t>(BASE64URL_TABLE[i])] = static_cast<int8_t>(i);
    }

    std::vector<uint8_t> result;
    result.reserve((encoded.size() * 3) / 4);

    uint32_t buffer = 0;
    int bits_collected = 0;

    for (char c : encoded) {
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
            continue;  // Skip whitespace
        }

        // Skip padding if present (shouldn't be in base64url, but handle gracefully)
        if (c == '=') {
            continue;
        }

        int8_t val = decode_table[static_cast<uint8_t>(c)];
        if (val < 0) {
            return std::nullopt;  // Invalid character
        }

        buffer = (buffer << 6) | static_cast<uint32_t>(val);
        bits_collected += 6;

        if (bits_collected >= 8) {
            bits_collected -= 8;
            result.push_back(static_cast<uint8_t>((buffer >> bits_collected) & 0xFF));
        }
    }

    return result;
}

/**
 * Decode Base64url to string
 */
inline std::optional<std::string> base64url_decode_string(const std::string& encoded) {
    auto decoded = base64url_decode(encoded);
    if (!decoded) return std::nullopt;
    return std::string(decoded->begin(), decoded->end());
}

} // namespace detail

// ============================================================================
// Algorithm Mapping
// ============================================================================

/**
 * JOSE Algorithm identifiers for PQC
 * Based on draft-ietf-cose-dilithium and draft-ietf-cose-sphincs-plus
 */
struct JOSEAlgorithm {
    std::string jose_name;      // JOSE "alg" value
    std::string internal_name;  // Internal algorithm name (e.g., "ML-DSA-65")
    int security_level;         // NIST security level (1-5)
    std::string standard;       // FIPS standard
};

/**
 * Get all supported JOSE algorithms
 */
inline const std::vector<JOSEAlgorithm>& supported_algorithms() {
    static const std::vector<JOSEAlgorithm> algorithms = {
        // ML-DSA (FIPS 204) - proposed JOSE identifiers
        {"ML-DSA-44", "ML-DSA-44", 2, "FIPS 204"},
        {"ML-DSA-65", "ML-DSA-65", 3, "FIPS 204"},
        {"ML-DSA-87", "ML-DSA-87", 5, "FIPS 204"},

        // SLH-DSA SHA2 variants (FIPS 205)
        {"SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128s", 1, "FIPS 205"},
        {"SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128f", 1, "FIPS 205"},
        {"SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192s", 3, "FIPS 205"},
        {"SLH-DSA-SHA2-192f", "SLH-DSA-SHA2-192f", 3, "FIPS 205"},
        {"SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256s", 5, "FIPS 205"},
        {"SLH-DSA-SHA2-256f", "SLH-DSA-SHA2-256f", 5, "FIPS 205"},

        // SLH-DSA SHAKE variants (FIPS 205)
        {"SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128s", 1, "FIPS 205"},
        {"SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-128f", 1, "FIPS 205"},
        {"SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192s", 3, "FIPS 205"},
        {"SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-192f", 3, "FIPS 205"},
        {"SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256s", 5, "FIPS 205"},
        {"SLH-DSA-SHAKE-256f", "SLH-DSA-SHAKE-256f", 5, "FIPS 205"},
    };
    return algorithms;
}

/**
 * Check if a JOSE algorithm is supported
 */
inline bool is_supported_algorithm(const std::string& alg) {
    for (const auto& a : supported_algorithms()) {
        if (a.jose_name == alg) return true;
    }
    return false;
}

/**
 * Get internal algorithm name from JOSE algorithm
 */
inline std::optional<std::string> get_internal_algorithm(const std::string& jose_alg) {
    for (const auto& a : supported_algorithms()) {
        if (a.jose_name == jose_alg) return a.internal_name;
    }
    return std::nullopt;
}

/**
 * Get JOSE algorithm from internal algorithm name
 */
inline std::optional<std::string> get_jose_algorithm(const std::string& internal_name) {
    for (const auto& a : supported_algorithms()) {
        if (a.internal_name == internal_name) return a.jose_name;
    }
    return std::nullopt;
}

// ============================================================================
// Simple JSON Utilities (minimal implementation for JOSE)
// ============================================================================

namespace json {

/**
 * Escape a string for JSON
 */
inline std::string escape(const std::string& s) {
    std::string result;
    result.reserve(s.size() + 10);
    for (char c : s) {
        switch (c) {
            case '"':  result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    result += buf;
                } else {
                    result += c;
                }
        }
    }
    return result;
}

/**
 * Build a simple JSON object from string key-value pairs
 */
inline std::string build_object(const std::map<std::string, std::string>& values) {
    std::string result = "{";
    bool first = true;
    for (const auto& [key, value] : values) {
        if (!first) result += ",";
        first = false;
        result += "\"" + escape(key) + "\":\"" + escape(value) + "\"";
    }
    result += "}";
    return result;
}

/**
 * Extract a string value from a simple JSON object
 * (minimal parser, only handles simple cases)
 */
inline std::optional<std::string> extract_string(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\"";
    size_t key_pos = json.find(search);
    if (key_pos == std::string::npos) return std::nullopt;

    size_t colon_pos = json.find(':', key_pos + search.size());
    if (colon_pos == std::string::npos) return std::nullopt;

    // Skip whitespace
    size_t value_start = colon_pos + 1;
    while (value_start < json.size() &&
           (json[value_start] == ' ' || json[value_start] == '\t' ||
            json[value_start] == '\n' || json[value_start] == '\r')) {
        value_start++;
    }

    if (value_start >= json.size() || json[value_start] != '"') {
        return std::nullopt;
    }

    // Find end of string value
    size_t value_end = value_start + 1;
    while (value_end < json.size()) {
        if (json[value_end] == '"' && json[value_end - 1] != '\\') {
            break;
        }
        value_end++;
    }

    if (value_end >= json.size()) return std::nullopt;

    return json.substr(value_start + 1, value_end - value_start - 1);
}

} // namespace json

// ============================================================================
// JWS Header
// ============================================================================

/**
 * JWS JOSE Header
 */
struct JWSHeader {
    std::string alg;     // Algorithm (required)
    std::string typ;     // Type (optional, typically "JWT")
    std::string kid;     // Key ID (optional)
    std::string jku;     // JWK Set URL (optional)
    std::string x5u;     // X.509 URL (optional)
    std::string cty;     // Content type (optional)

    /**
     * Serialize header to JSON
     */
    [[nodiscard]] std::string to_json() const {
        std::map<std::string, std::string> values;
        values["alg"] = alg;
        if (!typ.empty()) values["typ"] = typ;
        if (!kid.empty()) values["kid"] = kid;
        if (!jku.empty()) values["jku"] = jku;
        if (!x5u.empty()) values["x5u"] = x5u;
        if (!cty.empty()) values["cty"] = cty;
        return json::build_object(values);
    }

    /**
     * Parse header from JSON
     */
    static std::optional<JWSHeader> from_json(const std::string& json_str) {
        auto alg = json::extract_string(json_str, "alg");
        if (!alg) return std::nullopt;

        JWSHeader header;
        header.alg = *alg;
        if (auto typ = json::extract_string(json_str, "typ")) header.typ = *typ;
        if (auto kid = json::extract_string(json_str, "kid")) header.kid = *kid;
        if (auto jku = json::extract_string(json_str, "jku")) header.jku = *jku;
        if (auto x5u = json::extract_string(json_str, "x5u")) header.x5u = *x5u;
        if (auto cty = json::extract_string(json_str, "cty")) header.cty = *cty;
        return header;
    }
};

// ============================================================================
// JWS (JSON Web Signature)
// ============================================================================

/**
 * Parsed JWS structure
 */
struct JWS {
    JWSHeader header;
    std::string payload;      // Raw payload (JSON string)
    std::vector<uint8_t> signature;

    // Original parts for verification
    std::string header_b64;
    std::string payload_b64;
    std::string signature_b64;
};

/**
 * Parse a JWS compact serialization
 *
 * Format: BASE64URL(header).BASE64URL(payload).BASE64URL(signature)
 */
inline std::optional<JWS> parse_jws(const std::string& token) {
    // Split by dots
    size_t first_dot = token.find('.');
    if (first_dot == std::string::npos) return std::nullopt;

    size_t second_dot = token.find('.', first_dot + 1);
    if (second_dot == std::string::npos) return std::nullopt;

    // Ensure no more dots
    if (token.find('.', second_dot + 1) != std::string::npos) {
        return std::nullopt;
    }

    JWS jws;
    jws.header_b64 = token.substr(0, first_dot);
    jws.payload_b64 = token.substr(first_dot + 1, second_dot - first_dot - 1);
    jws.signature_b64 = token.substr(second_dot + 1);

    // Decode header
    auto header_json = detail::base64url_decode_string(jws.header_b64);
    if (!header_json) return std::nullopt;

    auto header = JWSHeader::from_json(*header_json);
    if (!header) return std::nullopt;
    jws.header = *header;

    // Decode payload
    auto payload = detail::base64url_decode_string(jws.payload_b64);
    if (!payload) return std::nullopt;
    jws.payload = *payload;

    // Decode signature
    auto sig = detail::base64url_decode(jws.signature_b64);
    if (!sig) return std::nullopt;
    jws.signature = *sig;

    return jws;
}

// ============================================================================
// JWS Builder
// ============================================================================

/**
 * Builder for creating JWS tokens
 *
 * Usage:
 *   auto [pk, sk] = pqc::create_dsa("ML-DSA-65")->keygen();
 *
 *   jose::JWSBuilder builder;
 *   std::string jwt = builder
 *       .set_algorithm("ML-DSA-65")
 *       .set_type("JWT")
 *       .set_payload(R"({"sub":"user","iat":1234567890})")
 *       .sign(sk);
 */
class JWSBuilder {
public:
    JWSBuilder() = default;

    /**
     * Set the signing algorithm
     */
    JWSBuilder& set_algorithm(const std::string& alg) {
        header_.alg = alg;
        return *this;
    }

    /**
     * Set token type (typically "JWT")
     */
    JWSBuilder& set_type(const std::string& typ) {
        header_.typ = typ;
        return *this;
    }

    /**
     * Set key ID
     */
    JWSBuilder& set_key_id(const std::string& kid) {
        header_.kid = kid;
        return *this;
    }

    /**
     * Set the payload (JSON string)
     */
    JWSBuilder& set_payload(const std::string& payload) {
        payload_ = payload;
        return *this;
    }

    /**
     * Set the payload from a claims map
     */
    JWSBuilder& set_claims(const std::map<std::string, std::string>& claims) {
        payload_ = json::build_object(claims);
        return *this;
    }

    /**
     * Add a context string (ML-DSA context parameter)
     */
    JWSBuilder& set_context(std::span<const uint8_t> ctx) {
        context_.assign(ctx.begin(), ctx.end());
        return *this;
    }

    /**
     * Sign and build the JWS token
     *
     * @param secret_key The secret key for signing
     * @return JWS compact serialization (header.payload.signature)
     * @throws std::runtime_error if algorithm not supported or signing fails
     */
    [[nodiscard]] std::string sign(std::span<const uint8_t> secret_key) const {
        if (header_.alg.empty()) {
            throw std::runtime_error("Algorithm not set");
        }

        auto internal_alg = get_internal_algorithm(header_.alg);
        if (!internal_alg) {
            throw std::runtime_error("Unsupported algorithm: " + header_.alg);
        }

        // Create signer
        auto dsa = pqc::create_dsa(*internal_alg);

        // Encode header and payload
        std::string header_b64 = detail::base64url_encode(header_.to_json());
        std::string payload_b64 = detail::base64url_encode(payload_);

        // Signing input: ASCII(BASE64URL(header) || '.' || BASE64URL(payload))
        std::string signing_input = header_b64 + "." + payload_b64;
        std::vector<uint8_t> message(signing_input.begin(), signing_input.end());

        // Sign
        auto signature = dsa->sign(secret_key, message, context_);

        // Encode signature
        std::string signature_b64 = detail::base64url_encode(signature);

        return header_b64 + "." + payload_b64 + "." + signature_b64;
    }

private:
    JWSHeader header_;
    std::string payload_;
    std::vector<uint8_t> context_;
};

// ============================================================================
// JWS Verifier
// ============================================================================

/**
 * Verifier for JWS tokens
 *
 * Usage:
 *   jose::JWSVerifier verifier(jwt_string);
 *   if (verifier.verify(public_key)) {
 *       auto payload = verifier.payload();
 *       // Use payload...
 *   }
 */
class JWSVerifier {
public:
    /**
     * Parse a JWS token for verification
     *
     * @param token JWS compact serialization
     * @throws std::runtime_error if token is malformed
     */
    explicit JWSVerifier(const std::string& token)
        : token_(token) {
        auto jws = parse_jws(token);
        if (!jws) {
            throw std::runtime_error("Malformed JWS token");
        }
        jws_ = *jws;
    }

    /**
     * Get the algorithm from the header
     */
    [[nodiscard]] std::string algorithm() const {
        return jws_.header.alg;
    }

    /**
     * Get the token type from the header
     */
    [[nodiscard]] std::string type() const {
        return jws_.header.typ;
    }

    /**
     * Get the key ID from the header
     */
    [[nodiscard]] std::string key_id() const {
        return jws_.header.kid;
    }

    /**
     * Get the payload (only valid after verification)
     */
    [[nodiscard]] const std::string& payload() const {
        return jws_.payload;
    }

    /**
     * Get the raw header
     */
    [[nodiscard]] const JWSHeader& header() const {
        return jws_.header;
    }

    /**
     * Verify the signature
     *
     * @param public_key The public key for verification
     * @param ctx Optional context string for ML-DSA
     * @return true if signature is valid
     * @throws std::runtime_error if algorithm not supported
     */
    [[nodiscard]] bool verify(std::span<const uint8_t> public_key,
                              std::span<const uint8_t> ctx = {}) const {
        auto internal_alg = get_internal_algorithm(jws_.header.alg);
        if (!internal_alg) {
            throw std::runtime_error("Unsupported algorithm: " + jws_.header.alg);
        }

        // Create verifier
        auto dsa = pqc::create_dsa(*internal_alg);

        // Reconstruct signing input
        std::string signing_input = jws_.header_b64 + "." + jws_.payload_b64;
        std::vector<uint8_t> message(signing_input.begin(), signing_input.end());

        // Verify
        return dsa->verify(public_key, message, jws_.signature, ctx);
    }

    /**
     * Extract a string claim from the payload
     */
    [[nodiscard]] std::optional<std::string> claim(const std::string& name) const {
        return json::extract_string(jws_.payload, name);
    }

private:
    std::string token_;
    JWS jws_;
};

// ============================================================================
// Convenience Functions
// ============================================================================

/**
 * Create and sign a JWT
 *
 * @param algorithm JOSE algorithm name (e.g., "ML-DSA-65")
 * @param payload JSON payload string
 * @param secret_key Secret key for signing
 * @param ctx Optional context string
 * @return JWS compact serialization
 */
inline std::string create_jwt(
    const std::string& algorithm,
    const std::string& payload,
    std::span<const uint8_t> secret_key,
    std::span<const uint8_t> ctx = {}) {

    JWSBuilder builder;
    builder.set_algorithm(algorithm)
           .set_type("JWT")
           .set_payload(payload);

    if (!ctx.empty()) {
        builder.set_context(ctx);
    }

    return builder.sign(secret_key);
}

/**
 * Verify a JWT and return the payload if valid
 *
 * @param token JWS compact serialization
 * @param public_key Public key for verification
 * @param ctx Optional context string
 * @return Payload if valid, nullopt otherwise
 */
inline std::optional<std::string> verify_jwt(
    const std::string& token,
    std::span<const uint8_t> public_key,
    std::span<const uint8_t> ctx = {}) {

    try {
        JWSVerifier verifier(token);
        if (verifier.verify(public_key, ctx)) {
            return verifier.payload();
        }
    } catch (...) {
        // Invalid token
    }
    return std::nullopt;
}

/**
 * Get algorithm list for display
 */
inline std::vector<std::string> available_algorithms() {
    std::vector<std::string> result;
    for (const auto& a : supported_algorithms()) {
        result.push_back(a.jose_name);
    }
    return result;
}

} // namespace jose

#endif // COMMON_JOSE_HPP
