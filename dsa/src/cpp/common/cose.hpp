/**
 * COSE (CBOR Object Signing and Encryption) Support for PQC
 *
 * Implements COSE_Sign1 with post-quantum algorithms.
 * Based on:
 * - RFC 9052: CBOR Object Signing and Encryption (COSE): Structures and Process
 * - RFC 9053: CBOR Object Signing and Encryption (COSE): Initial Algorithms
 * - draft-ietf-cose-dilithium: ML-DSA for COSE
 * - draft-ietf-cose-sphincs-plus: SLH-DSA for COSE
 *
 * Supported algorithms (proposed COSE algorithm IDs):
 * - ML-DSA-44: -48
 * - ML-DSA-65: -49
 * - ML-DSA-87: -50
 * - SLH-DSA variants: -51 to -62
 *
 * Usage:
 *   // Create COSE_Sign1
 *   auto signed_msg = cose::sign1("ML-DSA-65", payload, sk);
 *
 *   // Verify COSE_Sign1
 *   auto payload = cose::verify1(signed_msg, pk);
 */

#ifndef COMMON_COSE_HPP
#define COMMON_COSE_HPP

#include <algorithm>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include "algorithm_factory.hpp"

namespace cose {

// ============================================================================
// COSE Algorithm IDs (Proposed for PQC)
// ============================================================================

/**
 * Proposed COSE algorithm identifiers for PQC
 * Based on draft-ietf-cose-dilithium and draft-ietf-cose-sphincs-plus
 *
 * Note: These are proposed values and may change before standardization
 */
enum class Algorithm : int32_t {
    // ML-DSA (FIPS 204) - proposed
    ML_DSA_44 = -48,
    ML_DSA_65 = -49,
    ML_DSA_87 = -50,

    // SLH-DSA SHA2 (FIPS 205) - proposed
    SLH_DSA_SHA2_128s = -51,
    SLH_DSA_SHA2_128f = -52,
    SLH_DSA_SHA2_192s = -53,
    SLH_DSA_SHA2_192f = -54,
    SLH_DSA_SHA2_256s = -55,
    SLH_DSA_SHA2_256f = -56,

    // SLH-DSA SHAKE (FIPS 205) - proposed
    SLH_DSA_SHAKE_128s = -57,
    SLH_DSA_SHAKE_128f = -58,
    SLH_DSA_SHAKE_192s = -59,
    SLH_DSA_SHAKE_192f = -60,
    SLH_DSA_SHAKE_256s = -61,
    SLH_DSA_SHAKE_256f = -62,

    // Invalid/Unknown
    Unknown = 0
};

/**
 * Algorithm information
 */
struct AlgorithmInfo {
    Algorithm id;
    std::string name;           // COSE name
    std::string internal_name;  // Internal algorithm name
    int security_level;         // NIST security level
};

/**
 * Get algorithm info table
 */
inline const std::vector<AlgorithmInfo>& algorithm_table() {
    static const std::vector<AlgorithmInfo> table = {
        {Algorithm::ML_DSA_44, "ML-DSA-44", "ML-DSA-44", 2},
        {Algorithm::ML_DSA_65, "ML-DSA-65", "ML-DSA-65", 3},
        {Algorithm::ML_DSA_87, "ML-DSA-87", "ML-DSA-87", 5},

        {Algorithm::SLH_DSA_SHA2_128s, "SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128s", 1},
        {Algorithm::SLH_DSA_SHA2_128f, "SLH-DSA-SHA2-128f", "SLH-DSA-SHA2-128f", 1},
        {Algorithm::SLH_DSA_SHA2_192s, "SLH-DSA-SHA2-192s", "SLH-DSA-SHA2-192s", 3},
        {Algorithm::SLH_DSA_SHA2_192f, "SLH-DSA-SHA2-192f", "SLH-DSA-SHA2-192f", 3},
        {Algorithm::SLH_DSA_SHA2_256s, "SLH-DSA-SHA2-256s", "SLH-DSA-SHA2-256s", 5},
        {Algorithm::SLH_DSA_SHA2_256f, "SLH-DSA-SHA2-256f", "SLH-DSA-SHA2-256f", 5},

        {Algorithm::SLH_DSA_SHAKE_128s, "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128s", 1},
        {Algorithm::SLH_DSA_SHAKE_128f, "SLH-DSA-SHAKE-128f", "SLH-DSA-SHAKE-128f", 1},
        {Algorithm::SLH_DSA_SHAKE_192s, "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192s", 3},
        {Algorithm::SLH_DSA_SHAKE_192f, "SLH-DSA-SHAKE-192f", "SLH-DSA-SHAKE-192f", 3},
        {Algorithm::SLH_DSA_SHAKE_256s, "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256s", 5},
        {Algorithm::SLH_DSA_SHAKE_256f, "SLH-DSA-SHAKE-256f", "SLH-DSA-SHAKE-256f", 5},
    };
    return table;
}

/**
 * Get algorithm by name
 */
inline std::optional<Algorithm> algorithm_from_name(const std::string& name) {
    for (const auto& info : algorithm_table()) {
        if (info.name == name || info.internal_name == name) {
            return info.id;
        }
    }
    return std::nullopt;
}

/**
 * Get algorithm by ID
 */
inline std::optional<AlgorithmInfo> algorithm_info(Algorithm alg) {
    for (const auto& info : algorithm_table()) {
        if (info.id == alg) {
            return info;
        }
    }
    return std::nullopt;
}

/**
 * Get algorithm by numeric ID
 */
inline std::optional<AlgorithmInfo> algorithm_info(int32_t id) {
    return algorithm_info(static_cast<Algorithm>(id));
}

/**
 * Get internal algorithm name from COSE algorithm
 */
inline std::optional<std::string> get_internal_name(Algorithm alg) {
    auto info = algorithm_info(alg);
    if (info) return info->internal_name;
    return std::nullopt;
}

// ============================================================================
// CBOR Encoding Utilities
// ============================================================================

namespace cbor {

/**
 * CBOR major types
 */
enum class MajorType : uint8_t {
    UnsignedInt = 0,  // 0-23: immediate, 24: 1 byte, 25: 2 bytes, 26: 4 bytes, 27: 8 bytes
    NegativeInt = 1,  // Same encoding as unsigned, value is -1 - n
    ByteString = 2,   // Length-prefixed byte string
    TextString = 3,   // Length-prefixed UTF-8 string
    Array = 4,        // Length-prefixed array
    Map = 5,          // Length-prefixed map (key-value pairs)
    Tag = 6,          // Semantic tag
    Special = 7       // Simple values, floats, break
};

/**
 * Encode a CBOR header (major type + argument)
 */
inline void encode_header(std::vector<uint8_t>& out, MajorType type, uint64_t value) {
    uint8_t mt = static_cast<uint8_t>(type) << 5;

    if (value <= 23) {
        out.push_back(mt | static_cast<uint8_t>(value));
    } else if (value <= 0xFF) {
        out.push_back(mt | 24);
        out.push_back(static_cast<uint8_t>(value));
    } else if (value <= 0xFFFF) {
        out.push_back(mt | 25);
        out.push_back(static_cast<uint8_t>(value >> 8));
        out.push_back(static_cast<uint8_t>(value));
    } else if (value <= 0xFFFFFFFF) {
        out.push_back(mt | 26);
        out.push_back(static_cast<uint8_t>(value >> 24));
        out.push_back(static_cast<uint8_t>(value >> 16));
        out.push_back(static_cast<uint8_t>(value >> 8));
        out.push_back(static_cast<uint8_t>(value));
    } else {
        out.push_back(mt | 27);
        for (int i = 7; i >= 0; --i) {
            out.push_back(static_cast<uint8_t>(value >> (i * 8)));
        }
    }
}

/**
 * Encode a positive integer
 */
inline void encode_uint(std::vector<uint8_t>& out, uint64_t value) {
    encode_header(out, MajorType::UnsignedInt, value);
}

/**
 * Encode a negative integer (-1 - n encoded as n)
 */
inline void encode_nint(std::vector<uint8_t>& out, int64_t value) {
    // Negative CBOR: encode -1 - value
    // So for -1, we encode 0. For -10, we encode 9.
    uint64_t n = static_cast<uint64_t>(-(value + 1));
    encode_header(out, MajorType::NegativeInt, n);
}

/**
 * Encode an integer (positive or negative)
 */
inline void encode_int(std::vector<uint8_t>& out, int64_t value) {
    if (value >= 0) {
        encode_uint(out, static_cast<uint64_t>(value));
    } else {
        encode_nint(out, value);
    }
}

/**
 * Encode a byte string
 */
inline void encode_bytes(std::vector<uint8_t>& out, std::span<const uint8_t> data) {
    encode_header(out, MajorType::ByteString, data.size());
    out.insert(out.end(), data.begin(), data.end());
}

/**
 * Encode a text string
 */
inline void encode_text(std::vector<uint8_t>& out, const std::string& text) {
    encode_header(out, MajorType::TextString, text.size());
    out.insert(out.end(), text.begin(), text.end());
}

/**
 * Encode array header (items follow)
 */
inline void encode_array_header(std::vector<uint8_t>& out, size_t count) {
    encode_header(out, MajorType::Array, count);
}

/**
 * Encode map header (key-value pairs follow)
 */
inline void encode_map_header(std::vector<uint8_t>& out, size_t count) {
    encode_header(out, MajorType::Map, count);
}

/**
 * Encode CBOR null
 */
inline void encode_null(std::vector<uint8_t>& out) {
    out.push_back(0xF6);  // Simple value 22 (null)
}

/**
 * Decode a CBOR header, returns (major_type, value, bytes_consumed)
 */
inline std::optional<std::tuple<MajorType, uint64_t, size_t>>
decode_header(std::span<const uint8_t> data) {
    if (data.empty()) return std::nullopt;

    uint8_t first = data[0];
    MajorType mt = static_cast<MajorType>(first >> 5);
    uint8_t ai = first & 0x1F;

    if (ai <= 23) {
        return std::make_tuple(mt, static_cast<uint64_t>(ai), 1);
    } else if (ai == 24) {
        if (data.size() < 2) return std::nullopt;
        return std::make_tuple(mt, static_cast<uint64_t>(data[1]), 2);
    } else if (ai == 25) {
        if (data.size() < 3) return std::nullopt;
        uint64_t val = (static_cast<uint64_t>(data[1]) << 8) | data[2];
        return std::make_tuple(mt, val, 3);
    } else if (ai == 26) {
        if (data.size() < 5) return std::nullopt;
        uint64_t val = (static_cast<uint64_t>(data[1]) << 24) |
                       (static_cast<uint64_t>(data[2]) << 16) |
                       (static_cast<uint64_t>(data[3]) << 8) |
                       data[4];
        return std::make_tuple(mt, val, 5);
    } else if (ai == 27) {
        if (data.size() < 9) return std::nullopt;
        uint64_t val = 0;
        for (int i = 0; i < 8; ++i) {
            val = (val << 8) | data[1 + i];
        }
        return std::make_tuple(mt, val, 9);
    }

    return std::nullopt;  // Indefinite length or reserved
}

/**
 * Decode an integer (positive or negative)
 */
inline std::optional<std::pair<int64_t, size_t>>
decode_int(std::span<const uint8_t> data) {
    auto hdr = decode_header(data);
    if (!hdr) return std::nullopt;

    auto [mt, val, len] = *hdr;

    if (mt == MajorType::UnsignedInt) {
        if (val > static_cast<uint64_t>(INT64_MAX)) return std::nullopt;
        return std::make_pair(static_cast<int64_t>(val), len);
    } else if (mt == MajorType::NegativeInt) {
        // Negative: -1 - val
        if (val > static_cast<uint64_t>(INT64_MAX)) return std::nullopt;
        return std::make_pair(-1 - static_cast<int64_t>(val), len);
    }

    return std::nullopt;
}

/**
 * Decode a byte string
 */
inline std::optional<std::pair<std::vector<uint8_t>, size_t>>
decode_bytes(std::span<const uint8_t> data) {
    auto hdr = decode_header(data);
    if (!hdr) return std::nullopt;

    auto [mt, len, hdr_len] = *hdr;
    if (mt != MajorType::ByteString) return std::nullopt;
    if (data.size() < hdr_len + len) return std::nullopt;

    std::vector<uint8_t> result(data.begin() + hdr_len, data.begin() + hdr_len + len);
    return std::make_pair(std::move(result), hdr_len + len);
}

/**
 * Decode an array header
 */
inline std::optional<std::pair<size_t, size_t>>
decode_array_header(std::span<const uint8_t> data) {
    auto hdr = decode_header(data);
    if (!hdr) return std::nullopt;

    auto [mt, count, len] = *hdr;
    if (mt != MajorType::Array) return std::nullopt;

    return std::make_pair(static_cast<size_t>(count), len);
}

/**
 * Decode a map header
 */
inline std::optional<std::pair<size_t, size_t>>
decode_map_header(std::span<const uint8_t> data) {
    auto hdr = decode_header(data);
    if (!hdr) return std::nullopt;

    auto [mt, count, len] = *hdr;
    if (mt != MajorType::Map) return std::nullopt;

    return std::make_pair(static_cast<size_t>(count), len);
}

/**
 * Check if next item is null
 */
inline bool is_null(std::span<const uint8_t> data) {
    return !data.empty() && data[0] == 0xF6;
}

/**
 * Skip a CBOR item and return bytes consumed
 */
inline std::optional<size_t> skip_item(std::span<const uint8_t> data) {
    if (data.empty()) return std::nullopt;

    auto hdr = decode_header(data);
    if (!hdr) return std::nullopt;

    auto [mt, val, hdr_len] = *hdr;

    switch (mt) {
        case MajorType::UnsignedInt:
        case MajorType::NegativeInt:
            return hdr_len;

        case MajorType::ByteString:
        case MajorType::TextString:
            return hdr_len + val;

        case MajorType::Array: {
            size_t total = hdr_len;
            for (size_t i = 0; i < val; ++i) {
                auto item_len = skip_item(data.subspan(total));
                if (!item_len) return std::nullopt;
                total += *item_len;
            }
            return total;
        }

        case MajorType::Map: {
            size_t total = hdr_len;
            for (size_t i = 0; i < val; ++i) {
                // Skip key
                auto key_len = skip_item(data.subspan(total));
                if (!key_len) return std::nullopt;
                total += *key_len;
                // Skip value
                auto val_len = skip_item(data.subspan(total));
                if (!val_len) return std::nullopt;
                total += *val_len;
            }
            return total;
        }

        case MajorType::Tag: {
            // Skip tag number, then skip tagged item
            auto item_len = skip_item(data.subspan(hdr_len));
            if (!item_len) return std::nullopt;
            return hdr_len + *item_len;
        }

        case MajorType::Special:
            // Simple values (including null, true, false)
            if (val <= 23 || val == 24) return hdr_len;
            // Floats
            if (val == 25) return hdr_len;  // Already included in hdr_len
            if (val == 26) return hdr_len;
            if (val == 27) return hdr_len;
            return std::nullopt;
    }

    return std::nullopt;
}

} // namespace cbor

// ============================================================================
// COSE_Sign1 Structure
// ============================================================================

/**
 * COSE_Sign1 structure
 *
 * COSE_Sign1 = [
 *     protected : bstr .cbor protected-header,
 *     unprotected : unprotected-header,
 *     payload : bstr / nil,
 *     signature : bstr
 * ]
 */
struct Sign1 {
    std::map<int, std::vector<uint8_t>> protected_header;   // Encoded as bstr
    std::map<int, std::vector<uint8_t>> unprotected_header; // Encoded inline
    std::optional<std::vector<uint8_t>> payload;            // nil if detached
    std::vector<uint8_t> signature;

    /**
     * Get algorithm from protected header
     */
    [[nodiscard]] std::optional<Algorithm> algorithm() const {
        auto it = protected_header.find(1);  // Label 1 = alg
        if (it == protected_header.end() || it->second.empty()) {
            return std::nullopt;
        }

        auto val = cbor::decode_int(it->second);
        if (!val) return std::nullopt;

        return static_cast<Algorithm>(val->first);
    }

    /**
     * Set algorithm in protected header
     */
    void set_algorithm(Algorithm alg) {
        std::vector<uint8_t> encoded;
        cbor::encode_int(encoded, static_cast<int64_t>(alg));
        protected_header[1] = std::move(encoded);
    }

    /**
     * Get key ID from unprotected header
     */
    [[nodiscard]] std::optional<std::vector<uint8_t>> key_id() const {
        auto it = unprotected_header.find(4);  // Label 4 = kid
        if (it == unprotected_header.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    /**
     * Set key ID in unprotected header
     */
    void set_key_id(std::span<const uint8_t> kid) {
        unprotected_header[4] = std::vector<uint8_t>(kid.begin(), kid.end());
    }
};

// ============================================================================
// COSE_Sign1 Encoding/Decoding
// ============================================================================

namespace detail {

/**
 * Encode protected header map to CBOR bytes
 */
inline std::vector<uint8_t> encode_protected_header(
    const std::map<int, std::vector<uint8_t>>& header) {

    if (header.empty()) {
        return {};  // Empty bstr
    }

    std::vector<uint8_t> map_data;
    cbor::encode_map_header(map_data, header.size());

    for (const auto& [key, value] : header) {
        cbor::encode_int(map_data, key);
        // Value is already CBOR-encoded
        map_data.insert(map_data.end(), value.begin(), value.end());
    }

    return map_data;
}

/**
 * Build Sig_structure for signing/verification
 *
 * Sig_structure = [
 *     context : "Signature1",
 *     body_protected : empty_or_serialized_map,
 *     external_aad : bstr,
 *     payload : bstr
 * ]
 */
inline std::vector<uint8_t> build_sig_structure(
    const std::vector<uint8_t>& protected_header,
    const std::vector<uint8_t>& external_aad,
    const std::vector<uint8_t>& payload) {

    std::vector<uint8_t> result;

    // Array of 4 items
    cbor::encode_array_header(result, 4);

    // Context: "Signature1"
    cbor::encode_text(result, "Signature1");

    // Protected header as bstr
    cbor::encode_bytes(result, protected_header);

    // External AAD
    cbor::encode_bytes(result, external_aad);

    // Payload
    cbor::encode_bytes(result, payload);

    return result;
}

} // namespace detail

/**
 * Encode COSE_Sign1 to CBOR
 */
inline std::vector<uint8_t> encode_sign1(const Sign1& msg) {
    std::vector<uint8_t> result;

    // Array of 4 items
    cbor::encode_array_header(result, 4);

    // Protected header (as bstr containing CBOR map)
    auto protected_bytes = detail::encode_protected_header(msg.protected_header);
    cbor::encode_bytes(result, protected_bytes);

    // Unprotected header (as CBOR map)
    cbor::encode_map_header(result, msg.unprotected_header.size());
    for (const auto& [key, value] : msg.unprotected_header) {
        cbor::encode_int(result, key);
        // For kid (label 4), encode as bstr
        if (key == 4) {
            cbor::encode_bytes(result, value);
        } else {
            result.insert(result.end(), value.begin(), value.end());
        }
    }

    // Payload (or null if detached)
    if (msg.payload) {
        cbor::encode_bytes(result, *msg.payload);
    } else {
        cbor::encode_null(result);
    }

    // Signature
    cbor::encode_bytes(result, msg.signature);

    return result;
}

/**
 * Decode COSE_Sign1 from CBOR
 */
inline std::optional<Sign1> decode_sign1(std::span<const uint8_t> data) {
    size_t pos = 0;

    // Expect array of 4 items
    auto arr = cbor::decode_array_header(data);
    if (!arr || arr->first != 4) return std::nullopt;
    pos += arr->second;

    Sign1 result;

    // Protected header (bstr containing CBOR map)
    auto protected_bstr = cbor::decode_bytes(data.subspan(pos));
    if (!protected_bstr) return std::nullopt;
    pos += protected_bstr->second;

    // Parse protected header map
    if (!protected_bstr->first.empty()) {
        std::span<const uint8_t> prot_data = protected_bstr->first;
        auto map_hdr = cbor::decode_map_header(prot_data);
        if (!map_hdr) return std::nullopt;

        size_t map_pos = map_hdr->second;
        for (size_t i = 0; i < map_hdr->first; ++i) {
            auto key = cbor::decode_int(prot_data.subspan(map_pos));
            if (!key) return std::nullopt;
            map_pos += key->second;

            // Get the value (don't fully parse, just copy)
            auto val_len = cbor::skip_item(prot_data.subspan(map_pos));
            if (!val_len) return std::nullopt;

            std::vector<uint8_t> value(
                prot_data.begin() + map_pos,
                prot_data.begin() + map_pos + *val_len);
            result.protected_header[static_cast<int>(key->first)] = std::move(value);
            map_pos += *val_len;
        }
    }

    // Unprotected header (inline CBOR map)
    auto unprot_map = cbor::decode_map_header(data.subspan(pos));
    if (!unprot_map) return std::nullopt;
    pos += unprot_map->second;

    for (size_t i = 0; i < unprot_map->first; ++i) {
        auto key = cbor::decode_int(data.subspan(pos));
        if (!key) return std::nullopt;
        pos += key->second;

        // For kid (label 4), decode as bstr
        if (key->first == 4) {
            auto kid = cbor::decode_bytes(data.subspan(pos));
            if (!kid) return std::nullopt;
            result.unprotected_header[4] = std::move(kid->first);
            pos += kid->second;
        } else {
            auto val_len = cbor::skip_item(data.subspan(pos));
            if (!val_len) return std::nullopt;
            std::vector<uint8_t> value(
                data.begin() + pos,
                data.begin() + pos + *val_len);
            result.unprotected_header[static_cast<int>(key->first)] = std::move(value);
            pos += *val_len;
        }
    }

    // Payload (bstr or null)
    if (cbor::is_null(data.subspan(pos))) {
        result.payload = std::nullopt;
        pos += 1;
    } else {
        auto payload = cbor::decode_bytes(data.subspan(pos));
        if (!payload) return std::nullopt;
        result.payload = std::move(payload->first);
        pos += payload->second;
    }

    // Signature
    auto sig = cbor::decode_bytes(data.subspan(pos));
    if (!sig) return std::nullopt;
    result.signature = std::move(sig->first);

    return result;
}

// ============================================================================
// Sign/Verify Functions
// ============================================================================

/**
 * Create and sign a COSE_Sign1 message
 *
 * @param algorithm Algorithm name (e.g., "ML-DSA-65")
 * @param payload Payload to sign
 * @param secret_key Secret key for signing
 * @param external_aad Optional external additional authenticated data
 * @param ctx Optional context string for ML-DSA
 * @return CBOR-encoded COSE_Sign1
 * @throws std::runtime_error if algorithm not supported
 */
inline std::vector<uint8_t> sign1(
    const std::string& algorithm,
    std::span<const uint8_t> payload,
    std::span<const uint8_t> secret_key,
    std::span<const uint8_t> external_aad = {},
    std::span<const uint8_t> ctx = {}) {

    auto alg_id = algorithm_from_name(algorithm);
    if (!alg_id) {
        throw std::runtime_error("Unsupported COSE algorithm: " + algorithm);
    }

    auto internal_name = get_internal_name(*alg_id);
    if (!internal_name) {
        throw std::runtime_error("Cannot map COSE algorithm to internal: " + algorithm);
    }

    // Create signer
    auto dsa = pqc::create_dsa(*internal_name);

    // Build COSE_Sign1 structure
    Sign1 msg;
    msg.set_algorithm(*alg_id);
    msg.payload = std::vector<uint8_t>(payload.begin(), payload.end());

    // Encode protected header
    auto protected_bytes = detail::encode_protected_header(msg.protected_header);

    // Build Sig_structure
    auto sig_struct = detail::build_sig_structure(
        protected_bytes,
        std::vector<uint8_t>(external_aad.begin(), external_aad.end()),
        std::vector<uint8_t>(payload.begin(), payload.end()));

    // Sign
    msg.signature = dsa->sign(secret_key, sig_struct, ctx);

    return encode_sign1(msg);
}

/**
 * Verify a COSE_Sign1 message
 *
 * @param encoded CBOR-encoded COSE_Sign1
 * @param public_key Public key for verification
 * @param external_aad Optional external additional authenticated data
 * @param ctx Optional context string for ML-DSA
 * @return Payload if signature is valid, nullopt otherwise
 */
inline std::optional<std::vector<uint8_t>> verify1(
    std::span<const uint8_t> encoded,
    std::span<const uint8_t> public_key,
    std::span<const uint8_t> external_aad = {},
    std::span<const uint8_t> ctx = {}) {

    auto msg = decode_sign1(encoded);
    if (!msg) return std::nullopt;

    auto alg = msg->algorithm();
    if (!alg) return std::nullopt;

    auto internal_name = get_internal_name(*alg);
    if (!internal_name) return std::nullopt;

    // Create verifier
    std::unique_ptr<pqc::DigitalSignature> dsa;
    try {
        dsa = pqc::create_dsa(*internal_name);
    } catch (...) {
        return std::nullopt;
    }

    // Payload is required for verification
    if (!msg->payload) return std::nullopt;

    // Encode protected header
    auto protected_bytes = detail::encode_protected_header(msg->protected_header);

    // Build Sig_structure
    auto sig_struct = detail::build_sig_structure(
        protected_bytes,
        std::vector<uint8_t>(external_aad.begin(), external_aad.end()),
        *msg->payload);

    // Verify
    if (!dsa->verify(public_key, sig_struct, msg->signature, ctx)) {
        return std::nullopt;
    }

    return msg->payload;
}

/**
 * Sign with detached payload
 */
inline std::vector<uint8_t> sign1_detached(
    const std::string& algorithm,
    std::span<const uint8_t> payload,
    std::span<const uint8_t> secret_key,
    std::span<const uint8_t> external_aad = {},
    std::span<const uint8_t> ctx = {}) {

    auto alg_id = algorithm_from_name(algorithm);
    if (!alg_id) {
        throw std::runtime_error("Unsupported COSE algorithm: " + algorithm);
    }

    auto internal_name = get_internal_name(*alg_id);
    if (!internal_name) {
        throw std::runtime_error("Cannot map COSE algorithm to internal: " + algorithm);
    }

    auto dsa = pqc::create_dsa(*internal_name);

    Sign1 msg;
    msg.set_algorithm(*alg_id);
    msg.payload = std::nullopt;  // Detached

    auto protected_bytes = detail::encode_protected_header(msg.protected_header);

    auto sig_struct = detail::build_sig_structure(
        protected_bytes,
        std::vector<uint8_t>(external_aad.begin(), external_aad.end()),
        std::vector<uint8_t>(payload.begin(), payload.end()));

    msg.signature = dsa->sign(secret_key, sig_struct, ctx);

    return encode_sign1(msg);
}

/**
 * Verify with detached payload
 */
inline bool verify1_detached(
    std::span<const uint8_t> encoded,
    std::span<const uint8_t> detached_payload,
    std::span<const uint8_t> public_key,
    std::span<const uint8_t> external_aad = {},
    std::span<const uint8_t> ctx = {}) {

    auto msg = decode_sign1(encoded);
    if (!msg) return false;

    // Detached: payload in message should be null
    if (msg->payload) return false;

    auto alg = msg->algorithm();
    if (!alg) return false;

    auto internal_name = get_internal_name(*alg);
    if (!internal_name) return false;

    std::unique_ptr<pqc::DigitalSignature> dsa;
    try {
        dsa = pqc::create_dsa(*internal_name);
    } catch (...) {
        return false;
    }

    auto protected_bytes = detail::encode_protected_header(msg->protected_header);

    auto sig_struct = detail::build_sig_structure(
        protected_bytes,
        std::vector<uint8_t>(external_aad.begin(), external_aad.end()),
        std::vector<uint8_t>(detached_payload.begin(), detached_payload.end()));

    return dsa->verify(public_key, sig_struct, msg->signature, ctx);
}

// ============================================================================
// Convenience Functions
// ============================================================================

/**
 * Get list of supported COSE algorithms
 */
inline std::vector<std::string> available_algorithms() {
    std::vector<std::string> result;
    for (const auto& info : algorithm_table()) {
        result.push_back(info.name);
    }
    return result;
}

/**
 * Check if algorithm is supported
 */
inline bool is_supported(const std::string& algorithm) {
    return algorithm_from_name(algorithm).has_value();
}

} // namespace cose

#endif // COMMON_COSE_HPP
