/**
 * ASN.1 DER Encoding/Decoding Utilities
 *
 * Provides ASN.1 DER primitives for PKCS#8, SPKI, and X.509 structures.
 * Implements encoding/decoding for:
 * - SEQUENCE, SET
 * - OCTET STRING, BIT STRING
 * - OBJECT IDENTIFIER
 * - INTEGER
 * - PrintableString, UTF8String
 * - UTCTime, GeneralizedTime
 * - Context-specific tags (EXPLICIT)
 */

#ifndef COMMON_ASN1_HPP
#define COMMON_ASN1_HPP

#include <cstdint>
#include <vector>
#include <string>
#include <optional>
#include <stdexcept>

namespace asn1 {

// ASN.1 tag values
enum class Tag : uint8_t {
    BOOLEAN = 0x01,
    INTEGER = 0x02,
    BIT_STRING = 0x03,
    OCTET_STRING = 0x04,
    NULL_TAG = 0x05,
    OBJECT_IDENTIFIER = 0x06,
    UTF8_STRING = 0x0C,
    PRINTABLE_STRING = 0x13,
    IA5_STRING = 0x16,
    UTC_TIME = 0x17,
    GENERALIZED_TIME = 0x18,
    SEQUENCE = 0x30,
    SET = 0x31
};

/**
 * Encode length in DER format
 * Short form: length < 128 uses 1 byte
 * Long form: length >= 128 uses 1 byte (0x80 | num_octets) + length octets
 */
inline std::vector<uint8_t> encode_length(size_t length) {
    std::vector<uint8_t> result;

    if (length < 128) {
        result.push_back(static_cast<uint8_t>(length));
    } else if (length < 256) {
        result.push_back(0x81);
        result.push_back(static_cast<uint8_t>(length));
    } else if (length < 65536) {
        result.push_back(0x82);
        result.push_back(static_cast<uint8_t>(length >> 8));
        result.push_back(static_cast<uint8_t>(length & 0xFF));
    } else if (length < 16777216) {
        result.push_back(0x83);
        result.push_back(static_cast<uint8_t>(length >> 16));
        result.push_back(static_cast<uint8_t>((length >> 8) & 0xFF));
        result.push_back(static_cast<uint8_t>(length & 0xFF));
    } else {
        result.push_back(0x84);
        result.push_back(static_cast<uint8_t>(length >> 24));
        result.push_back(static_cast<uint8_t>((length >> 16) & 0xFF));
        result.push_back(static_cast<uint8_t>((length >> 8) & 0xFF));
        result.push_back(static_cast<uint8_t>(length & 0xFF));
    }

    return result;
}

/**
 * Decode length from DER format
 * Returns optional<(length, bytes_consumed)> - nullopt on error
 */
inline std::optional<std::pair<size_t, size_t>> decode_length(const uint8_t* data, size_t max_len) {
    if (max_len < 1) {
        return std::nullopt;
    }

    uint8_t first = data[0];

    if (first < 128) {
        return std::make_pair(static_cast<size_t>(first), static_cast<size_t>(1));
    }

    size_t num_octets = first & 0x7F;
    if (num_octets == 0 || num_octets > 4) {
        return std::nullopt;
    }
    if (max_len < 1 + num_octets) {
        return std::nullopt;
    }

    size_t length = 0;
    for (size_t i = 0; i < num_octets; ++i) {
        length = (length << 8) | data[1 + i];
    }

    return std::make_pair(length, 1 + num_octets);
}

/**
 * Encode a TLV (Tag-Length-Value) structure
 */
inline std::vector<uint8_t> encode_tlv(Tag tag, const std::vector<uint8_t>& value) {
    std::vector<uint8_t> result;
    result.push_back(static_cast<uint8_t>(tag));

    auto len_bytes = encode_length(value.size());
    result.insert(result.end(), len_bytes.begin(), len_bytes.end());
    result.insert(result.end(), value.begin(), value.end());

    return result;
}

/**
 * Encode SEQUENCE
 */
inline std::vector<uint8_t> encode_sequence(const std::vector<uint8_t>& content) {
    return encode_tlv(Tag::SEQUENCE, content);
}

/**
 * Encode OCTET STRING
 */
inline std::vector<uint8_t> encode_octet_string(const std::vector<uint8_t>& data) {
    return encode_tlv(Tag::OCTET_STRING, data);
}

/**
 * Encode BIT STRING (with zero unused bits)
 */
inline std::vector<uint8_t> encode_bit_string(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> content;
    content.push_back(0x00);  // unused bits = 0
    content.insert(content.end(), data.begin(), data.end());
    return encode_tlv(Tag::BIT_STRING, content);
}

/**
 * Encode INTEGER (unsigned, minimal encoding)
 */
inline std::vector<uint8_t> encode_integer(uint64_t value) {
    std::vector<uint8_t> bytes;

    if (value == 0) {
        bytes.push_back(0x00);
    } else {
        while (value > 0) {
            bytes.insert(bytes.begin(), static_cast<uint8_t>(value & 0xFF));
            value >>= 8;
        }
        // Add leading zero if high bit is set (to keep it positive)
        if (bytes[0] & 0x80) {
            bytes.insert(bytes.begin(), 0x00);
        }
    }

    return encode_tlv(Tag::INTEGER, bytes);
}

/**
 * Encode OBJECT IDENTIFIER from dotted string (e.g., "2.16.840.1.101.3.4.3.17")
 */
inline std::vector<uint8_t> encode_oid(const std::string& oid_str) {
    std::vector<uint32_t> components;
    std::string current;

    for (char c : oid_str) {
        if (c == '.') {
            if (!current.empty()) {
                components.push_back(std::stoul(current));
                current.clear();
            }
        } else {
            current += c;
        }
    }
    if (!current.empty()) {
        components.push_back(std::stoul(current));
    }

    if (components.size() < 2) {
        throw std::runtime_error("ASN.1: OID must have at least 2 components");
    }

    std::vector<uint8_t> encoded;

    // First two components are encoded as: first * 40 + second
    encoded.push_back(static_cast<uint8_t>(components[0] * 40 + components[1]));

    // Remaining components use base-128 encoding
    for (size_t i = 2; i < components.size(); ++i) {
        uint32_t val = components[i];

        if (val == 0) {
            encoded.push_back(0x00);
        } else {
            std::vector<uint8_t> base128;
            while (val > 0) {
                base128.insert(base128.begin(), static_cast<uint8_t>(val & 0x7F));
                val >>= 7;
            }
            // Set high bit on all but last byte
            for (size_t j = 0; j < base128.size() - 1; ++j) {
                base128[j] |= 0x80;
            }
            encoded.insert(encoded.end(), base128.begin(), base128.end());
        }
    }

    return encode_tlv(Tag::OBJECT_IDENTIFIER, encoded);
}

/**
 * Encode NULL
 */
inline std::vector<uint8_t> encode_null() {
    return {static_cast<uint8_t>(Tag::NULL_TAG), 0x00};
}

/**
 * Encode SET
 */
inline std::vector<uint8_t> encode_set(const std::vector<uint8_t>& content) {
    return encode_tlv(Tag::SET, content);
}

/**
 * Encode INTEGER from raw big-endian bytes (for serial numbers, etc.)
 */
inline std::vector<uint8_t> encode_integer_bytes(const std::vector<uint8_t>& bytes) {
    std::vector<uint8_t> value = bytes;
    // Add leading zero if high bit set (to keep positive)
    if (!value.empty() && (value[0] & 0x80)) {
        value.insert(value.begin(), 0x00);
    }
    return encode_tlv(Tag::INTEGER, value);
}

/**
 * Encode BOOLEAN
 */
inline std::vector<uint8_t> encode_boolean(bool value) {
    return encode_tlv(Tag::BOOLEAN, {static_cast<uint8_t>(value ? 0xFF : 0x00)});
}

/**
 * Encode PrintableString
 */
inline std::vector<uint8_t> encode_printable_string(const std::string& str) {
    std::vector<uint8_t> data(str.begin(), str.end());
    return encode_tlv(Tag::PRINTABLE_STRING, data);
}

/**
 * Encode UTF8String
 */
inline std::vector<uint8_t> encode_utf8_string(const std::string& str) {
    std::vector<uint8_t> data(str.begin(), str.end());
    return encode_tlv(Tag::UTF8_STRING, data);
}

/**
 * Encode IA5String
 */
inline std::vector<uint8_t> encode_ia5_string(const std::string& str) {
    std::vector<uint8_t> data(str.begin(), str.end());
    return encode_tlv(Tag::IA5_STRING, data);
}

/**
 * Encode UTCTime (format: "YYMMDDHHMMSSZ")
 */
inline std::vector<uint8_t> encode_utc_time(const std::string& time_str) {
    std::vector<uint8_t> data(time_str.begin(), time_str.end());
    return encode_tlv(Tag::UTC_TIME, data);
}

/**
 * Encode GeneralizedTime (format: "YYYYMMDDHHMMSSZ")
 */
inline std::vector<uint8_t> encode_generalized_time(const std::string& time_str) {
    std::vector<uint8_t> data(time_str.begin(), time_str.end());
    return encode_tlv(Tag::GENERALIZED_TIME, data);
}

/**
 * Encode with raw tag byte (for context-specific tags)
 */
inline std::vector<uint8_t> encode_raw_tag(uint8_t tag, const std::vector<uint8_t>& value) {
    std::vector<uint8_t> result;
    result.push_back(tag);
    auto len_bytes = encode_length(value.size());
    result.insert(result.end(), len_bytes.begin(), len_bytes.end());
    result.insert(result.end(), value.begin(), value.end());
    return result;
}

/**
 * Encode EXPLICIT context-specific tag [n]
 * Wraps content in a constructed context-specific tag
 */
inline std::vector<uint8_t> encode_explicit_tag(uint8_t tag_number, const std::vector<uint8_t>& content) {
    uint8_t tag = 0xA0 | (tag_number & 0x1F);  // Context-specific, constructed
    return encode_raw_tag(tag, content);
}

/**
 * Parse result for decoded TLV
 */
struct TLV {
    Tag tag;
    std::vector<uint8_t> value;
    size_t total_length;  // Total bytes consumed (tag + length + value)
};

/**
 * Decode a TLV structure
 */
inline std::optional<TLV> decode_tlv(const uint8_t* data, size_t len) {
    if (len < 2) {
        return std::nullopt;
    }

    TLV result;
    result.tag = static_cast<Tag>(data[0]);

    auto len_result = decode_length(data + 1, len - 1);
    if (!len_result) {
        return std::nullopt;
    }
    auto [value_len, len_bytes] = *len_result;

    size_t header_len = 1 + len_bytes;
    if (len < header_len + value_len) {
        return std::nullopt;
    }

    result.value.assign(data + header_len, data + header_len + value_len);
    result.total_length = header_len + value_len;

    return result;
}

/**
 * Decode OBJECT IDENTIFIER to dotted string
 */
inline std::optional<std::string> decode_oid(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return std::nullopt;
    }

    std::vector<uint32_t> components;

    // First byte encodes first two components
    components.push_back(data[0] / 40);
    components.push_back(data[0] % 40);

    // Decode remaining base-128 encoded components
    uint32_t current = 0;
    for (size_t i = 1; i < data.size(); ++i) {
        current = (current << 7) | (data[i] & 0x7F);
        if ((data[i] & 0x80) == 0) {
            components.push_back(current);
            current = 0;
        }
    }

    // Build dotted string
    std::string result;
    for (size_t i = 0; i < components.size(); ++i) {
        if (i > 0) result += '.';
        result += std::to_string(components[i]);
    }

    return result;
}

/**
 * Decode BIT STRING (returns the data without the unused bits prefix)
 */
inline std::optional<std::vector<uint8_t>> decode_bit_string(const std::vector<uint8_t>& data) {
    if (data.empty()) {
        return std::nullopt;
    }

    uint8_t unused_bits = data[0];
    if (unused_bits > 7) {
        return std::nullopt;
    }

    return std::vector<uint8_t>(data.begin() + 1, data.end());
}

/**
 * Concatenate multiple byte vectors
 */
inline std::vector<uint8_t> concat(std::initializer_list<std::vector<uint8_t>> parts) {
    std::vector<uint8_t> result;
    for (const auto& part : parts) {
        result.insert(result.end(), part.begin(), part.end());
    }
    return result;
}

} // namespace asn1

#endif // COMMON_ASN1_HPP
