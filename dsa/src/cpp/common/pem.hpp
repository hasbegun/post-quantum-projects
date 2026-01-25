/**
 * PEM Encoding/Decoding Utilities
 *
 * Provides PEM (Privacy-Enhanced Mail) format conversion for DER-encoded data.
 * PEM format uses Base64 encoding wrapped in -----BEGIN/END----- delimiters.
 */

#ifndef COMMON_PEM_HPP
#define COMMON_PEM_HPP

#include <cstdint>
#include <vector>
#include <string>
#include <optional>
#include <algorithm>

namespace pem {

// Base64 encoding table
inline constexpr char BASE64_TABLE[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/**
 * Encode binary data to Base64
 */
inline std::string base64_encode(const std::vector<uint8_t>& data) {
    std::string result;
    result.reserve(((data.size() + 2) / 3) * 4);

    size_t i = 0;
    while (i + 2 < data.size()) {
        uint32_t triple = (static_cast<uint32_t>(data[i]) << 16) |
                         (static_cast<uint32_t>(data[i + 1]) << 8) |
                         static_cast<uint32_t>(data[i + 2]);

        result += BASE64_TABLE[(triple >> 18) & 0x3F];
        result += BASE64_TABLE[(triple >> 12) & 0x3F];
        result += BASE64_TABLE[(triple >> 6) & 0x3F];
        result += BASE64_TABLE[triple & 0x3F];

        i += 3;
    }

    // Handle remaining bytes
    if (i + 1 == data.size()) {
        uint32_t val = static_cast<uint32_t>(data[i]) << 16;
        result += BASE64_TABLE[(val >> 18) & 0x3F];
        result += BASE64_TABLE[(val >> 12) & 0x3F];
        result += "==";
    } else if (i + 2 == data.size()) {
        uint32_t val = (static_cast<uint32_t>(data[i]) << 16) |
                      (static_cast<uint32_t>(data[i + 1]) << 8);
        result += BASE64_TABLE[(val >> 18) & 0x3F];
        result += BASE64_TABLE[(val >> 12) & 0x3F];
        result += BASE64_TABLE[(val >> 6) & 0x3F];
        result += '=';
    }

    return result;
}

/**
 * Decode Base64 to binary data
 */
inline std::optional<std::vector<uint8_t>> base64_decode(const std::string& encoded) {
    // Build decode table
    int8_t decode_table[256];
    std::fill(decode_table, decode_table + 256, -1);
    for (int i = 0; i < 64; ++i) {
        decode_table[static_cast<uint8_t>(BASE64_TABLE[i])] = static_cast<int8_t>(i);
    }
    decode_table[static_cast<uint8_t>('=')] = 0;  // Padding

    std::vector<uint8_t> result;
    result.reserve((encoded.size() * 3) / 4);

    uint32_t buffer = 0;
    int bits_collected = 0;
    int padding_count = 0;

    for (char c : encoded) {
        if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
            continue;  // Skip whitespace
        }

        if (c == '=') {
            padding_count++;
            if (padding_count > 2) {
                return std::nullopt;
            }
            continue;
        }

        if (padding_count > 0) {
            return std::nullopt;  // Data after padding
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
 * Encode DER data to PEM format
 *
 * @param der DER-encoded binary data
 * @param label PEM label (e.g., "PRIVATE KEY", "PUBLIC KEY")
 * @return PEM-encoded string with line breaks every 64 characters
 */
inline std::string encode(const std::vector<uint8_t>& der, const std::string& label) {
    std::string b64 = base64_encode(der);
    std::string result = "-----BEGIN " + label + "-----\n";

    // Insert line breaks every 64 characters
    for (size_t i = 0; i < b64.size(); i += 64) {
        result += b64.substr(i, 64) + "\n";
    }

    result += "-----END " + label + "-----\n";
    return result;
}

/**
 * Decode PEM to DER format
 *
 * @param pem PEM-encoded string
 * @param expected_label Expected label (e.g., "PRIVATE KEY"), empty to accept any
 * @return DER-encoded binary data if successful
 */
inline std::optional<std::vector<uint8_t>> decode(
    const std::string& pem,
    const std::string& expected_label = "") {

    // Find BEGIN marker
    size_t begin_pos = pem.find("-----BEGIN ");
    if (begin_pos == std::string::npos) {
        return std::nullopt;
    }

    size_t label_start = begin_pos + 11;
    size_t label_end = pem.find("-----", label_start);
    if (label_end == std::string::npos) {
        return std::nullopt;
    }

    std::string label = pem.substr(label_start, label_end - label_start);
    if (!expected_label.empty() && label != expected_label) {
        return std::nullopt;
    }

    // Find END marker
    size_t data_start = label_end + 5;
    std::string end_marker = "-----END " + label + "-----";
    size_t end_pos = pem.find(end_marker, data_start);
    if (end_pos == std::string::npos) {
        return std::nullopt;
    }

    // Extract Base64 data (removing whitespace)
    std::string b64_data;
    for (size_t i = data_start; i < end_pos; ++i) {
        char c = pem[i];
        if (c != ' ' && c != '\n' && c != '\r' && c != '\t') {
            b64_data += c;
        }
    }

    return base64_decode(b64_data);
}

/**
 * Extract the label from a PEM string
 */
inline std::optional<std::string> get_label(const std::string& pem) {
    size_t begin_pos = pem.find("-----BEGIN ");
    if (begin_pos == std::string::npos) {
        return std::nullopt;
    }

    size_t label_start = begin_pos + 11;
    size_t label_end = pem.find("-----", label_start);
    if (label_end == std::string::npos) {
        return std::nullopt;
    }

    return pem.substr(label_start, label_end - label_start);
}

} // namespace pem

#endif // COMMON_PEM_HPP
