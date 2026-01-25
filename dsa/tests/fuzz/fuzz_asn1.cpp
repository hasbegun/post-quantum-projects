/**
 * Fuzz target for ASN.1/DER parsing of composite keys and signatures
 *
 * Tests that malformed ASN.1 structures don't cause crashes or memory corruption.
 * This is critical for X.509 certificate security.
 * Run with: ./fuzz_asn1 -max_len=10000 -timeout=5
 */

#include <cstdint>
#include <cstddef>
#include <vector>
#include <span>
#include <cstring>

#include "common/composite.hpp"

// Basic ASN.1 DER parser for testing purposes
// This simulates what a certificate parser would do with composite signatures

// ASN.1 tag values
constexpr uint8_t ASN1_SEQUENCE = 0x30;
constexpr uint8_t ASN1_BIT_STRING = 0x03;
constexpr uint8_t ASN1_OCTET_STRING = 0x04;
constexpr uint8_t ASN1_OID = 0x06;

// Try to parse a length field
static bool parse_length(const uint8_t* data, size_t size, size_t& offset, size_t& length) {
    if (offset >= size) return false;

    uint8_t first = data[offset++];
    if (first < 0x80) {
        length = first;
        return true;
    }

    size_t num_bytes = first & 0x7F;
    if (num_bytes == 0 || num_bytes > 4 || offset + num_bytes > size) {
        return false;
    }

    length = 0;
    for (size_t i = 0; i < num_bytes; i++) {
        length = (length << 8) | data[offset++];
    }
    return true;
}

// Try to parse a complete TLV (Tag-Length-Value)
static bool parse_tlv(const uint8_t* data, size_t size, size_t& offset,
                      uint8_t& tag, const uint8_t*& value, size_t& value_len) {
    if (offset >= size) return false;

    tag = data[offset++];
    if (!parse_length(data, size, offset, value_len)) return false;
    if (offset + value_len > size) return false;

    value = data + offset;
    offset += value_len;
    return true;
}

// Simulate parsing a composite public key from DER
static void fuzz_composite_pubkey(const uint8_t* data, size_t size) {
    // CompositePublicKey ::= SEQUENCE {
    //     pqcPublicKey    BIT STRING,
    //     classicalPublicKey  BIT STRING
    // }

    size_t offset = 0;
    uint8_t tag;
    const uint8_t* value;
    size_t value_len;

    // Parse outer SEQUENCE
    if (!parse_tlv(data, size, offset, tag, value, value_len)) return;
    if (tag != ASN1_SEQUENCE) return;

    // Parse PQC public key (BIT STRING)
    size_t seq_offset = 0;
    if (!parse_tlv(value, value_len, seq_offset, tag, value, value_len)) return;
    // Could be BIT STRING or OCTET STRING
    if (tag != ASN1_BIT_STRING && tag != ASN1_OCTET_STRING) return;

    std::vector<uint8_t> pqc_pk(value, value + value_len);

    // Parse classical public key (BIT STRING)
    if (!parse_tlv(data + offset, size - offset, seq_offset, tag, value, value_len)) return;

    std::vector<uint8_t> classical_pk(value, value + value_len);

    // Try to use the parsed keys with various composite algorithms
    auto dsa = composite::create_composite_dsa("MLDSA65-ECDSA-P384");
    if (dsa) {
        // Combine into composite public key format
        std::vector<uint8_t> combined;
        combined.insert(combined.end(), pqc_pk.begin(), pqc_pk.end());
        combined.insert(combined.end(), classical_pk.begin(), classical_pk.end());

        // Try verification with fuzzed key
        std::vector<uint8_t> dummy_msg = {0x01, 0x02, 0x03};
        std::vector<uint8_t> dummy_sig(dsa->signature_size(), 0);

        try {
            volatile bool result = dsa->verify(combined, dummy_msg, dummy_sig);
            (void)result;
        } catch (...) {
            // Expected for invalid keys
        }
    }
}

// Simulate parsing a composite signature from DER
static void fuzz_composite_signature(const uint8_t* data, size_t size) {
    // CompositeSignature ::= SEQUENCE {
    //     pqcSignature        BIT STRING,
    //     classicalSignature  BIT STRING
    // }

    size_t offset = 0;
    uint8_t tag;
    const uint8_t* value;
    size_t value_len;

    // Parse outer SEQUENCE
    if (!parse_tlv(data, size, offset, tag, value, value_len)) return;
    if (tag != ASN1_SEQUENCE) return;

    // Parse PQC signature
    size_t seq_offset = 0;
    const uint8_t* seq_data = value;
    size_t seq_len = value_len;

    if (!parse_tlv(seq_data, seq_len, seq_offset, tag, value, value_len)) return;

    std::vector<uint8_t> pqc_sig(value, value + value_len);

    // Parse classical signature
    if (!parse_tlv(seq_data + seq_offset, seq_len - seq_offset, seq_offset, tag, value, value_len)) return;

    std::vector<uint8_t> classical_sig(value, value + value_len);

    // Try verification with parsed signature
    auto dsa = composite::create_composite_dsa("MLDSA44-ECDSA-P256");
    if (dsa) {
        std::vector<uint8_t> pk(dsa->public_key_size());
        std::vector<uint8_t> sk(dsa->secret_key_size());
        dsa->keygen(pk, sk);

        // Combine into composite signature format
        std::vector<uint8_t> combined;
        combined.insert(combined.end(), pqc_sig.begin(), pqc_sig.end());
        combined.insert(combined.end(), classical_sig.begin(), classical_sig.end());

        std::vector<uint8_t> msg = {0x01, 0x02, 0x03, 0x04};

        try {
            volatile bool result = dsa->verify(pk, msg, combined);
            (void)result;
        } catch (...) {
            // Expected for invalid signatures
        }
    }
}

// Fuzz OID parsing
static void fuzz_oid(const uint8_t* data, size_t size) {
    // Try to interpret as OID and look up algorithm
    if (size < 3 || size > 20) return;

    // Build OID string like "1.3.6.1.5.5.7.6.41"
    std::string oid_str;
    bool first = true;

    // First two components encoded in first byte
    if (size > 0) {
        uint8_t first_byte = data[0];
        oid_str = std::to_string(first_byte / 40) + "." + std::to_string(first_byte % 40);
        first = false;
    }

    // Remaining components
    uint32_t component = 0;
    for (size_t i = 1; i < size; i++) {
        component = (component << 7) | (data[i] & 0x7F);
        if (!(data[i] & 0x80)) {
            oid_str += "." + std::to_string(component);
            component = 0;
        }
    }

    // Try to create algorithm from OID
    try {
        auto dsa = composite::create_composite_dsa(oid_str);
        // If it succeeded, the OID was recognized
    } catch (...) {
        // Expected for invalid OIDs
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;

    // Use first byte to select parsing mode
    uint8_t mode = data[0] % 3;
    const uint8_t* payload = data + 1;
    size_t payload_size = size - 1;

    switch (mode) {
        case 0:
            fuzz_composite_pubkey(payload, payload_size);
            break;
        case 1:
            fuzz_composite_signature(payload, payload_size);
            break;
        case 2:
            fuzz_oid(payload, payload_size);
            break;
    }

    return 0;
}
