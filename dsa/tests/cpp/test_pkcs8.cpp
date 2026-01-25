/**
 * PKCS#8 Key Format Tests
 *
 * Tests for DER/PEM encoding and decoding of post-quantum keys.
 */

#include <iostream>
#include <sstream>
#include <cassert>
#include <cstring>
#include <iomanip>
#include "common/asn1.hpp"
#include "common/pem.hpp"
#include "common/pkcs8.hpp"
#include "mldsa/mldsa.hpp"
#include "slhdsa/slh_dsa.hpp"
#include "mlkem/mlkem.hpp"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    std::cout << "  Testing " << name << "..." << std::flush; \
    try {

#define TEST_END(name) \
        std::cout << " [PASS]" << std::endl; \
        tests_passed++; \
    } catch (const std::exception& e) { \
        std::cout << " [FAIL] " << e.what() << std::endl; \
        tests_failed++; \
    }

#define ASSERT(cond) \
    if (!(cond)) { \
        throw std::runtime_error("Assertion failed: " #cond); \
    }

void print_hex(const std::vector<uint8_t>& data, size_t max_bytes = 32) {
    for (size_t i = 0; i < std::min(data.size(), max_bytes); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]);
        if ((i + 1) % 16 == 0) std::cout << std::endl << "    ";
    }
    if (data.size() > max_bytes) {
        std::cout << "... (" << std::dec << data.size() << " bytes total)";
    }
    std::cout << std::dec << std::endl;
}

// =============================================================================
// ASN.1 Tests
// =============================================================================

void test_asn1_length_encoding() {
    TEST("ASN.1 short length encoding")
    {
        auto len = asn1::encode_length(50);
        ASSERT(len.size() == 1);
        ASSERT(len[0] == 50);
    }
    TEST_END("ASN.1 short length encoding")

    TEST("ASN.1 two-byte length encoding")
    {
        auto len = asn1::encode_length(200);
        ASSERT(len.size() == 2);
        ASSERT(len[0] == 0x81);
        ASSERT(len[1] == 200);
    }
    TEST_END("ASN.1 two-byte length encoding")

    TEST("ASN.1 three-byte length encoding")
    {
        auto len = asn1::encode_length(1000);
        ASSERT(len.size() == 3);
        ASSERT(len[0] == 0x82);
        ASSERT(len[1] == 0x03);
        ASSERT(len[2] == 0xE8);
    }
    TEST_END("ASN.1 three-byte length encoding")
}

void test_asn1_oid_encoding() {
    TEST("ASN.1 OID encoding - ML-DSA-65")
    {
        // OID: 2.16.840.1.101.3.4.3.18
        auto encoded = asn1::encode_oid("2.16.840.1.101.3.4.3.18");
        ASSERT(encoded.size() > 2);
        ASSERT(encoded[0] == 0x06);  // OID tag

        // Decode back
        auto tlv = asn1::decode_tlv(encoded.data(), encoded.size());
        ASSERT(tlv.has_value());
        auto decoded = asn1::decode_oid(tlv->value);
        ASSERT(decoded.has_value());
        ASSERT(*decoded == "2.16.840.1.101.3.4.3.18");
    }
    TEST_END("ASN.1 OID encoding - ML-DSA-65")

    TEST("ASN.1 OID encoding - ML-KEM-768")
    {
        auto encoded = asn1::encode_oid("2.16.840.1.101.3.4.4.2");
        auto tlv = asn1::decode_tlv(encoded.data(), encoded.size());
        ASSERT(tlv.has_value());
        auto decoded = asn1::decode_oid(tlv->value);
        ASSERT(decoded.has_value());
        ASSERT(*decoded == "2.16.840.1.101.3.4.4.2");
    }
    TEST_END("ASN.1 OID encoding - ML-KEM-768")
}

void test_asn1_sequence() {
    TEST("ASN.1 SEQUENCE encoding")
    {
        std::vector<uint8_t> content = {0x01, 0x02, 0x03};
        auto seq = asn1::encode_sequence(content);
        ASSERT(seq[0] == 0x30);  // SEQUENCE tag
        ASSERT(seq[1] == 3);     // Length
        ASSERT(seq[2] == 0x01);
        ASSERT(seq[3] == 0x02);
        ASSERT(seq[4] == 0x03);
    }
    TEST_END("ASN.1 SEQUENCE encoding")
}

void test_asn1_octet_string() {
    TEST("ASN.1 OCTET STRING encoding")
    {
        std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
        auto encoded = asn1::encode_octet_string(data);
        ASSERT(encoded[0] == 0x04);  // OCTET STRING tag
        ASSERT(encoded[1] == 4);
        ASSERT(encoded[2] == 0xDE);
        ASSERT(encoded[5] == 0xEF);
    }
    TEST_END("ASN.1 OCTET STRING encoding")
}

void test_asn1_bit_string() {
    TEST("ASN.1 BIT STRING encoding/decoding")
    {
        std::vector<uint8_t> data = {0xFF, 0x00, 0xAA};
        auto encoded = asn1::encode_bit_string(data);
        ASSERT(encoded[0] == 0x03);  // BIT STRING tag
        ASSERT(encoded[1] == 4);     // Length (1 byte unused + 3 data)
        ASSERT(encoded[2] == 0x00);  // Unused bits

        auto tlv = asn1::decode_tlv(encoded.data(), encoded.size());
        ASSERT(tlv.has_value());
        auto decoded = asn1::decode_bit_string(tlv->value);
        ASSERT(decoded.has_value());
        ASSERT(*decoded == data);
    }
    TEST_END("ASN.1 BIT STRING encoding/decoding")
}

// =============================================================================
// PEM Tests
// =============================================================================

void test_pem_base64() {
    TEST("PEM Base64 encode/decode")
    {
        std::vector<uint8_t> data = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  // "Hello"
        auto encoded = pem::base64_encode(data);
        ASSERT(encoded == "SGVsbG8=");

        auto decoded = pem::base64_decode(encoded);
        ASSERT(decoded.has_value());
        ASSERT(*decoded == data);
    }
    TEST_END("PEM Base64 encode/decode")

    TEST("PEM Base64 empty data")
    {
        std::vector<uint8_t> empty;
        auto encoded = pem::base64_encode(empty);
        ASSERT(encoded == "");

        auto decoded = pem::base64_decode(encoded);
        ASSERT(decoded.has_value());
        ASSERT(decoded->empty());
    }
    TEST_END("PEM Base64 empty data")
}

void test_pem_format() {
    TEST("PEM format encode/decode")
    {
        std::vector<uint8_t> data(100);
        for (size_t i = 0; i < data.size(); ++i) {
            data[i] = static_cast<uint8_t>(i);
        }

        auto pem_str = pem::encode(data, "TEST DATA");
        ASSERT(pem_str.find("-----BEGIN TEST DATA-----") != std::string::npos);
        ASSERT(pem_str.find("-----END TEST DATA-----") != std::string::npos);

        auto decoded = pem::decode(pem_str, "TEST DATA");
        ASSERT(decoded.has_value());
        ASSERT(*decoded == data);
    }
    TEST_END("PEM format encode/decode")

    TEST("PEM label extraction")
    {
        std::string pem = "-----BEGIN PRIVATE KEY-----\nABC=\n-----END PRIVATE KEY-----";
        auto label = pem::get_label(pem);
        ASSERT(label.has_value());
        ASSERT(*label == "PRIVATE KEY");
    }
    TEST_END("PEM label extraction")
}

// =============================================================================
// PKCS#8 Tests
// =============================================================================

void test_pkcs8_oid_mapping() {
    TEST("PKCS#8 OID mapping")
    {
        ASSERT(pkcs8::get_oid(pkcs8::Algorithm::ML_DSA_44) == "2.16.840.1.101.3.4.3.17");
        ASSERT(pkcs8::get_oid(pkcs8::Algorithm::ML_DSA_65) == "2.16.840.1.101.3.4.3.18");
        ASSERT(pkcs8::get_oid(pkcs8::Algorithm::ML_DSA_87) == "2.16.840.1.101.3.4.3.19");
        ASSERT(pkcs8::get_oid(pkcs8::Algorithm::ML_KEM_512) == "2.16.840.1.101.3.4.4.1");
        ASSERT(pkcs8::get_oid(pkcs8::Algorithm::ML_KEM_768) == "2.16.840.1.101.3.4.4.2");
        ASSERT(pkcs8::get_oid(pkcs8::Algorithm::ML_KEM_1024) == "2.16.840.1.101.3.4.4.3");

        auto alg = pkcs8::algorithm_from_oid("2.16.840.1.101.3.4.3.18");
        ASSERT(alg.has_value());
        ASSERT(*alg == pkcs8::Algorithm::ML_DSA_65);
    }
    TEST_END("PKCS#8 OID mapping")
}

void test_pkcs8_ml_dsa() {
    std::cout << "\n=== ML-DSA PKCS#8 Tests ===" << std::endl;

    TEST("ML-DSA-44 key round-trip (DER)")
    {
        mldsa::MLDSA44 dsa;
        auto [pk, sk] = dsa.keygen();

        // Encode to PKCS#8 DER
        auto sk_der = pkcs8::encode_private_key_der(pkcs8::Algorithm::ML_DSA_44, sk);
        auto pk_der = pkcs8::encode_public_key_der(pkcs8::Algorithm::ML_DSA_44, pk);

        // Decode from DER
        auto sk_info = pkcs8::decode_private_key_der(sk_der);
        auto pk_info = pkcs8::decode_public_key_der(pk_der);

        ASSERT(sk_info.has_value());
        ASSERT(pk_info.has_value());
        ASSERT(sk_info->algorithm == pkcs8::Algorithm::ML_DSA_44);
        ASSERT(pk_info->algorithm == pkcs8::Algorithm::ML_DSA_44);
        ASSERT(sk_info->private_key == sk);
        ASSERT(pk_info->public_key == pk);
    }
    TEST_END("ML-DSA-44 key round-trip (DER)")

    TEST("ML-DSA-65 key round-trip (PEM)")
    {
        mldsa::MLDSA65 dsa;
        auto [pk, sk] = dsa.keygen();

        // Encode to PEM
        auto sk_pem = pkcs8::encode_private_key_pem(pkcs8::Algorithm::ML_DSA_65, sk);
        auto pk_pem = pkcs8::encode_public_key_pem(pkcs8::Algorithm::ML_DSA_65, pk);

        // Verify PEM headers
        ASSERT(sk_pem.find("-----BEGIN PRIVATE KEY-----") != std::string::npos);
        ASSERT(pk_pem.find("-----BEGIN PUBLIC KEY-----") != std::string::npos);

        // Decode from PEM
        auto sk_info = pkcs8::decode_private_key_pem(sk_pem);
        auto pk_info = pkcs8::decode_public_key_pem(pk_pem);

        ASSERT(sk_info.has_value());
        ASSERT(pk_info.has_value());
        ASSERT(sk_info->algorithm == pkcs8::Algorithm::ML_DSA_65);
        ASSERT(pk_info->algorithm == pkcs8::Algorithm::ML_DSA_65);
        ASSERT(sk_info->private_key == sk);
        ASSERT(pk_info->public_key == pk);
    }
    TEST_END("ML-DSA-65 key round-trip (PEM)")

    TEST("ML-DSA-87 sign/verify with decoded key")
    {
        mldsa::MLDSA87 dsa;
        auto [pk, sk] = dsa.keygen();

        // Encode keys
        auto sk_pem = pkcs8::encode_private_key_pem(pkcs8::Algorithm::ML_DSA_87, sk);
        auto pk_pem = pkcs8::encode_public_key_pem(pkcs8::Algorithm::ML_DSA_87, pk);

        // Decode keys
        auto sk_info = pkcs8::decode_private_key_pem(sk_pem);
        auto pk_info = pkcs8::decode_public_key_pem(pk_pem);

        ASSERT(sk_info.has_value());
        ASSERT(pk_info.has_value());

        // Sign with decoded key
        std::vector<uint8_t> message = {'t', 'e', 's', 't'};
        auto sig = dsa.sign(sk_info->private_key, message);

        // Verify with decoded key
        bool valid = dsa.verify(pk_info->public_key, message, sig);
        ASSERT(valid);
    }
    TEST_END("ML-DSA-87 sign/verify with decoded key")
}

void test_pkcs8_slh_dsa() {
    std::cout << "\n=== SLH-DSA PKCS#8 Tests ===" << std::endl;

    TEST("SLH-DSA-SHA2-128s key round-trip")
    {
        slhdsa::SLHDSA_SHA2_128s dsa;
        auto [sk, pk] = dsa.keygen();

        // Encode
        auto sk_pem = pkcs8::encode_private_key_pem(pkcs8::Algorithm::SLH_DSA_SHA2_128s, sk);
        auto pk_pem = pkcs8::encode_public_key_pem(pkcs8::Algorithm::SLH_DSA_SHA2_128s, pk);

        // Decode
        auto sk_info = pkcs8::decode_private_key_pem(sk_pem);
        auto pk_info = pkcs8::decode_public_key_pem(pk_pem);

        ASSERT(sk_info.has_value());
        ASSERT(pk_info.has_value());
        ASSERT(sk_info->algorithm == pkcs8::Algorithm::SLH_DSA_SHA2_128s);
        ASSERT(pk_info->algorithm == pkcs8::Algorithm::SLH_DSA_SHA2_128s);
        ASSERT(sk_info->private_key == sk);
        ASSERT(pk_info->public_key == pk);
    }
    TEST_END("SLH-DSA-SHA2-128s key round-trip")

    TEST("SLH-DSA-SHAKE-128f sign/verify with decoded key")
    {
        slhdsa::SLHDSA_SHAKE_128f dsa;
        auto [sk, pk] = dsa.keygen();

        // Round-trip through PEM
        auto sk_pem = pkcs8::encode_private_key_pem(pkcs8::Algorithm::SLH_DSA_SHAKE_128f, sk);
        auto pk_pem = pkcs8::encode_public_key_pem(pkcs8::Algorithm::SLH_DSA_SHAKE_128f, pk);

        auto sk_info = pkcs8::decode_private_key_pem(sk_pem);
        auto pk_info = pkcs8::decode_public_key_pem(pk_pem);

        ASSERT(sk_info.has_value());
        ASSERT(pk_info.has_value());

        // Sign and verify
        std::vector<uint8_t> message = {'h', 'e', 'l', 'l', 'o'};
        auto sig = dsa.sign(sk_info->private_key, message);
        bool valid = dsa.verify(pk_info->public_key, message, sig);
        ASSERT(valid);
    }
    TEST_END("SLH-DSA-SHAKE-128f sign/verify with decoded key")
}

void test_pkcs8_ml_kem() {
    std::cout << "\n=== ML-KEM PKCS#8 Tests ===" << std::endl;

    TEST("ML-KEM-512 key round-trip")
    {
        mlkem::MLKEM512 kem;
        auto [ek, dk] = kem.keygen();

        // Encode (ek is public, dk is private)
        auto dk_pem = pkcs8::encode_private_key_pem(pkcs8::Algorithm::ML_KEM_512, dk);
        auto ek_pem = pkcs8::encode_public_key_pem(pkcs8::Algorithm::ML_KEM_512, ek);

        // Decode
        auto dk_info = pkcs8::decode_private_key_pem(dk_pem);
        auto ek_info = pkcs8::decode_public_key_pem(ek_pem);

        ASSERT(dk_info.has_value());
        ASSERT(ek_info.has_value());
        ASSERT(dk_info->algorithm == pkcs8::Algorithm::ML_KEM_512);
        ASSERT(ek_info->algorithm == pkcs8::Algorithm::ML_KEM_512);
        ASSERT(dk_info->private_key == dk);
        ASSERT(ek_info->public_key == ek);
    }
    TEST_END("ML-KEM-512 key round-trip")

    TEST("ML-KEM-768 encaps/decaps with decoded key")
    {
        mlkem::MLKEM768 kem;
        auto [ek, dk] = kem.keygen();

        // Round-trip through PEM
        auto dk_pem = pkcs8::encode_private_key_pem(pkcs8::Algorithm::ML_KEM_768, dk);
        auto ek_pem = pkcs8::encode_public_key_pem(pkcs8::Algorithm::ML_KEM_768, ek);

        auto dk_info = pkcs8::decode_private_key_pem(dk_pem);
        auto ek_info = pkcs8::decode_public_key_pem(ek_pem);

        ASSERT(dk_info.has_value());
        ASSERT(ek_info.has_value());

        // Encapsulate with decoded public key
        auto [K1, c] = kem.encaps(ek_info->public_key);

        // Decapsulate with decoded private key
        auto K2 = kem.decaps(dk_info->private_key, c);

        ASSERT(K1 == K2);
    }
    TEST_END("ML-KEM-768 encaps/decaps with decoded key")

    TEST("ML-KEM-1024 key round-trip (DER)")
    {
        mlkem::MLKEM1024 kem;
        auto [ek, dk] = kem.keygen();

        // Use DER format
        auto dk_der = pkcs8::encode_private_key_der(pkcs8::Algorithm::ML_KEM_1024, dk);
        auto ek_der = pkcs8::encode_public_key_der(pkcs8::Algorithm::ML_KEM_1024, ek);

        auto dk_info = pkcs8::decode_private_key_der(dk_der);
        auto ek_info = pkcs8::decode_public_key_der(ek_der);

        ASSERT(dk_info.has_value());
        ASSERT(ek_info.has_value());
        ASSERT(dk_info->private_key == dk);
        ASSERT(ek_info->public_key == ek);
    }
    TEST_END("ML-KEM-1024 key round-trip (DER)")
}

void test_pkcs8_error_handling() {
    std::cout << "\n=== Error Handling Tests ===" << std::endl;

    TEST("Invalid PEM format")
    {
        auto result = pkcs8::decode_private_key_pem("not a pem");
        ASSERT(!result.has_value());
    }
    TEST_END("Invalid PEM format")

    TEST("Wrong PEM label")
    {
        auto result = pem::decode("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----", "PUBLIC KEY");
        ASSERT(!result.has_value());
    }
    TEST_END("Wrong PEM label")

    TEST("Invalid DER data")
    {
        std::vector<uint8_t> garbage = {0xFF, 0xFF, 0xFF, 0xFF};
        auto result = pkcs8::decode_private_key_der(garbage);
        ASSERT(!result.has_value());
    }
    TEST_END("Invalid DER data")

    TEST("Unknown OID")
    {
        auto alg = pkcs8::algorithm_from_oid("1.2.3.4.5.6.7.8");
        ASSERT(!alg.has_value());
    }
    TEST_END("Unknown OID")
}

void test_pem_output_format() {
    std::cout << "\n=== PEM Output Format Tests ===" << std::endl;

    TEST("PEM line length")
    {
        mldsa::MLDSA65 dsa;
        auto [pk, sk] = dsa.keygen();

        auto pem = pkcs8::encode_public_key_pem(pkcs8::Algorithm::ML_DSA_65, pk);

        // Check that no content line exceeds 64 characters
        std::istringstream stream(pem);
        std::string line;
        while (std::getline(stream, line)) {
            if (line.find("-----") != std::string::npos) continue;
            ASSERT(line.size() <= 64);
        }
    }
    TEST_END("PEM line length")

    TEST("Print sample PEM output")
    {
        mldsa::MLDSA44 dsa;
        auto [pk, sk] = dsa.keygen();

        auto pk_pem = pkcs8::encode_public_key_pem(pkcs8::Algorithm::ML_DSA_44, pk);

        std::cout << std::endl << "  Sample ML-DSA-44 Public Key (first 300 chars):" << std::endl;
        std::cout << "  " << pk_pem.substr(0, 300) << "..." << std::endl;
    }
    TEST_END("Print sample PEM output")
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  PKCS#8 Key Format Tests" << std::endl;
    std::cout << "========================================" << std::endl;

    // ASN.1 tests
    std::cout << "\n=== ASN.1 Encoding Tests ===" << std::endl;
    test_asn1_length_encoding();
    test_asn1_oid_encoding();
    test_asn1_sequence();
    test_asn1_octet_string();
    test_asn1_bit_string();

    // PEM tests
    std::cout << "\n=== PEM Encoding Tests ===" << std::endl;
    test_pem_base64();
    test_pem_format();

    // PKCS#8 tests
    test_pkcs8_oid_mapping();
    test_pkcs8_ml_dsa();
    test_pkcs8_slh_dsa();
    test_pkcs8_ml_kem();
    test_pkcs8_error_handling();
    test_pem_output_format();

    std::cout << "\n========================================" << std::endl;
    std::cout << "  Results: " << tests_passed << " passed, "
              << tests_failed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
