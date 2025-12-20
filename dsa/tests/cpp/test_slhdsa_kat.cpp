/**
 * SLH-DSA Known Answer Tests (KAT)
 * Based on NIST ACVP Test Vectors for FIPS 205
 *
 * These test vectors are from the official NIST ACVP-Server repository:
 * https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/SLH-DSA-keyGen-FIPS205
 */

#include "slhdsa/slh_dsa.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>
#include <algorithm>

using namespace slhdsa;

// Test counters
static int tests_passed = 0;
static int tests_failed = 0;

// Helper function to convert hex string to bytes
std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        uint8_t byte = static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// Helper function to convert bytes to hex string
std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    for (auto b : bytes) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
    }
    return ss.str();
}

// Helper function to compare vectors
bool compare_vectors(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) return false;
    return std::memcmp(a.data(), b.data(), a.size()) == 0;
}

#define KAT_TEST(name) \
    std::cout << "KAT: " << name << "... " << std::flush; \
    try

#define KAT_END \
    std::cout << "PASSED" << std::endl; \
    ++tests_passed; \
    } catch (const std::exception& e) { \
        std::cout << "FAILED: " << e.what() << std::endl; \
        ++tests_failed; \
    } catch (...) { \
        std::cout << "FAILED: Unknown exception" << std::endl; \
        ++tests_failed; \
    }

#define KAT_ASSERT(cond, msg) \
    if (!(cond)) throw std::runtime_error(msg)

/**
 * SLH-DSA-SHA2-128s KeyGen KAT Test Vectors
 * From NIST ACVP SLH-DSA-keyGen-FIPS205 tgId=1
 */
void test_slhdsa_sha2_128s_keygen_kat() {
    SLHDSA_SHA2_128s dsa;

    // Test Case 1
    KAT_TEST("SLH-DSA-SHA2-128s KeyGen tcId=1") {
        auto sk_seed = hex_to_bytes("173D04C938C1C36BF289C3C022D04B14");
        auto sk_prf = hex_to_bytes("63AE23C41AA546DA589774AC20B745C4");
        auto pk_seed = hex_to_bytes("0D794777914C99766827F0F09CA972BE");

        std::string expected_pk = "0D794777914C99766827F0F09CA972BE0162C10219D422ADBA1359E6AA65299C";

        auto [sk, pk] = dsa.keygen(sk_seed, sk_prf, pk_seed);

        // SLH-DSA-SHA2-128s: pk = 32 bytes, sk = 64 bytes
        KAT_ASSERT(pk.size() == 32, "Public key size mismatch");
        KAT_ASSERT(sk.size() == 64, "Secret key size mismatch");

        std::string pk_hex = bytes_to_hex(pk);
        std::transform(pk_hex.begin(), pk_hex.end(), pk_hex.begin(), ::toupper);
        std::transform(expected_pk.begin(), expected_pk.end(), expected_pk.begin(), ::toupper);

        KAT_ASSERT(pk_hex == expected_pk,
            "Public key mismatch:\n  Expected: " + expected_pk + "\n  Got: " + pk_hex);
    KAT_END

    // Test Case 2
    KAT_TEST("SLH-DSA-SHA2-128s KeyGen tcId=2") {
        auto sk_seed = hex_to_bytes("91C7F86881416D5D3E0EC46AA9C35047");
        auto sk_prf = hex_to_bytes("506332ADCBDED3F2836DD7EDC30AEA0C");
        auto pk_seed = hex_to_bytes("BBBFEED9AD96AF5D8CB4E876BBEB07D1");

        std::string expected_pk = "BBBFEED9AD96AF5D8CB4E876BBEB07D11B4EA0A9EB42B9E7D2DBC2365F39E1DC";

        auto [sk, pk] = dsa.keygen(sk_seed, sk_prf, pk_seed);

        std::string pk_hex = bytes_to_hex(pk);
        std::transform(pk_hex.begin(), pk_hex.end(), pk_hex.begin(), ::toupper);
        std::transform(expected_pk.begin(), expected_pk.end(), expected_pk.begin(), ::toupper);

        KAT_ASSERT(pk_hex == expected_pk,
            "Public key mismatch:\n  Expected: " + expected_pk + "\n  Got: " + pk_hex);
    KAT_END

    // Test Case 3
    KAT_TEST("SLH-DSA-SHA2-128s KeyGen tcId=3") {
        auto sk_seed = hex_to_bytes("FCC9EEFD4C2CC975E8E5C341B0BD8F89");
        auto sk_prf = hex_to_bytes("152F1D461E5287D9BD83F48E0D70A47F");
        auto pk_seed = hex_to_bytes("72C9655C012CA033C81EE260E5A7CBEA");

        std::string expected_pk = "72C9655C012CA033C81EE260E5A7CBEA672854E720695ECE0CFDF751015B6A68";

        auto [sk, pk] = dsa.keygen(sk_seed, sk_prf, pk_seed);

        std::string pk_hex = bytes_to_hex(pk);
        std::transform(pk_hex.begin(), pk_hex.end(), pk_hex.begin(), ::toupper);
        std::transform(expected_pk.begin(), expected_pk.end(), expected_pk.begin(), ::toupper);

        KAT_ASSERT(pk_hex == expected_pk,
            "Public key mismatch:\n  Expected: " + expected_pk + "\n  Got: " + pk_hex);
    KAT_END
}

/**
 * SLH-DSA-SHAKE-128s KeyGen KAT Test Vectors
 * From NIST ACVP SLH-DSA-keyGen-FIPS205 tgId=2
 */
void test_slhdsa_shake_128s_keygen_kat() {
    SLHDSA_SHAKE_128s dsa;

    // Test Case 11
    KAT_TEST("SLH-DSA-SHAKE-128s KeyGen tcId=11") {
        auto sk_seed = hex_to_bytes("C151951F3811029239B74ADD24C506AF");
        auto sk_prf = hex_to_bytes("DD30363E156E6FE936EC6ED0231FEB5C");
        auto pk_seed = hex_to_bytes("529FFE86200D1F32C2B60D0CD909F190");

        std::string expected_pk = "529FFE86200D1F32C2B60D0CD909F1900761F9B727AFA724B47223016BB5B2BA";

        auto [sk, pk] = dsa.keygen(sk_seed, sk_prf, pk_seed);

        KAT_ASSERT(pk.size() == 32, "Public key size mismatch");
        KAT_ASSERT(sk.size() == 64, "Secret key size mismatch");

        std::string pk_hex = bytes_to_hex(pk);
        std::transform(pk_hex.begin(), pk_hex.end(), pk_hex.begin(), ::toupper);
        std::transform(expected_pk.begin(), expected_pk.end(), expected_pk.begin(), ::toupper);

        KAT_ASSERT(pk_hex == expected_pk,
            "Public key mismatch:\n  Expected: " + expected_pk + "\n  Got: " + pk_hex);
    KAT_END

    // Test Case 12
    KAT_TEST("SLH-DSA-SHAKE-128s KeyGen tcId=12") {
        auto sk_seed = hex_to_bytes("D3ADF41FF57EED108BEF2D8733F4C2B0");
        auto sk_prf = hex_to_bytes("09A00EF4596B23E1FFD5136C135A713A");
        auto pk_seed = hex_to_bytes("B64302C8D20FB89AA2414307D44E1F9C");

        std::string expected_pk = "B64302C8D20FB89AA2414307D44E1F9C6EFA39EBBA94B0633C900644B81DE2B9";

        auto [sk, pk] = dsa.keygen(sk_seed, sk_prf, pk_seed);

        std::string pk_hex = bytes_to_hex(pk);
        std::transform(pk_hex.begin(), pk_hex.end(), pk_hex.begin(), ::toupper);
        std::transform(expected_pk.begin(), expected_pk.end(), expected_pk.begin(), ::toupper);

        KAT_ASSERT(pk_hex == expected_pk,
            "Public key mismatch:\n  Expected: " + expected_pk + "\n  Got: " + pk_hex);
    KAT_END
}

/**
 * SLH-DSA-SHA2-128f KeyGen KAT Test Vectors
 * From NIST ACVP SLH-DSA-keyGen-FIPS205 tgId=3
 */
void test_slhdsa_sha2_128f_keygen_kat() {
    SLHDSA_SHA2_128f dsa;

    // Test Case 21
    KAT_TEST("SLH-DSA-SHA2-128f KeyGen tcId=21") {
        auto sk_seed = hex_to_bytes("C42BCB3B5A6F331F5CCE899253C6D9E2");
        auto sk_prf = hex_to_bytes("9FF2B7EAD7A04BAB1794DB8CC659C3B4");
        auto pk_seed = hex_to_bytes("A868F1BD5DEBC12D4C9FAD66AABD0A94");

        std::string expected_pk = "A868F1BD5DEBC12D4C9FAD66AABD0A94B546DF247BE4C457F3D467CDFCFABD39";

        auto [sk, pk] = dsa.keygen(sk_seed, sk_prf, pk_seed);

        KAT_ASSERT(pk.size() == 32, "Public key size mismatch");

        std::string pk_hex = bytes_to_hex(pk);
        std::transform(pk_hex.begin(), pk_hex.end(), pk_hex.begin(), ::toupper);
        std::transform(expected_pk.begin(), expected_pk.end(), expected_pk.begin(), ::toupper);

        KAT_ASSERT(pk_hex == expected_pk,
            "Public key mismatch:\n  Expected: " + expected_pk + "\n  Got: " + pk_hex);
    KAT_END
}

/**
 * SLH-DSA Sign/Verify Consistency Tests
 */
void test_slhdsa_sign_verify_consistency() {
    KAT_TEST("SLH-DSA-SHAKE-128f Sign/Verify consistency") {
        SLHDSA_SHAKE_128f dsa;

        auto [sk, pk] = dsa.keygen();

        std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};

        // Deterministic signing
        auto sig1 = dsa.sign(sk, message, {}, false);
        auto sig2 = dsa.sign(sk, message, {}, false);

        // SLH-DSA-SHAKE-128f signature size
        KAT_ASSERT(sig1.size() == 17088, "Signature size mismatch");

        KAT_ASSERT(dsa.verify(pk, message, sig1), "Valid signature failed verification");

        // Modify message, should fail
        message[0] ^= 0x01;
        KAT_ASSERT(!dsa.verify(pk, message, sig1), "Modified message should fail verification");
    KAT_END

    KAT_TEST("SLH-DSA-SHA2-128s Sign/Verify consistency") {
        SLHDSA_SHA2_128s dsa;

        auto [sk, pk] = dsa.keygen();

        std::vector<uint8_t> message = {'T', 'e', 's', 't', ' ', 'M', 's', 'g'};

        auto sig = dsa.sign(sk, message, {}, false);

        // SLH-DSA-SHA2-128s signature size
        KAT_ASSERT(sig.size() == 7856, "Signature size mismatch");
        KAT_ASSERT(dsa.verify(pk, message, sig), "Valid signature failed verification");
    KAT_END
}

/**
 * SLH-DSA Context String Tests
 */
void test_slhdsa_context() {
    KAT_TEST("SLH-DSA-SHAKE-128f context string handling") {
        SLHDSA_SHAKE_128f dsa;
        auto [sk, pk] = dsa.keygen();

        std::vector<uint8_t> message = {'M', 'e', 's', 's', 'a', 'g', 'e'};
        std::vector<uint8_t> ctx1 = {'c', 't', 'x', '1'};
        std::vector<uint8_t> ctx2 = {'c', 't', 'x', '2'};

        auto sig = dsa.sign(sk, message, ctx1, false);

        // Correct context should verify
        KAT_ASSERT(dsa.verify(pk, message, sig, ctx1), "Correct context should verify");

        // Wrong context should fail
        KAT_ASSERT(!dsa.verify(pk, message, sig, ctx2), "Wrong context should fail");

        // No context should fail
        KAT_ASSERT(!dsa.verify(pk, message, sig), "No context should fail when signed with context");
    KAT_END
}

/**
 * SLH-DSA Key Sizes Test
 */
void test_slhdsa_key_sizes() {
    KAT_TEST("SLH-DSA key and signature sizes") {
        std::vector<uint8_t> test_msg = {'t', 'e', 's', 't'};

        // 128-bit security (small)
        {
            SLHDSA_SHA2_128s dsa;
            auto [sk, pk] = dsa.keygen();
            auto sig = dsa.sign(sk, test_msg, {}, false);
            KAT_ASSERT(pk.size() == 32, "SHA2-128s pk size");
            KAT_ASSERT(sk.size() == 64, "SHA2-128s sk size");
            KAT_ASSERT(sig.size() == 7856, "SHA2-128s sig size");
        }

        // 128-bit security (fast)
        {
            SLHDSA_SHA2_128f dsa;
            auto [sk, pk] = dsa.keygen();
            auto sig = dsa.sign(sk, test_msg, {}, false);
            KAT_ASSERT(pk.size() == 32, "SHA2-128f pk size");
            KAT_ASSERT(sk.size() == 64, "SHA2-128f sk size");
            KAT_ASSERT(sig.size() == 17088, "SHA2-128f sig size");
        }

        // 192-bit security (small)
        {
            SLHDSA_SHA2_192s dsa;
            auto [sk, pk] = dsa.keygen();
            auto sig = dsa.sign(sk, test_msg, {}, false);
            KAT_ASSERT(pk.size() == 48, "SHA2-192s pk size");
            KAT_ASSERT(sk.size() == 96, "SHA2-192s sk size");
            KAT_ASSERT(sig.size() == 16224, "SHA2-192s sig size");
        }

        // 256-bit security (small)
        {
            SLHDSA_SHA2_256s dsa;
            auto [sk, pk] = dsa.keygen();
            auto sig = dsa.sign(sk, test_msg, {}, false);
            KAT_ASSERT(pk.size() == 64, "SHA2-256s pk size");
            KAT_ASSERT(sk.size() == 128, "SHA2-256s sk size");
            KAT_ASSERT(sig.size() == 29792, "SHA2-256s sig size");
        }
    KAT_END
}

int main() {
    std::cout << "=== SLH-DSA Known Answer Tests (FIPS 205) ===" << std::endl << std::endl;

    std::cout << "--- KeyGen KAT Tests ---" << std::endl;
    test_slhdsa_sha2_128s_keygen_kat();
    test_slhdsa_shake_128s_keygen_kat();
    test_slhdsa_sha2_128f_keygen_kat();

    std::cout << std::endl << "--- Sign/Verify Consistency Tests ---" << std::endl;
    test_slhdsa_sign_verify_consistency();

    std::cout << std::endl << "--- Context String Tests ---" << std::endl;
    test_slhdsa_context();

    std::cout << std::endl << "--- Key/Signature Size Tests ---" << std::endl;
    test_slhdsa_key_sizes();

    std::cout << std::endl << "=== KAT Test Results ===" << std::endl;
    std::cout << "Passed: " << tests_passed << std::endl;
    std::cout << "Failed: " << tests_failed << std::endl;

    if (tests_failed > 0) {
        std::cout << std::endl << "WARNING: Some KAT tests failed!" << std::endl;
        std::cout << "This may indicate non-compliance with FIPS 205." << std::endl;
    } else {
        std::cout << std::endl << "All KAT tests passed." << std::endl;
    }

    return tests_failed > 0 ? 1 : 0;
}
