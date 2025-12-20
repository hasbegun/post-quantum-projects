/**
 * ML-DSA Known Answer Tests (KAT)
 * Based on NIST ACVP Test Vectors for FIPS 204
 *
 * These test vectors are from the official NIST ACVP-Server repository:
 * https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/ML-DSA-keyGen-FIPS204
 */

#include "mldsa/mldsa.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <cstring>

using namespace mldsa;

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
 * ML-DSA-44 KeyGen KAT Test Vectors
 * From NIST ACVP ML-DSA-keyGen-FIPS204
 */
void test_mldsa44_keygen_kat() {
    MLDSA44 dsa;

    // Test Case 1 from NIST ACVP
    KAT_TEST("ML-DSA-44 KeyGen tcId=1") {
        auto seed = hex_to_bytes("D71361C000F9A7BC99DFB425BCB6BB27C32C36AB444FF3708B2D93B4E66D5B5B");

        // Expected public key (first 64 bytes for verification)
        std::string expected_pk_prefix = "B845FA2881407A59183071629B08223128116014FB58FF6BB4C8C9FE19CF5B0B";

        auto [pk, sk] = dsa.keygen(seed);

        // Verify key sizes
        KAT_ASSERT(pk.size() == 1312, "Public key size mismatch");
        KAT_ASSERT(sk.size() == 2560, "Secret key size mismatch");

        // Verify first 32 bytes of public key match
        std::string pk_prefix = bytes_to_hex(std::vector<uint8_t>(pk.begin(), pk.begin() + 32));

        // Convert both to uppercase for comparison
        std::transform(pk_prefix.begin(), pk_prefix.end(), pk_prefix.begin(), ::toupper);
        std::transform(expected_pk_prefix.begin(), expected_pk_prefix.end(), expected_pk_prefix.begin(), ::toupper);

        KAT_ASSERT(pk_prefix == expected_pk_prefix,
            "Public key prefix mismatch:\n  Expected: " + expected_pk_prefix + "\n  Got: " + pk_prefix);
    KAT_END

    // Test Case 2 from NIST ACVP
    KAT_TEST("ML-DSA-44 KeyGen tcId=2") {
        auto seed = hex_to_bytes("AB611F971C44D1B755D289E0FCFEE70F0EB5D9FDFB1BC31CA894A75794235AF8");

        std::string expected_pk_prefix = "D712599A161ECD99EF5B7A04313D5507D612565F03AA9695ED7C2DF1CFA18056";

        auto [pk, sk] = dsa.keygen(seed);

        KAT_ASSERT(pk.size() == 1312, "Public key size mismatch");

        std::string pk_prefix = bytes_to_hex(std::vector<uint8_t>(pk.begin(), pk.begin() + 32));
        std::transform(pk_prefix.begin(), pk_prefix.end(), pk_prefix.begin(), ::toupper);
        std::transform(expected_pk_prefix.begin(), expected_pk_prefix.end(), expected_pk_prefix.begin(), ::toupper);

        KAT_ASSERT(pk_prefix == expected_pk_prefix,
            "Public key prefix mismatch:\n  Expected: " + expected_pk_prefix + "\n  Got: " + pk_prefix);
    KAT_END

    // Test Case 3 from NIST ACVP
    KAT_TEST("ML-DSA-44 KeyGen tcId=3") {
        auto seed = hex_to_bytes("E0264F45D58EA02C8738C006CAED00F3ED9296E2F6BBF4D158FE71C2983FDF38");

        std::string expected_pk_prefix = "8A0DDD293EEA646F5A09A0513991CEAF8F5D7D458CF40F7C1F18F6DBA8F4C2F8";

        auto [pk, sk] = dsa.keygen(seed);

        std::string pk_prefix = bytes_to_hex(std::vector<uint8_t>(pk.begin(), pk.begin() + 32));
        std::transform(pk_prefix.begin(), pk_prefix.end(), pk_prefix.begin(), ::toupper);
        std::transform(expected_pk_prefix.begin(), expected_pk_prefix.end(), expected_pk_prefix.begin(), ::toupper);

        KAT_ASSERT(pk_prefix == expected_pk_prefix,
            "Public key prefix mismatch:\n  Expected: " + expected_pk_prefix + "\n  Got: " + pk_prefix);
    KAT_END
}

/**
 * ML-DSA-65 KeyGen KAT Test Vectors
 */
void test_mldsa65_keygen_kat() {
    MLDSA65 dsa;

    // Note: These test vectors would come from the ML-DSA-65 section of ACVP
    // For now, we verify that keygen produces consistent results with same seed

    KAT_TEST("ML-DSA-65 KeyGen determinism") {
        auto seed = hex_to_bytes("0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20");

        auto [pk1, sk1] = dsa.keygen(seed);
        auto [pk2, sk2] = dsa.keygen(seed);

        KAT_ASSERT(pk1.size() == 1952, "Public key size mismatch");
        KAT_ASSERT(sk1.size() == 4032, "Secret key size mismatch");
        KAT_ASSERT(compare_vectors(pk1, pk2), "KeyGen not deterministic");
        KAT_ASSERT(compare_vectors(sk1, sk2), "KeyGen not deterministic");
    KAT_END
}

/**
 * ML-DSA-87 KeyGen KAT Test Vectors
 */
void test_mldsa87_keygen_kat() {
    MLDSA87 dsa;

    KAT_TEST("ML-DSA-87 KeyGen determinism") {
        auto seed = hex_to_bytes("FFEEDDCCBBAA99887766554433221100F0E0D0C0B0A090807060504030201000");

        auto [pk1, sk1] = dsa.keygen(seed);
        auto [pk2, sk2] = dsa.keygen(seed);

        KAT_ASSERT(pk1.size() == 2592, "Public key size mismatch");
        KAT_ASSERT(sk1.size() == 4896, "Secret key size mismatch");
        KAT_ASSERT(compare_vectors(pk1, pk2), "KeyGen not deterministic");
        KAT_ASSERT(compare_vectors(sk1, sk2), "KeyGen not deterministic");
    KAT_END
}

/**
 * ML-DSA Sign/Verify Consistency Tests
 */
void test_mldsa_sign_verify_consistency() {
    KAT_TEST("ML-DSA-44 Sign/Verify consistency") {
        MLDSA44 dsa;
        auto seed = hex_to_bytes("D71361C000F9A7BC99DFB425BCB6BB27C32C36AB444FF3708B2D93B4E66D5B5B");

        auto [pk, sk] = dsa.keygen(seed);

        std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};

        // Deterministic signing
        auto sig1 = dsa.sign(sk, message, {}, true);
        auto sig2 = dsa.sign(sk, message, {}, true);

        KAT_ASSERT(sig1.size() == 2420, "Signature size mismatch");
        KAT_ASSERT(compare_vectors(sig1, sig2), "Deterministic signing not consistent");
        KAT_ASSERT(dsa.verify(pk, message, sig1), "Valid signature failed verification");

        // Modify message, should fail
        message[0] ^= 0x01;
        KAT_ASSERT(!dsa.verify(pk, message, sig1), "Modified message should fail verification");
    KAT_END

    KAT_TEST("ML-DSA-65 Sign/Verify consistency") {
        MLDSA65 dsa;
        auto seed = hex_to_bytes("0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20");

        auto [pk, sk] = dsa.keygen(seed);

        std::vector<uint8_t> message = {'T', 'e', 's', 't', ' ', 'M', 'e', 's', 's', 'a', 'g', 'e'};

        auto sig = dsa.sign(sk, message, {}, true);

        KAT_ASSERT(sig.size() == 3309, "Signature size mismatch");
        KAT_ASSERT(dsa.verify(pk, message, sig), "Valid signature failed verification");
    KAT_END

    KAT_TEST("ML-DSA-87 Sign/Verify consistency") {
        MLDSA87 dsa;
        auto seed = hex_to_bytes("FFEEDDCCBBAA99887766554433221100F0E0D0C0B0A090807060504030201000");

        auto [pk, sk] = dsa.keygen(seed);

        std::vector<uint8_t> message = {'A', 'n', 'o', 't', 'h', 'e', 'r', ' ', 'T', 'e', 's', 't'};

        auto sig = dsa.sign(sk, message, {}, true);

        KAT_ASSERT(sig.size() == 4627, "Signature size mismatch");
        KAT_ASSERT(dsa.verify(pk, message, sig), "Valid signature failed verification");
    KAT_END
}

/**
 * ML-DSA Context String Tests
 */
void test_mldsa_context() {
    KAT_TEST("ML-DSA-44 context string handling") {
        MLDSA44 dsa;
        auto [pk, sk] = dsa.keygen();

        std::vector<uint8_t> message = {'M', 'e', 's', 's', 'a', 'g', 'e'};
        std::vector<uint8_t> ctx1 = {'c', 't', 'x', '1'};
        std::vector<uint8_t> ctx2 = {'c', 't', 'x', '2'};

        auto sig = dsa.sign(sk, message, ctx1, true);

        // Correct context should verify
        KAT_ASSERT(dsa.verify(pk, message, sig, ctx1), "Correct context should verify");

        // Wrong context should fail
        KAT_ASSERT(!dsa.verify(pk, message, sig, ctx2), "Wrong context should fail");

        // No context should fail
        KAT_ASSERT(!dsa.verify(pk, message, sig), "No context should fail when signed with context");
    KAT_END
}

int main() {
    std::cout << "=== ML-DSA Known Answer Tests (FIPS 204) ===" << std::endl << std::endl;

    std::cout << "--- KeyGen KAT Tests ---" << std::endl;
    test_mldsa44_keygen_kat();
    test_mldsa65_keygen_kat();
    test_mldsa87_keygen_kat();

    std::cout << std::endl << "--- Sign/Verify Consistency Tests ---" << std::endl;
    test_mldsa_sign_verify_consistency();

    std::cout << std::endl << "--- Context String Tests ---" << std::endl;
    test_mldsa_context();

    std::cout << std::endl << "=== KAT Test Results ===" << std::endl;
    std::cout << "Passed: " << tests_passed << std::endl;
    std::cout << "Failed: " << tests_failed << std::endl;

    if (tests_failed > 0) {
        std::cout << std::endl << "WARNING: Some KAT tests failed!" << std::endl;
        std::cout << "This may indicate non-compliance with FIPS 204." << std::endl;
    } else {
        std::cout << std::endl << "All KAT tests passed." << std::endl;
    }

    return tests_failed > 0 ? 1 : 0;
}
