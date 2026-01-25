/**
 * Test suite for X.509 Composite Certificates
 *
 * Tests composite signatures (ML-DSA + ECDSA/Ed25519) and
 * composite certificate generation/verification.
 */

#include <iostream>
#include <vector>
#include <string>
#include <cstdint>
#include <cassert>

#include "common/composite.hpp"
#include "common/x509.hpp"
#include "common/pem.hpp"

// ============================================================================
// Test Framework
// ============================================================================

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    void test_##name(); \
    struct TestRunner_##name { \
        TestRunner_##name() { \
            std::cout << "Running " << #name << "... " << std::flush; \
            tests_run++; \
            try { \
                test_##name(); \
                tests_passed++; \
                std::cout << "PASSED\n"; \
            } catch (const std::exception& e) { \
                tests_failed++; \
                std::cout << "FAILED: " << e.what() << "\n"; \
            } catch (...) { \
                tests_failed++; \
                std::cout << "FAILED: Unknown exception\n"; \
            } \
        } \
    } test_runner_##name; \
    void test_##name()

#define ASSERT_TRUE(cond) \
    do { if (!(cond)) throw std::runtime_error("Assertion failed: " #cond); } while(0)

#define ASSERT_FALSE(cond) \
    do { if (cond) throw std::runtime_error("Assertion failed: NOT " #cond); } while(0)

#define ASSERT_EQ(a, b) \
    do { if ((a) != (b)) throw std::runtime_error("Assertion failed: " #a " == " #b); } while(0)

#define ASSERT_NE(a, b) \
    do { if ((a) == (b)) throw std::runtime_error("Assertion failed: " #a " != " #b); } while(0)

#define ASSERT_GT(a, b) \
    do { if (!((a) > (b))) throw std::runtime_error("Assertion failed: " #a " > " #b); } while(0)

#define ASSERT_THROW(expr, exc_type) \
    do { \
        bool caught = false; \
        try { expr; } catch (const exc_type&) { caught = true; } \
        if (!caught) throw std::runtime_error("Expected exception: " #exc_type); \
    } while(0)

// ============================================================================
// Composite Signature Tests
// ============================================================================

TEST(composite_available_algorithms) {
    auto algos = pqc::available_composite_algorithms();
    ASSERT_GT(algos.size(), 0);

    // Check expected algorithms are present
    bool found_p256 = false, found_ed25519 = false, found_p384 = false, found_ed448 = false;
    for (const auto& algo : algos) {
        if (algo.find("ECDSA-P256") != std::string::npos) found_p256 = true;
        if (algo.find("Ed25519") != std::string::npos) found_ed25519 = true;
        if (algo.find("ECDSA-P384") != std::string::npos) found_p384 = true;
        if (algo.find("Ed448") != std::string::npos) found_ed448 = true;
    }
    ASSERT_TRUE(found_p256);
    ASSERT_TRUE(found_ed25519);
    ASSERT_TRUE(found_p384);
    ASSERT_TRUE(found_ed448);
}

TEST(composite_is_composite_algorithm) {
    ASSERT_TRUE(pqc::is_composite_algorithm("MLDSA65-ECDSA-P256"));
    ASSERT_TRUE(pqc::is_composite_algorithm("MLDSA44-Ed25519"));
    ASSERT_TRUE(pqc::is_composite_algorithm("MLDSA87-Ed448"));
    ASSERT_FALSE(pqc::is_composite_algorithm("ML-DSA-65"));
    ASSERT_FALSE(pqc::is_composite_algorithm("ECDSA-P256"));
    ASSERT_FALSE(pqc::is_composite_algorithm("unknown"));
}

TEST(composite_get_oid) {
    auto oid1 = pqc::get_composite_oid("MLDSA44-ECDSA-P256");
    ASSERT_EQ(oid1, "1.3.6.1.5.5.7.6.41");

    auto oid2 = pqc::get_composite_oid("MLDSA65-ECDSA-P256");
    ASSERT_EQ(oid2, "1.3.6.1.5.5.7.6.45");

    auto oid3 = pqc::get_composite_oid("MLDSA65-Ed25519");
    ASSERT_EQ(oid3, "1.3.6.1.5.5.7.6.48");

    auto oid4 = pqc::get_composite_oid("MLDSA87-ECDSA-P384");
    ASSERT_EQ(oid4, "1.3.6.1.5.5.7.6.49");
}

// ============================================================================
// MLDSA44 + ECDSA-P256 Tests
// ============================================================================

TEST(composite_mldsa44_ecdsa_p256_keygen) {
    auto composite = pqc::create_composite_dsa("MLDSA44-ECDSA-P256");
    auto [pk, sk] = composite->keygen();

    // ML-DSA-44: pk=1312, sk=2560
    // ECDSA P-256: pk=65 (uncompressed), sk=32
    // sk format: pqc_sk || classical_sk || classical_pk
    ASSERT_EQ(pk.size(), 1312 + 65);
    ASSERT_EQ(sk.size(), 2560 + 32 + 65);

    ASSERT_EQ(composite->pqc_algorithm(), "ML-DSA-44");
    ASSERT_EQ(composite->classical_algorithm(), "ECDSA-P256");
}

TEST(composite_mldsa44_ecdsa_p256_sign_verify) {
    auto composite = pqc::create_composite_dsa("MLDSA44-ECDSA-P256");
    auto [pk, sk] = composite->keygen();

    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
    auto sig = composite->sign(sk, message);

    // ML-DSA-44 sig: 2420 bytes + ECDSA (variable, max ~72)
    ASSERT_GT(sig.size(), 2420);
    ASSERT_TRUE(composite->verify(pk, message, sig));
}

TEST(composite_mldsa44_ecdsa_p256_invalid_sig) {
    auto composite = pqc::create_composite_dsa("MLDSA44-ECDSA-P256");
    auto [pk, sk] = composite->keygen();

    std::vector<uint8_t> message = {'T', 'e', 's', 't'};
    auto sig = composite->sign(sk, message);

    // Corrupt PQC signature (first byte)
    sig[0] ^= 0xFF;
    ASSERT_FALSE(composite->verify(pk, message, sig));

    // Restore PQC, corrupt classical signature
    sig[0] ^= 0xFF;
    sig[2420] ^= 0xFF;  // After ML-DSA-44 signature
    ASSERT_FALSE(composite->verify(pk, message, sig));
}

TEST(composite_mldsa44_ecdsa_p256_wrong_message) {
    auto composite = pqc::create_composite_dsa("MLDSA44-ECDSA-P256");
    auto [pk, sk] = composite->keygen();

    std::vector<uint8_t> message1 = {'A', 'B', 'C'};
    std::vector<uint8_t> message2 = {'X', 'Y', 'Z'};

    auto sig = composite->sign(sk, message1);
    ASSERT_FALSE(composite->verify(pk, message2, sig));
}

TEST(composite_mldsa44_ecdsa_p256_split_keys) {
    auto composite = pqc::create_composite_dsa("MLDSA44-ECDSA-P256");
    auto [pk, sk] = composite->keygen();

    auto [pqc_pk, classical_pk] = composite->split_public_key(pk);
    ASSERT_EQ(pqc_pk.size(), 1312);
    ASSERT_EQ(classical_pk.size(), 65);
    ASSERT_EQ(classical_pk[0], 0x04);  // Uncompressed point marker

    auto [pqc_sk, classical_sk] = composite->split_secret_key(sk);
    ASSERT_EQ(pqc_sk.size(), 2560);
    ASSERT_EQ(classical_sk.size(), 32);
}

// ============================================================================
// MLDSA44 + Ed25519 Tests
// ============================================================================

TEST(composite_mldsa44_ed25519_keygen) {
    auto composite = pqc::create_composite_dsa("MLDSA44-Ed25519");
    auto [pk, sk] = composite->keygen();

    // ML-DSA-44: pk=1312, sk=2560
    // Ed25519: pk=32, sk=32
    // sk format: pqc_sk || classical_sk || classical_pk
    ASSERT_EQ(pk.size(), 1312 + 32);
    ASSERT_EQ(sk.size(), 2560 + 32 + 32);

    ASSERT_EQ(composite->classical_algorithm(), "Ed25519");
}

TEST(composite_mldsa44_ed25519_sign_verify) {
    auto composite = pqc::create_composite_dsa("MLDSA44-Ed25519");
    auto [pk, sk] = composite->keygen();

    std::vector<uint8_t> message = {'E', 'd', '2', '5', '5', '1', '9', ' ', 't', 'e', 's', 't'};
    auto sig = composite->sign(sk, message);

    // ML-DSA-44 sig: 2420 bytes + Ed25519: 64 bytes
    ASSERT_EQ(sig.size(), 2420 + 64);
    ASSERT_TRUE(composite->verify(pk, message, sig));
}

// ============================================================================
// MLDSA65 + ECDSA-P256 Tests
// ============================================================================

TEST(composite_mldsa65_ecdsa_p256_keygen) {
    auto composite = pqc::create_composite_dsa("MLDSA65-ECDSA-P256");
    auto [pk, sk] = composite->keygen();

    // ML-DSA-65: pk=1952, sk=4032
    // ECDSA P-256: pk=65, sk=32
    // sk format: pqc_sk || classical_sk || classical_pk
    ASSERT_EQ(pk.size(), 1952 + 65);
    ASSERT_EQ(sk.size(), 4032 + 32 + 65);
}

TEST(composite_mldsa65_ecdsa_p256_sign_verify) {
    auto composite = pqc::create_composite_dsa("MLDSA65-ECDSA-P256");
    auto [pk, sk] = composite->keygen();

    std::vector<uint8_t> message = {'M', 'L', 'D', 'S', 'A', '6', '5'};
    auto sig = composite->sign(sk, message);

    // ML-DSA-65 sig: 3309 bytes + ECDSA
    ASSERT_GT(sig.size(), 3309);
    ASSERT_TRUE(composite->verify(pk, message, sig));
}

TEST(composite_mldsa65_ecdsa_p256_both_required) {
    auto composite = pqc::create_composite_dsa("MLDSA65-ECDSA-P256");
    auto [pk, sk] = composite->keygen();

    std::vector<uint8_t> message = {'b', 'o', 't', 'h'};
    auto sig = composite->sign(sk, message);

    // Verify original
    ASSERT_TRUE(composite->verify(pk, message, sig));

    // Corrupt PQC part - should fail
    auto sig_bad_pqc = sig;
    sig_bad_pqc[100] ^= 0xFF;
    ASSERT_FALSE(composite->verify(pk, message, sig_bad_pqc));

    // Corrupt classical part - should fail
    auto sig_bad_classical = sig;
    sig_bad_classical[3309 + 10] ^= 0xFF;
    ASSERT_FALSE(composite->verify(pk, message, sig_bad_classical));
}

// ============================================================================
// MLDSA65 + ECDSA-P384 Tests
// ============================================================================

TEST(composite_mldsa65_ecdsa_p384_keygen) {
    auto composite = pqc::create_composite_dsa("MLDSA65-ECDSA-P384");
    auto [pk, sk] = composite->keygen();

    // ML-DSA-65: pk=1952, sk=4032
    // ECDSA P-384: pk=97 (uncompressed), sk=48
    // sk format: pqc_sk || classical_sk || classical_pk
    ASSERT_EQ(pk.size(), 1952 + 97);
    ASSERT_EQ(sk.size(), 4032 + 48 + 97);

    ASSERT_EQ(composite->classical_algorithm(), "ECDSA-P384");
}

TEST(composite_mldsa65_ecdsa_p384_sign_verify) {
    auto composite = pqc::create_composite_dsa("MLDSA65-ECDSA-P384");
    auto [pk, sk] = composite->keygen();

    std::vector<uint8_t> message = {'P', '3', '8', '4', ' ', 't', 'e', 's', 't'};
    auto sig = composite->sign(sk, message);

    ASSERT_GT(sig.size(), 3309);
    ASSERT_TRUE(composite->verify(pk, message, sig));
}

// ============================================================================
// MLDSA65 + Ed25519 Tests
// ============================================================================

TEST(composite_mldsa65_ed25519_keygen) {
    auto composite = pqc::create_composite_dsa("MLDSA65-Ed25519");
    auto [pk, sk] = composite->keygen();

    // sk format: pqc_sk || classical_sk || classical_pk
    ASSERT_EQ(pk.size(), 1952 + 32);
    ASSERT_EQ(sk.size(), 4032 + 32 + 32);
}

TEST(composite_mldsa65_ed25519_sign_verify) {
    auto composite = pqc::create_composite_dsa("MLDSA65-Ed25519");
    auto [pk, sk] = composite->keygen();

    std::vector<uint8_t> message = {'E', 'd', '2', '5', '5', '1', '9'};
    auto sig = composite->sign(sk, message);

    ASSERT_EQ(sig.size(), 3309 + 64);
    ASSERT_TRUE(composite->verify(pk, message, sig));
}

// ============================================================================
// MLDSA87 + ECDSA-P384 Tests
// ============================================================================

TEST(composite_mldsa87_ecdsa_p384_keygen) {
    auto composite = pqc::create_composite_dsa("MLDSA87-ECDSA-P384");
    auto [pk, sk] = composite->keygen();

    // ML-DSA-87: pk=2592, sk=4896
    // ECDSA P-384: pk=97, sk=48
    // sk format: pqc_sk || classical_sk || classical_pk
    ASSERT_EQ(pk.size(), 2592 + 97);
    ASSERT_EQ(sk.size(), 4896 + 48 + 97);
}

TEST(composite_mldsa87_ecdsa_p384_sign_verify) {
    auto composite = pqc::create_composite_dsa("MLDSA87-ECDSA-P384");
    auto [pk, sk] = composite->keygen();

    std::vector<uint8_t> message = {'M', 'L', 'D', 'S', 'A', '8', '7'};
    auto sig = composite->sign(sk, message);

    // ML-DSA-87 sig: 4627 bytes + ECDSA
    ASSERT_GT(sig.size(), 4627);
    ASSERT_TRUE(composite->verify(pk, message, sig));
}

// ============================================================================
// MLDSA87 + Ed448 Tests
// ============================================================================

TEST(composite_mldsa87_ed448_keygen) {
    auto composite = pqc::create_composite_dsa("MLDSA87-Ed448");
    auto [pk, sk] = composite->keygen();

    // ML-DSA-87: pk=2592, sk=4896
    // Ed448: pk=57, sk=57
    // sk format: pqc_sk || classical_sk || classical_pk
    ASSERT_EQ(pk.size(), 2592 + 57);
    ASSERT_EQ(sk.size(), 4896 + 57 + 57);

    ASSERT_EQ(composite->classical_algorithm(), "Ed448");
}

TEST(composite_mldsa87_ed448_sign_verify) {
    auto composite = pqc::create_composite_dsa("MLDSA87-Ed448");
    auto [pk, sk] = composite->keygen();

    std::vector<uint8_t> message = {'E', 'd', '4', '4', '8', ' ', 't', 'e', 's', 't'};
    auto sig = composite->sign(sk, message);

    // ML-DSA-87 sig: 4627 bytes + Ed448: 114 bytes
    ASSERT_EQ(sig.size(), 4627 + 114);
    ASSERT_TRUE(composite->verify(pk, message, sig));
}

// ============================================================================
// Error Handling Tests
// ============================================================================

TEST(composite_unknown_algorithm) {
    ASSERT_THROW(pqc::create_composite_dsa("UNKNOWN-ALGO"), std::runtime_error);
    ASSERT_THROW(pqc::create_composite_dsa("ML-DSA-65"), std::runtime_error);
    ASSERT_THROW(pqc::get_composite_oid("UNKNOWN"), std::runtime_error);
}

TEST(composite_empty_message) {
    auto composite = pqc::create_composite_dsa("MLDSA65-ECDSA-P256");
    auto [pk, sk] = composite->keygen();

    std::vector<uint8_t> empty_message;
    auto sig = composite->sign(sk, empty_message);
    ASSERT_TRUE(composite->verify(pk, empty_message, sig));
}

TEST(composite_large_message) {
    auto composite = pqc::create_composite_dsa("MLDSA65-ECDSA-P256");
    auto [pk, sk] = composite->keygen();

    // 1 MB message
    std::vector<uint8_t> large_message(1024 * 1024, 0xAB);
    auto sig = composite->sign(sk, large_message);
    ASSERT_TRUE(composite->verify(pk, large_message, sig));
}

// ============================================================================
// Context String Tests
// ============================================================================

TEST(composite_with_context) {
    auto composite = pqc::create_composite_dsa("MLDSA65-ECDSA-P256");
    auto [pk, sk] = composite->keygen();

    std::vector<uint8_t> message = {'c', 'o', 'n', 't', 'e', 'x', 't'};
    std::vector<uint8_t> ctx = {'t', 'e', 's', 't', '-', 'c', 't', 'x'};

    auto sig = composite->sign(sk, message, ctx);

    // Verify with same context
    ASSERT_TRUE(composite->verify(pk, message, sig, ctx));

    // Verify with different context should fail
    std::vector<uint8_t> wrong_ctx = {'w', 'r', 'o', 'n', 'g'};
    ASSERT_FALSE(composite->verify(pk, message, sig, wrong_ctx));

    // Verify with no context should fail
    ASSERT_FALSE(composite->verify(pk, message, sig));
}

// ============================================================================
// Cross-Key Verification Tests
// ============================================================================

TEST(composite_cross_key_fails) {
    auto composite = pqc::create_composite_dsa("MLDSA65-ECDSA-P256");

    auto [pk1, sk1] = composite->keygen();
    auto [pk2, sk2] = composite->keygen();

    std::vector<uint8_t> message = {'c', 'r', 'o', 's', 's'};
    auto sig = composite->sign(sk1, message);

    // Verify with correct key
    ASSERT_TRUE(composite->verify(pk1, message, sig));

    // Verify with different key should fail
    ASSERT_FALSE(composite->verify(pk2, message, sig));
}

// ============================================================================
// Signature Splitting Tests
// ============================================================================

TEST(composite_split_signature) {
    auto composite = pqc::create_composite_dsa("MLDSA65-Ed25519");
    auto [pk, sk] = composite->keygen();

    std::vector<uint8_t> message = {'s', 'p', 'l', 'i', 't'};
    auto sig = composite->sign(sk, message);

    auto [pqc_sig, classical_sig] = composite->split_signature(sig);
    ASSERT_EQ(pqc_sig.size(), 3309);  // ML-DSA-65 signature
    ASSERT_EQ(classical_sig.size(), 64);  // Ed25519 signature
}

// ============================================================================
// All Algorithms Smoke Test
// ============================================================================

TEST(composite_all_algorithms_smoke) {
    for (const auto& algo : pqc::available_composite_algorithms()) {
        auto composite = pqc::create_composite_dsa(algo);
        auto [pk, sk] = composite->keygen();

        std::vector<uint8_t> message = {'s', 'm', 'o', 'k', 'e'};
        auto sig = composite->sign(sk, message);

        if (!composite->verify(pk, message, sig)) {
            throw std::runtime_error("Failed for algorithm: " + algo);
        }
    }
}

// ============================================================================
// X.509 Certificate Tests
// ============================================================================

TEST(composite_x509_self_signed) {
    auto composite = pqc::create_composite_dsa("MLDSA65-ECDSA-P256");
    auto [pk, sk] = composite->keygen();

    // Create self-signed certificate
    x509::DistinguishedName dn;
    dn.common_name = "Test Composite Certificate";
    dn.organization = "Test Organization";
    dn.country = "US";

    // Use composite sign as callback
    auto sign_fn = [&](const std::vector<uint8_t>& tbs) -> std::vector<uint8_t> {
        return composite->sign(sk, tbs);
    };

    // Note: This requires adding composite OID support to pkcs8.hpp
    // For now, we'll use a generic test

    // Build certificate using ML-DSA-65 as placeholder
    // In a full implementation, we'd add composite OIDs
    x509::CertificateParams params;
    params.algorithm = pkcs8::Algorithm::ML_DSA_65;  // Placeholder
    params.issuer = dn;
    params.subject = dn;
    params.not_before = std::chrono::system_clock::now();
    params.not_after = params.not_before + std::chrono::hours(24 * 365);

    // Use PQC part of public key for the certificate
    auto [pqc_pk, classical_pk] = composite->split_public_key(pk);
    params.public_key = pqc_pk;  // Use just the PQC part for now
    params.is_ca = true;

    auto cert_der = x509::build_certificate_der(params, sign_fn);
    ASSERT_GT(cert_der.size(), 0);

    // Parse it back
    auto parsed = x509::parse_certificate_der(cert_der);
    ASSERT_TRUE(parsed.has_value());
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "\n=== X.509 Composite Certificate Tests ===\n\n";

    // Tests are auto-registered and run

    std::cout << "\n=== Test Summary ===\n";
    std::cout << "Total:  " << tests_run << "\n";
    std::cout << "Passed: " << tests_passed << "\n";
    std::cout << "Failed: " << tests_failed << "\n";

    return tests_failed > 0 ? 1 : 0;
}
