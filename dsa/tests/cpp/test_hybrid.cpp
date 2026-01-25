/**
 * Hybrid Cryptography Tests
 *
 * Tests for hybrid signature and KEM schemes combining PQC with classical algorithms.
 */

#include "common/hybrid.hpp"
#include <cassert>
#include <iostream>

// Test counters
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    void test_##name(); \
    struct TestRunner_##name { \
        TestRunner_##name() { \
            std::cout << "Running: " #name "..." << std::flush; \
            try { \
                test_##name(); \
                std::cout << " PASSED\n"; \
                tests_passed++; \
            } catch (const std::exception& e) { \
                std::cout << " FAILED: " << e.what() << "\n"; \
                tests_failed++; \
            } \
        } \
    } test_runner_##name; \
    void test_##name()

#define ASSERT(cond) \
    do { \
        if (!(cond)) { \
            throw std::runtime_error("Assertion failed: " #cond); \
        } \
    } while(0)

#define ASSERT_EQ(a, b) \
    do { \
        if ((a) != (b)) { \
            throw std::runtime_error("Assertion failed: " #a " == " #b); \
        } \
    } while(0)


// ============================================================================
// Hybrid DSA Tests - ML-DSA + Ed25519
// ============================================================================

TEST(hybrid_mldsa44_ed25519_keygen) {
    auto hybrid = pqc::create_hybrid_dsa("ML-DSA-44", "Ed25519");

    ASSERT_EQ(hybrid->name(), "ML-DSA-44+Ed25519");
    ASSERT_EQ(hybrid->pqc_algorithm(), "ML-DSA-44");
    ASSERT_EQ(hybrid->classical_algorithm(), "Ed25519");

    auto [pk, sk] = hybrid->keygen();

    // ML-DSA-44: pk=1312, sk=2560
    // Ed25519: pk=32, sk=32
    ASSERT_EQ(pk.size(), hybrid->public_key_size());
    ASSERT_EQ(sk.size(), hybrid->secret_key_size());
    ASSERT(pk.size() > 1312);  // At least ML-DSA-44 pk size
    ASSERT(sk.size() > 2560);  // At least ML-DSA-44 sk size
}

TEST(hybrid_mldsa44_ed25519_sign_verify) {
    auto hybrid = pqc::create_hybrid_dsa("ML-DSA-44", "Ed25519");
    auto [pk, sk] = hybrid->keygen();

    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o'};
    auto sig = hybrid->sign(sk, message);

    ASSERT(sig.size() <= hybrid->signature_size());

    bool valid = hybrid->verify(pk, message, sig);
    ASSERT(valid);
}

TEST(hybrid_mldsa44_ed25519_tampered_message) {
    auto hybrid = pqc::create_hybrid_dsa("ML-DSA-44", "Ed25519");
    auto [pk, sk] = hybrid->keygen();

    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o'};
    auto sig = hybrid->sign(sk, message);

    // Tamper with message
    message[0] = 'X';
    bool valid = hybrid->verify(pk, message, sig);
    ASSERT(!valid);
}

TEST(hybrid_mldsa44_ed25519_tampered_signature) {
    auto hybrid = pqc::create_hybrid_dsa("ML-DSA-44", "Ed25519");
    auto [pk, sk] = hybrid->keygen();

    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o'};
    auto sig = hybrid->sign(sk, message);

    // Tamper with signature
    sig[0] ^= 0xFF;
    bool valid = hybrid->verify(pk, message, sig);
    ASSERT(!valid);
}

TEST(hybrid_mldsa44_ed25519_wrong_key) {
    auto hybrid = pqc::create_hybrid_dsa("ML-DSA-44", "Ed25519");
    auto [pk1, sk1] = hybrid->keygen();
    auto [pk2, sk2] = hybrid->keygen();

    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o'};
    auto sig = hybrid->sign(sk1, message);

    // Verify with wrong key
    bool valid = hybrid->verify(pk2, message, sig);
    ASSERT(!valid);
}

// ============================================================================
// Hybrid DSA Tests - ML-DSA + ECDSA-P256
// ============================================================================

TEST(hybrid_mldsa65_ecdsap256_sign_verify) {
    auto hybrid = pqc::create_hybrid_dsa("ML-DSA-65", "ECDSA-P256");

    ASSERT_EQ(hybrid->name(), "ML-DSA-65+ECDSA-P256");

    auto [pk, sk] = hybrid->keygen();
    std::vector<uint8_t> message = {'T', 'e', 's', 't'};
    auto sig = hybrid->sign(sk, message);

    bool valid = hybrid->verify(pk, message, sig);
    ASSERT(valid);
}

TEST(hybrid_mldsa87_ecdsap384_sign_verify) {
    auto hybrid = pqc::create_hybrid_dsa("ML-DSA-87", "ECDSA-P384");

    ASSERT_EQ(hybrid->name(), "ML-DSA-87+ECDSA-P384");

    auto [pk, sk] = hybrid->keygen();
    std::vector<uint8_t> message = {'T', 'e', 's', 't'};
    auto sig = hybrid->sign(sk, message);

    bool valid = hybrid->verify(pk, message, sig);
    ASSERT(valid);
}

// ============================================================================
// Hybrid DSA Tests - SLH-DSA + Classical
// ============================================================================

TEST(hybrid_slhdsa_shake128f_ed25519) {
    auto hybrid = pqc::create_hybrid_dsa("SLH-DSA-SHAKE-128f", "Ed25519");

    ASSERT_EQ(hybrid->name(), "SLH-DSA-SHAKE-128f+Ed25519");
    ASSERT_EQ(hybrid->pqc_algorithm(), "SLH-DSA-SHAKE-128f");

    auto [pk, sk] = hybrid->keygen();
    std::vector<uint8_t> message = {'S', 'L', 'H'};
    auto sig = hybrid->sign(sk, message);

    bool valid = hybrid->verify(pk, message, sig);
    ASSERT(valid);
}

// ============================================================================
// Hybrid DSA Tests - Context Strings
// ============================================================================

TEST(hybrid_mldsa_ed25519_with_context) {
    auto hybrid = pqc::create_hybrid_dsa("ML-DSA-44", "Ed25519");
    auto [pk, sk] = hybrid->keygen();

    std::vector<uint8_t> message = {'M', 's', 'g'};
    std::vector<uint8_t> context = {'c', 't', 'x'};

    auto sig = hybrid->sign(sk, message, context);
    bool valid = hybrid->verify(pk, message, sig, context);
    ASSERT(valid);

    // Wrong context should fail
    std::vector<uint8_t> wrong_ctx = {'b', 'a', 'd'};
    valid = hybrid->verify(pk, message, sig, wrong_ctx);
    ASSERT(!valid);
}

// ============================================================================
// Hybrid KEM Tests - ML-KEM + X25519
// ============================================================================

TEST(hybrid_mlkem768_x25519_keygen) {
    auto hybrid = pqc::create_hybrid_kem("ML-KEM-768", "X25519");

    ASSERT_EQ(hybrid->name(), "ML-KEM-768+X25519");
    ASSERT_EQ(hybrid->pqc_algorithm(), "ML-KEM-768");
    ASSERT_EQ(hybrid->classical_algorithm(), "X25519");

    auto [ek, dk] = hybrid->keygen();

    ASSERT_EQ(ek.size(), hybrid->encapsulation_key_size());
    ASSERT_EQ(dk.size(), hybrid->decapsulation_key_size());
    // ML-KEM-768: ek=1184, dk=2400
    // X25519: pk=32, sk=32
    ASSERT(ek.size() > 1184);
    ASSERT(dk.size() > 2400);
}

TEST(hybrid_mlkem768_x25519_encaps_decaps) {
    auto hybrid = pqc::create_hybrid_kem("ML-KEM-768", "X25519");
    auto [ek, dk] = hybrid->keygen();

    auto [K1, ct] = hybrid->encaps(ek);
    auto K2 = hybrid->decaps(dk, ct);

    ASSERT_EQ(K1.size(), size_t(32));
    ASSERT_EQ(K2.size(), size_t(32));
    ASSERT_EQ(K1, K2);  // Shared secrets must match
}

TEST(hybrid_mlkem512_x25519_encaps_decaps) {
    auto hybrid = pqc::create_hybrid_kem("ML-KEM-512", "X25519");
    auto [ek, dk] = hybrid->keygen();

    auto [K1, ct] = hybrid->encaps(ek);
    auto K2 = hybrid->decaps(dk, ct);

    ASSERT_EQ(K1, K2);
}

TEST(hybrid_mlkem1024_x25519_encaps_decaps) {
    auto hybrid = pqc::create_hybrid_kem("ML-KEM-1024", "X25519");
    auto [ek, dk] = hybrid->keygen();

    auto [K1, ct] = hybrid->encaps(ek);
    auto K2 = hybrid->decaps(dk, ct);

    ASSERT_EQ(K1, K2);
}

// ============================================================================
// Hybrid KEM Tests - ML-KEM + ECDH-P256
// ============================================================================

TEST(hybrid_mlkem768_ecdhp256_encaps_decaps) {
    auto hybrid = pqc::create_hybrid_kem("ML-KEM-768", "ECDH-P256");

    ASSERT_EQ(hybrid->name(), "ML-KEM-768+ECDH-P256");

    auto [ek, dk] = hybrid->keygen();
    auto [K1, ct] = hybrid->encaps(ek);
    auto K2 = hybrid->decaps(dk, ct);

    ASSERT_EQ(K1, K2);
}

// ============================================================================
// Hybrid KEM Failure Tests
// ============================================================================

TEST(hybrid_kem_wrong_dk) {
    auto hybrid = pqc::create_hybrid_kem("ML-KEM-768", "X25519");
    auto [ek1, dk1] = hybrid->keygen();
    auto [ek2, dk2] = hybrid->keygen();

    auto [K1, ct] = hybrid->encaps(ek1);

    // Decapsulate with wrong key
    auto K2 = hybrid->decaps(dk2, ct);

    // Shared secrets should NOT match (ML-KEM uses implicit rejection)
    ASSERT(K1 != K2);
}

TEST(hybrid_kem_tampered_ciphertext) {
    auto hybrid = pqc::create_hybrid_kem("ML-KEM-768", "X25519");
    auto [ek, dk] = hybrid->keygen();

    auto [K1, ct] = hybrid->encaps(ek);

    // Tamper with ciphertext
    ct[0] ^= 0xFF;

    auto K2 = hybrid->decaps(dk, ct);

    // Shared secrets should NOT match
    ASSERT(K1 != K2);
}

// ============================================================================
// Multiple Encapsulations Test
// ============================================================================

TEST(hybrid_kem_multiple_encaps) {
    auto hybrid = pqc::create_hybrid_kem("ML-KEM-768", "X25519");
    auto [ek, dk] = hybrid->keygen();

    // Multiple encapsulations with same ek should produce different ciphertexts
    auto [K1, ct1] = hybrid->encaps(ek);
    auto [K2, ct2] = hybrid->encaps(ek);

    ASSERT(ct1 != ct2);  // Different ciphertexts (ephemeral randomness)

    // But decapsulation should still work
    auto K1_dec = hybrid->decaps(dk, ct1);
    auto K2_dec = hybrid->decaps(dk, ct2);

    ASSERT_EQ(K1, K1_dec);
    ASSERT_EQ(K2, K2_dec);
}

// ============================================================================
// Factory Tests
// ============================================================================

TEST(available_classical_algorithms) {
    auto dsa_algos = pqc::available_classical_dsa();
    ASSERT_EQ(dsa_algos.size(), size_t(3));

    auto kem_algos = pqc::available_classical_kem();
    ASSERT_EQ(kem_algos.size(), size_t(2));
}

TEST(create_hybrid_dsa_unknown_pqc) {
    bool threw = false;
    try {
        auto hybrid = pqc::create_hybrid_dsa("UNKNOWN-PQC", "Ed25519");
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    ASSERT(threw);
}

TEST(create_hybrid_dsa_unknown_classical) {
    bool threw = false;
    try {
        auto hybrid = pqc::create_hybrid_dsa("ML-DSA-44", "UNKNOWN");
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    ASSERT(threw);
}

TEST(create_hybrid_kem_unknown_pqc) {
    bool threw = false;
    try {
        auto hybrid = pqc::create_hybrid_kem("UNKNOWN-PQC", "X25519");
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    ASSERT(threw);
}

TEST(create_hybrid_kem_unknown_classical) {
    bool threw = false;
    try {
        auto hybrid = pqc::create_hybrid_kem("ML-KEM-768", "UNKNOWN");
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    ASSERT(threw);
}

// ============================================================================
// Size Metadata Tests
// ============================================================================

TEST(hybrid_dsa_sizes) {
    auto hybrid = pqc::create_hybrid_dsa("ML-DSA-65", "Ed25519");

    // ML-DSA-65: pk=1952, sk=4032, sig=3309
    // Ed25519: pk=32, sk=32, sig=64
    ASSERT_EQ(hybrid->public_key_size(), size_t(1952 + 32));
    ASSERT_EQ(hybrid->secret_key_size(), size_t(4032 + 32));
    // Signature includes 2-byte length prefix for classical sig
    ASSERT(hybrid->signature_size() >= 3309 + 2 + 64);
}

TEST(hybrid_kem_sizes) {
    auto hybrid = pqc::create_hybrid_kem("ML-KEM-768", "X25519");

    // ML-KEM-768: ek=1184, dk=2400, ct=1088
    // X25519: pk=32, sk=32, ct(ephemeral pk)=32
    ASSERT_EQ(hybrid->encapsulation_key_size(), size_t(1184 + 32));
    ASSERT_EQ(hybrid->decapsulation_key_size(), size_t(2400 + 32));
    ASSERT_EQ(hybrid->ciphertext_size(), size_t(1088 + 32));
    ASSERT_EQ(hybrid->shared_secret_size(), size_t(32));
}

// ============================================================================
// Alternative Name Parsing Tests
// ============================================================================

TEST(parse_classical_dsa_aliases) {
    // Test alternative names
    auto h1 = pqc::create_hybrid_dsa("ML-DSA-44", "P256");
    ASSERT_EQ(h1->classical_algorithm(), "ECDSA-P256");

    auto h2 = pqc::create_hybrid_dsa("ML-DSA-44", "P384");
    ASSERT_EQ(h2->classical_algorithm(), "ECDSA-P384");

    auto h3 = pqc::create_hybrid_dsa("ML-DSA-44", "ed25519");
    ASSERT_EQ(h3->classical_algorithm(), "Ed25519");
}

TEST(parse_classical_kem_aliases) {
    auto h1 = pqc::create_hybrid_kem("ML-KEM-768", "x25519");
    ASSERT_EQ(h1->classical_algorithm(), "X25519");
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "=== Hybrid Cryptography Tests ===\n\n";

    // Tests run automatically via static initialization

    std::cout << "\n=== Results ===\n";
    std::cout << "Passed: " << tests_passed << "\n";
    std::cout << "Failed: " << tests_failed << "\n";

    return tests_failed == 0 ? 0 : 1;
}
