/**
 * Comprehensive Edge Case Test Suite
 *
 * Tests boundary conditions, invalid inputs, and corner cases for all PQC algorithms.
 * Ensures robustness against malformed inputs and edge conditions.
 */

#include "mldsa/mldsa.hpp"
#include "slhdsa/slh_dsa.hpp"
#include "mlkem/mlkem.hpp"
#include <iostream>
#include <cassert>
#include <vector>
#include <cstring>
#include <limits>
#include <random>

// Simple test framework
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    std::cout << "  " << name << "... " << std::flush; \
    try

#define TEST_END \
    std::cout << "PASSED" << std::endl; \
    ++tests_passed; \
    } catch (const std::exception& e) { \
        std::cout << "FAILED: " << e.what() << std::endl; \
        ++tests_failed; \
    } catch (...) { \
        std::cout << "FAILED: Unknown exception" << std::endl; \
        ++tests_failed; \
    }

#define ASSERT_TRUE(cond) \
    if (!(cond)) throw std::runtime_error("Assertion failed: " #cond)

#define ASSERT_FALSE(cond) \
    if (cond) throw std::runtime_error("Assertion failed: NOT " #cond)

#define ASSERT_EQ(a, b) \
    if ((a) != (b)) throw std::runtime_error("Assertion failed: " #a " == " #b)

#define ASSERT_THROWS(expr) \
    { \
        bool threw = false; \
        try { expr; } catch (...) { threw = true; } \
        if (!threw) throw std::runtime_error("Expected exception: " #expr); \
    }

// =============================================================================
// ML-DSA Edge Cases
// =============================================================================

void test_mldsa_edge_cases() {
    std::cout << "\n=== ML-DSA Edge Cases ===" << std::endl;

    mldsa::MLDSA dsa(mldsa::MLDSA65_PARAMS);
    auto [pk, sk] = dsa.keygen();

    // All-zeros signature should fail verification
    TEST("all-zeros signature fails") {
        std::vector<uint8_t> message = {1, 2, 3, 4, 5};
        std::vector<uint8_t> zero_sig(dsa.params().sig_size(), 0);
        ASSERT_FALSE(dsa.verify(pk, message, zero_sig));
    TEST_END

    // All-ones signature should fail verification
    TEST("all-ones signature fails") {
        std::vector<uint8_t> message = {1, 2, 3, 4, 5};
        std::vector<uint8_t> ones_sig(dsa.params().sig_size(), 0xFF);
        ASSERT_FALSE(dsa.verify(pk, message, ones_sig));
    TEST_END

    // Wrong size signature should fail/throw
    TEST("wrong size signature fails") {
        std::vector<uint8_t> message = {1, 2, 3, 4, 5};
        std::vector<uint8_t> short_sig(100, 0x42);
        bool result = false;
        try {
            result = dsa.verify(pk, message, short_sig);
        } catch (...) {
            // Exception is also acceptable
            result = false;
        }
        ASSERT_FALSE(result);
    TEST_END

    // Maximum length message
    TEST("large message (1MB)") {
        std::vector<uint8_t> large_msg(1024 * 1024, 0xAB);
        auto sig = dsa.sign(sk, large_msg);
        ASSERT_TRUE(dsa.verify(pk, large_msg, sig));
    TEST_END

    // Empty message
    TEST("empty message sign/verify") {
        std::vector<uint8_t> empty_msg;
        auto sig = dsa.sign(sk, empty_msg);
        ASSERT_TRUE(dsa.verify(pk, empty_msg, sig));
    TEST_END

    // Single byte message
    TEST("single byte message") {
        std::vector<uint8_t> single = {0x00};
        auto sig = dsa.sign(sk, single);
        ASSERT_TRUE(dsa.verify(pk, single, sig));

        single = {0xFF};
        sig = dsa.sign(sk, single);
        ASSERT_TRUE(dsa.verify(pk, single, sig));
    TEST_END

    // Modified public key should fail
    TEST("modified public key fails verification") {
        std::vector<uint8_t> message = {1, 2, 3, 4, 5};
        auto sig = dsa.sign(sk, message);

        std::vector<uint8_t> bad_pk = pk;
        bad_pk[0] ^= 0x01;  // Flip one bit
        ASSERT_FALSE(dsa.verify(bad_pk, message, bad_pk.size() == pk.size() ? sig : sig));
    TEST_END

    // Modified signature should fail
    TEST("modified signature fails verification") {
        std::vector<uint8_t> message = {1, 2, 3, 4, 5};
        auto sig = dsa.sign(sk, message);

        std::vector<uint8_t> bad_sig = sig;
        bad_sig[bad_sig.size() / 2] ^= 0x01;  // Flip one bit in middle
        ASSERT_FALSE(dsa.verify(pk, message, bad_sig));
    TEST_END

    // Modified message should fail
    TEST("modified message fails verification") {
        std::vector<uint8_t> message = {1, 2, 3, 4, 5};
        auto sig = dsa.sign(sk, message);

        std::vector<uint8_t> bad_msg = message;
        bad_msg[0] ^= 0x01;
        ASSERT_FALSE(dsa.verify(pk, bad_msg, sig));
    TEST_END

    // Context string edge cases
    TEST("maximum context length (255 bytes)") {
        std::vector<uint8_t> message = {1, 2, 3};
        std::vector<uint8_t> max_ctx(255, 0x42);
        auto sig = dsa.sign(sk, message, max_ctx);
        ASSERT_TRUE(dsa.verify(pk, message, sig, max_ctx));
    TEST_END

    // All parameter sets
    TEST("all parameter sets basic sign/verify") {
        for (const auto* params : {&mldsa::MLDSA44_PARAMS, &mldsa::MLDSA65_PARAMS, &mldsa::MLDSA87_PARAMS}) {
            mldsa::MLDSA d(*params);
            auto [p, s] = d.keygen();
            std::vector<uint8_t> msg = {0xDE, 0xAD, 0xBE, 0xEF};
            auto signature = d.sign(s, msg);
            ASSERT_TRUE(d.verify(p, msg, signature));
        }
    TEST_END

    // Deterministic seed edge cases
    TEST("all-zeros seed produces valid keys") {
        std::vector<uint8_t> zero_seed(32, 0);
        auto [pk1, sk1] = dsa.keygen(zero_seed);
        std::vector<uint8_t> msg = {1, 2, 3};
        auto sig = dsa.sign(sk1, msg);
        ASSERT_TRUE(dsa.verify(pk1, msg, sig));
    TEST_END

    TEST("all-ones seed produces valid keys") {
        std::vector<uint8_t> ones_seed(32, 0xFF);
        auto [pk1, sk1] = dsa.keygen(ones_seed);
        std::vector<uint8_t> msg = {1, 2, 3};
        auto sig = dsa.sign(sk1, msg);
        ASSERT_TRUE(dsa.verify(pk1, msg, sig));
    TEST_END
}

// =============================================================================
// SLH-DSA Edge Cases
// =============================================================================

void test_slhdsa_edge_cases() {
    std::cout << "\n=== SLH-DSA Edge Cases ===" << std::endl;

    slhdsa::SLHDSA_SHAKE_128f dsa;
    // Note: SLH-DSA keygen returns (sk, pk) - secret key first
    auto [sk, pk] = dsa.keygen();

    // All-zeros signature should fail
    TEST("all-zeros signature fails") {
        std::vector<uint8_t> message = {1, 2, 3, 4, 5};
        std::vector<uint8_t> zero_sig(dsa.params().sig_size(), 0);
        ASSERT_FALSE(dsa.verify(pk, message, zero_sig));
    TEST_END

    // All-ones signature should fail
    TEST("all-ones signature fails") {
        std::vector<uint8_t> message = {1, 2, 3, 4, 5};
        std::vector<uint8_t> ones_sig(dsa.params().sig_size(), 0xFF);
        ASSERT_FALSE(dsa.verify(pk, message, ones_sig));
    TEST_END

    // Wrong size signature
    TEST("wrong size signature fails") {
        std::vector<uint8_t> message = {1, 2, 3, 4, 5};
        std::vector<uint8_t> short_sig(100, 0x42);
        bool result = false;
        try {
            result = dsa.verify(pk, message, short_sig);
        } catch (...) {
            result = false;
        }
        ASSERT_FALSE(result);
    TEST_END

    // Empty message
    TEST("empty message sign/verify") {
        std::vector<uint8_t> empty_msg;
        auto sig = dsa.sign(sk, empty_msg);
        ASSERT_TRUE(dsa.verify(pk, empty_msg, sig));
    TEST_END

    // Large message (SLH-DSA is slower, so use smaller size)
    TEST("large message (64KB)") {
        std::vector<uint8_t> large_msg(64 * 1024, 0xCD);
        auto sig = dsa.sign(sk, large_msg);
        ASSERT_TRUE(dsa.verify(pk, large_msg, sig));
    TEST_END

    // Modified signature
    TEST("modified signature fails") {
        std::vector<uint8_t> message = {1, 2, 3, 4, 5};
        auto sig = dsa.sign(sk, message);
        sig[sig.size() / 2] ^= 0x01;
        ASSERT_FALSE(dsa.verify(pk, message, sig));
    TEST_END

    // Test all SHAKE variants (fast ones only for speed)
    TEST("SHAKE variants basic sign/verify") {
        // 128f - Note: keygen returns (sk, pk)
        {
            slhdsa::SLHDSA_SHAKE_128f d;
            auto [s, p] = d.keygen();
            std::vector<uint8_t> msg = {0xAB, 0xCD};
            auto signature = d.sign(s, msg);
            ASSERT_TRUE(d.verify(p, msg, signature));
        }
        // 192f
        {
            slhdsa::SLHDSA_SHAKE_192f d;
            auto [s, p] = d.keygen();
            std::vector<uint8_t> msg = {0xAB, 0xCD};
            auto signature = d.sign(s, msg);
            ASSERT_TRUE(d.verify(p, msg, signature));
        }
        // 256f
        {
            slhdsa::SLHDSA_SHAKE_256f d;
            auto [s, p] = d.keygen();
            std::vector<uint8_t> msg = {0xAB, 0xCD};
            auto signature = d.sign(s, msg);
            ASSERT_TRUE(d.verify(p, msg, signature));
        }
    TEST_END
}

// =============================================================================
// ML-KEM Edge Cases
// =============================================================================

void test_mlkem_edge_cases() {
    std::cout << "\n=== ML-KEM Edge Cases ===" << std::endl;

    mlkem::MLKEM768 kem;
    auto [ek, dk] = kem.keygen();

    // Valid encapsulation/decapsulation
    // Note: encaps returns (K, c) - shared secret first, ciphertext second
    TEST("basic encaps/decaps") {
        auto [ss1, ct] = kem.encaps(ek);
        auto ss2 = kem.decaps(dk, ct);
        ASSERT_TRUE(ss1 == ss2);
    TEST_END

    // All-zeros ciphertext should trigger implicit rejection
    TEST("all-zeros ciphertext produces different shared secret") {
        auto [ss_valid, ct] = kem.encaps(ek);
        std::vector<uint8_t> zero_ct(ct.size(), 0);
        auto ss_invalid = kem.decaps(dk, zero_ct);
        // Should not crash, but should produce different secret
        ASSERT_FALSE(ss_valid == ss_invalid);
    TEST_END

    // All-ones ciphertext
    TEST("all-ones ciphertext produces different shared secret") {
        auto [ss_valid, ct] = kem.encaps(ek);
        std::vector<uint8_t> ones_ct(ct.size(), 0xFF);
        auto ss_invalid = kem.decaps(dk, ones_ct);
        ASSERT_FALSE(ss_valid == ss_invalid);
    TEST_END

    // Modified ciphertext produces different secret (implicit rejection)
    TEST("modified ciphertext triggers implicit rejection") {
        auto [ss_original, ct] = kem.encaps(ek);
        std::vector<uint8_t> bad_ct = ct;
        bad_ct[bad_ct.size() / 2] ^= 0x01;
        auto ss_bad = kem.decaps(dk, bad_ct);
        ASSERT_FALSE(ss_original == ss_bad);
    TEST_END

    // Shared secret is always 32 bytes
    TEST("shared secret size is always 32 bytes") {
        auto [ss, ct] = kem.encaps(ek);
        ASSERT_EQ(ss.size(), 32u);

        auto ss2 = kem.decaps(dk, ct);
        ASSERT_EQ(ss2.size(), 32u);

        // Even with invalid ciphertext
        std::vector<uint8_t> bad_ct(ct.size(), 0);
        auto ss3 = kem.decaps(dk, bad_ct);
        ASSERT_EQ(ss3.size(), 32u);
    TEST_END

    // All parameter sets
    TEST("all parameter sets encaps/decaps") {
        // 512
        {
            mlkem::MLKEM512 k;
            auto [e, d] = k.keygen();
            auto [s1, c] = k.encaps(e);
            auto s2 = k.decaps(d, c);
            ASSERT_TRUE(s1 == s2);
        }
        // 768
        {
            mlkem::MLKEM768 k;
            auto [e, d] = k.keygen();
            auto [s1, c] = k.encaps(e);
            auto s2 = k.decaps(d, c);
            ASSERT_TRUE(s1 == s2);
        }
        // 1024
        {
            mlkem::MLKEM1024 k;
            auto [e, d] = k.keygen();
            auto [s1, c] = k.encaps(e);
            auto s2 = k.decaps(d, c);
            ASSERT_TRUE(s1 == s2);
        }
    TEST_END

    // Deterministic keygen
    TEST("deterministic keygen with seed") {
        std::vector<uint8_t> seed(64, 0x42);
        auto [ek1, dk1] = kem.keygen(seed);
        auto [ek2, dk2] = kem.keygen(seed);
        ASSERT_TRUE(ek1 == ek2);
        ASSERT_TRUE(dk1 == dk2);
    TEST_END

    // All-zeros seed
    TEST("all-zeros seed produces valid keys") {
        std::vector<uint8_t> zero_seed(64, 0);
        auto [ek1, dk1] = kem.keygen(zero_seed);
        auto [ss1, ct] = kem.encaps(ek1);
        auto ss2 = kem.decaps(dk1, ct);
        ASSERT_TRUE(ss1 == ss2);
    TEST_END

    // All-ones seed
    TEST("all-ones seed produces valid keys") {
        std::vector<uint8_t> ones_seed(64, 0xFF);
        auto [ek1, dk1] = kem.keygen(ones_seed);
        auto [ss1, ct] = kem.encaps(ek1);
        auto ss2 = kem.decaps(dk1, ct);
        ASSERT_TRUE(ss1 == ss2);
    TEST_END
}

// =============================================================================
// Cross-Algorithm Edge Cases
// =============================================================================

void test_cross_algorithm_edge_cases() {
    std::cout << "\n=== Cross-Algorithm Edge Cases ===" << std::endl;

    // Same seed produces different but deterministic keys for different algorithms
    TEST("same seed different algorithms") {
        std::vector<uint8_t> seed(32, 0x55);

        mldsa::MLDSA dsa44(mldsa::MLDSA44_PARAMS);
        mldsa::MLDSA dsa65(mldsa::MLDSA65_PARAMS);

        auto [pk44, sk44] = dsa44.keygen(seed);
        auto [pk65, sk65] = dsa65.keygen(seed);

        // Keys should be different sizes and content
        ASSERT_FALSE(pk44 == pk65);
        ASSERT_FALSE(sk44 == sk65);
    TEST_END

    // Signature from one parameter set cannot verify with another
    TEST("cross-parameter signature fails") {
        mldsa::MLDSA dsa44(mldsa::MLDSA44_PARAMS);
        mldsa::MLDSA dsa65(mldsa::MLDSA65_PARAMS);

        auto [pk44, sk44] = dsa44.keygen();
        auto [pk65, sk65] = dsa65.keygen();

        std::vector<uint8_t> msg = {1, 2, 3, 4, 5};
        auto sig44 = dsa44.sign(sk44, msg);

        // Try to verify with wrong parameter set (should fail or throw)
        bool result = false;
        try {
            result = dsa65.verify(pk65, msg, sig44);
        } catch (...) {
            result = false;
        }
        ASSERT_FALSE(result);
    TEST_END
}

// =============================================================================
// Bit Manipulation Edge Cases
// =============================================================================

void test_bit_manipulation_edge_cases() {
    std::cout << "\n=== Bit Manipulation Edge Cases ===" << std::endl;

    mldsa::MLDSA dsa(mldsa::MLDSA65_PARAMS);
    auto [pk, sk] = dsa.keygen();

    // Test each bit position in signature (sample a few positions)
    TEST("single bit flips in signature all fail") {
        std::vector<uint8_t> message = {0xDE, 0xAD, 0xBE, 0xEF};
        auto sig = dsa.sign(sk, message);

        // Test first byte
        for (int bit = 0; bit < 8; bit++) {
            std::vector<uint8_t> bad_sig = sig;
            bad_sig[0] ^= (1 << bit);
            ASSERT_FALSE(dsa.verify(pk, message, bad_sig));
        }

        // Test middle byte
        size_t mid = sig.size() / 2;
        for (int bit = 0; bit < 8; bit++) {
            std::vector<uint8_t> bad_sig = sig;
            bad_sig[mid] ^= (1 << bit);
            ASSERT_FALSE(dsa.verify(pk, message, bad_sig));
        }

        // Test last byte
        for (int bit = 0; bit < 8; bit++) {
            std::vector<uint8_t> bad_sig = sig;
            bad_sig[sig.size() - 1] ^= (1 << bit);
            ASSERT_FALSE(dsa.verify(pk, message, bad_sig));
        }
    TEST_END

    // Test bit flips in public key
    TEST("single bit flips in public key all fail") {
        std::vector<uint8_t> message = {0xDE, 0xAD, 0xBE, 0xEF};
        auto sig = dsa.sign(sk, message);

        // Test first byte
        for (int bit = 0; bit < 8; bit++) {
            std::vector<uint8_t> bad_pk = pk;
            bad_pk[0] ^= (1 << bit);
            ASSERT_FALSE(dsa.verify(bad_pk, message, sig));
        }

        // Test middle byte
        size_t mid = pk.size() / 2;
        for (int bit = 0; bit < 8; bit++) {
            std::vector<uint8_t> bad_pk = pk;
            bad_pk[mid] ^= (1 << bit);
            ASSERT_FALSE(dsa.verify(bad_pk, message, sig));
        }
    TEST_END
}

// =============================================================================
// Randomized Edge Cases
// =============================================================================

void test_randomized_edge_cases() {
    std::cout << "\n=== Randomized Edge Cases ===" << std::endl;

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    mldsa::MLDSA dsa(mldsa::MLDSA65_PARAMS);
    auto [pk, sk] = dsa.keygen();

    // Random garbage signatures should all fail
    TEST("100 random signatures all fail") {
        std::vector<uint8_t> message = {1, 2, 3, 4, 5};
        for (int i = 0; i < 100; i++) {
            std::vector<uint8_t> random_sig(dsa.params().sig_size());
            for (auto& byte : random_sig) {
                byte = static_cast<uint8_t>(dis(gen));
            }
            ASSERT_FALSE(dsa.verify(pk, message, random_sig));
        }
    TEST_END

    // Random message modifications should all fail
    TEST("100 random message modifications all fail") {
        std::vector<uint8_t> original_msg(100);
        for (auto& byte : original_msg) {
            byte = static_cast<uint8_t>(dis(gen));
        }
        auto sig = dsa.sign(sk, original_msg);
        ASSERT_TRUE(dsa.verify(pk, original_msg, sig));

        for (int i = 0; i < 100; i++) {
            std::vector<uint8_t> modified_msg = original_msg;
            size_t pos = dis(gen) % modified_msg.size();
            modified_msg[pos] ^= (1 << (dis(gen) % 8));
            ASSERT_FALSE(dsa.verify(pk, modified_msg, sig));
        }
    TEST_END
}

// =============================================================================
// Main
// =============================================================================

int main() {
    std::cout << "=== Comprehensive Edge Case Tests ===" << std::endl;
    std::cout << "Testing boundary conditions, invalid inputs, and corner cases\n" << std::endl;

    test_mldsa_edge_cases();
    test_slhdsa_edge_cases();
    test_mlkem_edge_cases();
    test_cross_algorithm_edge_cases();
    test_bit_manipulation_edge_cases();
    test_randomized_edge_cases();

    std::cout << "\n========================================" << std::endl;
    std::cout << "Results: " << tests_passed << " passed, " << tests_failed << " failed" << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
