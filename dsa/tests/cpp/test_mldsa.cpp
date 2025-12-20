/**
 * ML-DSA Test Suite
 * Tests for ML-DSA-44, ML-DSA-65, and ML-DSA-87
 */

#include "mldsa/mldsa.hpp"
#include <iostream>
#include <cassert>
#include <chrono>
#include <iomanip>

using namespace mldsa;

// Simple test framework
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    std::cout << "Testing " << name << "... " << std::flush; \
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

template<typename DSA>
void test_keygen() {
    DSA dsa;

    TEST("keygen generates valid key sizes") {
        auto [pk, sk] = dsa.keygen();
        ASSERT_EQ(pk.size(), dsa.params().pk_size());
        ASSERT_EQ(sk.size(), dsa.params().sk_size());
    TEST_END

    TEST("keygen with seed is deterministic") {
        std::vector<uint8_t> seed(32, 0x42);
        auto [pk1, sk1] = dsa.keygen(seed);
        auto [pk2, sk2] = dsa.keygen(seed);
        ASSERT_TRUE(pk1 == pk2);
        ASSERT_TRUE(sk1 == sk2);
    TEST_END

    TEST("keygen without seed is random") {
        auto [pk1, sk1] = dsa.keygen();
        auto [pk2, sk2] = dsa.keygen();
        ASSERT_FALSE(pk1 == pk2);
        ASSERT_FALSE(sk1 == sk2);
    TEST_END
}

template<typename DSA>
void test_sign_verify() {
    DSA dsa;

    TEST("sign/verify basic") {
        auto [pk, sk] = dsa.keygen();
        std::vector<uint8_t> message = {'h', 'e', 'l', 'l', 'o'};
        auto sig = dsa.sign(sk, message);
        ASSERT_EQ(sig.size(), dsa.params().sig_size());
        ASSERT_TRUE(dsa.verify(pk, message, sig));
    TEST_END

    TEST("sign/verify empty message") {
        auto [pk, sk] = dsa.keygen();
        std::vector<uint8_t> message;
        auto sig = dsa.sign(sk, message);
        ASSERT_TRUE(dsa.verify(pk, message, sig));
    TEST_END

    TEST("sign/verify with context") {
        auto [pk, sk] = dsa.keygen();
        std::vector<uint8_t> message = {'t', 'e', 's', 't'};
        std::vector<uint8_t> ctx = {'c', 't', 'x'};
        auto sig = dsa.sign(sk, message, ctx);
        ASSERT_TRUE(dsa.verify(pk, message, sig, ctx));
        // Wrong context should fail
        std::vector<uint8_t> wrong_ctx = {'w', 'r', 'o', 'n', 'g'};
        ASSERT_FALSE(dsa.verify(pk, message, sig, wrong_ctx));
    TEST_END

    TEST("deterministic signing") {
        auto [pk, sk] = dsa.keygen();
        std::vector<uint8_t> message = {'d', 'e', 't', 'e', 'r', 'm'};
        auto sig1 = dsa.sign(sk, message, {}, true);
        auto sig2 = dsa.sign(sk, message, {}, true);
        ASSERT_TRUE(sig1 == sig2);
    TEST_END

    TEST("randomized signing produces different signatures") {
        auto [pk, sk] = dsa.keygen();
        std::vector<uint8_t> message = {'r', 'a', 'n', 'd'};
        auto sig1 = dsa.sign(sk, message, {}, false);
        auto sig2 = dsa.sign(sk, message, {}, false);
        // Both should verify
        ASSERT_TRUE(dsa.verify(pk, message, sig1));
        ASSERT_TRUE(dsa.verify(pk, message, sig2));
        // But be different (with very high probability)
        ASSERT_FALSE(sig1 == sig2);
    TEST_END
}

template<typename DSA>
void test_verification_failures() {
    DSA dsa;

    TEST("wrong message fails verification") {
        auto [pk, sk] = dsa.keygen();
        std::vector<uint8_t> message = {'o', 'r', 'i', 'g'};
        auto sig = dsa.sign(sk, message);
        std::vector<uint8_t> wrong_message = {'w', 'r', 'o', 'n', 'g'};
        ASSERT_FALSE(dsa.verify(pk, wrong_message, sig));
    TEST_END

    TEST("wrong public key fails verification") {
        auto [pk1, sk1] = dsa.keygen();
        auto [pk2, sk2] = dsa.keygen();
        std::vector<uint8_t> message = {'t', 'e', 's', 't'};
        auto sig = dsa.sign(sk1, message);
        ASSERT_TRUE(dsa.verify(pk1, message, sig));
        ASSERT_FALSE(dsa.verify(pk2, message, sig));
    TEST_END

    TEST("tampered signature fails verification") {
        auto [pk, sk] = dsa.keygen();
        std::vector<uint8_t> message = {'t', 'e', 's', 't'};
        auto sig = dsa.sign(sk, message);
        // Tamper with signature
        sig[0] ^= 0xFF;
        ASSERT_FALSE(dsa.verify(pk, message, sig));
    TEST_END
}

template<typename DSA>
void test_performance(const std::string& name) {
    DSA dsa;
    const int iterations = 10;

    std::cout << "\nPerformance (" << name << ", " << iterations << " iterations):" << std::endl;

    // Keygen timing
    auto start = std::chrono::high_resolution_clock::now();
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> keys;
    for (int i = 0; i < iterations; ++i) {
        keys.push_back(dsa.keygen());
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto keygen_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    std::cout << "  KeyGen: " << keygen_ms << " ms total, "
              << std::fixed << std::setprecision(2)
              << (double)keygen_ms / iterations << " ms/op" << std::endl;

    // Sign timing
    std::vector<uint8_t> message = {'b', 'e', 'n', 'c', 'h', 'm', 'a', 'r', 'k'};
    std::vector<std::vector<uint8_t>> sigs;
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        sigs.push_back(dsa.sign(keys[i].second, message));
    }
    end = std::chrono::high_resolution_clock::now();
    auto sign_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    std::cout << "  Sign:   " << sign_ms << " ms total, "
              << std::fixed << std::setprecision(2)
              << (double)sign_ms / iterations << " ms/op" << std::endl;

    // Verify timing
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        bool valid = dsa.verify(keys[i].first, message, sigs[i]);
        if (!valid) {
            std::cerr << "Verification failed during benchmark!" << std::endl;
        }
    }
    end = std::chrono::high_resolution_clock::now();
    auto verify_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    std::cout << "  Verify: " << verify_ms << " ms total, "
              << std::fixed << std::setprecision(2)
              << (double)verify_ms / iterations << " ms/op" << std::endl;

    // Key and signature sizes
    std::cout << "  PK size: " << keys[0].first.size() << " bytes" << std::endl;
    std::cout << "  SK size: " << keys[0].second.size() << " bytes" << std::endl;
    std::cout << "  Sig size: " << sigs[0].size() << " bytes" << std::endl;
}

int main() {
    std::cout << "=== ML-DSA Test Suite ===" << std::endl << std::endl;

    std::cout << "--- ML-DSA-44 Tests ---" << std::endl;
    test_keygen<MLDSA44>();
    test_sign_verify<MLDSA44>();
    test_verification_failures<MLDSA44>();

    std::cout << std::endl << "--- ML-DSA-65 Tests ---" << std::endl;
    test_keygen<MLDSA65>();
    test_sign_verify<MLDSA65>();
    test_verification_failures<MLDSA65>();

    std::cout << std::endl << "--- ML-DSA-87 Tests ---" << std::endl;
    test_keygen<MLDSA87>();
    test_sign_verify<MLDSA87>();
    test_verification_failures<MLDSA87>();

    // Performance tests
    test_performance<MLDSA44>("ML-DSA-44");
    test_performance<MLDSA65>("ML-DSA-65");
    test_performance<MLDSA87>("ML-DSA-87");

    std::cout << std::endl << "=== Test Results ===" << std::endl;
    std::cout << "Passed: " << tests_passed << std::endl;
    std::cout << "Failed: " << tests_failed << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
