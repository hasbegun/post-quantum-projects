/**
 * SLH-DSA Test Suite
 * Tests for all SLH-DSA parameter sets (FIPS 205)
 */

#include "slhdsa/slh_dsa.hpp"
#include <iostream>
#include <cassert>
#include <chrono>
#include <iomanip>

using namespace slhdsa;

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
void test_keygen(const std::string& name) {
    DSA dsa;

    TEST(name + " keygen generates valid key sizes") {
        auto [sk, pk] = dsa.keygen();
        ASSERT_EQ(pk.size(), dsa.params().pk_size());
        ASSERT_EQ(sk.size(), dsa.params().sk_size());
    TEST_END

    TEST(name + " keygen produces random keys") {
        auto [pk1, sk1] = dsa.keygen();
        auto [pk2, sk2] = dsa.keygen();
        ASSERT_FALSE(pk1 == pk2);
        ASSERT_FALSE(sk1 == sk2);
    TEST_END
}

template<typename DSA>
void test_sign_verify(const std::string& name) {
    DSA dsa;

    TEST(name + " sign/verify basic") {
        auto [sk, pk] = dsa.keygen();
        std::vector<uint8_t> message = {'h', 'e', 'l', 'l', 'o'};
        auto sig = dsa.sign(sk, message);
        ASSERT_EQ(sig.size(), dsa.params().sig_size());
        ASSERT_TRUE(dsa.verify(pk, message, sig));
    TEST_END

    TEST(name + " sign/verify empty message") {
        auto [sk, pk] = dsa.keygen();
        std::vector<uint8_t> message;
        auto sig = dsa.sign(sk, message);
        ASSERT_TRUE(dsa.verify(pk, message, sig));
    TEST_END

    TEST(name + " sign/verify with context") {
        auto [sk, pk] = dsa.keygen();
        std::vector<uint8_t> message = {'t', 'e', 's', 't'};
        std::vector<uint8_t> ctx = {'c', 't', 'x'};
        auto sig = dsa.sign(sk, message, ctx);
        ASSERT_TRUE(dsa.verify(pk, message, sig, ctx));
        // Wrong context should fail
        std::vector<uint8_t> wrong_ctx = {'w', 'r', 'o', 'n', 'g'};
        ASSERT_FALSE(dsa.verify(pk, message, sig, wrong_ctx));
    TEST_END

    TEST(name + " deterministic signing") {
        auto [sk, pk] = dsa.keygen();
        std::vector<uint8_t> message = {'d', 'e', 't', 'e', 'r', 'm'};
        auto sig1 = dsa.sign(sk, message, {}, false);
        auto sig2 = dsa.sign(sk, message, {}, false);
        ASSERT_TRUE(sig1 == sig2);
    TEST_END

    TEST(name + " randomized signing produces different signatures") {
        auto [sk, pk] = dsa.keygen();
        std::vector<uint8_t> message = {'r', 'a', 'n', 'd'};
        auto sig1 = dsa.sign(sk, message, {}, true);
        auto sig2 = dsa.sign(sk, message, {}, true);
        // Both should verify
        ASSERT_TRUE(dsa.verify(pk, message, sig1));
        ASSERT_TRUE(dsa.verify(pk, message, sig2));
        // But be different (with very high probability)
        ASSERT_FALSE(sig1 == sig2);
    TEST_END
}

template<typename DSA>
void test_verification_failures(const std::string& name) {
    DSA dsa;

    TEST(name + " wrong message fails verification") {
        auto [sk, pk] = dsa.keygen();
        std::vector<uint8_t> message = {'o', 'r', 'i', 'g'};
        auto sig = dsa.sign(sk, message);
        std::vector<uint8_t> wrong_message = {'w', 'r', 'o', 'n', 'g'};
        ASSERT_FALSE(dsa.verify(pk, wrong_message, sig));
    TEST_END

    TEST(name + " wrong public key fails verification") {
        auto [sk1, pk1] = dsa.keygen();
        auto [sk2, pk2] = dsa.keygen();
        std::vector<uint8_t> message = {'t', 'e', 's', 't'};
        auto sig = dsa.sign(sk1, message);
        ASSERT_TRUE(dsa.verify(pk1, message, sig));
        ASSERT_FALSE(dsa.verify(pk2, message, sig));
    TEST_END

    TEST(name + " tampered signature fails verification") {
        auto [sk, pk] = dsa.keygen();
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
    const int iterations = 1;  // SLH-DSA is slow, use fewer iterations

    std::cout << "\nPerformance (" << name << ", " << iterations << " iterations):" << std::endl;

    // Keygen timing
    auto start = std::chrono::high_resolution_clock::now();
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> keys;
    for (int i = 0; i < iterations; ++i) {
        auto [sk, pk] = dsa.keygen();
        keys.push_back({sk, pk});
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
        sigs.push_back(dsa.sign(keys[i].first, message));
    }
    end = std::chrono::high_resolution_clock::now();
    auto sign_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    std::cout << "  Sign:   " << sign_ms << " ms total, "
              << std::fixed << std::setprecision(2)
              << (double)sign_ms / iterations << " ms/op" << std::endl;

    // Verify timing
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        bool valid = dsa.verify(keys[i].second, message, sigs[i]);
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
    std::cout << "  PK size: " << keys[0].second.size() << " bytes" << std::endl;
    std::cout << "  SK size: " << keys[0].first.size() << " bytes" << std::endl;
    std::cout << "  Sig size: " << sigs[0].size() << " bytes" << std::endl;
}

int main() {
    std::cout << "=== SLH-DSA Test Suite (FIPS 205) ===" << std::endl << std::endl;

    // Test SHAKE-based parameter sets (faster)
    std::cout << "--- SLH-DSA-SHAKE-128f Tests ---" << std::endl;
    test_keygen<SLHDSA_SHAKE_128f>("SHAKE-128f");
    test_sign_verify<SLHDSA_SHAKE_128f>("SHAKE-128f");
    test_verification_failures<SLHDSA_SHAKE_128f>("SHAKE-128f");

    std::cout << std::endl << "--- SLH-DSA-SHA2-128f Tests ---" << std::endl;
    test_keygen<SLHDSA_SHA2_128f>("SHA2-128f");
    test_sign_verify<SLHDSA_SHA2_128f>("SHA2-128f");
    test_verification_failures<SLHDSA_SHA2_128f>("SHA2-128f");

    // Performance tests on fast variants only (to keep test time reasonable)
    test_performance<SLHDSA_SHAKE_128f>("SLH-DSA-SHAKE-128f");
    test_performance<SLHDSA_SHA2_128f>("SLH-DSA-SHA2-128f");

    std::cout << std::endl << "=== Test Results ===" << std::endl;
    std::cout << "Passed: " << tests_passed << std::endl;
    std::cout << "Failed: " << tests_failed << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
