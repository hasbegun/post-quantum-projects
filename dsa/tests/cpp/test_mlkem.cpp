/**
 * ML-KEM Test Suite
 * Tests for ML-KEM-512, ML-KEM-768, and ML-KEM-1024
 */

#include "mlkem/mlkem.hpp"
#include <iostream>
#include <cassert>
#include <chrono>
#include <iomanip>
#include <cstring>

using namespace mlkem;

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

template<typename KEM>
void test_keygen() {
    KEM kem;

    TEST("keygen generates valid key sizes") {
        auto [ek, dk] = kem.keygen();
        ASSERT_EQ(ek.size(), kem.params().ek_size());
        ASSERT_EQ(dk.size(), kem.params().dk_size());
    TEST_END

    TEST("keygen with seed is deterministic") {
        std::vector<uint8_t> seed(64, 0x42);
        auto [ek1, dk1] = kem.keygen(seed);
        auto [ek2, dk2] = kem.keygen(seed);
        ASSERT_TRUE(ek1 == ek2);
        ASSERT_TRUE(dk1 == dk2);
    TEST_END

    TEST("keygen without seed is random") {
        auto [ek1, dk1] = kem.keygen();
        auto [ek2, dk2] = kem.keygen();
        ASSERT_FALSE(ek1 == ek2);
        ASSERT_FALSE(dk1 == dk2);
    TEST_END
}

template<typename KEM>
void test_encaps_decaps() {
    KEM kem;

    TEST("encaps/decaps basic round-trip") {
        auto [ek, dk] = kem.keygen();
        auto [K1, c] = kem.encaps(ek);

        ASSERT_EQ(K1.size(), kem.params().ss_size());
        ASSERT_EQ(c.size(), kem.params().ct_size());

        auto K2 = kem.decaps(dk, c);
        ASSERT_EQ(K2.size(), kem.params().ss_size());
        ASSERT_TRUE(K1 == K2);
    TEST_END

    TEST("encaps with randomness is deterministic") {
        auto [ek, dk] = kem.keygen();
        std::vector<uint8_t> rand(32, 0xAB);

        auto [K1, c1] = kem.encaps(ek, rand);
        auto [K2, c2] = kem.encaps(ek, rand);

        ASSERT_TRUE(K1 == K2);
        ASSERT_TRUE(c1 == c2);
    TEST_END

    TEST("encaps without randomness is random") {
        auto [ek, dk] = kem.keygen();

        auto [K1, c1] = kem.encaps(ek);
        auto [K2, c2] = kem.encaps(ek);

        // Ciphertexts and shared secrets should be different
        ASSERT_FALSE(c1 == c2);
        ASSERT_FALSE(K1 == K2);
    TEST_END

    TEST("shared secret size is always 32 bytes") {
        auto [ek, dk] = kem.keygen();
        auto [K, c] = kem.encaps(ek);

        ASSERT_EQ(K.size(), static_cast<size_t>(32));

        auto K2 = kem.decaps(dk, c);
        ASSERT_EQ(K2.size(), static_cast<size_t>(32));
    TEST_END
}

template<typename KEM>
void test_decaps_failures() {
    KEM kem;

    TEST("decaps with wrong dk returns implicit rejection") {
        auto [ek1, dk1] = kem.keygen();
        auto [ek2, dk2] = kem.keygen();

        auto [K_expected, c] = kem.encaps(ek1);

        // Decaps with wrong dk should return a pseudorandom value, not K
        auto K_wrong = kem.decaps(dk2, c);

        // The result should be a valid 32-byte value
        ASSERT_EQ(K_wrong.size(), static_cast<size_t>(32));

        // But it should NOT be the correct shared secret
        ASSERT_FALSE(K_expected == K_wrong);
    TEST_END

    TEST("decaps with tampered ciphertext returns implicit rejection") {
        auto [ek, dk] = kem.keygen();
        auto [K_expected, c] = kem.encaps(ek);

        // Tamper with ciphertext
        std::vector<uint8_t> c_tampered = c;
        c_tampered[0] ^= 0xFF;

        auto K_wrong = kem.decaps(dk, c_tampered);

        // Should return a valid but incorrect shared secret
        ASSERT_EQ(K_wrong.size(), static_cast<size_t>(32));
        ASSERT_FALSE(K_expected == K_wrong);
    TEST_END

    TEST("implicit rejection is deterministic") {
        auto [ek, dk] = kem.keygen();
        auto [K, c] = kem.encaps(ek);

        // Tamper with ciphertext
        std::vector<uint8_t> c_tampered = c;
        c_tampered[0] ^= 0xFF;

        // Same tampered ciphertext should give same rejection value
        auto K1 = kem.decaps(dk, c_tampered);
        auto K2 = kem.decaps(dk, c_tampered);

        ASSERT_TRUE(K1 == K2);
    TEST_END
}

template<typename KEM>
void test_input_validation() {
    KEM kem;

    TEST("keygen rejects wrong seed size") {
        std::vector<uint8_t> bad_seed(32, 0);  // Should be 64 bytes
        bool threw = false;
        try {
            kem.keygen(bad_seed);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        ASSERT_TRUE(threw);
    TEST_END

    TEST("encaps rejects wrong ek size") {
        std::vector<uint8_t> bad_ek(100, 0);  // Wrong size
        bool threw = false;
        try {
            kem.encaps(bad_ek);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        ASSERT_TRUE(threw);
    TEST_END

    TEST("decaps rejects wrong dk size") {
        auto [ek, dk] = kem.keygen();
        auto [K, c] = kem.encaps(ek);

        std::vector<uint8_t> bad_dk(100, 0);  // Wrong size
        bool threw = false;
        try {
            kem.decaps(bad_dk, c);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        ASSERT_TRUE(threw);
    TEST_END

    TEST("decaps rejects wrong ciphertext size") {
        auto [ek, dk] = kem.keygen();

        std::vector<uint8_t> bad_ct(100, 0);  // Wrong size
        bool threw = false;
        try {
            kem.decaps(dk, bad_ct);
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        ASSERT_TRUE(threw);
    TEST_END
}

template<typename KEM>
void test_performance(const std::string& name) {
    KEM kem;
    const int iterations = 10;

    std::cout << "\nPerformance (" << name << ", " << iterations << " iterations):" << std::endl;

    // Keygen timing
    auto start = std::chrono::high_resolution_clock::now();
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> keys;
    for (int i = 0; i < iterations; ++i) {
        keys.push_back(kem.keygen());
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto keygen_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    std::cout << "  KeyGen: " << keygen_ms << " ms total, "
              << std::fixed << std::setprecision(2)
              << (double)keygen_ms / iterations << " ms/op" << std::endl;

    // Encaps timing
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> encaps_results;
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        encaps_results.push_back(kem.encaps(keys[i].first));
    }
    end = std::chrono::high_resolution_clock::now();
    auto encaps_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    std::cout << "  Encaps: " << encaps_ms << " ms total, "
              << std::fixed << std::setprecision(2)
              << (double)encaps_ms / iterations << " ms/op" << std::endl;

    // Decaps timing
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        kem.decaps(keys[i].second, encaps_results[i].second);
    }
    end = std::chrono::high_resolution_clock::now();
    auto decaps_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    std::cout << "  Decaps: " << decaps_ms << " ms total, "
              << std::fixed << std::setprecision(2)
              << (double)decaps_ms / iterations << " ms/op" << std::endl;

    // Key and ciphertext sizes
    std::cout << "  EK size: " << keys[0].first.size() << " bytes" << std::endl;
    std::cout << "  DK size: " << keys[0].second.size() << " bytes" << std::endl;
    std::cout << "  CT size: " << encaps_results[0].second.size() << " bytes" << std::endl;
    std::cout << "  SS size: " << encaps_results[0].first.size() << " bytes" << std::endl;
}

int main() {
    std::cout << "=== ML-KEM Test Suite ===" << std::endl << std::endl;

    std::cout << "--- ML-KEM-512 Tests ---" << std::endl;
    test_keygen<MLKEM512>();
    test_encaps_decaps<MLKEM512>();
    test_decaps_failures<MLKEM512>();
    test_input_validation<MLKEM512>();

    std::cout << std::endl << "--- ML-KEM-768 Tests ---" << std::endl;
    test_keygen<MLKEM768>();
    test_encaps_decaps<MLKEM768>();
    test_decaps_failures<MLKEM768>();
    test_input_validation<MLKEM768>();

    std::cout << std::endl << "--- ML-KEM-1024 Tests ---" << std::endl;
    test_keygen<MLKEM1024>();
    test_encaps_decaps<MLKEM1024>();
    test_decaps_failures<MLKEM1024>();
    test_input_validation<MLKEM1024>();

    // Performance tests
    test_performance<MLKEM512>("ML-KEM-512");
    test_performance<MLKEM768>("ML-KEM-768");
    test_performance<MLKEM1024>("ML-KEM-1024");

    std::cout << std::endl << "=== Test Results ===" << std::endl;
    std::cout << "Passed: " << tests_passed << std::endl;
    std::cout << "Failed: " << tests_failed << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
