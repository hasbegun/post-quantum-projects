/**
 * FIPS 140-3 Self-Test Tests
 *
 * Tests for the FIPS self-test module.
 */

#include "common/fips_selftest.hpp"
#include <cassert>
#include <chrono>
#include <iostream>
#include <thread>
#include <vector>

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
// Initial State Tests
// ============================================================================

TEST(initial_state_not_run) {
    pqc::fips::reset_self_test_state();

    auto status = pqc::fips::get_self_test_status();

    ASSERT_EQ(status.mldsa, pqc::fips::TestState::NOT_RUN);
    ASSERT_EQ(status.slhdsa, pqc::fips::TestState::NOT_RUN);
    ASSERT_EQ(status.mlkem, pqc::fips::TestState::NOT_RUN);

    ASSERT(!status.all_passed());
    ASSERT(!status.any_failed());
    ASSERT(!status.all_run());
}


// ============================================================================
// ML-DSA Self-Test Tests
// ============================================================================

TEST(mldsa_self_test_runs) {
    pqc::fips::reset_self_test_state();

    ASSERT(!pqc::fips::mldsa_self_test_passed());

    pqc::fips::run_mldsa_self_test();

    ASSERT(pqc::fips::mldsa_self_test_passed());

    auto status = pqc::fips::get_self_test_status();
    ASSERT_EQ(status.mldsa, pqc::fips::TestState::PASSED);
}

TEST(mldsa_self_test_idempotent) {
    pqc::fips::reset_self_test_state();

    // Run twice, should succeed both times
    pqc::fips::run_mldsa_self_test();
    pqc::fips::run_mldsa_self_test();

    ASSERT(pqc::fips::mldsa_self_test_passed());
}

TEST(mldsa_ensure_tested) {
    pqc::fips::reset_self_test_state();

    ASSERT(!pqc::fips::mldsa_self_test_passed());

    // ensure_mldsa_tested should run the test
    pqc::fips::ensure_mldsa_tested();

    ASSERT(pqc::fips::mldsa_self_test_passed());
}


// ============================================================================
// SLH-DSA Self-Test Tests
// ============================================================================

TEST(slhdsa_self_test_runs) {
    pqc::fips::reset_self_test_state();

    ASSERT(!pqc::fips::slhdsa_self_test_passed());

    pqc::fips::run_slhdsa_self_test();

    ASSERT(pqc::fips::slhdsa_self_test_passed());

    auto status = pqc::fips::get_self_test_status();
    ASSERT_EQ(status.slhdsa, pqc::fips::TestState::PASSED);
}

TEST(slhdsa_self_test_idempotent) {
    pqc::fips::reset_self_test_state();

    pqc::fips::run_slhdsa_self_test();
    pqc::fips::run_slhdsa_self_test();

    ASSERT(pqc::fips::slhdsa_self_test_passed());
}

TEST(slhdsa_ensure_tested) {
    pqc::fips::reset_self_test_state();

    ASSERT(!pqc::fips::slhdsa_self_test_passed());

    pqc::fips::ensure_slhdsa_tested();

    ASSERT(pqc::fips::slhdsa_self_test_passed());
}


// ============================================================================
// ML-KEM Self-Test Tests
// ============================================================================

TEST(mlkem_self_test_runs) {
    pqc::fips::reset_self_test_state();

    ASSERT(!pqc::fips::mlkem_self_test_passed());

    pqc::fips::run_mlkem_self_test();

    ASSERT(pqc::fips::mlkem_self_test_passed());

    auto status = pqc::fips::get_self_test_status();
    ASSERT_EQ(status.mlkem, pqc::fips::TestState::PASSED);
}

TEST(mlkem_self_test_idempotent) {
    pqc::fips::reset_self_test_state();

    pqc::fips::run_mlkem_self_test();
    pqc::fips::run_mlkem_self_test();

    ASSERT(pqc::fips::mlkem_self_test_passed());
}

TEST(mlkem_ensure_tested) {
    pqc::fips::reset_self_test_state();

    ASSERT(!pqc::fips::mlkem_self_test_passed());

    pqc::fips::ensure_mlkem_tested();

    ASSERT(pqc::fips::mlkem_self_test_passed());
}


// ============================================================================
// Run All Tests
// ============================================================================

TEST(run_all_self_tests) {
    pqc::fips::reset_self_test_state();

    auto status_before = pqc::fips::get_self_test_status();
    ASSERT(!status_before.all_passed());
    ASSERT(!status_before.all_run());

    pqc::fips::run_all_self_tests();

    auto status_after = pqc::fips::get_self_test_status();
    ASSERT(status_after.all_passed());
    ASSERT(!status_after.any_failed());
    ASSERT(status_after.all_run());
}

TEST(run_all_idempotent) {
    pqc::fips::reset_self_test_state();

    pqc::fips::run_all_self_tests();
    pqc::fips::run_all_self_tests();

    auto status = pqc::fips::get_self_test_status();
    ASSERT(status.all_passed());
}


// ============================================================================
// Status Query Tests
// ============================================================================

TEST(status_partial_run) {
    pqc::fips::reset_self_test_state();

    pqc::fips::run_mldsa_self_test();

    auto status = pqc::fips::get_self_test_status();

    ASSERT_EQ(status.mldsa, pqc::fips::TestState::PASSED);
    ASSERT_EQ(status.slhdsa, pqc::fips::TestState::NOT_RUN);
    ASSERT_EQ(status.mlkem, pqc::fips::TestState::NOT_RUN);

    ASSERT(!status.all_passed());
    ASSERT(!status.any_failed());
    ASSERT(!status.all_run());
}

TEST(status_methods) {
    pqc::fips::reset_self_test_state();
    pqc::fips::run_all_self_tests();

    auto status = pqc::fips::get_self_test_status();

    ASSERT(status.all_passed());
    ASSERT(!status.any_failed());
    ASSERT(status.all_run());
}


// ============================================================================
// Thread Safety Tests
// ============================================================================

TEST(concurrent_self_tests) {
    pqc::fips::reset_self_test_state();

    std::vector<std::thread> threads;

    // Launch multiple threads trying to run self-tests concurrently
    for (int i = 0; i < 4; ++i) {
        threads.emplace_back([]() {
            pqc::fips::run_mldsa_self_test();
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    ASSERT(pqc::fips::mldsa_self_test_passed());
}

TEST(concurrent_different_algorithms) {
    pqc::fips::reset_self_test_state();

    std::thread t1([]() { pqc::fips::run_mldsa_self_test(); });
    std::thread t2([]() { pqc::fips::run_slhdsa_self_test(); });
    std::thread t3([]() { pqc::fips::run_mlkem_self_test(); });

    t1.join();
    t2.join();
    t3.join();

    auto status = pqc::fips::get_self_test_status();
    ASSERT(status.all_passed());
}


// ============================================================================
// Performance Tests
// ============================================================================

TEST(self_test_timing) {
    pqc::fips::reset_self_test_state();

    auto start = std::chrono::high_resolution_clock::now();
    pqc::fips::run_all_self_tests();
    auto end = std::chrono::high_resolution_clock::now();

    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::cout << " (" << duration_ms << "ms)";

    // Self-tests should complete in reasonable time (< 30 seconds)
    ASSERT(duration_ms < 30000);
}

TEST(repeated_ensure_fast) {
    // First ensure runs the test
    pqc::fips::reset_self_test_state();
    pqc::fips::ensure_mldsa_tested();

    // Subsequent ensures should be very fast (just atomic read)
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i) {
        pqc::fips::ensure_mldsa_tested();
    }
    auto end = std::chrono::high_resolution_clock::now();

    auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    std::cout << " (1000 calls in " << duration_us << "us)";

    // 1000 calls should take < 1ms (just atomic reads)
    ASSERT(duration_us < 1000);
}


// ============================================================================
// Exception Tests
// ============================================================================

TEST(self_test_failure_exception) {
    // Test that SelfTestFailure exception works correctly
    try {
        throw pqc::fips::SelfTestFailure("TEST-ALGO", "test reason");
    } catch (const pqc::fips::SelfTestFailure& e) {
        ASSERT_EQ(e.algorithm(), std::string("TEST-ALGO"));
        ASSERT_EQ(e.reason(), std::string("test reason"));
        ASSERT(std::string(e.what()).find("TEST-ALGO") != std::string::npos);
        ASSERT(std::string(e.what()).find("test reason") != std::string::npos);
    }
}


// ============================================================================
// Integration Tests
// ============================================================================

TEST(self_test_before_algorithm_use) {
    pqc::fips::reset_self_test_state();

    // In a FIPS-compliant deployment, you'd call ensure_*_tested() before use
    pqc::fips::ensure_mldsa_tested();

    // Now use the algorithm
    mldsa::MLDSA44 dsa;
    auto [pk, sk] = dsa.keygen();
    std::vector<uint8_t> msg = {1, 2, 3};
    auto sig = dsa.sign(sk, msg);
    ASSERT(dsa.verify(pk, msg, sig));
}

TEST(all_algorithms_tested_before_use) {
    pqc::fips::reset_self_test_state();

    // Run all self-tests upfront
    pqc::fips::run_all_self_tests();

    // Use ML-DSA
    {
        mldsa::MLDSA65 dsa;
        auto [pk, sk] = dsa.keygen();
        std::vector<uint8_t> msg = {1, 2, 3};
        auto sig = dsa.sign(sk, msg);
        ASSERT(dsa.verify(pk, msg, sig));
    }

    // Use SLH-DSA
    {
        auto [sk, pk] = slhdsa::slh_keygen(slhdsa::SLH_DSA_SHAKE_128f);
        std::vector<uint8_t> msg = {4, 5, 6};
        auto sig = slhdsa::slh_sign(slhdsa::SLH_DSA_SHAKE_128f, msg, sk);
        ASSERT(slhdsa::slh_verify(slhdsa::SLH_DSA_SHAKE_128f, msg, sig, pk));
    }

    // Use ML-KEM
    {
        mlkem::MLKEM768 kem;
        auto [ek, dk] = kem.keygen();
        auto [K1, ct] = kem.encaps(ek);
        auto K2 = kem.decaps(dk, ct);
        ASSERT(K1 == K2);
    }
}


// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "=== FIPS 140-3 Self-Test Tests ===\n\n";

    // Tests run automatically via static initialization

    std::cout << "\n=== Results ===\n";
    std::cout << "Passed: " << tests_passed << "\n";
    std::cout << "Failed: " << tests_failed << "\n";

    return tests_failed == 0 ? 0 : 1;
}
