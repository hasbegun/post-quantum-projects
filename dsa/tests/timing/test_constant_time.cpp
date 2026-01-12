/**
 * Constant-Time Verification Tests using dudect methodology
 *
 * This tests critical constant-time operations for timing leaks using
 * statistical analysis of execution times.
 *
 * For each function, we:
 * 1. Generate two classes of inputs (class 0: fixed, class 1: random)
 * 2. Measure execution time for many samples
 * 3. Apply Welch's t-test to detect timing differences
 *
 * A |t| value >= 4.5 indicates a timing leak with high confidence.
 */

#include "dudect.h"
#include "../../src/cpp/ct_utils.hpp"
#include "../../src/cpp/slhdsa/ct_utils.hpp"
#include "../../src/cpp/mldsa/mldsa.hpp"
#include "../../src/cpp/slhdsa/slh_dsa.hpp"

#include <iostream>
#include <iomanip>
#include <random>
#include <vector>
#include <functional>
#include <array>

// Number of measurements per test
constexpr int NUM_MEASUREMENTS = 100000;

// Random number generator
static std::random_device rd;
static std::mt19937_64 rng(rd());

// Generate random bytes
static std::vector<uint8_t> random_bytes(size_t n) {
    std::vector<uint8_t> bytes(n);
    std::uniform_int_distribution<int> dist(0, 255);
    for (auto& b : bytes) b = static_cast<uint8_t>(dist(rng));
    return bytes;
}

// Test result structure
struct TestResult {
    const char* name;
    double t_value;
    dudect_result_t result;
    int64_t measurements;
};

// ============================================================================
// Test: ct::equal (byte array comparison)
// Tests that comparison takes same time regardless of match position
// ============================================================================
TestResult test_ct_equal() {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx);

    for (int i = 0; i < NUM_MEASUREMENTS; i++) {
        int input_class = rng() % 2;

        // Both classes use random data
        std::vector<uint8_t> a = random_bytes(32);
        std::vector<uint8_t> b = a;  // Start with copy

        if (input_class == 0) {
            // Class 0: difference at FIRST byte
            b[0] ^= 0x01;
        } else {
            // Class 1: difference at LAST byte
            b[31] ^= 0x01;
        }

        uint64_t start = dudect_get_time();
        volatile bool result = ct::equal(a, b);
        (void)result;
        uint64_t end = dudect_get_time();

        dudect_ctx_update(&ctx, input_class, (double)(end - start));
    }

    double t = dudect_ctx_t_value(&ctx);
    return {"ct::equal (early vs late diff)", t, dudect_interpret(t), NUM_MEASUREMENTS};
}

// ============================================================================
// Test: ct::select_u32 (constant-time selection)
// ============================================================================
TestResult test_ct_select_u32() {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx);

    for (int i = 0; i < NUM_MEASUREMENTS; i++) {
        int input_class = rng() % 2;

        uint32_t a = static_cast<uint32_t>(rng());
        uint32_t b = static_cast<uint32_t>(rng());
        bool condition;

        if (input_class == 0) {
            condition = false;  // Always select b
        } else {
            condition = true;   // Always select a
        }

        uint64_t start = dudect_get_time();
        volatile uint32_t result = ct::select_u32(a, b, condition);
        (void)result;
        uint64_t end = dudect_get_time();

        dudect_ctx_update(&ctx, input_class, (double)(end - start));
    }

    double t = dudect_ctx_t_value(&ctx);
    return {"ct::select_u32", t, dudect_interpret(t), NUM_MEASUREMENTS};
}

// ============================================================================
// Test: ct::ge_u32 (constant-time comparison)
// ============================================================================
TestResult test_ct_ge_u32() {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx);

    for (int i = 0; i < NUM_MEASUREMENTS; i++) {
        int input_class = rng() % 2;

        uint32_t a, b;
        if (input_class == 0) {
            // Class 0: a >= b
            b = static_cast<uint32_t>(rng() % 1000000);
            a = b + static_cast<uint32_t>(rng() % 1000000);
        } else {
            // Class 1: a < b
            a = static_cast<uint32_t>(rng() % 1000000);
            b = a + 1 + static_cast<uint32_t>(rng() % 1000000);
        }

        uint64_t start = dudect_get_time();
        volatile uint32_t result = ct::ge_u32(a, b);
        (void)result;
        uint64_t end = dudect_get_time();

        dudect_ctx_update(&ctx, input_class, (double)(end - start));
    }

    double t = dudect_ctx_t_value(&ctx);
    return {"ct::ge_u32", t, dudect_interpret(t), NUM_MEASUREMENTS};
}

// ============================================================================
// Test: slhdsa::ct::ct_equal (SLH-DSA constant-time comparison)
// Tests that comparison takes same time regardless of match position
// ============================================================================
TestResult test_slhdsa_ct_equal() {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx);

    for (int i = 0; i < NUM_MEASUREMENTS; i++) {
        int input_class = rng() % 2;

        // Both classes use random data
        std::vector<uint8_t> a = random_bytes(32);
        std::vector<uint8_t> b = a;  // Start with copy

        if (input_class == 0) {
            // Class 0: difference at FIRST byte
            b[0] ^= 0x01;
        } else {
            // Class 1: difference at LAST byte
            b[31] ^= 0x01;
        }

        uint64_t start = dudect_get_time();
        volatile bool result = slhdsa::ct::ct_equal(a, b);
        (void)result;
        uint64_t end = dudect_get_time();

        dudect_ctx_update(&ctx, input_class, (double)(end - start));
    }

    double t = dudect_ctx_t_value(&ctx);
    return {"slhdsa::ct::ct_equal (early vs late)", t, dudect_interpret(t), NUM_MEASUREMENTS};
}

// ============================================================================
// Test: slhdsa::ct::ct_concat_conditional
// ============================================================================
TestResult test_ct_concat_conditional() {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx);

    std::vector<uint8_t> a(16, 0xAA);
    std::vector<uint8_t> b(16, 0xBB);

    for (int i = 0; i < NUM_MEASUREMENTS; i++) {
        int input_class = rng() % 2;

        bool a_first = (input_class == 0);

        uint64_t start = dudect_get_time();
        auto result = slhdsa::ct::ct_concat_conditional(a, b, a_first);
        volatile uint8_t sink = result[0];
        (void)sink;
        uint64_t end = dudect_get_time();

        dudect_ctx_update(&ctx, input_class, (double)(end - start));
    }

    double t = dudect_ctx_t_value(&ctx);
    return {"slhdsa::ct::ct_concat_conditional", t, dudect_interpret(t), NUM_MEASUREMENTS};
}

// ============================================================================
// Test: ML-DSA verification (different signature validity)
// ============================================================================
TestResult test_mldsa_verify_timing() {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx);

    // Generate a valid key pair and signature
    mldsa::MLDSA dsa(mldsa::MLDSA44_PARAMS);
    auto [pk, sk] = dsa.keygen();
    std::vector<uint8_t> message = {'t', 'e', 's', 't'};
    auto valid_sig = dsa.sign(sk, message);

    // Create invalid signature (tampered)
    std::vector<uint8_t> invalid_sig = valid_sig;
    invalid_sig[100] ^= 0xFF;

    // Reduce measurements for this slow test
    constexpr int VERIFY_MEASUREMENTS = 1000;

    for (int i = 0; i < VERIFY_MEASUREMENTS; i++) {
        int input_class = rng() % 2;

        const auto& sig = (input_class == 0) ? valid_sig : invalid_sig;

        uint64_t start = dudect_get_time();
        volatile bool result = dsa.verify(pk, message, sig);
        (void)result;
        uint64_t end = dudect_get_time();

        dudect_ctx_update(&ctx, input_class, (double)(end - start));
    }

    double t = dudect_ctx_t_value(&ctx);
    return {"MLDSA::verify (valid vs invalid)", t, dudect_interpret(t), VERIFY_MEASUREMENTS};
}

// ============================================================================
// Test: SLH-DSA verification (different signature validity)
// ============================================================================
TestResult test_slhdsa_verify_timing() {
    dudect_ctx_t ctx;
    dudect_ctx_init(&ctx);

    // Generate a valid key pair and signature
    slhdsa::SLHDSA_SHAKE_128f dsa;
    auto [pk, sk] = dsa.keygen();
    std::vector<uint8_t> message = {'t', 'e', 's', 't'};
    auto valid_sig = dsa.sign(sk, message);

    // Create invalid signature (tampered)
    std::vector<uint8_t> invalid_sig = valid_sig;
    invalid_sig[100] ^= 0xFF;

    // Reduce measurements for this slow test
    constexpr int VERIFY_MEASUREMENTS = 200;

    for (int i = 0; i < VERIFY_MEASUREMENTS; i++) {
        int input_class = rng() % 2;

        const auto& sig = (input_class == 0) ? valid_sig : invalid_sig;

        uint64_t start = dudect_get_time();
        volatile bool result = dsa.verify(pk, message, sig);
        (void)result;
        uint64_t end = dudect_get_time();

        dudect_ctx_update(&ctx, input_class, (double)(end - start));
    }

    double t = dudect_ctx_t_value(&ctx);
    return {"SLHDSA::verify (valid vs invalid)", t, dudect_interpret(t), VERIFY_MEASUREMENTS};
}

// ============================================================================
// Main test runner
// ============================================================================
int main() {
    std::cout << "========================================================\n";
    std::cout << "  Constant-Time Verification Tests (dudect methodology)\n";
    std::cout << "========================================================\n\n";

    std::cout << "Interpretation:\n";
    std::cout << "  |t| < 2.0  : No timing leak evidence (PASS)\n";
    std::cout << "  |t| < 4.5  : Possible leak, inconclusive\n";
    std::cout << "  |t| >= 4.5 : Timing leak detected (FAIL)\n\n";

    std::vector<TestResult> results;

    std::cout << "Running tests...\n\n";

    // Run all tests
    std::cout << "  [1/7] Testing ct::equal..." << std::flush;
    results.push_back(test_ct_equal());
    std::cout << " done\n";

    std::cout << "  [2/7] Testing ct::select_u32..." << std::flush;
    results.push_back(test_ct_select_u32());
    std::cout << " done\n";

    std::cout << "  [3/7] Testing ct::ge_u32..." << std::flush;
    results.push_back(test_ct_ge_u32());
    std::cout << " done\n";

    std::cout << "  [4/7] Testing slhdsa::ct::ct_equal..." << std::flush;
    results.push_back(test_slhdsa_ct_equal());
    std::cout << " done\n";

    std::cout << "  [5/7] Testing slhdsa::ct::ct_concat_conditional..." << std::flush;
    results.push_back(test_ct_concat_conditional());
    std::cout << " done\n";

    std::cout << "  [6/7] Testing MLDSA::verify timing..." << std::flush;
    results.push_back(test_mldsa_verify_timing());
    std::cout << " done\n";

    std::cout << "  [7/7] Testing SLHDSA::verify timing..." << std::flush;
    results.push_back(test_slhdsa_verify_timing());
    std::cout << " done\n";

    // Print results
    std::cout << "\n========================================================\n";
    std::cout << "                        RESULTS\n";
    std::cout << "========================================================\n\n";

    int passed = 0, failed = 0, inconclusive = 0;

    std::cout << std::left << std::setw(40) << "Test"
              << std::right << std::setw(12) << "t-value"
              << std::setw(12) << "Samples"
              << "  Result\n";
    std::cout << std::string(76, '-') << "\n";

    for (const auto& r : results) {
        std::cout << std::left << std::setw(40) << r.name
                  << std::right << std::setw(12) << std::fixed << std::setprecision(2) << r.t_value
                  << std::setw(12) << r.measurements
                  << "  ";

        switch (r.result) {
            case DUDECT_NO_LEAK_EVIDENCE:
                std::cout << "\033[32mPASS\033[0m";
                passed++;
                break;
            case DUDECT_POSSIBLE_LEAK:
                std::cout << "\033[33mINCONCLUSIVE\033[0m";
                inconclusive++;
                break;
            case DUDECT_LEAK_FOUND:
                std::cout << "\033[31mFAIL - TIMING LEAK\033[0m";
                failed++;
                break;
        }
        std::cout << "\n";
    }

    std::cout << std::string(76, '-') << "\n";
    std::cout << "\nSummary: " << passed << " passed, "
              << inconclusive << " inconclusive, "
              << failed << " failed\n\n";

    if (failed > 0) {
        std::cout << "\033[31mWARNING: Timing leaks detected!\033[0m\n";
        return 1;
    } else if (inconclusive > 0) {
        std::cout << "\033[33mNote: Some tests inconclusive. Run with more samples.\033[0m\n";
        return 0;
    } else {
        std::cout << "\033[32mAll tests passed - no timing leaks detected.\033[0m\n";
        return 0;
    }
}
