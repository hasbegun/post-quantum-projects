/**
 * Batch Verification Tests
 *
 * Tests for the batch signature verification functionality.
 */

#include "common/batch_verify.hpp"
#include "common/algorithm_factory.hpp"
#include <cassert>
#include <chrono>
#include <iostream>
#include <random>

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
// Empty Batch Tests
// ============================================================================

TEST(empty_batch_homogeneous) {
    auto dsa = pqc::create_dsa("ML-DSA-44");
    std::vector<pqc::VerificationItem> items;

    auto result = pqc::batch_verify(*dsa, items);

    ASSERT(result.all_valid);
    ASSERT_EQ(result.total_count, size_t(0));
    ASSERT_EQ(result.valid_count, size_t(0));
    ASSERT_EQ(result.invalid_count, size_t(0));
    ASSERT(result.results.empty());
}

TEST(empty_batch_heterogeneous) {
    std::vector<pqc::HeterogeneousItem> items;

    auto result = pqc::batch_verify_heterogeneous(items);

    ASSERT(result.all_valid);
    ASSERT_EQ(result.total_count, size_t(0));
    ASSERT_EQ(result.valid_count, size_t(0));
    ASSERT_EQ(result.invalid_count, size_t(0));
}


// ============================================================================
// Single Item Tests
// ============================================================================

TEST(single_valid_signature) {
    auto dsa = pqc::create_dsa("ML-DSA-44");
    auto [pk, sk] = dsa->keygen();

    std::vector<uint8_t> message = {1, 2, 3, 4, 5};
    auto sig = dsa->sign(sk, message);

    std::vector<pqc::VerificationItem> items;
    items.emplace_back(pk, message, sig);

    auto result = pqc::batch_verify(*dsa, items);

    ASSERT(result.all_valid);
    ASSERT_EQ(result.valid_count, size_t(1));
    ASSERT_EQ(result.invalid_count, size_t(0));
    ASSERT(result.results[0]);
}

TEST(single_invalid_signature) {
    auto dsa = pqc::create_dsa("ML-DSA-44");
    auto [pk, sk] = dsa->keygen();

    std::vector<uint8_t> message = {1, 2, 3, 4, 5};
    auto sig = dsa->sign(sk, message);

    // Corrupt signature
    sig[0] ^= 0xFF;

    std::vector<pqc::VerificationItem> items;
    items.emplace_back(pk, message, sig);

    auto result = pqc::batch_verify(*dsa, items);

    ASSERT(!result.all_valid);
    ASSERT_EQ(result.valid_count, size_t(0));
    ASSERT_EQ(result.invalid_count, size_t(1));
    ASSERT(!result.results[0]);
}


// ============================================================================
// Multi-Item Homogeneous Tests
// ============================================================================

TEST(multiple_valid_signatures_mldsa44) {
    auto dsa = pqc::create_dsa("ML-DSA-44");
    auto [pk, sk] = dsa->keygen();

    std::vector<pqc::VerificationItem> items;
    for (int i = 0; i < 10; ++i) {
        std::vector<uint8_t> msg(32);
        for (int j = 0; j < 32; ++j) msg[j] = static_cast<uint8_t>(i * 32 + j);
        auto sig = dsa->sign(sk, msg);
        items.emplace_back(pk, msg, sig);
    }

    auto result = pqc::batch_verify(*dsa, items);

    ASSERT(result.all_valid);
    ASSERT_EQ(result.valid_count, size_t(10));
    ASSERT_EQ(result.invalid_count, size_t(0));
    ASSERT_EQ(result.total_count, size_t(10));

    for (size_t i = 0; i < 10; ++i) {
        ASSERT(result.is_valid(i));
    }
}

TEST(mixed_valid_invalid_signatures) {
    auto dsa = pqc::create_dsa("ML-DSA-44");
    auto [pk, sk] = dsa->keygen();

    std::vector<pqc::VerificationItem> items;

    // Create 5 valid and 5 invalid signatures
    for (int i = 0; i < 10; ++i) {
        std::vector<uint8_t> msg = {static_cast<uint8_t>(i)};
        auto sig = dsa->sign(sk, msg);

        // Corrupt odd-indexed signatures
        if (i % 2 == 1) {
            sig[0] ^= 0xFF;
        }

        items.emplace_back(pk, msg, sig);
    }

    auto result = pqc::batch_verify(*dsa, items);

    ASSERT(!result.all_valid);
    ASSERT_EQ(result.valid_count, size_t(5));
    ASSERT_EQ(result.invalid_count, size_t(5));

    // Check individual results
    for (int i = 0; i < 10; ++i) {
        if (i % 2 == 0) {
            ASSERT(result.results[i]);
        } else {
            ASSERT(!result.results[i]);
        }
    }

    // Check failed_indices
    auto failed = result.failed_indices();
    ASSERT_EQ(failed.size(), size_t(5));
    for (size_t idx : failed) {
        ASSERT(idx % 2 == 1);
    }
}


// ============================================================================
// Sequential Verification Tests
// ============================================================================

TEST(sequential_verification) {
    auto dsa = pqc::create_dsa("ML-DSA-44");
    auto [pk, sk] = dsa->keygen();

    std::vector<pqc::VerificationItem> items;
    for (int i = 0; i < 5; ++i) {
        std::vector<uint8_t> msg = {static_cast<uint8_t>(i)};
        auto sig = dsa->sign(sk, msg);
        items.emplace_back(pk, msg, sig);
    }

    auto result = pqc::batch_verify_sequential(*dsa, items);

    ASSERT(result.all_valid);
    ASSERT_EQ(result.valid_count, size_t(5));
}

TEST(sequential_fail_fast) {
    auto dsa = pqc::create_dsa("ML-DSA-44");
    auto [pk, sk] = dsa->keygen();

    std::vector<pqc::VerificationItem> items;

    // First item is invalid
    std::vector<uint8_t> msg1 = {1};
    auto sig1 = dsa->sign(sk, msg1);
    sig1[0] ^= 0xFF;  // Corrupt
    items.emplace_back(pk, msg1, sig1);

    // Rest are valid
    for (int i = 1; i < 5; ++i) {
        std::vector<uint8_t> msg = {static_cast<uint8_t>(i)};
        auto sig = dsa->sign(sk, msg);
        items.emplace_back(pk, msg, sig);
    }

    auto result = pqc::batch_verify_sequential(*dsa, items, true);  // fail_fast = true

    ASSERT(!result.all_valid);
    ASSERT(!result.results[0]);  // First item should be invalid
}


// ============================================================================
// Heterogeneous Batch Tests
// ============================================================================

TEST(heterogeneous_single_algorithm) {
    auto dsa = pqc::create_dsa("ML-DSA-65");
    auto [pk, sk] = dsa->keygen();

    std::vector<pqc::HeterogeneousItem> items;
    for (int i = 0; i < 5; ++i) {
        std::vector<uint8_t> msg = {static_cast<uint8_t>(i)};
        auto sig = dsa->sign(sk, msg);
        items.emplace_back("ML-DSA-65", pk, msg, sig);
    }

    auto result = pqc::batch_verify_heterogeneous(items);

    ASSERT(result.all_valid);
    ASSERT_EQ(result.valid_count, size_t(5));
}

TEST(heterogeneous_mixed_mldsa) {
    // Create keys for different ML-DSA variants
    auto dsa44 = pqc::create_dsa("ML-DSA-44");
    auto dsa65 = pqc::create_dsa("ML-DSA-65");
    auto dsa87 = pqc::create_dsa("ML-DSA-87");

    auto [pk44, sk44] = dsa44->keygen();
    auto [pk65, sk65] = dsa65->keygen();
    auto [pk87, sk87] = dsa87->keygen();

    std::vector<pqc::HeterogeneousItem> items;

    // Add signatures from each algorithm
    std::vector<uint8_t> msg1 = {1, 2, 3};
    std::vector<uint8_t> msg2 = {4, 5, 6};
    std::vector<uint8_t> msg3 = {7, 8, 9};

    auto sig44 = dsa44->sign(sk44, msg1);
    auto sig65 = dsa65->sign(sk65, msg2);
    auto sig87 = dsa87->sign(sk87, msg3);

    items.emplace_back("ML-DSA-44", pk44, msg1, sig44);
    items.emplace_back("ML-DSA-65", pk65, msg2, sig65);
    items.emplace_back("ML-DSA-87", pk87, msg3, sig87);

    auto result = pqc::batch_verify_heterogeneous(items);

    ASSERT(result.all_valid);
    ASSERT_EQ(result.valid_count, size_t(3));
    ASSERT_EQ(result.total_count, size_t(3));
}

TEST(heterogeneous_mixed_mldsa_slhdsa) {
    // Mix ML-DSA and SLH-DSA algorithms
    auto mldsa = pqc::create_dsa("ML-DSA-44");
    auto slhdsa = pqc::create_dsa("SLH-DSA-SHAKE-128f");  // Use 'f' variant for speed

    auto [pk_mldsa, sk_mldsa] = mldsa->keygen();
    auto [pk_slhdsa, sk_slhdsa] = slhdsa->keygen();

    std::vector<pqc::HeterogeneousItem> items;

    std::vector<uint8_t> msg1 = {1, 2, 3};
    std::vector<uint8_t> msg2 = {4, 5, 6};

    auto sig1 = mldsa->sign(sk_mldsa, msg1);
    auto sig2 = slhdsa->sign(sk_slhdsa, msg2);

    items.emplace_back("ML-DSA-44", pk_mldsa, msg1, sig1);
    items.emplace_back("SLH-DSA-SHAKE-128f", pk_slhdsa, msg2, sig2);

    auto result = pqc::batch_verify_heterogeneous(items);

    ASSERT(result.all_valid);
    ASSERT_EQ(result.valid_count, size_t(2));
}

TEST(heterogeneous_unknown_algorithm) {
    std::vector<pqc::HeterogeneousItem> items;

    // Add an item with an unknown algorithm
    std::vector<uint8_t> dummy(32, 0);
    items.emplace_back("UNKNOWN-ALGO", dummy, dummy, dummy);

    auto result = pqc::batch_verify_heterogeneous(items);

    ASSERT(!result.all_valid);
    ASSERT_EQ(result.invalid_count, size_t(1));
    ASSERT(!result.results[0]);
}

TEST(heterogeneous_sequential) {
    auto dsa = pqc::create_dsa("ML-DSA-44");
    auto [pk, sk] = dsa->keygen();

    std::vector<pqc::HeterogeneousItem> items;
    for (int i = 0; i < 5; ++i) {
        std::vector<uint8_t> msg = {static_cast<uint8_t>(i)};
        auto sig = dsa->sign(sk, msg);
        items.emplace_back("ML-DSA-44", pk, msg, sig);
    }

    auto result = pqc::batch_verify_heterogeneous_sequential(items);

    ASSERT(result.all_valid);
    ASSERT_EQ(result.valid_count, size_t(5));
}


// ============================================================================
// Options Tests
// ============================================================================

TEST(explicit_single_thread) {
    auto dsa = pqc::create_dsa("ML-DSA-44");
    auto [pk, sk] = dsa->keygen();

    std::vector<pqc::VerificationItem> items;
    for (int i = 0; i < 5; ++i) {
        std::vector<uint8_t> msg = {static_cast<uint8_t>(i)};
        auto sig = dsa->sign(sk, msg);
        items.emplace_back(pk, msg, sig);
    }

    pqc::BatchOptions options;
    options.num_threads = 1;

    auto result = pqc::batch_verify(*dsa, items, options);

    ASSERT(result.all_valid);
    ASSERT_EQ(result.valid_count, size_t(5));
}

TEST(explicit_multi_thread) {
    auto dsa = pqc::create_dsa("ML-DSA-44");
    auto [pk, sk] = dsa->keygen();

    std::vector<pqc::VerificationItem> items;
    for (int i = 0; i < 20; ++i) {
        std::vector<uint8_t> msg = {static_cast<uint8_t>(i)};
        auto sig = dsa->sign(sk, msg);
        items.emplace_back(pk, msg, sig);
    }

    pqc::BatchOptions options;
    options.num_threads = 4;

    auto result = pqc::batch_verify(*dsa, items, options);

    ASSERT(result.all_valid);
    ASSERT_EQ(result.valid_count, size_t(20));
}

TEST(custom_chunk_size) {
    auto dsa = pqc::create_dsa("ML-DSA-44");
    auto [pk, sk] = dsa->keygen();

    std::vector<pqc::VerificationItem> items;
    for (int i = 0; i < 20; ++i) {
        std::vector<uint8_t> msg = {static_cast<uint8_t>(i)};
        auto sig = dsa->sign(sk, msg);
        items.emplace_back(pk, msg, sig);
    }

    pqc::BatchOptions options;
    options.num_threads = 4;
    options.chunk_size = 2;  // Small chunks

    auto result = pqc::batch_verify(*dsa, items, options);

    ASSERT(result.all_valid);
    ASSERT_EQ(result.valid_count, size_t(20));
}

TEST(fail_fast_option) {
    auto dsa = pqc::create_dsa("ML-DSA-44");
    auto [pk, sk] = dsa->keygen();

    std::vector<pqc::VerificationItem> items;

    // Add 5 items, with the 3rd one invalid
    for (int i = 0; i < 5; ++i) {
        std::vector<uint8_t> msg = {static_cast<uint8_t>(i)};
        auto sig = dsa->sign(sk, msg);
        if (i == 2) sig[0] ^= 0xFF;  // Corrupt 3rd signature
        items.emplace_back(pk, msg, sig);
    }

    pqc::BatchOptions options;
    options.fail_fast = true;
    options.num_threads = 1;  // Use single thread for deterministic behavior

    auto result = pqc::batch_verify(*dsa, items, options);

    ASSERT(!result.all_valid);
    // First two should be valid, third invalid, rest may not be verified
    ASSERT(result.results[0]);
    ASSERT(result.results[1]);
    ASSERT(!result.results[2]);
}


// ============================================================================
// Context String Tests
// ============================================================================

TEST(batch_with_context_strings) {
    auto dsa = pqc::create_dsa("ML-DSA-44");
    auto [pk, sk] = dsa->keygen();

    std::vector<pqc::VerificationItem> items;

    // Sign with different context strings
    std::vector<uint8_t> msg1 = {1, 2, 3};
    std::vector<uint8_t> msg2 = {4, 5, 6};
    std::vector<uint8_t> ctx1 = {'a', 'b', 'c'};
    std::vector<uint8_t> ctx2 = {'x', 'y', 'z'};

    auto sig1 = dsa->sign(sk, msg1, ctx1);
    auto sig2 = dsa->sign(sk, msg2, ctx2);

    items.emplace_back(pk, msg1, sig1, ctx1);
    items.emplace_back(pk, msg2, sig2, ctx2);

    auto result = pqc::batch_verify(*dsa, items);

    ASSERT(result.all_valid);
    ASSERT_EQ(result.valid_count, size_t(2));
}

TEST(batch_wrong_context_fails) {
    auto dsa = pqc::create_dsa("ML-DSA-44");
    auto [pk, sk] = dsa->keygen();

    std::vector<uint8_t> msg = {1, 2, 3};
    std::vector<uint8_t> ctx1 = {'a', 'b', 'c'};
    std::vector<uint8_t> ctx2 = {'x', 'y', 'z'};

    auto sig = dsa->sign(sk, msg, ctx1);

    // Verify with wrong context
    std::vector<pqc::VerificationItem> items;
    items.emplace_back(pk, msg, sig, ctx2);

    auto result = pqc::batch_verify(*dsa, items);

    ASSERT(!result.all_valid);
    ASSERT_EQ(result.invalid_count, size_t(1));
}


// ============================================================================
// Utility Function Tests
// ============================================================================

TEST(hardware_threads_detection) {
    size_t threads = pqc::hardware_threads();
    ASSERT(threads > 0);
    std::cout << " (detected " << threads << " threads)";
}

TEST(make_verification_item) {
    std::vector<uint8_t> pk = {1, 2, 3};
    std::vector<uint8_t> msg = {4, 5, 6};
    std::vector<uint8_t> sig = {7, 8, 9};
    std::vector<uint8_t> ctx = {10, 11};

    auto item = pqc::make_verification_item(pk, msg, sig, ctx);

    ASSERT_EQ(item.public_key.size(), size_t(3));
    ASSERT_EQ(item.message.size(), size_t(3));
    ASSERT_EQ(item.signature.size(), size_t(3));
    ASSERT_EQ(item.context.size(), size_t(2));
}

TEST(make_heterogeneous_item) {
    std::vector<uint8_t> pk = {1, 2, 3};
    std::vector<uint8_t> msg = {4, 5, 6};
    std::vector<uint8_t> sig = {7, 8, 9};

    auto item = pqc::make_heterogeneous_item("ML-DSA-44", pk, msg, sig);

    ASSERT_EQ(item.algorithm, "ML-DSA-44");
    ASSERT_EQ(item.public_key.size(), size_t(3));
    ASSERT_EQ(item.message.size(), size_t(3));
    ASSERT_EQ(item.signature.size(), size_t(3));
    ASSERT(item.context.empty());
}

TEST(batch_result_is_valid_method) {
    pqc::BatchResult result;
    result.results = {true, false, true, false, true};
    result.valid_count = 3;
    result.invalid_count = 2;
    result.total_count = 5;
    result.all_valid = false;

    ASSERT(result.is_valid(0));
    ASSERT(!result.is_valid(1));
    ASSERT(result.is_valid(2));
    ASSERT(!result.is_valid(3));
    ASSERT(result.is_valid(4));
    ASSERT(!result.is_valid(100));  // Out of bounds returns false
}


// ============================================================================
// Performance Test (optional, can be slow)
// ============================================================================

TEST(parallel_vs_sequential_comparison) {
    auto dsa = pqc::create_dsa("ML-DSA-44");
    auto [pk, sk] = dsa->keygen();

    // Create batch of signatures
    const size_t batch_size = 16;
    std::vector<pqc::VerificationItem> items;
    for (size_t i = 0; i < batch_size; ++i) {
        std::vector<uint8_t> msg(32);
        for (size_t j = 0; j < 32; ++j) msg[j] = static_cast<uint8_t>(i * 32 + j);
        auto sig = dsa->sign(sk, msg);
        items.emplace_back(pk, msg, sig);
    }

    // Verify sequentially
    auto start_seq = std::chrono::high_resolution_clock::now();
    auto result_seq = pqc::batch_verify_sequential(*dsa, items);
    auto end_seq = std::chrono::high_resolution_clock::now();
    auto seq_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_seq - start_seq).count();

    // Verify in parallel
    auto start_par = std::chrono::high_resolution_clock::now();
    auto result_par = pqc::batch_verify(*dsa, items);
    auto end_par = std::chrono::high_resolution_clock::now();
    auto par_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_par - start_par).count();

    ASSERT(result_seq.all_valid);
    ASSERT(result_par.all_valid);
    ASSERT_EQ(result_seq.valid_count, result_par.valid_count);

    std::cout << " (seq=" << seq_time << "ms, par=" << par_time << "ms)";
}


// ============================================================================
// Different Key Tests
// ============================================================================

TEST(batch_with_different_keys) {
    auto dsa = pqc::create_dsa("ML-DSA-44");

    std::vector<pqc::VerificationItem> items;

    // Create multiple key pairs and signatures
    for (int i = 0; i < 5; ++i) {
        auto [pk, sk] = dsa->keygen();
        std::vector<uint8_t> msg = {static_cast<uint8_t>(i), static_cast<uint8_t>(i + 1)};
        auto sig = dsa->sign(sk, msg);
        items.emplace_back(pk, msg, sig);
    }

    auto result = pqc::batch_verify(*dsa, items);

    ASSERT(result.all_valid);
    ASSERT_EQ(result.valid_count, size_t(5));
}

TEST(batch_with_wrong_key) {
    auto dsa = pqc::create_dsa("ML-DSA-44");

    auto [pk1, sk1] = dsa->keygen();
    auto [pk2, sk2] = dsa->keygen();

    std::vector<uint8_t> msg = {1, 2, 3};
    auto sig = dsa->sign(sk1, msg);

    // Verify with wrong public key
    std::vector<pqc::VerificationItem> items;
    items.emplace_back(pk2, msg, sig);  // Using pk2 instead of pk1

    auto result = pqc::batch_verify(*dsa, items);

    ASSERT(!result.all_valid);
    ASSERT_EQ(result.invalid_count, size_t(1));
}


// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "=== Batch Verification Tests ===\n\n";

    // Tests run automatically via static initialization

    std::cout << "\n=== Results ===\n";
    std::cout << "Passed: " << tests_passed << "\n";
    std::cout << "Failed: " << tests_failed << "\n";

    return tests_failed == 0 ? 0 : 1;
}
