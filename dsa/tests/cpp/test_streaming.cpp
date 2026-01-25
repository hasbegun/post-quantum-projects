/**
 * Streaming API Tests
 *
 * Tests for pre-hash mode (HashML-DSA and HashSLH-DSA) streaming signatures.
 */

#include "common/streaming.hpp"
#include <cassert>
#include <iostream>
#include <vector>
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

// Generate random bytes for testing
std::vector<uint8_t> random_test_bytes(size_t len) {
    static std::mt19937 rng(42);  // Fixed seed for reproducibility
    std::vector<uint8_t> result(len);
    for (auto& b : result) {
        b = static_cast<uint8_t>(rng() & 0xFF);
    }
    return result;
}

// ============================================================================
// Hash Algorithm Tests
// ============================================================================

TEST(hash_oid_sha256) {
    auto oid = pqc::streaming::get_hash_oid(pqc::streaming::HashAlgorithm::SHA256);
    ASSERT(oid.size() == 9);
    ASSERT(oid[0] == 0x60);  // Start of 2.16.840...
}

TEST(hash_oid_sha512) {
    auto oid = pqc::streaming::get_hash_oid(pqc::streaming::HashAlgorithm::SHA512);
    ASSERT(oid.size() == 9);
    ASSERT(oid[8] == 0x03);  // .3 at end
}

TEST(hash_output_sizes) {
    ASSERT_EQ(pqc::streaming::get_hash_output_size(pqc::streaming::HashAlgorithm::SHA256), 32u);
    ASSERT_EQ(pqc::streaming::get_hash_output_size(pqc::streaming::HashAlgorithm::SHA384), 48u);
    ASSERT_EQ(pqc::streaming::get_hash_output_size(pqc::streaming::HashAlgorithm::SHA512), 64u);
    ASSERT_EQ(pqc::streaming::get_hash_output_size(pqc::streaming::HashAlgorithm::SHA3_256), 32u);
    ASSERT_EQ(pqc::streaming::get_hash_output_size(pqc::streaming::HashAlgorithm::SHA3_512), 64u);
}

TEST(hash_context_basic) {
    pqc::streaming::HashContext ctx(pqc::streaming::HashAlgorithm::SHA256);
    std::vector<uint8_t> data = {1, 2, 3, 4, 5};
    ctx.update(data);
    auto digest = ctx.finalize();
    ASSERT_EQ(digest.size(), 32u);
}

TEST(hash_context_incremental) {
    // Hash incrementally
    pqc::streaming::HashContext ctx1(pqc::streaming::HashAlgorithm::SHA256);
    std::vector<uint8_t> part1 = {1, 2, 3};
    std::vector<uint8_t> part2 = {4, 5, 6};
    ctx1.update(part1);
    ctx1.update(part2);
    auto digest1 = ctx1.finalize();

    // Hash in one shot
    pqc::streaming::HashContext ctx2(pqc::streaming::HashAlgorithm::SHA256);
    std::vector<uint8_t> full = {1, 2, 3, 4, 5, 6};
    ctx2.update(full);
    auto digest2 = ctx2.finalize();

    ASSERT(digest1 == digest2);
}

// ============================================================================
// ML-DSA Streaming Tests
// ============================================================================

TEST(mldsa44_streaming_sign_verify) {
    mldsa::MLDSA44 dsa;
    auto [pk, sk] = dsa.keygen();

    std::vector<uint8_t> message = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

    // Sign using streaming API
    auto signer = pqc::streaming::create_signer("ML-DSA-44", sk);
    signer->update(message);
    auto signature = signer->finalize();

    // Verify using streaming API
    auto verifier = pqc::streaming::create_verifier("ML-DSA-44", pk, signature);
    verifier->update(message);
    ASSERT(verifier->finalize());
}

TEST(mldsa65_streaming_sign_verify) {
    mldsa::MLDSA65 dsa;
    auto [pk, sk] = dsa.keygen();

    std::vector<uint8_t> message = random_test_bytes(1000);

    auto signer = pqc::streaming::create_signer("ML-DSA-65", sk);
    signer->update(message);
    auto signature = signer->finalize();

    auto verifier = pqc::streaming::create_verifier("ML-DSA-65", pk, signature);
    verifier->update(message);
    ASSERT(verifier->finalize());
}

TEST(mldsa87_streaming_sign_verify) {
    mldsa::MLDSA87 dsa;
    auto [pk, sk] = dsa.keygen();

    std::vector<uint8_t> message = random_test_bytes(500);

    auto signer = pqc::streaming::create_signer("ML-DSA-87", sk);
    signer->update(message);
    auto signature = signer->finalize();

    auto verifier = pqc::streaming::create_verifier("ML-DSA-87", pk, signature);
    verifier->update(message);
    ASSERT(verifier->finalize());
}

TEST(mldsa_streaming_chunked) {
    mldsa::MLDSA65 dsa;
    auto [pk, sk] = dsa.keygen();

    // Create a large message split into chunks
    std::vector<std::vector<uint8_t>> chunks;
    for (int i = 0; i < 10; ++i) {
        chunks.push_back(random_test_bytes(100));
    }

    // Sign with multiple updates
    auto signer = pqc::streaming::create_signer("ML-DSA-65", sk);
    for (const auto& chunk : chunks) {
        signer->update(chunk);
    }
    auto signature = signer->finalize();

    // Verify with multiple updates
    auto verifier = pqc::streaming::create_verifier("ML-DSA-65", pk, signature);
    for (const auto& chunk : chunks) {
        verifier->update(chunk);
    }
    ASSERT(verifier->finalize());
}

TEST(mldsa_streaming_tampered_message) {
    mldsa::MLDSA65 dsa;
    auto [pk, sk] = dsa.keygen();

    std::vector<uint8_t> message = {1, 2, 3, 4, 5};

    auto signer = pqc::streaming::create_signer("ML-DSA-65", sk);
    signer->update(message);
    auto signature = signer->finalize();

    // Tamper with message
    std::vector<uint8_t> tampered = {1, 2, 3, 4, 6};  // Changed last byte

    auto verifier = pqc::streaming::create_verifier("ML-DSA-65", pk, signature);
    verifier->update(tampered);
    ASSERT(!verifier->finalize());
}

TEST(mldsa_streaming_tampered_signature) {
    mldsa::MLDSA65 dsa;
    auto [pk, sk] = dsa.keygen();

    std::vector<uint8_t> message = {1, 2, 3, 4, 5};

    auto signer = pqc::streaming::create_signer("ML-DSA-65", sk);
    signer->update(message);
    auto signature = signer->finalize();

    // Tamper with signature
    signature[0] ^= 0xFF;

    auto verifier = pqc::streaming::create_verifier("ML-DSA-65", pk, signature);
    verifier->update(message);
    ASSERT(!verifier->finalize());
}

TEST(mldsa_streaming_with_context) {
    mldsa::MLDSA65 dsa;
    auto [pk, sk] = dsa.keygen();

    std::vector<uint8_t> message = {1, 2, 3, 4, 5};
    std::vector<uint8_t> ctx = {'t', 'e', 's', 't'};

    // Sign with context
    auto signer = pqc::streaming::create_signer("ML-DSA-65", sk,
        pqc::streaming::HashAlgorithm::SHA512, ctx);
    signer->update(message);
    auto signature = signer->finalize();

    // Verify with same context
    auto verifier = pqc::streaming::create_verifier("ML-DSA-65", pk, signature,
        pqc::streaming::HashAlgorithm::SHA512, ctx);
    verifier->update(message);
    ASSERT(verifier->finalize());

    // Verify with different context should fail
    std::vector<uint8_t> wrong_ctx = {'w', 'r', 'o', 'n', 'g'};
    auto verifier2 = pqc::streaming::create_verifier("ML-DSA-65", pk, signature,
        pqc::streaming::HashAlgorithm::SHA512, wrong_ctx);
    verifier2->update(message);
    ASSERT(!verifier2->finalize());
}

TEST(mldsa_streaming_different_hash_algorithms) {
    mldsa::MLDSA65 dsa;
    auto [pk, sk] = dsa.keygen();

    std::vector<uint8_t> message = random_test_bytes(200);

    // Test with SHA-256
    {
        auto signer = pqc::streaming::create_signer("ML-DSA-65", sk,
            pqc::streaming::HashAlgorithm::SHA256);
        signer->update(message);
        auto signature = signer->finalize();

        auto verifier = pqc::streaming::create_verifier("ML-DSA-65", pk, signature,
            pqc::streaming::HashAlgorithm::SHA256);
        verifier->update(message);
        ASSERT(verifier->finalize());
    }

    // Test with SHA3-512
    {
        auto signer = pqc::streaming::create_signer("ML-DSA-65", sk,
            pqc::streaming::HashAlgorithm::SHA3_512);
        signer->update(message);
        auto signature = signer->finalize();

        auto verifier = pqc::streaming::create_verifier("ML-DSA-65", pk, signature,
            pqc::streaming::HashAlgorithm::SHA3_512);
        verifier->update(message);
        ASSERT(verifier->finalize());
    }
}

// ============================================================================
// SLH-DSA Streaming Tests
// ============================================================================

TEST(slhdsa_shake_128f_streaming_sign_verify) {
    auto [sk, pk] = slhdsa::slh_keygen(slhdsa::SLH_DSA_SHAKE_128f);

    std::vector<uint8_t> message = {1, 2, 3, 4, 5, 6, 7, 8};

    auto signer = pqc::streaming::create_signer("SLH-DSA-SHAKE-128f", sk);
    signer->update(message);
    auto signature = signer->finalize();

    auto verifier = pqc::streaming::create_verifier("SLH-DSA-SHAKE-128f", pk, signature);
    verifier->update(message);
    ASSERT(verifier->finalize());
}

TEST(slhdsa_sha2_128f_streaming_sign_verify) {
    auto [sk, pk] = slhdsa::slh_keygen(slhdsa::SLH_DSA_SHA2_128f);

    std::vector<uint8_t> message = random_test_bytes(100);

    auto signer = pqc::streaming::create_signer("SLH-DSA-SHA2-128f", sk);
    signer->update(message);
    auto signature = signer->finalize();

    auto verifier = pqc::streaming::create_verifier("SLH-DSA-SHA2-128f", pk, signature);
    verifier->update(message);
    ASSERT(verifier->finalize());
}

TEST(slhdsa_streaming_chunked) {
    auto [sk, pk] = slhdsa::slh_keygen(slhdsa::SLH_DSA_SHAKE_128f);

    // Create message chunks
    std::vector<std::vector<uint8_t>> chunks;
    for (int i = 0; i < 5; ++i) {
        chunks.push_back(random_test_bytes(50));
    }

    auto signer = pqc::streaming::create_signer("SLH-DSA-SHAKE-128f", sk);
    for (const auto& chunk : chunks) {
        signer->update(chunk);
    }
    auto signature = signer->finalize();

    auto verifier = pqc::streaming::create_verifier("SLH-DSA-SHAKE-128f", pk, signature);
    for (const auto& chunk : chunks) {
        verifier->update(chunk);
    }
    ASSERT(verifier->finalize());
}

TEST(slhdsa_streaming_tampered_message) {
    auto [sk, pk] = slhdsa::slh_keygen(slhdsa::SLH_DSA_SHAKE_128f);

    std::vector<uint8_t> message = {1, 2, 3, 4, 5};

    auto signer = pqc::streaming::create_signer("SLH-DSA-SHAKE-128f", sk);
    signer->update(message);
    auto signature = signer->finalize();

    // Tamper with message
    std::vector<uint8_t> tampered = {1, 2, 3, 4, 6};

    auto verifier = pqc::streaming::create_verifier("SLH-DSA-SHAKE-128f", pk, signature);
    verifier->update(tampered);
    ASSERT(!verifier->finalize());
}

TEST(slhdsa_streaming_with_context) {
    auto [sk, pk] = slhdsa::slh_keygen(slhdsa::SLH_DSA_SHAKE_128f);

    std::vector<uint8_t> message = {1, 2, 3, 4, 5};
    std::vector<uint8_t> ctx = {'c', 't', 'x'};

    auto signer = pqc::streaming::create_signer("SLH-DSA-SHAKE-128f", sk,
        pqc::streaming::HashAlgorithm::SHA512, ctx);
    signer->update(message);
    auto signature = signer->finalize();

    auto verifier = pqc::streaming::create_verifier("SLH-DSA-SHAKE-128f", pk, signature,
        pqc::streaming::HashAlgorithm::SHA512, ctx);
    verifier->update(message);
    ASSERT(verifier->finalize());
}

// ============================================================================
// Factory Tests
// ============================================================================

TEST(factory_available_algorithms) {
    auto algorithms = pqc::streaming::available_streaming_algorithms();
    ASSERT(algorithms.size() >= 15);  // 3 ML-DSA + 12 SLH-DSA

    // Check some specific algorithms are present
    bool has_mldsa65 = false;
    bool has_slhdsa_shake_128f = false;
    for (const auto& alg : algorithms) {
        if (alg == "ML-DSA-65") has_mldsa65 = true;
        if (alg == "SLH-DSA-SHAKE-128f") has_slhdsa_shake_128f = true;
    }
    ASSERT(has_mldsa65);
    ASSERT(has_slhdsa_shake_128f);
}

TEST(factory_available_hash_algorithms) {
    auto hash_algs = pqc::streaming::available_hash_algorithms();
    ASSERT(hash_algs.size() == 8);
}

TEST(factory_unknown_algorithm) {
    std::vector<uint8_t> dummy_key(100);
    bool threw = false;
    try {
        pqc::streaming::create_signer("UNKNOWN-ALGO", dummy_key);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    ASSERT(threw);
}

// ============================================================================
// Convenience Function Tests
// ============================================================================

TEST(sign_verify_streaming_convenience) {
    mldsa::MLDSA65 dsa;
    auto [pk, sk] = dsa.keygen();

    std::vector<std::vector<uint8_t>> chunks = {
        {1, 2, 3},
        {4, 5, 6},
        {7, 8, 9}
    };

    auto signature = pqc::streaming::sign_streaming("ML-DSA-65", sk, chunks);

    bool valid = pqc::streaming::verify_streaming("ML-DSA-65", pk, signature, chunks);
    ASSERT(valid);
}

// ============================================================================
// Algorithm Name Tests
// ============================================================================

TEST(algorithm_names) {
    mldsa::MLDSA65 dsa;
    auto [pk, sk] = dsa.keygen();

    auto signer = pqc::streaming::create_signer("ML-DSA-65", sk);
    ASSERT_EQ(signer->algorithm_name(), std::string("HashML-DSA-65"));
    ASSERT_EQ(signer->hash_algorithm(), pqc::streaming::HashAlgorithm::SHA512);
}

// ============================================================================
// Error Handling Tests
// ============================================================================

TEST(error_double_finalize_signer) {
    mldsa::MLDSA44 dsa;
    auto [pk, sk] = dsa.keygen();

    auto signer = pqc::streaming::create_signer("ML-DSA-44", sk);
    std::vector<uint8_t> data = {1, 2, 3};
    signer->update(data);
    signer->finalize();

    bool threw = false;
    try {
        signer->finalize();
    } catch (const std::runtime_error&) {
        threw = true;
    }
    ASSERT(threw);
}

TEST(error_update_after_finalize) {
    mldsa::MLDSA44 dsa;
    auto [pk, sk] = dsa.keygen();

    auto signer = pqc::streaming::create_signer("ML-DSA-44", sk);
    std::vector<uint8_t> data1 = {1, 2, 3};
    signer->update(data1);
    signer->finalize();

    bool threw = false;
    try {
        std::vector<uint8_t> data2 = {4, 5, 6};
        signer->update(data2);
    } catch (const std::runtime_error&) {
        threw = true;
    }
    ASSERT(threw);
}

TEST(error_context_too_long) {
    mldsa::MLDSA44 dsa;
    auto [pk, sk] = dsa.keygen();

    std::vector<uint8_t> long_ctx(300, 'x');  // > 255 bytes

    bool threw = false;
    try {
        pqc::streaming::create_signer("ML-DSA-44", sk,
            pqc::streaming::HashAlgorithm::SHA512, long_ctx);
    } catch (const std::invalid_argument&) {
        threw = true;
    }
    ASSERT(threw);
}

// ============================================================================
// Large Message Tests
// ============================================================================

TEST(large_message_streaming) {
    mldsa::MLDSA65 dsa;
    auto [pk, sk] = dsa.keygen();

    // Create a "large" message (10KB)
    std::vector<uint8_t> large_message = random_test_bytes(10 * 1024);

    // Split into chunks and sign
    auto signer = pqc::streaming::create_signer("ML-DSA-65", sk);
    size_t chunk_size = 1024;
    for (size_t i = 0; i < large_message.size(); i += chunk_size) {
        size_t len = std::min(chunk_size, large_message.size() - i);
        signer->update(std::span<const uint8_t>(large_message.data() + i, len));
    }
    auto signature = signer->finalize();

    // Verify
    auto verifier = pqc::streaming::create_verifier("ML-DSA-65", pk, signature);
    for (size_t i = 0; i < large_message.size(); i += chunk_size) {
        size_t len = std::min(chunk_size, large_message.size() - i);
        verifier->update(std::span<const uint8_t>(large_message.data() + i, len));
    }
    ASSERT(verifier->finalize());
}

// ============================================================================
// Cross-Algorithm Incompatibility Tests
// ============================================================================

TEST(different_hash_algorithms_fail) {
    mldsa::MLDSA65 dsa;
    auto [pk, sk] = dsa.keygen();

    std::vector<uint8_t> message = {1, 2, 3, 4, 5};

    // Sign with SHA-512
    auto signer = pqc::streaming::create_signer("ML-DSA-65", sk,
        pqc::streaming::HashAlgorithm::SHA512);
    signer->update(message);
    auto signature = signer->finalize();

    // Verify with SHA-256 should fail
    auto verifier = pqc::streaming::create_verifier("ML-DSA-65", pk, signature,
        pqc::streaming::HashAlgorithm::SHA256);
    verifier->update(message);
    ASSERT(!verifier->finalize());
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "=== Streaming API Tests ===\n\n";

    // Tests run automatically via static initialization

    std::cout << "\n=== Results ===\n";
    std::cout << "Passed: " << tests_passed << "\n";
    std::cout << "Failed: " << tests_failed << "\n";

    return tests_failed == 0 ? 0 : 1;
}
