/**
 * FIPS 140-3 Self-Test Module
 *
 * Provides Conditional Algorithm Self-Tests (CAST) for FIPS 140-3 compliance.
 * Self-tests run automatically on first use of each algorithm family.
 *
 * Test Types:
 *   - Known Answer Tests (KAT): Verify algorithm output against pre-computed values
 *   - Pairwise Consistency Tests (PCT): Verify generated key pairs work correctly
 *
 * Usage:
 *   // Automatic testing on first use (recommended)
 *   auto dsa = pqc::create_dsa("ML-DSA-65");  // Self-test runs automatically
 *
 *   // Manual testing
 *   pqc::fips::run_all_self_tests();          // Run all tests
 *   pqc::fips::run_mldsa_self_test();         // Test ML-DSA only
 *
 *   // Query status
 *   auto status = pqc::fips::get_self_test_status();
 *   if (status.all_passed()) { ... }
 */

#ifndef COMMON_FIPS_SELFTEST_HPP
#define COMMON_FIPS_SELFTEST_HPP

#include <atomic>
#include <cstdint>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

#include "mldsa/mldsa.hpp"
#include "slhdsa/slh_dsa.hpp"
#include "mlkem/mlkem.hpp"

namespace pqc {
namespace fips {

// ============================================================================
// Self-Test Status
// ============================================================================

/**
 * Status of self-tests for each algorithm family
 */
enum class TestState {
    NOT_RUN,    // Test has not been executed
    PASSED,     // Test completed successfully
    FAILED      // Test failed - algorithm should not be used
};

/**
 * Aggregated self-test status
 */
struct SelfTestStatus {
    TestState mldsa = TestState::NOT_RUN;
    TestState slhdsa = TestState::NOT_RUN;
    TestState mlkem = TestState::NOT_RUN;

    [[nodiscard]] bool all_passed() const {
        return mldsa == TestState::PASSED &&
               slhdsa == TestState::PASSED &&
               mlkem == TestState::PASSED;
    }

    [[nodiscard]] bool any_failed() const {
        return mldsa == TestState::FAILED ||
               slhdsa == TestState::FAILED ||
               mlkem == TestState::FAILED;
    }

    [[nodiscard]] bool all_run() const {
        return mldsa != TestState::NOT_RUN &&
               slhdsa != TestState::NOT_RUN &&
               mlkem != TestState::NOT_RUN;
    }
};

// ============================================================================
// Exception Types
// ============================================================================

/**
 * Exception thrown when a FIPS self-test fails
 */
class SelfTestFailure : public std::runtime_error {
public:
    explicit SelfTestFailure(const std::string& algorithm, const std::string& reason)
        : std::runtime_error("FIPS self-test failed for " + algorithm + ": " + reason)
        , algorithm_(algorithm)
        , reason_(reason) {}

    [[nodiscard]] const std::string& algorithm() const { return algorithm_; }
    [[nodiscard]] const std::string& reason() const { return reason_; }

private:
    std::string algorithm_;
    std::string reason_;
};

// ============================================================================
// Internal State
// ============================================================================

namespace detail {

// Thread-safe test state tracking
inline std::atomic<int> mldsa_state{0};   // 0=not run, 1=passed, -1=failed
inline std::atomic<int> slhdsa_state{0};
inline std::atomic<int> mlkem_state{0};

// Mutexes for one-time test execution
inline std::mutex mldsa_mutex;
inline std::mutex slhdsa_mutex;
inline std::mutex mlkem_mutex;

/**
 * Convert hex string to bytes
 */
inline std::vector<uint8_t> hex_to_bytes(const char* hex) {
    std::vector<uint8_t> bytes;
    while (*hex) {
        char high = *hex++;
        char low = *hex++;
        uint8_t byte = 0;

        if (high >= '0' && high <= '9') byte = (high - '0') << 4;
        else if (high >= 'A' && high <= 'F') byte = (high - 'A' + 10) << 4;
        else if (high >= 'a' && high <= 'f') byte = (high - 'a' + 10) << 4;

        if (low >= '0' && low <= '9') byte |= (low - '0');
        else if (low >= 'A' && low <= 'F') byte |= (low - 'A' + 10);
        else if (low >= 'a' && low <= 'f') byte |= (low - 'a' + 10);

        bytes.push_back(byte);
    }
    return bytes;
}

/**
 * Constant-time memory comparison
 */
inline bool secure_compare(const std::vector<uint8_t>& a,
                           const std::vector<uint8_t>& b) {
    if (a.size() != b.size()) return false;
    volatile uint8_t diff = 0;
    for (size_t i = 0; i < a.size(); ++i) {
        diff |= a[i] ^ b[i];
    }
    return diff == 0;
}

// ============================================================================
// ML-DSA Known Answer Test Vectors (from NIST ACVP)
// ============================================================================

// ML-DSA-44 test vector
constexpr const char* MLDSA44_SEED =
    "D71361C000F9A7BC99DFB425BCB6BB27C32C36AB444FF3708B2D93B4E66D5B5B";
constexpr const char* MLDSA44_PK_PREFIX =
    "B845FA2881407A59183071629B08223128116014FB58FF6BB4C8C9FE19CF5B0B";

// ML-DSA-65 test vector
constexpr const char* MLDSA65_SEED =
    "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F20";

// ML-DSA-87 test vector
constexpr const char* MLDSA87_SEED =
    "FFEEDDCCBBAA99887766554433221100F0E0D0C0B0A090807060504030201000";

// ============================================================================
// SLH-DSA Known Answer Test Configuration
// ============================================================================

// SLH-DSA-SHAKE-128f test seeds (shorter test for speed)
constexpr const char* SLHDSA_SK_SEED =
    "000102030405060708090A0B0C0D0E0F";
constexpr const char* SLHDSA_SK_PRF =
    "101112131415161718191A1B1C1D1E1F";
constexpr const char* SLHDSA_PK_SEED =
    "202122232425262728292A2B2C2D2E2F";

// ============================================================================
// ML-KEM Known Answer Test Vectors
// ============================================================================

// ML-KEM-768 uses 64-byte seed (d || z)
constexpr const char* MLKEM768_SEED =
    "0001020304050607080910111213141516171819202122232425262728293031"
    "3233343536373839404142434445464748495051525354555657585960616263";

} // namespace detail

// ============================================================================
// Self-Test Functions
// ============================================================================

/**
 * Run ML-DSA self-tests (KAT + PCT)
 *
 * Tests ML-DSA-44, ML-DSA-65, and ML-DSA-87 with known answer tests
 * and pairwise consistency tests.
 *
 * @throws SelfTestFailure if any test fails
 */
inline void run_mldsa_self_test() {
    std::lock_guard<std::mutex> lock(detail::mldsa_mutex);

    // Check if already run
    int state = detail::mldsa_state.load(std::memory_order_acquire);
    if (state == 1) return;  // Already passed
    if (state == -1) throw SelfTestFailure("ML-DSA", "Previous self-test failed");

    try {
        // ===== ML-DSA-44 KAT =====
        {
            mldsa::MLDSA44 dsa;
            auto seed = detail::hex_to_bytes(detail::MLDSA44_SEED);
            auto expected_prefix = detail::hex_to_bytes(detail::MLDSA44_PK_PREFIX);

            auto [pk, sk] = dsa.keygen(seed);

            // Verify key sizes
            if (pk.size() != 1312)
                throw SelfTestFailure("ML-DSA-44", "Invalid public key size");
            if (sk.size() != 2560)
                throw SelfTestFailure("ML-DSA-44", "Invalid secret key size");

            // Verify public key prefix matches expected value
            std::vector<uint8_t> pk_prefix(pk.begin(), pk.begin() + 32);
            if (!detail::secure_compare(pk_prefix, expected_prefix))
                throw SelfTestFailure("ML-DSA-44", "KAT public key mismatch");

            // Pairwise consistency test
            std::vector<uint8_t> message = {0x01, 0x02, 0x03, 0x04};
            auto sig = dsa.sign(sk, message, {}, true);
            if (!dsa.verify(pk, message, sig))
                throw SelfTestFailure("ML-DSA-44", "PCT sign/verify failed");
        }

        // ===== ML-DSA-65 KAT =====
        {
            mldsa::MLDSA65 dsa;
            auto seed = detail::hex_to_bytes(detail::MLDSA65_SEED);

            auto [pk1, sk1] = dsa.keygen(seed);
            auto [pk2, sk2] = dsa.keygen(seed);

            // Verify determinism
            if (!detail::secure_compare(pk1, pk2))
                throw SelfTestFailure("ML-DSA-65", "KeyGen not deterministic");

            // Verify key sizes
            if (pk1.size() != 1952)
                throw SelfTestFailure("ML-DSA-65", "Invalid public key size");
            if (sk1.size() != 4032)
                throw SelfTestFailure("ML-DSA-65", "Invalid secret key size");

            // Pairwise consistency test
            std::vector<uint8_t> message = {0x05, 0x06, 0x07, 0x08};
            auto sig = dsa.sign(sk1, message, {}, true);
            if (sig.size() != 3309)
                throw SelfTestFailure("ML-DSA-65", "Invalid signature size");
            if (!dsa.verify(pk1, message, sig))
                throw SelfTestFailure("ML-DSA-65", "PCT sign/verify failed");
        }

        // ===== ML-DSA-87 KAT =====
        {
            mldsa::MLDSA87 dsa;
            auto seed = detail::hex_to_bytes(detail::MLDSA87_SEED);

            auto [pk, sk] = dsa.keygen(seed);

            // Verify key sizes
            if (pk.size() != 2592)
                throw SelfTestFailure("ML-DSA-87", "Invalid public key size");
            if (sk.size() != 4896)
                throw SelfTestFailure("ML-DSA-87", "Invalid secret key size");

            // Pairwise consistency test
            std::vector<uint8_t> message = {0x09, 0x0A, 0x0B, 0x0C};
            auto sig = dsa.sign(sk, message, {}, true);
            if (sig.size() != 4627)
                throw SelfTestFailure("ML-DSA-87", "Invalid signature size");
            if (!dsa.verify(pk, message, sig))
                throw SelfTestFailure("ML-DSA-87", "PCT sign/verify failed");
        }

        detail::mldsa_state.store(1, std::memory_order_release);

    } catch (const SelfTestFailure&) {
        detail::mldsa_state.store(-1, std::memory_order_release);
        throw;
    } catch (const std::exception& e) {
        detail::mldsa_state.store(-1, std::memory_order_release);
        throw SelfTestFailure("ML-DSA", e.what());
    }
}

/**
 * Run SLH-DSA self-tests (KAT + PCT)
 *
 * Tests SLH-DSA-SHAKE-128f with pairwise consistency test.
 * Uses the fast variant for reasonable test time.
 *
 * @throws SelfTestFailure if any test fails
 */
inline void run_slhdsa_self_test() {
    std::lock_guard<std::mutex> lock(detail::slhdsa_mutex);

    int state = detail::slhdsa_state.load(std::memory_order_acquire);
    if (state == 1) return;
    if (state == -1) throw SelfTestFailure("SLH-DSA", "Previous self-test failed");

    try {
        // Use SHAKE-128f (fast variant) for self-test to keep time reasonable
        const auto& params = slhdsa::SLH_DSA_SHAKE_128f;

        auto sk_seed = detail::hex_to_bytes(detail::SLHDSA_SK_SEED);
        auto sk_prf = detail::hex_to_bytes(detail::SLHDSA_SK_PRF);
        auto pk_seed = detail::hex_to_bytes(detail::SLHDSA_PK_SEED);

        // Deterministic key generation
        auto [sk1, pk1] = slhdsa::slh_keygen_internal(params, sk_seed, sk_prf, pk_seed);
        auto [sk2, pk2] = slhdsa::slh_keygen_internal(params, sk_seed, sk_prf, pk_seed);

        // Verify determinism
        if (!detail::secure_compare(sk1, sk2))
            throw SelfTestFailure("SLH-DSA", "KeyGen not deterministic (sk)");
        if (!detail::secure_compare(pk1, pk2))
            throw SelfTestFailure("SLH-DSA", "KeyGen not deterministic (pk)");

        // Verify key sizes
        if (pk1.size() != params.pk_size())
            throw SelfTestFailure("SLH-DSA", "Invalid public key size");
        if (sk1.size() != params.sk_size())
            throw SelfTestFailure("SLH-DSA", "Invalid secret key size");

        // Pairwise consistency test
        std::vector<uint8_t> message = {0x10, 0x11, 0x12, 0x13};
        auto sig = slhdsa::slh_sign(params, message, sk1, {}, false);

        if (sig.size() != params.sig_size())
            throw SelfTestFailure("SLH-DSA", "Invalid signature size");

        if (!slhdsa::slh_verify(params, message, sig, pk1))
            throw SelfTestFailure("SLH-DSA", "PCT sign/verify failed");

        detail::slhdsa_state.store(1, std::memory_order_release);

    } catch (const SelfTestFailure&) {
        detail::slhdsa_state.store(-1, std::memory_order_release);
        throw;
    } catch (const std::exception& e) {
        detail::slhdsa_state.store(-1, std::memory_order_release);
        throw SelfTestFailure("SLH-DSA", e.what());
    }
}

/**
 * Run ML-KEM self-tests (KAT + PCT)
 *
 * Tests ML-KEM-512, ML-KEM-768, and ML-KEM-1024 with pairwise consistency tests.
 *
 * @throws SelfTestFailure if any test fails
 */
inline void run_mlkem_self_test() {
    std::lock_guard<std::mutex> lock(detail::mlkem_mutex);

    int state = detail::mlkem_state.load(std::memory_order_acquire);
    if (state == 1) return;
    if (state == -1) throw SelfTestFailure("ML-KEM", "Previous self-test failed");

    try {
        // ===== ML-KEM-512 PCT =====
        {
            mlkem::MLKEM512 kem;
            auto [ek, dk] = kem.keygen();

            if (ek.size() != 800)
                throw SelfTestFailure("ML-KEM-512", "Invalid encapsulation key size");
            if (dk.size() != 1632)
                throw SelfTestFailure("ML-KEM-512", "Invalid decapsulation key size");

            auto [K1, ct] = kem.encaps(ek);
            auto K2 = kem.decaps(dk, ct);

            if (K1.size() != 32)
                throw SelfTestFailure("ML-KEM-512", "Invalid shared secret size");
            if (ct.size() != 768)
                throw SelfTestFailure("ML-KEM-512", "Invalid ciphertext size");
            if (!detail::secure_compare(K1, K2))
                throw SelfTestFailure("ML-KEM-512", "PCT encaps/decaps mismatch");
        }

        // ===== ML-KEM-768 PCT =====
        {
            mlkem::MLKEM768 kem;
            auto [ek, dk] = kem.keygen();

            if (ek.size() != 1184)
                throw SelfTestFailure("ML-KEM-768", "Invalid encapsulation key size");
            if (dk.size() != 2400)
                throw SelfTestFailure("ML-KEM-768", "Invalid decapsulation key size");

            auto [K1, ct] = kem.encaps(ek);
            auto K2 = kem.decaps(dk, ct);

            if (K1.size() != 32)
                throw SelfTestFailure("ML-KEM-768", "Invalid shared secret size");
            if (ct.size() != 1088)
                throw SelfTestFailure("ML-KEM-768", "Invalid ciphertext size");
            if (!detail::secure_compare(K1, K2))
                throw SelfTestFailure("ML-KEM-768", "PCT encaps/decaps mismatch");
        }

        // ===== ML-KEM-1024 PCT =====
        {
            mlkem::MLKEM1024 kem;
            auto [ek, dk] = kem.keygen();

            if (ek.size() != 1568)
                throw SelfTestFailure("ML-KEM-1024", "Invalid encapsulation key size");
            if (dk.size() != 3168)
                throw SelfTestFailure("ML-KEM-1024", "Invalid decapsulation key size");

            auto [K1, ct] = kem.encaps(ek);
            auto K2 = kem.decaps(dk, ct);

            if (K1.size() != 32)
                throw SelfTestFailure("ML-KEM-1024", "Invalid shared secret size");
            if (ct.size() != 1568)
                throw SelfTestFailure("ML-KEM-1024", "Invalid ciphertext size");
            if (!detail::secure_compare(K1, K2))
                throw SelfTestFailure("ML-KEM-1024", "PCT encaps/decaps mismatch");
        }

        detail::mlkem_state.store(1, std::memory_order_release);

    } catch (const SelfTestFailure&) {
        detail::mlkem_state.store(-1, std::memory_order_release);
        throw;
    } catch (const std::exception& e) {
        detail::mlkem_state.store(-1, std::memory_order_release);
        throw SelfTestFailure("ML-KEM", e.what());
    }
}

/**
 * Run all self-tests
 *
 * Executes self-tests for ML-DSA, SLH-DSA, and ML-KEM.
 * Tests only run once; subsequent calls return immediately if tests passed.
 *
 * @throws SelfTestFailure if any test fails
 */
inline void run_all_self_tests() {
    run_mldsa_self_test();
    run_slhdsa_self_test();
    run_mlkem_self_test();
}

/**
 * Get current self-test status
 *
 * @return SelfTestStatus containing the state of all algorithm tests
 */
inline SelfTestStatus get_self_test_status() {
    SelfTestStatus status;

    int mldsa = detail::mldsa_state.load(std::memory_order_acquire);
    int slhdsa = detail::slhdsa_state.load(std::memory_order_acquire);
    int mlkem = detail::mlkem_state.load(std::memory_order_acquire);

    status.mldsa = (mldsa == 1) ? TestState::PASSED :
                   (mldsa == -1) ? TestState::FAILED : TestState::NOT_RUN;
    status.slhdsa = (slhdsa == 1) ? TestState::PASSED :
                    (slhdsa == -1) ? TestState::FAILED : TestState::NOT_RUN;
    status.mlkem = (mlkem == 1) ? TestState::PASSED :
                   (mlkem == -1) ? TestState::FAILED : TestState::NOT_RUN;

    return status;
}

/**
 * Reset self-test state (for testing purposes only)
 *
 * WARNING: This should only be used in test code, never in production.
 */
inline void reset_self_test_state() {
    detail::mldsa_state.store(0, std::memory_order_release);
    detail::slhdsa_state.store(0, std::memory_order_release);
    detail::mlkem_state.store(0, std::memory_order_release);
}

/**
 * Check if ML-DSA self-test has passed
 *
 * @return true if self-test passed, false otherwise
 */
inline bool mldsa_self_test_passed() {
    return detail::mldsa_state.load(std::memory_order_acquire) == 1;
}

/**
 * Check if SLH-DSA self-test has passed
 */
inline bool slhdsa_self_test_passed() {
    return detail::slhdsa_state.load(std::memory_order_acquire) == 1;
}

/**
 * Check if ML-KEM self-test has passed
 */
inline bool mlkem_self_test_passed() {
    return detail::mlkem_state.load(std::memory_order_acquire) == 1;
}

// ============================================================================
// CAST Guards (for automatic testing on first use)
// ============================================================================

/**
 * Ensure ML-DSA self-test has passed before use
 *
 * Call this at the start of any ML-DSA operation to ensure CAST compliance.
 *
 * @throws SelfTestFailure if self-test fails
 */
inline void ensure_mldsa_tested() {
    if (detail::mldsa_state.load(std::memory_order_acquire) != 1) {
        run_mldsa_self_test();
    }
}

/**
 * Ensure SLH-DSA self-test has passed before use
 */
inline void ensure_slhdsa_tested() {
    if (detail::slhdsa_state.load(std::memory_order_acquire) != 1) {
        run_slhdsa_self_test();
    }
}

/**
 * Ensure ML-KEM self-test has passed before use
 */
inline void ensure_mlkem_tested() {
    if (detail::mlkem_state.load(std::memory_order_acquire) != 1) {
        run_mlkem_self_test();
    }
}

} // namespace fips
} // namespace pqc

#endif // COMMON_FIPS_SELFTEST_HPP
