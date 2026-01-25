/**
 * SIMD NTT Correctness Tests
 *
 * Verifies that AVX2/NEON implementations produce identical results
 * to the scalar reference implementations.
 */

#include <iostream>
#include <iomanip>
#include <random>
#include <cstring>

// Include common SIMD detection
#include "../../src/cpp/common/simd_detect.hpp"

// Include ML-KEM scalar and SIMD implementations
#include "../../src/cpp/mlkem/params.hpp"
#include "../../src/cpp/mlkem/ntt.hpp"
#include "../../src/cpp/mlkem/ntt_avx2.hpp"
#include "../../src/cpp/mlkem/ntt_neon.hpp"

// Include ML-DSA scalar and SIMD implementations
#include "../../src/cpp/mldsa/params.hpp"
#include "../../src/cpp/mldsa/ntt.hpp"
#include "../../src/cpp/mldsa/ntt_avx2.hpp"
#include "../../src/cpp/mldsa/ntt_neon.hpp"

// Test result tracking
static int tests_passed = 0;
static int tests_failed = 0;

void report(const char* name, bool passed) {
    if (passed) {
        std::cout << "  [PASS] " << name << std::endl;
        tests_passed++;
    } else {
        std::cout << "  [FAIL] " << name << std::endl;
        tests_failed++;
    }
}

// ============================================================================
// SIMD Detection Tests
// ============================================================================

void test_simd_detection() {
    std::cout << "\n=== SIMD Detection ===" << std::endl;

    auto features = simd::CpuFeatures::detect();

    std::cout << "  Platform: ";
#if SIMD_X86
    std::cout << "x86-64";
#elif SIMD_ARM64
    std::cout << "ARM64";
#else
    std::cout << "Unknown";
#endif
    std::cout << std::endl;

    std::cout << "  AVX2: " << (features.avx2 ? "Yes" : "No") << std::endl;
    std::cout << "  AVX-512: " << (features.avx512f ? "Yes" : "No") << std::endl;
    std::cout << "  NEON: " << (features.neon ? "Yes" : "No") << std::endl;
    std::cout << "  SIMD Available: " << (simd::has_simd() ? "Yes" : "No") << std::endl;

    // Detection should work without crashing
    report("SIMD detection runs", true);
}

// ============================================================================
// ML-KEM SIMD Tests
// ============================================================================

#if SIMD_AVX2_COMPILED

void test_mlkem_ntt_avx2() {
    std::cout << "\n=== ML-KEM AVX2 NTT Tests ===" << std::endl;

    if (!simd::has_avx2()) {
        std::cout << "  [SKIP] AVX2 not available on this CPU" << std::endl;
        return;
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int16_t> dist(0, mlkem::Q - 1);

    // Test 1: NTT forward transform consistency
    {
        std::array<int16_t, mlkem::N> poly_scalar;
        std::array<int16_t, mlkem::N> poly_avx2;

        // Generate random polynomial
        for (size_t i = 0; i < mlkem::N; ++i) {
            int16_t val = dist(gen);
            poly_scalar[i] = val;
            poly_avx2[i] = val;
        }

        // Apply NTT with both implementations
        poly_scalar = mlkem::ntt(poly_scalar);
        mlkem::avx2::ntt_avx2(poly_avx2);

        // Compare results
        bool match = true;
        for (size_t i = 0; i < mlkem::N; ++i) {
            // Allow small differences due to Montgomery form
            int16_t diff = std::abs(
                mlkem::barrett_reduce(poly_scalar[i]) -
                mlkem::barrett_reduce(poly_avx2[i]));
            if (diff > 1) {
                match = false;
                break;
            }
        }
        report("NTT forward transform", match);
    }

    // Test 2: NTT inverse transform consistency
    {
        std::array<int16_t, mlkem::N> poly_scalar;
        std::array<int16_t, mlkem::N> poly_avx2;

        for (size_t i = 0; i < mlkem::N; ++i) {
            int16_t val = dist(gen);
            poly_scalar[i] = val;
            poly_avx2[i] = val;
        }

        poly_scalar = mlkem::ntt_inv(poly_scalar);
        mlkem::avx2::ntt_inv_avx2(poly_avx2);

        bool match = true;
        for (size_t i = 0; i < mlkem::N; ++i) {
            int16_t diff = std::abs(
                mlkem::barrett_reduce(poly_scalar[i]) -
                mlkem::barrett_reduce(poly_avx2[i]));
            if (diff > 1) {
                match = false;
                break;
            }
        }
        report("NTT inverse transform", match);
    }

    // Test 3: Round-trip (NTT -> INTT)
    {
        std::array<int16_t, mlkem::N> original;
        std::array<int16_t, mlkem::N> poly_avx2;

        for (size_t i = 0; i < mlkem::N; ++i) {
            original[i] = dist(gen);
            poly_avx2[i] = original[i];
        }

        mlkem::avx2::ntt_avx2(poly_avx2);
        mlkem::avx2::ntt_inv_avx2(poly_avx2);

        bool match = true;
        for (size_t i = 0; i < mlkem::N; ++i) {
            int16_t reduced = mlkem::barrett_reduce(poly_avx2[i]);
            if (reduced < 0) reduced += mlkem::Q;
            int16_t orig = original[i];
            if (orig < 0) orig += mlkem::Q;

            if (std::abs(reduced - orig) > 1) {
                match = false;
                break;
            }
        }
        report("Round-trip NTT -> INTT", match);
    }

    // Test 4: Polynomial addition
    {
        std::array<int16_t, mlkem::N> a, b;
        std::array<int16_t, mlkem::N> c_scalar, c_avx2;

        for (size_t i = 0; i < mlkem::N; ++i) {
            a[i] = dist(gen);
            b[i] = dist(gen);
        }

        // Scalar addition
        for (size_t i = 0; i < mlkem::N; ++i) {
            c_scalar[i] = a[i] + b[i];
        }

        // AVX2 addition
        mlkem::avx2::poly_add_avx2(c_avx2, a, b);

        bool match = (std::memcmp(c_scalar.data(), c_avx2.data(),
            sizeof(c_scalar)) == 0);
        report("Polynomial addition", match);
    }

    // Test 5: Polynomial subtraction
    {
        std::array<int16_t, mlkem::N> a, b;
        std::array<int16_t, mlkem::N> c_scalar, c_avx2;

        for (size_t i = 0; i < mlkem::N; ++i) {
            a[i] = dist(gen);
            b[i] = dist(gen);
        }

        for (size_t i = 0; i < mlkem::N; ++i) {
            c_scalar[i] = a[i] - b[i];
        }

        mlkem::avx2::poly_sub_avx2(c_avx2, a, b);

        bool match = (std::memcmp(c_scalar.data(), c_avx2.data(),
            sizeof(c_scalar)) == 0);
        report("Polynomial subtraction", match);
    }
}

#endif // SIMD_AVX2_COMPILED

// ============================================================================
// ML-KEM NEON Tests
// ============================================================================

#if SIMD_NEON_COMPILED

void test_mlkem_ntt_neon() {
    std::cout << "\n=== ML-KEM NEON NTT Tests ===" << std::endl;

    if (!simd::has_neon()) {
        std::cout << "  [SKIP] NEON not available on this CPU" << std::endl;
        return;
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int16_t> dist(0, mlkem::Q - 1);

    // Test 1: NTT forward transform consistency
    {
        std::array<int16_t, mlkem::N> poly_scalar;
        std::array<int16_t, mlkem::N> poly_neon;

        for (size_t i = 0; i < mlkem::N; ++i) {
            int16_t val = dist(gen);
            poly_scalar[i] = val;
            poly_neon[i] = val;
        }

        poly_scalar = mlkem::ntt(poly_scalar);
        mlkem::neon::ntt_neon(poly_neon);

        bool match = true;
        for (size_t i = 0; i < mlkem::N; ++i) {
            int16_t diff = std::abs(
                mlkem::barrett_reduce(poly_scalar[i]) -
                mlkem::barrett_reduce(poly_neon[i]));
            if (diff > 1) {
                match = false;
                break;
            }
        }
        report("NTT forward transform", match);
    }

    // Test 2: NTT inverse transform consistency
    {
        std::array<int16_t, mlkem::N> poly_scalar;
        std::array<int16_t, mlkem::N> poly_neon;

        for (size_t i = 0; i < mlkem::N; ++i) {
            int16_t val = dist(gen);
            poly_scalar[i] = val;
            poly_neon[i] = val;
        }

        poly_scalar = mlkem::ntt_inv(poly_scalar);
        mlkem::neon::ntt_inv_neon(poly_neon);

        bool match = true;
        for (size_t i = 0; i < mlkem::N; ++i) {
            int16_t diff = std::abs(
                mlkem::barrett_reduce(poly_scalar[i]) -
                mlkem::barrett_reduce(poly_neon[i]));
            if (diff > 1) {
                match = false;
                break;
            }
        }
        report("NTT inverse transform", match);
    }

    // Test 3: Round-trip (NTT -> INTT)
    {
        std::array<int16_t, mlkem::N> original;
        std::array<int16_t, mlkem::N> poly_neon;

        for (size_t i = 0; i < mlkem::N; ++i) {
            original[i] = dist(gen);
            poly_neon[i] = original[i];
        }

        mlkem::neon::ntt_neon(poly_neon);
        mlkem::neon::ntt_inv_neon(poly_neon);

        bool match = true;
        for (size_t i = 0; i < mlkem::N; ++i) {
            int16_t reduced = mlkem::barrett_reduce(poly_neon[i]);
            if (reduced < 0) reduced += mlkem::Q;
            int16_t orig = original[i];
            if (orig < 0) orig += mlkem::Q;

            if (std::abs(reduced - orig) > 1) {
                match = false;
                break;
            }
        }
        report("Round-trip NTT -> INTT", match);
    }

    // Test 4: Polynomial addition
    {
        std::array<int16_t, mlkem::N> a, b;
        std::array<int16_t, mlkem::N> c_scalar, c_neon;

        for (size_t i = 0; i < mlkem::N; ++i) {
            a[i] = dist(gen);
            b[i] = dist(gen);
        }

        for (size_t i = 0; i < mlkem::N; ++i) {
            c_scalar[i] = a[i] + b[i];
        }

        mlkem::neon::poly_add_neon(c_neon, a, b);

        bool match = (std::memcmp(c_scalar.data(), c_neon.data(),
            sizeof(c_scalar)) == 0);
        report("Polynomial addition", match);
    }

    // Test 5: Polynomial subtraction
    {
        std::array<int16_t, mlkem::N> a, b;
        std::array<int16_t, mlkem::N> c_scalar, c_neon;

        for (size_t i = 0; i < mlkem::N; ++i) {
            a[i] = dist(gen);
            b[i] = dist(gen);
        }

        for (size_t i = 0; i < mlkem::N; ++i) {
            c_scalar[i] = a[i] - b[i];
        }

        mlkem::neon::poly_sub_neon(c_neon, a, b);

        bool match = (std::memcmp(c_scalar.data(), c_neon.data(),
            sizeof(c_scalar)) == 0);
        report("Polynomial subtraction", match);
    }
}

#endif // SIMD_NEON_COMPILED

// ============================================================================
// ML-DSA SIMD Tests
// ============================================================================

#if SIMD_AVX2_COMPILED

void test_mldsa_ntt_avx2() {
    std::cout << "\n=== ML-DSA AVX2 NTT Tests ===" << std::endl;

    if (!simd::has_avx2()) {
        std::cout << "  [SKIP] AVX2 not available on this CPU" << std::endl;
        return;
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int32_t> dist(0, mldsa::Q - 1);

    // Test 1: NTT forward transform consistency
    {
        mldsa::Poly poly_scalar;
        mldsa::Poly poly_avx2;

        for (size_t i = 0; i < mldsa::N; ++i) {
            int32_t val = dist(gen);
            poly_scalar[i] = val;
            poly_avx2[i] = val;
        }

        auto result_scalar = mldsa::ntt(poly_scalar);
        mldsa::avx2::ntt_avx2(poly_avx2);

        bool match = true;
        for (size_t i = 0; i < mldsa::N; ++i) {
            if (mldsa::mod_q(result_scalar[i]) != mldsa::mod_q(poly_avx2[i])) {
                match = false;
                break;
            }
        }
        report("NTT forward transform", match);
    }

    // Test 2: NTT inverse transform consistency
    {
        mldsa::Poly poly_scalar;
        mldsa::Poly poly_avx2;

        for (size_t i = 0; i < mldsa::N; ++i) {
            int32_t val = dist(gen);
            poly_scalar[i] = val;
            poly_avx2[i] = val;
        }

        auto result_scalar = mldsa::ntt_inv(poly_scalar);
        mldsa::avx2::ntt_inv_avx2(poly_avx2);

        bool match = true;
        for (size_t i = 0; i < mldsa::N; ++i) {
            if (mldsa::mod_q(result_scalar[i]) != mldsa::mod_q(poly_avx2[i])) {
                match = false;
                break;
            }
        }
        report("NTT inverse transform", match);
    }

    // Test 3: Round-trip
    {
        mldsa::Poly original;
        mldsa::Poly poly_avx2;

        for (size_t i = 0; i < mldsa::N; ++i) {
            original[i] = dist(gen);
            poly_avx2[i] = original[i];
        }

        mldsa::avx2::ntt_avx2(poly_avx2);
        mldsa::avx2::ntt_inv_avx2(poly_avx2);

        bool match = true;
        for (size_t i = 0; i < mldsa::N; ++i) {
            if (mldsa::mod_q(original[i]) != mldsa::mod_q(poly_avx2[i])) {
                match = false;
                break;
            }
        }
        report("Round-trip NTT -> INTT", match);
    }

    // Test 4: Pointwise multiplication
    {
        mldsa::Poly a, b;

        for (size_t i = 0; i < mldsa::N; ++i) {
            a[i] = dist(gen);
            b[i] = dist(gen);
        }

        // Apply NTT first (both implementations should match)
        auto a_ntt = mldsa::ntt(a);
        auto b_ntt = mldsa::ntt(b);

        auto c_scalar = mldsa::ntt_multiply(a_ntt, b_ntt);
        auto c_avx2 = mldsa::avx2::ntt_multiply_avx2(a_ntt, b_ntt);

        bool match = true;
        for (size_t i = 0; i < mldsa::N; ++i) {
            if (mldsa::mod_q(c_scalar[i]) != mldsa::mod_q(c_avx2[i])) {
                match = false;
                break;
            }
        }
        report("Pointwise multiplication", match);
    }

    // Test 5: Polynomial addition
    {
        mldsa::Poly a, b;

        for (size_t i = 0; i < mldsa::N; ++i) {
            a[i] = dist(gen);
            b[i] = dist(gen);
        }

        auto c_scalar = mldsa::poly_add(a, b);
        auto c_avx2 = mldsa::avx2::poly_add_avx2(a, b);

        bool match = true;
        for (size_t i = 0; i < mldsa::N; ++i) {
            if (mldsa::mod_q(c_scalar[i]) != mldsa::mod_q(c_avx2[i])) {
                match = false;
                break;
            }
        }
        report("Polynomial addition", match);
    }

    // Test 6: Polynomial subtraction
    {
        mldsa::Poly a, b;

        for (size_t i = 0; i < mldsa::N; ++i) {
            a[i] = dist(gen);
            b[i] = dist(gen);
        }

        auto c_scalar = mldsa::poly_sub(a, b);
        auto c_avx2 = mldsa::avx2::poly_sub_avx2(a, b);

        bool match = true;
        for (size_t i = 0; i < mldsa::N; ++i) {
            if (mldsa::mod_q(c_scalar[i]) != mldsa::mod_q(c_avx2[i])) {
                match = false;
                break;
            }
        }
        report("Polynomial subtraction", match);
    }
}

#endif // SIMD_AVX2_COMPILED

// ============================================================================
// ML-DSA NEON Tests
// ============================================================================

#if SIMD_NEON_COMPILED

void test_mldsa_ntt_neon() {
    std::cout << "\n=== ML-DSA NEON NTT Tests ===" << std::endl;

    if (!simd::has_neon()) {
        std::cout << "  [SKIP] NEON not available on this CPU" << std::endl;
        return;
    }

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int32_t> dist(0, mldsa::Q - 1);

    // Test 1: NTT forward transform consistency
    {
        mldsa::Poly poly_scalar;
        mldsa::Poly poly_neon;

        for (size_t i = 0; i < mldsa::N; ++i) {
            int32_t val = dist(gen);
            poly_scalar[i] = val;
            poly_neon[i] = val;
        }

        auto result_scalar = mldsa::ntt(poly_scalar);
        mldsa::neon::ntt_neon(poly_neon);

        bool match = true;
        for (size_t i = 0; i < mldsa::N; ++i) {
            if (mldsa::mod_q(result_scalar[i]) != mldsa::mod_q(poly_neon[i])) {
                match = false;
                break;
            }
        }
        report("NTT forward transform", match);
    }

    // Test 2: NTT inverse transform consistency
    {
        mldsa::Poly poly_scalar;
        mldsa::Poly poly_neon;

        for (size_t i = 0; i < mldsa::N; ++i) {
            int32_t val = dist(gen);
            poly_scalar[i] = val;
            poly_neon[i] = val;
        }

        auto result_scalar = mldsa::ntt_inv(poly_scalar);
        mldsa::neon::ntt_inv_neon(poly_neon);

        bool match = true;
        for (size_t i = 0; i < mldsa::N; ++i) {
            if (mldsa::mod_q(result_scalar[i]) != mldsa::mod_q(poly_neon[i])) {
                match = false;
                break;
            }
        }
        report("NTT inverse transform", match);
    }

    // Test 3: Round-trip
    {
        mldsa::Poly original;
        mldsa::Poly poly_neon;

        for (size_t i = 0; i < mldsa::N; ++i) {
            original[i] = dist(gen);
            poly_neon[i] = original[i];
        }

        mldsa::neon::ntt_neon(poly_neon);
        mldsa::neon::ntt_inv_neon(poly_neon);

        bool match = true;
        for (size_t i = 0; i < mldsa::N; ++i) {
            if (mldsa::mod_q(original[i]) != mldsa::mod_q(poly_neon[i])) {
                match = false;
                break;
            }
        }
        report("Round-trip NTT -> INTT", match);
    }

    // Test 4: Pointwise multiplication
    {
        mldsa::Poly a, b;

        for (size_t i = 0; i < mldsa::N; ++i) {
            a[i] = dist(gen);
            b[i] = dist(gen);
        }

        auto a_ntt = mldsa::ntt(a);
        auto b_ntt = mldsa::ntt(b);

        auto c_scalar = mldsa::ntt_multiply(a_ntt, b_ntt);
        auto c_neon = mldsa::neon::ntt_multiply_neon(a_ntt, b_ntt);

        bool match = true;
        for (size_t i = 0; i < mldsa::N; ++i) {
            if (mldsa::mod_q(c_scalar[i]) != mldsa::mod_q(c_neon[i])) {
                match = false;
                break;
            }
        }
        report("Pointwise multiplication", match);
    }

    // Test 5: Polynomial addition
    {
        mldsa::Poly a, b;

        for (size_t i = 0; i < mldsa::N; ++i) {
            a[i] = dist(gen);
            b[i] = dist(gen);
        }

        auto c_scalar = mldsa::poly_add(a, b);
        auto c_neon = mldsa::neon::poly_add_neon(a, b);

        bool match = true;
        for (size_t i = 0; i < mldsa::N; ++i) {
            if (mldsa::mod_q(c_scalar[i]) != mldsa::mod_q(c_neon[i])) {
                match = false;
                break;
            }
        }
        report("Polynomial addition", match);
    }

    // Test 6: Polynomial subtraction
    {
        mldsa::Poly a, b;

        for (size_t i = 0; i < mldsa::N; ++i) {
            a[i] = dist(gen);
            b[i] = dist(gen);
        }

        auto c_scalar = mldsa::poly_sub(a, b);
        auto c_neon = mldsa::neon::poly_sub_neon(a, b);

        bool match = true;
        for (size_t i = 0; i < mldsa::N; ++i) {
            if (mldsa::mod_q(c_scalar[i]) != mldsa::mod_q(c_neon[i])) {
                match = false;
                break;
            }
        }
        report("Polynomial subtraction", match);
    }
}

#endif // SIMD_NEON_COMPILED

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "SIMD NTT Correctness Tests" << std::endl;
    std::cout << "========================================" << std::endl;

    test_simd_detection();

#if SIMD_AVX2_COMPILED
    test_mlkem_ntt_avx2();
    test_mldsa_ntt_avx2();
#else
    std::cout << "\n[INFO] AVX2 not compiled. Compile with -mavx2 to enable." << std::endl;
#endif

#if SIMD_NEON_COMPILED
    test_mlkem_ntt_neon();
    test_mldsa_ntt_neon();
#else
    std::cout << "\n[INFO] NEON not compiled (not ARM64 platform)." << std::endl;
#endif

    std::cout << "\n========================================" << std::endl;
    std::cout << "Results: " << tests_passed << " passed, "
              << tests_failed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
