/**
 * SIMD Feature Detection
 *
 * Runtime detection of CPU SIMD capabilities for optimal algorithm dispatch.
 * Supports AVX2 (x86-64) and NEON (ARM64).
 */

#ifndef COMMON_SIMD_DETECT_HPP
#define COMMON_SIMD_DETECT_HPP

#include <cstdint>

namespace simd {

// Compile-time platform detection
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    #define SIMD_X86 1
#else
    #define SIMD_X86 0
#endif

#if defined(__aarch64__) || defined(_M_ARM64)
    #define SIMD_ARM64 1
#else
    #define SIMD_ARM64 0
#endif

// Compile-time SIMD availability
#if SIMD_X86 && defined(__AVX2__)
    #define SIMD_AVX2_COMPILED 1
#else
    #define SIMD_AVX2_COMPILED 0
#endif

#if SIMD_ARM64 && defined(__ARM_NEON)
    #define SIMD_NEON_COMPILED 1
#else
    #define SIMD_NEON_COMPILED 0
#endif

#if SIMD_X86
    #ifdef _MSC_VER
        #include <intrin.h>
    #else
        #include <cpuid.h>
    #endif
#endif

/**
 * Runtime CPU feature flags
 */
struct CpuFeatures {
    bool avx2 = false;
    bool avx512f = false;
    bool neon = false;

    static CpuFeatures detect() noexcept {
        CpuFeatures features;

#if SIMD_X86
        // x86/x64: Use CPUID to detect features
        uint32_t eax, ebx, ecx, edx;

    #ifdef _MSC_VER
        int cpuInfo[4];
        __cpuid(cpuInfo, 0);
        uint32_t maxFunc = cpuInfo[0];

        if (maxFunc >= 7) {
            __cpuidex(cpuInfo, 7, 0);
            ebx = cpuInfo[1];
            features.avx2 = (ebx & (1 << 5)) != 0;
            features.avx512f = (ebx & (1 << 16)) != 0;
        }
    #else
        if (__get_cpuid_max(0, nullptr) >= 7) {
            __cpuid_count(7, 0, eax, ebx, ecx, edx);
            features.avx2 = (ebx & (1 << 5)) != 0;
            features.avx512f = (ebx & (1 << 16)) != 0;
        }
    #endif
#endif

#if SIMD_ARM64
        // ARM64: NEON is mandatory on AArch64
        features.neon = true;
#endif

        return features;
    }
};

/**
 * Get cached CPU features (detected once at startup)
 */
inline const CpuFeatures& cpu_features() noexcept {
    static const CpuFeatures features = CpuFeatures::detect();
    return features;
}

/**
 * Check if AVX2 is available at runtime
 */
inline bool has_avx2() noexcept {
#if SIMD_AVX2_COMPILED
    return cpu_features().avx2;
#else
    return false;
#endif
}

/**
 * Check if NEON is available at runtime
 */
inline bool has_neon() noexcept {
#if SIMD_NEON_COMPILED
    return cpu_features().neon;
#else
    return false;
#endif
}

/**
 * Check if any SIMD is available
 */
inline bool has_simd() noexcept {
    return has_avx2() || has_neon();
}

} // namespace simd

#endif // COMMON_SIMD_DETECT_HPP
