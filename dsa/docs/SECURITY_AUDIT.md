# Security Audit and Fixes

This document summarizes the security audit performed on the post-quantum cryptography library and the fixes implemented.

## Audit Date
January 2025

## Executive Summary

A comprehensive security audit was performed on the ML-KEM (FIPS 203), ML-DSA (FIPS 204), and SLH-DSA (FIPS 205) implementations. The audit identified several security issues ranging from critical timing vulnerabilities to medium-severity information leakage. All identified issues have been fixed and verified through the test suite.

**Results:** 95/95 tests passing after fixes.

---

## Critical Issues Fixed

### 1. ML-KEM Implicit Rejection Timing Vulnerability

**Location:** `src/cpp/mlkem/mlkem.hpp:200-213`

**Issue:** The decapsulation function used non-constant-time operations for implicit rejection:
- `std::memcmp()` returns early on first byte difference (timing leak)
- Branching `if (valid)` statement leaked timing information about ciphertext validity

**Impact:** Violated FIPS 203 security requirements. Attackers could potentially determine ciphertext validity through timing analysis.

**Fix:**
```cpp
// Before (VULNERABLE):
bool valid = (c.size() == c_prime.size()) &&
             (std::memcmp(c.data(), c_prime.data(), c.size()) == 0);
if (valid) {
    return K_prime;
} else {
    return J(z_c);
}

// After (SECURE):
auto K_bar = J(z_c);  // Compute both outputs
bool valid = ct::equal(c, c_prime);  // Constant-time comparison
ct::barrier();
return ct::select_bytes(K_prime, K_bar, valid);  // Branch-free selection
```

### 2. SLH-DSA SHA2 Hash Function Selection

**Location:** `src/cpp/slhdsa/hash_functions.cpp:292-334`

**Issue:** The `PRF()` and `F()` functions always used SHA-256 regardless of parameter set. According to FIPS 205:
- n=16: Use SHA-256 with 64-byte block
- n=24,32: Use SHA-512 with 128-byte block

**Impact:** SLH-DSA-SHA2-192s/f and SLH-DSA-SHA2-256s/f parameter sets produced cryptographically incorrect outputs.

**Fix:**
```cpp
// Before (INCORRECT):
auto result = sha256(data);  // Always SHA-256

// After (CORRECT):
auto result = hash(data);  // Uses SHA-256 or SHA-512 based on n
```

Also fixed padding calculation from hardcoded `64 - n_` to `block_size_ - n_`.

---

## High Severity Issues Fixed

### 3. ML-KEM Modular Multiplication Timing

**Location:** `src/cpp/mlkem/ntt.hpp:21-26`

**Issue:** The `fqmul()` function used the `%` operator for modular reduction, which is not constant-time on many CPU architectures.

**Fix:** Implemented constant-time Barrett reduction for 32-bit values:
```cpp
// Before:
t = t % Q;
if (t < 0) t += Q;

// After:
return barrett_reduce_32(t);  // Constant-time Barrett reduction
```

Added new function in `params.hpp`:
```cpp
[[nodiscard]] inline constexpr int16_t barrett_reduce_32(int32_t a) noexcept {
    constexpr int64_t v = 20642679;  // floor(2^36 / q)
    int64_t t = (static_cast<int64_t>(a) * v) >> 36;
    int32_t r = a - static_cast<int32_t>(t) * Q;
    r -= Q;
    r += (r >> 31) & Q;  // Constant-time conditional add
    return static_cast<int16_t>(r);
}
```

### 4. ML-DSA Verification Final Comparison

**Location:** `src/cpp/mldsa/mldsa.hpp:505-513`

**Issue:** The final challenge comparison used `==` operator which may not be constant-time.

**Fix:**
```cpp
// Before:
return c_tilde == c_tilde_prime;

// After:
ct::barrier();
return ct::equal(c_tilde, c_tilde_prime);
```

---

## Medium Severity Issues Fixed

### 5. Error Message Information Leakage

**Locations:**
- `src/cpp/bindings/mldsa_module.cpp`
- `src/cpp/bindings/mlkem_module.cpp`
- `src/cpp/bindings/slhdsa_module.cpp`

**Issue:** Error messages revealed expected key/signature sizes, allowing attackers to fingerprint which algorithm variant is in use.

**Before:**
```cpp
throw std::invalid_argument(
    "Invalid secret key size: expected " +
    std::to_string(dsa_.params().sk_size()) +
    " bytes, got " + std::to_string(sk_vec.size()));
```

**After:**
```cpp
throw std::invalid_argument("Invalid secret key format");
```

### 6. Buffer Allocation Overflow Protection

**Location:** `src/cpp/mlkem/utils.cpp`

**Issue:** SHAKE stream buffer calculations could overflow with extreme input sizes.

**Fix:** Added bounds checking:
```cpp
constexpr size_t MAX_BUFFER_SIZE = 1ULL << 30;  // 1 GB

if (n > MAX_BUFFER_SIZE) {
    throw std::runtime_error("SHAKE128 read request too large");
}

// Check for overflow before addition
if (remaining > MAX_BUFFER_SIZE - 1024) {
    throw std::runtime_error("SHAKE128 buffer size overflow");
}
```

---

## New Infrastructure

### Shared Constant-Time Utilities

**New File:** `src/cpp/ct_utils.hpp`

Created a shared constant-time utility library for all algorithms:

| Function | Description |
|----------|-------------|
| `ct::equal()` | Constant-time byte array comparison |
| `ct::select_bytes()` | Constant-time conditional byte selection |
| `ct::select_u8/u32/u64()` | Constant-time conditional integer selection |
| `ct::zero()` | Secure memory zeroing |
| `ct::barrier()` | Compiler memory barrier |
| `ct::lt_u32()` | Constant-time less-than comparison |
| `ct::ge_u32()` | Constant-time greater-or-equal comparison |

These utilities use:
- Volatile variables to prevent compiler optimization
- Arithmetic masking instead of branching
- Compiler memory barriers to prevent instruction reordering

---

## Files Modified

| File | Changes |
|------|---------|
| `src/cpp/ct_utils.hpp` | **NEW** - Shared constant-time utilities |
| `src/cpp/mlkem/mlkem.hpp` | Fixed implicit rejection timing |
| `src/cpp/mlkem/ntt.hpp` | Fixed fqmul to use Barrett reduction |
| `src/cpp/mlkem/params.hpp` | Added barrett_reduce_32() |
| `src/cpp/mlkem/utils.cpp` | Added overflow checks in SHAKE streams |
| `src/cpp/mldsa/mldsa.hpp` | Added CT comparison in verification |
| `src/cpp/slhdsa/hash_functions.cpp` | Fixed SHA2 PRF/F hash selection |
| `src/cpp/bindings/mldsa_module.cpp` | Sanitized error messages |
| `src/cpp/bindings/mlkem_module.cpp` | Sanitized error messages |
| `src/cpp/bindings/slhdsa_module.cpp` | Sanitized error messages |

---

## Verification

All fixes were verified through the test suite:

```
=== Test Results ===
ML-DSA:  33/33 tests passed
SLH-DSA: 20/20 tests passed
ML-KEM:  42/42 tests passed
Total:   95/95 tests passed
```

---

## Recommendations for Production Use

1. **Constant-Time Verification:** Use tools like `ctgrind` or `dudect` to verify constant-time properties in your target environment.

2. **Compiler Settings:** Compile with optimization level `-O2` or lower. Higher optimization levels may defeat some constant-time protections.

3. **Key Zeroization:** Implement RAII-style secure containers that automatically zero sensitive data on destruction.

4. **Memory Protection:** Consider using `mlock()` to prevent sensitive key material from being swapped to disk.

5. **Hardware Considerations:** The `volatile` keyword used in constant-time utilities is not guaranteed across all architectures. Consider platform-specific intrinsics for critical deployments.

---

## Security Contact

For security issues, please refer to the project's security policy.
