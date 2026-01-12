# Security Assessment: Side-Channel Attack Analysis

This document provides a security assessment of the SLH-DSA and ML-DSA implementations with respect to side-channel attacks.

## Executive Summary

| Implementation | Side-Channel Safe | Status | Suitable For |
|----------------|-------------------|--------|--------------|
| SLH-DSA (C++) | Partial | Mitigated | Reference/Educational |
| ML-DSA (C++) | No | Unmitigated | Reference/Educational |
| ML-DSA (Python) | No | Unmitigated | Reference/Educational |
| SLH-DSA (Python) | No | Unmitigated | Reference/Educational |

**Status Update (v1.1)**: The SLH-DSA C++ implementation has been updated with constant-time mitigations for the critical vulnerabilities identified in the initial assessment. While these mitigations significantly improve side-channel resistance, the implementation has NOT been formally verified and should still be considered **educational/reference quality**.

---

## Side-Channel Attack Background

Side-channel attacks exploit information leaked through physical implementation details rather than cryptographic weaknesses:

| Attack Type | Leaked Information | Mitigation |
|-------------|-------------------|------------|
| **Timing** | Execution time variations | Constant-time code |
| **Cache** | Memory access patterns | Data-independent access |
| **Power** | Power consumption variations | Masking, shuffling |
| **Branch Prediction** | Conditional branch outcomes | Branchless code |

For cryptographic implementations, the primary concern is **timing attacks** and **cache attacks**, which can be exploited remotely or by co-located processes.

---

## SLH-DSA (FIPS 205) - Mitigated Vulnerabilities

### MITIGATED: WOTS+ Chain Function

**Location**: `src/cpp/slhdsa/wots.hpp:43-99`

**Original Issue**: Loop iterations depended on secret value 's', leaking information about message digest through timing.

**Mitigation Applied**: The chain function now always executes `w` iterations (maximum possible) regardless of the actual chain length. A constant-time conditional select is used to accumulate the correct result.

```cpp
// MITIGATED: Always iterate w times for constant time
for (uint32_t j = 0; j < w; ++j) {
    adrs.set_hash_address(j);
    auto hashed = hash_funcs.F(pk_seed, adrs, tmp);

    // Constant-time conditional update
    bool should_hash = (j >= i);
    tmp = ct::ct_select_bytes(hashed, tmp, should_hash);

    bool is_final = (s > 0) && (j == i + s - 1);
    result = ct::ct_select_bytes(tmp, result, is_final);
}
ct::ct_barrier();
```

**Status**: MITIGATED with constant-time implementation in `ct_utils.hpp`

---

### MITIGATED: XMSS Tree Reconstruction

**Location**: `src/cpp/slhdsa/xmss.hpp:157-178`

**Original Issue**: Branch based on secret index bit revealed tree traversal path through branch prediction and cache timing.

**Mitigation Applied**: Both possible concatenation orderings are computed, and constant-time selection chooses the correct one without branching.

```cpp
// MITIGATED: Constant-time conditional concatenation
for (size_t j = 0; j < hp; ++j) {
    adrs.set_tree_height(static_cast<uint32_t>(j + 1));
    adrs.set_tree_index(idx >> (j + 1));
    std::span<const uint8_t> auth_node = auth.subspan(j * n, n);

    // Determine if node is left child (bit is 0) or right child (bit is 1)
    bool is_left_child = ((idx >> j) & 1) == 0;

    // Constant-time: compute both orderings and select
    auto concat = ct::ct_concat_conditional(node, auth_node, is_left_child);
    node = hash_funcs.H(pk_seed, adrs, concat);
}
ct::ct_barrier();
```

**Status**: MITIGATED with `ct::ct_concat_conditional()`

---

### MITIGATED: FORS Tree Path Branching

**Location**: `src/cpp/slhdsa/fors.hpp:208-229`

**Original Issue**: Same branch-based concatenation issue as XMSS.

**Mitigation Applied**: Same constant-time conditional concatenation pattern.

```cpp
// MITIGATED: Constant-time conditional concatenation
for (size_t j = 0; j < a; ++j) {
    // ... setup ...

    bool is_left_child = ((idx >> j) & 1) == 0;
    auto concat = ct::ct_concat_conditional(node, auth_node, is_left_child);
    node = hash_funcs.H(pk_seed, adrs, concat);
}
ct::ct_barrier();
```

**Status**: MITIGATED with `ct::ct_concat_conditional()`

---

### MITIGATED: Non-Constant-Time Verification

**Location**: `src/cpp/slhdsa/hypertree.hpp:144-146`

**Original Issue**: `std::equal` performed early termination on first mismatch, enabling timing oracle attacks.

**Mitigation Applied**: Replaced with constant-time comparison that always examines all bytes.

```cpp
// MITIGATED: Constant-time comparison
ct::ct_barrier();
return ct::ct_equal(node, pk_root);
```

**Status**: MITIGATED with `ct::ct_equal()`

---

### Remaining Consideration: FORS Secret Indexing

**Location**: `src/cpp/slhdsa/fors.hpp:130-138`

The FORS indices derived from the message hash are used in computations. While the tree traversal is now constant-time, the memory access patterns when computing different `global_leaf_idx` values may still leak information through cache timing.

**Risk Level**: Low - The hash function calls dominate execution time, and the index computation itself is arithmetic (not memory-dependent).

**Status**: Partially mitigated - main concern addressed by tree traversal fix.

---

## Constant-Time Utilities

A new utility header `ct_utils.hpp` provides the following constant-time primitives:

| Function | Purpose |
|----------|---------|
| `ct_select_u8/u32/u64` | Constant-time conditional select for integers |
| `ct_select_bytes` | Constant-time conditional select for byte vectors |
| `ct_equal` | Constant-time byte array comparison |
| `ct_copy_conditional` | Constant-time conditional memory copy |
| `ct_swap_conditional` | Constant-time conditional swap |
| `ct_concat_conditional` | Constant-time conditional concatenation ordering |
| `ct_lt_u32/ct_ge_u32` | Constant-time integer comparisons |
| `ct_zero` | Secure memory zeroing |
| `ct_barrier` | Compiler memory barrier |

**Implementation Notes**:
- Uses `volatile` qualifiers to prevent compiler optimization of constant-time patterns
- Includes compiler-specific memory barriers for GCC/Clang and MSVC
- All selection functions use bit masking rather than branching

---

## ML-DSA (FIPS 204) Vulnerabilities (Unmitigated)

### Medium: Polynomial Operations

**Location**: `src/cpp/mldsa/ntt.hpp`

The NTT (Number Theoretic Transform) operations use modular arithmetic that may have timing variations based on operand values, though this is less severe than SLH-DSA issues.

### Medium: Rejection Sampling

**Location**: `src/cpp/mldsa/sampling.hpp`

Rejection sampling inherently has variable timing based on random input, though this is acceptable per the ML-DSA specification when properly implemented.

### Low: Hint Encoding

The hint vector operations may have minor timing variations based on the number of non-zero hints.

---

## Risk Assessment Matrix (Updated)

| Vulnerability | Original Severity | Current Status | Component |
|--------------|-------------------|----------------|-----------|
| WOTS+ chain timing | Critical | **MITIGATED** | SLH-DSA Sign |
| XMSS branch leakage | Critical | **MITIGATED** | SLH-DSA Sign/Verify |
| FORS path leakage | Critical | **MITIGATED** | SLH-DSA Sign |
| FORS index leakage | Medium | Partially Mitigated | SLH-DSA Sign |
| Verification timing | Medium | **MITIGATED** | SLH-DSA Verify |
| NTT timing | Low | Unmitigated | ML-DSA |

---

## Recommendations

### For Production Use

1. **This implementation is improved but still reference-quality** - while critical timing vulnerabilities have been addressed, it has not been formally verified
2. For high-security applications, use NIST-certified or audited implementations:
   - [liboqs](https://github.com/open-quantum-safe/liboqs) - Open Quantum Safe project
   - [Post-Quantum Cryptography Alliance (PQCA)](https://pqca.org/) - Linux Foundation projects
   - Vendor implementations with side-channel certifications

### For Further Hardening

If additional hardening is required:

1. **Formal Verification**: Use tools like ctgrind or dudect to verify constant-time properties
2. **Platform Testing**: Test on target hardware, as timing behavior may vary
3. **Memory Access Patterns**: Consider cache-oblivious algorithms for memory-bound operations
4. **Power Analysis**: For embedded use, consider masking and shuffling techniques

### Testing for Side-Channel Resistance

1. **dudect**: Statistical timing leak detection
   ```bash
   # https://github.com/oreparaz/dudect
   ./dudect_test --iterations 1000000
   ```

2. **ctgrind**: Valgrind-based constant-time verification
   ```bash
   valgrind --tool=ctgrind ./test_signing
   ```

3. **timecop**: Timing attack simulator
   ```bash
   ./timecop analyze --binary ./sign --input random
   ```

---

## Compliance Notes

| Standard | Requirement | This Implementation |
|----------|-------------|---------------------|
| FIPS 205 | Functional correctness | Compliant (KAT tests pass) |
| FIPS 205 | Side-channel resistance | Mitigations applied (not formally verified) |
| Common Criteria | AVA_VAN.5 | Not formally verified |
| PCI-DSS | Secure implementation | Improved, needs formal audit |

**Note**: FIPS 205 does not mandate side-channel resistance. However, real-world deployments should consider side-channel attacks as part of their threat model.

---

## Changes Summary (v1.1)

### Files Modified

| File | Changes |
|------|---------|
| `ct_utils.hpp` | **NEW** - Constant-time utility functions |
| `wots.hpp` | Chain function now executes fixed w iterations |
| `xmss.hpp` | Tree reconstruction uses ct_concat_conditional |
| `fors.hpp` | Tree reconstruction uses ct_concat_conditional |
| `hypertree.hpp` | Verification uses ct_equal |

### New Constant-Time Patterns

1. **Fixed-iteration loops**: Loops always execute maximum iterations, with conditional selection for results
2. **Branchless selection**: Uses bit masking instead of if/else for secret-dependent choices
3. **Constant-time comparison**: Examines all bytes regardless of mismatch position
4. **Memory barriers**: Prevents compiler from reordering or optimizing away constant-time code

---

## References

- [FIPS 205 - SLH-DSA Standard](https://csrc.nist.gov/pubs/fips/205/final)
- [FIPS 204 - ML-DSA Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems](https://www.rambus.com/timing-attacks-on-implementations-of-diffie-hellman-rsa-dss-and-other-systems/) - Kocher, 1996
- [Cache-timing attacks on AES](https://cr.yp.to/antiforgery/cachetiming-20050414.pdf) - Bernstein, 2005
- [dudect: Dude, is my code constant time?](https://github.com/oreparaz/dudect)
- [Guidelines for Mitigating Timing Side Channels Against Cryptographic Implementations](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/secure-coding/mitigate-timing-side-channel-crypto-implementation.html) - Intel

---

## Document History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2024-12-17 | Initial security assessment |
| 1.1 | 2024-12-17 | Documented constant-time mitigations for SLH-DSA C++ |
