# NIST Known Answer Tests (KAT)

This document describes the Known Answer Test (KAT) infrastructure for verifying ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) implementations against official NIST ACVP test vectors.

## Overview

Known Answer Tests (KAT) are standardized test vectors provided by NIST to verify that cryptographic implementations produce correct, bit-identical outputs. These tests are essential for FIPS certification and interoperability.

### Test Vector Source

Test vectors are from the official NIST ACVP-Server repository:
- **Repository**: https://github.com/usnistgov/ACVP-Server
- **ML-DSA vectors**: `gen-val/json-files/ML-DSA-*-FIPS204/`
- **SLH-DSA vectors**: `gen-val/json-files/SLH-DSA-*-FIPS205/`

## Running KAT Tests

### Prerequisites

- Docker installed and running
- Make utility

### Commands

```bash
# Run all KAT tests
make test-kat

# Run ML-DSA KAT tests only
make test-kat-mldsa

# Run SLH-DSA KAT tests only
make test-kat-slhdsa
```

### Download Fresh Test Vectors

To download the latest NIST ACVP test vectors:

```bash
./scripts/download_kat_vectors.sh
```

This downloads vectors to `tests/kat/`:
```
tests/kat/
├── mldsa/
│   ├── keyGen_prompt.json      # Input seeds
│   ├── keyGen_expected.json    # Expected keys
│   ├── sigGen_prompt.json      # Signing inputs
│   ├── sigGen_expected.json    # Expected signatures
│   ├── sigVer_prompt.json      # Verification inputs
│   └── sigVer_expected.json    # Expected results
└── slhdsa/
    └── (same structure)
```

## Test Structure

### ML-DSA KAT Tests (`tests/cpp/test_mldsa_kat.cpp`)

| Test Category | Description |
|---------------|-------------|
| KeyGen KAT | Verify key generation with NIST seeds produces expected public keys |
| KeyGen Determinism | Same seed produces identical keys |
| Sign/Verify Consistency | Signatures verify correctly for all parameter sets |
| Context String | Context strings are correctly incorporated |

**Parameter Sets Tested:**
- ML-DSA-44 (Security Category 2)
- ML-DSA-65 (Security Category 3)
- ML-DSA-87 (Security Category 5)

### SLH-DSA KAT Tests (`tests/cpp/test_slhdsa_kat.cpp`)

| Test Category | Description |
|---------------|-------------|
| KeyGen KAT | Verify key generation with NIST seeds |
| Sign/Verify Consistency | Signatures verify correctly |
| Context String | Context string handling |
| Key/Signature Sizes | Verify correct sizes per parameter set |

**Parameter Sets Tested:**
- SLH-DSA-SHA2-128s/128f
- SLH-DSA-SHAKE-128s/128f
- SLH-DSA-SHA2-192s/192f
- SLH-DSA-SHA2-256s/256f

## Test Vector Format

### ML-DSA KeyGen (ACVP)

**Input (`keyGen_prompt.json`):**
```json
{
  "testGroups": [{
    "parameterSet": "ML-DSA-44",
    "tests": [{
      "tcId": 1,
      "seed": "D71361C000F9A7BC99DFB425BCB6BB27..."
    }]
  }]
}
```

**Expected Output (`keyGen_expected.json`):**
```json
{
  "testGroups": [{
    "tests": [{
      "tcId": 1,
      "pk": "B845FA2881407A59...",
      "sk": "B845FA2881407A59..."
    }]
  }]
}
```

### SLH-DSA KeyGen (ACVP)

**Input** (3 separate seeds):
```json
{
  "tcId": 1,
  "skSeed": "173D04C938C1C36BF289C3C022D04B14",
  "skPrf": "63AE23C41AA546DA589774AC20B745C4",
  "pkSeed": "0D794777914C99766827F0F09CA972BE"
}
```

## FIPS 204 Domain Separation

The final FIPS 204 standard (August 2024) added domain separation to prevent cross-parameter-set key reuse:

```
H(ξ || k || l)  instead of  H(ξ)
```

Where:
- `ξ` = 32-byte seed
- `k` = number of polynomial rows (single byte)
- `l` = number of polynomial columns (single byte)

| Parameter Set | k | l |
|---------------|---|---|
| ML-DSA-44 | 4 | 4 |
| ML-DSA-65 | 6 | 5 |
| ML-DSA-87 | 8 | 7 |

This ensures different parameter sets produce completely different keys even with the same seed.

## Current Test Status

### ML-DSA (FIPS 204)

| Test | Status |
|------|--------|
| KeyGen tcId=1 | PASSED |
| KeyGen tcId=2 | PASSED |
| KeyGen tcId=3 | PASSED |
| KeyGen determinism (ML-DSA-65) | PASSED |
| KeyGen determinism (ML-DSA-87) | PASSED |
| Sign/Verify (ML-DSA-44) | PASSED |
| Sign/Verify (ML-DSA-65) | PASSED |
| Sign/Verify (ML-DSA-87) | PASSED |
| Context string handling | PASSED |

**Result: 9/9 tests passing**

### SLH-DSA (FIPS 205)

| Test | Status |
|------|--------|
| KeyGen KAT (SHA2-128s, tcId=1-3) | PASSED |
| KeyGen KAT (SHAKE-128s, tcId=11-12) | PASSED |
| KeyGen KAT (SHA2-128f, tcId=21) | PASSED |
| Sign/Verify consistency (SHAKE-128f) | PASSED |
| Sign/Verify consistency (SHA2-128s) | PASSED |
| Context string handling | PASSED |
| Key/Signature sizes | PASSED |

**Result: 10/10 tests passing**

## Adding New Test Vectors

To add new test cases from ACVP:

1. Add test data to the appropriate test file
2. Use the `hex_to_bytes()` helper to convert hex strings
3. Compare against expected values using `KAT_ASSERT`

Example:
```cpp
KAT_TEST("ML-DSA-44 KeyGen tcId=N") {
    auto seed = hex_to_bytes("...");
    std::string expected_pk_prefix = "...";

    auto [pk, sk] = dsa.keygen(seed);

    std::string pk_prefix = bytes_to_hex(
        std::vector<uint8_t>(pk.begin(), pk.begin() + 32));

    KAT_ASSERT(pk_prefix == expected_pk_prefix, "Public key mismatch");
KAT_END
```

## References

- [FIPS 204 - ML-DSA Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205 - SLH-DSA Standard](https://csrc.nist.gov/pubs/fips/205/final)
- [NIST ACVP Server](https://github.com/usnistgov/ACVP-Server)
- [ACVP ML-DSA Specification](https://pages.nist.gov/ACVP/draft-celi-acvp-ml-dsa.html)
- [PQShield: What's Changed in Final Standards](https://pqshield.com/new-pqc-standards-whats-changed-since-the-draft-versions/)
