# Firmware Protection with Post-Quantum Cryptography

This guide explains how to use post-quantum digital signatures to protect firmware integrity and authenticity.

> **IMPORTANT SECURITY NOTICE**
>
> Digital signatures alone are NOT sufficient for secure firmware updates.
> Production deployments require **Hardware Root of Trust** - see the
> [Security Architecture](#security-architecture-hardware-root-of-trust) section.

---

## Understanding Digital Signatures

### What Signatures DO

| Protection | Description |
|------------|-------------|
| **Authenticity** | Proves firmware comes from the legitimate manufacturer |
| **Integrity** | Detects if firmware was modified in transit or storage |
| **Non-repudiation** | The signer cannot deny signing the firmware |

### What Signatures DO NOT Do

| NOT Protected | Description |
|---------------|-------------|
| **Confidentiality** | Firmware is NOT encrypted - anyone can read it |
| **Bootloader protection** | Signatures cannot prevent bootloader tampering |
| **Hardware attacks** | Physical access can bypass software verification |
| **Key replacement** | If attacker replaces public key, they control verification |

### Common Misconception: "Decrypt the Firmware"

**Digital signatures do not encrypt anything.**

```
ENCRYPTION (Confidentiality):
  plaintext  --[encrypt with key]--> ciphertext --[decrypt with key]--> plaintext
  Only key holder can READ the data

SIGNATURES (Authenticity):
  message --[sign with SECRET key]--> signature
  message + signature --[verify with PUBLIC key]--> valid/invalid
  Anyone can READ the message, only secret key holder can SIGN
```

The firmware in a signed package is **plaintext** - fully readable. The signature only proves it hasn't been tampered with and came from the legitimate signer.

---

## Threat Model

### Attacks PREVENTED by Signatures

| Attack | How Signatures Help |
|--------|---------------------|
| **Man-in-the-middle** | Modified firmware fails verification |
| **Compromised CDN** | Attacker cannot forge valid signatures |
| **Supply chain injection** | Unauthorized firmware is rejected |
| **Accidental corruption** | Bit flips detected during verification |

### Attacks NOT PREVENTED by Signatures Alone

| Attack | Why Signatures Don't Help |
|--------|---------------------------|
| **Bootloader replacement** | Attacker disables verification entirely |
| **Public key replacement** | Attacker's firmware passes verification |
| **Physical flash access** | Direct write bypasses all software checks |
| **Debug port access** | JTAG/SWD can overwrite anything |
| **Voltage glitching** | Causes verification to be skipped |
| **Reverse engineering** | Firmware is readable (not encrypted) |

### The Critical Question

> "If an attacker distributes firmware.bin + firmware.sig + public.key,
> what stops them from creating their own signature?"

**Answer:** They don't have the **secret key**.

- The **public key** can only **verify** signatures
- The **secret key** is required to **create** signatures
- Without the secret key, forging a signature is computationally infeasible

**BUT:** If the attacker can replace the public key embedded in the device's bootloader, they can use their own key pair and sign malicious firmware that the device will accept.

---

## Security Architecture: Hardware Root of Trust

### Why Software-Only Is Insufficient

```
SOFTWARE-ONLY VERIFICATION (VULNERABLE):
┌─────────────────────────────────────────────────────────┐
│  Bootloader in Writable Flash                           │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Public Key (can be replaced by attacker)       │    │
│  │  Verification Code (can be disabled/bypassed)   │    │
│  └─────────────────────────────────────────────────┘    │
│                         ↓                               │
│  IF attacker has physical access or exploits a bug:     │
│  - Replace public key with attacker's key               │
│  - Disable signature verification                       │
│  - Device now accepts attacker's firmware               │
└─────────────────────────────────────────────────────────┘
```

### Hardware Root of Trust Architecture

```
SECURE BOOT WITH HARDWARE ROOT OF TRUST:

┌─────────────────────────────────────────────────────────┐
│  IMMUTABLE (Cannot be changed after manufacturing)      │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Boot ROM (mask ROM in silicon)                 │    │
│  │  - Minimal verification code                    │    │
│  │  - Reads public key hash from OTP/eFuses        │    │
│  └─────────────────────────────────────────────────┘    │
│                         │                               │
│                    verifies                             │
│                         ↓                               │
├─────────────────────────────────────────────────────────┤
│  PROTECTED (Hardware-locked, not easily modified)       │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Stage 1 Bootloader (in protected flash)        │    │
│  │  - Signed by key trusted by Boot ROM            │    │
│  │  - Contains firmware verification public key    │    │
│  │  - Protected by flash lock bits / secure boot   │    │
│  └─────────────────────────────────────────────────┘    │
│                         │                               │
│                    verifies                             │
│                         ↓                               │
├─────────────────────────────────────────────────────────┤
│  UPDATEABLE (Normal firmware updates)                   │
│  ┌─────────────────────────────────────────────────┐    │
│  │  Application Firmware                           │    │
│  │  - Signed by firmware signing key               │    │
│  │  - Can be updated via OTA                       │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

### Hardware Security Mechanisms

| Mechanism | Purpose |
|-----------|---------|
| **OTP/eFuses** | One-time programmable memory to store public key hash permanently |
| **Boot ROM** | Immutable first-stage code burned into silicon during manufacturing |
| **Flash Lock Bits** | Hardware mechanism to prevent modification of bootloader region |
| **Secure Enclave / TEE** | Isolated execution environment (e.g., ARM TrustZone) |
| **TPM** | Tamper-resistant cryptographic coprocessor for key storage (ISO/IEC 11889) |
| **Anti-rollback** | Version counter in OTP to prevent downgrade attacks |
| **Secure Debug** | Hardware mechanism to disable or authenticate debug port access |

### Example: ESP32 Secure Boot V2

The ESP32 provides a well-documented example of Hardware Root of Trust:

| Component | ESP32 Implementation |
|-----------|---------------------|
| **Key Storage** | RSA-3072 public key digest stored in eFuse (one-time programmable) |
| **Boot ROM** | Verifies second-stage bootloader signature |
| **Algorithm** | RSA-PSS with SHA-256 |
| **Chain of Trust** | ROM → Bootloader → Application (each stage verifies the next) |

For details, see: [ESP32 Secure Boot V2 Documentation](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/security/secure-boot-v2.html)

### Other Platforms

Most microcontroller vendors provide similar secure boot features. Consult your
vendor's official documentation for platform-specific implementation details:

- Search your vendor's documentation for "secure boot" or "trusted boot"
- Look for application notes on firmware security
- Check for hardware security modules or secure elements

---

## When to Use This Library

### Appropriate Use Cases

| Use Case | This Library | Hardware RoT Required? |
|----------|--------------|------------------------|
| **Development/Testing** | Yes | No |
| **Internal tools** | Yes | Recommended |
| **Production firmware** | Yes (for signing) | **Yes (for verification)** |
| **High-security products** | Yes (for signing) | **Mandatory** |

### This Library Provides

- Post-quantum signature algorithms (ML-DSA, SLH-DSA)
- Key generation with certificate metadata
- Signing and verification tools
- Password-protected key storage

### You Must Provide (for Production)

- Hardware Root of Trust implementation
- Secure key storage (HSM for signing keys)
- Protected bootloader with embedded public key
- Anti-rollback mechanism
- Secure debug configuration

---

## Why Firmware Protection Matters

Firmware is the foundational software that runs on embedded devices, IoT systems, routers, medical devices, and industrial controllers. Compromised firmware can:

- **Brick devices** - Malicious updates can permanently disable hardware
- **Create backdoors** - Attackers gain persistent access that survives reboots
- **Exfiltrate data** - Steal sensitive information from devices
- **Form botnets** - Compromised devices attack other systems
- **Cause physical harm** - In medical or industrial systems

## Why Post-Quantum Cryptography?

Traditional signatures (RSA, ECDSA) are vulnerable to quantum computers:

| Threat | Impact |
|--------|--------|
| **Harvest Now, Decrypt Later** | Attackers collect signed firmware today to forge signatures once quantum computers exist |
| **Long Device Lifecycles** | Devices deployed today may operate for 10-20+ years |
| **Difficult Updates** | Embedded devices are hard to update with new algorithms |
| **Supply Chain Attacks** | Forged firmware could be distributed through legitimate channels |

**NIST Post-Quantum Standards** provide quantum-resistant alternatives:
- **ML-DSA (FIPS 204)** - Fast, compact signatures for most use cases
- **SLH-DSA (FIPS 205)** - Hash-based signatures with conservative security assumptions

## Algorithm Selection for Firmware

| Use Case | Recommended Algorithm | Rationale |
|----------|----------------------|-----------|
| **Resource-constrained devices** | ML-DSA-44 | Smallest signatures (2.4 KB), fast verification |
| **Standard firmware** | ML-DSA-65 | Balance of security (NIST Level 3) and size |
| **High-security firmware** | ML-DSA-87 | Maximum security (NIST Level 5) |
| **Long-term archival** | SLH-DSA-SHA2-128s | Conservative, hash-based security |
| **Critical infrastructure** | SLH-DSA-SHA2-256f | Maximum hash-based security |

### Size Comparison

| Algorithm | Public Key | Signature | Security Level |
|-----------|-----------|-----------|----------------|
| ML-DSA-44 | 1.3 KB | 2.4 KB | NIST Level 2 |
| ML-DSA-65 | 2.0 KB | 3.3 KB | NIST Level 3 |
| ML-DSA-87 | 2.6 KB | 4.6 KB | NIST Level 5 |
| ECDSA P-256 (legacy) | 64 B | 64 B | ~Level 1 (quantum-vulnerable) |

---

## Current Implementation Capabilities

### What Works Today

1. **Sign firmware files** - Complete files loaded into memory
2. **Multiple algorithms** - ML-DSA and SLH-DSA variants
3. **Password-protected keys** - AES-256-GCM with PBKDF2 (600K iterations)
4. **Certificate metadata** - JSON certificates with subject info
5. **CLI tools** - `keygen` and `sign` commands

### Signing Workflow

```
+------------------+     +------------------+     +------------------+
|  Firmware Build  | --> |  Sign Firmware   | --> | Distribute       |
|  (firmware.bin)  |     |  (create .sig)   |     | (bin + sig + pk) |
+------------------+     +------------------+     +------------------+
                                                          |
                                                          v
+------------------+     +------------------+     +------------------+
|  Device Boot     | <-- |  Verify Sig      | <-- | Receive Update   |
|  (if valid)      |     |  (check .sig)    |     | (bin + sig)      |
+------------------+     +------------------+     +------------------+
```

---

## Step-by-Step Guide

### 1. Generate Signing Keys

Create a dedicated firmware signing key pair with certificate metadata:

```bash
# Generate ML-DSA-65 key pair with certificate info
make keygen-cpp ALG=mldsa65 OUT=firmware-signer \
    CN="Firmware Signing Key" \
    ORG="Your Company" \
    OU="Security Team" \
    COUNTRY=US \
    DAYS=1825 \
    PASSWORD=your-secure-password

# Output files:
#   keys/firmware-signer_public.key      - Embed in bootloader
#   keys/firmware-signer_secret.key      - Keep secure (encrypted)
#   keys/firmware-signer_certificate.json - Metadata
```

### 2. Sign Firmware

Sign the firmware binary with the secret key:

```bash
# Sign firmware file
make sign-cpp ALG=mldsa65 \
    SK=keys/firmware-signer_secret.key \
    MSG=build/firmware.bin \
    OUT=build/firmware.sig \
    FORMAT=binary \
    PASSWORD=your-secure-password
```

### 3. Create Firmware Package

Bundle the firmware with its signature for distribution:

```bash
# Create distribution package
mkdir -p dist/
cp build/firmware.bin dist/
cp build/firmware.sig dist/

# Create the package (NO public key - it's embedded in device!)
tar -czf firmware-v1.0.0.tar.gz -C dist .
```

> **IMPORTANT: Do NOT distribute the public key with firmware updates!**
>
> The public key must be:
> - Embedded in the device during manufacturing
> - Stored in protected memory (OTP, locked flash, secure enclave)
> - Never updateable via firmware updates
>
> If you include the public key in the update package, an attacker can
> simply replace it with their own key and sign malicious firmware.

### 3b. Verify Signature (Testing/Development)

Use the `verify` tool to test signatures before distribution:

```bash
# Verify the firmware signature
./build/verify mldsa65 keys/firmware-signer_public.key \
    dist/firmware.bin dist/firmware.sig

# Expected output: VALID
```

### 4. Verify on Device (Pseudocode)

The bootloader must verify the signature before applying the update:

```c
// Bootloader verification (pseudocode)
#include "mldsa.h"

bool verify_firmware_update(
    const uint8_t* firmware, size_t firmware_len,
    const uint8_t* signature, size_t sig_len,
    const uint8_t* public_key, size_t pk_len
) {
    // Initialize ML-DSA-65 verifier
    MLDSA65 verifier;

    // Verify signature
    bool valid = verifier.verify(
        public_key, pk_len,
        firmware, firmware_len,
        signature, sig_len
    );

    if (!valid) {
        log_error("Firmware signature verification failed!");
        return false;
    }

    log_info("Firmware signature valid, proceeding with update");
    return true;
}

void firmware_update_handler(void) {
    // 1. Receive firmware and signature
    // 2. Verify signature against embedded public key
    // 3. Only flash if signature is valid
    // 4. Reboot into new firmware
}
```

---

## Production Deployment Considerations

### Key Management

| Practice | Description |
|----------|-------------|
| **Offline signing** | Keep signing keys on air-gapped systems |
| **HSM storage** | Use Hardware Security Modules for key protection |
| **Key rotation** | Plan for key expiration and rotation |
| **Backup keys** | Secure backup with split custody |
| **Revocation list** | Maintain list of compromised key fingerprints |

### Firmware Manifest

For production, include a signed manifest with metadata:

```json
{
  "version": "1.0.0",
  "build": "2025-01-11T10:30:00Z",
  "target": "device-model-x",
  "minBootloaderVersion": "2.0.0",
  "sha256": "a1b2c3d4e5f6...",
  "size": 1048576,
  "algorithm": "ML-DSA-65",
  "signature": "base64-encoded-signature..."
}
```

### Secure Boot Chain

```
+----------------+     +----------------+     +----------------+
| ROM Bootloader | --> | Stage 1 Boot   | --> | Stage 2 Boot   |
| (immutable)    |     | (signed)       |     | (signed)       |
+----------------+     +----------------+     +----------------+
       |                      |                      |
       v                      v                      v
  Root of Trust         Verify Stage 2        Verify Firmware
  (embedded PK)         before loading        before running
```

---

## Gap Analysis and Roadmap

### Implemented Features

| Feature | Status | Tool |
|---------|--------|------|
| **Key generation** | Done | `keygen` |
| **Firmware signing** | Done | `sign` |
| **Signature verification** | Done | `verify` |
| **Password-protected keys** | Done | AES-256-GCM |
| **Certificate metadata** | Done | JSON format |

### Current Gaps

| Gap | Impact | Priority |
|-----|--------|----------|
| **No firmware encryption** | Firmware readable by anyone | Medium |
| **No streaming API** | Large firmware must fit in RAM | Medium |
| **No pre-hash mode** | Less efficient for large files | Medium |
| **No manifest format** | No standard metadata structure | Medium |
| **No bootloader example** | Integration guidance missing | Low |

### Verify Tool Usage

The `verify` tool is now available:

```bash
# Verify a firmware signature
./build/verify mldsa65 public.key firmware.bin firmware.sig

# Output on success (exit code 0):
VALID

# Output on failure (exit code 1):
INVALID

# Quiet mode for scripts
./build/verify mldsa65 public.key firmware.bin firmware.sig --quiet && echo "OK"

# Support for hex/base64 encoded signatures
./build/verify mldsa65 public.key firmware.bin signature.hex --format hex
./build/verify mldsa65 public.key firmware.bin signature.b64 --format base64
```

### Implementation Roadmap

#### Phase 1: Firmware Encryption (If Confidentiality Needed)

If you need to protect firmware from reverse engineering, encryption is separate from signing:

```
SIGN THEN ENCRYPT (Recommended):
  1. firmware.bin
  2. Sign: firmware.bin → firmware.sig
  3. Encrypt: firmware.bin → firmware.bin.enc
  4. Distribute: firmware.bin.enc + firmware.sig

ON DEVICE:
  1. Decrypt: firmware.bin.enc → firmware.bin
  2. Verify: firmware.bin + firmware.sig → VALID?
  3. Flash if valid
```

> **Note:** ML-KEM (FIPS 203) in this library can be used to establish
> a shared secret for firmware encryption, but the encryption itself
> would use a symmetric cipher like AES-256-GCM.

#### Phase 2: Firmware Manifest Support

Define a standard manifest format and signing:

```cpp
struct FirmwareManifest {
    std::string version;
    std::string target_device;
    std::string min_bootloader;
    std::vector<uint8_t> firmware_hash;  // SHA-256
    size_t firmware_size;
    std::string build_timestamp;
};

// Sign manifest + firmware together
std::vector<uint8_t> sign_firmware_package(
    const FirmwareManifest& manifest,
    const std::vector<uint8_t>& firmware,
    const std::vector<uint8_t>& secret_key
);
```

#### Phase 3: Pre-Hash Mode (HashML-DSA)

For large firmware, hash first then sign:

```cpp
// Current: signs message directly (internal hashing)
auto sig = dsa.sign(sk, large_firmware);

// Proposed: external pre-hash for large files
auto hash = sha256(large_firmware);  // Can be streamed
auto sig = dsa.sign_prehash(sk, hash);  // Signs 32-byte hash
```

Benefits:
- Firmware can be streamed through SHA-256
- Only 32 bytes passed to signing function
- Reduces memory requirements

#### Phase 4: Streaming Verification

For bootloaders with limited RAM:

```cpp
class StreamingVerifier {
public:
    void init(const std::vector<uint8_t>& public_key);
    void update(std::span<const uint8_t> chunk);
    bool finalize(const std::vector<uint8_t>& signature);
};

// Usage in bootloader
StreamingVerifier verifier;
verifier.init(embedded_public_key);

while (has_more_chunks()) {
    auto chunk = read_next_chunk(4096);
    verifier.update(chunk);
}

bool valid = verifier.finalize(signature);
```

---

## Security Best Practices

### DO

- Generate keys on secure, offline systems (air-gapped)
- Use HSM (Hardware Security Module) for production signing keys
- Use password protection for stored keys (development)
- Embed public key in **hardware-protected** storage (OTP, locked flash)
- Implement Hardware Root of Trust for production devices
- Verify signatures before ANY firmware execution
- Implement anti-rollback protection (version counters)
- Log all signature verification attempts
- Use ML-DSA-65 or higher for new deployments
- Plan for algorithm agility (support multiple algorithms)
- Disable debug interfaces (JTAG/SWD) in production

### DON'T

- Store signing keys on build servers
- Transmit signing keys over networks
- Include public key in firmware update packages
- Store public key in updateable flash (without hardware protection)
- Use the same key for multiple product lines
- Skip verification for "trusted" sources
- Ignore verification failures
- Use legacy algorithms (RSA, ECDSA) for new products
- Rely on software-only protection for production devices
- Leave debug interfaces enabled in production

---

## Example: Complete Firmware Signing Script

```bash
#!/bin/bash
# firmware-sign.sh - Sign firmware for distribution
#
# SECURITY NOTE: This script is for the BUILD/SIGNING server.
# The public key should NEVER be distributed with firmware updates.
# It must be embedded in devices during manufacturing.

set -e

FIRMWARE=$1
VERSION=$2
ALG=${3:-mldsa65}
KEY_DIR=${KEY_DIR:-./keys}
OUTPUT_DIR=${OUTPUT_DIR:-./dist}

if [ -z "$FIRMWARE" ] || [ -z "$VERSION" ]; then
    echo "Usage: $0 <firmware.bin> <version> [algorithm]"
    echo ""
    echo "Environment variables:"
    echo "  SIGNING_PASSWORD  - Password for encrypted signing key"
    echo "  KEY_DIR           - Directory containing keys (default: ./keys)"
    echo "  OUTPUT_DIR        - Output directory (default: ./dist)"
    exit 1
fi

# Check firmware exists
if [ ! -f "$FIRMWARE" ]; then
    echo "Error: Firmware file not found: $FIRMWARE"
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Calculate firmware hash
HASH=$(sha256sum "$FIRMWARE" | cut -d' ' -f1)
SIZE=$(stat -f%z "$FIRMWARE" 2>/dev/null || stat -c%s "$FIRMWARE")

echo "Signing firmware..."
echo "  File: $FIRMWARE"
echo "  Size: $SIZE bytes"
echo "  SHA256: $HASH"
echo "  Algorithm: $ALG"

# Sign the firmware
./build/sign $ALG "$KEY_DIR/firmware-signer_secret.key" "$FIRMWARE" \
    --output "$OUTPUT_DIR/firmware-$VERSION.sig" \
    --format binary \
    --password "${SIGNING_PASSWORD}"

# Create manifest (signature is in separate file)
cat > "$OUTPUT_DIR/firmware-$VERSION.json" << EOF
{
  "version": "$VERSION",
  "filename": "firmware-$VERSION.bin",
  "size": $SIZE,
  "sha256": "$HASH",
  "algorithm": "$ALG",
  "signed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "signature_file": "firmware-$VERSION.sig",
  "public_key_fingerprint": "$(sha256sum $KEY_DIR/firmware-signer_public.key | cut -d' ' -f1)"
}
EOF

# Copy firmware (NOT the public key!)
cp "$FIRMWARE" "$OUTPUT_DIR/firmware-$VERSION.bin"

echo ""
echo "Firmware package created:"
ls -la "$OUTPUT_DIR"/firmware-$VERSION.*

echo ""
echo "IMPORTANT: Do NOT distribute the public key with this package!"
echo "The public key must be embedded in devices during manufacturing."
echo ""
echo "To verify (for testing only):"
echo "  ./build/verify $ALG $KEY_DIR/firmware-signer_public.key \\"
echo "      $OUTPUT_DIR/firmware-$VERSION.bin \\"
echo "      $OUTPUT_DIR/firmware-$VERSION.sig"

# Verify the signature before release
echo ""
echo "Verifying signature before release..."
./build/verify $ALG "$KEY_DIR/firmware-signer_public.key" \
    "$OUTPUT_DIR/firmware-$VERSION.bin" \
    "$OUTPUT_DIR/firmware-$VERSION.sig"

echo ""
echo "Firmware signed and verified successfully!"
```

---

## Summary: Security Checklist

Before deploying firmware signing in production, ensure:

- [ ] Hardware Root of Trust implemented (Boot ROM, OTP, locked flash)
- [ ] Public key stored in hardware-protected memory
- [ ] Debug interfaces disabled or authenticated
- [ ] Anti-rollback mechanism in place
- [ ] Signing keys stored in HSM (not on build servers)
- [ ] Key ceremony performed for production keys
- [ ] Firmware update packages do NOT contain public key
- [ ] Verification failure handling tested
- [ ] Recovery mechanism for bricked devices planned

---

## References

### Post-Quantum Cryptography Standards
- [NIST FIPS 203 - ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 - ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 - SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [NIST Post-Quantum Cryptography Project](https://csrc.nist.gov/projects/post-quantum-cryptography)

### Hardware Security & Secure Boot
- [ARM Platform Security Architecture](https://www.arm.com/architecture/security-features/platform-security)
- [UEFI Specifications](https://uefi.org/specifications)
- [TCG TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/)
- [NIST SP 800-193 Platform Firmware Resiliency Guidelines](https://csrc.nist.gov/publications/detail/sp/800-193/final)

### Vendor Secure Boot Documentation
- [ESP32 Secure Boot V2](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/security/secure-boot-v2.html)

> **Note:** For other platforms (STM32, Nordic nRF, NXP i.MX, etc.), refer to the
> vendor's official documentation portal as URLs change frequently.
