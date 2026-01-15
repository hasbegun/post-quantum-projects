# Post-Quantum Code Signing

Sign and verify software releases using post-quantum digital signatures.

## Overview

This example demonstrates how to sign software releases (binaries, tarballs, packages) with post-quantum cryptographic algorithms that are resistant to attacks from quantum computers.

### Supported Algorithms

| Algorithm | Standard | Security Level | Signature Size | Use Case |
|-----------|----------|----------------|----------------|----------|
| ML-DSA-44 | FIPS 204 | NIST Level 2 | 2,420 bytes | Fast verification, smallest signatures |
| ML-DSA-65 | FIPS 204 | NIST Level 3 | 3,309 bytes | **Recommended** - balanced |
| ML-DSA-87 | FIPS 204 | NIST Level 5 | 4,627 bytes | Maximum security |
| SLH-DSA-SHAKE-128f | FIPS 205 | NIST Level 1 | 17,088 bytes | Hash-based, conservative |
| SLH-DSA-SHAKE-256f | FIPS 205 | NIST Level 5 | 49,856 bytes | Maximum security, hash-based |

### Recommendation

For code signing, we recommend **ML-DSA-65** because:
- NIST Level 3 security (128-bit post-quantum security)
- Fast signing and verification
- Reasonable signature size (3.3 KB)
- Suitable for software distribution

For long-term archival or maximum security, consider **SLH-DSA-SHAKE-256f** (hash-based, conservative assumptions).

## Quick Start (Docker)

### 1. Generate Signing Keys

```bash
# From the project root directory
make keygen-cpp ALG=mldsa65 OUT=release-signing CN="Release Signing Key" ORG="My Organization"
```

This creates:
- `keys/release-signing_public.key` - Public verification key (distribute to users)
- `keys/release-signing_secret.key` - Secret signing key (keep secure!)
- `keys/release-signing_certificate.json` - Key metadata

### 2. Sign a Release

```bash
# Sign a tarball
docker run --rm \
  -v $(pwd)/keys:/keys:ro \
  -v $(pwd):/work \
  -w /work \
  dsa-py python examples/use-cases/code-signing/sign_release.py \
    --key /keys/release-signing_secret.key \
    --file dist/myproject-1.0.0.tar.gz
```

Output: `dist/myproject-1.0.0.tar.gz.sig`

### 3. Verify a Release

```bash
# Verify the signature
docker run --rm \
  -v $(pwd)/keys:/keys:ro \
  -v $(pwd):/work \
  -w /work \
  dsa-py python examples/use-cases/code-signing/verify_release.py \
    --key /keys/release-signing_public.key \
    --file dist/myproject-1.0.0.tar.gz
```

## Shell Script Usage

For convenience, shell script wrappers are provided that handle Docker execution:

### Sign a Release

```bash
./sign.sh --key keys/release_secret.key --file dist/myapp-1.0.0.tar.gz
```

### Verify a Release

```bash
./verify.sh --key keys/release_public.key --file dist/myapp-1.0.0.tar.gz
```

## C++ Usage

C++ implementations are available for direct integration:

### Build the Tools

```bash
# From project root
mkdir -p build && cd build
cmake .. -DBUILD_EXAMPLES=ON
make sign_release verify_release
```

### Sign with C++

```bash
./build/sign_release keys/release_secret.key dist/myapp-1.0.0.tar.gz \
    --signer-name "Release Team" \
    --signer-email "release@example.com"
```

### Verify with C++

```bash
./build/verify_release keys/release_public.key dist/myapp-1.0.0.tar.gz
```

## Detailed Usage

### Python Signing Options

```bash
python sign_release.py [OPTIONS]

Required:
  --key, -k PATH       Secret key file
  --file, -f PATH      File to sign

Optional:
  --algorithm, -a ALG  Signing algorithm (auto-detected from key)
  --output, -o PATH    Output signature file (default: <file>.sig)
  --context, -c STR    Context string for domain separation
  --signer-name STR    Override signer name from certificate
  --signer-email STR   Override signer email
  --quiet, -q          Suppress output
```

### Verification Options

```bash
python verify_release.py [OPTIONS]

Required:
  --key, -k PATH       Public key file
  --file, -f PATH      File to verify

Optional:
  --signature, -s PATH Signature file (default: <file>.sig)
  --quiet, -q          Exit code only, no output
  --json               Output result as JSON
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Signature valid |
| 1 | Signature invalid or verification failed |
| 2 | Input error (file not found, etc.) |

## Signature File Format

The signature file is JSON with the following structure:

```json
{
  "version": "1.0",
  "type": "code-signature",
  "algorithm": {
    "id": "mldsa65",
    "name": "ML-DSA-65",
    "security_level": "NIST Level 3",
    "standard": "FIPS 204"
  },
  "file": {
    "name": "myproject-1.0.0.tar.gz",
    "size": 1234567,
    "hash": {
      "algorithm": "sha256",
      "value": "abc123..."
    }
  },
  "signature": {
    "value": "deadbeef...",
    "encoding": "hex",
    "context": ""
  },
  "timestamp": "2024-01-15T10:30:00+00:00",
  "signer": {
    "common_name": "Release Signing Key",
    "organization": "My Organization"
  }
}
```

## Integration Examples

### CI/CD Pipeline (GitHub Actions)

```yaml
name: Sign Release

on:
  release:
    types: [created]

jobs:
  sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build release
        run: make build-release

      - name: Sign release artifacts
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/work \
            -w /work \
            dsa-py python examples/use-cases/code-signing/sign_release.py \
              --key /work/keys/release_secret.key \
              --file /work/dist/release.tar.gz

      - name: Upload signature
        uses: actions/upload-artifact@v4
        with:
          name: release-signature
          path: dist/release.tar.gz.sig
```

### Makefile Integration

```makefile
SIGN_KEY := keys/release_secret.key
VERIFY_KEY := keys/release_public.key

sign-release: dist/$(PROJECT)-$(VERSION).tar.gz
	docker run --rm \
		-v $(PWD):/work -w /work \
		dsa-py python examples/use-cases/code-signing/sign_release.py \
			--key $(SIGN_KEY) \
			--file $<

verify-release: dist/$(PROJECT)-$(VERSION).tar.gz
	docker run --rm \
		-v $(PWD):/work -w /work \
		dsa-py python examples/use-cases/code-signing/verify_release.py \
			--key $(VERIFY_KEY) \
			--file $<
```

### Shell Script Wrapper

```bash
#!/bin/bash
# verify-download.sh - Verify downloaded software

set -e

FILE="$1"
PUBKEY="$2"

if [ -z "$FILE" ] || [ -z "$PUBKEY" ]; then
    echo "Usage: $0 <file> <public-key>"
    exit 2
fi

# Download signature if not present
if [ ! -f "${FILE}.sig" ]; then
    echo "Downloading signature..."
    curl -sLO "${FILE}.sig"
fi

# Verify
docker run --rm \
    -v "$(dirname "$FILE"):/work:ro" \
    -w /work \
    dsa-py python examples/use-cases/code-signing/verify_release.py \
        --key "$PUBKEY" \
        --file "$(basename "$FILE")" \
        --quiet

if [ $? -eq 0 ]; then
    echo "✓ Signature verified"
else
    echo "✗ Signature verification FAILED"
    exit 1
fi
```

## Security Considerations

### Key Management

1. **Protect secret keys**: Store signing keys securely (HSM, encrypted storage)
2. **Rotate keys periodically**: Generate new keys annually or after suspected compromise
3. **Use separate keys**: Don't reuse keys across different projects/purposes
4. **Backup keys securely**: Encrypted backups in multiple locations

### Context Strings

Use context strings to prevent signature reuse across different purposes:

```bash
# Sign firmware with context
python sign_release.py --key key.key --file firmware.bin --context "firmware-v2"

# Sign application with different context
python sign_release.py --key key.key --file app.exe --context "application-release"
```

### Verification Best Practices

1. **Always verify before execution**: Check signatures before running downloaded software
2. **Pin public keys**: Distribute public keys through secure channels
3. **Check timestamps**: Reject signatures older than expected
4. **Verify file integrity**: The tool checks both hash and signature

## Troubleshooting

### "Algorithm auto-detection failed"

Specify the algorithm explicitly:
```bash
python sign_release.py --key key.key --file release.tar.gz --algorithm mldsa65
```

### "Signature verification failed"

1. Ensure you're using the correct public key (matching the secret key used to sign)
2. Verify the file hasn't been modified after signing
3. Check the signature file hasn't been corrupted

### "File hash mismatch"

The file has been modified since signing. Re-download the file or obtain a new signature.

## Testing

Run the test suite:

```bash
# From project root
docker run --rm \
  -v $(pwd):/work -w /work \
  dsa-py python -m pytest tests/examples/test_code_signing.py -v
```

## Related Examples

- [Firmware Signing](../firmware-signing/) - Sign firmware images with secure boot support
- [Document Signing](../document-signing/) - Sign documents with timestamps
- [API Request Signing](../api-signing/) - Authenticate API requests
