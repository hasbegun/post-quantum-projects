# Post-Quantum Firmware Signing

Sign and verify firmware images for secure boot and OTA updates using post-quantum cryptographic signatures.

## Overview

This example demonstrates firmware signing for IoT devices and embedded systems with:

- **Secure Boot**: Verify firmware authenticity before execution
- **OTA Updates**: Sign firmware updates for over-the-air deployment
- **Rollback Protection**: Prevent installation of older vulnerable firmware
- **Device Compatibility**: Ensure firmware matches target hardware

### Features

| Feature | Description |
|---------|-------------|
| Post-Quantum Signatures | ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) |
| Dual Hashing | SHA-256 and SHA-512 for redundancy |
| Version Codes | Numeric version for rollback protection |
| Device Binding | Device type and model compatibility checks |
| Signed Manifests | JSON manifest with all verification data |

### Algorithm Recommendations

| Use Case | Algorithm | Rationale |
|----------|-----------|-----------|
| Constrained devices | **ML-DSA-44** | Smallest signatures, fast verification |
| General IoT | **ML-DSA-65** | Balanced security/performance |
| Critical infrastructure | **ML-DSA-87** | Maximum security |
| Long-term (10+ years) | **SLH-DSA-SHAKE-256f** | Conservative, hash-based |

## Quick Start (Docker)

### 1. Generate Signing Keys

```bash
# From project root
make keygen-cpp ALG=mldsa65 OUT=firmware-signing \
    CN="Firmware Signing Key" ORG="IoT Corp"
```

### 2. Sign Firmware

```bash
docker run --rm \
  -v $(pwd)/keys:/keys:ro \
  -v $(pwd):/work \
  -w /work \
  dsa-py python examples/use-cases/firmware-signing/sign_firmware.py \
    --key /keys/firmware-signing_secret.key \
    --firmware build/firmware.bin \
    --version 2.1.0 \
    --device-type "Smart-Sensor-v2"
```

Output: `build/firmware.bin.fwsig`

### 3. Verify Firmware

```bash
docker run --rm \
  -v $(pwd)/keys:/keys:ro \
  -v $(pwd):/work \
  -w /work \
  dsa-py python examples/use-cases/firmware-signing/verify_firmware.py \
    --key /keys/firmware-signing_public.key \
    --firmware build/firmware.bin
```

## Shell Script Usage

For convenience, shell script wrappers are provided that handle Docker execution:

### Sign Firmware

```bash
./sign.sh --key keys/fw_secret.key --firmware build/firmware.bin \
    --version 2.1.0 --device-type "IoT-Sensor"
```

### Verify Firmware

```bash
./verify.sh --key keys/fw_public.key --firmware build/firmware.bin
```

With rollback protection:

```bash
./verify.sh --key keys/fw_public.key --firmware update.bin \
    --current-version 2000000
```

## C++ Usage

C++ implementations are available for direct integration:

### Build the Tools

```bash
# From project root
mkdir -p build && cd build
cmake .. -DBUILD_EXAMPLES=ON
make sign_firmware verify_firmware
```

### Sign with C++

```bash
./build/sign_firmware keys/fw_secret.key firmware.bin \
    -v 2.1.0 --device-type "IoT-Sensor" \
    --hardware-rev "rev-c" --build-id "build-12345"
```

### Verify with C++

```bash
# Basic verification
./build/verify_firmware keys/fw_public.key firmware.bin

# With rollback protection
./build/verify_firmware keys/fw_public.key firmware.bin \
    --current-version 2000000 --device-type "IoT-Sensor"
```

## Detailed Usage

### Python Signing Options

```bash
python sign_firmware.py [OPTIONS]

Required:
  --key, -k PATH         Secret key file
  --firmware, -f PATH    Firmware binary to sign
  --version, -v VER      Firmware version (e.g., 2.1.0)
  --device-type TYPE     Device type identifier

Optional:
  --algorithm, -a ALG    Signing algorithm (auto-detected)
  --output, -o PATH      Output manifest (default: <firmware>.fwsig)
  --hardware-rev REV     Hardware revision
  --build-id ID          Build identifier
  --build-date DATE      Build date (ISO format)
  --description DESC     Firmware description
  --min-bootloader VER   Minimum bootloader version
  --compatible MODEL     Compatible device model (repeatable)
```

### Verification Options

```bash
python verify_firmware.py [OPTIONS]

Required:
  --key, -k PATH         Public key file
  --firmware, -f PATH    Firmware to verify

Optional:
  --manifest, -m PATH    Manifest file (default: <firmware>.fwsig)
  --current-version CODE Current version code for rollback check
  --device-type TYPE     Device type for compatibility
  --device-model MODEL   Device model for compatibility
  --quiet, -q            Exit code only
  --json                 JSON output
```

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Verification successful - safe to install |
| 1 | Signature or integrity verification failed |
| 2 | Input error (file not found) |
| 3 | Rollback protection triggered |
| 4 | Device compatibility error |

## Manifest Format

The `.fwsig` manifest file contains:

```json
{
  "manifest_version": "1.0",
  "type": "firmware-signature",
  "algorithm": {
    "id": "mldsa65",
    "name": "ML-DSA-65",
    "security_level": "NIST Level 3",
    "standard": "FIPS 204"
  },
  "firmware": {
    "name": "firmware.bin",
    "size": 524288,
    "hashes": {
      "sha256": "abc123...",
      "sha512": "def456..."
    }
  },
  "metadata": {
    "version": "2.1.0",
    "version_code": 2001000,
    "device_type": "Smart-Sensor-v2",
    "hardware_rev": "rev-c",
    "build_date": "2024-01-15",
    "build_id": "build-20240115143022",
    "description": "Security update",
    "min_bootloader_version": "1.0.0",
    "compatibility": ["Model-A", "Model-B"]
  },
  "signature": {
    "value": "...",
    "encoding": "hex",
    "context": "6669726d77617265"
  },
  "timestamp": "2024-01-15T14:30:22+00:00",
  "signer": {
    "name": "Firmware Signing Key",
    "organization": "IoT Corp"
  },
  "security": {
    "rollback_protection": true,
    "minimum_version_code": 2001000
  }
}
```

## Integration Examples

### Secure Boot Verification (C/Embedded)

```c
// Pseudo-code for embedded secure boot
int verify_and_boot(const uint8_t* firmware, size_t size,
                    const uint8_t* manifest, size_t manifest_size) {
    // 1. Parse manifest
    firmware_manifest_t m;
    if (parse_manifest(manifest, manifest_size, &m) != 0) {
        return BOOT_ERR_INVALID_MANIFEST;
    }

    // 2. Check firmware hash
    uint8_t hash[32];
    sha256(firmware, size, hash);
    if (memcmp(hash, m.firmware_hash, 32) != 0) {
        return BOOT_ERR_HASH_MISMATCH;
    }

    // 3. Verify signature (using PQC library)
    if (!mldsa_verify(public_key, m.signed_data, m.signature)) {
        return BOOT_ERR_SIGNATURE_INVALID;
    }

    // 4. Check rollback protection
    if (m.version_code < get_current_version_code()) {
        return BOOT_ERR_ROLLBACK;
    }

    // 5. Boot the firmware
    jump_to_firmware(firmware);
    return BOOT_OK;
}
```

### OTA Update Service (Python)

```python
from flask import Flask, request, jsonify
import subprocess

app = Flask(__name__)

@app.route('/api/firmware/verify', methods=['POST'])
def verify_firmware():
    """API endpoint to verify firmware before deployment."""
    firmware_path = request.json['firmware_path']
    manifest_path = request.json['manifest_path']

    result = subprocess.run([
        'python', 'verify_firmware.py',
        '--key', '/keys/firmware_public.key',
        '--firmware', firmware_path,
        '--manifest', manifest_path,
        '--json'
    ], capture_output=True, text=True)

    return jsonify(json.loads(result.stdout))

@app.route('/api/firmware/deploy', methods=['POST'])
def deploy_firmware():
    """Deploy verified firmware to devices."""
    # First verify
    verify_result = verify_firmware()
    if not verify_result.json['valid']:
        return jsonify({'error': 'Verification failed'}), 400

    # Then deploy...
    return jsonify({'status': 'deploying'})
```

### CI/CD Pipeline (GitHub Actions)

```yaml
name: Build and Sign Firmware

on:
  push:
    tags:
      - 'v*'

jobs:
  build-and-sign:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build firmware
        run: make firmware

      - name: Extract version from tag
        id: version
        run: echo "version=${GITHUB_REF#refs/tags/v}" >> $GITHUB_OUTPUT

      - name: Sign firmware
        run: |
          docker run --rm \
            -v ${{ github.workspace }}:/work \
            -w /work \
            dsa-py python examples/use-cases/firmware-signing/sign_firmware.py \
              --key /work/keys/firmware_secret.key \
              --firmware /work/build/firmware.bin \
              --version ${{ steps.version.outputs.version }} \
              --device-type "Production-Device" \
              --build-id "${{ github.sha }}"

      - name: Upload artifacts
        uses: actions/upload-artifact@v4
        with:
          name: firmware-signed
          path: |
            build/firmware.bin
            build/firmware.bin.fwsig
```

## Security Best Practices

### Key Management

1. **Hardware Security Module (HSM)**: Store signing keys in HSM for production
2. **Key Rotation**: Rotate signing keys annually
3. **Separate Keys**: Use different keys for development and production
4. **Audit Logging**: Log all signing operations

### Rollback Protection

```bash
# When verifying, always provide current version
python verify_firmware.py \
    --key public.key \
    --firmware new_firmware.bin \
    --current-version 2000000  # Current installed version code

# Version code format: MAJOR*1000000 + MINOR*1000 + PATCH
# 2.0.0 = 2000000
# 2.1.5 = 2001005
```

### Device Binding

```bash
# Sign for specific device types
python sign_firmware.py \
    --key key.key \
    --firmware firmware.bin \
    --version 1.0.0 \
    --device-type "Sensor-Pro" \
    --compatible "Model-X" \
    --compatible "Model-Y"

# Verify on device
python verify_firmware.py \
    --key public.key \
    --firmware firmware.bin \
    --device-type "Sensor-Pro" \
    --device-model "Model-X"
```

## Testing

Run the test suite:

```bash
make test-examples-firmware-signing
```

## Related Examples

- [Code Signing](../code-signing/) - Sign software releases
- [Document Signing](../document-signing/) - Sign documents with timestamps
- [API Request Signing](../api-signing/) - Authenticate API requests
