#!/usr/bin/env python3
"""
Post-Quantum Firmware Signing Tool

Sign firmware images using post-quantum digital signatures (ML-DSA or SLH-DSA)
for secure boot and OTA update verification.

Features:
- Firmware version tracking for rollback protection
- Device/hardware compatibility metadata
- Manifest generation for OTA updates
- Support for multiple signature algorithms

Usage:
    python sign_firmware.py --key secret.key --firmware firmware.bin [options]

Output:
    Creates firmware.bin.fwsig (signed firmware manifest)
"""

import argparse
import hashlib
import json
import sys
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, asdict

# Try to import from installed package first, fall back to source path
try:
    from mldsa import MLDSA44, MLDSA65, MLDSA87
    from slhdsa import (
        SLHDSA_SHAKE_128f, SLHDSA_SHAKE_128s,
        SLHDSA_SHAKE_192f, SLHDSA_SHAKE_256f,
    )
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src" / "py"))
    from mldsa import MLDSA44, MLDSA65, MLDSA87
    from slhdsa import (
        SLHDSA_SHAKE_128f, SLHDSA_SHAKE_128s,
        SLHDSA_SHAKE_192f, SLHDSA_SHAKE_256f,
    )


# Supported algorithms
ALGORITHMS = {
    "mldsa44": {"class": MLDSA44, "name": "ML-DSA-44", "security": "NIST Level 2"},
    "mldsa65": {"class": MLDSA65, "name": "ML-DSA-65", "security": "NIST Level 3"},
    "mldsa87": {"class": MLDSA87, "name": "ML-DSA-87", "security": "NIST Level 5"},
    "slh-shake-128f": {"class": SLHDSA_SHAKE_128f, "name": "SLH-DSA-SHAKE-128f", "security": "NIST Level 1"},
    "slh-shake-128s": {"class": SLHDSA_SHAKE_128s, "name": "SLH-DSA-SHAKE-128s", "security": "NIST Level 1"},
    "slh-shake-192f": {"class": SLHDSA_SHAKE_192f, "name": "SLH-DSA-SHAKE-192f", "security": "NIST Level 3"},
    "slh-shake-256f": {"class": SLHDSA_SHAKE_256f, "name": "SLH-DSA-SHAKE-256f", "security": "NIST Level 5"},
}


@dataclass
class FirmwareMetadata:
    """Firmware metadata for signing."""
    version: str
    version_code: int  # Numeric version for rollback protection
    device_type: str
    hardware_rev: str
    build_date: str
    build_id: str
    description: str = ""
    min_bootloader_version: str = ""
    compatibility: list = None  # List of compatible device models

    def __post_init__(self):
        if self.compatibility is None:
            self.compatibility = []


def compute_firmware_hash(filepath: Path) -> dict:
    """
    Compute multiple hashes of firmware image.

    Returns SHA-256 and SHA-512 for redundancy.
    """
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()

    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
            sha512.update(chunk)

    return {
        "sha256": sha256.hexdigest(),
        "sha512": sha512.hexdigest(),
    }


def parse_version(version_str: str) -> int:
    """
    Convert version string to numeric code for rollback protection.

    Supports formats: "1.2.3", "1.2", "1"
    """
    parts = version_str.split(".")
    code = 0
    multipliers = [1000000, 1000, 1]  # Major.Minor.Patch

    for i, part in enumerate(parts[:3]):
        try:
            code += int(part) * multipliers[i]
        except ValueError:
            pass

    return code


def detect_algorithm(key_bytes: bytes) -> str:
    """Detect algorithm from secret key size."""
    key_sizes = {
        2560: "mldsa44",
        4032: "mldsa65",
        4896: "mldsa87",
    }

    size = len(key_bytes)
    if size in key_sizes:
        return key_sizes[size]

    if 64 <= size <= 128:
        return "slh-shake-128f"

    raise ValueError(f"Cannot detect algorithm from key size {size} bytes")


def load_secret_key(key_path: Path, password: Optional[str] = None) -> tuple[bytes, dict]:
    """Load secret key and certificate metadata."""
    key_data = key_path.read_bytes()

    if key_data.startswith(b'{'):
        key_json = json.loads(key_data)
        if "encrypted" in key_json and key_json["encrypted"]:
            if not password:
                raise ValueError("Key is encrypted but no password provided")
            raise NotImplementedError("Encrypted key support requires password decryption")
        key_data = bytes.fromhex(key_json.get("key", key_json.get("secret_key", "")))

    cert_path = key_path.parent / key_path.name.replace("_secret.key", "_certificate.json")
    cert_data = {}
    if cert_path.exists():
        cert_data = json.loads(cert_path.read_text())

    return key_data, cert_data


def sign_firmware(
    filepath: Path,
    secret_key: bytes,
    algorithm: str,
    metadata: FirmwareMetadata,
    signer_info: dict,
    context: bytes = b"firmware",
) -> dict:
    """
    Sign firmware image and generate signed manifest.

    Args:
        filepath: Path to firmware binary
        secret_key: Secret signing key
        algorithm: Algorithm identifier
        metadata: Firmware metadata
        signer_info: Signer identity
        context: Context string for domain separation

    Returns:
        Signed firmware manifest dictionary
    """
    if algorithm not in ALGORITHMS:
        raise ValueError(f"Unknown algorithm: {algorithm}")

    algo_info = ALGORITHMS[algorithm]

    # Compute firmware hashes
    hashes = compute_firmware_hash(filepath)
    file_size = filepath.stat().st_size

    # Generate timestamp
    timestamp = datetime.now(timezone.utc).isoformat()

    # Create the message to sign (canonical JSON)
    sign_data = {
        "firmware": {
            "name": filepath.name,
            "size": file_size,
            "hashes": hashes,
        },
        "metadata": asdict(metadata),
        "timestamp": timestamp,
    }
    sign_message = json.dumps(sign_data, sort_keys=True).encode("utf-8")

    # Sign the message
    signer = algo_info["class"]()
    signature = signer.sign(secret_key, sign_message, ctx=context)

    # Build the complete manifest
    manifest = {
        "manifest_version": "1.0",
        "type": "firmware-signature",
        "algorithm": {
            "id": algorithm,
            "name": algo_info["name"],
            "security_level": algo_info["security"],
            "standard": "FIPS 204" if algorithm.startswith("mldsa") else "FIPS 205",
        },
        "firmware": {
            "name": filepath.name,
            "size": file_size,
            "hashes": hashes,
        },
        "metadata": asdict(metadata),
        "signature": {
            "value": signature.hex(),
            "encoding": "hex",
            "context": context.hex(),
        },
        "timestamp": timestamp,
        "signer": signer_info,
        "security": {
            "rollback_protection": True,
            "minimum_version_code": metadata.version_code,
        },
    }

    return manifest


def main():
    parser = argparse.ArgumentParser(
        description="Sign firmware images with post-quantum signatures",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sign firmware with version info
  python sign_firmware.py --key signing.key --firmware firmware.bin \\
      --version 2.1.0 --device-type "IoT-Sensor-v1"

  # Sign with full metadata
  python sign_firmware.py --key signing.key --firmware update.bin \\
      --version 3.0.0 --device-type "Gateway" --hardware-rev "rev-c" \\
      --build-id "build-12345" --description "Security update"

  # Sign for specific hardware compatibility
  python sign_firmware.py --key signing.key --firmware firmware.bin \\
      --version 1.5.0 --device-type "Sensor" \\
      --compatible "Model-A" --compatible "Model-B"
        """,
    )

    parser.add_argument(
        "--key", "-k",
        required=True,
        type=Path,
        help="Path to secret key file",
    )
    parser.add_argument(
        "--firmware", "-f",
        required=True,
        type=Path,
        help="Path to firmware binary",
    )
    parser.add_argument(
        "--algorithm", "-a",
        choices=list(ALGORITHMS.keys()),
        help="Signing algorithm (auto-detected from key if not specified)",
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        help="Output manifest file (default: <firmware>.fwsig)",
    )

    # Firmware metadata
    parser.add_argument(
        "--version", "-v",
        required=True,
        help="Firmware version (e.g., 2.1.0)",
    )
    parser.add_argument(
        "--device-type",
        required=True,
        help="Device type identifier",
    )
    parser.add_argument(
        "--hardware-rev",
        default="",
        help="Hardware revision (e.g., rev-c)",
    )
    parser.add_argument(
        "--build-id",
        default="",
        help="Build identifier",
    )
    parser.add_argument(
        "--build-date",
        help="Build date (ISO format, defaults to now)",
    )
    parser.add_argument(
        "--description",
        default="",
        help="Firmware description",
    )
    parser.add_argument(
        "--min-bootloader",
        default="",
        help="Minimum bootloader version required",
    )
    parser.add_argument(
        "--compatible",
        action="append",
        default=[],
        help="Compatible device model (can specify multiple)",
    )

    # Signer info
    parser.add_argument(
        "--signer-name",
        help="Signer name",
    )
    parser.add_argument(
        "--signer-org",
        help="Signer organization",
    )

    parser.add_argument(
        "--password", "-p",
        help="Password for encrypted key",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress output except errors",
    )

    args = parser.parse_args()

    # Validate inputs
    if not args.key.exists():
        print(f"Error: Key file not found: {args.key}", file=sys.stderr)
        sys.exit(1)

    if not args.firmware.exists():
        print(f"Error: Firmware file not found: {args.firmware}", file=sys.stderr)
        sys.exit(1)

    # Load key
    try:
        secret_key, cert_data = load_secret_key(args.key, args.password)
    except Exception as e:
        print(f"Error loading key: {e}", file=sys.stderr)
        sys.exit(1)

    # Determine algorithm
    algorithm = args.algorithm
    if not algorithm:
        try:
            algorithm = detect_algorithm(secret_key)
            if not args.quiet:
                print(f"Auto-detected algorithm: {algorithm}")
        except ValueError as e:
            print(f"Error: {e}. Please specify --algorithm", file=sys.stderr)
            sys.exit(1)

    # Build metadata
    build_date = args.build_date or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    metadata = FirmwareMetadata(
        version=args.version,
        version_code=parse_version(args.version),
        device_type=args.device_type,
        hardware_rev=args.hardware_rev,
        build_date=build_date,
        build_id=args.build_id or f"build-{datetime.now().strftime('%Y%m%d%H%M%S')}",
        description=args.description,
        min_bootloader_version=args.min_bootloader,
        compatibility=args.compatible,
    )

    # Build signer info
    signer_info = {}
    if cert_data:
        subject = cert_data.get("subject", {})
        signer_info = {
            "name": args.signer_name or subject.get("common_name", ""),
            "organization": args.signer_org or subject.get("organization", ""),
        }
    else:
        signer_info = {
            "name": args.signer_name or "Unknown",
            "organization": args.signer_org or "",
        }
    signer_info = {k: v for k, v in signer_info.items() if v}

    # Sign the firmware
    try:
        manifest = sign_firmware(
            filepath=args.firmware,
            secret_key=secret_key,
            algorithm=algorithm,
            metadata=metadata,
            signer_info=signer_info,
        )
    except Exception as e:
        print(f"Error signing firmware: {e}", file=sys.stderr)
        sys.exit(1)

    # Write manifest
    output_path = args.output or args.firmware.with_suffix(args.firmware.suffix + ".fwsig")
    try:
        with open(output_path, "w") as f:
            json.dump(manifest, f, indent=2)
    except Exception as e:
        print(f"Error writing manifest: {e}", file=sys.stderr)
        sys.exit(1)

    if not args.quiet:
        print(f"\nFirmware signed successfully!")
        print(f"  Firmware:     {args.firmware}")
        print(f"  Version:      {metadata.version} (code: {metadata.version_code})")
        print(f"  Device Type:  {metadata.device_type}")
        print(f"  SHA-256:      {manifest['firmware']['hashes']['sha256'][:16]}...")
        print(f"  Algorithm:    {manifest['algorithm']['name']}")
        print(f"  Output:       {output_path}")


if __name__ == "__main__":
    main()
