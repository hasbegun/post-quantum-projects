#!/usr/bin/env python3
"""
Post-Quantum Firmware Signature Verification Tool

Verify firmware signatures and check rollback protection.

Features:
- Cryptographic signature verification
- Firmware hash integrity check
- Rollback protection (version checking)
- Device compatibility verification

Usage:
    python verify_firmware.py --key public.key --firmware firmware.bin [options]

Exit codes:
    0 - Signature valid, firmware safe to install
    1 - Verification failed (signature invalid, hash mismatch, etc.)
    2 - Input error (file not found, etc.)
    3 - Rollback protection triggered (firmware version too old)
    4 - Device compatibility error
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# Try to import from installed package first
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
    "mldsa44": {"class": MLDSA44, "name": "ML-DSA-44"},
    "mldsa65": {"class": MLDSA65, "name": "ML-DSA-65"},
    "mldsa87": {"class": MLDSA87, "name": "ML-DSA-87"},
    "slh-shake-128f": {"class": SLHDSA_SHAKE_128f, "name": "SLH-DSA-SHAKE-128f"},
    "slh-shake-128s": {"class": SLHDSA_SHAKE_128s, "name": "SLH-DSA-SHAKE-128s"},
    "slh-shake-192f": {"class": SLHDSA_SHAKE_192f, "name": "SLH-DSA-SHAKE-192f"},
    "slh-shake-256f": {"class": SLHDSA_SHAKE_256f, "name": "SLH-DSA-SHAKE-256f"},
}


class VerificationError(Exception):
    """Raised when signature verification fails."""
    pass


class IntegrityError(Exception):
    """Raised when firmware integrity check fails."""
    pass


class RollbackError(Exception):
    """Raised when rollback protection is triggered."""
    pass


class CompatibilityError(Exception):
    """Raised when device compatibility check fails."""
    pass


def compute_firmware_hash(filepath: Path) -> dict:
    """Compute hashes of firmware image."""
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


def load_public_key(key_path: Path) -> bytes:
    """Load public key from file."""
    key_data = key_path.read_bytes()

    if key_data.startswith(b'{'):
        key_json = json.loads(key_data)
        key_hex = key_json.get("key", key_json.get("public_key", ""))
        return bytes.fromhex(key_hex)

    return key_data


def load_manifest(manifest_path: Path) -> dict:
    """Load and parse firmware manifest."""
    try:
        with open(manifest_path, "r") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid manifest format: {e}")


def verify_firmware_integrity(filepath: Path, manifest: dict) -> None:
    """
    Verify firmware file integrity against manifest.

    Raises:
        IntegrityError: If firmware doesn't match manifest
    """
    if not filepath.exists():
        raise IntegrityError(f"Firmware file not found: {filepath}")

    firmware_info = manifest.get("firmware", {})

    # Check file size
    expected_size = firmware_info.get("size")
    actual_size = filepath.stat().st_size
    if expected_size is not None and actual_size != expected_size:
        raise IntegrityError(
            f"Firmware size mismatch: expected {expected_size}, got {actual_size}"
        )

    # Check hashes
    expected_hashes = firmware_info.get("hashes", {})
    actual_hashes = compute_firmware_hash(filepath)

    # Check SHA-256
    if expected_hashes.get("sha256"):
        if actual_hashes["sha256"] != expected_hashes["sha256"]:
            raise IntegrityError(
                f"SHA-256 hash mismatch:\n"
                f"  Expected: {expected_hashes['sha256']}\n"
                f"  Got:      {actual_hashes['sha256']}"
            )

    # Check SHA-512 if present
    if expected_hashes.get("sha512"):
        if actual_hashes["sha512"] != expected_hashes["sha512"]:
            raise IntegrityError(
                f"SHA-512 hash mismatch:\n"
                f"  Expected: {expected_hashes['sha512']}\n"
                f"  Got:      {actual_hashes['sha512']}"
            )


def verify_signature(
    manifest: dict,
    public_key: bytes,
) -> dict:
    """
    Verify cryptographic signature.

    Returns:
        Verification result details

    Raises:
        VerificationError: If signature is invalid
    """
    algo_info = manifest.get("algorithm", {})
    algorithm = algo_info.get("id")

    if algorithm not in ALGORITHMS:
        raise VerificationError(f"Unsupported algorithm: {algorithm}")

    # Get signature
    sig_info = manifest.get("signature", {})
    sig_hex = sig_info.get("value", "")
    signature = bytes.fromhex(sig_hex)

    context_hex = sig_info.get("context", "")
    context = bytes.fromhex(context_hex) if context_hex else b"firmware"

    # Reconstruct signed data
    sign_data = {
        "firmware": manifest.get("firmware"),
        "metadata": manifest.get("metadata"),
        "timestamp": manifest.get("timestamp"),
    }
    sign_message = json.dumps(sign_data, sort_keys=True).encode("utf-8")

    # Verify
    verifier = ALGORITHMS[algorithm]["class"]()

    try:
        is_valid = verifier.verify(public_key, sign_message, signature, ctx=context)
    except Exception as e:
        raise VerificationError(f"Signature verification error: {e}")

    if not is_valid:
        raise VerificationError("Signature verification failed: invalid signature")

    return {
        "algorithm": algo_info.get("name"),
        "security_level": algo_info.get("security_level"),
        "timestamp": manifest.get("timestamp"),
    }


def check_rollback_protection(
    manifest: dict,
    current_version_code: Optional[int] = None,
) -> None:
    """
    Check rollback protection.

    Args:
        manifest: Firmware manifest
        current_version_code: Currently installed firmware version code

    Raises:
        RollbackError: If firmware is older than current version
    """
    if current_version_code is None:
        return  # Skip check if current version not provided

    metadata = manifest.get("metadata", {})
    new_version_code = metadata.get("version_code", 0)

    if new_version_code < current_version_code:
        raise RollbackError(
            f"Rollback protection: new firmware version code ({new_version_code}) "
            f"is older than current ({current_version_code})"
        )


def check_device_compatibility(
    manifest: dict,
    device_type: Optional[str] = None,
    device_model: Optional[str] = None,
) -> None:
    """
    Check device compatibility.

    Raises:
        CompatibilityError: If firmware is not compatible with device
    """
    metadata = manifest.get("metadata", {})

    # Check device type
    if device_type:
        manifest_device_type = metadata.get("device_type", "")
        if manifest_device_type and manifest_device_type != device_type:
            raise CompatibilityError(
                f"Device type mismatch: firmware is for '{manifest_device_type}', "
                f"but device is '{device_type}'"
            )

    # Check compatibility list
    if device_model:
        compatibility = metadata.get("compatibility", [])
        if compatibility and device_model not in compatibility:
            raise CompatibilityError(
                f"Device model '{device_model}' not in compatibility list: {compatibility}"
            )


def format_timestamp(iso_timestamp: str) -> str:
    """Format ISO timestamp for display."""
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, AttributeError):
        return iso_timestamp or "Unknown"


def main():
    parser = argparse.ArgumentParser(
        description="Verify post-quantum firmware signatures",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic verification
  python verify_firmware.py --key public.key --firmware firmware.bin

  # Verify with rollback protection
  python verify_firmware.py --key public.key --firmware firmware.bin \\
      --current-version 1005000

  # Verify device compatibility
  python verify_firmware.py --key public.key --firmware firmware.bin \\
      --device-type "IoT-Sensor-v1" --device-model "Model-A"

Exit codes:
  0 - Verification successful
  1 - Signature/integrity verification failed
  2 - Input error (file not found)
  3 - Rollback protection triggered
  4 - Device compatibility error
        """,
    )

    parser.add_argument(
        "--key", "-k",
        required=True,
        type=Path,
        help="Path to public key file",
    )
    parser.add_argument(
        "--firmware", "-f",
        required=True,
        type=Path,
        help="Path to firmware binary",
    )
    parser.add_argument(
        "--manifest", "-m",
        type=Path,
        help="Path to manifest file (default: <firmware>.fwsig)",
    )

    # Rollback protection
    parser.add_argument(
        "--current-version",
        type=int,
        help="Current firmware version code for rollback protection",
    )

    # Device compatibility
    parser.add_argument(
        "--device-type",
        help="Device type to check compatibility",
    )
    parser.add_argument(
        "--device-model",
        help="Device model to check compatibility",
    )

    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress output, use exit code only",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output result as JSON",
    )

    args = parser.parse_args()

    # Validate inputs
    if not args.key.exists():
        if not args.quiet:
            print(f"Error: Public key not found: {args.key}", file=sys.stderr)
        sys.exit(2)

    if not args.firmware.exists():
        if not args.quiet:
            print(f"Error: Firmware not found: {args.firmware}", file=sys.stderr)
        sys.exit(2)

    manifest_path = args.manifest or args.firmware.with_suffix(args.firmware.suffix + ".fwsig")
    if not manifest_path.exists():
        if not args.quiet:
            print(f"Error: Manifest not found: {manifest_path}", file=sys.stderr)
        sys.exit(2)

    # Load inputs
    try:
        public_key = load_public_key(args.key)
        manifest = load_manifest(manifest_path)
    except Exception as e:
        if not args.quiet:
            print(f"Error loading inputs: {e}", file=sys.stderr)
        sys.exit(2)

    result = {"valid": False}

    # Step 1: Verify firmware integrity
    try:
        verify_firmware_integrity(args.firmware, manifest)
    except IntegrityError as e:
        if args.json:
            print(json.dumps({"valid": False, "error": "integrity", "message": str(e)}, indent=2))
        elif not args.quiet:
            print(f"\n[FAILED] Firmware integrity check failed", file=sys.stderr)
            print(f"  {e}", file=sys.stderr)
        sys.exit(1)

    # Step 2: Verify cryptographic signature
    try:
        sig_result = verify_signature(manifest, public_key)
    except VerificationError as e:
        if args.json:
            print(json.dumps({"valid": False, "error": "signature", "message": str(e)}, indent=2))
        elif not args.quiet:
            print(f"\n[FAILED] Signature verification failed", file=sys.stderr)
            print(f"  {e}", file=sys.stderr)
        sys.exit(1)

    # Step 3: Check rollback protection
    try:
        check_rollback_protection(manifest, args.current_version)
    except RollbackError as e:
        if args.json:
            print(json.dumps({"valid": False, "error": "rollback", "message": str(e)}, indent=2))
        elif not args.quiet:
            print(f"\n[BLOCKED] Rollback protection triggered", file=sys.stderr)
            print(f"  {e}", file=sys.stderr)
        sys.exit(3)

    # Step 4: Check device compatibility
    try:
        check_device_compatibility(manifest, args.device_type, args.device_model)
    except CompatibilityError as e:
        if args.json:
            print(json.dumps({"valid": False, "error": "compatibility", "message": str(e)}, indent=2))
        elif not args.quiet:
            print(f"\n[BLOCKED] Device compatibility error", file=sys.stderr)
            print(f"  {e}", file=sys.stderr)
        sys.exit(4)

    # Success
    metadata = manifest.get("metadata", {})
    result = {
        "valid": True,
        "firmware": str(args.firmware),
        "version": metadata.get("version"),
        "version_code": metadata.get("version_code"),
        "device_type": metadata.get("device_type"),
        "algorithm": sig_result["algorithm"],
        "security_level": sig_result["security_level"],
        "timestamp": sig_result["timestamp"],
        "signer": manifest.get("signer", {}),
    }

    if args.json:
        print(json.dumps(result, indent=2))
    elif not args.quiet:
        print(f"\n[OK] Firmware verification successful!")
        print(f"")
        print(f"  Firmware:       {args.firmware}")
        print(f"  Version:        {metadata.get('version')} (code: {metadata.get('version_code')})")
        print(f"  Device Type:    {metadata.get('device_type')}")
        print(f"  Algorithm:      {sig_result['algorithm']}")
        print(f"  Security Level: {sig_result['security_level']}")
        print(f"  Signed:         {format_timestamp(sig_result['timestamp'])}")
        if manifest.get("signer", {}).get("name"):
            print(f"  Signer:         {manifest['signer']['name']}")
        print(f"")
        print(f"  Status: SAFE TO INSTALL")

    sys.exit(0)


if __name__ == "__main__":
    main()
