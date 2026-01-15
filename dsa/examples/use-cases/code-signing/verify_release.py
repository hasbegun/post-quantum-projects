#!/usr/bin/env python3
"""
Post-Quantum Code Signature Verification Tool

Verify software release signatures created by sign_release.py.

This tool verifies:
- Cryptographic signature validity
- File hash matches
- File size matches
- Signature metadata integrity

Usage:
    python verify_release.py --key public.key --file release.tar.gz --signature release.tar.gz.sig

Exit codes:
    0 - Signature valid
    1 - Signature invalid or verification failed
    2 - Input error (file not found, etc.)
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# Try to import from installed package first, fall back to source path
try:
    from mldsa import MLDSA44, MLDSA65, MLDSA87
    from slhdsa import (
        SLHDSA_SHAKE_128f, SLHDSA_SHAKE_128s,
        SLHDSA_SHAKE_192f, SLHDSA_SHAKE_256f,
    )
except ImportError:
    # Add parent directories to path for imports (development mode)
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
    """Raised when file integrity check fails."""
    pass


def compute_file_hash(filepath: Path, algorithm: str = "sha256") -> str:
    """Compute cryptographic hash of a file."""
    h = hashlib.new(algorithm)
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_public_key(key_path: Path) -> bytes:
    """Load public key from file."""
    key_data = key_path.read_bytes()

    # Check for JSON format
    if key_data.startswith(b'{'):
        key_json = json.loads(key_data)
        key_hex = key_json.get("key", key_json.get("public_key", ""))
        return bytes.fromhex(key_hex)

    # Raw binary key
    return key_data


def load_signature(sig_path: Path) -> dict:
    """Load and parse signature file."""
    try:
        with open(sig_path, "r") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid signature file format: {e}")


def verify_file_integrity(filepath: Path, sig_doc: dict) -> None:
    """
    Verify file integrity against signature metadata.

    Raises:
        IntegrityError: If file doesn't match signature metadata
    """
    file_info = sig_doc.get("file", {})

    # Check file exists
    if not filepath.exists():
        raise IntegrityError(f"File not found: {filepath}")

    # Check file size
    expected_size = file_info.get("size")
    actual_size = filepath.stat().st_size
    if expected_size is not None and actual_size != expected_size:
        raise IntegrityError(
            f"File size mismatch: expected {expected_size}, got {actual_size}"
        )

    # Check file hash
    hash_info = file_info.get("hash", {})
    hash_algo = hash_info.get("algorithm", "sha256")
    expected_hash = hash_info.get("value")

    if expected_hash:
        actual_hash = compute_file_hash(filepath, hash_algo)
        if actual_hash != expected_hash:
            raise IntegrityError(
                f"File hash mismatch:\n"
                f"  Expected: {expected_hash}\n"
                f"  Got:      {actual_hash}"
            )


def verify_signature(
    filepath: Path,
    sig_doc: dict,
    public_key: bytes,
) -> dict:
    """
    Verify cryptographic signature.

    Args:
        filepath: Path to signed file
        sig_doc: Parsed signature document
        public_key: Public verification key

    Returns:
        Dictionary with verification details

    Raises:
        VerificationError: If signature is invalid
    """
    # Get algorithm
    algo_info = sig_doc.get("algorithm", {})
    algorithm = algo_info.get("id")

    if algorithm not in ALGORITHMS:
        raise VerificationError(f"Unsupported algorithm: {algorithm}")

    # Get signature bytes
    sig_info = sig_doc.get("signature", {})
    sig_hex = sig_info.get("value", "")
    sig_encoding = sig_info.get("encoding", "hex")

    if sig_encoding == "hex":
        signature = bytes.fromhex(sig_hex)
    elif sig_encoding == "base64":
        import base64
        signature = base64.b64decode(sig_hex)
    else:
        raise VerificationError(f"Unsupported signature encoding: {sig_encoding}")

    # Get context
    context_hex = sig_info.get("context", "")
    context = bytes.fromhex(context_hex) if context_hex else b""

    # Reconstruct the signed message
    file_info = sig_doc.get("file", {})
    hash_info = file_info.get("hash", {})

    sign_message = json.dumps({
        "file_hash": hash_info.get("value"),
        "file_name": file_info.get("name"),
        "file_size": file_info.get("size"),
        "timestamp": sig_doc.get("timestamp"),
    }, sort_keys=True).encode("utf-8")

    # Initialize verifier
    verifier = ALGORITHMS[algorithm]["class"]()

    # Verify signature
    try:
        if algorithm.startswith("mldsa"):
            is_valid = verifier.verify(public_key, sign_message, signature, ctx=context)
        else:
            is_valid = verifier.verify(public_key, sign_message, signature, ctx=context)
    except Exception as e:
        raise VerificationError(f"Signature verification error: {e}")

    if not is_valid:
        raise VerificationError("Signature verification failed: invalid signature")

    return {
        "algorithm": algo_info.get("name"),
        "security_level": algo_info.get("security_level"),
        "signer": sig_doc.get("signer", {}),
        "timestamp": sig_doc.get("timestamp"),
    }


def format_timestamp(iso_timestamp: str) -> str:
    """Format ISO timestamp for display."""
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, AttributeError):
        return iso_timestamp or "Unknown"


def main():
    parser = argparse.ArgumentParser(
        description="Verify post-quantum code signatures",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Verify a signed release
  python verify_release.py --key mykey_public.key --file release-1.0.tar.gz

  # Verify with explicit signature file
  python verify_release.py --key mykey_public.key --file app.exe --signature app.exe.pqsig

  # Quiet mode (exit code only)
  python verify_release.py --key mykey_public.key --file release.tar.gz --quiet

Exit codes:
  0 - Signature valid
  1 - Signature invalid
  2 - Input error
        """,
    )

    parser.add_argument(
        "--key", "-k",
        required=True,
        type=Path,
        help="Path to public key file",
    )
    parser.add_argument(
        "--file", "-f",
        required=True,
        type=Path,
        help="Path to file to verify",
    )
    parser.add_argument(
        "--signature", "-s",
        type=Path,
        help="Path to signature file (default: <file>.sig)",
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

    if not args.file.exists():
        if not args.quiet:
            print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(2)

    sig_path = args.signature or args.file.with_suffix(args.file.suffix + ".sig")
    if not sig_path.exists():
        if not args.quiet:
            print(f"Error: Signature file not found: {sig_path}", file=sys.stderr)
        sys.exit(2)

    # Load inputs
    try:
        public_key = load_public_key(args.key)
        sig_doc = load_signature(sig_path)
    except Exception as e:
        if not args.quiet:
            print(f"Error loading inputs: {e}", file=sys.stderr)
        sys.exit(2)

    # Verify file integrity
    try:
        verify_file_integrity(args.file, sig_doc)
    except IntegrityError as e:
        if args.json:
            print(json.dumps({
                "valid": False,
                "error": "integrity",
                "message": str(e),
            }, indent=2))
        elif not args.quiet:
            print(f"\n[FAILED] File integrity check failed", file=sys.stderr)
            print(f"  {e}", file=sys.stderr)
        sys.exit(1)

    # Verify cryptographic signature
    try:
        result = verify_signature(args.file, sig_doc, public_key)
    except VerificationError as e:
        if args.json:
            print(json.dumps({
                "valid": False,
                "error": "signature",
                "message": str(e),
            }, indent=2))
        elif not args.quiet:
            print(f"\n[FAILED] Signature verification failed", file=sys.stderr)
            print(f"  {e}", file=sys.stderr)
        sys.exit(1)

    # Success
    if args.json:
        print(json.dumps({
            "valid": True,
            "file": str(args.file),
            "algorithm": result["algorithm"],
            "security_level": result["security_level"],
            "signer": result["signer"],
            "timestamp": result["timestamp"],
        }, indent=2))
    elif not args.quiet:
        print(f"\n[OK] Signature verification successful!")
        print(f"")
        print(f"  File:           {args.file}")
        print(f"  Hash:           {sig_doc['file']['hash']['value'][:16]}...")
        print(f"  Algorithm:      {result['algorithm']}")
        print(f"  Security Level: {result['security_level']}")
        print(f"  Signed:         {format_timestamp(result['timestamp'])}")
        if result.get("signer"):
            signer = result["signer"]
            if signer.get("common_name"):
                print(f"  Signer:         {signer['common_name']}")
            if signer.get("organization"):
                print(f"  Organization:   {signer['organization']}")

    sys.exit(0)


if __name__ == "__main__":
    main()
