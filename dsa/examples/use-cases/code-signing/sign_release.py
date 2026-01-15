#!/usr/bin/env python3
"""
Post-Quantum Code Signing Tool

Sign software releases (binaries, tarballs, packages) using post-quantum
digital signatures (ML-DSA or SLH-DSA) as specified in FIPS 204/205.

This tool creates detached signatures with metadata including:
- Timestamp (ISO 8601 format)
- Algorithm used
- Signer identity (from certificate)
- File hash (SHA-256)

Usage:
    python sign_release.py --key secret.key --file release.tar.gz [options]

Output:
    Creates release.tar.gz.sig (JSON signature file)
"""

import argparse
import hashlib
import json
import sys
import os
from datetime import datetime, timezone
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
    "mldsa44": {"class": MLDSA44, "name": "ML-DSA-44", "security": "NIST Level 2"},
    "mldsa65": {"class": MLDSA65, "name": "ML-DSA-65", "security": "NIST Level 3"},
    "mldsa87": {"class": MLDSA87, "name": "ML-DSA-87", "security": "NIST Level 5"},
    "slh-shake-128f": {"class": SLHDSA_SHAKE_128f, "name": "SLH-DSA-SHAKE-128f", "security": "NIST Level 1"},
    "slh-shake-128s": {"class": SLHDSA_SHAKE_128s, "name": "SLH-DSA-SHAKE-128s", "security": "NIST Level 1"},
    "slh-shake-192f": {"class": SLHDSA_SHAKE_192f, "name": "SLH-DSA-SHAKE-192f", "security": "NIST Level 3"},
    "slh-shake-256f": {"class": SLHDSA_SHAKE_256f, "name": "SLH-DSA-SHAKE-256f", "security": "NIST Level 5"},
}


def compute_file_hash(filepath: Path, algorithm: str = "sha256") -> str:
    """Compute cryptographic hash of a file."""
    h = hashlib.new(algorithm)
    with open(filepath, "rb") as f:
        # Read in chunks for large files
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_secret_key(key_path: Path, password: Optional[str] = None) -> tuple[bytes, dict]:
    """
    Load secret key and certificate metadata.

    Returns:
        Tuple of (key_bytes, certificate_dict)
    """
    key_data = key_path.read_bytes()

    # Check for encrypted key (JSON format with encryption metadata)
    if key_data.startswith(b'{'):
        key_json = json.loads(key_data)
        if "encrypted" in key_json and key_json["encrypted"]:
            if not password:
                raise ValueError("Key is encrypted but no password provided")
            # Decrypt key (simplified - in production use proper KDF)
            raise NotImplementedError("Encrypted key support requires password decryption")
        key_data = bytes.fromhex(key_json.get("key", key_json.get("secret_key", "")))

    # Load certificate if exists
    cert_path = key_path.parent / key_path.name.replace("_secret.key", "_certificate.json")
    cert_data = {}
    if cert_path.exists():
        cert_data = json.loads(cert_path.read_text())

    return key_data, cert_data


def detect_algorithm(key_bytes: bytes) -> str:
    """Detect algorithm from secret key size."""
    key_sizes = {
        2560: "mldsa44",   # ML-DSA-44 secret key
        4032: "mldsa65",   # ML-DSA-65 secret key
        4896: "mldsa87",   # ML-DSA-87 secret key
    }

    size = len(key_bytes)
    if size in key_sizes:
        return key_sizes[size]

    # SLH-DSA keys are larger, check ranges
    if 64 <= size <= 128:
        # Could be SLH-DSA, need more context
        return "slh-shake-128f"  # Default guess

    raise ValueError(f"Cannot detect algorithm from key size {size} bytes")


def sign_file(
    filepath: Path,
    secret_key: bytes,
    algorithm: str,
    signer_info: dict,
    context: bytes = b"",
) -> dict:
    """
    Sign a file and return signature metadata.

    Args:
        filepath: Path to file to sign
        secret_key: Secret signing key bytes
        algorithm: Algorithm identifier (e.g., "mldsa65")
        signer_info: Dictionary with signer identity information
        context: Optional context string for domain separation

    Returns:
        Dictionary containing signature and metadata
    """
    if algorithm not in ALGORITHMS:
        raise ValueError(f"Unknown algorithm: {algorithm}")

    algo_info = ALGORITHMS[algorithm]

    # Compute file hash
    file_hash = compute_file_hash(filepath)
    file_size = filepath.stat().st_size

    # Generate timestamp once (used in both signed message and metadata)
    timestamp = datetime.now(timezone.utc).isoformat()

    # Create message to sign (hash + metadata for binding)
    # This prevents signature reuse across different files with same hash
    sign_message = json.dumps({
        "file_hash": file_hash,
        "file_name": filepath.name,
        "file_size": file_size,
        "timestamp": timestamp,
    }, sort_keys=True).encode("utf-8")

    # Initialize signer
    signer = algo_info["class"]()

    # Sign the message
    signature = signer.sign(secret_key, sign_message, ctx=context)

    # Build signature document
    sig_doc = {
        "version": "1.0",
        "type": "code-signature",
        "algorithm": {
            "id": algorithm,
            "name": algo_info["name"],
            "security_level": algo_info["security"],
            "standard": "FIPS 204" if algorithm.startswith("mldsa") else "FIPS 205",
        },
        "file": {
            "name": filepath.name,
            "size": file_size,
            "hash": {
                "algorithm": "sha256",
                "value": file_hash,
            },
        },
        "signature": {
            "value": signature.hex(),
            "encoding": "hex",
            "context": context.hex() if context else "",
        },
        "timestamp": timestamp,
        "signer": signer_info,
        "metadata": {
            "tool": "pqc-code-signing",
            "tool_version": "1.0.0",
        },
    }

    return sig_doc


def main():
    parser = argparse.ArgumentParser(
        description="Sign software releases with post-quantum signatures",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sign a release tarball
  python sign_release.py --key mykey_secret.key --file release-1.0.tar.gz

  # Sign with specific algorithm
  python sign_release.py --key mykey_secret.key --file app.exe --algorithm mldsa87

  # Sign with context (domain separation)
  python sign_release.py --key mykey_secret.key --file firmware.bin --context "firmware-v2"

  # Specify output file
  python sign_release.py --key mykey_secret.key --file release.tar.gz --output release.tar.gz.pqsig
        """,
    )

    parser.add_argument(
        "--key", "-k",
        required=True,
        type=Path,
        help="Path to secret key file",
    )
    parser.add_argument(
        "--file", "-f",
        required=True,
        type=Path,
        help="Path to file to sign",
    )
    parser.add_argument(
        "--algorithm", "-a",
        choices=list(ALGORITHMS.keys()),
        help="Signing algorithm (auto-detected from key if not specified)",
    )
    parser.add_argument(
        "--output", "-o",
        type=Path,
        help="Output signature file (default: <file>.sig)",
    )
    parser.add_argument(
        "--context", "-c",
        default="",
        help="Context string for domain separation",
    )
    parser.add_argument(
        "--password", "-p",
        help="Password for encrypted key",
    )
    parser.add_argument(
        "--signer-name",
        help="Signer name (overrides certificate)",
    )
    parser.add_argument(
        "--signer-email",
        help="Signer email (overrides certificate)",
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

    if not args.file.exists():
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    # Load secret key
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

    # Build signer info
    signer_info = {}
    if cert_data:
        subject = cert_data.get("subject", {})
        signer_info = {
            "common_name": args.signer_name or subject.get("common_name", ""),
            "organization": subject.get("organization", ""),
            "email": args.signer_email or subject.get("email", ""),
        }
    else:
        signer_info = {
            "common_name": args.signer_name or "Unknown",
            "email": args.signer_email or "",
        }

    # Remove empty fields
    signer_info = {k: v for k, v in signer_info.items() if v}

    # Sign the file
    try:
        sig_doc = sign_file(
            filepath=args.file,
            secret_key=secret_key,
            algorithm=algorithm,
            signer_info=signer_info,
            context=args.context.encode("utf-8"),
        )
    except Exception as e:
        print(f"Error signing file: {e}", file=sys.stderr)
        sys.exit(1)

    # Write signature file
    output_path = args.output or args.file.with_suffix(args.file.suffix + ".sig")
    try:
        with open(output_path, "w") as f:
            json.dump(sig_doc, f, indent=2)
    except Exception as e:
        print(f"Error writing signature: {e}", file=sys.stderr)
        sys.exit(1)

    if not args.quiet:
        print(f"\nSignature created successfully!")
        print(f"  File:      {args.file}")
        print(f"  Hash:      {sig_doc['file']['hash']['value'][:16]}...")
        print(f"  Algorithm: {sig_doc['algorithm']['name']}")
        print(f"  Security:  {sig_doc['algorithm']['security_level']}")
        print(f"  Output:    {output_path}")


if __name__ == "__main__":
    main()
