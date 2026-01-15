#!/usr/bin/env python3
"""
Post-Quantum Document Signature Verification Tool

Verifies document signatures created with sign_document.py.

Usage:
    python verify_document.py --key <public_key> --document <document> [options]

Exit codes:
    0 - Signature valid
    1 - Signature invalid
    2 - Input error

Example:
    python verify_document.py --key keys/signer_public.key --document contract.pdf
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Add parent directories to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent / "src" / "python"))

try:
    from mldsa import MLDSA44, MLDSA65, MLDSA87
    from slhdsa import (
        SLHDSA_SHAKE_128f, SLHDSA_SHAKE_128s,
        SLHDSA_SHAKE_192f, SLHDSA_SHAKE_256f
    )
except ImportError:
    print("Error: Could not import PQC modules. Ensure the library is installed.")
    sys.exit(1)


# Algorithm registry
ALGORITHMS = {
    "mldsa44": {"class": MLDSA44, "name": "ML-DSA-44"},
    "mldsa65": {"class": MLDSA65, "name": "ML-DSA-65"},
    "mldsa87": {"class": MLDSA87, "name": "ML-DSA-87"},
    "slh-shake-128f": {"class": SLHDSA_SHAKE_128f, "name": "SLH-DSA-SHAKE-128f"},
    "slh-shake-128s": {"class": SLHDSA_SHAKE_128s, "name": "SLH-DSA-SHAKE-128s"},
    "slh-shake-192f": {"class": SLHDSA_SHAKE_192f, "name": "SLH-DSA-SHAKE-192f"},
    "slh-shake-256f": {"class": SLHDSA_SHAKE_256f, "name": "SLH-DSA-SHAKE-256f"},
}

# Key size to algorithm mapping for auto-detection
KEY_SIZE_MAP = {
    1312: "mldsa44",
    1952: "mldsa65",
    2592: "mldsa87",
    32: "slh-shake-128f",
    48: "slh-shake-192f",
    64: "slh-shake-256f",
}


def detect_algorithm(key_data: bytes) -> str:
    """Detect algorithm from public key size."""
    key_size = len(key_data)
    if key_size in KEY_SIZE_MAP:
        return KEY_SIZE_MAP[key_size]
    raise ValueError(f"Cannot detect algorithm from key size: {key_size}")


def compute_document_hash(filepath: Path) -> tuple:
    """Compute SHA-256 and SHA-512 hashes of a document."""
    sha256_hash = hashlib.sha256()
    sha512_hash = hashlib.sha512()

    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256_hash.update(chunk)
            sha512_hash.update(chunk)

    return sha256_hash.hexdigest(), sha512_hash.hexdigest()


def verify_document(
    key_path: Path,
    document_path: Path,
    signature_path: Optional[Path] = None,
    quiet: bool = False,
    json_output: bool = False,
) -> dict:
    """Verify a document signature."""

    result = {
        "valid": False,
        "checks": {
            "hash": False,
            "size": False,
            "signature": False,
        },
        "document": {},
        "signer": {},
        "timestamp": None,
        "error": None,
    }

    try:
        # Read public key
        with open(key_path, "rb") as f:
            pk = f.read()

        # Default signature path
        if signature_path is None:
            signature_path = document_path.with_suffix(document_path.suffix + ".docsig")

        # Read manifest
        with open(signature_path, "r") as f:
            manifest = json.load(f)

        # Extract values from manifest
        algorithm = manifest["algorithm"]["id"]
        expected_hash = manifest["document"]["hashes"]["sha256"]
        expected_size = manifest["document"]["size"]
        signature_hex = manifest["signature"]["value"]
        context_hex = manifest["signature"].get("context", "")
        timestamp = manifest.get("timestamp", "")

        result["document"] = {
            "name": manifest["document"]["name"],
            "size": expected_size,
        }
        result["timestamp"] = timestamp
        result["algorithm"] = algorithm

        if "signer" in manifest:
            result["signer"] = manifest["signer"]

        if "signing_details" in manifest:
            result["signing_details"] = manifest["signing_details"]

        # Compute actual document hash
        actual_hash, actual_sha512 = compute_document_hash(document_path)
        actual_size = document_path.stat().st_size

        # Check hash
        result["checks"]["hash"] = (actual_hash == expected_hash)

        # Also verify SHA-512 if present
        if "sha512" in manifest["document"]["hashes"]:
            expected_sha512 = manifest["document"]["hashes"]["sha512"]
            result["checks"]["hash"] = result["checks"]["hash"] and (actual_sha512 == expected_sha512)

        # Check size
        result["checks"]["size"] = (actual_size == expected_size)

        if not result["checks"]["hash"]:
            result["error"] = "Document hash mismatch - document may have been modified"
        elif not result["checks"]["size"]:
            result["error"] = "Document size mismatch"

        # Initialize algorithm
        if algorithm not in ALGORITHMS:
            # Try to detect from key
            algorithm = detect_algorithm(pk)
        alg_info = ALGORITHMS[algorithm]
        dsa = alg_info["class"]()

        # Decode signature and context
        signature = bytes.fromhex(signature_hex)
        ctx_bytes = bytes.fromhex(context_hex) if context_hex else b"document"

        # Build message to verify (must match what was signed)
        # Extract signer info from manifest if present
        signed_data = {
            "document_hash": expected_hash,
            "document_name": manifest["document"]["name"],
            "document_size": expected_size,
            "timestamp": timestamp,
        }

        if "signer" in manifest and "name" in manifest["signer"]:
            signed_data["signer_name"] = manifest["signer"]["name"]
        if "signing_details" in manifest:
            if "reason" in manifest["signing_details"]:
                signed_data["reason"] = manifest["signing_details"]["reason"]
            if "location" in manifest["signing_details"]:
                signed_data["location"] = manifest["signing_details"]["location"]

        message = json.dumps(signed_data, sort_keys=True).encode("utf-8")

        # Verify signature
        try:
            is_valid = dsa.verify(pk, message, signature, ctx=ctx_bytes)
            result["checks"]["signature"] = is_valid
        except Exception as e:
            result["checks"]["signature"] = False
            result["error"] = f"Signature verification error: {e}"

        # Overall result
        result["valid"] = all(result["checks"].values())

        if result["valid"]:
            result["error"] = None

    except FileNotFoundError as e:
        result["error"] = str(e)
    except json.JSONDecodeError:
        result["error"] = "Invalid signature file format"
    except Exception as e:
        result["error"] = str(e)

    return result


def print_result(result: dict, quiet: bool = False, json_output: bool = False):
    """Print verification result."""
    if json_output:
        print(json.dumps(result, indent=2))
        return

    if quiet:
        return

    print()
    print("=" * 50)
    print("  Document Signature Verification")
    print("=" * 50)
    print()

    if "document" in result and result["document"]:
        print(f"Document:   {result['document'].get('name', 'Unknown')}")
        print(f"Size:       {result['document'].get('size', 0)} bytes")

    if "algorithm" in result:
        print(f"Algorithm:  {result['algorithm']}")

    if result.get("timestamp"):
        print(f"Signed:     {result['timestamp']}")

    if result.get("signer"):
        signer = result["signer"]
        if "name" in signer:
            print(f"Signer:     {signer['name']}")
        if "email" in signer:
            print(f"Email:      {signer['email']}")
        if "organization" in signer:
            print(f"Org:        {signer['organization']}")

    if result.get("signing_details"):
        details = result["signing_details"]
        if "reason" in details:
            print(f"Reason:     {details['reason']}")
        if "location" in details:
            print(f"Location:   {details['location']}")

    print()
    print("Checks:")
    checks = result.get("checks", {})
    print(f"  Hash:       {'PASS' if checks.get('hash') else 'FAIL'}")
    print(f"  Size:       {'PASS' if checks.get('size') else 'FAIL'}")
    print(f"  Signature:  {'PASS' if checks.get('signature') else 'FAIL'}")

    if result.get("error"):
        print()
        print(f"Error: {result['error']}")

    print()
    print("=" * 50)
    if result["valid"]:
        print("  SIGNATURE VALID")
    else:
        print("  SIGNATURE INVALID")
    print("=" * 50)


def main():
    parser = argparse.ArgumentParser(
        description="Post-Quantum Document Signature Verification Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit Codes:
  0 - Signature valid
  1 - Signature invalid
  2 - Input error

Examples:
  # Verify a document signature
  %(prog)s --key keys/signer_public.key --document contract.pdf

  # JSON output for scripting
  %(prog)s --key keys/signer_public.key --document contract.pdf --json

  # Quiet mode (exit code only)
  %(prog)s --key keys/signer_public.key --document contract.pdf --quiet
        """,
    )

    parser.add_argument(
        "-k", "--key",
        required=True,
        type=Path,
        help="Public key file for verification",
    )
    parser.add_argument(
        "-d", "--document",
        required=True,
        type=Path,
        help="Document to verify",
    )
    parser.add_argument(
        "-s", "--signature",
        type=Path,
        help="Signature file (default: <document>.docsig)",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress output, exit code only",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output result as JSON",
    )

    args = parser.parse_args()

    # Validate inputs
    if not args.key.exists():
        print(f"Error: Key file not found: {args.key}", file=sys.stderr)
        sys.exit(2)
    if not args.document.exists():
        print(f"Error: Document not found: {args.document}", file=sys.stderr)
        sys.exit(2)

    result = verify_document(
        key_path=args.key,
        document_path=args.document,
        signature_path=args.signature,
        quiet=args.quiet,
        json_output=args.json,
    )

    print_result(result, quiet=args.quiet, json_output=args.json)

    sys.exit(0 if result["valid"] else 1)


if __name__ == "__main__":
    main()
