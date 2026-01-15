#!/usr/bin/env python3
"""
Post-Quantum Document Signing Tool

Signs documents (PDFs, contracts, legal documents) with post-quantum
digital signatures, including timestamping and signer identity.

Usage:
    python sign_document.py --key <secret_key> --document <document> [options]

Example:
    python sign_document.py --key keys/signer_secret.key --document contract.pdf \
        --signer-name "John Doe" --reason "Contract approval"
"""

import argparse
import hashlib
import json
import os
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
    "mldsa44": {"class": MLDSA44, "name": "ML-DSA-44", "security": "NIST Level 2", "standard": "FIPS 204"},
    "mldsa65": {"class": MLDSA65, "name": "ML-DSA-65", "security": "NIST Level 3", "standard": "FIPS 204"},
    "mldsa87": {"class": MLDSA87, "name": "ML-DSA-87", "security": "NIST Level 5", "standard": "FIPS 204"},
    "slh-shake-128f": {"class": SLHDSA_SHAKE_128f, "name": "SLH-DSA-SHAKE-128f", "security": "NIST Level 1", "standard": "FIPS 205"},
    "slh-shake-128s": {"class": SLHDSA_SHAKE_128s, "name": "SLH-DSA-SHAKE-128s", "security": "NIST Level 1", "standard": "FIPS 205"},
    "slh-shake-192f": {"class": SLHDSA_SHAKE_192f, "name": "SLH-DSA-SHAKE-192f", "security": "NIST Level 3", "standard": "FIPS 205"},
    "slh-shake-256f": {"class": SLHDSA_SHAKE_256f, "name": "SLH-DSA-SHAKE-256f", "security": "NIST Level 5", "standard": "FIPS 205"},
}

# Key size to algorithm mapping for auto-detection
KEY_SIZE_MAP = {
    2560: "mldsa44",
    4032: "mldsa65",
    4896: "mldsa87",
    64: "slh-shake-128f",
    96: "slh-shake-192f",
    128: "slh-shake-256f",
}


def detect_algorithm(key_data: bytes) -> str:
    """Detect algorithm from key size."""
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


def get_document_metadata(filepath: Path) -> dict:
    """Extract document metadata."""
    stat = filepath.stat()
    return {
        "name": filepath.name,
        "size": stat.st_size,
        "modified": datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
    }


def sign_document(
    key_path: Path,
    document_path: Path,
    algorithm: Optional[str] = None,
    output_path: Optional[Path] = None,
    signer_name: Optional[str] = None,
    signer_email: Optional[str] = None,
    signer_org: Optional[str] = None,
    reason: Optional[str] = None,
    location: Optional[str] = None,
    context: Optional[str] = None,
    quiet: bool = False,
) -> dict:
    """Sign a document and create signature manifest."""

    # Read secret key
    with open(key_path, "rb") as f:
        sk = f.read()

    # Auto-detect algorithm if not specified
    if algorithm is None:
        algorithm = detect_algorithm(sk)
        if not quiet:
            print(f"Detected algorithm: {algorithm}")

    if algorithm not in ALGORITHMS:
        raise ValueError(f"Unknown algorithm: {algorithm}")

    # Initialize signing algorithm
    alg_info = ALGORITHMS[algorithm]
    dsa = alg_info["class"]()

    # Compute document hashes
    sha256_hash, sha512_hash = compute_document_hash(document_path)
    doc_metadata = get_document_metadata(document_path)

    # Generate timestamp
    timestamp = datetime.now(timezone.utc).isoformat()

    # Build signed message - includes document hash and metadata
    signed_data = {
        "document_hash": sha256_hash,
        "document_name": doc_metadata["name"],
        "document_size": doc_metadata["size"],
        "timestamp": timestamp,
    }

    if signer_name:
        signed_data["signer_name"] = signer_name
    if reason:
        signed_data["reason"] = reason
    if location:
        signed_data["location"] = location

    message = json.dumps(signed_data, sort_keys=True).encode("utf-8")

    # Prepare context bytes
    ctx_bytes = b"document"
    if context:
        ctx_bytes = context.encode("utf-8")

    # Sign the message
    if not quiet:
        print(f"Signing document: {document_path}")

    signature = dsa.sign(sk, message, ctx=ctx_bytes)

    if not quiet:
        print(f"Signature size: {len(signature)} bytes")

    # Build manifest
    manifest = {
        "manifest_version": "1.0",
        "type": "document-signature",
        "algorithm": {
            "id": algorithm,
            "name": alg_info["name"],
            "security_level": alg_info["security"],
            "standard": alg_info["standard"],
        },
        "document": {
            "name": doc_metadata["name"],
            "size": doc_metadata["size"],
            "hashes": {
                "sha256": sha256_hash,
                "sha512": sha512_hash,
            },
        },
        "signature": {
            "value": signature.hex(),
            "encoding": "hex",
            "context": ctx_bytes.hex(),
        },
        "timestamp": timestamp,
    }

    # Add signer information
    signer_info = {}
    if signer_name:
        signer_info["name"] = signer_name
    if signer_email:
        signer_info["email"] = signer_email
    if signer_org:
        signer_info["organization"] = signer_org
    if signer_info:
        manifest["signer"] = signer_info

    # Add signing details
    signing_details = {}
    if reason:
        signing_details["reason"] = reason
    if location:
        signing_details["location"] = location
    if signing_details:
        manifest["signing_details"] = signing_details

    # Write manifest
    if output_path is None:
        output_path = document_path.with_suffix(document_path.suffix + ".docsig")

    with open(output_path, "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")

    if not quiet:
        print(f"Signature written to: {output_path}")

    return manifest


def main():
    parser = argparse.ArgumentParser(
        description="Post-Quantum Document Signing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sign a PDF document
  %(prog)s --key keys/signer_secret.key --document contract.pdf

  # Sign with signer identity
  %(prog)s --key keys/signer_secret.key --document agreement.pdf \\
      --signer-name "John Doe" --signer-email "john@example.com" \\
      --reason "Contract approval" --location "New York, NY"

  # Use specific algorithm
  %(prog)s --key keys/signer_secret.key --document doc.pdf -a mldsa87
        """,
    )

    parser.add_argument(
        "-k", "--key",
        required=True,
        type=Path,
        help="Secret key file for signing",
    )
    parser.add_argument(
        "-d", "--document",
        required=True,
        type=Path,
        help="Document to sign",
    )
    parser.add_argument(
        "-a", "--algorithm",
        choices=list(ALGORITHMS.keys()),
        help="Signing algorithm (auto-detected from key if not specified)",
    )
    parser.add_argument(
        "-o", "--output",
        type=Path,
        help="Output signature file (default: <document>.docsig)",
    )
    parser.add_argument(
        "--signer-name",
        help="Name of the signer",
    )
    parser.add_argument(
        "--signer-email",
        help="Email of the signer",
    )
    parser.add_argument(
        "--signer-org",
        help="Organization of the signer",
    )
    parser.add_argument(
        "--reason",
        help="Reason for signing (e.g., 'Contract approval', 'Document review')",
    )
    parser.add_argument(
        "--location",
        help="Location where document was signed",
    )
    parser.add_argument(
        "-c", "--context",
        help="Context string for domain separation",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress output",
    )

    args = parser.parse_args()

    # Validate inputs
    if not args.key.exists():
        print(f"Error: Key file not found: {args.key}", file=sys.stderr)
        sys.exit(2)
    if not args.document.exists():
        print(f"Error: Document not found: {args.document}", file=sys.stderr)
        sys.exit(2)

    try:
        sign_document(
            key_path=args.key,
            document_path=args.document,
            algorithm=args.algorithm,
            output_path=args.output,
            signer_name=args.signer_name,
            signer_email=args.signer_email,
            signer_org=args.signer_org,
            reason=args.reason,
            location=args.location,
            context=args.context,
            quiet=args.quiet,
        )
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
