#!/usr/bin/env python3
"""
Post-Quantum API Request Verification Library

Verifies HTTP API request signatures created with sign_request.py.

Usage:
    from verify_request import RequestVerifier

    verifier = RequestVerifier(public_key_path="keys/api_public.key")
    result = verifier.verify_request(
        method="POST",
        path="/api/v1/orders",
        headers=request.headers,
        body=request.body
    )

CLI Usage:
    python verify_request.py --key <public_key> --method POST --path /api/v1/orders \\
        --header "Authorization: PQC-MLDSA65 KeyId=..." --body '{"item": "widget"}'
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, Optional, Any
from urllib.parse import urlencode

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

# Key size to algorithm mapping (public key sizes)
KEY_SIZE_MAP = {
    1312: "mldsa44",
    1952: "mldsa65",
    2592: "mldsa87",
    32: "slh-shake-128f",
    48: "slh-shake-192f",
    64: "slh-shake-256f",
}


class VerificationResult:
    """Result of request verification."""

    def __init__(self):
        self.valid = False
        self.signature_valid = False
        self.timestamp_valid = False
        self.content_hash_valid = False
        self.algorithm = None
        self.key_id = None
        self.timestamp = None
        self.error = None

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "checks": {
                "signature": self.signature_valid,
                "timestamp": self.timestamp_valid,
                "content_hash": self.content_hash_valid,
            },
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "timestamp": self.timestamp,
            "error": self.error,
        }


class RequestVerifier:
    """Verifies API request signatures."""

    # Maximum age of a request timestamp (5 minutes)
    MAX_TIMESTAMP_AGE = timedelta(minutes=5)

    # Signed headers that should be included
    SIGNED_HEADERS = ["host", "content-type", "x-pqc-date", "x-pqc-content-sha256"]

    def __init__(
        self,
        public_key: Optional[bytes] = None,
        public_key_path: Optional[Path] = None,
        algorithm: Optional[str] = None,
        max_timestamp_age: Optional[timedelta] = None,
    ):
        """
        Initialize the request verifier.

        Args:
            public_key: Public key bytes
            public_key_path: Path to public key file
            algorithm: Algorithm to use (auto-detected if not specified)
            max_timestamp_age: Maximum age for request timestamps
        """
        if public_key is None and public_key_path is None:
            raise ValueError("Either public_key or public_key_path is required")

        if public_key_path is not None:
            with open(public_key_path, "rb") as f:
                public_key = f.read()

        self.public_key = public_key

        if max_timestamp_age is not None:
            self.MAX_TIMESTAMP_AGE = max_timestamp_age

        # Auto-detect algorithm if not specified
        if algorithm is None:
            key_size = len(public_key)
            if key_size not in KEY_SIZE_MAP:
                raise ValueError(f"Cannot detect algorithm from key size: {key_size}")
            algorithm = KEY_SIZE_MAP[key_size]

        if algorithm not in ALGORITHMS:
            raise ValueError(f"Unknown algorithm: {algorithm}")

        self.algorithm = algorithm
        self.dsa = ALGORITHMS[algorithm]["class"]()

    def _parse_authorization_header(self, auth_header: str) -> dict:
        """Parse the Authorization header."""
        # Format: PQC-MLDSA65 KeyId=xxx, SignedHeaders=xxx, Signature=xxx
        parts = auth_header.split(" ", 1)
        if len(parts) != 2:
            raise ValueError("Invalid Authorization header format")

        scheme = parts[0]
        if not scheme.startswith("PQC-"):
            raise ValueError(f"Unknown authorization scheme: {scheme}")

        # Extract algorithm from scheme
        algorithm = scheme[4:].lower()

        # Parse key=value pairs
        params = {}
        for item in parts[1].split(","):
            item = item.strip()
            if "=" not in item:
                continue
            key, value = item.split("=", 1)
            params[key.strip()] = value.strip()

        return {
            "algorithm": algorithm,
            "key_id": params.get("KeyId", ""),
            "signed_headers": params.get("SignedHeaders", ""),
            "signature": params.get("Signature", ""),
        }

    def _canonical_headers(self, headers: Dict[str, str], signed_headers_list: str) -> str:
        """Create canonical headers string."""
        normalized = {k.lower(): v.strip() for k, v in headers.items()}
        signed_list = signed_headers_list.split(";")

        lines = []
        for key in sorted(signed_list):
            if key in normalized:
                lines.append(f"{key}:{normalized[key]}")

        return "\n".join(lines)

    def _hash_payload(self, body: Any) -> str:
        """Hash the request payload."""
        if body is None:
            body_bytes = b""
        elif isinstance(body, bytes):
            body_bytes = body
        elif isinstance(body, str):
            body_bytes = body.encode("utf-8")
        else:
            body_bytes = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

        return hashlib.sha256(body_bytes).hexdigest()

    def _validate_timestamp(self, timestamp_str: str) -> bool:
        """Validate the request timestamp is recent."""
        try:
            # Parse timestamp (format: 20240115T103000Z)
            dt = datetime.strptime(timestamp_str, "%Y%m%dT%H%M%SZ")
            dt = dt.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            age = abs(now - dt)

            return age <= self.MAX_TIMESTAMP_AGE
        except ValueError:
            return False

    def verify_request(
        self,
        method: str,
        path: str,
        headers: Dict[str, str],
        query_params: Optional[Dict[str, str]] = None,
        body: Any = None,
    ) -> VerificationResult:
        """
        Verify an HTTP request signature.

        Args:
            method: HTTP method
            path: Request path
            headers: Request headers (must include Authorization)
            query_params: Query parameters
            body: Request body

        Returns:
            VerificationResult with verification status
        """
        result = VerificationResult()
        query_params = query_params or {}

        try:
            # Normalize headers
            normalized_headers = {k.lower(): v for k, v in headers.items()}

            # Get required headers
            auth_header = normalized_headers.get("authorization")
            if not auth_header:
                result.error = "Missing Authorization header"
                return result

            timestamp = normalized_headers.get("x-pqc-date")
            if not timestamp:
                result.error = "Missing X-PQC-Date header"
                return result

            content_hash = normalized_headers.get("x-pqc-content-sha256")
            if not content_hash:
                result.error = "Missing X-PQC-Content-SHA256 header"
                return result

            # Parse authorization header
            auth_parts = self._parse_authorization_header(auth_header)
            result.algorithm = auth_parts["algorithm"]
            result.key_id = auth_parts["key_id"]
            result.timestamp = timestamp

            # Validate timestamp
            result.timestamp_valid = self._validate_timestamp(timestamp)
            if not result.timestamp_valid:
                result.error = "Request timestamp is expired or invalid"

            # Validate content hash
            computed_hash = self._hash_payload(body)
            result.content_hash_valid = (computed_hash == content_hash)
            if not result.content_hash_valid:
                result.error = "Content hash mismatch"

            # Rebuild canonical request
            canonical_uri = path
            canonical_query = urlencode(sorted(query_params.items())) if query_params else ""
            canonical_headers = self._canonical_headers(headers, auth_parts["signed_headers"])
            signed_headers = auth_parts["signed_headers"]

            canonical_request = "\n".join([
                method.upper(),
                canonical_uri,
                canonical_query,
                canonical_headers,
                "",
                signed_headers,
                content_hash,
            ])

            # Hash the canonical request
            request_hash = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()

            # Create string to sign
            string_to_sign = "\n".join([
                f"PQC-{auth_parts['algorithm'].upper()}-SIGNATURE",
                timestamp,
                request_hash,
            ])

            # Verify signature
            message = string_to_sign.encode("utf-8")
            ctx = b"api-request"
            signature = bytes.fromhex(auth_parts["signature"])

            result.signature_valid = self.dsa.verify(
                self.public_key, message, signature, ctx=ctx
            )

            if not result.signature_valid:
                result.error = "Invalid signature"

            # Overall result
            result.valid = (
                result.signature_valid and
                result.timestamp_valid and
                result.content_hash_valid
            )

        except Exception as e:
            result.error = str(e)

        return result


def main():
    """CLI interface for verifying requests."""
    parser = argparse.ArgumentParser(
        description="Post-Quantum API Request Verification Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exit Codes:
  0 - Signature valid
  1 - Signature invalid
  2 - Input error

Examples:
  # Verify a request
  %(prog)s --key keys/api_public.key --method POST --path /api/v1/orders \\
      --header "Authorization: PQC-MLDSA65 KeyId=default, ..." \\
      --header "X-PQC-Date: 20240115T103000Z" \\
      --header "X-PQC-Content-SHA256: abc123..."
        """,
    )

    parser.add_argument(
        "-k", "--key",
        required=True,
        type=Path,
        help="Public key file",
    )
    parser.add_argument(
        "-m", "--method",
        required=True,
        help="HTTP method",
    )
    parser.add_argument(
        "-p", "--path",
        required=True,
        help="Request path",
    )
    parser.add_argument(
        "--header",
        action="append",
        dest="headers",
        required=True,
        help="Header in format 'Name: Value' (must include Authorization)",
    )
    parser.add_argument(
        "--query",
        action="append",
        dest="query_params",
        help="Query param in format 'key=value'",
    )
    parser.add_argument(
        "--body",
        help="Request body (JSON string)",
    )
    parser.add_argument(
        "-a", "--algorithm",
        choices=list(ALGORITHMS.keys()),
        help="Verification algorithm (auto-detected from key)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Exit code only",
    )

    args = parser.parse_args()

    # Parse headers
    headers = {}
    for h in args.headers:
        if ":" not in h:
            print(f"Error: Invalid header format: {h}", file=sys.stderr)
            sys.exit(2)
        name, value = h.split(":", 1)
        headers[name.strip()] = value.strip()

    # Parse query params
    query_params = {}
    if args.query_params:
        for q in args.query_params:
            if "=" not in q:
                print(f"Error: Invalid query param format: {q}", file=sys.stderr)
                sys.exit(2)
            name, value = q.split("=", 1)
            query_params[name] = value

    # Parse body
    body = None
    if args.body:
        try:
            body = json.loads(args.body)
        except json.JSONDecodeError:
            body = args.body

    try:
        verifier = RequestVerifier(
            public_key_path=args.key,
            algorithm=args.algorithm,
        )

        result = verifier.verify_request(
            method=args.method,
            path=args.path,
            headers=headers,
            query_params=query_params,
            body=body,
        )

        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        elif not args.quiet:
            print()
            print("=" * 40)
            print("  Request Verification Result")
            print("=" * 40)
            print()
            print(f"Algorithm:  {result.algorithm}")
            print(f"Key ID:     {result.key_id}")
            print(f"Timestamp:  {result.timestamp}")
            print()
            print("Checks:")
            print(f"  Signature:    {'PASS' if result.signature_valid else 'FAIL'}")
            print(f"  Timestamp:    {'PASS' if result.timestamp_valid else 'FAIL'}")
            print(f"  Content Hash: {'PASS' if result.content_hash_valid else 'FAIL'}")

            if result.error:
                print()
                print(f"Error: {result.error}")

            print()
            print("=" * 40)
            if result.valid:
                print("  REQUEST VALID")
            else:
                print("  REQUEST INVALID")
            print("=" * 40)

        sys.exit(0 if result.valid else 1)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)


if __name__ == "__main__":
    main()
