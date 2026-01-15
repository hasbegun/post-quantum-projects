#!/usr/bin/env python3
"""
Post-Quantum API Request Signing Library

Signs HTTP API requests for authentication using post-quantum signatures.
Similar to AWS Signature Version 4 but using PQC algorithms.

Usage:
    from sign_request import RequestSigner

    signer = RequestSigner(secret_key_path="keys/api_secret.key")
    signed_headers = signer.sign_request(
        method="POST",
        path="/api/v1/orders",
        headers={"Content-Type": "application/json"},
        body={"item": "widget", "qty": 10}
    )

CLI Usage:
    python sign_request.py --key <secret_key> --method POST --path /api/v1/orders \\
        --header "Content-Type: application/json" --body '{"item": "widget"}'
"""

import argparse
import hashlib
import hmac
import json
import sys
from datetime import datetime, timezone
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

# Key size to algorithm mapping
KEY_SIZE_MAP = {
    2560: "mldsa44",
    4032: "mldsa65",
    4896: "mldsa87",
    64: "slh-shake-128f",
    96: "slh-shake-192f",
    128: "slh-shake-256f",
}


class RequestSigner:
    """Signs API requests with post-quantum signatures."""

    # Signed headers that are included in the signature
    SIGNED_HEADERS = ["host", "content-type", "x-pqc-date", "x-pqc-content-sha256"]

    def __init__(
        self,
        secret_key: Optional[bytes] = None,
        secret_key_path: Optional[Path] = None,
        algorithm: Optional[str] = None,
        key_id: Optional[str] = None,
    ):
        """
        Initialize the request signer.

        Args:
            secret_key: Secret key bytes
            secret_key_path: Path to secret key file
            algorithm: Algorithm to use (auto-detected if not specified)
            key_id: Identifier for the key (for key rotation)
        """
        if secret_key is None and secret_key_path is None:
            raise ValueError("Either secret_key or secret_key_path is required")

        if secret_key_path is not None:
            with open(secret_key_path, "rb") as f:
                secret_key = f.read()

        self.secret_key = secret_key
        self.key_id = key_id or "default"

        # Auto-detect algorithm if not specified
        if algorithm is None:
            key_size = len(secret_key)
            if key_size not in KEY_SIZE_MAP:
                raise ValueError(f"Cannot detect algorithm from key size: {key_size}")
            algorithm = KEY_SIZE_MAP[key_size]

        if algorithm not in ALGORITHMS:
            raise ValueError(f"Unknown algorithm: {algorithm}")

        self.algorithm = algorithm
        self.dsa = ALGORITHMS[algorithm]["class"]()

    def _canonical_headers(self, headers: Dict[str, str]) -> str:
        """Create canonical headers string (lowercase, sorted)."""
        # Normalize headers to lowercase
        normalized = {k.lower(): v.strip() for k, v in headers.items()}

        # Sort and format
        lines = []
        for key in sorted(normalized.keys()):
            if key in self.SIGNED_HEADERS or key.startswith("x-pqc-"):
                lines.append(f"{key}:{normalized[key]}")

        return "\n".join(lines)

    def _signed_headers_list(self, headers: Dict[str, str]) -> str:
        """Get list of signed header names."""
        normalized = {k.lower() for k in headers.keys()}
        signed = sorted(
            k for k in normalized
            if k in self.SIGNED_HEADERS or k.startswith("x-pqc-")
        )
        return ";".join(signed)

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

    def sign_request(
        self,
        method: str,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        query_params: Optional[Dict[str, str]] = None,
        body: Any = None,
        host: Optional[str] = None,
    ) -> Dict[str, str]:
        """
        Sign an HTTP request and return the signed headers.

        Args:
            method: HTTP method (GET, POST, etc.)
            path: Request path (/api/v1/resource)
            headers: Existing headers to include
            query_params: Query parameters
            body: Request body (dict, str, or bytes)
            host: Host header value

        Returns:
            Dict of headers to add to the request
        """
        headers = headers or {}
        query_params = query_params or {}

        # Generate timestamp
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

        # Compute content hash
        content_hash = self._hash_payload(body)

        # Build complete headers
        complete_headers = dict(headers)
        complete_headers["x-pqc-date"] = timestamp
        complete_headers["x-pqc-content-sha256"] = content_hash
        if host:
            complete_headers["host"] = host

        # Build canonical request
        canonical_uri = path
        canonical_query = urlencode(sorted(query_params.items())) if query_params else ""
        canonical_headers = self._canonical_headers(complete_headers)
        signed_headers = self._signed_headers_list(complete_headers)

        canonical_request = "\n".join([
            method.upper(),
            canonical_uri,
            canonical_query,
            canonical_headers,
            "",  # Empty line after headers
            signed_headers,
            content_hash,
        ])

        # Hash the canonical request
        request_hash = hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()

        # Create string to sign
        string_to_sign = "\n".join([
            f"PQC-{self.algorithm.upper()}-SIGNATURE",
            timestamp,
            request_hash,
        ])

        # Sign with PQC
        message = string_to_sign.encode("utf-8")
        ctx = b"api-request"
        signature = self.dsa.sign(self.secret_key, message, ctx=ctx)

        # Build authorization header
        auth_header = (
            f"PQC-{self.algorithm.upper()} "
            f"KeyId={self.key_id}, "
            f"SignedHeaders={signed_headers}, "
            f"Signature={signature.hex()}"
        )

        # Return headers to add
        return {
            "X-PQC-Date": timestamp,
            "X-PQC-Content-SHA256": content_hash,
            "X-PQC-Algorithm": self.algorithm,
            "Authorization": auth_header,
        }


def main():
    """CLI interface for signing requests."""
    parser = argparse.ArgumentParser(
        description="Post-Quantum API Request Signing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sign a GET request
  %(prog)s --key keys/api_secret.key --method GET --path /api/v1/users

  # Sign a POST request with body
  %(prog)s --key keys/api_secret.key --method POST --path /api/v1/orders \\
      --header "Content-Type: application/json" --body '{"item": "widget"}'

  # Sign with specific algorithm
  %(prog)s --key keys/api_secret.key --method GET --path /api/v1/data -a mldsa87
        """,
    )

    parser.add_argument(
        "-k", "--key",
        required=True,
        type=Path,
        help="Secret key file",
    )
    parser.add_argument(
        "-m", "--method",
        required=True,
        help="HTTP method (GET, POST, PUT, DELETE, etc.)",
    )
    parser.add_argument(
        "-p", "--path",
        required=True,
        help="Request path (e.g., /api/v1/resource)",
    )
    parser.add_argument(
        "--header",
        action="append",
        dest="headers",
        help="Header in format 'Name: Value' (can be repeated)",
    )
    parser.add_argument(
        "--query",
        action="append",
        dest="query_params",
        help="Query param in format 'key=value' (can be repeated)",
    )
    parser.add_argument(
        "--body",
        help="Request body (JSON string)",
    )
    parser.add_argument(
        "--host",
        help="Host header value",
    )
    parser.add_argument(
        "-a", "--algorithm",
        choices=list(ALGORITHMS.keys()),
        help="Signing algorithm (auto-detected from key)",
    )
    parser.add_argument(
        "--key-id",
        default="default",
        help="Key identifier (for key rotation)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON",
    )

    args = parser.parse_args()

    # Parse headers
    headers = {}
    if args.headers:
        for h in args.headers:
            if ":" not in h:
                print(f"Error: Invalid header format: {h}", file=sys.stderr)
                sys.exit(1)
            name, value = h.split(":", 1)
            headers[name.strip()] = value.strip()

    # Parse query params
    query_params = {}
    if args.query_params:
        for q in args.query_params:
            if "=" not in q:
                print(f"Error: Invalid query param format: {q}", file=sys.stderr)
                sys.exit(1)
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
        signer = RequestSigner(
            secret_key_path=args.key,
            algorithm=args.algorithm,
            key_id=args.key_id,
        )

        signed_headers = signer.sign_request(
            method=args.method,
            path=args.path,
            headers=headers,
            query_params=query_params,
            body=body,
            host=args.host,
        )

        if args.json:
            print(json.dumps(signed_headers, indent=2))
        else:
            print("Signed Headers:")
            print("-" * 40)
            for name, value in signed_headers.items():
                # Truncate long values for display
                display_value = value
                if len(value) > 80 and name == "Authorization":
                    display_value = value[:77] + "..."
                print(f"{name}: {display_value}")

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
