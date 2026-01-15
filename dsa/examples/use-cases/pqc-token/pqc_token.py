#!/usr/bin/env python3
"""
Post-Quantum Cryptographic Token Library

A JWT-like token format using post-quantum digital signatures.

Token Format:
    <base64url(header)>.<base64url(payload)>.<base64url(signature)>

Usage:
    from pqc_token import PQCToken

    # Create a token
    token = PQCToken.create(
        payload={"sub": "user123", "role": "admin"},
        secret_key_path="keys/token_secret.key",
        expires_in=3600,
    )

    # Verify a token
    result = PQCToken.verify(
        token=token,
        public_key_path="keys/token_public.key",
    )

CLI Usage:
    python pqc_token.py create --key <secret_key> --payload '{"sub": "user"}'
    python pqc_token.py verify --key <public_key> --token <token_string>
"""

import argparse
import base64
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional, Any, Union
from dataclasses import dataclass

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
    "mldsa44": {"class": MLDSA44, "name": "ML-DSA-44", "type": "pqc"},
    "mldsa65": {"class": MLDSA65, "name": "ML-DSA-65", "type": "pqc"},
    "mldsa87": {"class": MLDSA87, "name": "ML-DSA-87", "type": "pqc"},
    "slh-shake-128f": {"class": SLHDSA_SHAKE_128f, "name": "SLH-DSA-SHAKE-128f", "type": "pqc"},
    "slh-shake-128s": {"class": SLHDSA_SHAKE_128s, "name": "SLH-DSA-SHAKE-128s", "type": "pqc"},
    "slh-shake-192f": {"class": SLHDSA_SHAKE_192f, "name": "SLH-DSA-SHAKE-192f", "type": "pqc"},
    "slh-shake-256f": {"class": SLHDSA_SHAKE_256f, "name": "SLH-DSA-SHAKE-256f", "type": "pqc"},
}

# Secret key size to algorithm mapping
SECRET_KEY_SIZE_MAP = {
    2560: "mldsa44",
    4032: "mldsa65",
    4896: "mldsa87",
    64: "slh-shake-128f",
    96: "slh-shake-192f",
    128: "slh-shake-256f",
}

# Public key size to algorithm mapping
PUBLIC_KEY_SIZE_MAP = {
    1312: "mldsa44",
    1952: "mldsa65",
    2592: "mldsa87",
    32: "slh-shake-128f",
    48: "slh-shake-192f",
    64: "slh-shake-256f",
}


def base64url_encode(data: bytes) -> str:
    """Encode bytes to base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def base64url_decode(data: str) -> bytes:
    """Decode base64url string (with or without padding)."""
    # Add padding if needed
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


@dataclass
class TokenResult:
    """Result of token verification."""
    valid: bool
    payload: Optional[Dict[str, Any]] = None
    header: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    expired: bool = False
    not_before: bool = False

    def to_dict(self) -> dict:
        return {
            "valid": self.valid,
            "payload": self.payload,
            "header": self.header,
            "error": self.error,
            "expired": self.expired,
            "not_before": self.not_before,
        }


class PQCToken:
    """Post-Quantum Cryptographic Token handler."""

    # Standard claims
    REGISTERED_CLAIMS = {"iss", "sub", "aud", "exp", "nbf", "iat", "jti"}

    @staticmethod
    def _detect_algorithm(key: bytes, is_secret: bool = True) -> str:
        """Detect algorithm from key size."""
        key_size = len(key)
        size_map = SECRET_KEY_SIZE_MAP if is_secret else PUBLIC_KEY_SIZE_MAP

        if key_size not in size_map:
            raise ValueError(f"Cannot detect algorithm from key size: {key_size}")
        return size_map[key_size]

    @staticmethod
    def _get_dsa(algorithm: str):
        """Get DSA instance for algorithm."""
        if algorithm not in ALGORITHMS:
            raise ValueError(f"Unknown algorithm: {algorithm}")
        return ALGORITHMS[algorithm]["class"]()

    @classmethod
    def create(
        cls,
        payload: Dict[str, Any],
        secret_key: Optional[bytes] = None,
        secret_key_path: Optional[Path] = None,
        algorithm: Optional[str] = None,
        expires_in: Optional[int] = None,
        not_before: Optional[int] = None,
        issuer: Optional[str] = None,
        subject: Optional[str] = None,
        audience: Optional[str] = None,
        token_id: Optional[str] = None,
    ) -> str:
        """
        Create a signed PQC token.

        Args:
            payload: Token payload (claims)
            secret_key: Secret key bytes
            secret_key_path: Path to secret key file
            algorithm: Algorithm to use (auto-detected if not specified)
            expires_in: Token lifetime in seconds
            not_before: Token not valid before (Unix timestamp)
            issuer: Token issuer (iss claim)
            subject: Token subject (sub claim)
            audience: Token audience (aud claim)
            token_id: Unique token ID (jti claim)

        Returns:
            Signed token string
        """
        if secret_key is None and secret_key_path is None:
            raise ValueError("Either secret_key or secret_key_path is required")

        if secret_key_path is not None:
            with open(secret_key_path, "rb") as f:
                secret_key = f.read()

        # Auto-detect algorithm
        if algorithm is None:
            algorithm = cls._detect_algorithm(secret_key, is_secret=True)

        dsa = cls._get_dsa(algorithm)

        # Build payload with claims
        now = int(time.time())
        token_payload = dict(payload)

        # Add standard claims
        token_payload["iat"] = now

        if expires_in is not None:
            token_payload["exp"] = now + expires_in

        if not_before is not None:
            token_payload["nbf"] = not_before

        if issuer is not None:
            token_payload["iss"] = issuer

        if subject is not None:
            token_payload["sub"] = subject

        if audience is not None:
            token_payload["aud"] = audience

        if token_id is not None:
            token_payload["jti"] = token_id

        # Build header
        header = {
            "alg": algorithm.upper(),
            "typ": "PQT",  # Post-Quantum Token
        }

        # Encode header and payload
        header_b64 = base64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        payload_b64 = base64url_encode(json.dumps(token_payload, separators=(",", ":")).encode("utf-8"))

        # Create signing input
        signing_input = f"{header_b64}.{payload_b64}"

        # Sign
        ctx = b"pqc-token"
        signature = dsa.sign(secret_key, signing_input.encode("utf-8"), ctx=ctx)
        signature_b64 = base64url_encode(signature)

        return f"{header_b64}.{payload_b64}.{signature_b64}"

    @classmethod
    def verify(
        cls,
        token: str,
        public_key: Optional[bytes] = None,
        public_key_path: Optional[Path] = None,
        algorithm: Optional[str] = None,
        verify_exp: bool = True,
        verify_nbf: bool = True,
        leeway: int = 0,
    ) -> TokenResult:
        """
        Verify a PQC token.

        Args:
            token: Token string to verify
            public_key: Public key bytes
            public_key_path: Path to public key file
            algorithm: Expected algorithm (auto-detected if not specified)
            verify_exp: Verify expiration claim
            verify_nbf: Verify not-before claim
            leeway: Clock skew allowance in seconds

        Returns:
            TokenResult with verification status
        """
        result = TokenResult(valid=False)

        try:
            if public_key is None and public_key_path is None:
                raise ValueError("Either public_key or public_key_path is required")

            if public_key_path is not None:
                with open(public_key_path, "rb") as f:
                    public_key = f.read()

            # Parse token
            parts = token.split(".")
            if len(parts) != 3:
                result.error = "Invalid token format: expected 3 parts"
                return result

            header_b64, payload_b64, signature_b64 = parts

            # Decode header
            try:
                header = json.loads(base64url_decode(header_b64))
                result.header = header
            except (json.JSONDecodeError, ValueError) as e:
                result.error = f"Invalid header: {e}"
                return result

            # Decode payload
            try:
                payload = json.loads(base64url_decode(payload_b64))
                result.payload = payload
            except (json.JSONDecodeError, ValueError) as e:
                result.error = f"Invalid payload: {e}"
                return result

            # Decode signature
            try:
                signature = base64url_decode(signature_b64)
            except ValueError as e:
                result.error = f"Invalid signature encoding: {e}"
                return result

            # Check token type
            if header.get("typ") != "PQT":
                result.error = f"Invalid token type: {header.get('typ')}"
                return result

            # Get algorithm from header
            token_algorithm = header.get("alg", "").lower()
            if not token_algorithm:
                result.error = "Missing algorithm in header"
                return result

            # Verify algorithm matches expected
            if algorithm is not None and token_algorithm != algorithm.lower():
                result.error = f"Algorithm mismatch: expected {algorithm}, got {token_algorithm}"
                return result

            # Auto-detect algorithm from key if not specified
            if algorithm is None:
                algorithm = cls._detect_algorithm(public_key, is_secret=False)
                if algorithm.lower() != token_algorithm:
                    result.error = f"Algorithm mismatch: key is {algorithm}, token uses {token_algorithm}"
                    return result

            dsa = cls._get_dsa(token_algorithm)

            # Verify signature
            signing_input = f"{header_b64}.{payload_b64}"
            ctx = b"pqc-token"

            try:
                sig_valid = dsa.verify(public_key, signing_input.encode("utf-8"), signature, ctx=ctx)
            except Exception as e:
                result.error = f"Signature verification failed: {e}"
                return result

            if not sig_valid:
                result.error = "Invalid signature"
                return result

            # Verify time-based claims
            now = int(time.time())

            # Check expiration
            if verify_exp and "exp" in payload:
                exp = payload["exp"]
                if now > exp + leeway:
                    result.expired = True
                    result.error = "Token has expired"
                    return result

            # Check not-before
            if verify_nbf and "nbf" in payload:
                nbf = payload["nbf"]
                if now < nbf - leeway:
                    result.not_before = True
                    result.error = "Token is not yet valid"
                    return result

            result.valid = True
            return result

        except Exception as e:
            result.error = str(e)
            return result

    @classmethod
    def decode(cls, token: str) -> TokenResult:
        """
        Decode a token without verification.

        Args:
            token: Token string to decode

        Returns:
            TokenResult with header and payload (valid is always False)
        """
        result = TokenResult(valid=False)

        try:
            parts = token.split(".")
            if len(parts) != 3:
                result.error = "Invalid token format"
                return result

            header_b64, payload_b64, _ = parts

            result.header = json.loads(base64url_decode(header_b64))
            result.payload = json.loads(base64url_decode(payload_b64))

        except Exception as e:
            result.error = str(e)

        return result

    @classmethod
    def get_claim(cls, token: str, claim: str) -> Any:
        """Get a specific claim from a token without verification."""
        result = cls.decode(token)
        if result.payload:
            return result.payload.get(claim)
        return None


def main():
    """CLI interface for PQC tokens."""
    parser = argparse.ArgumentParser(
        description="Post-Quantum Cryptographic Token Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Create a token
  %(prog)s create --key keys/token_secret.key --payload '{"sub": "user123"}'

  # Create token with expiration
  %(prog)s create --key keys/token_secret.key --payload '{"role": "admin"}' --expires 3600

  # Verify a token
  %(prog)s verify --key keys/token_public.key --token <token_string>

  # Decode token (no verification)
  %(prog)s decode --token <token_string>
        """,
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Create command
    create_parser = subparsers.add_parser("create", help="Create a signed token")
    create_parser.add_argument(
        "-k", "--key",
        required=True,
        type=Path,
        help="Secret key file",
    )
    create_parser.add_argument(
        "-p", "--payload",
        required=True,
        help="Token payload (JSON string)",
    )
    create_parser.add_argument(
        "-a", "--algorithm",
        choices=list(ALGORITHMS.keys()),
        help="Signing algorithm (auto-detected from key)",
    )
    create_parser.add_argument(
        "--expires",
        type=int,
        metavar="SECONDS",
        help="Token expiration time in seconds",
    )
    create_parser.add_argument(
        "--nbf",
        type=int,
        metavar="TIMESTAMP",
        help="Token not valid before (Unix timestamp)",
    )
    create_parser.add_argument(
        "--issuer",
        help="Token issuer (iss claim)",
    )
    create_parser.add_argument(
        "--subject",
        help="Token subject (sub claim)",
    )
    create_parser.add_argument(
        "--audience",
        help="Token audience (aud claim)",
    )
    create_parser.add_argument(
        "--token-id",
        help="Unique token ID (jti claim)",
    )
    create_parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON",
    )

    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify a token")
    verify_parser.add_argument(
        "-k", "--key",
        required=True,
        type=Path,
        help="Public key file",
    )
    verify_parser.add_argument(
        "-t", "--token",
        required=True,
        help="Token string to verify",
    )
    verify_parser.add_argument(
        "-a", "--algorithm",
        choices=list(ALGORITHMS.keys()),
        help="Expected algorithm (auto-detected from key)",
    )
    verify_parser.add_argument(
        "--no-exp",
        action="store_true",
        help="Skip expiration verification",
    )
    verify_parser.add_argument(
        "--no-nbf",
        action="store_true",
        help="Skip not-before verification",
    )
    verify_parser.add_argument(
        "--leeway",
        type=int,
        default=0,
        help="Clock skew allowance in seconds",
    )
    verify_parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON",
    )
    verify_parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Exit code only",
    )

    # Decode command
    decode_parser = subparsers.add_parser("decode", help="Decode token without verification")
    decode_parser.add_argument(
        "-t", "--token",
        required=True,
        help="Token string to decode",
    )
    decode_parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON",
    )

    args = parser.parse_args()

    if args.command == "create":
        # Parse payload
        try:
            payload = json.loads(args.payload)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON payload: {e}", file=sys.stderr)
            sys.exit(1)

        try:
            token = PQCToken.create(
                payload=payload,
                secret_key_path=args.key,
                algorithm=args.algorithm,
                expires_in=args.expires,
                not_before=args.nbf,
                issuer=args.issuer,
                subject=args.subject,
                audience=args.audience,
                token_id=args.token_id,
            )

            if args.json:
                output = {
                    "token": token,
                    "algorithm": args.algorithm or PQCToken._detect_algorithm(
                        open(args.key, "rb").read(), is_secret=True
                    ),
                }
                print(json.dumps(output, indent=2))
            else:
                print(token)

        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)

    elif args.command == "verify":
        try:
            result = PQCToken.verify(
                token=args.token,
                public_key_path=args.key,
                algorithm=args.algorithm,
                verify_exp=not args.no_exp,
                verify_nbf=not args.no_nbf,
                leeway=args.leeway,
            )

            if args.json:
                print(json.dumps(result.to_dict(), indent=2))
            elif not args.quiet:
                print()
                print("=" * 50)
                print("  Token Verification Result")
                print("=" * 50)
                print()

                if result.header:
                    print(f"Algorithm:  {result.header.get('alg')}")
                    print(f"Type:       {result.header.get('typ')}")
                print()

                if result.payload:
                    print("Claims:")
                    for key, value in result.payload.items():
                        if key in ("iat", "exp", "nbf"):
                            dt = datetime.fromtimestamp(value, tz=timezone.utc)
                            value = f"{value} ({dt.isoformat()})"
                        print(f"  {key}: {value}")
                print()

                if result.valid:
                    print("Status: VALID")
                else:
                    print(f"Status: INVALID")
                    if result.error:
                        print(f"Error:  {result.error}")

                print("=" * 50)

            sys.exit(0 if result.valid else 1)

        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(2)

    elif args.command == "decode":
        result = PQCToken.decode(args.token)

        if args.json:
            print(json.dumps({
                "header": result.header,
                "payload": result.payload,
                "error": result.error,
            }, indent=2))
        else:
            if result.error:
                print(f"Error: {result.error}", file=sys.stderr)
                sys.exit(1)

            print()
            print("Header:")
            print(json.dumps(result.header, indent=2))
            print()
            print("Payload:")
            print(json.dumps(result.payload, indent=2))


if __name__ == "__main__":
    main()
