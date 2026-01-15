#!/usr/bin/env python3
"""
Test suite for PQC Token use case.

Tests cover:
- Token creation with various algorithms
- Token verification
- Claim validation (exp, nbf, iat)
- Error handling
- Token decoding
"""

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

# Add paths for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src" / "python"))
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "examples" / "use-cases" / "pqc-token"))

from mldsa import MLDSA44, MLDSA65, MLDSA87
from slhdsa import SLHDSA_SHAKE_128f

from pqc_token import PQCToken, TokenResult, base64url_encode, base64url_decode


class TestBase64url:
    """Test base64url encoding/decoding."""

    def test_encode_decode_roundtrip(self):
        """Test that encode/decode are inverses."""
        data = b"Hello, World!"
        encoded = base64url_encode(data)
        decoded = base64url_decode(encoded)
        assert decoded == data

    def test_encode_without_padding(self):
        """Test that encoding doesn't add padding."""
        data = b"test"
        encoded = base64url_encode(data)
        assert "=" not in encoded

    def test_decode_with_padding(self):
        """Test decoding with padding."""
        data = b"test"
        encoded = base64url_encode(data) + "=="  # Add padding
        decoded = base64url_decode(encoded)
        assert decoded == data

    def test_url_safe_characters(self):
        """Test that encoding uses URL-safe characters."""
        # This should produce + and / in standard base64
        data = bytes([0xff, 0xef, 0xbe])
        encoded = base64url_encode(data)
        assert "+" not in encoded
        assert "/" not in encoded


class TestTokenCreation:
    """Test token creation functionality."""

    @pytest.fixture
    def mldsa65_keys(self, tmp_path):
        """Generate ML-DSA-65 key pair."""
        dsa = MLDSA65()
        pk, sk = dsa.keygen()

        pk_file = tmp_path / "public.key"
        sk_file = tmp_path / "secret.key"
        pk_file.write_bytes(pk)
        sk_file.write_bytes(sk)

        return {"pk_file": pk_file, "sk_file": sk_file, "pk": pk, "sk": sk}

    def test_create_simple_token(self, mldsa65_keys):
        """Test creating a simple token."""
        token = PQCToken.create(
            payload={"sub": "user123"},
            secret_key_path=mldsa65_keys["sk_file"],
        )

        assert isinstance(token, str)
        assert token.count(".") == 2

    def test_token_has_three_parts(self, mldsa65_keys):
        """Test token format has header.payload.signature."""
        token = PQCToken.create(
            payload={"sub": "user123"},
            secret_key_path=mldsa65_keys["sk_file"],
        )

        parts = token.split(".")
        assert len(parts) == 3
        assert all(len(p) > 0 for p in parts)

    def test_token_header(self, mldsa65_keys):
        """Test token header contains algorithm and type."""
        token = PQCToken.create(
            payload={"sub": "user123"},
            secret_key_path=mldsa65_keys["sk_file"],
        )

        header_b64 = token.split(".")[0]
        header = json.loads(base64url_decode(header_b64))

        assert header["alg"] == "MLDSA65"
        assert header["typ"] == "PQT"

    def test_token_iat_claim(self, mldsa65_keys):
        """Test that iat claim is added automatically."""
        before = int(time.time())

        token = PQCToken.create(
            payload={"sub": "user123"},
            secret_key_path=mldsa65_keys["sk_file"],
        )

        after = int(time.time())

        payload_b64 = token.split(".")[1]
        payload = json.loads(base64url_decode(payload_b64))

        assert "iat" in payload
        assert before <= payload["iat"] <= after

    def test_token_exp_claim(self, mldsa65_keys):
        """Test expiration claim is set correctly."""
        now = int(time.time())

        token = PQCToken.create(
            payload={"sub": "user123"},
            secret_key_path=mldsa65_keys["sk_file"],
            expires_in=3600,
        )

        payload_b64 = token.split(".")[1]
        payload = json.loads(base64url_decode(payload_b64))

        assert "exp" in payload
        assert payload["exp"] == payload["iat"] + 3600

    def test_token_standard_claims(self, mldsa65_keys):
        """Test setting standard claims."""
        token = PQCToken.create(
            payload={"custom": "data"},
            secret_key_path=mldsa65_keys["sk_file"],
            issuer="auth.example.com",
            subject="user@example.com",
            audience="api.example.com",
            token_id="unique-id-123",
        )

        payload_b64 = token.split(".")[1]
        payload = json.loads(base64url_decode(payload_b64))

        assert payload["iss"] == "auth.example.com"
        assert payload["sub"] == "user@example.com"
        assert payload["aud"] == "api.example.com"
        assert payload["jti"] == "unique-id-123"
        assert payload["custom"] == "data"

    def test_token_nbf_claim(self, mldsa65_keys):
        """Test not-before claim."""
        future_time = int(time.time()) + 3600

        token = PQCToken.create(
            payload={"sub": "user123"},
            secret_key_path=mldsa65_keys["sk_file"],
            not_before=future_time,
        )

        payload_b64 = token.split(".")[1]
        payload = json.loads(base64url_decode(payload_b64))

        assert payload["nbf"] == future_time


class TestTokenVerification:
    """Test token verification functionality."""

    @pytest.fixture
    def key_pair(self, tmp_path):
        """Generate and save key pair."""
        dsa = MLDSA65()
        pk, sk = dsa.keygen()

        pk_file = tmp_path / "public.key"
        sk_file = tmp_path / "secret.key"
        pk_file.write_bytes(pk)
        sk_file.write_bytes(sk)

        return {"pk_file": pk_file, "sk_file": sk_file, "pk": pk, "sk": sk}

    def test_verify_valid_token(self, key_pair):
        """Test verification of valid token."""
        token = PQCToken.create(
            payload={"sub": "user123"},
            secret_key_path=key_pair["sk_file"],
            expires_in=3600,
        )

        result = PQCToken.verify(
            token=token,
            public_key_path=key_pair["pk_file"],
        )

        assert result.valid is True
        assert result.payload["sub"] == "user123"

    def test_verify_tampered_payload(self, key_pair):
        """Test detection of tampered payload."""
        token = PQCToken.create(
            payload={"sub": "user123", "role": "user"},
            secret_key_path=key_pair["sk_file"],
        )

        # Tamper with payload
        parts = token.split(".")
        payload = json.loads(base64url_decode(parts[1]))
        payload["role"] = "admin"
        parts[1] = base64url_encode(json.dumps(payload, separators=(",", ":")).encode())
        tampered_token = ".".join(parts)

        result = PQCToken.verify(
            token=tampered_token,
            public_key_path=key_pair["pk_file"],
        )

        assert result.valid is False
        assert "signature" in result.error.lower()

    def test_verify_wrong_key(self, key_pair, tmp_path):
        """Test rejection with wrong public key."""
        token = PQCToken.create(
            payload={"sub": "user123"},
            secret_key_path=key_pair["sk_file"],
        )

        # Generate different key pair
        dsa = MLDSA65()
        wrong_pk, _ = dsa.keygen()
        wrong_pk_file = tmp_path / "wrong_public.key"
        wrong_pk_file.write_bytes(wrong_pk)

        result = PQCToken.verify(
            token=token,
            public_key_path=wrong_pk_file,
        )

        assert result.valid is False

    def test_verify_expired_token(self, key_pair):
        """Test rejection of expired token."""
        # Create token that expires immediately
        token = PQCToken.create(
            payload={"sub": "user123"},
            secret_key_path=key_pair["sk_file"],
            expires_in=-10,  # Already expired
        )

        result = PQCToken.verify(
            token=token,
            public_key_path=key_pair["pk_file"],
        )

        assert result.valid is False
        assert result.expired is True

    def test_verify_skip_exp(self, key_pair):
        """Test skipping expiration check."""
        token = PQCToken.create(
            payload={"sub": "user123"},
            secret_key_path=key_pair["sk_file"],
            expires_in=-10,  # Already expired
        )

        result = PQCToken.verify(
            token=token,
            public_key_path=key_pair["pk_file"],
            verify_exp=False,
        )

        assert result.valid is True

    def test_verify_nbf_not_yet_valid(self, key_pair):
        """Test rejection of not-yet-valid token."""
        future_time = int(time.time()) + 3600

        token = PQCToken.create(
            payload={"sub": "user123"},
            secret_key_path=key_pair["sk_file"],
            not_before=future_time,
        )

        result = PQCToken.verify(
            token=token,
            public_key_path=key_pair["pk_file"],
        )

        assert result.valid is False
        assert result.not_before is True

    def test_verify_with_leeway(self, key_pair):
        """Test verification with clock skew leeway."""
        # Token expired 30 seconds ago
        token = PQCToken.create(
            payload={"sub": "user123"},
            secret_key_path=key_pair["sk_file"],
            expires_in=-30,
        )

        # Without leeway - should fail
        result = PQCToken.verify(
            token=token,
            public_key_path=key_pair["pk_file"],
            leeway=0,
        )
        assert result.valid is False

        # With 60 second leeway - should pass
        result = PQCToken.verify(
            token=token,
            public_key_path=key_pair["pk_file"],
            leeway=60,
        )
        assert result.valid is True


class TestTokenDecoding:
    """Test token decoding functionality."""

    @pytest.fixture
    def mldsa65_keys(self, tmp_path):
        """Generate ML-DSA-65 key pair."""
        dsa = MLDSA65()
        pk, sk = dsa.keygen()

        sk_file = tmp_path / "secret.key"
        sk_file.write_bytes(sk)

        return {"sk_file": sk_file}

    def test_decode_token(self, mldsa65_keys):
        """Test decoding token without verification."""
        token = PQCToken.create(
            payload={"sub": "user123", "role": "admin"},
            secret_key_path=mldsa65_keys["sk_file"],
        )

        result = PQCToken.decode(token)

        assert result.header["alg"] == "MLDSA65"
        assert result.header["typ"] == "PQT"
        assert result.payload["sub"] == "user123"
        assert result.payload["role"] == "admin"

    def test_decode_invalid_format(self):
        """Test decoding invalid token format."""
        result = PQCToken.decode("not.a.valid.token.format")
        assert result.error is not None

        result = PQCToken.decode("onlyonepart")
        assert result.error is not None

    def test_get_claim(self, mldsa65_keys):
        """Test getting specific claim."""
        token = PQCToken.create(
            payload={"sub": "user123", "scope": "read write"},
            secret_key_path=mldsa65_keys["sk_file"],
        )

        assert PQCToken.get_claim(token, "sub") == "user123"
        assert PQCToken.get_claim(token, "scope") == "read write"
        assert PQCToken.get_claim(token, "nonexistent") is None


class TestMultipleAlgorithms:
    """Test with different algorithms."""

    @pytest.mark.parametrize("algorithm,dsa_class", [
        ("mldsa44", MLDSA44),
        ("mldsa65", MLDSA65),
        ("mldsa87", MLDSA87),
    ])
    def test_mldsa_algorithms(self, tmp_path, algorithm, dsa_class):
        """Test token creation and verification with ML-DSA algorithms."""
        dsa = dsa_class()
        pk, sk = dsa.keygen()

        pk_file = tmp_path / "public.key"
        sk_file = tmp_path / "secret.key"
        pk_file.write_bytes(pk)
        sk_file.write_bytes(sk)

        token = PQCToken.create(
            payload={"sub": "user123"},
            secret_key_path=sk_file,
            algorithm=algorithm,
        )

        result = PQCToken.verify(
            token=token,
            public_key_path=pk_file,
            algorithm=algorithm,
        )

        assert result.valid is True
        assert result.header["alg"] == algorithm.upper()

    def test_slhdsa_algorithm(self, tmp_path):
        """Test with SLH-DSA algorithm."""
        dsa = SLHDSA_SHAKE_128f()
        # SLH-DSA keygen returns (pk, sk) - different from ML-DSA
        pk, sk = dsa.keygen()

        pk_file = tmp_path / "public.key"
        sk_file = tmp_path / "secret.key"
        pk_file.write_bytes(pk)
        sk_file.write_bytes(sk)

        token = PQCToken.create(
            payload={"sub": "user123"},
            secret_key_path=sk_file,
            algorithm="slh-shake-128f",
        )

        result = PQCToken.verify(
            token=token,
            public_key_path=pk_file,
            algorithm="slh-shake-128f",
        )

        assert result.valid is True


class TestErrorHandling:
    """Test error handling."""

    def test_missing_key(self):
        """Test handling of missing key."""
        with pytest.raises(ValueError):
            PQCToken.create(
                payload={"sub": "user123"},
            )

    def test_invalid_key_file(self, tmp_path):
        """Test handling of invalid key file."""
        with pytest.raises(FileNotFoundError):
            PQCToken.create(
                payload={"sub": "user123"},
                secret_key_path=tmp_path / "nonexistent.key",
            )

    def test_invalid_token_format(self, tmp_path):
        """Test verification of invalid token format."""
        dsa = MLDSA65()
        pk, _ = dsa.keygen()

        pk_file = tmp_path / "public.key"
        pk_file.write_bytes(pk)

        result = PQCToken.verify(
            token="invalid",
            public_key_path=pk_file,
        )

        assert result.valid is False
        assert "format" in result.error.lower()

    def test_invalid_header(self, tmp_path):
        """Test verification of token with invalid header."""
        dsa = MLDSA65()
        pk, _ = dsa.keygen()

        pk_file = tmp_path / "public.key"
        pk_file.write_bytes(pk)

        # Create token with invalid header
        invalid_header = base64url_encode(b"not json")
        invalid_token = f"{invalid_header}.payload.signature"

        result = PQCToken.verify(
            token=invalid_token,
            public_key_path=pk_file,
        )

        assert result.valid is False
        assert "header" in result.error.lower()

    def test_wrong_token_type(self, tmp_path):
        """Test rejection of wrong token type."""
        dsa = MLDSA65()
        pk, sk = dsa.keygen()

        pk_file = tmp_path / "public.key"
        sk_file = tmp_path / "secret.key"
        pk_file.write_bytes(pk)
        sk_file.write_bytes(sk)

        # Create token with wrong type
        token = PQCToken.create(
            payload={"sub": "user123"},
            secret_key_path=sk_file,
        )

        # Modify type to JWT
        parts = token.split(".")
        header = json.loads(base64url_decode(parts[0]))
        header["typ"] = "JWT"
        parts[0] = base64url_encode(json.dumps(header, separators=(",", ":")).encode())
        modified_token = ".".join(parts)

        result = PQCToken.verify(
            token=modified_token,
            public_key_path=pk_file,
        )

        assert result.valid is False
        assert "type" in result.error.lower()

    def test_algorithm_mismatch(self, tmp_path):
        """Test detection of algorithm mismatch."""
        dsa44 = MLDSA44()
        pk44, sk44 = dsa44.keygen()

        dsa65 = MLDSA65()
        pk65, _ = dsa65.keygen()

        sk_file = tmp_path / "secret.key"
        pk_file = tmp_path / "public.key"
        sk_file.write_bytes(sk44)
        pk_file.write_bytes(pk65)  # Different algorithm

        token = PQCToken.create(
            payload={"sub": "user123"},
            secret_key_path=sk_file,
        )

        result = PQCToken.verify(
            token=token,
            public_key_path=pk_file,
        )

        assert result.valid is False
        assert "mismatch" in result.error.lower()


class TestEdgeCases:
    """Test edge cases."""

    @pytest.fixture
    def key_pair(self, tmp_path):
        """Generate and save key pair."""
        dsa = MLDSA65()
        pk, sk = dsa.keygen()

        pk_file = tmp_path / "public.key"
        sk_file = tmp_path / "secret.key"
        pk_file.write_bytes(pk)
        sk_file.write_bytes(sk)

        return {"pk_file": pk_file, "sk_file": sk_file}

    def test_empty_payload(self, key_pair):
        """Test token with empty payload."""
        token = PQCToken.create(
            payload={},
            secret_key_path=key_pair["sk_file"],
        )

        result = PQCToken.verify(
            token=token,
            public_key_path=key_pair["pk_file"],
        )

        assert result.valid is True
        assert "iat" in result.payload

    def test_unicode_payload(self, key_pair):
        """Test token with unicode characters."""
        token = PQCToken.create(
            payload={"name": "Test User", "greeting": "Hello, 世界! 🌍"},
            secret_key_path=key_pair["sk_file"],
        )

        result = PQCToken.verify(
            token=token,
            public_key_path=key_pair["pk_file"],
        )

        assert result.valid is True
        assert result.payload["greeting"] == "Hello, 世界! 🌍"

    def test_nested_payload(self, key_pair):
        """Test token with nested JSON payload."""
        payload = {
            "user": {
                "id": "123",
                "name": "Test",
                "roles": ["admin", "user"],
            },
            "permissions": {
                "read": True,
                "write": True,
            },
        }

        token = PQCToken.create(
            payload=payload,
            secret_key_path=key_pair["sk_file"],
        )

        result = PQCToken.verify(
            token=token,
            public_key_path=key_pair["pk_file"],
        )

        assert result.valid is True
        assert result.payload["user"]["id"] == "123"
        assert result.payload["user"]["roles"] == ["admin", "user"]

    def test_large_payload(self, key_pair):
        """Test token with large payload."""
        large_data = "x" * 10000

        token = PQCToken.create(
            payload={"data": large_data},
            secret_key_path=key_pair["sk_file"],
        )

        result = PQCToken.verify(
            token=token,
            public_key_path=key_pair["pk_file"],
        )

        assert result.valid is True
        assert result.payload["data"] == large_data

    def test_numeric_claims(self, key_pair):
        """Test token with numeric claims."""
        token = PQCToken.create(
            payload={"count": 42, "price": 99.99, "negative": -10},
            secret_key_path=key_pair["sk_file"],
        )

        result = PQCToken.verify(
            token=token,
            public_key_path=key_pair["pk_file"],
        )

        assert result.valid is True
        assert result.payload["count"] == 42
        assert result.payload["price"] == 99.99
        assert result.payload["negative"] == -10

    def test_token_from_bytes_key(self, key_pair):
        """Test creating token from key bytes directly."""
        sk = key_pair["sk_file"].read_bytes()
        pk = key_pair["pk_file"].read_bytes()

        token = PQCToken.create(
            payload={"sub": "user123"},
            secret_key=sk,
        )

        result = PQCToken.verify(
            token=token,
            public_key=pk,
        )

        assert result.valid is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
