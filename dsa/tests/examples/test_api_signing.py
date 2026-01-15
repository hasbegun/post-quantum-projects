#!/usr/bin/env python3
"""
Test suite for API request signing use case.

Tests cover:
- Request signing with various methods
- Signature verification
- Timestamp validation
- Content hash verification
- Key rotation support
- Error handling
"""

import hashlib
import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import patch

import pytest

# Add paths for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src" / "python"))
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "examples" / "use-cases" / "api-signing"))

from mldsa import MLDSA44, MLDSA65, MLDSA87
from slhdsa import SLHDSA_SHAKE_128f

from sign_request import RequestSigner
from verify_request import RequestVerifier


class TestRequestSigning:
    """Test request signing functionality."""

    @pytest.fixture
    def mldsa65_keys(self):
        """Generate ML-DSA-65 key pair."""
        dsa = MLDSA65()
        pk, sk = dsa.keygen()
        return pk, sk

    @pytest.fixture
    def signer(self, tmp_path, mldsa65_keys):
        """Create a request signer."""
        pk, sk = mldsa65_keys
        sk_file = tmp_path / "secret.key"
        sk_file.write_bytes(sk)
        return RequestSigner(secret_key_path=sk_file)

    def test_sign_get_request(self, signer):
        """Test signing a simple GET request."""
        headers = signer.sign_request(
            method="GET",
            path="/api/v1/users",
        )

        assert "X-PQC-Date" in headers
        assert "X-PQC-Content-SHA256" in headers
        assert "X-PQC-Algorithm" in headers
        assert "Authorization" in headers

    def test_sign_post_request_with_body(self, signer):
        """Test signing a POST request with JSON body."""
        headers = signer.sign_request(
            method="POST",
            path="/api/v1/orders",
            headers={"Content-Type": "application/json"},
            body={"item": "widget", "quantity": 10},
        )

        assert "Authorization" in headers
        # Body hash should be non-empty hash
        assert len(headers["X-PQC-Content-SHA256"]) == 64

    def test_sign_with_query_params(self, signer):
        """Test signing with query parameters."""
        headers = signer.sign_request(
            method="GET",
            path="/api/v1/search",
            query_params={"q": "test", "page": "1"},
        )

        assert "Authorization" in headers

    def test_sign_with_host(self, signer):
        """Test signing with host header."""
        headers = signer.sign_request(
            method="GET",
            path="/api/v1/users",
            host="api.example.com",
        )

        assert "Authorization" in headers

    def test_sign_with_key_id(self, tmp_path, mldsa65_keys):
        """Test signing with custom key ID."""
        pk, sk = mldsa65_keys
        sk_file = tmp_path / "secret.key"
        sk_file.write_bytes(sk)

        signer = RequestSigner(
            secret_key_path=sk_file,
            key_id="my-service-v2",
        )

        headers = signer.sign_request(
            method="GET",
            path="/api/v1/users",
        )

        assert "KeyId=my-service-v2" in headers["Authorization"]

    def test_algorithm_in_header(self, signer):
        """Test algorithm is included in headers."""
        headers = signer.sign_request(
            method="GET",
            path="/api/v1/users",
        )

        assert headers["X-PQC-Algorithm"] == "mldsa65"
        assert "PQC-MLDSA65" in headers["Authorization"]


class TestRequestVerification:
    """Test request verification functionality."""

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

    @pytest.fixture
    def signed_request(self, key_pair):
        """Create a signed request."""
        signer = RequestSigner(secret_key_path=key_pair["sk_file"])

        body = {"item": "widget", "quantity": 10}
        headers = {"Content-Type": "application/json"}

        signed_headers = signer.sign_request(
            method="POST",
            path="/api/v1/orders",
            headers=headers,
            body=body,
            host="api.example.com",
        )

        # Combine original and signed headers
        all_headers = {**headers, **signed_headers, "Host": "api.example.com"}

        return {
            "method": "POST",
            "path": "/api/v1/orders",
            "headers": all_headers,
            "body": body,
            "pk_file": key_pair["pk_file"],
        }

    def test_verify_valid_request(self, signed_request):
        """Test verification of valid request."""
        verifier = RequestVerifier(public_key_path=signed_request["pk_file"])

        result = verifier.verify_request(
            method=signed_request["method"],
            path=signed_request["path"],
            headers=signed_request["headers"],
            body=signed_request["body"],
        )

        assert result.valid is True
        assert result.signature_valid is True
        assert result.timestamp_valid is True
        assert result.content_hash_valid is True

    def test_verify_tampered_body(self, signed_request):
        """Test detection of tampered body."""
        verifier = RequestVerifier(public_key_path=signed_request["pk_file"])

        # Modify body after signing
        tampered_body = {"item": "expensive-widget", "quantity": 100}

        result = verifier.verify_request(
            method=signed_request["method"],
            path=signed_request["path"],
            headers=signed_request["headers"],
            body=tampered_body,
        )

        assert result.valid is False
        assert result.content_hash_valid is False

    def test_verify_wrong_method(self, signed_request):
        """Test rejection of wrong HTTP method."""
        verifier = RequestVerifier(public_key_path=signed_request["pk_file"])

        result = verifier.verify_request(
            method="PUT",  # Wrong method
            path=signed_request["path"],
            headers=signed_request["headers"],
            body=signed_request["body"],
        )

        assert result.valid is False
        assert result.signature_valid is False

    def test_verify_wrong_path(self, signed_request):
        """Test rejection of wrong path."""
        verifier = RequestVerifier(public_key_path=signed_request["pk_file"])

        result = verifier.verify_request(
            method=signed_request["method"],
            path="/api/v1/other",  # Wrong path
            headers=signed_request["headers"],
            body=signed_request["body"],
        )

        assert result.valid is False
        assert result.signature_valid is False

    def test_verify_wrong_key(self, signed_request, tmp_path):
        """Test rejection with wrong public key."""
        # Generate different key pair
        dsa = MLDSA65()
        wrong_pk, _ = dsa.keygen()

        wrong_pk_file = tmp_path / "wrong_public.key"
        wrong_pk_file.write_bytes(wrong_pk)

        verifier = RequestVerifier(public_key_path=wrong_pk_file)

        result = verifier.verify_request(
            method=signed_request["method"],
            path=signed_request["path"],
            headers=signed_request["headers"],
            body=signed_request["body"],
        )

        assert result.valid is False
        assert result.signature_valid is False


class TestTimestampValidation:
    """Test timestamp validation."""

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

    def test_expired_timestamp(self, key_pair):
        """Test rejection of expired timestamp."""
        signer = RequestSigner(secret_key_path=key_pair["sk_file"])

        # Sign request
        signed_headers = signer.sign_request(
            method="GET",
            path="/api/v1/users",
        )

        # Modify timestamp to be old
        old_time = (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime("%Y%m%dT%H%M%SZ")
        signed_headers["X-PQC-Date"] = old_time

        verifier = RequestVerifier(public_key_path=key_pair["pk_file"])

        result = verifier.verify_request(
            method="GET",
            path="/api/v1/users",
            headers=signed_headers,
        )

        assert result.timestamp_valid is False

    def test_future_timestamp(self, key_pair):
        """Test rejection of future timestamp."""
        signer = RequestSigner(secret_key_path=key_pair["sk_file"])

        # Sign request
        signed_headers = signer.sign_request(
            method="GET",
            path="/api/v1/users",
        )

        # Modify timestamp to be in future
        future_time = (datetime.now(timezone.utc) + timedelta(minutes=10)).strftime("%Y%m%dT%H%M%SZ")
        signed_headers["X-PQC-Date"] = future_time

        verifier = RequestVerifier(public_key_path=key_pair["pk_file"])

        result = verifier.verify_request(
            method="GET",
            path="/api/v1/users",
            headers=signed_headers,
        )

        assert result.timestamp_valid is False

    def test_custom_max_age(self, key_pair):
        """Test custom maximum timestamp age."""
        signer = RequestSigner(secret_key_path=key_pair["sk_file"])

        signed_headers = signer.sign_request(
            method="GET",
            path="/api/v1/users",
        )

        # Use verifier with 1 minute max age
        verifier = RequestVerifier(
            public_key_path=key_pair["pk_file"],
            max_timestamp_age=timedelta(minutes=1),
        )

        # Recent request should be valid
        result = verifier.verify_request(
            method="GET",
            path="/api/v1/users",
            headers=signed_headers,
        )

        assert result.timestamp_valid is True


class TestMultipleAlgorithms:
    """Test with different algorithms."""

    @pytest.mark.parametrize("algorithm,dsa_class", [
        ("mldsa44", MLDSA44),
        ("mldsa65", MLDSA65),
        ("mldsa87", MLDSA87),
    ])
    def test_mldsa_algorithms(self, tmp_path, algorithm, dsa_class):
        """Test signing and verification with ML-DSA algorithms."""
        dsa = dsa_class()
        pk, sk = dsa.keygen()

        pk_file = tmp_path / "public.key"
        sk_file = tmp_path / "secret.key"
        pk_file.write_bytes(pk)
        sk_file.write_bytes(sk)

        signer = RequestSigner(secret_key_path=sk_file, algorithm=algorithm)
        verifier = RequestVerifier(public_key_path=pk_file, algorithm=algorithm)

        signed_headers = signer.sign_request(
            method="POST",
            path="/api/v1/test",
            body={"test": True},
        )

        result = verifier.verify_request(
            method="POST",
            path="/api/v1/test",
            headers=signed_headers,
            body={"test": True},
        )

        assert result.valid is True

    def test_slhdsa_algorithm(self, tmp_path):
        """Test with SLH-DSA algorithm."""
        dsa = SLHDSA_SHAKE_128f()
        # SLH-DSA keygen returns (pk, sk) - different from ML-DSA
        pk, sk = dsa.keygen()

        pk_file = tmp_path / "public.key"
        sk_file = tmp_path / "secret.key"
        pk_file.write_bytes(pk)
        sk_file.write_bytes(sk)

        signer = RequestSigner(
            secret_key_path=sk_file,
            algorithm="slh-shake-128f",
        )
        verifier = RequestVerifier(
            public_key_path=pk_file,
            algorithm="slh-shake-128f",
        )

        signed_headers = signer.sign_request(
            method="GET",
            path="/api/v1/test",
        )

        result = verifier.verify_request(
            method="GET",
            path="/api/v1/test",
            headers=signed_headers,
        )

        assert result.valid is True


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

    def test_empty_body(self, key_pair):
        """Test request with no body."""
        signer = RequestSigner(secret_key_path=key_pair["sk_file"])
        verifier = RequestVerifier(public_key_path=key_pair["pk_file"])

        signed_headers = signer.sign_request(
            method="DELETE",
            path="/api/v1/users/123",
        )

        result = verifier.verify_request(
            method="DELETE",
            path="/api/v1/users/123",
            headers=signed_headers,
        )

        assert result.valid is True

    def test_binary_body(self, key_pair):
        """Test request with binary body."""
        signer = RequestSigner(secret_key_path=key_pair["sk_file"])
        verifier = RequestVerifier(public_key_path=key_pair["pk_file"])

        binary_body = bytes(range(256))

        signed_headers = signer.sign_request(
            method="POST",
            path="/api/v1/upload",
            headers={"Content-Type": "application/octet-stream"},
            body=binary_body,
        )

        all_headers = {"Content-Type": "application/octet-stream", **signed_headers}

        result = verifier.verify_request(
            method="POST",
            path="/api/v1/upload",
            headers=all_headers,
            body=binary_body,
        )

        assert result.valid is True

    def test_unicode_body(self, key_pair):
        """Test request with unicode body."""
        signer = RequestSigner(secret_key_path=key_pair["sk_file"])
        verifier = RequestVerifier(public_key_path=key_pair["pk_file"])

        body = {"message": "Hello, 世界! 🌍"}

        signed_headers = signer.sign_request(
            method="POST",
            path="/api/v1/messages",
            headers={"Content-Type": "application/json"},
            body=body,
        )

        all_headers = {"Content-Type": "application/json", **signed_headers}

        result = verifier.verify_request(
            method="POST",
            path="/api/v1/messages",
            headers=all_headers,
            body=body,
        )

        assert result.valid is True

    def test_special_path_characters(self, key_pair):
        """Test path with special characters."""
        signer = RequestSigner(secret_key_path=key_pair["sk_file"])
        verifier = RequestVerifier(public_key_path=key_pair["pk_file"])

        path = "/api/v1/users/john@example.com/profile"

        signed_headers = signer.sign_request(
            method="GET",
            path=path,
        )

        result = verifier.verify_request(
            method="GET",
            path=path,
            headers=signed_headers,
        )

        assert result.valid is True


class TestErrorHandling:
    """Test error handling."""

    def test_missing_authorization_header(self, tmp_path):
        """Test handling of missing Authorization header."""
        dsa = MLDSA65()
        pk, _ = dsa.keygen()

        pk_file = tmp_path / "public.key"
        pk_file.write_bytes(pk)

        verifier = RequestVerifier(public_key_path=pk_file)

        result = verifier.verify_request(
            method="GET",
            path="/api/v1/users",
            headers={},  # No Authorization
        )

        assert result.valid is False
        assert "Authorization" in result.error

    def test_missing_timestamp_header(self, tmp_path):
        """Test handling of missing timestamp header."""
        dsa = MLDSA65()
        pk, _ = dsa.keygen()

        pk_file = tmp_path / "public.key"
        pk_file.write_bytes(pk)

        verifier = RequestVerifier(public_key_path=pk_file)

        result = verifier.verify_request(
            method="GET",
            path="/api/v1/users",
            headers={"Authorization": "PQC-MLDSA65 KeyId=x, SignedHeaders=x, Signature=abc"},
        )

        assert result.valid is False
        assert "Date" in result.error

    def test_invalid_key_file(self, tmp_path):
        """Test handling of invalid key file."""
        with pytest.raises(FileNotFoundError):
            RequestSigner(secret_key_path=tmp_path / "nonexistent.key")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
