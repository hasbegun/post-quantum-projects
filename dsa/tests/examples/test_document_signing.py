#!/usr/bin/env python3
"""
Test suite for document signing use case.

Tests cover:
- Document signing with various algorithms
- Signature verification
- Signer identity handling
- Signing details (reason, location)
- Integrity verification
- Error handling
"""

import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

# Add paths for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src" / "python"))
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "examples" / "use-cases" / "document-signing"))

from mldsa import MLDSA44, MLDSA65, MLDSA87
from slhdsa import SLHDSA_SHAKE_128f, SLHDSA_SHAKE_256f

from sign_document import sign_document, compute_document_hash, get_document_metadata
from verify_document import verify_document


class TestDocumentHashing:
    """Test document hashing functions."""

    def test_hash_simple_document(self, tmp_path):
        """Test hashing a simple document."""
        doc = tmp_path / "test.txt"
        doc.write_text("Hello, World!")

        sha256_hash, sha512_hash = compute_document_hash(doc)

        assert len(sha256_hash) == 64  # 256 bits = 64 hex chars
        assert len(sha512_hash) == 128  # 512 bits = 128 hex chars

    def test_hash_binary_document(self, tmp_path):
        """Test hashing a binary document."""
        doc = tmp_path / "test.bin"
        doc.write_bytes(bytes(range(256)))

        sha256_hash, sha512_hash = compute_document_hash(doc)

        # Verify hash is consistent
        expected_sha256 = hashlib.sha256(bytes(range(256))).hexdigest()
        assert sha256_hash == expected_sha256

    def test_hash_large_document(self, tmp_path):
        """Test hashing a large document (tests chunking)."""
        doc = tmp_path / "large.bin"
        # Write 1MB of data
        doc.write_bytes(b"x" * (1024 * 1024))

        sha256_hash, sha512_hash = compute_document_hash(doc)

        assert len(sha256_hash) == 64
        assert len(sha512_hash) == 128


class TestDocumentMetadata:
    """Test document metadata extraction."""

    def test_metadata_extraction(self, tmp_path):
        """Test basic metadata extraction."""
        doc = tmp_path / "document.pdf"
        doc.write_text("PDF content")

        metadata = get_document_metadata(doc)

        assert metadata["name"] == "document.pdf"
        assert metadata["size"] == len("PDF content")
        assert "modified" in metadata


class TestSignDocument:
    """Test document signing functionality."""

    @pytest.fixture
    def mldsa65_keys(self):
        """Generate ML-DSA-65 key pair."""
        dsa = MLDSA65()
        pk, sk = dsa.keygen()
        return pk, sk

    @pytest.fixture
    def test_document(self, tmp_path):
        """Create a test document."""
        doc = tmp_path / "contract.pdf"
        doc.write_text("This is a test contract document.")
        return doc

    def test_sign_document_basic(self, tmp_path, mldsa65_keys, test_document):
        """Test basic document signing."""
        pk, sk = mldsa65_keys

        # Write key
        key_file = tmp_path / "secret.key"
        key_file.write_bytes(sk)

        manifest = sign_document(
            key_path=key_file,
            document_path=test_document,
            quiet=True,
        )

        assert manifest["type"] == "document-signature"
        assert manifest["algorithm"]["id"] == "mldsa65"
        assert "signature" in manifest
        assert "document" in manifest
        assert manifest["document"]["name"] == "contract.pdf"

    def test_sign_with_signer_identity(self, tmp_path, mldsa65_keys, test_document):
        """Test signing with signer identity."""
        pk, sk = mldsa65_keys

        key_file = tmp_path / "secret.key"
        key_file.write_bytes(sk)

        manifest = sign_document(
            key_path=key_file,
            document_path=test_document,
            signer_name="John Doe",
            signer_email="john@example.com",
            signer_org="Legal Department",
            quiet=True,
        )

        assert "signer" in manifest
        assert manifest["signer"]["name"] == "John Doe"
        assert manifest["signer"]["email"] == "john@example.com"
        assert manifest["signer"]["organization"] == "Legal Department"

    def test_sign_with_reason_and_location(self, tmp_path, mldsa65_keys, test_document):
        """Test signing with reason and location."""
        pk, sk = mldsa65_keys

        key_file = tmp_path / "secret.key"
        key_file.write_bytes(sk)

        manifest = sign_document(
            key_path=key_file,
            document_path=test_document,
            reason="Contract approval",
            location="New York, NY",
            quiet=True,
        )

        assert "signing_details" in manifest
        assert manifest["signing_details"]["reason"] == "Contract approval"
        assert manifest["signing_details"]["location"] == "New York, NY"

    def test_sign_with_custom_output(self, tmp_path, mldsa65_keys, test_document):
        """Test signing with custom output path."""
        pk, sk = mldsa65_keys

        key_file = tmp_path / "secret.key"
        key_file.write_bytes(sk)

        output_file = tmp_path / "custom.sig"

        manifest = sign_document(
            key_path=key_file,
            document_path=test_document,
            output_path=output_file,
            quiet=True,
        )

        assert output_file.exists()

    def test_sign_with_context(self, tmp_path, mldsa65_keys, test_document):
        """Test signing with custom context."""
        pk, sk = mldsa65_keys

        key_file = tmp_path / "secret.key"
        key_file.write_bytes(sk)

        manifest = sign_document(
            key_path=key_file,
            document_path=test_document,
            context="legal-contracts",
            quiet=True,
        )

        assert manifest["signature"]["context"] == "legal-contracts".encode().hex()


class TestVerifyDocument:
    """Test document signature verification."""

    @pytest.fixture
    def signed_document(self, tmp_path):
        """Create and sign a test document."""
        dsa = MLDSA65()
        pk, sk = dsa.keygen()

        pk_file = tmp_path / "public.key"
        sk_file = tmp_path / "secret.key"
        pk_file.write_bytes(pk)
        sk_file.write_bytes(sk)

        doc = tmp_path / "document.txt"
        doc.write_text("This is a test document for verification.")

        manifest = sign_document(
            key_path=sk_file,
            document_path=doc,
            signer_name="Test Signer",
            reason="Testing",
            quiet=True,
        )

        return {
            "pk_file": pk_file,
            "sk_file": sk_file,
            "doc": doc,
            "sig_file": doc.with_suffix(doc.suffix + ".docsig"),
            "manifest": manifest,
        }

    def test_verify_valid_signature(self, signed_document):
        """Test verification of valid signature."""
        result = verify_document(
            key_path=signed_document["pk_file"],
            document_path=signed_document["doc"],
            quiet=True,
        )

        assert result["valid"] is True
        assert result["checks"]["hash"] is True
        assert result["checks"]["size"] is True
        assert result["checks"]["signature"] is True

    def test_verify_modified_document(self, signed_document):
        """Test detection of modified document."""
        # Modify the document after signing
        signed_document["doc"].write_text("This document has been modified!")

        result = verify_document(
            key_path=signed_document["pk_file"],
            document_path=signed_document["doc"],
            quiet=True,
        )

        assert result["valid"] is False
        assert result["checks"]["hash"] is False

    def test_verify_wrong_key(self, signed_document, tmp_path):
        """Test rejection with wrong public key."""
        # Generate different key pair
        dsa = MLDSA65()
        wrong_pk, _ = dsa.keygen()

        wrong_key_file = tmp_path / "wrong_public.key"
        wrong_key_file.write_bytes(wrong_pk)

        result = verify_document(
            key_path=wrong_key_file,
            document_path=signed_document["doc"],
            quiet=True,
        )

        assert result["valid"] is False
        assert result["checks"]["signature"] is False

    def test_verify_extracts_signer_info(self, signed_document):
        """Test that verification extracts signer information."""
        result = verify_document(
            key_path=signed_document["pk_file"],
            document_path=signed_document["doc"],
            quiet=True,
        )

        assert result["signer"]["name"] == "Test Signer"
        assert result["signing_details"]["reason"] == "Testing"


class TestMultipleAlgorithms:
    """Test document signing with different algorithms."""

    @pytest.mark.parametrize("algorithm,dsa_class", [
        ("mldsa44", MLDSA44),
        ("mldsa65", MLDSA65),
        ("mldsa87", MLDSA87),
    ])
    def test_mldsa_algorithms(self, tmp_path, algorithm, dsa_class):
        """Test signing with ML-DSA algorithms."""
        dsa = dsa_class()
        pk, sk = dsa.keygen()

        pk_file = tmp_path / "public.key"
        sk_file = tmp_path / "secret.key"
        pk_file.write_bytes(pk)
        sk_file.write_bytes(sk)

        doc = tmp_path / "document.txt"
        doc.write_text(f"Document for {algorithm}")

        manifest = sign_document(
            key_path=sk_file,
            document_path=doc,
            algorithm=algorithm,
            quiet=True,
        )

        assert manifest["algorithm"]["id"] == algorithm

        result = verify_document(
            key_path=pk_file,
            document_path=doc,
            quiet=True,
        )

        assert result["valid"] is True

    def test_slhdsa_algorithm(self, tmp_path):
        """Test signing with SLH-DSA algorithm."""
        dsa = SLHDSA_SHAKE_128f()
        # SLH-DSA keygen returns (pk, sk) - different from ML-DSA
        pk, sk = dsa.keygen()

        pk_file = tmp_path / "public.key"
        sk_file = tmp_path / "secret.key"
        pk_file.write_bytes(pk)
        sk_file.write_bytes(sk)

        doc = tmp_path / "document.txt"
        doc.write_text("Document for SLH-DSA")

        manifest = sign_document(
            key_path=sk_file,
            document_path=doc,
            algorithm="slh-shake-128f",
            quiet=True,
        )

        assert manifest["algorithm"]["id"] == "slh-shake-128f"

        result = verify_document(
            key_path=pk_file,
            document_path=doc,
            quiet=True,
        )

        assert result["valid"] is True


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_document(self, tmp_path):
        """Test signing an empty document."""
        dsa = MLDSA65()
        pk, sk = dsa.keygen()

        sk_file = tmp_path / "secret.key"
        sk_file.write_bytes(sk)

        doc = tmp_path / "empty.txt"
        doc.write_text("")

        manifest = sign_document(
            key_path=sk_file,
            document_path=doc,
            quiet=True,
        )

        assert manifest["document"]["size"] == 0

    def test_unicode_signer_name(self, tmp_path):
        """Test signing with unicode signer name."""
        dsa = MLDSA65()
        pk, sk = dsa.keygen()

        pk_file = tmp_path / "public.key"
        sk_file = tmp_path / "secret.key"
        pk_file.write_bytes(pk)
        sk_file.write_bytes(sk)

        doc = tmp_path / "document.txt"
        doc.write_text("Test document")

        manifest = sign_document(
            key_path=sk_file,
            document_path=doc,
            signer_name="Jean-Pierre Müller",
            quiet=True,
        )

        assert manifest["signer"]["name"] == "Jean-Pierre Müller"

        result = verify_document(
            key_path=pk_file,
            document_path=doc,
            quiet=True,
        )

        assert result["valid"] is True

    def test_special_characters_in_filename(self, tmp_path):
        """Test document with special characters in filename."""
        dsa = MLDSA65()
        pk, sk = dsa.keygen()

        pk_file = tmp_path / "public.key"
        sk_file = tmp_path / "secret.key"
        pk_file.write_bytes(pk)
        sk_file.write_bytes(sk)

        doc = tmp_path / "contract (2024) - final.pdf"
        doc.write_text("Test content")

        manifest = sign_document(
            key_path=sk_file,
            document_path=doc,
            quiet=True,
        )

        assert "contract (2024) - final.pdf" in manifest["document"]["name"]

        result = verify_document(
            key_path=pk_file,
            document_path=doc,
            quiet=True,
        )

        assert result["valid"] is True

    def test_long_reason_text(self, tmp_path):
        """Test signing with very long reason text."""
        dsa = MLDSA65()
        pk, sk = dsa.keygen()

        pk_file = tmp_path / "public.key"
        sk_file = tmp_path / "secret.key"
        pk_file.write_bytes(pk)
        sk_file.write_bytes(sk)

        doc = tmp_path / "document.txt"
        doc.write_text("Test document")

        long_reason = "A" * 1000  # Very long reason

        manifest = sign_document(
            key_path=sk_file,
            document_path=doc,
            reason=long_reason,
            quiet=True,
        )

        assert manifest["signing_details"]["reason"] == long_reason

        result = verify_document(
            key_path=pk_file,
            document_path=doc,
            quiet=True,
        )

        assert result["valid"] is True


class TestErrorHandling:
    """Test error handling."""

    def test_nonexistent_key_file(self, tmp_path):
        """Test handling of missing key file."""
        doc = tmp_path / "document.txt"
        doc.write_text("Test")

        with pytest.raises(FileNotFoundError):
            sign_document(
                key_path=tmp_path / "nonexistent.key",
                document_path=doc,
                quiet=True,
            )

    def test_nonexistent_document(self, tmp_path):
        """Test handling of missing document."""
        dsa = MLDSA65()
        _, sk = dsa.keygen()

        sk_file = tmp_path / "secret.key"
        sk_file.write_bytes(sk)

        with pytest.raises(FileNotFoundError):
            sign_document(
                key_path=sk_file,
                document_path=tmp_path / "nonexistent.pdf",
                quiet=True,
            )

    def test_invalid_algorithm(self, tmp_path):
        """Test handling of invalid algorithm."""
        dsa = MLDSA65()
        _, sk = dsa.keygen()

        sk_file = tmp_path / "secret.key"
        sk_file.write_bytes(sk)

        doc = tmp_path / "document.txt"
        doc.write_text("Test")

        with pytest.raises(ValueError, match="Unknown algorithm"):
            sign_document(
                key_path=sk_file,
                document_path=doc,
                algorithm="invalid-algo",
                quiet=True,
            )


class TestTimestamp:
    """Test timestamp handling."""

    def test_timestamp_format(self, tmp_path):
        """Test timestamp is in ISO 8601 format."""
        dsa = MLDSA65()
        _, sk = dsa.keygen()

        sk_file = tmp_path / "secret.key"
        sk_file.write_bytes(sk)

        doc = tmp_path / "document.txt"
        doc.write_text("Test")

        manifest = sign_document(
            key_path=sk_file,
            document_path=doc,
            quiet=True,
        )

        timestamp = manifest["timestamp"]

        # Should be parseable as ISO 8601
        dt = datetime.fromisoformat(timestamp)
        assert dt is not None

    def test_timestamp_in_verification(self, tmp_path):
        """Test timestamp is available in verification result."""
        dsa = MLDSA65()
        pk, sk = dsa.keygen()

        pk_file = tmp_path / "public.key"
        sk_file = tmp_path / "secret.key"
        pk_file.write_bytes(pk)
        sk_file.write_bytes(sk)

        doc = tmp_path / "document.txt"
        doc.write_text("Test")

        sign_document(
            key_path=sk_file,
            document_path=doc,
            quiet=True,
        )

        result = verify_document(
            key_path=pk_file,
            document_path=doc,
            quiet=True,
        )

        assert result["timestamp"] is not None
        # Should be parseable
        dt = datetime.fromisoformat(result["timestamp"])
        assert dt is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
