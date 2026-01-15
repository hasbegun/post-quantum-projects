#!/usr/bin/env python3
"""
Comprehensive tests for Post-Quantum Code Signing.

These tests verify:
1. Basic signing and verification workflow
2. All supported algorithms
3. Error handling and edge cases
4. Security properties
5. File integrity validation
6. Signature format compliance

Run with:
    pytest tests/examples/test_code_signing.py -v
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

# Add examples path for code signing tools (but not src/py to avoid overriding installed modules)
examples_path = str(Path(__file__).parent.parent.parent / "examples" / "use-cases" / "code-signing")
if examples_path not in sys.path:
    sys.path.insert(0, examples_path)

from mldsa import MLDSA44, MLDSA65, MLDSA87
from slhdsa import SLHDSA_SHAKE_128f

# Import the signing/verification modules
from sign_release import (
    compute_file_hash,
    detect_algorithm,
    sign_file,
    ALGORITHMS,
)
from verify_release import (
    verify_file_integrity,
    verify_signature,
    load_signature,
    VerificationError,
    IntegrityError,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_file(temp_dir):
    """Create a sample file to sign."""
    filepath = temp_dir / "sample-release-1.0.0.tar.gz"
    # Create a file with known content
    content = b"This is a sample release file for testing.\n" * 100
    filepath.write_bytes(content)
    return filepath


@pytest.fixture
def large_file(temp_dir):
    """Create a large file (1MB) to test chunked hashing."""
    filepath = temp_dir / "large-release.bin"
    # Create 1MB file
    content = os.urandom(1024 * 1024)
    filepath.write_bytes(content)
    return filepath


@pytest.fixture
def mldsa44_keys():
    """Generate ML-DSA-44 key pair."""
    dsa = MLDSA44()
    pk, sk = dsa.keygen()
    return {"public": pk, "secret": sk, "algorithm": "mldsa44"}


@pytest.fixture
def mldsa65_keys():
    """Generate ML-DSA-65 key pair."""
    dsa = MLDSA65()
    pk, sk = dsa.keygen()
    return {"public": pk, "secret": sk, "algorithm": "mldsa65"}


@pytest.fixture
def mldsa87_keys():
    """Generate ML-DSA-87 key pair."""
    dsa = MLDSA87()
    pk, sk = dsa.keygen()
    return {"public": pk, "secret": sk, "algorithm": "mldsa87"}


@pytest.fixture
def slhdsa_keys():
    """Generate SLH-DSA key pair."""
    dsa = SLHDSA_SHAKE_128f()
    pk, sk = dsa.keygen()
    return {"public": pk, "secret": sk, "algorithm": "slh-shake-128f"}


# =============================================================================
# File Hash Tests
# =============================================================================

class TestFileHashing:
    """Tests for file hash computation."""

    def test_hash_computation(self, sample_file):
        """Test basic SHA-256 hash computation."""
        file_hash = compute_file_hash(sample_file)

        # Verify it's a valid hex string
        assert len(file_hash) == 64
        assert all(c in "0123456789abcdef" for c in file_hash)

        # Verify against standard library
        expected = hashlib.sha256(sample_file.read_bytes()).hexdigest()
        assert file_hash == expected

    def test_hash_deterministic(self, sample_file):
        """Test that hash is deterministic."""
        hash1 = compute_file_hash(sample_file)
        hash2 = compute_file_hash(sample_file)
        assert hash1 == hash2

    def test_hash_large_file(self, large_file):
        """Test hash computation for large files (chunked reading)."""
        file_hash = compute_file_hash(large_file)

        # Verify against standard library
        expected = hashlib.sha256(large_file.read_bytes()).hexdigest()
        assert file_hash == expected

    def test_hash_different_files(self, temp_dir):
        """Test that different files produce different hashes."""
        file1 = temp_dir / "file1.txt"
        file2 = temp_dir / "file2.txt"

        file1.write_bytes(b"content A")
        file2.write_bytes(b"content B")

        hash1 = compute_file_hash(file1)
        hash2 = compute_file_hash(file2)

        assert hash1 != hash2

    def test_hash_empty_file(self, temp_dir):
        """Test hash of empty file."""
        empty_file = temp_dir / "empty.txt"
        empty_file.write_bytes(b"")

        file_hash = compute_file_hash(empty_file)

        # SHA-256 of empty string
        expected = hashlib.sha256(b"").hexdigest()
        assert file_hash == expected


# =============================================================================
# Algorithm Detection Tests
# =============================================================================

class TestAlgorithmDetection:
    """Tests for automatic algorithm detection from key size."""

    def test_detect_mldsa44(self, mldsa44_keys):
        """Test ML-DSA-44 detection from secret key."""
        detected = detect_algorithm(mldsa44_keys["secret"])
        assert detected == "mldsa44"

    def test_detect_mldsa65(self, mldsa65_keys):
        """Test ML-DSA-65 detection from secret key."""
        detected = detect_algorithm(mldsa65_keys["secret"])
        assert detected == "mldsa65"

    def test_detect_mldsa87(self, mldsa87_keys):
        """Test ML-DSA-87 detection from secret key."""
        detected = detect_algorithm(mldsa87_keys["secret"])
        assert detected == "mldsa87"

    def test_detect_unknown_size(self):
        """Test detection fails for unknown key size."""
        unknown_key = os.urandom(1234)  # Not a valid key size
        with pytest.raises(ValueError, match="Cannot detect algorithm"):
            detect_algorithm(unknown_key)


# =============================================================================
# Signing Tests
# =============================================================================

class TestSigning:
    """Tests for file signing functionality."""

    def test_sign_basic(self, sample_file, mldsa65_keys):
        """Test basic file signing."""
        sig_doc = sign_file(
            filepath=sample_file,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            signer_info={"common_name": "Test Signer"},
        )

        # Verify structure
        assert sig_doc["version"] == "1.0"
        assert sig_doc["type"] == "code-signature"
        assert sig_doc["algorithm"]["id"] == "mldsa65"
        assert sig_doc["algorithm"]["name"] == "ML-DSA-65"
        assert sig_doc["file"]["name"] == sample_file.name
        assert "signature" in sig_doc
        assert "timestamp" in sig_doc

    def test_sign_with_context(self, sample_file, mldsa65_keys):
        """Test signing with context string."""
        context = b"release-v1"
        sig_doc = sign_file(
            filepath=sample_file,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            signer_info={},
            context=context,
        )

        assert sig_doc["signature"]["context"] == context.hex()

    def test_sign_all_mldsa_algorithms(self, sample_file, mldsa44_keys, mldsa65_keys, mldsa87_keys):
        """Test signing with all ML-DSA algorithms."""
        for keys in [mldsa44_keys, mldsa65_keys, mldsa87_keys]:
            sig_doc = sign_file(
                filepath=sample_file,
                secret_key=keys["secret"],
                algorithm=keys["algorithm"],
                signer_info={},
            )
            assert sig_doc["algorithm"]["id"] == keys["algorithm"]

    def test_sign_slhdsa(self, sample_file, slhdsa_keys):
        """Test signing with SLH-DSA."""
        sig_doc = sign_file(
            filepath=sample_file,
            secret_key=slhdsa_keys["secret"],
            algorithm="slh-shake-128f",
            signer_info={},
        )
        assert sig_doc["algorithm"]["id"] == "slh-shake-128f"
        assert sig_doc["algorithm"]["standard"] == "FIPS 205"

    def test_sign_preserves_file_info(self, sample_file, mldsa65_keys):
        """Test that signature preserves accurate file information."""
        sig_doc = sign_file(
            filepath=sample_file,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            signer_info={},
        )

        assert sig_doc["file"]["name"] == sample_file.name
        assert sig_doc["file"]["size"] == sample_file.stat().st_size
        assert sig_doc["file"]["hash"]["algorithm"] == "sha256"
        assert sig_doc["file"]["hash"]["value"] == compute_file_hash(sample_file)

    def test_sign_invalid_algorithm(self, sample_file, mldsa65_keys):
        """Test signing with invalid algorithm fails."""
        with pytest.raises(ValueError, match="Unknown algorithm"):
            sign_file(
                filepath=sample_file,
                secret_key=mldsa65_keys["secret"],
                algorithm="invalid-algo",
                signer_info={},
            )

    def test_sign_timestamp_format(self, sample_file, mldsa65_keys):
        """Test that timestamp is valid ISO 8601."""
        sig_doc = sign_file(
            filepath=sample_file,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            signer_info={},
        )

        timestamp = sig_doc["timestamp"]
        # Should be parseable
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        assert dt is not None

    def test_sign_different_files_different_signatures(self, temp_dir, mldsa65_keys):
        """Test that different files produce different signatures."""
        file1 = temp_dir / "file1.bin"
        file2 = temp_dir / "file2.bin"
        file1.write_bytes(b"content A")
        file2.write_bytes(b"content B")

        sig1 = sign_file(file1, mldsa65_keys["secret"], "mldsa65", {})
        sig2 = sign_file(file2, mldsa65_keys["secret"], "mldsa65", {})

        assert sig1["signature"]["value"] != sig2["signature"]["value"]


# =============================================================================
# Verification Tests
# =============================================================================

class TestVerification:
    """Tests for signature verification functionality."""

    def test_verify_valid_signature(self, sample_file, mldsa65_keys):
        """Test verification of valid signature."""
        sig_doc = sign_file(
            filepath=sample_file,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            signer_info={"common_name": "Test"},
        )

        result = verify_signature(sample_file, sig_doc, mldsa65_keys["public"])

        assert result["algorithm"] == "ML-DSA-65"
        assert "timestamp" in result

    def test_verify_all_algorithms(self, sample_file, mldsa44_keys, mldsa65_keys, mldsa87_keys, slhdsa_keys):
        """Test verification with all supported algorithms."""
        all_keys = [mldsa44_keys, mldsa65_keys, mldsa87_keys, slhdsa_keys]

        for keys in all_keys:
            sig_doc = sign_file(
                filepath=sample_file,
                secret_key=keys["secret"],
                algorithm=keys["algorithm"],
                signer_info={},
            )
            result = verify_signature(sample_file, sig_doc, keys["public"])
            assert result is not None

    def test_verify_wrong_public_key(self, sample_file, mldsa65_keys):
        """Test verification fails with wrong public key."""
        # Sign with one key
        sig_doc = sign_file(
            filepath=sample_file,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            signer_info={},
        )

        # Generate different key pair
        dsa = MLDSA65()
        wrong_pk, _ = dsa.keygen()

        # Verification should fail
        with pytest.raises(VerificationError):
            verify_signature(sample_file, sig_doc, wrong_pk)

    def test_verify_tampered_signature(self, sample_file, mldsa65_keys):
        """Test verification fails if signature is tampered."""
        sig_doc = sign_file(
            filepath=sample_file,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            signer_info={},
        )

        # Tamper with signature
        sig_bytes = bytes.fromhex(sig_doc["signature"]["value"])
        tampered = bytes([sig_bytes[0] ^ 0xFF]) + sig_bytes[1:]
        sig_doc["signature"]["value"] = tampered.hex()

        with pytest.raises(VerificationError):
            verify_signature(sample_file, sig_doc, mldsa65_keys["public"])

    def test_verify_with_context(self, sample_file, mldsa65_keys):
        """Test verification with context string."""
        context = b"test-context"
        sig_doc = sign_file(
            filepath=sample_file,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            signer_info={},
            context=context,
        )

        result = verify_signature(sample_file, sig_doc, mldsa65_keys["public"])
        assert result is not None


# =============================================================================
# File Integrity Tests
# =============================================================================

class TestFileIntegrity:
    """Tests for file integrity verification."""

    def test_integrity_valid_file(self, sample_file, mldsa65_keys):
        """Test integrity check passes for unmodified file."""
        sig_doc = sign_file(
            filepath=sample_file,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            signer_info={},
        )

        # Should not raise
        verify_file_integrity(sample_file, sig_doc)

    def test_integrity_modified_file(self, sample_file, mldsa65_keys):
        """Test integrity check fails for modified file."""
        sig_doc = sign_file(
            filepath=sample_file,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            signer_info={},
        )

        # Modify the file
        original_content = sample_file.read_bytes()
        sample_file.write_bytes(original_content + b"MODIFIED")

        # Could fail on either size mismatch or hash mismatch
        with pytest.raises(IntegrityError, match="(hash mismatch|size mismatch)"):
            verify_file_integrity(sample_file, sig_doc)

    def test_integrity_size_mismatch(self, sample_file, mldsa65_keys):
        """Test integrity check detects size changes."""
        sig_doc = sign_file(
            filepath=sample_file,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            signer_info={},
        )

        # Truncate the file
        sample_file.write_bytes(b"short")

        with pytest.raises(IntegrityError, match="size mismatch"):
            verify_file_integrity(sample_file, sig_doc)

    def test_integrity_missing_file(self, sample_file, mldsa65_keys, temp_dir):
        """Test integrity check fails for missing file."""
        sig_doc = sign_file(
            filepath=sample_file,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            signer_info={},
        )

        missing_file = temp_dir / "nonexistent.bin"

        with pytest.raises(IntegrityError, match="not found"):
            verify_file_integrity(missing_file, sig_doc)


# =============================================================================
# Signature Format Tests
# =============================================================================

class TestSignatureFormat:
    """Tests for signature file format compliance."""

    def test_signature_json_valid(self, sample_file, mldsa65_keys, temp_dir):
        """Test signature file is valid JSON."""
        sig_doc = sign_file(
            filepath=sample_file,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            signer_info={},
        )

        sig_path = temp_dir / "test.sig"
        with open(sig_path, "w") as f:
            json.dump(sig_doc, f)

        # Should be loadable
        loaded = load_signature(sig_path)
        assert loaded == sig_doc

    def test_signature_required_fields(self, sample_file, mldsa65_keys):
        """Test signature contains all required fields."""
        sig_doc = sign_file(
            filepath=sample_file,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            signer_info={},
        )

        required_fields = ["version", "type", "algorithm", "file", "signature", "timestamp"]
        for field in required_fields:
            assert field in sig_doc, f"Missing required field: {field}"

        # Algorithm subfields
        assert "id" in sig_doc["algorithm"]
        assert "name" in sig_doc["algorithm"]

        # File subfields
        assert "name" in sig_doc["file"]
        assert "size" in sig_doc["file"]
        assert "hash" in sig_doc["file"]

        # Signature subfields
        assert "value" in sig_doc["signature"]
        assert "encoding" in sig_doc["signature"]

    def test_signature_hex_encoding(self, sample_file, mldsa65_keys):
        """Test signature value is valid hex."""
        sig_doc = sign_file(
            filepath=sample_file,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            signer_info={},
        )

        sig_hex = sig_doc["signature"]["value"]
        # Should be valid hex
        try:
            bytes.fromhex(sig_hex)
        except ValueError:
            pytest.fail("Signature value is not valid hex")


# =============================================================================
# Security Tests
# =============================================================================

class TestSecurity:
    """Security-focused tests."""

    def test_signature_not_reusable_across_files(self, temp_dir, mldsa65_keys):
        """Test that signature from one file doesn't verify another."""
        file1 = temp_dir / "file1.bin"
        file2 = temp_dir / "file2.bin"
        file1.write_bytes(b"content A")
        file2.write_bytes(b"content B")

        sig_doc = sign_file(
            filepath=file1,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            signer_info={},
        )

        # Signature should not verify against different file
        with pytest.raises(IntegrityError):
            verify_file_integrity(file2, sig_doc)

    def test_context_separation(self, sample_file, mldsa65_keys):
        """Test that different contexts produce different signatures."""
        sig1 = sign_file(
            filepath=sample_file,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            signer_info={},
            context=b"context-A",
        )

        sig2 = sign_file(
            filepath=sample_file,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            signer_info={},
            context=b"context-B",
        )

        assert sig1["signature"]["value"] != sig2["signature"]["value"]

    def test_signature_uniqueness(self, sample_file, mldsa65_keys):
        """Test that signing the same file twice produces different signatures (due to timestamp)."""
        sig1 = sign_file(
            filepath=sample_file,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            signer_info={},
        )

        # Small delay to ensure different timestamp
        import time
        time.sleep(0.01)

        sig2 = sign_file(
            filepath=sample_file,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            signer_info={},
        )

        # Signatures should be different due to timestamp in signed message
        assert sig1["signature"]["value"] != sig2["signature"]["value"]


# =============================================================================
# Edge Case Tests
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and boundary conditions."""

    def test_empty_file(self, temp_dir, mldsa65_keys):
        """Test signing empty file."""
        empty_file = temp_dir / "empty.bin"
        empty_file.write_bytes(b"")

        sig_doc = sign_file(
            filepath=empty_file,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            signer_info={},
        )

        assert sig_doc["file"]["size"] == 0
        result = verify_signature(empty_file, sig_doc, mldsa65_keys["public"])
        assert result is not None

    def test_unicode_filename(self, temp_dir, mldsa65_keys):
        """Test signing file with unicode filename."""
        unicode_file = temp_dir / "релиз-1.0.0.tar.gz"
        unicode_file.write_bytes(b"content")

        sig_doc = sign_file(
            filepath=unicode_file,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            signer_info={},
        )

        assert sig_doc["file"]["name"] == unicode_file.name

    def test_special_characters_in_signer_info(self, sample_file, mldsa65_keys):
        """Test signer info with special characters."""
        signer_info = {
            "common_name": "Test <User> & Co.",
            "organization": 'Org with "quotes"',
        }

        sig_doc = sign_file(
            filepath=sample_file,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            signer_info=signer_info,
        )

        assert sig_doc["signer"]["common_name"] == signer_info["common_name"]

    def test_binary_context(self, sample_file, mldsa65_keys):
        """Test signing with binary context data."""
        # Context must be <= 255 bytes per FIPS 204
        context = bytes(range(255))

        sig_doc = sign_file(
            filepath=sample_file,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            signer_info={},
            context=context,
        )

        assert sig_doc["signature"]["context"] == context.hex()


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """End-to-end integration tests."""

    def test_full_workflow(self, temp_dir, mldsa65_keys):
        """Test complete sign-verify workflow."""
        # Create release file
        release_file = temp_dir / "myproject-1.0.0.tar.gz"
        release_file.write_bytes(b"Release content " * 1000)

        # Sign
        sig_doc = sign_file(
            filepath=release_file,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            signer_info={
                "common_name": "Release Manager",
                "organization": "My Project",
            },
        )

        # Save signature
        sig_path = temp_dir / "myproject-1.0.0.tar.gz.sig"
        with open(sig_path, "w") as f:
            json.dump(sig_doc, f)

        # Load and verify
        loaded_sig = load_signature(sig_path)
        verify_file_integrity(release_file, loaded_sig)
        result = verify_signature(release_file, loaded_sig, mldsa65_keys["public"])

        assert result["signer"]["common_name"] == "Release Manager"

    def test_workflow_with_key_files(self, temp_dir, mldsa65_keys):
        """Test workflow with key files on disk."""
        # Save keys to files
        pk_path = temp_dir / "test_public.key"
        sk_path = temp_dir / "test_secret.key"

        pk_path.write_bytes(mldsa65_keys["public"])
        sk_path.write_bytes(mldsa65_keys["secret"])

        # Create file to sign
        release_file = temp_dir / "release.bin"
        release_file.write_bytes(b"Release data")

        # Sign using loaded key
        secret_key = sk_path.read_bytes()
        sig_doc = sign_file(
            filepath=release_file,
            secret_key=secret_key,
            algorithm="mldsa65",
            signer_info={},
        )

        # Verify using loaded key
        public_key = pk_path.read_bytes()
        result = verify_signature(release_file, sig_doc, public_key)

        assert result is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
