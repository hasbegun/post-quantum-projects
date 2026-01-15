#!/usr/bin/env python3
"""
Comprehensive tests for Post-Quantum Firmware Signing.

These tests verify:
1. Firmware signing and verification workflow
2. Rollback protection
3. Device compatibility checks
4. All supported algorithms
5. Error handling and edge cases

Run with:
    pytest tests/examples/test_firmware_signing.py -v
"""

import hashlib
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

# Add examples path
examples_path = str(Path(__file__).parent.parent.parent / "examples" / "use-cases" / "firmware-signing")
if examples_path not in sys.path:
    sys.path.insert(0, examples_path)

from mldsa import MLDSA44, MLDSA65, MLDSA87
from slhdsa import SLHDSA_SHAKE_128f

from sign_firmware import (
    compute_firmware_hash,
    parse_version,
    detect_algorithm,
    sign_firmware,
    FirmwareMetadata,
    ALGORITHMS,
)
from verify_firmware import (
    verify_firmware_integrity,
    verify_signature,
    check_rollback_protection,
    check_device_compatibility,
    VerificationError,
    IntegrityError,
    RollbackError,
    CompatibilityError,
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
def sample_firmware(temp_dir):
    """Create a sample firmware binary."""
    filepath = temp_dir / "firmware-v1.0.0.bin"
    # Create firmware-like content
    header = b"FWHDR\x01\x00\x00"  # Simple header
    code = os.urandom(1024 * 100)  # 100KB of "code"
    filepath.write_bytes(header + code)
    return filepath


@pytest.fixture
def mldsa65_keys():
    """Generate ML-DSA-65 key pair."""
    dsa = MLDSA65()
    pk, sk = dsa.keygen()
    return {"public": pk, "secret": sk, "algorithm": "mldsa65"}


@pytest.fixture
def sample_metadata():
    """Create sample firmware metadata."""
    return FirmwareMetadata(
        version="2.1.0",
        version_code=2001000,
        device_type="IoT-Sensor-v1",
        hardware_rev="rev-c",
        build_date="2024-01-15",
        build_id="build-12345",
        description="Test firmware",
        min_bootloader_version="1.0.0",
        compatibility=["Model-A", "Model-B"],
    )


# =============================================================================
# Hash Tests
# =============================================================================

class TestFirmwareHashing:
    """Tests for firmware hash computation."""

    def test_dual_hash_computation(self, sample_firmware):
        """Test SHA-256 and SHA-512 hash computation."""
        hashes = compute_firmware_hash(sample_firmware)

        assert "sha256" in hashes
        assert "sha512" in hashes
        assert len(hashes["sha256"]) == 64  # SHA-256 hex
        assert len(hashes["sha512"]) == 128  # SHA-512 hex

    def test_hash_verification(self, sample_firmware):
        """Test hash values are correct."""
        hashes = compute_firmware_hash(sample_firmware)
        content = sample_firmware.read_bytes()

        expected_sha256 = hashlib.sha256(content).hexdigest()
        expected_sha512 = hashlib.sha512(content).hexdigest()

        assert hashes["sha256"] == expected_sha256
        assert hashes["sha512"] == expected_sha512


# =============================================================================
# Version Parsing Tests
# =============================================================================

class TestVersionParsing:
    """Tests for version string parsing."""

    def test_parse_full_version(self):
        """Test parsing full version string."""
        assert parse_version("1.2.3") == 1002003
        assert parse_version("2.0.0") == 2000000
        assert parse_version("10.20.30") == 10020030

    def test_parse_partial_version(self):
        """Test parsing partial version strings."""
        assert parse_version("1.2") == 1002000
        assert parse_version("5") == 5000000

    def test_parse_with_suffix(self):
        """Test parsing version with non-numeric suffix (suffix ignored)."""
        # Note: suffixes cause int() to fail, so patch number is skipped
        assert parse_version("1.2.3-beta") == 1002000  # -beta part ignored
        assert parse_version("2.0.0-rc1") == 2000000


# =============================================================================
# Signing Tests
# =============================================================================

class TestFirmwareSigning:
    """Tests for firmware signing functionality."""

    def test_sign_basic(self, sample_firmware, mldsa65_keys, sample_metadata):
        """Test basic firmware signing."""
        manifest = sign_firmware(
            filepath=sample_firmware,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            metadata=sample_metadata,
            signer_info={"name": "Test Signer"},
        )

        assert manifest["manifest_version"] == "1.0"
        assert manifest["type"] == "firmware-signature"
        assert manifest["algorithm"]["id"] == "mldsa65"
        assert "firmware" in manifest
        assert "metadata" in manifest
        assert "signature" in manifest

    def test_sign_with_default_context(self, sample_firmware, mldsa65_keys, sample_metadata):
        """Test that firmware signing uses 'firmware' as default context."""
        manifest = sign_firmware(
            filepath=sample_firmware,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            metadata=sample_metadata,
            signer_info={},
        )

        # Default context is b"firmware" = "6669726d77617265" in hex
        assert manifest["signature"]["context"] == "6669726d77617265"

    def test_sign_preserves_metadata(self, sample_firmware, mldsa65_keys, sample_metadata):
        """Test that signing preserves all metadata."""
        manifest = sign_firmware(
            filepath=sample_firmware,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            metadata=sample_metadata,
            signer_info={},
        )

        meta = manifest["metadata"]
        assert meta["version"] == "2.1.0"
        assert meta["version_code"] == 2001000
        assert meta["device_type"] == "IoT-Sensor-v1"
        assert meta["hardware_rev"] == "rev-c"
        assert meta["compatibility"] == ["Model-A", "Model-B"]

    def test_sign_includes_security_info(self, sample_firmware, mldsa65_keys, sample_metadata):
        """Test that manifest includes security information."""
        manifest = sign_firmware(
            filepath=sample_firmware,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            metadata=sample_metadata,
            signer_info={},
        )

        assert "security" in manifest
        assert manifest["security"]["rollback_protection"] is True
        assert manifest["security"]["minimum_version_code"] == 2001000


# =============================================================================
# Verification Tests
# =============================================================================

class TestFirmwareVerification:
    """Tests for firmware signature verification."""

    def test_verify_valid_signature(self, sample_firmware, mldsa65_keys, sample_metadata):
        """Test verification of valid signature."""
        manifest = sign_firmware(
            filepath=sample_firmware,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            metadata=sample_metadata,
            signer_info={"name": "Test"},
        )

        result = verify_signature(manifest, mldsa65_keys["public"])

        assert result["algorithm"] == "ML-DSA-65"
        assert "timestamp" in result

    def test_verify_wrong_public_key(self, sample_firmware, mldsa65_keys, sample_metadata):
        """Test verification fails with wrong public key."""
        manifest = sign_firmware(
            filepath=sample_firmware,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            metadata=sample_metadata,
            signer_info={},
        )

        # Generate different key pair
        dsa = MLDSA65()
        wrong_pk, _ = dsa.keygen()

        with pytest.raises(VerificationError):
            verify_signature(manifest, wrong_pk)

    def test_verify_tampered_manifest(self, sample_firmware, mldsa65_keys, sample_metadata):
        """Test verification fails if manifest is tampered."""
        manifest = sign_firmware(
            filepath=sample_firmware,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            metadata=sample_metadata,
            signer_info={},
        )

        # Tamper with metadata
        manifest["metadata"]["version"] = "9.9.9"

        with pytest.raises(VerificationError):
            verify_signature(manifest, mldsa65_keys["public"])


# =============================================================================
# Integrity Tests
# =============================================================================

class TestFirmwareIntegrity:
    """Tests for firmware integrity verification."""

    def test_integrity_valid(self, sample_firmware, mldsa65_keys, sample_metadata):
        """Test integrity check passes for unmodified firmware."""
        manifest = sign_firmware(
            filepath=sample_firmware,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            metadata=sample_metadata,
            signer_info={},
        )

        # Should not raise
        verify_firmware_integrity(sample_firmware, manifest)

    def test_integrity_modified_firmware(self, sample_firmware, mldsa65_keys, sample_metadata):
        """Test integrity check fails for modified firmware."""
        manifest = sign_firmware(
            filepath=sample_firmware,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            metadata=sample_metadata,
            signer_info={},
        )

        # Modify firmware
        original = sample_firmware.read_bytes()
        sample_firmware.write_bytes(original + b"TAMPERED")

        with pytest.raises(IntegrityError, match="(size mismatch|hash mismatch)"):
            verify_firmware_integrity(sample_firmware, manifest)

    def test_integrity_hash_mismatch(self, sample_firmware, mldsa65_keys, sample_metadata):
        """Test integrity check detects hash mismatch."""
        manifest = sign_firmware(
            filepath=sample_firmware,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            metadata=sample_metadata,
            signer_info={},
        )

        # Modify same-size content (overwrite, don't append)
        original = sample_firmware.read_bytes()
        modified = b"X" + original[1:]
        sample_firmware.write_bytes(modified)

        with pytest.raises(IntegrityError, match="hash mismatch"):
            verify_firmware_integrity(sample_firmware, manifest)


# =============================================================================
# Rollback Protection Tests
# =============================================================================

class TestRollbackProtection:
    """Tests for rollback protection functionality."""

    def test_rollback_allowed_newer_version(self, sample_firmware, mldsa65_keys, sample_metadata):
        """Test that newer firmware is allowed."""
        manifest = sign_firmware(
            filepath=sample_firmware,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            metadata=sample_metadata,  # version_code = 2001000
            signer_info={},
        )

        # Current version is older
        current_version_code = 1000000

        # Should not raise
        check_rollback_protection(manifest, current_version_code)

    def test_rollback_blocked_older_version(self, sample_firmware, mldsa65_keys, sample_metadata):
        """Test that older firmware is blocked."""
        manifest = sign_firmware(
            filepath=sample_firmware,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            metadata=sample_metadata,  # version_code = 2001000
            signer_info={},
        )

        # Current version is newer
        current_version_code = 3000000

        with pytest.raises(RollbackError, match="older than current"):
            check_rollback_protection(manifest, current_version_code)

    def test_rollback_same_version_allowed(self, sample_firmware, mldsa65_keys, sample_metadata):
        """Test that same version is allowed (for re-flashing)."""
        manifest = sign_firmware(
            filepath=sample_firmware,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            metadata=sample_metadata,
            signer_info={},
        )

        # Same version
        check_rollback_protection(manifest, sample_metadata.version_code)

    def test_rollback_skipped_when_no_current_version(self, sample_firmware, mldsa65_keys, sample_metadata):
        """Test rollback check is skipped when current version not provided."""
        manifest = sign_firmware(
            filepath=sample_firmware,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            metadata=sample_metadata,
            signer_info={},
        )

        # Should not raise when current_version is None
        check_rollback_protection(manifest, None)


# =============================================================================
# Device Compatibility Tests
# =============================================================================

class TestDeviceCompatibility:
    """Tests for device compatibility checking."""

    def test_compatible_device_type(self, sample_firmware, mldsa65_keys, sample_metadata):
        """Test compatibility check passes for matching device type."""
        manifest = sign_firmware(
            filepath=sample_firmware,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            metadata=sample_metadata,
            signer_info={},
        )

        # Should not raise
        check_device_compatibility(manifest, device_type="IoT-Sensor-v1")

    def test_incompatible_device_type(self, sample_firmware, mldsa65_keys, sample_metadata):
        """Test compatibility check fails for wrong device type."""
        manifest = sign_firmware(
            filepath=sample_firmware,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            metadata=sample_metadata,
            signer_info={},
        )

        with pytest.raises(CompatibilityError, match="Device type mismatch"):
            check_device_compatibility(manifest, device_type="Different-Device")

    def test_compatible_device_model(self, sample_firmware, mldsa65_keys, sample_metadata):
        """Test compatibility check passes for model in compatibility list."""
        manifest = sign_firmware(
            filepath=sample_firmware,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            metadata=sample_metadata,  # compatibility = ["Model-A", "Model-B"]
            signer_info={},
        )

        # Should not raise
        check_device_compatibility(manifest, device_model="Model-A")
        check_device_compatibility(manifest, device_model="Model-B")

    def test_incompatible_device_model(self, sample_firmware, mldsa65_keys, sample_metadata):
        """Test compatibility check fails for model not in list."""
        manifest = sign_firmware(
            filepath=sample_firmware,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            metadata=sample_metadata,
            signer_info={},
        )

        with pytest.raises(CompatibilityError, match="not in compatibility list"):
            check_device_compatibility(manifest, device_model="Model-X")

    def test_compatibility_skipped_when_not_specified(self, sample_firmware, mldsa65_keys, sample_metadata):
        """Test compatibility check is skipped when no device info provided."""
        manifest = sign_firmware(
            filepath=sample_firmware,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            metadata=sample_metadata,
            signer_info={},
        )

        # Should not raise when device info is None
        check_device_compatibility(manifest, device_type=None, device_model=None)


# =============================================================================
# Algorithm Tests
# =============================================================================

class TestAlgorithms:
    """Tests for different algorithm support."""

    def test_all_mldsa_algorithms(self, sample_firmware, sample_metadata):
        """Test signing with all ML-DSA algorithms."""
        for algo_id in ["mldsa44", "mldsa65", "mldsa87"]:
            dsa = ALGORITHMS[algo_id]["class"]()
            pk, sk = dsa.keygen()

            manifest = sign_firmware(
                filepath=sample_firmware,
                secret_key=sk,
                algorithm=algo_id,
                metadata=sample_metadata,
                signer_info={},
            )

            result = verify_signature(manifest, pk)
            assert result is not None

    def test_slhdsa_algorithm(self, sample_firmware, sample_metadata):
        """Test signing with SLH-DSA."""
        dsa = SLHDSA_SHAKE_128f()
        pk, sk = dsa.keygen()

        manifest = sign_firmware(
            filepath=sample_firmware,
            secret_key=sk,
            algorithm="slh-shake-128f",
            metadata=sample_metadata,
            signer_info={},
        )

        result = verify_signature(manifest, pk)
        assert manifest["algorithm"]["standard"] == "FIPS 205"


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """End-to-end integration tests."""

    def test_full_workflow(self, temp_dir, mldsa65_keys):
        """Test complete firmware sign/verify workflow."""
        # Create firmware
        firmware = temp_dir / "device_firmware.bin"
        firmware.write_bytes(b"Firmware content " * 1000)

        metadata = FirmwareMetadata(
            version="1.5.0",
            version_code=1005000,
            device_type="Smart-Device",
            hardware_rev="rev-b",
            build_date="2024-01-20",
            build_id="build-abc123",
            description="Production firmware",
        )

        # Sign
        manifest = sign_firmware(
            filepath=firmware,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            metadata=metadata,
            signer_info={"name": "Build Server", "organization": "IoT Corp"},
        )

        # Save manifest
        manifest_path = temp_dir / "device_firmware.bin.fwsig"
        with open(manifest_path, "w") as f:
            json.dump(manifest, f)

        # Load and verify
        with open(manifest_path) as f:
            loaded_manifest = json.load(f)

        verify_firmware_integrity(firmware, loaded_manifest)
        result = verify_signature(loaded_manifest, mldsa65_keys["public"])

        assert result["algorithm"] == "ML-DSA-65"
        assert loaded_manifest["signer"]["name"] == "Build Server"

    def test_ota_update_scenario(self, temp_dir, mldsa65_keys):
        """Test OTA update verification scenario."""
        # Simulate current installed firmware (v1.0.0)
        current_version_code = 1000000

        # New firmware update (v2.0.0)
        firmware = temp_dir / "update.bin"
        firmware.write_bytes(os.urandom(50000))

        metadata = FirmwareMetadata(
            version="2.0.0",
            version_code=2000000,
            device_type="Gateway",
            hardware_rev="",
            build_date="2024-01-25",
            build_id="update-20240125",
        )

        manifest = sign_firmware(
            filepath=firmware,
            secret_key=mldsa65_keys["secret"],
            algorithm="mldsa65",
            metadata=metadata,
            signer_info={},
        )

        # Full verification chain
        verify_firmware_integrity(firmware, manifest)
        verify_signature(manifest, mldsa65_keys["public"])
        check_rollback_protection(manifest, current_version_code)

        # Success - firmware can be installed


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
