"""
Test suite for key generation tool with certificate parameters
"""

import os
import sys
import json
import pytest
import tempfile
import subprocess
from datetime import datetime, timezone, timedelta


class TestSubjectClass:
    """Test the Subject dataclass"""

    def test_empty_subject(self):
        """Test empty subject"""
        from examples.py.generate_keys import Subject
        s = Subject()
        assert s.is_empty()
        assert s.to_dn() == ""

    def test_full_subject(self):
        """Test subject with all fields"""
        from examples.py.generate_keys import Subject
        s = Subject(
            common_name="test.example.com",
            organization="Test Org",
            organizational_unit="Engineering",
            country="US",
            state="California",
            locality="San Francisco",
            email="test@example.com"
        )
        assert not s.is_empty()
        dn = s.to_dn()
        assert "CN=test.example.com" in dn
        assert "O=Test Org" in dn
        assert "OU=Engineering" in dn
        assert "C=US" in dn
        assert "ST=California" in dn
        assert "L=San Francisco" in dn
        assert "emailAddress=test@example.com" in dn

    def test_partial_subject(self):
        """Test subject with some fields"""
        from examples.py.generate_keys import Subject
        s = Subject(common_name="api.example.com", organization="My Corp")
        assert not s.is_empty()
        dn = s.to_dn()
        assert "CN=api.example.com" in dn
        assert "O=My Corp" in dn
        assert "OU=" not in dn  # Not included when empty

    def test_dn_order(self):
        """Test DN field ordering (C, ST, L, O, OU, CN, emailAddress)"""
        from examples.py.generate_keys import Subject
        s = Subject(
            common_name="test",
            organization="Org",
            country="US"
        )
        dn = s.to_dn()
        # C should come before O, O before CN
        c_pos = dn.find("C=US")
        o_pos = dn.find("O=Org")
        cn_pos = dn.find("CN=test")
        assert c_pos < o_pos < cn_pos


class TestCertificateInfo:
    """Test the CertificateInfo dataclass"""

    def test_auto_serial_number(self):
        """Test automatic serial number generation"""
        from examples.py.generate_keys import CertificateInfo, Subject
        cert = CertificateInfo(subject=Subject())
        assert cert.serial_number != ""
        assert len(cert.serial_number) == 16  # 8 bytes = 16 hex chars

    def test_custom_serial_number(self):
        """Test custom serial number"""
        from examples.py.generate_keys import CertificateInfo, Subject
        cert = CertificateInfo(subject=Subject(), serial_number="abcd1234")
        assert cert.serial_number == "abcd1234"

    def test_default_validity(self):
        """Test default validity period"""
        from examples.py.generate_keys import CertificateInfo, Subject
        cert = CertificateInfo(subject=Subject())
        assert cert.validity_days == 365

    def test_custom_validity(self):
        """Test custom validity period"""
        from examples.py.generate_keys import CertificateInfo, Subject
        cert = CertificateInfo(subject=Subject(), validity_days=730)
        assert cert.validity_days == 730


class TestMLDSAKeyGeneration:
    """Test ML-DSA key generation with certificate parameters"""

    def test_basic_keygen_mldsa44(self):
        """Test basic ML-DSA-44 key generation"""
        from examples.py.generate_keys import generate_mldsa_keys, Subject, CertificateInfo
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_info = CertificateInfo(subject=Subject())
            pk, sk, cert = generate_mldsa_keys("mldsa44", tmpdir, cert_info)

            assert len(pk) == 1312  # ML-DSA-44 public key size
            assert len(sk) == 2560  # ML-DSA-44 secret key size
            assert cert["algorithm"] == "MLDSA44"
            assert cert["type"] == "ML-DSA"
            assert cert["standard"] == "FIPS 204"

            # Verify files exist
            assert os.path.exists(os.path.join(tmpdir, "mldsa44_public.key"))
            assert os.path.exists(os.path.join(tmpdir, "mldsa44_secret.key"))
            assert os.path.exists(os.path.join(tmpdir, "mldsa44_certificate.json"))

    def test_keygen_with_subject(self):
        """Test key generation with subject information"""
        from examples.py.generate_keys import generate_mldsa_keys, Subject, CertificateInfo
        with tempfile.TemporaryDirectory() as tmpdir:
            subject = Subject(
                common_name="api.example.com",
                organization="Example Corp",
                country="US"
            )
            cert_info = CertificateInfo(subject=subject, validity_days=730)
            pk, sk, cert = generate_mldsa_keys("mldsa65", tmpdir, cert_info)

            assert cert["subject"]["commonName"] == "api.example.com"
            assert cert["subject"]["organization"] == "Example Corp"
            assert cert["subject"]["country"] == "US"
            assert cert["validity"]["days"] == 730
            assert "C=US" in cert["subject"]["dn"]
            assert "O=Example Corp" in cert["subject"]["dn"]
            assert "CN=api.example.com" in cert["subject"]["dn"]

    def test_keygen_all_levels(self):
        """Test all ML-DSA security levels"""
        from examples.py.generate_keys import generate_mldsa_keys, Subject, CertificateInfo

        expected_sizes = {
            "mldsa44": (1312, 2560, 2420),
            "mldsa65": (1952, 4032, 3309),
            "mldsa87": (2592, 4896, 4627),
        }

        for level, (pk_size, sk_size, sig_size) in expected_sizes.items():
            with tempfile.TemporaryDirectory() as tmpdir:
                cert_info = CertificateInfo(subject=Subject())
                pk, sk, cert = generate_mldsa_keys(level, tmpdir, cert_info)

                assert len(pk) == pk_size, f"{level} public key size"
                assert len(sk) == sk_size, f"{level} secret key size"
                assert cert["keyInfo"]["signatureSize"] == sig_size, f"{level} signature size"


class TestSLHDSAKeyGeneration:
    """Test SLH-DSA key generation with certificate parameters"""

    def test_basic_keygen_slhdsa(self):
        """Test basic SLH-DSA key generation"""
        from examples.py.generate_keys import generate_slhdsa_keys, Subject, CertificateInfo
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_info = CertificateInfo(subject=Subject())
            pk, sk, cert = generate_slhdsa_keys("slh-shake-128f", tmpdir, cert_info)

            assert len(pk) == 32  # SLH-DSA public key size
            assert len(sk) == 64  # SLH-DSA secret key size
            assert cert["algorithm"] == "SLH-DSA-SHAKE-128f"
            assert cert["type"] == "SLH-DSA"
            assert cert["standard"] == "FIPS 205"

            # Verify files exist
            assert os.path.exists(os.path.join(tmpdir, "slh_shake_128f_public.key"))
            assert os.path.exists(os.path.join(tmpdir, "slh_shake_128f_secret.key"))
            assert os.path.exists(os.path.join(tmpdir, "slh_shake_128f_certificate.json"))

    def test_keygen_with_subject(self):
        """Test SLH-DSA key generation with subject information"""
        from examples.py.generate_keys import generate_slhdsa_keys, Subject, CertificateInfo
        with tempfile.TemporaryDirectory() as tmpdir:
            subject = Subject(
                common_name="firmware-signer",
                organizational_unit="Security",
                email="security@example.com"
            )
            cert_info = CertificateInfo(subject=subject, validity_days=1825)
            pk, sk, cert = generate_slhdsa_keys("slh-shake-256f", tmpdir, cert_info)

            assert cert["subject"]["commonName"] == "firmware-signer"
            assert cert["subject"]["organizationalUnit"] == "Security"
            assert cert["subject"]["email"] == "security@example.com"
            assert cert["validity"]["days"] == 1825


class TestCertificateJSONFormat:
    """Test certificate JSON format and structure"""

    def test_certificate_structure(self):
        """Test certificate JSON has all required fields"""
        from examples.py.generate_keys import generate_mldsa_keys, Subject, CertificateInfo
        with tempfile.TemporaryDirectory() as tmpdir:
            subject = Subject(common_name="test")
            cert_info = CertificateInfo(subject=subject, validity_days=365)
            pk, sk, cert = generate_mldsa_keys("mldsa44", tmpdir, cert_info)

            # Required top-level fields
            assert "version" in cert
            assert "algorithm" in cert
            assert "type" in cert
            assert "standard" in cert
            assert "subject" in cert
            assert "validity" in cert
            assert "serialNumber" in cert
            assert "keyInfo" in cert
            assert "created" in cert

            # Subject fields
            assert "commonName" in cert["subject"]
            assert "organization" in cert["subject"]
            assert "organizationalUnit" in cert["subject"]
            assert "country" in cert["subject"]
            assert "state" in cert["subject"]
            assert "locality" in cert["subject"]
            assert "email" in cert["subject"]
            assert "dn" in cert["subject"]

            # Validity fields
            assert "notBefore" in cert["validity"]
            assert "notAfter" in cert["validity"]
            assert "days" in cert["validity"]

            # KeyInfo fields
            assert "publicKeySize" in cert["keyInfo"]
            assert "secretKeySize" in cert["keyInfo"]
            assert "signatureSize" in cert["keyInfo"]
            assert "publicKeyFile" in cert["keyInfo"]
            assert "secretKeyFile" in cert["keyInfo"]

    def test_validity_dates(self):
        """Test validity dates are correct"""
        from examples.py.generate_keys import generate_mldsa_keys, Subject, CertificateInfo
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_info = CertificateInfo(subject=Subject(), validity_days=365)
            pk, sk, cert = generate_mldsa_keys("mldsa44", tmpdir, cert_info)

            not_before = datetime.fromisoformat(cert["validity"]["notBefore"].replace("Z", "+00:00"))
            not_after = datetime.fromisoformat(cert["validity"]["notAfter"].replace("Z", "+00:00"))

            # Check difference is approximately 365 days
            diff = not_after - not_before
            assert diff.days == 365

    def test_certificate_json_file(self):
        """Test certificate JSON file is valid JSON"""
        from examples.py.generate_keys import generate_mldsa_keys, Subject, CertificateInfo
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_info = CertificateInfo(subject=Subject())
            generate_mldsa_keys("mldsa44", tmpdir, cert_info)

            cert_path = os.path.join(tmpdir, "mldsa44_certificate.json")
            with open(cert_path, "r") as f:
                loaded = json.load(f)

            assert loaded["algorithm"] == "MLDSA44"


class TestKeyFileContents:
    """Test key file contents match certificate metadata"""

    def test_key_sizes_match(self):
        """Test that key file sizes match certificate info"""
        from examples.py.generate_keys import generate_mldsa_keys, Subject, CertificateInfo
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_info = CertificateInfo(subject=Subject())
            pk, sk, cert = generate_mldsa_keys("mldsa65", tmpdir, cert_info)

            # Read key files
            with open(os.path.join(tmpdir, "mldsa65_public.key"), "rb") as f:
                pk_from_file = f.read()
            with open(os.path.join(tmpdir, "mldsa65_secret.key"), "rb") as f:
                sk_from_file = f.read()

            assert len(pk_from_file) == cert["keyInfo"]["publicKeySize"]
            assert len(sk_from_file) == cert["keyInfo"]["secretKeySize"]
            assert pk_from_file == pk
            assert sk_from_file == sk

    def test_keys_are_valid(self):
        """Test that generated keys can sign/verify"""
        from examples.py.generate_keys import generate_mldsa_keys, Subject, CertificateInfo
        from dsa import MLDSA65
        with tempfile.TemporaryDirectory() as tmpdir:
            cert_info = CertificateInfo(subject=Subject())
            pk, sk, cert = generate_mldsa_keys("mldsa65", tmpdir, cert_info)

            # Use keys to sign and verify
            dsa = MLDSA65()
            message = b"test message"
            sig = dsa.sign(sk, message)
            assert dsa.verify(pk, message, sig)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
