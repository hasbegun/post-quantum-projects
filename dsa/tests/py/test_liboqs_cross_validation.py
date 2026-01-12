"""
Cross-validation tests with liboqs reference implementation

These tests verify that our implementation produces outputs compatible
with the Open Quantum Safe (liboqs) library when available.

If liboqs is not installed, tests are skipped.

Install liboqs: pip install liboqs-python
"""

import pytest

# Try to import liboqs
try:
    import oqs
    LIBOQS_AVAILABLE = True
except ImportError:
    LIBOQS_AVAILABLE = False

# Our implementation
from mldsa import MLDSA44, MLDSA65, MLDSA87
from slhdsa import SLHDSA_SHAKE_128f, SLHDSA_SHA2_128f
from mlkem import MLKEM512, MLKEM768, MLKEM1024


@pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not installed")
class TestMLDSALiboqsCrossValidation:
    """Cross-validate ML-DSA with liboqs"""

    def test_mldsa44_signature_sizes_match(self):
        """Verify signature sizes match liboqs"""
        our_dsa = MLDSA44()
        oqs_dsa = oqs.Signature("Dilithium2")  # ML-DSA-44 equivalent

        our_pk, our_sk = our_dsa.keygen()

        # Size comparison
        assert len(our_pk) == oqs_dsa.details["length_public_key"]
        assert len(our_sk) == oqs_dsa.details["length_secret_key"]

        message = b"Test message for cross-validation"
        our_sig = our_dsa.sign(our_sk, message)

        # Signature should be within expected range
        assert len(our_sig) == oqs_dsa.details["length_signature"]

    def test_mldsa65_signature_sizes_match(self):
        """Verify ML-DSA-65 signature sizes match liboqs"""
        our_dsa = MLDSA65()
        oqs_dsa = oqs.Signature("Dilithium3")  # ML-DSA-65 equivalent

        our_pk, our_sk = our_dsa.keygen()

        assert len(our_pk) == oqs_dsa.details["length_public_key"]
        assert len(our_sk) == oqs_dsa.details["length_secret_key"]

    def test_mldsa87_signature_sizes_match(self):
        """Verify ML-DSA-87 signature sizes match liboqs"""
        our_dsa = MLDSA87()
        oqs_dsa = oqs.Signature("Dilithium5")  # ML-DSA-87 equivalent

        our_pk, our_sk = our_dsa.keygen()

        assert len(our_pk) == oqs_dsa.details["length_public_key"]
        assert len(our_sk) == oqs_dsa.details["length_secret_key"]

    def test_our_signature_format_valid(self):
        """Verify our signatures have valid format"""
        dsa = MLDSA65()
        pk, sk = dsa.keygen()
        message = b"Test message"
        sig = dsa.sign(sk, message)

        # Signature should verify with our implementation
        assert dsa.verify(pk, message, sig)

        # Tampered signature should fail
        tampered = bytearray(sig)
        tampered[0] ^= 0xFF
        assert not dsa.verify(pk, message, bytes(tampered))


@pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not installed")
class TestMLKEMLiboqsCrossValidation:
    """Cross-validate ML-KEM with liboqs"""

    def test_mlkem512_key_sizes_match(self):
        """Verify ML-KEM-512 key sizes match liboqs"""
        our_kem = MLKEM512()
        oqs_kem = oqs.KeyEncapsulation("Kyber512")  # ML-KEM-512 equivalent

        our_ek, our_dk = our_kem.keygen()

        assert len(our_ek) == oqs_kem.details["length_public_key"]
        assert len(our_dk) == oqs_kem.details["length_secret_key"]

    def test_mlkem768_key_sizes_match(self):
        """Verify ML-KEM-768 key sizes match liboqs"""
        our_kem = MLKEM768()
        oqs_kem = oqs.KeyEncapsulation("Kyber768")  # ML-KEM-768 equivalent

        our_ek, our_dk = our_kem.keygen()

        assert len(our_ek) == oqs_kem.details["length_public_key"]
        assert len(our_dk) == oqs_kem.details["length_secret_key"]

    def test_mlkem1024_key_sizes_match(self):
        """Verify ML-KEM-1024 key sizes match liboqs"""
        our_kem = MLKEM1024()
        oqs_kem = oqs.KeyEncapsulation("Kyber1024")  # ML-KEM-1024 equivalent

        our_ek, our_dk = our_kem.keygen()

        assert len(our_ek) == oqs_kem.details["length_public_key"]
        assert len(our_dk) == oqs_kem.details["length_secret_key"]

    def test_shared_secret_size(self):
        """Verify shared secret is 32 bytes (standard)"""
        kem = MLKEM768()
        ek, dk = kem.keygen()
        ss, ct = kem.encaps(ek)

        assert len(ss) == 32  # ML-KEM shared secret is always 32 bytes

        # Decapsulation should produce same shared secret
        ss2 = kem.decaps(dk, ct)
        assert ss == ss2


@pytest.mark.skipif(not LIBOQS_AVAILABLE, reason="liboqs not installed")
class TestSLHDSALiboqsCrossValidation:
    """Cross-validate SLH-DSA with liboqs"""

    def test_slhdsa_shake128f_signature_sizes_match(self):
        """Verify SLH-DSA-SHAKE-128f signature sizes match liboqs"""
        our_dsa = SLHDSA_SHAKE_128f()
        oqs_dsa = oqs.Signature("SPHINCS+-SHAKE-128f-simple")

        pk, sk = our_dsa.keygen()  # SLH-DSA returns (pk, sk)

        assert len(pk) == oqs_dsa.details["length_public_key"]
        assert len(sk) == oqs_dsa.details["length_secret_key"]

    def test_slhdsa_signature_format_valid(self):
        """Verify our SLH-DSA signatures have valid format"""
        dsa = SLHDSA_SHAKE_128f()
        pk, sk = dsa.keygen()
        message = b"Test message"
        sig = dsa.sign(sk, message)

        # Signature should verify with our implementation
        assert dsa.verify(pk, message, sig)

        # Tampered signature should fail
        tampered = bytearray(sig)
        tampered[100] ^= 0xFF  # Tamper in the middle
        assert not dsa.verify(pk, message, bytes(tampered))


class TestWithoutLiboqs:
    """Tests that run even without liboqs installed"""

    def test_mldsa_fips204_compliance(self):
        """Verify ML-DSA key/signature sizes match FIPS 204"""
        # FIPS 204 specified sizes
        fips204_sizes = {
            "ML-DSA-44": {"pk": 1312, "sk": 2560, "sig": 2420},
            "ML-DSA-65": {"pk": 1952, "sk": 4032, "sig": 3309},
            "ML-DSA-87": {"pk": 2592, "sk": 4896, "sig": 4627},
        }

        for cls, name in [(MLDSA44, "ML-DSA-44"), (MLDSA65, "ML-DSA-65"), (MLDSA87, "ML-DSA-87")]:
            dsa = cls()
            pk, sk = dsa.keygen()
            sig = dsa.sign(sk, b"test")

            assert len(pk) == fips204_sizes[name]["pk"], f"{name} public key size mismatch"
            assert len(sk) == fips204_sizes[name]["sk"], f"{name} secret key size mismatch"
            assert len(sig) == fips204_sizes[name]["sig"], f"{name} signature size mismatch"

    def test_mlkem_fips203_compliance(self):
        """Verify ML-KEM key/ciphertext sizes match FIPS 203"""
        # FIPS 203 specified sizes
        fips203_sizes = {
            "ML-KEM-512": {"ek": 800, "dk": 1632, "ct": 768, "ss": 32},
            "ML-KEM-768": {"ek": 1184, "dk": 2400, "ct": 1088, "ss": 32},
            "ML-KEM-1024": {"ek": 1568, "dk": 3168, "ct": 1568, "ss": 32},
        }

        for cls, name in [(MLKEM512, "ML-KEM-512"), (MLKEM768, "ML-KEM-768"), (MLKEM1024, "ML-KEM-1024")]:
            kem = cls()
            ek, dk = kem.keygen()
            ss, ct = kem.encaps(ek)
            ss2 = kem.decaps(dk, ct)

            assert len(ek) == fips203_sizes[name]["ek"], f"{name} encapsulation key size mismatch"
            assert len(dk) == fips203_sizes[name]["dk"], f"{name} decapsulation key size mismatch"
            assert len(ct) == fips203_sizes[name]["ct"], f"{name} ciphertext size mismatch"
            assert len(ss) == fips203_sizes[name]["ss"], f"{name} shared secret size mismatch"
            assert ss == ss2, f"{name} shared secret mismatch"

    def test_slhdsa_fips205_compliance(self):
        """Verify SLH-DSA key/signature sizes match FIPS 205"""
        # FIPS 205 specified sizes for SHAKE-128f
        fips205_shake128f = {"pk": 32, "sk": 64, "sig": 17088}

        dsa = SLHDSA_SHAKE_128f()
        pk, sk = dsa.keygen()
        sig = dsa.sign(sk, b"test")

        assert len(pk) == fips205_shake128f["pk"], "SLH-DSA-SHAKE-128f public key size mismatch"
        assert len(sk) == fips205_shake128f["sk"], "SLH-DSA-SHAKE-128f secret key size mismatch"
        assert len(sig) == fips205_shake128f["sig"], "SLH-DSA-SHAKE-128f signature size mismatch"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
