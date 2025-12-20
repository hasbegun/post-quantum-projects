"""
Test suite for ML-DSA (FIPS 204) implementation
"""

import pytest
from dsa import MLDSA, MLDSA44, MLDSA65, MLDSA87
from dsa import MLDSA44_PARAMS, MLDSA65_PARAMS, MLDSA87_PARAMS


class TestMLDSA44:
    """Test ML-DSA-44 (Security Category 2)"""

    def test_keygen(self):
        """Test key generation produces correct sizes"""
        dsa = MLDSA44()
        pk, sk = dsa.keygen()
        assert len(pk) == MLDSA44_PARAMS.pk_size
        assert len(sk) == MLDSA44_PARAMS.sk_size

    def test_deterministic_keygen(self):
        """Test deterministic key generation"""
        dsa = MLDSA44()
        seed = bytes(range(32))
        pk1, sk1 = dsa.keygen(seed)
        pk2, sk2 = dsa.keygen(seed)
        assert pk1 == pk2
        assert sk1 == sk2

    def test_sign_verify(self):
        """Test basic sign and verify"""
        dsa = MLDSA44()
        pk, sk = dsa.keygen()
        message = b"Test message for ML-DSA-44"
        sig = dsa.sign(sk, message)
        assert len(sig) == MLDSA44_PARAMS.sig_size
        assert dsa.verify(pk, message, sig)

    def test_wrong_message_fails(self):
        """Test verification fails for wrong message"""
        dsa = MLDSA44()
        pk, sk = dsa.keygen()
        sig = dsa.sign(sk, b"original message")
        assert not dsa.verify(pk, b"different message", sig)

    def test_wrong_key_fails(self):
        """Test verification fails with wrong public key"""
        dsa = MLDSA44()
        pk1, sk1 = dsa.keygen()
        pk2, sk2 = dsa.keygen()
        sig = dsa.sign(sk1, b"message")
        assert not dsa.verify(pk2, b"message", sig)

    def test_context_string(self):
        """Test signing with context string"""
        dsa = MLDSA44()
        pk, sk = dsa.keygen()
        message = b"message"
        ctx = b"context"
        sig = dsa.sign(sk, message, ctx=ctx)
        assert dsa.verify(pk, message, sig, ctx=ctx)
        assert not dsa.verify(pk, message, sig, ctx=b"wrong context")

    def test_deterministic_signing(self):
        """Test deterministic signing produces same signature"""
        dsa = MLDSA44()
        pk, sk = dsa.keygen()
        message = b"deterministic test"
        sig1 = dsa.sign(sk, message, deterministic=True)
        sig2 = dsa.sign(sk, message, deterministic=True)
        assert sig1 == sig2


class TestMLDSA65:
    """Test ML-DSA-65 (Security Category 3)"""

    def test_keygen(self):
        """Test key generation"""
        dsa = MLDSA65()
        pk, sk = dsa.keygen()
        assert len(pk) == MLDSA65_PARAMS.pk_size
        assert len(sk) == MLDSA65_PARAMS.sk_size

    def test_sign_verify(self):
        """Test sign and verify"""
        dsa = MLDSA65()
        pk, sk = dsa.keygen()
        message = b"Test message for ML-DSA-65"
        sig = dsa.sign(sk, message)
        assert len(sig) == MLDSA65_PARAMS.sig_size
        assert dsa.verify(pk, message, sig)


class TestMLDSA87:
    """Test ML-DSA-87 (Security Category 5)"""

    def test_keygen(self):
        """Test key generation"""
        dsa = MLDSA87()
        pk, sk = dsa.keygen()
        assert len(pk) == MLDSA87_PARAMS.pk_size
        assert len(sk) == MLDSA87_PARAMS.sk_size

    def test_sign_verify(self):
        """Test sign and verify"""
        dsa = MLDSA87()
        pk, sk = dsa.keygen()
        message = b"Test message for ML-DSA-87"
        sig = dsa.sign(sk, message)
        assert len(sig) == MLDSA87_PARAMS.sig_size
        assert dsa.verify(pk, message, sig)


class TestMLDSAEdgeCases:
    """Test edge cases and error handling"""

    def test_empty_message(self):
        """Test signing empty message"""
        dsa = MLDSA44()
        pk, sk = dsa.keygen()
        sig = dsa.sign(sk, b"")
        assert dsa.verify(pk, b"", sig)

    def test_large_message(self):
        """Test signing large message"""
        dsa = MLDSA44()
        pk, sk = dsa.keygen()
        message = b"x" * 10000
        sig = dsa.sign(sk, message)
        assert dsa.verify(pk, message, sig)

    def test_context_max_length(self):
        """Test maximum context length"""
        dsa = MLDSA44()
        pk, sk = dsa.keygen()
        ctx = b"x" * 255
        sig = dsa.sign(sk, b"message", ctx=ctx)
        assert dsa.verify(pk, b"message", sig, ctx=ctx)

    def test_context_too_long(self):
        """Test context longer than 255 bytes raises error"""
        dsa = MLDSA44()
        pk, sk = dsa.keygen()
        ctx = b"x" * 256
        with pytest.raises(ValueError):
            dsa.sign(sk, b"message", ctx=ctx)

    def test_invalid_signature_format(self):
        """Test verification rejects malformed signatures"""
        dsa = MLDSA44()
        pk, sk = dsa.keygen()
        assert not dsa.verify(pk, b"message", b"short")
        fake_sig = bytes(MLDSA44_PARAMS.sig_size)
        assert not dsa.verify(pk, b"message", fake_sig)


class TestMLDSAParameterSizes:
    """Verify parameter sizes match FIPS 204 specification"""

    def test_mldsa44_sizes(self):
        """Verify ML-DSA-44 sizes"""
        assert MLDSA44_PARAMS.pk_size == 1312
        assert MLDSA44_PARAMS.sk_size == 2560
        assert MLDSA44_PARAMS.sig_size == 2420

    def test_mldsa65_sizes(self):
        """Verify ML-DSA-65 sizes"""
        assert MLDSA65_PARAMS.pk_size == 1952
        assert MLDSA65_PARAMS.sk_size == 4032
        assert MLDSA65_PARAMS.sig_size == 3309

    def test_mldsa87_sizes(self):
        """Verify ML-DSA-87 sizes"""
        assert MLDSA87_PARAMS.pk_size == 2592
        assert MLDSA87_PARAMS.sk_size == 4896
        assert MLDSA87_PARAMS.sig_size == 4627


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
