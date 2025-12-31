"""
Test suite for SLH-DSA (FIPS 205) implementation
"""

import pytest
from slhdsa import (
    SLHDSA_SHAKE_128s,
    SLHDSA_SHAKE_128f,
    SLHDSA_SHA2_128f,
    SLH_DSA_SHAKE_128s,
    SLH_DSA_SHAKE_128f,
    SLH_DSA_SHA2_128f,
)


class TestSLHDSAParameterSizes:
    """Verify parameter sizes match FIPS 205 specification"""

    def test_shake_128s_sizes(self):
        params = SLH_DSA_SHAKE_128s
        assert params.pk_size == 32
        assert params.sk_size == 64
        assert params.sig_size == 7856

    def test_shake_128f_sizes(self):
        params = SLH_DSA_SHAKE_128f
        assert params.pk_size == 32
        assert params.sk_size == 64
        assert params.sig_size == 17088

    def test_sha2_128f_sizes(self):
        params = SLH_DSA_SHA2_128f
        assert params.pk_size == 32
        assert params.sk_size == 64
        assert params.sig_size == 17088


class TestSLHDSASHAKE128f:
    """Test SLH-DSA-SHAKE-128f (fast variant)"""

    def test_keygen_sizes(self):
        dsa = SLHDSA_SHAKE_128f()
        pk, sk = dsa.keygen()
        assert len(pk) == SLH_DSA_SHAKE_128f.pk_size
        assert len(sk) == SLH_DSA_SHAKE_128f.sk_size

    def test_sign_verify(self):
        dsa = SLHDSA_SHAKE_128f()
        pk, sk = dsa.keygen()
        message = b"Test message for SLH-DSA-SHAKE-128f"
        sig = dsa.sign(sk, message)
        assert len(sig) == SLH_DSA_SHAKE_128f.sig_size
        assert dsa.verify(pk, message, sig)

    def test_wrong_message_fails(self):
        dsa = SLHDSA_SHAKE_128f()
        pk, sk = dsa.keygen()
        sig = dsa.sign(sk, b"original message")
        assert not dsa.verify(pk, b"different message", sig)

    def test_wrong_key_fails(self):
        dsa = SLHDSA_SHAKE_128f()
        pk1, sk1 = dsa.keygen()
        pk2, sk2 = dsa.keygen()
        sig = dsa.sign(sk1, b"message")
        assert not dsa.verify(pk2, b"message", sig)

    def test_context_string(self):
        dsa = SLHDSA_SHAKE_128f()
        pk, sk = dsa.keygen()
        message = b"message"
        ctx = b"context"
        sig = dsa.sign(sk, message, ctx=ctx)
        assert dsa.verify(pk, message, sig, ctx=ctx)
        assert not dsa.verify(pk, message, sig, ctx=b"wrong context")
        assert not dsa.verify(pk, message, sig)

    def test_deterministic_signing(self):
        dsa = SLHDSA_SHAKE_128f()
        pk, sk = dsa.keygen()
        message = b"deterministic test"
        sig1 = dsa.sign(sk, message, randomize=False)
        sig2 = dsa.sign(sk, message, randomize=False)
        assert sig1 == sig2
        assert dsa.verify(pk, message, sig1)


class TestSLHDSASHA2128f:
    """Test SLH-DSA-SHA2-128f"""

    def test_keygen_sizes(self):
        dsa = SLHDSA_SHA2_128f()
        pk, sk = dsa.keygen()
        assert len(pk) == SLH_DSA_SHA2_128f.pk_size
        assert len(sk) == SLH_DSA_SHA2_128f.sk_size

    def test_sign_verify(self):
        dsa = SLHDSA_SHA2_128f()
        pk, sk = dsa.keygen()
        message = b"Test message for SLH-DSA-SHA2-128f"
        sig = dsa.sign(sk, message)
        assert len(sig) == SLH_DSA_SHA2_128f.sig_size
        assert dsa.verify(pk, message, sig)


class TestSLHDSAEdgeCases:
    """Test edge cases and error handling"""

    def test_empty_message(self):
        dsa = SLHDSA_SHAKE_128f()
        pk, sk = dsa.keygen()
        sig = dsa.sign(sk, b"")
        assert dsa.verify(pk, b"", sig)

    def test_large_message(self):
        dsa = SLHDSA_SHAKE_128f()
        pk, sk = dsa.keygen()
        message = b"x" * 10000
        sig = dsa.sign(sk, message)
        assert dsa.verify(pk, message, sig)

    def test_context_max_length(self):
        dsa = SLHDSA_SHAKE_128f()
        pk, sk = dsa.keygen()
        ctx = b"x" * 255
        sig = dsa.sign(sk, b"message", ctx=ctx)
        assert dsa.verify(pk, b"message", sig, ctx=ctx)

    def test_context_too_long(self):
        dsa = SLHDSA_SHAKE_128f()
        pk, sk = dsa.keygen()
        ctx = b"x" * 256
        with pytest.raises((ValueError, RuntimeError)):
            dsa.sign(sk, b"message", ctx=ctx)

    def test_invalid_signature_length(self):
        dsa = SLHDSA_SHAKE_128f()
        pk, sk = dsa.keygen()
        # Wrong-size signatures should raise ValueError
        with pytest.raises(ValueError):
            dsa.verify(pk, b"message", b"short")

    def test_invalid_signature_content(self):
        dsa = SLHDSA_SHAKE_128f()
        pk, sk = dsa.keygen()
        fake_sig = bytes(SLH_DSA_SHAKE_128f.sig_size)
        assert not dsa.verify(pk, b"message", fake_sig)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
