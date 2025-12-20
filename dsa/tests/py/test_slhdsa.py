"""
Test suite for SLH-DSA (FIPS 205) implementation
"""

import pytest
from dsa import (
    slh_keygen, slh_sign, slh_verify,
    hash_slh_sign, hash_slh_verify,
    SLH_DSA_SHAKE_128s, SLH_DSA_SHAKE_128f,
    SLH_DSA_SHAKE_192s, SLH_DSA_SHAKE_192f,
    SLH_DSA_SHAKE_256s, SLH_DSA_SHAKE_256f,
    SLH_DSA_SHA2_128s, SLH_DSA_SHA2_128f,
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

    def test_sha2_128s_sizes(self):
        params = SLH_DSA_SHA2_128s
        assert params.pk_size == 32
        assert params.sk_size == 64
        assert params.sig_size == 7856

    def test_sha2_128f_sizes(self):
        params = SLH_DSA_SHA2_128f
        assert params.pk_size == 32
        assert params.sk_size == 64
        assert params.sig_size == 17088


class TestSLHDSASHAKE128f:
    """Test SLH-DSA-SHAKE-128f (fast variant)"""

    @pytest.fixture
    def params(self):
        return SLH_DSA_SHAKE_128f

    @pytest.fixture
    def keypair(self, params):
        return slh_keygen(params)

    def test_keygen_sizes(self, params, keypair):
        sk, pk = keypair
        assert len(sk) == params.sk_size
        assert len(pk) == params.pk_size

    def test_sign_verify(self, params, keypair):
        sk, pk = keypair
        message = b"Test message for SLH-DSA-SHAKE-128f"
        sig = slh_sign(params, message, sk)
        assert len(sig) == params.sig_size
        assert slh_verify(params, message, sig, pk)

    def test_wrong_message_fails(self, params, keypair):
        sk, pk = keypair
        sig = slh_sign(params, b"original message", sk)
        assert not slh_verify(params, b"different message", sig, pk)

    def test_wrong_key_fails(self, params):
        sk1, pk1 = slh_keygen(params)
        sk2, pk2 = slh_keygen(params)
        sig = slh_sign(params, b"message", sk1)
        assert not slh_verify(params, b"message", sig, pk2)

    def test_context_string(self, params, keypair):
        sk, pk = keypair
        message = b"message"
        ctx = b"context"
        sig = slh_sign(params, message, sk, ctx=ctx)
        assert slh_verify(params, message, sig, pk, ctx=ctx)
        assert not slh_verify(params, message, sig, pk, ctx=b"wrong context")
        assert not slh_verify(params, message, sig, pk)

    def test_deterministic_signing(self, params, keypair):
        sk, pk = keypair
        message = b"deterministic test"
        sig1 = slh_sign(params, message, sk, randomize=False)
        sig2 = slh_sign(params, message, sk, randomize=False)
        assert sig1 == sig2
        assert slh_verify(params, message, sig1, pk)


class TestSLHDSASHA2128f:
    """Test SLH-DSA-SHA2-128f"""

    @pytest.fixture
    def params(self):
        return SLH_DSA_SHA2_128f

    @pytest.fixture
    def keypair(self, params):
        return slh_keygen(params)

    def test_keygen_sizes(self, params, keypair):
        sk, pk = keypair
        assert len(sk) == params.sk_size
        assert len(pk) == params.pk_size

    def test_sign_verify(self, params, keypair):
        sk, pk = keypair
        message = b"Test message for SLH-DSA-SHA2-128f"
        sig = slh_sign(params, message, sk)
        assert len(sig) == params.sig_size
        assert slh_verify(params, message, sig, pk)


class TestSLHDSAPreHashMode:
    """Test pre-hash signing mode"""

    @pytest.fixture
    def params(self):
        return SLH_DSA_SHAKE_128f

    @pytest.fixture
    def keypair(self, params):
        return slh_keygen(params)

    def test_prehash_sign_verify(self, params, keypair):
        sk, pk = keypair
        message = b"Large message to be pre-hashed" * 100
        sig = hash_slh_sign(params, message, sk)
        assert hash_slh_verify(params, message, sig, pk)

    def test_prehash_with_context(self, params, keypair):
        sk, pk = keypair
        message = b"message"
        ctx = b"prehash context"
        sig = hash_slh_sign(params, message, sk, ctx=ctx)
        assert hash_slh_verify(params, message, sig, pk, ctx=ctx)
        assert not hash_slh_verify(params, message, sig, pk, ctx=b"wrong")

    def test_prehash_wrong_message_fails(self, params, keypair):
        sk, pk = keypair
        sig = hash_slh_sign(params, b"original", sk)
        assert not hash_slh_verify(params, b"different", sig, pk)


class TestSLHDSAEdgeCases:
    """Test edge cases and error handling"""

    @pytest.fixture
    def params(self):
        return SLH_DSA_SHAKE_128f

    @pytest.fixture
    def keypair(self, params):
        return slh_keygen(params)

    def test_empty_message(self, params, keypair):
        sk, pk = keypair
        sig = slh_sign(params, b"", sk)
        assert slh_verify(params, b"", sig, pk)

    def test_large_message(self, params, keypair):
        sk, pk = keypair
        message = b"x" * 10000
        sig = slh_sign(params, message, sk)
        assert slh_verify(params, message, sig, pk)

    def test_context_max_length(self, params, keypair):
        sk, pk = keypair
        ctx = b"x" * 255
        sig = slh_sign(params, b"message", sk, ctx=ctx)
        assert slh_verify(params, b"message", sig, pk, ctx=ctx)

    def test_context_too_long(self, params, keypair):
        sk, pk = keypair
        ctx = b"x" * 256
        with pytest.raises(ValueError):
            slh_sign(params, b"message", sk, ctx=ctx)

    def test_invalid_signature_length(self, params, keypair):
        sk, pk = keypair
        assert not slh_verify(params, b"message", b"short", pk)

    def test_invalid_signature_content(self, params, keypair):
        sk, pk = keypair
        fake_sig = bytes(params.sig_size)
        assert not slh_verify(params, b"message", fake_sig, pk)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
