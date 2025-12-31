"""
Cross-validation tests for ML-DSA and SLH-DSA

These tests verify that the native C++ bindings produce results
consistent with expected behavior and can interoperate correctly.
"""

import pytest
from mldsa import MLDSA44, MLDSA65, MLDSA87
from mldsa import MLDSA44_PARAMS, MLDSA65_PARAMS, MLDSA87_PARAMS
from slhdsa import SLHDSA_SHAKE_128f, SLH_DSA_SHAKE_128f


class TestMLDSACrossValidation:
    """Cross-validation tests for ML-DSA"""

    def test_deterministic_keygen_consistency(self):
        """Test that same seed always produces same keys"""
        seed = bytes(range(32))

        for _ in range(3):
            dsa = MLDSA65()
            pk, sk = dsa.keygen(seed)

            # Create new instance and verify same result
            dsa2 = MLDSA65()
            pk2, sk2 = dsa2.keygen(seed)

            assert pk == pk2
            assert sk == sk2

    def test_signature_cross_instance_verify(self):
        """Test signatures can be verified by different instances"""
        dsa1 = MLDSA44()
        dsa2 = MLDSA44()

        pk, sk = dsa1.keygen()
        sig = dsa1.sign(sk, b"cross instance test")

        # Verify with different instance
        assert dsa2.verify(pk, b"cross instance test", sig)

    def test_all_variants_consistent(self):
        """Test all ML-DSA variants work consistently"""
        variants = [
            (MLDSA44, MLDSA44_PARAMS),
            (MLDSA65, MLDSA65_PARAMS),
            (MLDSA87, MLDSA87_PARAMS),
        ]

        for cls, params in variants:
            dsa = cls()

            # Test keygen
            pk, sk = dsa.keygen()
            assert len(pk) == params.pk_size
            assert len(sk) == params.sk_size

            # Test sign/verify
            sig = dsa.sign(sk, b"test")
            assert len(sig) == params.sig_size
            assert dsa.verify(pk, b"test", sig)

            # Test with context
            sig_ctx = dsa.sign(sk, b"test", ctx=b"ctx")
            assert dsa.verify(pk, b"test", sig_ctx, ctx=b"ctx")
            assert not dsa.verify(pk, b"test", sig_ctx)

    def test_deterministic_vs_randomized(self):
        """Test deterministic and randomized signing"""
        dsa = MLDSA65()
        pk, sk = dsa.keygen()
        msg = b"test message"

        # Deterministic should be identical
        det1 = dsa.sign(sk, msg, deterministic=True)
        det2 = dsa.sign(sk, msg, deterministic=True)
        assert det1 == det2

        # Randomized should be different
        rand1 = dsa.sign(sk, msg, deterministic=False)
        rand2 = dsa.sign(sk, msg, deterministic=False)
        assert rand1 != rand2

        # Both should verify
        assert dsa.verify(pk, msg, det1)
        assert dsa.verify(pk, msg, rand1)
        assert dsa.verify(pk, msg, rand2)


class TestSLHDSACrossValidation:
    """Cross-validation tests for SLH-DSA"""

    def test_signature_cross_instance_verify(self):
        """Test signatures can be verified by different instances"""
        dsa1 = SLHDSA_SHAKE_128f()
        dsa2 = SLHDSA_SHAKE_128f()

        pk, sk = dsa1.keygen()
        sig = dsa1.sign(sk, b"cross instance test")

        # Verify with different instance
        assert dsa2.verify(pk, b"cross instance test", sig)

    def test_seeded_keygen_consistency(self):
        """Test seeded keygen is consistent"""
        n = SLH_DSA_SHAKE_128f.n
        seeds = (b"\x11" * n, b"\x22" * n, b"\x33" * n)

        dsa1 = SLHDSA_SHAKE_128f()
        dsa2 = SLHDSA_SHAKE_128f()

        pk1, sk1 = dsa1.keygen_from_seeds(*seeds)
        pk2, sk2 = dsa2.keygen_from_seeds(*seeds)

        assert pk1 == pk2
        assert sk1 == sk2

    def test_deterministic_vs_randomized(self):
        """Test deterministic and randomized signing"""
        dsa = SLHDSA_SHAKE_128f()
        pk, sk = dsa.keygen()
        msg = b"test message"

        # Deterministic should be identical
        det1 = dsa.sign(sk, msg, randomize=False)
        det2 = dsa.sign(sk, msg, randomize=False)
        assert det1 == det2

        # Randomized should be different
        rand1 = dsa.sign(sk, msg, randomize=True)
        rand2 = dsa.sign(sk, msg, randomize=True)
        assert rand1 != rand2

        # Both should verify
        assert dsa.verify(pk, msg, det1)
        assert dsa.verify(pk, msg, rand1)
        assert dsa.verify(pk, msg, rand2)


class TestInteroperability:
    """Test interoperability between different keys/signatures"""

    def test_mldsa_keys_not_interchangeable(self):
        """Test that ML-DSA keys from different parameter sets don't mix"""
        dsa44 = MLDSA44()
        dsa65 = MLDSA65()

        pk44, sk44 = dsa44.keygen()
        pk65, sk65 = dsa65.keygen()

        # Sign with 44
        sig44 = dsa44.sign(sk44, b"test")

        # Should not verify with 65's key
        # (may raise or return False depending on implementation)
        try:
            result = dsa65.verify(pk65, b"test", sig44)
            assert not result
        except (ValueError, RuntimeError):
            pass  # Expected

    def test_context_isolation(self):
        """Test that context strings properly isolate signatures"""
        dsa = MLDSA65()
        pk, sk = dsa.keygen()

        contexts = [b"ctx1", b"ctx2", b"", b"long context string"]

        for ctx in contexts:
            sig = dsa.sign(sk, b"message", ctx=ctx)
            assert dsa.verify(pk, b"message", sig, ctx=ctx)

            # Should not verify with different context
            for other_ctx in contexts:
                if other_ctx != ctx:
                    assert not dsa.verify(pk, b"message", sig, ctx=other_ctx)


class TestKeyReuse:
    """Test proper key reuse behavior"""

    def test_sign_many_messages_same_key(self):
        """Test signing many messages with same key"""
        dsa = MLDSA44()
        pk, sk = dsa.keygen()

        messages = [f"Message {i}".encode() for i in range(50)]
        signatures = [dsa.sign(sk, msg) for msg in messages]

        # All should verify
        for msg, sig in zip(messages, signatures):
            assert dsa.verify(pk, msg, sig)

    def test_verify_many_signatures_same_key(self):
        """Test verifying many signatures with same key"""
        dsa = MLDSA44()
        pk, sk = dsa.keygen()

        # Create signatures
        sigs = [dsa.sign(sk, f"msg{i}".encode()) for i in range(50)]

        # Verify all
        for i, sig in enumerate(sigs):
            assert dsa.verify(pk, f"msg{i}".encode(), sig)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
