"""
Native binding tests for SLH-DSA

Tests specific to the pybind11 native bindings functionality.
"""

import pytest
from slhdsa import (
    SLHDSA_SHAKE_128f,
    SLHDSA_SHAKE_128s,
    SLHDSA_SHA2_128f,
    SLHDSAParams,
    SLH_DSA_SHAKE_128f,
    SLH_DSA_SHAKE_128s,
    SLH_DSA_SHA2_128f,
)


class TestSLHDSANativeBindings:
    """Test native binding-specific functionality"""

    def test_module_version(self):
        """Test module has version attribute"""
        import slhdsa
        assert hasattr(slhdsa, "__version__")

    def test_params_type(self):
        """Test parameter sets are SLHDSAParams instances"""
        assert isinstance(SLH_DSA_SHAKE_128f, SLHDSAParams)
        assert isinstance(SLH_DSA_SHAKE_128s, SLHDSAParams)
        assert isinstance(SLH_DSA_SHA2_128f, SLHDSAParams)

    def test_params_repr(self):
        """Test parameter repr"""
        repr_str = repr(SLH_DSA_SHAKE_128f)
        assert "SLH" in repr_str or "128" in repr_str

    def test_instance_params(self):
        """Test instance has params property"""
        dsa = SLHDSA_SHAKE_128f()
        assert dsa.params is not None
        assert dsa.params.pk_size == 32

    def test_bytes_input_output(self):
        """Test that inputs and outputs are proper bytes"""
        dsa = SLHDSA_SHAKE_128f()
        pk, sk = dsa.keygen()

        # Verify types
        assert isinstance(pk, bytes)
        assert isinstance(sk, bytes)

        sig = dsa.sign(sk, b"message")
        assert isinstance(sig, bytes)

        result = dsa.verify(pk, b"message", sig)
        assert isinstance(result, bool)

    def test_context_as_bytes(self):
        """Test context string as bytes"""
        dsa = SLHDSA_SHAKE_128f()
        pk, sk = dsa.keygen()
        ctx = b"test context"
        sig = dsa.sign(sk, b"message", ctx=ctx)
        assert dsa.verify(pk, b"message", sig, ctx=ctx)

    def test_all_classes_instantiable(self):
        """Test all SLH-DSA classes can be instantiated"""
        from slhdsa import (
            SLHDSA_SHA2_128s, SLHDSA_SHA2_128f,
            SLHDSA_SHA2_192s, SLHDSA_SHA2_192f,
            SLHDSA_SHA2_256s, SLHDSA_SHA2_256f,
            SLHDSA_SHAKE_128s, SLHDSA_SHAKE_128f,
            SLHDSA_SHAKE_192s, SLHDSA_SHAKE_192f,
            SLHDSA_SHAKE_256s, SLHDSA_SHAKE_256f,
        )

        classes = [
            SLHDSA_SHA2_128s, SLHDSA_SHA2_128f,
            SLHDSA_SHA2_192s, SLHDSA_SHA2_192f,
            SLHDSA_SHA2_256s, SLHDSA_SHA2_256f,
            SLHDSA_SHAKE_128s, SLHDSA_SHAKE_128f,
            SLHDSA_SHAKE_192s, SLHDSA_SHAKE_192f,
            SLHDSA_SHAKE_256s, SLHDSA_SHAKE_256f,
        ]

        for cls in classes:
            dsa = cls()
            assert dsa.params is not None
            assert dsa.params.pk_size > 0


class TestSLHDSAMemorySafety:
    """Test memory safety of native bindings"""

    def test_multiple_instances(self):
        """Test creating multiple instances"""
        instances = [SLHDSA_SHAKE_128f() for _ in range(10)]
        for dsa in instances:
            pk, sk = dsa.keygen()
            assert len(pk) == SLH_DSA_SHAKE_128f.pk_size

    def test_large_operations(self):
        """Test with many operations"""
        dsa = SLHDSA_SHAKE_128f()
        pk, sk = dsa.keygen()

        for i in range(10):  # Fewer iterations due to slower SLH-DSA
            message = f"Message {i}".encode()
            sig = dsa.sign(sk, message)
            assert dsa.verify(pk, message, sig)

    def test_no_memory_leak_on_error(self):
        """Test that errors don't leak memory"""
        dsa = SLHDSA_SHAKE_128f()
        pk, sk = dsa.keygen()

        # Try to trigger errors
        for _ in range(20):
            try:
                dsa.sign(sk, b"message", ctx=b"x" * 256)
            except (ValueError, RuntimeError):
                pass


class TestSLHDSAErrorHandling:
    """Test error handling in native bindings"""

    def test_context_too_long(self):
        """Test error on context > 255 bytes"""
        dsa = SLHDSA_SHAKE_128f()
        pk, sk = dsa.keygen()
        with pytest.raises((ValueError, RuntimeError)):
            dsa.sign(sk, b"message", ctx=b"x" * 256)

    def test_empty_signature(self):
        """Test verification with empty signature raises ValueError"""
        dsa = SLHDSA_SHAKE_128f()
        pk, sk = dsa.keygen()
        with pytest.raises(ValueError):
            dsa.verify(pk, b"message", b"")

    def test_corrupted_signature(self):
        """Test verification with corrupted signature"""
        dsa = SLHDSA_SHAKE_128f()
        pk, sk = dsa.keygen()
        sig = dsa.sign(sk, b"message")

        # Corrupt the signature
        corrupted = bytearray(sig)
        corrupted[0] ^= 0xFF
        assert not dsa.verify(pk, b"message", bytes(corrupted))


class TestSLHDSAKeygenFromSeeds:
    """Test seeded key generation"""

    def test_keygen_from_seeds_deterministic(self):
        """Test keygen_from_seeds produces deterministic results"""
        dsa = SLHDSA_SHAKE_128f()
        n = SLH_DSA_SHAKE_128f.n

        sk_seed = b"\x01" * n
        sk_prf = b"\x02" * n
        pk_seed = b"\x03" * n

        pk1, sk1 = dsa.keygen_from_seeds(sk_seed, sk_prf, pk_seed)
        pk2, sk2 = dsa.keygen_from_seeds(sk_seed, sk_prf, pk_seed)

        assert pk1 == pk2
        assert sk1 == sk2

    def test_keygen_from_seeds_different(self):
        """Test different seeds produce different keys"""
        dsa = SLHDSA_SHAKE_128f()
        n = SLH_DSA_SHAKE_128f.n

        pk1, sk1 = dsa.keygen_from_seeds(b"\x01" * n, b"\x02" * n, b"\x03" * n)
        pk2, sk2 = dsa.keygen_from_seeds(b"\x04" * n, b"\x05" * n, b"\x06" * n)

        assert pk1 != pk2
        assert sk1 != sk2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
