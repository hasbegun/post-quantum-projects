"""
Native binding tests for ML-DSA

Tests specific to the pybind11 native bindings functionality.
"""

import pytest
from mldsa import MLDSA44, MLDSA65, MLDSA87, MLDSAParams
from mldsa import MLDSA44_PARAMS, MLDSA65_PARAMS, MLDSA87_PARAMS


class TestMLDSANativeBindings:
    """Test native binding-specific functionality"""

    def test_module_version(self):
        """Test module has version attribute"""
        import mldsa
        assert hasattr(mldsa, "__version__")

    def test_params_type(self):
        """Test parameter sets are MLDSAParams instances"""
        assert isinstance(MLDSA44_PARAMS, MLDSAParams)
        assert isinstance(MLDSA65_PARAMS, MLDSAParams)
        assert isinstance(MLDSA87_PARAMS, MLDSAParams)

    def test_params_repr(self):
        """Test parameter repr"""
        repr_str = repr(MLDSA44_PARAMS)
        assert "ML-DSA-44" in repr_str or "MLDSA44" in repr_str

    def test_instance_params(self):
        """Test instance has params property"""
        dsa = MLDSA65()
        assert dsa.params is not None
        assert dsa.params.pk_size == 1952

    def test_bytes_input_output(self):
        """Test that inputs and outputs are proper bytes"""
        dsa = MLDSA44()
        pk, sk = dsa.keygen()

        # Verify types
        assert isinstance(pk, bytes)
        assert isinstance(sk, bytes)

        sig = dsa.sign(sk, b"message")
        assert isinstance(sig, bytes)

        result = dsa.verify(pk, b"message", sig)
        assert isinstance(result, bool)

    def test_seed_as_bytes(self):
        """Test that seed input accepts bytes"""
        dsa = MLDSA44()
        seed = b"\x00" * 32
        pk, sk = dsa.keygen(seed)
        assert isinstance(pk, bytes)

    def test_context_as_bytes(self):
        """Test context string as bytes"""
        dsa = MLDSA44()
        pk, sk = dsa.keygen()
        ctx = b"test context"
        sig = dsa.sign(sk, b"message", ctx=ctx)
        assert dsa.verify(pk, b"message", sig, ctx=ctx)

    def test_all_parameter_sets_accessible(self):
        """Test all parameter sets are accessible"""
        params_list = [MLDSA44_PARAMS, MLDSA65_PARAMS, MLDSA87_PARAMS]
        for p in params_list:
            assert p.k > 0
            assert p.l > 0
            assert p.pk_size > 0
            assert p.sk_size > 0
            assert p.sig_size > 0


class TestMLDSAMemorySafety:
    """Test memory safety of native bindings"""

    def test_multiple_instances(self):
        """Test creating multiple instances"""
        instances = [MLDSA44() for _ in range(10)]
        for dsa in instances:
            pk, sk = dsa.keygen()
            assert len(pk) == MLDSA44_PARAMS.pk_size

    def test_large_operations(self):
        """Test with many operations"""
        dsa = MLDSA44()
        pk, sk = dsa.keygen()

        for i in range(100):
            message = f"Message {i}".encode()
            sig = dsa.sign(sk, message)
            assert dsa.verify(pk, message, sig)

    def test_no_memory_leak_on_error(self):
        """Test that errors don't leak memory"""
        dsa = MLDSA44()
        pk, sk = dsa.keygen()

        # Try to trigger errors
        for _ in range(100):
            try:
                dsa.sign(sk, b"message", ctx=b"x" * 256)
            except (ValueError, RuntimeError):
                pass


class TestMLDSAErrorHandling:
    """Test error handling in native bindings"""

    def test_invalid_seed_size(self):
        """Test error on wrong seed size"""
        dsa = MLDSA44()
        with pytest.raises((ValueError, RuntimeError)):
            dsa.keygen(b"short")

    def test_empty_key(self):
        """Test behavior with empty key"""
        dsa = MLDSA44()
        pk, _ = dsa.keygen()
        # Empty secret key should fail or return invalid signature
        try:
            sig = dsa.sign(b"", b"message")
            # If it doesn't raise, verify should fail
            assert not dsa.verify(pk, b"message", sig)
        except (ValueError, RuntimeError):
            pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
