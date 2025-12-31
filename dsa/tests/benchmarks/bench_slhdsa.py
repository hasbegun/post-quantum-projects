"""
SLH-DSA Performance Benchmarks

Run with: pytest tests/benchmarks/bench_slhdsa.py -v --benchmark-only

Note: SLH-DSA is significantly slower than ML-DSA, especially the 's' variants.
"""

import pytest
from slhdsa import (
    SLHDSA_SHAKE_128f,
    SLHDSA_SHAKE_128s,
    SLHDSA_SHA2_128f,
)


# Test fixtures
@pytest.fixture(scope="module")
def slhdsa_shake_128f():
    return SLHDSA_SHAKE_128f()


@pytest.fixture(scope="module")
def slhdsa_shake_128s():
    return SLHDSA_SHAKE_128s()


@pytest.fixture(scope="module")
def slhdsa_sha2_128f():
    return SLHDSA_SHA2_128f()


@pytest.fixture(scope="module")
def shake_128f_keys(slhdsa_shake_128f):
    return slhdsa_shake_128f.keygen()


@pytest.fixture(scope="module")
def shake_128s_keys(slhdsa_shake_128s):
    return slhdsa_shake_128s.keygen()


@pytest.fixture(scope="module")
def sha2_128f_keys(slhdsa_sha2_128f):
    return slhdsa_sha2_128f.keygen()


# SLH-DSA-SHAKE-128f Benchmarks (fast variant)
class TestSLHDSASHAKE128fBenchmarks:
    """Benchmarks for SLH-DSA-SHAKE-128f (fast variant)"""

    def test_keygen(self, benchmark, slhdsa_shake_128f):
        """Benchmark key generation"""
        benchmark(slhdsa_shake_128f.keygen)

    def test_sign(self, benchmark, slhdsa_shake_128f, shake_128f_keys):
        """Benchmark signing"""
        pk, sk = shake_128f_keys
        message = b"Benchmark message for SLH-DSA signing"
        benchmark(slhdsa_shake_128f.sign, sk, message)

    def test_verify(self, benchmark, slhdsa_shake_128f, shake_128f_keys):
        """Benchmark verification"""
        pk, sk = shake_128f_keys
        message = b"Benchmark message for SLH-DSA verification"
        sig = slhdsa_shake_128f.sign(sk, message)
        benchmark(slhdsa_shake_128f.verify, pk, message, sig)


# SLH-DSA-SHAKE-128s Benchmarks (small variant - slower)
class TestSLHDSASHAKE128sBenchmarks:
    """Benchmarks for SLH-DSA-SHAKE-128s (small signatures, slower)"""

    def test_keygen(self, benchmark, slhdsa_shake_128s):
        """Benchmark key generation"""
        benchmark(slhdsa_shake_128s.keygen)

    def test_sign(self, benchmark, slhdsa_shake_128s, shake_128s_keys):
        """Benchmark signing"""
        pk, sk = shake_128s_keys
        message = b"Benchmark message for SLH-DSA signing"
        benchmark(slhdsa_shake_128s.sign, sk, message)

    def test_verify(self, benchmark, slhdsa_shake_128s, shake_128s_keys):
        """Benchmark verification"""
        pk, sk = shake_128s_keys
        message = b"Benchmark message for SLH-DSA verification"
        sig = slhdsa_shake_128s.sign(sk, message)
        benchmark(slhdsa_shake_128s.verify, pk, message, sig)


# SLH-DSA-SHA2-128f Benchmarks
class TestSLHDSASHA2128fBenchmarks:
    """Benchmarks for SLH-DSA-SHA2-128f"""

    def test_keygen(self, benchmark, slhdsa_sha2_128f):
        """Benchmark key generation"""
        benchmark(slhdsa_sha2_128f.keygen)

    def test_sign(self, benchmark, slhdsa_sha2_128f, sha2_128f_keys):
        """Benchmark signing"""
        pk, sk = sha2_128f_keys
        message = b"Benchmark message for SLH-DSA signing"
        benchmark(slhdsa_sha2_128f.sign, sk, message)

    def test_verify(self, benchmark, slhdsa_sha2_128f, sha2_128f_keys):
        """Benchmark verification"""
        pk, sk = sha2_128f_keys
        message = b"Benchmark message for SLH-DSA verification"
        sig = slhdsa_sha2_128f.sign(sk, message)
        benchmark(slhdsa_sha2_128f.verify, pk, message, sig)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--benchmark-only"])
