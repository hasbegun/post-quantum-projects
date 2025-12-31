"""
ML-DSA Performance Benchmarks

Run with: pytest tests/benchmarks/bench_mldsa.py -v --benchmark-only
"""

import pytest
from mldsa import MLDSA44, MLDSA65, MLDSA87


# Test fixtures
@pytest.fixture(scope="module")
def mldsa44():
    return MLDSA44()


@pytest.fixture(scope="module")
def mldsa65():
    return MLDSA65()


@pytest.fixture(scope="module")
def mldsa87():
    return MLDSA87()


@pytest.fixture(scope="module")
def mldsa44_keys(mldsa44):
    return mldsa44.keygen()


@pytest.fixture(scope="module")
def mldsa65_keys(mldsa65):
    return mldsa65.keygen()


@pytest.fixture(scope="module")
def mldsa87_keys(mldsa87):
    return mldsa87.keygen()


# ML-DSA-44 Benchmarks
class TestMLDSA44Benchmarks:
    """Benchmarks for ML-DSA-44"""

    def test_keygen(self, benchmark, mldsa44):
        """Benchmark key generation"""
        benchmark(mldsa44.keygen)

    def test_sign(self, benchmark, mldsa44, mldsa44_keys):
        """Benchmark signing"""
        pk, sk = mldsa44_keys
        message = b"Benchmark message for ML-DSA-44 signing performance test"
        benchmark(mldsa44.sign, sk, message)

    def test_verify(self, benchmark, mldsa44, mldsa44_keys):
        """Benchmark verification"""
        pk, sk = mldsa44_keys
        message = b"Benchmark message for ML-DSA-44 verification test"
        sig = mldsa44.sign(sk, message)
        benchmark(mldsa44.verify, pk, message, sig)


# ML-DSA-65 Benchmarks
class TestMLDSA65Benchmarks:
    """Benchmarks for ML-DSA-65"""

    def test_keygen(self, benchmark, mldsa65):
        """Benchmark key generation"""
        benchmark(mldsa65.keygen)

    def test_sign(self, benchmark, mldsa65, mldsa65_keys):
        """Benchmark signing"""
        pk, sk = mldsa65_keys
        message = b"Benchmark message for ML-DSA-65 signing performance test"
        benchmark(mldsa65.sign, sk, message)

    def test_verify(self, benchmark, mldsa65, mldsa65_keys):
        """Benchmark verification"""
        pk, sk = mldsa65_keys
        message = b"Benchmark message for ML-DSA-65 verification test"
        sig = mldsa65.sign(sk, message)
        benchmark(mldsa65.verify, pk, message, sig)


# ML-DSA-87 Benchmarks
class TestMLDSA87Benchmarks:
    """Benchmarks for ML-DSA-87"""

    def test_keygen(self, benchmark, mldsa87):
        """Benchmark key generation"""
        benchmark(mldsa87.keygen)

    def test_sign(self, benchmark, mldsa87, mldsa87_keys):
        """Benchmark signing"""
        pk, sk = mldsa87_keys
        message = b"Benchmark message for ML-DSA-87 signing performance test"
        benchmark(mldsa87.sign, sk, message)

    def test_verify(self, benchmark, mldsa87, mldsa87_keys):
        """Benchmark verification"""
        pk, sk = mldsa87_keys
        message = b"Benchmark message for ML-DSA-87 verification test"
        sig = mldsa87.sign(sk, message)
        benchmark(mldsa87.verify, pk, message, sig)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--benchmark-only"])
