"""
ML-KEM Performance Benchmarks

Run with: pytest tests/benchmarks/bench_mlkem.py -v
"""

import pytest
from mlkem import MLKEM512, MLKEM768, MLKEM1024


# Test fixtures
@pytest.fixture(scope="module")
def mlkem512():
    return MLKEM512()


@pytest.fixture(scope="module")
def mlkem768():
    return MLKEM768()


@pytest.fixture(scope="module")
def mlkem1024():
    return MLKEM1024()


@pytest.fixture(scope="module")
def mlkem512_keys(mlkem512):
    return mlkem512.keygen()


@pytest.fixture(scope="module")
def mlkem768_keys(mlkem768):
    return mlkem768.keygen()


@pytest.fixture(scope="module")
def mlkem1024_keys(mlkem1024):
    return mlkem1024.keygen()


# ML-KEM-512 Benchmarks
class TestMLKEM512Benchmarks:
    """Benchmarks for ML-KEM-512"""

    def test_keygen(self, benchmark, mlkem512):
        """Benchmark key generation"""
        benchmark(mlkem512.keygen)

    def test_encaps(self, benchmark, mlkem512, mlkem512_keys):
        """Benchmark encapsulation"""
        ek, dk = mlkem512_keys
        benchmark(mlkem512.encaps, ek)

    def test_decaps(self, benchmark, mlkem512, mlkem512_keys):
        """Benchmark decapsulation"""
        ek, dk = mlkem512_keys
        ss, ct = mlkem512.encaps(ek)
        benchmark(mlkem512.decaps, dk, ct)


# ML-KEM-768 Benchmarks
class TestMLKEM768Benchmarks:
    """Benchmarks for ML-KEM-768"""

    def test_keygen(self, benchmark, mlkem768):
        """Benchmark key generation"""
        benchmark(mlkem768.keygen)

    def test_encaps(self, benchmark, mlkem768, mlkem768_keys):
        """Benchmark encapsulation"""
        ek, dk = mlkem768_keys
        benchmark(mlkem768.encaps, ek)

    def test_decaps(self, benchmark, mlkem768, mlkem768_keys):
        """Benchmark decapsulation"""
        ek, dk = mlkem768_keys
        ss, ct = mlkem768.encaps(ek)
        benchmark(mlkem768.decaps, dk, ct)


# ML-KEM-1024 Benchmarks
class TestMLKEM1024Benchmarks:
    """Benchmarks for ML-KEM-1024"""

    def test_keygen(self, benchmark, mlkem1024):
        """Benchmark key generation"""
        benchmark(mlkem1024.keygen)

    def test_encaps(self, benchmark, mlkem1024, mlkem1024_keys):
        """Benchmark encapsulation"""
        ek, dk = mlkem1024_keys
        benchmark(mlkem1024.encaps, ek)

    def test_decaps(self, benchmark, mlkem1024, mlkem1024_keys):
        """Benchmark decapsulation"""
        ek, dk = mlkem1024_keys
        ss, ct = mlkem1024.encaps(ek)
        benchmark(mlkem1024.decaps, dk, ct)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
