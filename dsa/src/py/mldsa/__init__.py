"""
ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
Implementation based on NIST FIPS 204

This module provides ML-DSA digital signature operations using native C++ bindings
for optimal performance.

Classes:
    MLDSA44: ML-DSA with security category 2 (128-bit classical)
    MLDSA65: ML-DSA with security category 3 (192-bit classical)
    MLDSA87: ML-DSA with security category 5 (256-bit classical)

Example:
    >>> from mldsa import MLDSA65
    >>> dsa = MLDSA65()
    >>> pk, sk = dsa.keygen()
    >>> sig = dsa.sign(sk, b"Hello, World!")
    >>> assert dsa.verify(pk, b"Hello, World!", sig)
"""

from ._mldsa_native import (
    MLDSA44,
    MLDSA65,
    MLDSA87,
    MLDSAParams,
    MLDSA44_PARAMS,
    MLDSA65_PARAMS,
    MLDSA87_PARAMS,
)

__version__ = "1.0.0"
__all__ = [
    "MLDSA44",
    "MLDSA65",
    "MLDSA87",
    "MLDSAParams",
    "MLDSA44_PARAMS",
    "MLDSA65_PARAMS",
    "MLDSA87_PARAMS",
]
