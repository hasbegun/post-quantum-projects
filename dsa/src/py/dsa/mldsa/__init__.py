"""
ML-DSA (Module-Lattice-Based Digital Signature Algorithm)
Implementation based on NIST FIPS 204

This module provides a complete implementation of the ML-DSA digital signature
algorithm, including key generation, signing, and verification.
"""

from .mldsa import MLDSA, MLDSA44, MLDSA65, MLDSA87
from .params import MLDSAParams, MLDSA44_PARAMS, MLDSA65_PARAMS, MLDSA87_PARAMS

__version__ = "1.0.0"
__all__ = [
    "MLDSA",
    "MLDSA44",
    "MLDSA65",
    "MLDSA87",
    "MLDSAParams",
    "MLDSA44_PARAMS",
    "MLDSA65_PARAMS",
    "MLDSA87_PARAMS",
]
