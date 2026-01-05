"""
ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism)
Implementation based on NIST FIPS 203

This module provides ML-KEM key encapsulation operations using native C++ bindings
for optimal performance.

Classes:
    MLKEM512: ML-KEM with security category 1 (128-bit classical)
    MLKEM768: ML-KEM with security category 3 (192-bit classical)
    MLKEM1024: ML-KEM with security category 5 (256-bit classical)

Example:
    >>> from mlkem import MLKEM768
    >>> kem = MLKEM768()
    >>> ek, dk = kem.keygen()
    >>> shared_secret, ciphertext = kem.encaps(ek)
    >>> recovered_secret = kem.decaps(dk, ciphertext)
    >>> assert shared_secret == recovered_secret
"""

from ._mlkem_native import (
    MLKEM512,
    MLKEM768,
    MLKEM1024,
    MLKEMParams,
    MLKEM512_PARAMS,
    MLKEM768_PARAMS,
    MLKEM1024_PARAMS,
)

__version__ = "1.0.0"
__all__ = [
    "MLKEM512",
    "MLKEM768",
    "MLKEM1024",
    "MLKEMParams",
    "MLKEM512_PARAMS",
    "MLKEM768_PARAMS",
    "MLKEM1024_PARAMS",
]
