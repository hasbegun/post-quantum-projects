"""
SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
Implementation based on NIST FIPS 205

This module provides SLH-DSA digital signature operations using native C++ bindings
for optimal performance.

Parameter Sets:
    SHA2 variants (faster on systems with SHA2 hardware acceleration):
        - SLHDSA_SHA2_128s, SLHDSA_SHA2_128f: 128-bit security
        - SLHDSA_SHA2_192s, SLHDSA_SHA2_192f: 192-bit security
        - SLHDSA_SHA2_256s, SLHDSA_SHA2_256f: 256-bit security

    SHAKE variants (consistent performance across platforms):
        - SLHDSA_SHAKE_128s, SLHDSA_SHAKE_128f: 128-bit security
        - SLHDSA_SHAKE_192s, SLHDSA_SHAKE_192f: 192-bit security
        - SLHDSA_SHAKE_256s, SLHDSA_SHAKE_256f: 256-bit security

    's' suffix = smaller signatures, slower signing
    'f' suffix = faster signing, larger signatures

Example:
    >>> from slhdsa import SLHDSA_SHAKE_128f
    >>> dsa = SLHDSA_SHAKE_128f()
    >>> pk, sk = dsa.keygen()
    >>> sig = dsa.sign(sk, b"Hello, World!")
    >>> assert dsa.verify(pk, b"Hello, World!", sig)
"""

from ._slhdsa_native import (
    # Classes
    SLHDSA_SHA2_128s,
    SLHDSA_SHA2_128f,
    SLHDSA_SHA2_192s,
    SLHDSA_SHA2_192f,
    SLHDSA_SHA2_256s,
    SLHDSA_SHA2_256f,
    SLHDSA_SHAKE_128s,
    SLHDSA_SHAKE_128f,
    SLHDSA_SHAKE_192s,
    SLHDSA_SHAKE_192f,
    SLHDSA_SHAKE_256s,
    SLHDSA_SHAKE_256f,
    # Parameter struct
    SLHDSAParams,
    # Parameter constants
    SLH_DSA_SHA2_128s,
    SLH_DSA_SHA2_128f,
    SLH_DSA_SHA2_192s,
    SLH_DSA_SHA2_192f,
    SLH_DSA_SHA2_256s,
    SLH_DSA_SHA2_256f,
    SLH_DSA_SHAKE_128s,
    SLH_DSA_SHAKE_128f,
    SLH_DSA_SHAKE_192s,
    SLH_DSA_SHAKE_192f,
    SLH_DSA_SHAKE_256s,
    SLH_DSA_SHAKE_256f,
)

__version__ = "1.0.0"
__all__ = [
    # Classes
    "SLHDSA_SHA2_128s",
    "SLHDSA_SHA2_128f",
    "SLHDSA_SHA2_192s",
    "SLHDSA_SHA2_192f",
    "SLHDSA_SHA2_256s",
    "SLHDSA_SHA2_256f",
    "SLHDSA_SHAKE_128s",
    "SLHDSA_SHAKE_128f",
    "SLHDSA_SHAKE_192s",
    "SLHDSA_SHAKE_192f",
    "SLHDSA_SHAKE_256s",
    "SLHDSA_SHAKE_256f",
    # Parameter struct
    "SLHDSAParams",
    # Parameter constants
    "SLH_DSA_SHA2_128s",
    "SLH_DSA_SHA2_128f",
    "SLH_DSA_SHA2_192s",
    "SLH_DSA_SHA2_192f",
    "SLH_DSA_SHA2_256s",
    "SLH_DSA_SHA2_256f",
    "SLH_DSA_SHAKE_128s",
    "SLH_DSA_SHAKE_128f",
    "SLH_DSA_SHAKE_192s",
    "SLH_DSA_SHAKE_192f",
    "SLH_DSA_SHAKE_256s",
    "SLH_DSA_SHAKE_256f",
]
