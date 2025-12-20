"""
Post-Quantum Digital Signature Algorithms (DSA)

A unified implementation of NIST FIPS post-quantum signature standards:
- ML-DSA (FIPS 204): Module-Lattice-Based Digital Signature Algorithm
- SLH-DSA (FIPS 205): Stateless Hash-Based Digital Signature Algorithm

Usage:
    # ML-DSA (fast, smaller signatures)
    from dsa import MLDSA44, MLDSA65, MLDSA87

    # SLH-DSA (conservative, hash-based security)
    from dsa import slh_keygen, slh_sign, slh_verify, SLH_DSA_SHAKE_128f
"""

# ML-DSA (FIPS 204) - Lattice-based
from .mldsa import (
    MLDSA,
    MLDSA44,
    MLDSA65,
    MLDSA87,
    MLDSAParams,
    MLDSA44_PARAMS,
    MLDSA65_PARAMS,
    MLDSA87_PARAMS,
)

# SLH-DSA (FIPS 205) - Hash-based
from .slhdsa import (
    slh_keygen,
    slh_sign,
    slh_verify,
    hash_slh_sign,
    hash_slh_verify,
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
    # ML-DSA
    "MLDSA",
    "MLDSA44",
    "MLDSA65",
    "MLDSA87",
    "MLDSAParams",
    "MLDSA44_PARAMS",
    "MLDSA65_PARAMS",
    "MLDSA87_PARAMS",
    # SLH-DSA
    "slh_keygen",
    "slh_sign",
    "slh_verify",
    "hash_slh_sign",
    "hash_slh_verify",
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
