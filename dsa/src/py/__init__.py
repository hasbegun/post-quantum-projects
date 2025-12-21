"""
Post-Quantum Digital Signature Algorithms (DSA)

This package provides implementations of NIST-standardized post-quantum
digital signature algorithms:

- ML-DSA (FIPS 204) - Module-Lattice-Based Digital Signature Algorithm
- SLH-DSA (FIPS 205) - Stateless Hash-Based Digital Signature Algorithm

Example usage:

    # ML-DSA
    from dsa import MLDSA44
    dsa = MLDSA44()
    pk, sk = dsa.keygen()
    sig = dsa.sign(sk, b"message")
    valid = dsa.verify(pk, b"message", sig)

    # SLH-DSA
    from dsa import slh_keygen, slh_sign, slh_verify, SLH_DSA_SHAKE_128f
    sk, pk = slh_keygen(SLH_DSA_SHAKE_128f)
    sig = slh_sign(SLH_DSA_SHAKE_128f, b"message", sk)
    valid = slh_verify(SLH_DSA_SHAKE_128f, b"message", sig, pk)
"""

# ML-DSA exports
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

# SLH-DSA exports
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
