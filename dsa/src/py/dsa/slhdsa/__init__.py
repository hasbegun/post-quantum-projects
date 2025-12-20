"""
SLH-DSA (Stateless Hash-Based Digital Signature Algorithm)
FIPS 205 Implementation

A post-quantum digital signature standard based on SPHINCS+.
"""

from .slh_dsa import (
    slh_keygen,
    slh_sign,
    slh_verify,
    hash_slh_sign,
    hash_slh_verify,
)
from .parameters import (
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
