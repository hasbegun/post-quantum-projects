"""
SLH-DSA Parameter Sets (FIPS 205 Section 11)

Defines all 12 approved parameter sets with their configurations.
"""

from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class SLHDSAParameterSet:
    """SLH-DSA parameter set configuration."""

    name: str
    n: int          # Security parameter (hash output length in bytes)
    h: int          # Total tree height
    d: int          # Number of layers in hypertree
    hp: int         # Height of each tree (h' = h/d)
    a: int          # FORS tree height
    k: int          # Number of FORS trees
    lg_w: int       # Log2 of Winternitz parameter (always 4, so w=16)
    m: int          # Message digest length in bytes
    hash_type: Literal["sha2", "shake"]  # Hash function family

    @property
    def w(self) -> int:
        """Winternitz parameter."""
        return 1 << self.lg_w  # 2^lg_w = 16

    @property
    def len1(self) -> int:
        """Number of len1 WOTS+ chains (for message)."""
        return (8 * self.n + self.lg_w - 1) // self.lg_w

    @property
    def len2(self) -> int:
        """Number of len2 WOTS+ chains (for checksum)."""
        # len2 = floor(log_w(len1 * (w-1))) + 1
        # For w=16: len2 = floor(log_16(len1 * 15)) + 1
        max_checksum = self.len1 * (self.w - 1)
        len2 = 1
        tmp = self.w
        while tmp <= max_checksum:
            len2 += 1
            tmp *= self.w
        return len2

    @property
    def len_total(self) -> int:
        """Total number of WOTS+ chains."""
        return self.len1 + self.len2

    @property
    def sig_fors_size(self) -> int:
        """FORS signature size in bytes."""
        return self.k * (self.a + 1) * self.n

    @property
    def sig_ht_size(self) -> int:
        """Hypertree signature size in bytes."""
        return (self.h + self.d * self.len_total) * self.n

    @property
    def sig_size(self) -> int:
        """Total signature size in bytes."""
        return self.n + self.sig_fors_size + self.sig_ht_size

    @property
    def pk_size(self) -> int:
        """Public key size in bytes."""
        return 2 * self.n

    @property
    def sk_size(self) -> int:
        """Secret key size in bytes."""
        return 4 * self.n


# SHA2-based parameter sets

SLH_DSA_SHA2_128s = SLHDSAParameterSet(
    name="SLH-DSA-SHA2-128s",
    n=16, h=63, d=7, hp=9, a=12, k=14,
    lg_w=4, m=30, hash_type="sha2"
)

SLH_DSA_SHA2_128f = SLHDSAParameterSet(
    name="SLH-DSA-SHA2-128f",
    n=16, h=66, d=22, hp=3, a=6, k=33,
    lg_w=4, m=34, hash_type="sha2"
)

SLH_DSA_SHA2_192s = SLHDSAParameterSet(
    name="SLH-DSA-SHA2-192s",
    n=24, h=63, d=7, hp=9, a=14, k=17,
    lg_w=4, m=39, hash_type="sha2"
)

SLH_DSA_SHA2_192f = SLHDSAParameterSet(
    name="SLH-DSA-SHA2-192f",
    n=24, h=66, d=22, hp=3, a=8, k=33,
    lg_w=4, m=42, hash_type="sha2"
)

SLH_DSA_SHA2_256s = SLHDSAParameterSet(
    name="SLH-DSA-SHA2-256s",
    n=32, h=64, d=8, hp=8, a=14, k=22,
    lg_w=4, m=47, hash_type="sha2"
)

SLH_DSA_SHA2_256f = SLHDSAParameterSet(
    name="SLH-DSA-SHA2-256f",
    n=32, h=68, d=17, hp=4, a=9, k=35,
    lg_w=4, m=49, hash_type="sha2"
)

# SHAKE-based parameter sets

SLH_DSA_SHAKE_128s = SLHDSAParameterSet(
    name="SLH-DSA-SHAKE-128s",
    n=16, h=63, d=7, hp=9, a=12, k=14,
    lg_w=4, m=30, hash_type="shake"
)

SLH_DSA_SHAKE_128f = SLHDSAParameterSet(
    name="SLH-DSA-SHAKE-128f",
    n=16, h=66, d=22, hp=3, a=6, k=33,
    lg_w=4, m=34, hash_type="shake"
)

SLH_DSA_SHAKE_192s = SLHDSAParameterSet(
    name="SLH-DSA-SHAKE-192s",
    n=24, h=63, d=7, hp=9, a=14, k=17,
    lg_w=4, m=39, hash_type="shake"
)

SLH_DSA_SHAKE_192f = SLHDSAParameterSet(
    name="SLH-DSA-SHAKE-192f",
    n=24, h=66, d=22, hp=3, a=8, k=33,
    lg_w=4, m=42, hash_type="shake"
)

SLH_DSA_SHAKE_256s = SLHDSAParameterSet(
    name="SLH-DSA-SHAKE-256s",
    n=32, h=64, d=8, hp=8, a=14, k=22,
    lg_w=4, m=47, hash_type="shake"
)

SLH_DSA_SHAKE_256f = SLHDSAParameterSet(
    name="SLH-DSA-SHAKE-256f",
    n=32, h=68, d=17, hp=4, a=9, k=35,
    lg_w=4, m=49, hash_type="shake"
)

# Dictionary of all parameter sets for lookup
PARAMETER_SETS = {
    "SLH-DSA-SHA2-128s": SLH_DSA_SHA2_128s,
    "SLH-DSA-SHA2-128f": SLH_DSA_SHA2_128f,
    "SLH-DSA-SHA2-192s": SLH_DSA_SHA2_192s,
    "SLH-DSA-SHA2-192f": SLH_DSA_SHA2_192f,
    "SLH-DSA-SHA2-256s": SLH_DSA_SHA2_256s,
    "SLH-DSA-SHA2-256f": SLH_DSA_SHA2_256f,
    "SLH-DSA-SHAKE-128s": SLH_DSA_SHAKE_128s,
    "SLH-DSA-SHAKE-128f": SLH_DSA_SHAKE_128f,
    "SLH-DSA-SHAKE-192s": SLH_DSA_SHAKE_192s,
    "SLH-DSA-SHAKE-192f": SLH_DSA_SHAKE_192f,
    "SLH-DSA-SHAKE-256s": SLH_DSA_SHAKE_256s,
    "SLH-DSA-SHAKE-256f": SLH_DSA_SHAKE_256f,
}


def get_parameter_set(name: str) -> SLHDSAParameterSet:
    """Get a parameter set by name."""
    if name not in PARAMETER_SETS:
        raise ValueError(f"Unknown parameter set: {name}")
    return PARAMETER_SETS[name]
