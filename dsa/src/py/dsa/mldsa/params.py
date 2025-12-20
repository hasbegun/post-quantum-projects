"""
ML-DSA Parameter Sets as defined in FIPS 204
"""

from dataclasses import dataclass
from typing import List


# Global constants from FIPS 204
Q = 8380417  # Modulus q = 2^23 - 2^13 + 1
N = 256  # Polynomial degree
D = 13  # Dropped bits from t
ZETA = 1753  # Primitive 512th root of unity mod q


@dataclass(frozen=True)
class MLDSAParams:
    """Parameter set for ML-DSA"""
    name: str
    k: int  # Rows in matrix A
    l: int  # Columns in matrix A
    eta: int  # Secret key coefficient bound
    tau: int  # Number of +/-1 coefficients in challenge
    beta: int  # tau * eta
    gamma1: int  # y coefficient range
    gamma2: int  # Low-order rounding range
    omega: int  # Maximum number of 1s in hint
    lambda_: int  # Collision strength (bits)

    @property
    def pk_size(self) -> int:
        """Public key size in bytes"""
        return 32 + 32 * self.k * (23 - D)  # rho + t1 encoding

    @property
    def sk_size(self) -> int:
        """Private key size in bytes"""
        # rho + K + tr + s1 + s2 + t0
        s1_size = 32 * self.l * self._bitlen_eta()
        s2_size = 32 * self.k * self._bitlen_eta()
        t0_size = 32 * self.k * D
        return 32 + 32 + 64 + s1_size + s2_size + t0_size

    @property
    def sig_size(self) -> int:
        """Signature size in bytes"""
        # c_tilde + z encoding + hint encoding
        c_tilde_size = self.lambda_ // 4  # 2 * lambda / 8
        z_size = 32 * self.l * (1 + self._bitlen_gamma1())
        h_size = self.omega + self.k
        return c_tilde_size + z_size + h_size

    def _bitlen_eta(self) -> int:
        """Bit length for encoding eta-bounded coefficients"""
        if self.eta == 2:
            return 3
        elif self.eta == 4:
            return 4
        else:
            raise ValueError(f"Unsupported eta: {self.eta}")

    def _bitlen_gamma1(self) -> int:
        """Bit length for encoding gamma1-bounded coefficients"""
        if self.gamma1 == (1 << 17):
            return 17
        elif self.gamma1 == (1 << 19):
            return 19
        else:
            raise ValueError(f"Unsupported gamma1: {self.gamma1}")


# ML-DSA-44: Security Category 2
MLDSA44_PARAMS = MLDSAParams(
    name="ML-DSA-44",
    k=4,
    l=4,
    eta=2,
    tau=39,
    beta=78,  # tau * eta
    gamma1=1 << 17,  # 2^17
    gamma2=(Q - 1) // 88,
    omega=80,
    lambda_=128,
)

# ML-DSA-65: Security Category 3
MLDSA65_PARAMS = MLDSAParams(
    name="ML-DSA-65",
    k=6,
    l=5,
    eta=4,
    tau=49,
    beta=196,  # tau * eta
    gamma1=1 << 19,  # 2^19
    gamma2=(Q - 1) // 32,
    omega=55,
    lambda_=192,
)

# ML-DSA-87: Security Category 5
MLDSA87_PARAMS = MLDSAParams(
    name="ML-DSA-87",
    k=8,
    l=7,
    eta=2,
    tau=60,
    beta=120,  # tau * eta
    gamma1=1 << 19,  # 2^19
    gamma2=(Q - 1) // 32,
    omega=75,
    lambda_=256,
)


# Precomputed NTT twiddle factors (zeta^BitRev(i) mod q)
def _compute_zetas() -> List[int]:
    """Compute zeta powers in bit-reversed order for NTT"""
    zetas = [0] * 256
    zetas[0] = 1

    def bitrev8(x: int) -> int:
        """8-bit bit reversal"""
        result = 0
        for _ in range(8):
            result = (result << 1) | (x & 1)
            x >>= 1
        return result

    # Compute zeta^(2*BitRev8(i)+1) for i = 0..127
    for i in range(256):
        br = bitrev8(i)
        exp = br
        zetas[i] = pow(ZETA, exp, Q)

    return zetas


# Precomputed values for NTT
ZETAS = _compute_zetas()


# Compute zetas for NTT (Algorithm 33)
def compute_ntt_zetas() -> List[int]:
    """
    Compute zeta^BitRev8(k) for k = 0, ..., 255
    As used in Algorithm 33 (NTT)
    """
    def bitrev8(x: int) -> int:
        result = 0
        for _ in range(8):
            result = (result << 1) | (x & 1)
            x >>= 1
        return result

    return [pow(ZETA, bitrev8(k), Q) for k in range(256)]


NTT_ZETAS = compute_ntt_zetas()
