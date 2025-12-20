"""
Sampling functions for ML-DSA
Based on FIPS 204 Algorithms 35-49
"""

from typing import List, Tuple
from .params import Q, N, MLDSAParams
from .utils import (
    coef_from_three_bytes, coef_from_half_byte,
    SHAKE128Stream, SHAKE256Stream, shake256_xof
)
from .ntt import ntt


def sample_in_ball(rho: bytes, tau: int) -> List[int]:
    """
    Algorithm 35: SampleInBall
    Sample polynomial with exactly tau +/-1 coefficients

    Input: rho in B^32, tau (number of non-zero coefficients)
    Output: c in R (polynomial with tau non-zero +/-1 coefficients)
    """
    c = [0] * 256
    xof = SHAKE256Stream(rho)

    # Use first 8 bytes for sign bits
    sign_bytes = xof.read(8)
    signs = 0
    for i in range(8):
        signs |= sign_bytes[i] << (8 * i)

    k = 0
    for i in range(256 - tau, 256):
        # Rejection sampling for j in [0, i]
        while True:
            j = xof.read(1)[0]
            if j <= i:
                break

        c[i] = c[j]
        c[j] = 1 - 2 * ((signs >> k) & 1)  # +1 or -1 based on sign bit
        k += 1

    return c


def rej_ntt_poly(rho: bytes) -> List[int]:
    """
    Algorithm 36: RejNTTPoly
    Sample uniform polynomial in NTT domain using rejection sampling

    Input: rho (seed bytes)
    Output: a_hat in Z_q^256
    """
    a_hat = [0] * 256
    xof = SHAKE128Stream(rho)
    j = 0

    while j < 256:
        # Read 3 bytes at a time
        b = xof.read(3)
        coef = coef_from_three_bytes(b[0], b[1], b[2])
        if coef is not None:
            a_hat[j] = coef
            j += 1

    return a_hat


def rej_bounded_poly(rho: bytes, eta: int) -> List[int]:
    """
    Algorithm 37: RejBoundedPoly
    Sample polynomial with bounded coefficients using rejection sampling

    Input: rho (seed bytes), eta in {2, 4}
    Output: a in S_eta (polynomial with coefficients in {-eta, ..., eta})
    """
    a = [0] * 256
    xof = SHAKE256Stream(rho)
    j = 0

    while j < 256:
        # Read 1 byte, use both half-bytes
        b = xof.read(1)[0]
        b0 = b & 0x0F
        b1 = (b >> 4) & 0x0F

        coef0 = coef_from_half_byte(b0, eta)
        if coef0 is not None and j < 256:
            a[j] = coef0
            j += 1

        coef1 = coef_from_half_byte(b1, eta)
        if coef1 is not None and j < 256:
            a[j] = coef1
            j += 1

    return a


def expand_a(rho: bytes, params: MLDSAParams) -> List[List[List[int]]]:
    """
    Algorithm 38: ExpandA
    Expand seed to k x l matrix of polynomials in NTT domain

    Input: rho in B^32
    Output: A_hat in (Z_q^256)^(k x l) (matrix of NTT polynomials)
    """
    k, l = params.k, params.l
    A_hat = []
    for r in range(k):
        row = []
        for s in range(l):
            # Append index bytes to rho
            seed = rho + bytes([s, r])
            a_hat = rej_ntt_poly(seed)
            row.append(a_hat)
        A_hat.append(row)
    return A_hat


def expand_s(rho: bytes, params: MLDSAParams) -> Tuple[List[List[int]], List[List[int]]]:
    """
    Algorithm 39: ExpandS
    Expand seed to secret vectors s1 and s2

    Input: rho in B^64
    Output: (s1 in S_eta^l, s2 in S_eta^k)
    """
    k, l, eta = params.k, params.l, params.eta

    s1 = []
    for r in range(l):
        # Use counter r for s1
        seed = rho + bytes([r & 0xFF, r >> 8])
        s1.append(rej_bounded_poly(seed, eta))

    s2 = []
    for r in range(k):
        # Use counter l + r for s2
        counter = l + r
        seed = rho + bytes([counter & 0xFF, counter >> 8])
        s2.append(rej_bounded_poly(seed, eta))

    return s1, s2


def expand_mask(rho: bytes, mu: int, params: MLDSAParams) -> List[List[int]]:
    """
    Algorithm 40: ExpandMask
    Expand seed to masking vector y

    Input: rho in B^64, mu (counter), params
    Output: y in S_{gamma1-1}^l (coefficients in {-gamma1+1, ..., gamma1})
    """
    l = params.l
    gamma1 = params.gamma1

    # Determine bit length based on gamma1
    if gamma1 == (1 << 17):
        gamma1_bits = 18  # 2*17+2 bits but we use 18 = ceil(log2(2*gamma1))
    else:  # gamma1 == (1 << 19)
        gamma1_bits = 20

    y = []
    for r in range(l):
        # Compute index
        counter = mu + r
        seed = rho + bytes([counter & 0xFF, (counter >> 8) & 0xFF])

        # Generate bytes for polynomial - need 32 * gamma1_bits bytes
        bytes_needed = 32 * gamma1_bits
        v = shake256_xof(seed, bytes_needed)

        # Unpack using BitUnpack with a=gamma1-1, b=gamma1
        # Each coefficient uses gamma1_bits bits
        poly = []
        bits = []
        for byte in v:
            for bit_idx in range(8):
                bits.append((byte >> bit_idx) & 1)

        for i in range(256):
            # Extract gamma1_bits bits
            val = 0
            for j in range(gamma1_bits):
                if i * gamma1_bits + j < len(bits):
                    val |= bits[i * gamma1_bits + j] << j
            # Map to centered representation: gamma1 - val
            coef = gamma1 - val
            poly.append(coef)

        y.append(poly)

    return y


# Additional helper functions from the spec

def h_function(seed: bytes, output_len: int) -> bytes:
    """
    H function: SHAKE256 XOF
    Used throughout the scheme for hashing
    """
    return shake256_xof(seed, output_len)


def h1_function(seed: bytes) -> bytes:
    """
    H1: Hash to 64 bytes using SHAKE256
    """
    return shake256_xof(seed, 64)


def h2_function(seed: bytes, lambda_: int) -> bytes:
    """
    H2: Hash to 2*lambda/8 bytes using SHAKE256
    """
    return shake256_xof(seed, lambda_ // 4)


# Functions for computing w1 encoding for challenge hash

def w1_encode(w1: List[List[int]], params: MLDSAParams) -> bytes:
    """
    Encode w1 for challenge hash computation

    Each coefficient of w1 is in range based on gamma2:
    - If gamma2 = (q-1)/88: coefficients in {0, ..., 43}
    - If gamma2 = (q-1)/32: coefficients in {0, ..., 15}
    """
    gamma2 = params.gamma2
    k = params.k

    result = bytearray()

    if gamma2 == (Q - 1) // 88:
        # 6 bits per coefficient
        for poly in w1:
            bits = []
            for coef in poly:
                for j in range(6):
                    bits.append((coef >> j) & 1)
            # Pack bits to bytes
            for i in range(len(bits) // 8):
                byte = 0
                for j in range(8):
                    byte |= bits[i * 8 + j] << j
                result.append(byte)
    else:
        # gamma2 = (q-1)/32, 4 bits per coefficient
        for poly in w1:
            for i in range(0, 256, 2):
                byte = (poly[i] & 0x0F) | ((poly[i + 1] & 0x0F) << 4)
                result.append(byte)

    return bytes(result)


def compute_tr(pk: bytes) -> bytes:
    """
    Compute tr = H(pk, 64) = SHAKE256(pk, 64)
    """
    return shake256_xof(pk, 64)


def compute_mu(tr: bytes, M_prime: bytes) -> bytes:
    """
    Compute mu = H(tr || M', 64)
    """
    return shake256_xof(tr + M_prime, 64)


def compute_rho_prime(K: bytes, rnd: bytes, mu: bytes) -> bytes:
    """
    Compute rho' = H(K || rnd || mu, 64)
    For randomized signing
    """
    return shake256_xof(K + rnd + mu, 64)


def compute_rho_prime_deterministic(K: bytes, mu: bytes) -> bytes:
    """
    Compute rho' = H(K || mu, 64)
    For deterministic signing (rnd = 0^32)
    """
    return shake256_xof(K + bytes(32) + mu, 64)
