"""
Encoding and arithmetic functions for ML-DSA
Based on FIPS 204 Algorithms 21-32
"""

from typing import List, Tuple, Optional
from .params import Q, D, MLDSAParams
from .utils import (
    simple_bit_pack, simple_bit_unpack,
    bit_pack, bit_unpack,
    hint_bit_pack, hint_bit_unpack,
    bytes_to_bits, bits_to_bytes, bits_to_integer, integer_to_bits
)


def pk_encode(rho: bytes, t1: List[List[int]], params: MLDSAParams) -> bytes:
    """
    Algorithm 21: pkEncode
    Encode public key

    Input: rho in B^32, t1 in (Z_{2^(23-d)})^256^k
    Output: pk in B^(32 + 32*k*(23-d))
    """
    pk = bytearray(rho)
    bitlen = 23 - D  # = 10 bits per coefficient
    for i in range(params.k):
        pk.extend(simple_bit_pack(t1[i], bitlen))
    return bytes(pk)


def pk_decode(pk: bytes, params: MLDSAParams) -> Tuple[bytes, List[List[int]]]:
    """
    Algorithm 22: pkDecode
    Decode public key

    Input: pk in B^(32 + 32*k*(23-d))
    Output: (rho in B^32, t1 in (Z_{2^(23-d)})^256^k)
    """
    rho = pk[:32]
    bitlen = 23 - D  # = 10 bits per coefficient
    bytes_per_poly = 32 * bitlen

    t1 = []
    offset = 32
    for i in range(params.k):
        t1.append(simple_bit_unpack(pk[offset:offset + bytes_per_poly], bitlen))
        offset += bytes_per_poly

    return rho, t1


def sk_encode(rho: bytes, K: bytes, tr: bytes,
              s1: List[List[int]], s2: List[List[int]], t0: List[List[int]],
              params: MLDSAParams) -> bytes:
    """
    Algorithm 23: skEncode
    Encode private key

    Input: rho, K in B^32, tr in B^64, s1 in S_eta^l, s2 in S_eta^k, t0 in (Z_{2^(d-1)})^256^k
    Output: sk
    """
    sk = bytearray()
    sk.extend(rho)  # 32 bytes
    sk.extend(K)    # 32 bytes
    sk.extend(tr)   # 64 bytes

    eta = params.eta
    # Encode s1 (l polynomials with eta-bounded coefficients)
    for i in range(params.l):
        sk.extend(bit_pack(s1[i], eta, eta))

    # Encode s2 (k polynomials with eta-bounded coefficients)
    for i in range(params.k):
        sk.extend(bit_pack(s2[i], eta, eta))

    # Encode t0 (k polynomials with coefficients in {-2^(d-1)+1, ..., 2^(d-1)})
    # Actually t0 has coefficients in {-2^(d-1), ..., 2^(d-1)-1} mapped appropriately
    # Using range a=2^(d-1)-1, b=2^(d-1) to cover full range
    d_half = 1 << (D - 1)  # 2^(d-1) = 4096
    for i in range(params.k):
        sk.extend(bit_pack(t0[i], d_half - 1, d_half))

    return bytes(sk)


def sk_decode(sk: bytes, params: MLDSAParams) -> Tuple[bytes, bytes, bytes,
                                                        List[List[int]], List[List[int]], List[List[int]]]:
    """
    Algorithm 24: skDecode
    Decode private key

    Output: (rho, K, tr, s1, s2, t0)
    """
    eta = params.eta
    offset = 0

    rho = sk[offset:offset + 32]
    offset += 32

    K = sk[offset:offset + 32]
    offset += 32

    tr = sk[offset:offset + 64]
    offset += 64

    # Calculate bytes per polynomial
    eta_bits = (2 * eta).bit_length()
    bytes_per_eta_poly = 32 * eta_bits

    # Decode s1
    s1 = []
    for i in range(params.l):
        s1.append(bit_unpack(sk[offset:offset + bytes_per_eta_poly], eta, eta))
        offset += bytes_per_eta_poly

    # Decode s2
    s2 = []
    for i in range(params.k):
        s2.append(bit_unpack(sk[offset:offset + bytes_per_eta_poly], eta, eta))
        offset += bytes_per_eta_poly

    # Decode t0
    d_half = 1 << (D - 1)
    t0_bits = D  # 13 bits
    bytes_per_t0_poly = 32 * t0_bits
    t0 = []
    for i in range(params.k):
        t0.append(bit_unpack(sk[offset:offset + bytes_per_t0_poly], d_half - 1, d_half))
        offset += bytes_per_t0_poly

    return rho, K, tr, s1, s2, t0


def sig_encode(c_tilde: bytes, z: List[List[int]], h: List[List[int]],
               params: MLDSAParams) -> bytes:
    """
    Algorithm 25: sigEncode
    Encode signature

    Input: c_tilde, z, h
    Output: sigma
    """
    sigma = bytearray()
    sigma.extend(c_tilde)  # lambda/4 bytes

    # Encode z with gamma1 range
    gamma1 = params.gamma1
    gamma1_bits = gamma1.bit_length()  # 17 or 19
    for i in range(params.l):
        sigma.extend(bit_pack(z[i], gamma1 - 1, gamma1))

    # Encode hint
    sigma.extend(hint_bit_pack(h, params.omega, params.k))

    return bytes(sigma)


def sig_decode(sigma: bytes, params: MLDSAParams) -> Optional[Tuple[bytes, List[List[int]], List[List[int]]]]:
    """
    Algorithm 26: sigDecode
    Decode signature

    Input: sigma
    Output: (c_tilde, z, h) or None if malformed
    """
    # Check minimum signature length
    if len(sigma) < params.sig_size:
        return None

    try:
        offset = 0

        # Decode c_tilde
        c_tilde_len = params.lambda_ // 4
        c_tilde = sigma[offset:offset + c_tilde_len]
        offset += c_tilde_len

        # Decode z
        gamma1 = params.gamma1
        gamma1_bits = gamma1.bit_length()
        bytes_per_z_poly = 32 * gamma1_bits
        z = []
        for i in range(params.l):
            z.append(bit_unpack(sigma[offset:offset + bytes_per_z_poly], gamma1 - 1, gamma1))
            offset += bytes_per_z_poly

        # Decode hint
        hint_len = params.omega + params.k
        h = hint_bit_unpack(sigma[offset:offset + hint_len], params.omega, params.k)
        if h is None:
            return None

        return c_tilde, z, h
    except Exception:
        return None


def power2round(r: int) -> Tuple[int, int]:
    """
    Algorithm 27: Power2Round
    Decompose r into (r1, r0) such that r = r1 * 2^d + r0

    Input: r in Z_q
    Output: (r1, r0) with r0 in {-2^(d-1)+1, ..., 2^(d-1)}
    """
    r = r % Q
    # r0 = r mod 2^d (centered)
    r0 = r % (1 << D)
    if r0 > (1 << (D - 1)):
        r0 -= (1 << D)
    # r1 = (r - r0) / 2^d
    r1 = (r - r0) >> D
    return r1, r0


def decompose(r: int, gamma2: int) -> Tuple[int, int]:
    """
    Algorithm 28: Decompose
    Decompose r into (r1, r0) for signature scheme

    Input: r in Z_q, gamma2 in {(q-1)/32, (q-1)/88}
    Output: (r1, r0)
    """
    r = r % Q

    # r0 = r mod (2*gamma2) centered
    r0 = r % (2 * gamma2)
    if r0 > gamma2:
        r0 -= 2 * gamma2

    # Handle special case
    if r - r0 == Q - 1:
        r1 = 0
        r0 = r0 - 1
    else:
        r1 = (r - r0) // (2 * gamma2)

    return r1, r0


def high_bits(r: int, gamma2: int) -> int:
    """
    Algorithm 29: HighBits
    Extract high bits of r

    Input: r in Z_q
    Output: r1
    """
    r1, _ = decompose(r, gamma2)
    return r1


def low_bits(r: int, gamma2: int) -> int:
    """
    Algorithm 30: LowBits
    Extract low bits of r

    Input: r in Z_q
    Output: r0
    """
    _, r0 = decompose(r, gamma2)
    return r0


def make_hint(z: int, r: int, gamma2: int) -> int:
    """
    Algorithm 31: MakeHint
    Create hint bit

    Input: z, r in Z_q
    Output: hint in {0, 1}
    """
    r1 = high_bits(r, gamma2)
    v1 = high_bits(r + z, gamma2)
    if r1 != v1:
        return 1
    return 0


def use_hint(h: int, r: int, gamma2: int) -> int:
    """
    Algorithm 32: UseHint
    Use hint to recover high bits

    Input: h in {0, 1}, r in Z_q
    Output: high bits
    """
    m = (Q - 1) // (2 * gamma2)
    r1, r0 = decompose(r, gamma2)

    if h == 1:
        if r0 > 0:
            return (r1 + 1) % m
        else:
            return (r1 - 1) % m
    return r1


# Polynomial-level operations
def poly_power2round(w: List[int]) -> Tuple[List[int], List[int]]:
    """Apply Power2Round to each coefficient"""
    w1 = []
    w0 = []
    for c in w:
        c1, c0 = power2round(c)
        w1.append(c1)
        w0.append(c0)
    return w1, w0


def poly_decompose(w: List[int], gamma2: int) -> Tuple[List[int], List[int]]:
    """Apply Decompose to each coefficient"""
    w1 = []
    w0 = []
    for c in w:
        c1, c0 = decompose(c, gamma2)
        w1.append(c1)
        w0.append(c0)
    return w1, w0


def poly_high_bits(w: List[int], gamma2: int) -> List[int]:
    """Extract high bits from each coefficient"""
    return [high_bits(c, gamma2) for c in w]


def poly_low_bits(w: List[int], gamma2: int) -> List[int]:
    """Extract low bits from each coefficient"""
    return [low_bits(c, gamma2) for c in w]


def poly_make_hint(z: List[int], r: List[int], gamma2: int) -> Tuple[List[int], int]:
    """Make hints for polynomial, returns (hint, count of 1s)"""
    h = []
    count = 0
    for i in range(256):
        hint = make_hint(z[i], r[i], gamma2)
        h.append(hint)
        count += hint
    return h, count


def poly_use_hint(h: List[int], r: List[int], gamma2: int) -> List[int]:
    """Use hints to recover high bits"""
    return [use_hint(h[i], r[i], gamma2) for i in range(256)]


# Vector-level operations
def vec_power2round(v: List[List[int]]) -> Tuple[List[List[int]], List[List[int]]]:
    """Apply Power2Round to vector of polynomials"""
    v1 = []
    v0 = []
    for p in v:
        p1, p0 = poly_power2round(p)
        v1.append(p1)
        v0.append(p0)
    return v1, v0


def vec_decompose(v: List[List[int]], gamma2: int) -> Tuple[List[List[int]], List[List[int]]]:
    """Apply Decompose to vector of polynomials"""
    v1 = []
    v0 = []
    for p in v:
        p1, p0 = poly_decompose(p, gamma2)
        v1.append(p1)
        v0.append(p0)
    return v1, v0


def vec_high_bits(v: List[List[int]], gamma2: int) -> List[List[int]]:
    """Extract high bits from vector"""
    return [poly_high_bits(p, gamma2) for p in v]


def vec_low_bits(v: List[List[int]], gamma2: int) -> List[List[int]]:
    """Extract low bits from vector"""
    return [poly_low_bits(p, gamma2) for p in v]


def vec_make_hint(z: List[List[int]], r: List[List[int]], gamma2: int) -> Tuple[List[List[int]], int]:
    """Make hints for vector, returns (hint_vec, total count)"""
    h = []
    total = 0
    for i in range(len(z)):
        hi, count = poly_make_hint(z[i], r[i], gamma2)
        h.append(hi)
        total += count
    return h, total


def vec_use_hint(h: List[List[int]], r: List[List[int]], gamma2: int) -> List[List[int]]:
    """Use hints to recover high bits for vector"""
    return [poly_use_hint(h[i], r[i], gamma2) for i in range(len(h))]
