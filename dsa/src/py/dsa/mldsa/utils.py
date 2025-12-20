"""
Utility functions for ML-DSA implementation
Based on FIPS 204 Algorithms 9-15
"""

from typing import List
from hashlib import shake_128, shake_256


def mod_q(x: int, q: int = 8380417) -> int:
    """Reduce x modulo q to range [0, q)"""
    return x % q


def mod_pm(x: int, q: int = 8380417) -> int:
    """Reduce x modulo q to centered range (-q/2, q/2]"""
    r = x % q
    if r > q // 2:
        r -= q
    return r


def integer_to_bits(x: int, alpha: int) -> List[int]:
    """
    Algorithm 9: IntegerToBits
    Convert integer x to bit array of length alpha (LSB first)

    Input: x in {0, 1, ..., 2^alpha - 1}, alpha > 0
    Output: y in {0, 1}^alpha
    """
    y = []
    for _ in range(alpha):
        y.append(x & 1)
        x >>= 1
    return y


def bits_to_integer(y: List[int]) -> int:
    """
    Algorithm 10: BitsToInteger
    Convert bit array to integer (LSB first)

    Input: y in {0, 1}^alpha
    Output: x in {0, 1, ..., 2^alpha - 1}
    """
    x = 0
    for i in range(len(y) - 1, -1, -1):
        x = 2 * x + y[i]
    return x


def bits_to_bytes(y: List[int]) -> bytes:
    """
    Algorithm 11: BitsToBytes
    Convert bit array to byte array

    Input: y in {0, 1}^(8*c) for some c >= 0
    Output: z in B^c
    """
    c = len(y) // 8
    z = bytearray(c)
    for i in range(c):
        z[i] = bits_to_integer(y[8 * i : 8 * i + 8])
    return bytes(z)


def bytes_to_bits(z: bytes) -> List[int]:
    """
    Algorithm 12: BytesToBits
    Convert byte array to bit array

    Input: z in B^c
    Output: y in {0, 1}^(8*c)
    """
    y = []
    for byte in z:
        y.extend(integer_to_bits(byte, 8))
    return y


def coef_from_three_bytes(b0: int, b1: int, b2: int, q: int = 8380417) -> int:
    """
    Algorithm 13: CoefFromThreeBytes
    Extract coefficient from three bytes (for rejection sampling)

    Input: b0, b1, b2 in B
    Output: integer in {0, ..., q-1} or None if rejection
    """
    z = b0 + 256 * b1 + 65536 * (b2 & 0x7F)  # Mask high bit of b2
    if z < q:
        return z
    return None  # Rejection


def coef_from_half_byte(b: int, eta: int) -> int:
    """
    Algorithm 14: CoefFromHalfByte
    Extract coefficient from half byte (for eta-bounded sampling)

    Input: b in {0, ..., 15}, eta in {2, 4}
    Output: integer in {-eta, ..., eta} or None if rejection
    """
    if eta == 2:
        if b < 15:
            return 2 - (b % 5)
        return None  # Rejection
    elif eta == 4:
        if b < 9:
            return 4 - b
        return None  # Rejection
    else:
        raise ValueError(f"Unsupported eta: {eta}")


def simple_bit_pack(w: List[int], b: int) -> bytes:
    """
    Algorithm 15: SimpleBitPack
    Pack array of unsigned integers into bytes

    Input: w in {0, ..., 2^b - 1}^256, b > 0
    Output: z in B^(32*b)
    """
    z = []
    for coef in w:
        z.extend(integer_to_bits(coef, b))
    return bits_to_bytes(z)


def simple_bit_unpack(z: bytes, b: int) -> List[int]:
    """
    Algorithm 16: SimpleBitUnpack (reverse of SimpleBitPack)
    Unpack bytes to array of unsigned integers

    Input: z in B^(32*b), b > 0
    Output: w in {0, ..., 2^b - 1}^256
    """
    bits = bytes_to_bits(z)
    w = []
    for i in range(256):
        w.append(bits_to_integer(bits[b * i : b * i + b]))
    return w


def bit_pack(w: List[int], a: int, b: int) -> bytes:
    """
    Algorithm 17: BitPack
    Pack array of signed integers into bytes

    Input: w in {-a, ..., b}^256 with a, b >= 0
    Output: z in B^(32 * bitlen(a + b))
    """
    bitlen = (a + b).bit_length()
    z = []
    for coef in w:
        # Map [-a, b] to [0, a+b]
        z.extend(integer_to_bits(b - coef, bitlen))
    return bits_to_bytes(z)


def bit_unpack(z: bytes, a: int, b: int) -> List[int]:
    """
    Algorithm 18: BitUnpack (reverse of BitPack)
    Unpack bytes to array of signed integers

    Input: z in B^(32 * bitlen(a + b))
    Output: w in {-a, ..., b}^256
    """
    bitlen = (a + b).bit_length()
    bits = bytes_to_bits(z)
    w = []
    for i in range(256):
        val = bits_to_integer(bits[bitlen * i : bitlen * i + bitlen])
        w.append(b - val)
    return w


def hint_bit_pack(h: List[List[int]], omega: int, k: int) -> bytes:
    """
    Algorithm 19: HintBitPack
    Pack hint polynomial vector into bytes

    Input: h in {h in {0,1}^256 : ||h||_1 <= omega}^k
    Output: y in B^(omega + k)
    """
    y = bytearray(omega + k)
    idx = 0
    for i in range(k):
        for j in range(256):
            if h[i][j] == 1:
                y[idx] = j
                idx += 1
        y[omega + i] = idx
    return bytes(y)


def hint_bit_unpack(y: bytes, omega: int, k: int) -> List[List[int]]:
    """
    Algorithm 20: HintBitUnpack
    Unpack bytes to hint polynomial vector

    Input: y in B^(omega + k)
    Output: h in {h in {0,1}^256 : ||h||_1 <= omega}^k or None if malformed
    """
    h = [[0] * 256 for _ in range(k)]
    idx = 0
    for i in range(k):
        end = y[omega + i]
        if end < idx or end > omega:
            return None  # Malformed hint

        first = idx
        while idx < end:
            if idx > first:
                if y[idx] <= y[idx - 1]:
                    return None  # Indices must be strictly increasing
            h[i][y[idx]] = 1
            idx += 1
    # Check remaining indices are zero (implicitly by checking idx == last end)
    if idx != y[omega + k - 1]:
        return None
    return h


# SHAKE functions
def shake128_xof(data: bytes, output_len: int) -> bytes:
    """SHAKE128 XOF"""
    return shake_128(data).digest(output_len)


def shake256_xof(data: bytes, output_len: int) -> bytes:
    """SHAKE256 XOF"""
    return shake_256(data).digest(output_len)


class SHAKE128Stream:
    """Streaming SHAKE128 XOF"""
    def __init__(self, data: bytes):
        self._hasher = shake_128(data)
        self._buffer = b""
        self._pos = 0
        self._total_read = 0

    def read(self, n: int) -> bytes:
        """Read n bytes from the XOF stream"""
        # We need to generate enough bytes
        needed = self._total_read + n
        if len(self._buffer) < needed:
            # Generate more bytes (with some buffer)
            self._buffer = self._hasher.digest(needed + 1024)
        result = self._buffer[self._total_read : self._total_read + n]
        self._total_read += n
        return result


class SHAKE256Stream:
    """Streaming SHAKE256 XOF"""
    def __init__(self, data: bytes):
        self._hasher = shake_256(data)
        self._buffer = b""
        self._pos = 0
        self._total_read = 0

    def read(self, n: int) -> bytes:
        """Read n bytes from the XOF stream"""
        needed = self._total_read + n
        if len(self._buffer) < needed:
            self._buffer = self._hasher.digest(needed + 1024)
        result = self._buffer[self._total_read : self._total_read + n]
        self._total_read += n
        return result


def infinity_norm(w: List[int]) -> int:
    """Compute infinity norm (max absolute value) of polynomial"""
    return max(abs(c) for c in w)


def infinity_norm_vec(v: List[List[int]]) -> int:
    """Compute infinity norm of vector of polynomials"""
    return max(infinity_norm(p) for p in v)
