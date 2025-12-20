"""
SLH-DSA Utility Functions (FIPS 205 Section 4)

Core conversion and utility functions used throughout the implementation.
"""

from typing import List


def toInt(x: bytes, n: int) -> int:
    """
    Algorithm 1: toInt(X, n)

    Converts a byte string X of length n to a non-negative integer.
    Uses big-endian byte order.

    Args:
        x: Input byte string
        n: Length of byte string

    Returns:
        Non-negative integer representation
    """
    total = 0
    for i in range(n):
        total = (total << 8) | x[i]
    return total


def toByte(x: int, n: int) -> bytes:
    """
    Algorithm 2: toByte(x, n)

    Converts a non-negative integer x to a byte string of length n.
    Uses big-endian byte order.

    Args:
        x: Non-negative integer
        n: Desired length of output byte string

    Returns:
        Byte string of length n
    """
    result = bytearray(n)
    for i in range(n - 1, -1, -1):
        result[i] = x & 0xff
        x >>= 8
    return bytes(result)


def base_2b(x: bytes, b: int, out_len: int) -> List[int]:
    """
    Algorithm 3: base_2b(X, b, out_len)

    Computes the base-2^b representation of X.

    Args:
        x: Input byte string
        b: Number of bits per output element
        out_len: Number of output elements

    Returns:
        List of out_len integers, each in range [0, 2^b - 1]
    """
    in_bits = 0
    bits = 0
    result = []
    mask = (1 << b) - 1

    byte_idx = 0
    for _ in range(out_len):
        while bits < b:
            in_bits = (in_bits << 8) | x[byte_idx]
            byte_idx += 1
            bits += 8
        bits -= b
        result.append((in_bits >> bits) & mask)

    return result


def cdiv(a: int, b: int) -> int:
    """Ceiling division."""
    return (a + b - 1) // b


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    return bytes(x ^ y for x, y in zip(a, b))


def concat(*args: bytes) -> bytes:
    """Concatenate multiple byte strings."""
    return b"".join(args)
