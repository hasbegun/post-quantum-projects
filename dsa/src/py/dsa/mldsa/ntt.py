"""
Number Theoretic Transform (NTT) for ML-DSA
Based on FIPS 204 Algorithms 33-34

The NTT enables efficient polynomial multiplication in R_q.
"""

from typing import List
from .params import Q, N, ZETA


def bitrev8(x: int) -> int:
    """8-bit reversal"""
    result = 0
    for _ in range(8):
        result = (result << 1) | (x & 1)
        x >>= 1
    return result


# Precompute zetas for NTT
# zeta^(BitRev8(k)) for k = 0, ..., 255
_ZETAS = [pow(ZETA, bitrev8(k), Q) for k in range(256)]


def ntt(w: List[int]) -> List[int]:
    """
    Algorithm 33: NTT
    Number Theoretic Transform

    Input: w in Z_q^256 (polynomial coefficients)
    Output: w_hat in Z_q^256 (NTT representation)

    Converts a polynomial from standard representation to NTT domain.
    """
    w_hat = list(w)  # Copy input

    k = 0
    length = 128
    while length >= 1:
        start = 0
        while start < 256:
            k += 1
            zeta = _ZETAS[k]
            for j in range(start, start + length):
                t = (zeta * w_hat[j + length]) % Q
                w_hat[j + length] = (w_hat[j] - t) % Q
                w_hat[j] = (w_hat[j] + t) % Q
            start += 2 * length
        length //= 2

    return w_hat


def ntt_inv(w_hat: List[int]) -> List[int]:
    """
    Algorithm 34: NTT^(-1)
    Inverse Number Theoretic Transform

    Input: w_hat in Z_q^256 (NTT representation)
    Output: w in Z_q^256 (polynomial coefficients)

    Converts a polynomial from NTT domain back to standard representation.
    """
    w = list(w_hat)  # Copy input

    k = 256
    length = 1
    while length < 256:
        start = 0
        while start < 256:
            k -= 1
            zeta = -_ZETAS[k]  # Note: negative zeta
            for j in range(start, start + length):
                t = w[j]
                w[j] = (t + w[j + length]) % Q
                w[j + length] = (zeta * (t - w[j + length])) % Q
            start += 2 * length
        length *= 2

    # Multiply by n^(-1) = 256^(-1) mod q
    # 256^(-1) mod q = 8347681
    n_inv = pow(256, -1, Q)  # = 8347681
    w = [(c * n_inv) % Q for c in w]

    return w


def ntt_multiply(a_hat: List[int], b_hat: List[int]) -> List[int]:
    """
    Multiply two polynomials in NTT domain (coefficient-wise with special structure)

    For ML-DSA, this is point-wise multiplication since we're in the NTT domain.

    Input: a_hat, b_hat in Z_q^256 (both in NTT representation)
    Output: c_hat in Z_q^256 (product in NTT representation)
    """
    return [(a_hat[i] * b_hat[i]) % Q for i in range(256)]


def poly_add(a: List[int], b: List[int]) -> List[int]:
    """Add two polynomials coefficient-wise"""
    return [(a[i] + b[i]) % Q for i in range(256)]


def poly_sub(a: List[int], b: List[int]) -> List[int]:
    """Subtract two polynomials coefficient-wise"""
    return [(a[i] - b[i]) % Q for i in range(256)]


def poly_scalar_mul(s: int, a: List[int]) -> List[int]:
    """Multiply polynomial by scalar"""
    return [(s * a[i]) % Q for i in range(256)]


def poly_negate(a: List[int]) -> List[int]:
    """Negate polynomial"""
    return [(-a[i]) % Q for i in range(256)]


def poly_reduce(a: List[int]) -> List[int]:
    """Reduce polynomial coefficients to centered representation (-q/2, q/2]"""
    result = []
    for c in a:
        c = c % Q
        if c > Q // 2:
            c -= Q
        result.append(c)
    return result


# Vector operations (vectors of polynomials)
def vec_ntt(v: List[List[int]]) -> List[List[int]]:
    """Apply NTT to each polynomial in vector"""
    return [ntt(p) for p in v]


def vec_ntt_inv(v_hat: List[List[int]]) -> List[List[int]]:
    """Apply inverse NTT to each polynomial in vector"""
    return [ntt_inv(p) for p in v_hat]


def vec_add(a: List[List[int]], b: List[List[int]]) -> List[List[int]]:
    """Add two vectors of polynomials"""
    return [poly_add(a[i], b[i]) for i in range(len(a))]


def vec_sub(a: List[List[int]], b: List[List[int]]) -> List[List[int]]:
    """Subtract two vectors of polynomials"""
    return [poly_sub(a[i], b[i]) for i in range(len(a))]


def mat_vec_mul_ntt(A_hat: List[List[List[int]]], v_hat: List[List[int]]) -> List[List[int]]:
    """
    Multiply matrix by vector in NTT domain
    A_hat is k x l matrix of polynomials in NTT form
    v_hat is length l vector of polynomials in NTT form
    Result is length k vector of polynomials in NTT form
    """
    k = len(A_hat)
    l = len(v_hat)
    result = []
    for i in range(k):
        # Sum over j of A[i][j] * v[j]
        acc = [0] * 256
        for j in range(l):
            prod = ntt_multiply(A_hat[i][j], v_hat[j])
            acc = poly_add(acc, prod)
        result.append(acc)
    return result


def inner_product_ntt(a_hat: List[List[int]], b_hat: List[List[int]]) -> List[int]:
    """
    Compute inner product of two vectors in NTT domain
    Result is single polynomial in NTT form
    """
    acc = [0] * 256
    for i in range(len(a_hat)):
        prod = ntt_multiply(a_hat[i], b_hat[i])
        acc = poly_add(acc, prod)
    return acc
