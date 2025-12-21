"""
SLH-DSA Core Functions
FIPS 205 Sections 9 and 10

Main key generation, signing, and verification functions.
"""

import os
import hashlib
from typing import Tuple, Optional

from .address import ADRS, FORS_TREE
from .fors import fors_sign, fors_pkFromSig
from .hash_functions import HashFunctions, get_hash_functions
from .hypertree import ht_sign, ht_verify
from .parameters import SLHDSAParameterSet
from .utils import toByte, toInt
from .xmss import xmss_node


# Domain separators for pure and pre-hash modes (FIPS 205 Section 10)
PURE_MODE_PREFIX = b"\x00"
PREHASH_MODE_PREFIX = b"\x01"

# Pre-hash OID for SHA-256 (can extend for other hash functions)
SHA256_OID = bytes([
    0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
])


def slh_keygen_internal(
    params: SLHDSAParameterSet,
    sk_seed: bytes,
    sk_prf: bytes,
    pk_seed: bytes
) -> Tuple[bytes, bytes]:
    """
    Algorithm 17: slh_keygen_internal(SK.seed, SK.prf, PK.seed)

    Internal key generation.

    Args:
        params: Parameter set
        sk_seed: Secret seed (n bytes)
        sk_prf: PRF key for randomizing (n bytes)
        pk_seed: Public seed (n bytes)

    Returns:
        Tuple of (secret_key, public_key)
    """
    hash_funcs = get_hash_functions(params)
    n = params.n
    hp = params.hp

    # Compute root of top-level XMSS tree
    adrs = ADRS()
    adrs.set_layer_address(params.d - 1)
    adrs.set_tree_address(0)

    pk_root = xmss_node(hash_funcs, sk_seed, 0, hp, pk_seed, adrs)

    # Form keys
    sk = sk_seed + sk_prf + pk_seed + pk_root
    pk = pk_seed + pk_root

    return sk, pk


def slh_sign_internal(
    params: SLHDSAParameterSet,
    M: bytes,
    sk: bytes,
    randomize: bool = True,
    opt_rand: Optional[bytes] = None
) -> bytes:
    """
    Algorithm 18: slh_sign_internal(M, SK, opt_rand)

    Internal signing function.

    Args:
        params: Parameter set
        M: Message to sign
        sk: Secret key
        randomize: Whether to use randomized signing
        opt_rand: Optional randomness (for deterministic mode, use pk_seed)

    Returns:
        SLH-DSA signature
    """
    hash_funcs = get_hash_functions(params)
    n = params.n
    h = params.h
    d = params.d
    hp = params.hp
    k = params.k
    a = params.a
    m = params.m

    # Parse secret key
    sk_seed = sk[0:n]
    sk_prf = sk[n:2*n]
    pk_seed = sk[2*n:3*n]
    pk_root = sk[3*n:4*n]

    # Generate randomizer
    if opt_rand is None:
        if randomize:
            opt_rand = os.urandom(n)
        else:
            opt_rand = pk_seed

    R = hash_funcs.PRF_msg(sk_prf, opt_rand, M)

    # Compute message digest
    digest = hash_funcs.H_msg(R, pk_seed, pk_root, M)

    # Split digest into indices
    # First part: FORS message (ceil(k*a/8) bytes)
    md_len = (k * a + 7) // 8
    md = digest[0:md_len]

    # Second part: tree index (ceil((h - h/d)/8) bytes)
    tree_bits = h - hp
    tree_len = (tree_bits + 7) // 8
    idx_tree = toInt(digest[md_len:md_len + tree_len], tree_len) % (1 << tree_bits)

    # Third part: leaf index (ceil(h'/8) bytes)
    leaf_len = (hp + 7) // 8
    idx_leaf = toInt(digest[md_len + tree_len:md_len + tree_len + leaf_len], leaf_len) % (1 << hp)

    # Generate FORS signature
    adrs = ADRS()
    adrs.set_layer_address(0)
    adrs.set_tree_address(idx_tree)
    adrs.set_type(FORS_TREE)
    adrs.set_key_pair_address(idx_leaf)

    sig_fors = fors_sign(hash_funcs, md, sk_seed, pk_seed, adrs)

    # Get FORS public key for HT signing
    pk_fors = fors_pkFromSig(hash_funcs, sig_fors, md, pk_seed, adrs)

    # Generate hypertree signature
    sig_ht = ht_sign(hash_funcs, pk_fors, sk_seed, pk_seed, idx_tree, idx_leaf)

    # Assemble signature
    sig = R + sig_fors + sig_ht

    return sig


def slh_verify_internal(
    params: SLHDSAParameterSet,
    M: bytes,
    sig: bytes,
    pk: bytes
) -> bool:
    """
    Algorithm 19: slh_verify_internal(M, SIG, PK)

    Internal verification function.

    Args:
        params: Parameter set
        M: Message
        sig: Signature
        pk: Public key

    Returns:
        True if valid, False otherwise
    """
    hash_funcs = get_hash_functions(params)
    n = params.n
    h = params.h
    d = params.d
    hp = params.hp
    k = params.k
    a = params.a
    m = params.m

    # Check signature length
    expected_len = params.sig_size
    if len(sig) != expected_len:
        return False

    # Check public key length
    if len(pk) != params.pk_size:
        return False

    # Parse public key
    pk_seed = pk[0:n]
    pk_root = pk[n:2*n]

    # Parse signature
    R = sig[0:n]
    sig_fors_len = k * (a + 1) * n
    sig_fors = sig[n:n + sig_fors_len]
    sig_ht = sig[n + sig_fors_len:]

    # Compute message digest
    digest = hash_funcs.H_msg(R, pk_seed, pk_root, M)

    # Split digest into indices
    md_len = (k * a + 7) // 8
    md = digest[0:md_len]

    tree_bits = h - hp
    tree_len = (tree_bits + 7) // 8
    idx_tree = toInt(digest[md_len:md_len + tree_len], tree_len) % (1 << tree_bits)

    leaf_len = (hp + 7) // 8
    idx_leaf = toInt(digest[md_len + tree_len:md_len + tree_len + leaf_len], leaf_len) % (1 << hp)

    # Recover FORS public key from signature
    adrs = ADRS()
    adrs.set_layer_address(0)
    adrs.set_tree_address(idx_tree)
    adrs.set_type(FORS_TREE)
    adrs.set_key_pair_address(idx_leaf)

    pk_fors = fors_pkFromSig(hash_funcs, sig_fors, md, pk_seed, adrs)

    # Verify hypertree signature
    return ht_verify(hash_funcs, pk_fors, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root)


# External API functions (FIPS 205 Section 10)

def slh_keygen(params: SLHDSAParameterSet) -> Tuple[bytes, bytes]:
    """
    Algorithm 20: slh_keygen()

    Generate an SLH-DSA key pair.

    Args:
        params: Parameter set to use

    Returns:
        Tuple of (secret_key, public_key)
    """
    n = params.n

    # Generate random seeds
    sk_seed = os.urandom(n)
    sk_prf = os.urandom(n)
    pk_seed = os.urandom(n)

    return slh_keygen_internal(params, sk_seed, sk_prf, pk_seed)


def slh_sign(
    params: SLHDSAParameterSet,
    M: bytes,
    sk: bytes,
    ctx: bytes = b"",
    randomize: bool = True
) -> bytes:
    """
    Algorithm 21: slh_sign(M, SK, ctx)

    Sign a message in pure mode.

    Args:
        params: Parameter set
        M: Message to sign
        sk: Secret key
        ctx: Context string (0-255 bytes)
        randomize: Whether to use randomized signing

    Returns:
        SLH-DSA signature

    Raises:
        ValueError: If context string is too long
    """
    if len(ctx) > 255:
        raise ValueError("Context string must be at most 255 bytes")

    # Form prefixed message
    M_prime = PURE_MODE_PREFIX + bytes([len(ctx)]) + ctx + M

    return slh_sign_internal(params, M_prime, sk, randomize)


def hash_slh_sign(
    params: SLHDSAParameterSet,
    M: bytes,
    sk: bytes,
    ctx: bytes = b"",
    ph: str = "SHA-256",
    randomize: bool = True
) -> bytes:
    """
    Algorithm 22: hash_slh_sign(M, SK, ctx, PH)

    Sign a message in pre-hash mode.

    Args:
        params: Parameter set
        M: Message to sign
        sk: Secret key
        ctx: Context string (0-255 bytes)
        ph: Pre-hash function identifier
        randomize: Whether to use randomized signing

    Returns:
        SLH-DSA signature

    Raises:
        ValueError: If context string is too long or ph is unsupported
    """
    if len(ctx) > 255:
        raise ValueError("Context string must be at most 255 bytes")

    # Compute pre-hash
    if ph == "SHA-256":
        ph_oid = SHA256_OID
        ph_hash = hashlib.sha256(M).digest()
    else:
        raise ValueError(f"Unsupported pre-hash function: {ph}")

    # Form prefixed message
    M_prime = PREHASH_MODE_PREFIX + bytes([len(ctx)]) + ctx + ph_oid + ph_hash

    return slh_sign_internal(params, M_prime, sk, randomize)


def slh_verify(
    params: SLHDSAParameterSet,
    M: bytes,
    sig: bytes,
    pk: bytes,
    ctx: bytes = b""
) -> bool:
    """
    Algorithm 23: slh_verify(M, SIG, PK, ctx)

    Verify a signature in pure mode.

    Args:
        params: Parameter set
        M: Message
        sig: Signature
        pk: Public key
        ctx: Context string (0-255 bytes)

    Returns:
        True if valid, False otherwise
    """
    if len(ctx) > 255:
        return False

    # Form prefixed message
    M_prime = PURE_MODE_PREFIX + bytes([len(ctx)]) + ctx + M

    return slh_verify_internal(params, M_prime, sig, pk)


def hash_slh_verify(
    params: SLHDSAParameterSet,
    M: bytes,
    sig: bytes,
    pk: bytes,
    ctx: bytes = b"",
    ph: str = "SHA-256"
) -> bool:
    """
    Algorithm 24: hash_slh_verify(M, SIG, PK, ctx, PH)

    Verify a signature in pre-hash mode.

    Args:
        params: Parameter set
        M: Message
        sig: Signature
        pk: Public key
        ctx: Context string (0-255 bytes)
        ph: Pre-hash function identifier

    Returns:
        True if valid, False otherwise
    """
    if len(ctx) > 255:
        return False

    # Compute pre-hash
    if ph == "SHA-256":
        ph_oid = SHA256_OID
        ph_hash = hashlib.sha256(M).digest()
    else:
        return False

    # Form prefixed message
    M_prime = PREHASH_MODE_PREFIX + bytes([len(ctx)]) + ctx + ph_oid + ph_hash

    return slh_verify_internal(params, M_prime, sig, pk)
