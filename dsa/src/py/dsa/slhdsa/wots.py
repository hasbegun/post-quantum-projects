"""
WOTS+ (Winternitz One-Time Signature Plus) Implementation
FIPS 205 Section 5

WOTS+ is the base one-time signature scheme used in SLH-DSA.
"""

from typing import List

from .address import ADRS, WOTS_HASH, WOTS_PK, WOTS_PRF
from .hash_functions import HashFunctions
from .parameters import SLHDSAParameterSet
from .utils import base_2b, toByte


def chain(
    hash_funcs: HashFunctions,
    X: bytes,
    i: int,
    s: int,
    pk_seed: bytes,
    adrs: ADRS
) -> bytes:
    """
    Algorithm 4: chain(X, i, s, PK.seed, ADRS)

    Compute the s-step hash chain starting at X from position i.

    Args:
        hash_funcs: Hash function instantiation
        X: Starting value (n bytes)
        i: Starting index in chain
        s: Number of steps
        pk_seed: Public seed
        adrs: Address structure (will be modified)

    Returns:
        Chain output (n bytes)
    """
    if s == 0:
        return X

    if i + s > hash_funcs.params.w:
        return b""  # Invalid parameters

    tmp = X
    for j in range(i, i + s):
        adrs.set_hash_address(j)
        tmp = hash_funcs.F(pk_seed, adrs, tmp)

    return tmp


def wots_pkGen(
    hash_funcs: HashFunctions,
    sk_seed: bytes,
    pk_seed: bytes,
    adrs: ADRS
) -> bytes:
    """
    Algorithm 5: wots_pkGen(SK.seed, PK.seed, ADRS)

    Generate a WOTS+ public key.

    Args:
        hash_funcs: Hash function instantiation
        sk_seed: Secret seed
        pk_seed: Public seed
        adrs: Address structure

    Returns:
        WOTS+ public key (n bytes, compressed)
    """
    params = hash_funcs.params
    n = params.n
    len_total = params.len_total

    # Generate chain endpoints
    sk_adrs = adrs.copy()
    sk_adrs.set_type(WOTS_PRF)
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address())

    chain_adrs = adrs.copy()
    chain_adrs.set_type(WOTS_HASH)
    chain_adrs.set_key_pair_address(adrs.get_key_pair_address())

    tmp = b""
    for i in range(len_total):
        # Generate secret key element
        sk_adrs.set_chain_address(i)
        sk_i = hash_funcs.PRF(pk_seed, sk_seed, sk_adrs)

        # Compute chain endpoint
        chain_adrs.set_chain_address(i)
        tmp += chain(hash_funcs, sk_i, 0, params.w - 1, pk_seed, chain_adrs)

    # Compress public key
    pk_adrs = adrs.copy()
    pk_adrs.set_type(WOTS_PK)
    pk_adrs.set_key_pair_address(adrs.get_key_pair_address())

    pk = hash_funcs.T_l(pk_seed, pk_adrs, tmp)
    return pk


def wots_sign(
    hash_funcs: HashFunctions,
    M: bytes,
    sk_seed: bytes,
    pk_seed: bytes,
    adrs: ADRS
) -> bytes:
    """
    Algorithm 6: wots_sign(M, SK.seed, PK.seed, ADRS)

    Generate a WOTS+ signature for message M.

    Args:
        hash_funcs: Hash function instantiation
        M: Message to sign (n bytes)
        sk_seed: Secret seed
        pk_seed: Public seed
        adrs: Address structure

    Returns:
        WOTS+ signature (len_total * n bytes)
    """
    params = hash_funcs.params
    n = params.n
    len1 = params.len1
    len2 = params.len2
    len_total = params.len_total
    w = params.w
    lg_w = params.lg_w

    # Convert message to base-w
    msg = base_2b(M, lg_w, len1)

    # Compute checksum
    csum = 0
    for i in range(len1):
        csum += w - 1 - msg[i]

    # Append checksum in base-w
    csum_bytes = toByte(csum << (8 - ((len2 * lg_w) % 8)) % 8, (len2 * lg_w + 7) // 8)
    csum_base_w = base_2b(csum_bytes, lg_w, len2)
    msg_all = msg + csum_base_w

    # Generate signature
    sk_adrs = adrs.copy()
    sk_adrs.set_type(WOTS_PRF)
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address())

    chain_adrs = adrs.copy()
    chain_adrs.set_type(WOTS_HASH)
    chain_adrs.set_key_pair_address(adrs.get_key_pair_address())

    sig = b""
    for i in range(len_total):
        sk_adrs.set_chain_address(i)
        sk_i = hash_funcs.PRF(pk_seed, sk_seed, sk_adrs)

        chain_adrs.set_chain_address(i)
        sig += chain(hash_funcs, sk_i, 0, msg_all[i], pk_seed, chain_adrs)

    return sig


def wots_pkFromSig(
    hash_funcs: HashFunctions,
    sig: bytes,
    M: bytes,
    pk_seed: bytes,
    adrs: ADRS
) -> bytes:
    """
    Algorithm 7: wots_pkFromSig(sig, M, PK.seed, ADRS)

    Compute WOTS+ public key from signature.

    Args:
        hash_funcs: Hash function instantiation
        sig: WOTS+ signature
        M: Message (n bytes)
        pk_seed: Public seed
        adrs: Address structure

    Returns:
        Recovered public key (n bytes)
    """
    params = hash_funcs.params
    n = params.n
    len1 = params.len1
    len2 = params.len2
    len_total = params.len_total
    w = params.w
    lg_w = params.lg_w

    # Convert message to base-w
    msg = base_2b(M, lg_w, len1)

    # Compute checksum
    csum = 0
    for i in range(len1):
        csum += w - 1 - msg[i]

    # Append checksum in base-w
    csum_bytes = toByte(csum << (8 - ((len2 * lg_w) % 8)) % 8, (len2 * lg_w + 7) // 8)
    csum_base_w = base_2b(csum_bytes, lg_w, len2)
    msg_all = msg + csum_base_w

    # Compute chain endpoints from signature
    chain_adrs = adrs.copy()
    chain_adrs.set_type(WOTS_HASH)
    chain_adrs.set_key_pair_address(adrs.get_key_pair_address())

    tmp = b""
    for i in range(len_total):
        chain_adrs.set_chain_address(i)
        sig_i = sig[i * n:(i + 1) * n]
        tmp += chain(hash_funcs, sig_i, msg_all[i], w - 1 - msg_all[i], pk_seed, chain_adrs)

    # Compress to get public key
    pk_adrs = adrs.copy()
    pk_adrs.set_type(WOTS_PK)
    pk_adrs.set_key_pair_address(adrs.get_key_pair_address())

    return hash_funcs.T_l(pk_seed, pk_adrs, tmp)
