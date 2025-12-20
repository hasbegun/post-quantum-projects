"""
XMSS (eXtended Merkle Signature Scheme) Implementation
FIPS 205 Section 6

XMSS extends WOTS+ to allow multiple signatures using a Merkle tree.
"""

from typing import List, Tuple

from .address import ADRS, TREE, WOTS_HASH
from .hash_functions import HashFunctions
from .parameters import SLHDSAParameterSet
from .wots import wots_pkGen, wots_sign, wots_pkFromSig


def xmss_node(
    hash_funcs: HashFunctions,
    sk_seed: bytes,
    i: int,
    z: int,
    pk_seed: bytes,
    adrs: ADRS
) -> bytes:
    """
    Algorithm 8: xmss_node(SK.seed, i, z, PK.seed, ADRS)

    Compute the root of a subtree of the XMSS tree.

    Args:
        hash_funcs: Hash function instantiation
        sk_seed: Secret seed
        i: Leaf index (0 to 2^(h'-z) - 1)
        z: Target node height (0 to h')
        pk_seed: Public seed
        adrs: Address structure

    Returns:
        Node value (n bytes)
    """
    params = hash_funcs.params
    hp = params.hp

    if z > hp or i >= (1 << (hp - z)):
        return b""  # Invalid parameters

    if z == 0:
        # Leaf node: compute WOTS+ public key
        adrs.set_type(WOTS_HASH)
        adrs.set_key_pair_address(i)
        return wots_pkGen(hash_funcs, sk_seed, pk_seed, adrs)
    else:
        # Internal node: hash children
        left = xmss_node(hash_funcs, sk_seed, 2 * i, z - 1, pk_seed, adrs)
        right = xmss_node(hash_funcs, sk_seed, 2 * i + 1, z - 1, pk_seed, adrs)

        adrs.set_type(TREE)
        adrs.set_tree_height(z)
        adrs.set_tree_index(i)

        return hash_funcs.H(pk_seed, adrs, left + right)


def xmss_sign(
    hash_funcs: HashFunctions,
    M: bytes,
    sk_seed: bytes,
    idx: int,
    pk_seed: bytes,
    adrs: ADRS
) -> bytes:
    """
    Algorithm 9: xmss_sign(M, SK.seed, idx, PK.seed, ADRS)

    Generate an XMSS signature.

    Args:
        hash_funcs: Hash function instantiation
        M: Message to sign (n bytes)
        sk_seed: Secret seed
        idx: Leaf index to use
        pk_seed: Public seed
        adrs: Address structure

    Returns:
        XMSS signature (WOTS+ signature + authentication path)
    """
    params = hash_funcs.params
    n = params.n
    hp = params.hp

    # Generate WOTS+ signature
    adrs.set_type(WOTS_HASH)
    adrs.set_key_pair_address(idx)
    sig = wots_sign(hash_funcs, M, sk_seed, pk_seed, adrs)

    # Compute authentication path
    auth = b""
    for j in range(hp):
        # Sibling index at height j
        sibling_idx = (idx >> j) ^ 1
        auth += xmss_node(hash_funcs, sk_seed, sibling_idx, j, pk_seed, adrs)

    return sig + auth


def xmss_pkFromSig(
    hash_funcs: HashFunctions,
    idx: int,
    sig_xmss: bytes,
    M: bytes,
    pk_seed: bytes,
    adrs: ADRS
) -> bytes:
    """
    Algorithm 10: xmss_pkFromSig(idx, SIG_XMSS, M, PK.seed, ADRS)

    Compute XMSS public key (root) from signature.

    Args:
        hash_funcs: Hash function instantiation
        idx: Leaf index used in signature
        sig_xmss: XMSS signature
        M: Message (n bytes)
        pk_seed: Public seed
        adrs: Address structure

    Returns:
        Computed root (n bytes)
    """
    params = hash_funcs.params
    n = params.n
    hp = params.hp
    len_total = params.len_total

    # Extract WOTS+ signature and auth path
    wots_sig_len = len_total * n
    sig_wots = sig_xmss[:wots_sig_len]
    auth = sig_xmss[wots_sig_len:]

    # Compute WOTS+ public key from signature
    adrs.set_type(WOTS_HASH)
    adrs.set_key_pair_address(idx)
    node_0 = wots_pkFromSig(hash_funcs, sig_wots, M, pk_seed, adrs)

    # Compute root using authentication path
    adrs.set_type(TREE)
    node = node_0
    for j in range(hp):
        adrs.set_tree_height(j + 1)
        if (idx >> j) & 1 == 0:
            # Node is left child
            adrs.set_tree_index(idx >> (j + 1))
            auth_node = auth[j * n:(j + 1) * n]
            node = hash_funcs.H(pk_seed, adrs, node + auth_node)
        else:
            # Node is right child
            adrs.set_tree_index(idx >> (j + 1))
            auth_node = auth[j * n:(j + 1) * n]
            node = hash_funcs.H(pk_seed, adrs, auth_node + node)

    return node
