"""
Hypertree Implementation
FIPS 205 Section 7

The hypertree is a tree of XMSS trees that enables signing capacity
beyond what a single XMSS tree can provide.
"""

from .address import ADRS
from .hash_functions import HashFunctions
from .parameters import SLHDSAParameterSet
from .xmss import xmss_node, xmss_sign, xmss_pkFromSig


def ht_sign(
    hash_funcs: HashFunctions,
    M: bytes,
    sk_seed: bytes,
    pk_seed: bytes,
    idx_tree: int,
    idx_leaf: int
) -> bytes:
    """
    Algorithm 11: ht_sign(M, SK.seed, PK.seed, idx_tree, idx_leaf)

    Generate a hypertree signature.

    Args:
        hash_funcs: Hash function instantiation
        M: Message to sign (n bytes)
        sk_seed: Secret seed
        pk_seed: Public seed
        idx_tree: Tree index (identifies the XMSS tree in the forest)
        idx_leaf: Leaf index within the tree

    Returns:
        Hypertree signature (d XMSS signatures)
    """
    params = hash_funcs.params
    n = params.n
    d = params.d
    hp = params.hp

    # Initialize address for layer 0
    adrs = ADRS()
    adrs.set_layer_address(0)
    adrs.set_tree_address(idx_tree)

    # Sign with bottom XMSS tree
    sig_tmp = xmss_sign(hash_funcs, M, sk_seed, idx_leaf, pk_seed, adrs)
    sig_ht = sig_tmp

    # Get root of bottom tree for next layer
    root = xmss_node(hash_funcs, sk_seed, 0, hp, pk_seed, adrs)

    # Sign with remaining layers
    for j in range(1, d):
        # Update indices for next layer
        idx_leaf = idx_tree % (1 << hp)
        idx_tree = idx_tree >> hp

        # Update address for layer j
        adrs.set_layer_address(j)
        adrs.set_tree_address(idx_tree)

        # Sign root with XMSS at layer j
        sig_tmp = xmss_sign(hash_funcs, root, sk_seed, idx_leaf, pk_seed, adrs)
        sig_ht += sig_tmp

        # Compute root for next layer (if not last)
        if j < d - 1:
            root = xmss_node(hash_funcs, sk_seed, 0, hp, pk_seed, adrs)

    return sig_ht


def ht_verify(
    hash_funcs: HashFunctions,
    M: bytes,
    sig_ht: bytes,
    pk_seed: bytes,
    idx_tree: int,
    idx_leaf: int,
    pk_root: bytes
) -> bool:
    """
    Algorithm 12: ht_verify(M, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root)

    Verify a hypertree signature.

    Args:
        hash_funcs: Hash function instantiation
        M: Message (n bytes)
        sig_ht: Hypertree signature
        pk_seed: Public seed
        idx_tree: Tree index
        idx_leaf: Leaf index
        pk_root: Expected root (public key)

    Returns:
        True if signature is valid, False otherwise
    """
    params = hash_funcs.params
    n = params.n
    d = params.d
    hp = params.hp
    len_total = params.len_total

    # Size of one XMSS signature
    xmss_sig_len = (len_total + hp) * n

    # Initialize address for layer 0
    adrs = ADRS()
    adrs.set_layer_address(0)
    adrs.set_tree_address(idx_tree)

    # Extract first XMSS signature
    sig_xmss = sig_ht[:xmss_sig_len]
    offset = xmss_sig_len

    # Compute root from bottom layer
    node = xmss_pkFromSig(hash_funcs, idx_leaf, sig_xmss, M, pk_seed, adrs)

    # Verify remaining layers
    for j in range(1, d):
        # Update indices for next layer
        idx_leaf = idx_tree % (1 << hp)
        idx_tree = idx_tree >> hp

        # Update address for layer j
        adrs.set_layer_address(j)
        adrs.set_tree_address(idx_tree)

        # Extract XMSS signature for layer j
        sig_xmss = sig_ht[offset:offset + xmss_sig_len]
        offset += xmss_sig_len

        # Compute root using signature
        node = xmss_pkFromSig(hash_funcs, idx_leaf, sig_xmss, node, pk_seed, adrs)

    # Verify computed root matches public key
    return node == pk_root
