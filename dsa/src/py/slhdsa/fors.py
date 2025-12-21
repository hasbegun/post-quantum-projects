"""
FORS (Forest of Random Subsets) Implementation
FIPS 205 Section 8

FORS is a few-time signature scheme used to sign the message digest in SLH-DSA.
"""

from typing import List

from .address import ADRS, FORS_TREE, FORS_ROOTS, FORS_PRF
from .hash_functions import HashFunctions
from .parameters import SLHDSAParameterSet
from .utils import base_2b


def fors_skGen(
    hash_funcs: HashFunctions,
    sk_seed: bytes,
    pk_seed: bytes,
    adrs: ADRS,
    idx: int
) -> bytes:
    """
    Algorithm 13: fors_skGen(SK.seed, PK.seed, ADRS, idx)

    Generate a FORS secret key element.

    Args:
        hash_funcs: Hash function instantiation
        sk_seed: Secret seed
        pk_seed: Public seed
        adrs: Address structure
        idx: Secret key index (global across all k trees)

    Returns:
        FORS secret key element (n bytes)
    """
    sk_adrs = adrs.copy()
    sk_adrs.set_type(FORS_PRF)
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address())
    sk_adrs.set_tree_index(idx)

    return hash_funcs.PRF(pk_seed, sk_seed, sk_adrs)


def fors_node(
    hash_funcs: HashFunctions,
    sk_seed: bytes,
    i: int,
    z: int,
    pk_seed: bytes,
    adrs: ADRS
) -> bytes:
    """
    Algorithm 14: fors_node(SK.seed, i, z, PK.seed, ADRS)

    Compute a FORS tree node.

    Uses global indexing: at height z, there are k * 2^(a-z) nodes total.
    Node i at height z covers leaves from i * 2^z to (i+1) * 2^z - 1.

    Args:
        hash_funcs: Hash function instantiation
        sk_seed: Secret seed
        i: Global node index at height z
        z: Target node height
        pk_seed: Public seed
        adrs: Address structure

    Returns:
        Node value (n bytes)
    """
    params = hash_funcs.params
    a = params.a
    k = params.k

    if z == 0:
        # Leaf node: hash secret key element
        sk = fors_skGen(hash_funcs, sk_seed, pk_seed, adrs, i)
        adrs.set_tree_height(0)
        adrs.set_tree_index(i)
        return hash_funcs.F(pk_seed, adrs, sk)
    else:
        # Internal node: hash children
        left = fors_node(hash_funcs, sk_seed, 2 * i, z - 1, pk_seed, adrs)
        right = fors_node(hash_funcs, sk_seed, 2 * i + 1, z - 1, pk_seed, adrs)

        adrs.set_tree_height(z)
        adrs.set_tree_index(i)

        return hash_funcs.H(pk_seed, adrs, left + right)


def fors_sign(
    hash_funcs: HashFunctions,
    md: bytes,
    sk_seed: bytes,
    pk_seed: bytes,
    adrs: ADRS
) -> bytes:
    """
    Algorithm 15: fors_sign(md, SK.seed, PK.seed, ADRS)

    Generate a FORS signature.

    Args:
        hash_funcs: Hash function instantiation
        md: Message digest (ceil(k*a/8) bytes)
        sk_seed: Secret seed
        pk_seed: Public seed
        adrs: Address structure

    Returns:
        FORS signature (k * (a+1) * n bytes)
    """
    params = hash_funcs.params
    n = params.n
    k = params.k
    a = params.a

    # Parse message digest into k a-bit values
    indices = base_2b(md, a, k)

    sig_fors = b""
    for i in range(k):
        idx = indices[i]

        # Global leaf index for selected leaf in tree i
        global_leaf_idx = i * (1 << a) + idx

        # Add secret key element
        sig_fors += fors_skGen(hash_funcs, sk_seed, pk_seed, adrs, global_leaf_idx)

        # Add authentication path
        for j in range(a):
            # Sibling index at height j (local within subtree)
            s = (idx >> j) ^ 1
            # Global node index at height j
            # At height j, tree i's nodes start at index i * 2^(a-j)
            global_node_idx = i * (1 << (a - j)) + s
            sig_fors += fors_node(hash_funcs, sk_seed, global_node_idx, j, pk_seed, adrs)

    return sig_fors


def fors_pkFromSig(
    hash_funcs: HashFunctions,
    sig_fors: bytes,
    md: bytes,
    pk_seed: bytes,
    adrs: ADRS
) -> bytes:
    """
    Algorithm 16: fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS)

    Compute FORS public key from signature.

    Args:
        hash_funcs: Hash function instantiation
        sig_fors: FORS signature
        md: Message digest
        pk_seed: Public seed
        adrs: Address structure

    Returns:
        FORS public key (n bytes)
    """
    params = hash_funcs.params
    n = params.n
    k = params.k
    a = params.a

    # Parse message digest into k a-bit values
    indices = base_2b(md, a, k)

    # Size of one FORS tree signature (sk + auth path)
    fors_tree_sig_len = (a + 1) * n

    roots = b""
    for i in range(k):
        idx = indices[i]

        # Extract signature for tree i
        offset = i * fors_tree_sig_len
        sk = sig_fors[offset:offset + n]
        auth = sig_fors[offset + n:offset + fors_tree_sig_len]

        # Global leaf index
        global_leaf_idx = i * (1 << a) + idx

        # Compute leaf from secret key
        adrs.set_tree_height(0)
        adrs.set_tree_index(global_leaf_idx)
        node = hash_funcs.F(pk_seed, adrs, sk)

        # Compute root using authentication path
        for j in range(a):
            adrs.set_tree_height(j + 1)
            auth_node = auth[j * n:(j + 1) * n]

            # Compute parent index
            # At height j+1, tree i's nodes start at i * 2^(a-j-1)
            parent_local_idx = idx >> (j + 1)
            global_parent_idx = i * (1 << (a - j - 1)) + parent_local_idx
            adrs.set_tree_index(global_parent_idx)

            if (idx >> j) & 1 == 0:
                # Node is left child
                node = hash_funcs.H(pk_seed, adrs, node + auth_node)
            else:
                # Node is right child
                node = hash_funcs.H(pk_seed, adrs, auth_node + node)

        roots += node

    # Compress roots
    pk_adrs = adrs.copy()
    pk_adrs.set_type(FORS_ROOTS)
    pk_adrs.set_key_pair_address(adrs.get_key_pair_address())

    return hash_funcs.T_l(pk_seed, pk_adrs, roots)
