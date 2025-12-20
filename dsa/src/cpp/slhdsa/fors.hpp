/**
 * FORS (Forest of Random Subsets) Implementation
 * FIPS 205 Section 8
 *
 * FORS is a few-time signature scheme used to sign the message digest in SLH-DSA.
 *
 * SECURITY: This implementation uses constant-time operations for tree
 * traversal to resist timing-based side-channel attacks.
 */

#ifndef SLHDSA_FORS_HPP
#define SLHDSA_FORS_HPP

#include "params.hpp"
#include "address.hpp"
#include "hash_functions.hpp"
#include "utils.hpp"
#include "ct_utils.hpp"
#include <vector>
#include <span>
#include <cstdint>

namespace slhdsa {

/**
 * Algorithm 13: fors_skGen(SK.seed, PK.seed, ADRS, idx)
 *
 * Generate a FORS secret key element.
 *
 * @param hash_funcs Hash function instantiation
 * @param sk_seed Secret seed
 * @param pk_seed Public seed
 * @param adrs Address structure
 * @param idx Secret key index (global across all k trees)
 * @return FORS secret key element (n bytes)
 */
inline std::vector<uint8_t> fors_skGen(
    const HashFunctions& hash_funcs,
    std::span<const uint8_t> sk_seed,
    std::span<const uint8_t> pk_seed,
    const ADRS& adrs,
    uint32_t idx) {

    ADRS sk_adrs = adrs.copy();
    sk_adrs.set_type(AddressType::FORS_PRF);
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address());
    sk_adrs.set_tree_index(idx);

    return hash_funcs.PRF(pk_seed, sk_seed, sk_adrs);
}

/**
 * Algorithm 14: fors_node(SK.seed, i, z, PK.seed, ADRS)
 *
 * Compute a FORS tree node.
 *
 * Uses global indexing: at height z, there are k * 2^(a-z) nodes total.
 * Node i at height z covers leaves from i * 2^z to (i+1) * 2^z - 1.
 *
 * @param hash_funcs Hash function instantiation
 * @param sk_seed Secret seed
 * @param i Global node index at height z
 * @param z Target node height
 * @param pk_seed Public seed
 * @param adrs Address structure
 * @return Node value (n bytes)
 */
inline std::vector<uint8_t> fors_node(
    const HashFunctions& hash_funcs,
    std::span<const uint8_t> sk_seed,
    uint32_t i,
    uint32_t z,
    std::span<const uint8_t> pk_seed,
    ADRS adrs) {

    if (z == 0) {
        // Leaf node: hash secret key element
        auto sk = fors_skGen(hash_funcs, sk_seed, pk_seed, adrs, i);
        adrs.set_tree_height(0);
        adrs.set_tree_index(i);
        return hash_funcs.F(pk_seed, adrs, sk);
    } else {
        // Internal node: hash children
        auto left = fors_node(hash_funcs, sk_seed, 2 * i, z - 1, pk_seed, adrs);
        auto right = fors_node(hash_funcs, sk_seed, 2 * i + 1, z - 1, pk_seed, adrs);

        adrs.set_tree_height(z);
        adrs.set_tree_index(i);

        // Concatenate left and right
        std::vector<uint8_t> concat;
        concat.reserve(left.size() + right.size());
        concat.insert(concat.end(), left.begin(), left.end());
        concat.insert(concat.end(), right.begin(), right.end());

        return hash_funcs.H(pk_seed, adrs, concat);
    }
}

/**
 * Algorithm 15: fors_sign(md, SK.seed, PK.seed, ADRS)
 *
 * Generate a FORS signature.
 *
 * @param hash_funcs Hash function instantiation
 * @param md Message digest (ceil(k*a/8) bytes)
 * @param sk_seed Secret seed
 * @param pk_seed Public seed
 * @param adrs Address structure
 * @return FORS signature (k * (a+1) * n bytes)
 */
inline std::vector<uint8_t> fors_sign(
    const HashFunctions& hash_funcs,
    std::span<const uint8_t> md,
    std::span<const uint8_t> sk_seed,
    std::span<const uint8_t> pk_seed,
    ADRS adrs) {

    const auto& params = hash_funcs.params();
    size_t n = params.n;
    size_t k = params.k;
    size_t a = params.a;

    // Parse message digest into k a-bit values
    auto indices = base_2b(md, a, k);

    std::vector<uint8_t> sig_fors;
    sig_fors.reserve(k * (a + 1) * n);

    for (size_t i = 0; i < k; ++i) {
        uint32_t idx = indices[i];

        // Global leaf index for selected leaf in tree i
        uint32_t global_leaf_idx = static_cast<uint32_t>(i * (1u << a)) + idx;

        // Add secret key element
        auto sk = fors_skGen(hash_funcs, sk_seed, pk_seed, adrs, global_leaf_idx);
        sig_fors.insert(sig_fors.end(), sk.begin(), sk.end());

        // Add authentication path
        for (size_t j = 0; j < a; ++j) {
            // Sibling index at height j (local within subtree)
            uint32_t s = (idx >> j) ^ 1;
            // Global node index at height j
            // At height j, tree i's nodes start at index i * 2^(a-j)
            uint32_t global_node_idx = static_cast<uint32_t>(i * (1u << (a - j))) + s;
            auto auth_node = fors_node(hash_funcs, sk_seed, global_node_idx,
                                       static_cast<uint32_t>(j), pk_seed, adrs);
            sig_fors.insert(sig_fors.end(), auth_node.begin(), auth_node.end());
        }
    }

    return sig_fors;
}

/**
 * Algorithm 16: fors_pkFromSig(SIG_FORS, md, PK.seed, ADRS) - CONSTANT TIME VERSION
 *
 * Compute FORS public key from signature.
 *
 * SECURITY: Uses constant-time conditional concatenation to avoid
 * leaking the tree path through branching.
 *
 * @param hash_funcs Hash function instantiation
 * @param sig_fors FORS signature
 * @param md Message digest
 * @param pk_seed Public seed
 * @param adrs Address structure
 * @return FORS public key (n bytes)
 */
inline std::vector<uint8_t> fors_pkFromSig(
    const HashFunctions& hash_funcs,
    std::span<const uint8_t> sig_fors,
    std::span<const uint8_t> md,
    std::span<const uint8_t> pk_seed,
    ADRS adrs) {

    const auto& params = hash_funcs.params();
    size_t n = params.n;
    size_t k = params.k;
    size_t a = params.a;

    // Parse message digest into k a-bit values
    auto indices = base_2b(md, a, k);

    // Size of one FORS tree signature (sk + auth path)
    size_t fors_tree_sig_len = (a + 1) * n;

    std::vector<uint8_t> roots;
    roots.reserve(k * n);

    for (size_t i = 0; i < k; ++i) {
        uint32_t idx = indices[i];

        // Extract signature for tree i
        size_t offset = i * fors_tree_sig_len;
        std::span<const uint8_t> sk = sig_fors.subspan(offset, n);
        std::span<const uint8_t> auth = sig_fors.subspan(offset + n, a * n);

        // Global leaf index
        uint32_t global_leaf_idx = static_cast<uint32_t>(i * (1u << a)) + idx;

        // Compute leaf from secret key
        adrs.set_tree_height(0);
        adrs.set_tree_index(global_leaf_idx);
        auto node = hash_funcs.F(pk_seed, adrs, sk);

        // Compute root using authentication path - CONSTANT TIME
        for (size_t j = 0; j < a; ++j) {
            adrs.set_tree_height(static_cast<uint32_t>(j + 1));
            std::span<const uint8_t> auth_node = auth.subspan(j * n, n);

            // Compute parent index
            // At height j+1, tree i's nodes start at i * 2^(a-j-1)
            uint32_t parent_local_idx = idx >> (j + 1);
            uint32_t global_parent_idx = static_cast<uint32_t>(i * (1u << (a - j - 1))) + parent_local_idx;
            adrs.set_tree_index(global_parent_idx);

            // Determine if node is left child (bit is 0) or right child (bit is 1)
            // Use constant-time conditional concatenation
            bool is_left_child = ((idx >> j) & 1) == 0;

            // Constant-time: compute both orderings and select
            // If is_left_child: concat = node || auth_node
            // If !is_left_child: concat = auth_node || node
            auto concat = ct::ct_concat_conditional(node, auth_node, is_left_child);

            node = hash_funcs.H(pk_seed, adrs, concat);
        }

        roots.insert(roots.end(), node.begin(), node.end());
    }

    // Compress roots
    ADRS pk_adrs = adrs.copy();
    pk_adrs.set_type(AddressType::FORS_ROOTS);
    pk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    ct::ct_barrier();
    return hash_funcs.T_l(pk_seed, pk_adrs, roots);
}

} // namespace slhdsa

#endif // SLHDSA_FORS_HPP
