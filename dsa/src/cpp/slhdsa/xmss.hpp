/**
 * XMSS (eXtended Merkle Signature Scheme) Implementation
 * FIPS 205 Section 6
 *
 * XMSS extends WOTS+ to allow multiple signatures using a Merkle tree.
 *
 * SECURITY: This implementation uses constant-time operations for tree
 * traversal to resist timing-based side-channel attacks.
 */

#ifndef SLHDSA_XMSS_HPP
#define SLHDSA_XMSS_HPP

#include "params.hpp"
#include "address.hpp"
#include "hash_functions.hpp"
#include "wots.hpp"
#include "ct_utils.hpp"
#include <vector>
#include <span>
#include <cstdint>

namespace slhdsa {

/**
 * Algorithm 8: xmss_node(SK.seed, i, z, PK.seed, ADRS)
 *
 * Compute the root of a subtree of the XMSS tree.
 *
 * @param hash_funcs Hash function instantiation
 * @param sk_seed Secret seed
 * @param i Leaf index (0 to 2^(h'-z) - 1)
 * @param z Target node height (0 to h')
 * @param pk_seed Public seed
 * @param adrs Address structure
 * @return Node value (n bytes)
 */
inline std::vector<uint8_t> xmss_node(
    const HashFunctions& hash_funcs,
    std::span<const uint8_t> sk_seed,
    uint32_t i,
    uint32_t z,
    std::span<const uint8_t> pk_seed,
    ADRS adrs) {

    const auto& params = hash_funcs.params();
    size_t hp = params.hp;

    if (z > hp || i >= (1u << (hp - z))) {
        return {};  // Invalid parameters
    }

    if (z == 0) {
        // Leaf node: compute WOTS+ public key
        adrs.set_type(AddressType::WOTS_HASH);
        adrs.set_key_pair_address(i);
        return wots_pkGen(hash_funcs, sk_seed, pk_seed, adrs);
    } else {
        // Internal node: hash children
        auto left = xmss_node(hash_funcs, sk_seed, 2 * i, z - 1, pk_seed, adrs);
        auto right = xmss_node(hash_funcs, sk_seed, 2 * i + 1, z - 1, pk_seed, adrs);

        adrs.set_type(AddressType::TREE);
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
 * Algorithm 9: xmss_sign(M, SK.seed, idx, PK.seed, ADRS)
 *
 * Generate an XMSS signature.
 *
 * @param hash_funcs Hash function instantiation
 * @param M Message to sign (n bytes)
 * @param sk_seed Secret seed
 * @param idx Leaf index to use
 * @param pk_seed Public seed
 * @param adrs Address structure
 * @return XMSS signature (WOTS+ signature + authentication path)
 */
inline std::vector<uint8_t> xmss_sign(
    const HashFunctions& hash_funcs,
    std::span<const uint8_t> M,
    std::span<const uint8_t> sk_seed,
    uint32_t idx,
    std::span<const uint8_t> pk_seed,
    ADRS adrs) {

    const auto& params = hash_funcs.params();
    size_t hp = params.hp;

    // Generate WOTS+ signature
    adrs.set_type(AddressType::WOTS_HASH);
    adrs.set_key_pair_address(idx);
    auto sig = wots_sign(hash_funcs, M, sk_seed, pk_seed, adrs);

    // Compute authentication path
    for (size_t j = 0; j < hp; ++j) {
        // Sibling index at height j
        uint32_t sibling_idx = (idx >> j) ^ 1;
        auto auth_node = xmss_node(hash_funcs, sk_seed, sibling_idx,
                                   static_cast<uint32_t>(j), pk_seed, adrs);
        sig.insert(sig.end(), auth_node.begin(), auth_node.end());
    }

    return sig;
}

/**
 * Algorithm 10: xmss_pkFromSig(idx, SIG_XMSS, M, PK.seed, ADRS) - CONSTANT TIME VERSION
 *
 * Compute XMSS public key (root) from signature.
 *
 * SECURITY: Uses constant-time conditional concatenation to avoid
 * leaking the tree path through branching.
 *
 * @param hash_funcs Hash function instantiation
 * @param idx Leaf index used in signature
 * @param sig_xmss XMSS signature
 * @param M Message (n bytes)
 * @param pk_seed Public seed
 * @param adrs Address structure
 * @return Computed root (n bytes)
 */
inline std::vector<uint8_t> xmss_pkFromSig(
    const HashFunctions& hash_funcs,
    uint32_t idx,
    std::span<const uint8_t> sig_xmss,
    std::span<const uint8_t> M,
    std::span<const uint8_t> pk_seed,
    ADRS adrs) {

    const auto& params = hash_funcs.params();
    size_t n = params.n;
    size_t hp = params.hp;
    size_t len_total = params.len_total();

    // Extract WOTS+ signature and auth path
    size_t wots_sig_len = len_total * n;
    std::span<const uint8_t> sig_wots = sig_xmss.subspan(0, wots_sig_len);
    std::span<const uint8_t> auth = sig_xmss.subspan(wots_sig_len);

    // Compute WOTS+ public key from signature
    adrs.set_type(AddressType::WOTS_HASH);
    adrs.set_key_pair_address(idx);
    auto node = wots_pkFromSig(hash_funcs, sig_wots, M, pk_seed, adrs);

    // Compute root using authentication path - CONSTANT TIME
    adrs.set_type(AddressType::TREE);
    for (size_t j = 0; j < hp; ++j) {
        adrs.set_tree_height(static_cast<uint32_t>(j + 1));
        adrs.set_tree_index(idx >> (j + 1));

        std::span<const uint8_t> auth_node = auth.subspan(j * n, n);

        // Determine if node is left child (bit is 0) or right child (bit is 1)
        // Use constant-time conditional concatenation
        bool is_left_child = ((idx >> j) & 1) == 0;

        // Constant-time: compute both orderings and select
        // If is_left_child: concat = node || auth_node
        // If !is_left_child: concat = auth_node || node
        auto concat = ct::ct_concat_conditional(node, auth_node, is_left_child);

        node = hash_funcs.H(pk_seed, adrs, concat);
    }

    ct::ct_barrier();
    return node;
}

} // namespace slhdsa

#endif // SLHDSA_XMSS_HPP
