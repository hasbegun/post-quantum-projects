/**
 * Hypertree Implementation
 * FIPS 205 Section 7
 *
 * The hypertree is a tree of XMSS trees that enables signing capacity
 * beyond what a single XMSS tree can provide.
 */

#ifndef SLHDSA_HYPERTREE_HPP
#define SLHDSA_HYPERTREE_HPP

#include "params.hpp"
#include "address.hpp"
#include "hash_functions.hpp"
#include "xmss.hpp"
#include "ct_utils.hpp"
#include <vector>
#include <span>
#include <cstdint>
#include <stdexcept>

namespace slhdsa {

namespace {

/**
 * Safely compute a bit mask for tree/leaf index extraction.
 * Validates that the height parameter is within safe bounds.
 *
 * @param hp Height parameter (tree height)
 * @return Bit mask (2^hp - 1)
 * @throws std::overflow_error if hp >= 32
 */
inline uint32_t safe_index_mask(size_t hp) {
    if (hp >= 32) {
        throw std::overflow_error("Hypertree height parameter too large (>= 32)");
    }
    return (1u << hp) - 1;
}

} // anonymous namespace

/**
 * Algorithm 11: ht_sign(M, SK.seed, PK.seed, idx_tree, idx_leaf)
 *
 * Generate a hypertree signature.
 *
 * @param hash_funcs Hash function instantiation
 * @param M Message to sign (n bytes)
 * @param sk_seed Secret seed
 * @param pk_seed Public seed
 * @param idx_tree Tree index (identifies the XMSS tree in the forest)
 * @param idx_leaf Leaf index within the tree
 * @return Hypertree signature (d XMSS signatures)
 */
inline std::vector<uint8_t> ht_sign(
    const HashFunctions& hash_funcs,
    std::span<const uint8_t> M,
    std::span<const uint8_t> sk_seed,
    std::span<const uint8_t> pk_seed,
    uint64_t idx_tree,
    uint32_t idx_leaf) {

    const auto& params = hash_funcs.params();
    size_t d = params.d;
    size_t hp = params.hp;

    // Initialize address for layer 0
    ADRS adrs;
    adrs.set_layer_address(0);
    adrs.set_tree_address(idx_tree);

    // Sign with bottom XMSS tree
    auto sig_ht = xmss_sign(hash_funcs, M, sk_seed, idx_leaf, pk_seed, adrs);

    // Get root of bottom tree for next layer
    auto root = xmss_node(hash_funcs, sk_seed, 0, static_cast<uint32_t>(hp), pk_seed, adrs);

    // Pre-compute the index mask for safe operations
    uint32_t index_mask = safe_index_mask(hp);

    // Sign with remaining layers
    for (size_t j = 1; j < d; ++j) {
        // Update indices for next layer
        idx_leaf = static_cast<uint32_t>(idx_tree & index_mask);
        idx_tree = idx_tree >> hp;

        // Update address for layer j
        adrs.set_layer_address(static_cast<uint32_t>(j));
        adrs.set_tree_address(idx_tree);

        // Sign root with XMSS at layer j
        auto sig_tmp = xmss_sign(hash_funcs, root, sk_seed, idx_leaf, pk_seed, adrs);
        sig_ht.insert(sig_ht.end(), sig_tmp.begin(), sig_tmp.end());

        // Compute root for next layer (if not last)
        if (j < d - 1) {
            root = xmss_node(hash_funcs, sk_seed, 0, static_cast<uint32_t>(hp), pk_seed, adrs);
        }
    }

    return sig_ht;
}

/**
 * Algorithm 12: ht_verify(M, SIG_HT, PK.seed, idx_tree, idx_leaf, PK.root)
 *
 * Verify a hypertree signature.
 *
 * @param hash_funcs Hash function instantiation
 * @param M Message (n bytes)
 * @param sig_ht Hypertree signature
 * @param pk_seed Public seed
 * @param idx_tree Tree index
 * @param idx_leaf Leaf index
 * @param pk_root Expected root (public key)
 * @return True if signature is valid, False otherwise
 */
inline bool ht_verify(
    const HashFunctions& hash_funcs,
    std::span<const uint8_t> M,
    std::span<const uint8_t> sig_ht,
    std::span<const uint8_t> pk_seed,
    uint64_t idx_tree,
    uint32_t idx_leaf,
    std::span<const uint8_t> pk_root) {

    const auto& params = hash_funcs.params();
    size_t n = params.n;
    size_t d = params.d;
    size_t hp = params.hp;
    size_t len_total = params.len_total();

    // Size of one XMSS signature
    size_t xmss_sig_len = (len_total + hp) * n;

    // Initialize address for layer 0
    ADRS adrs;
    adrs.set_layer_address(0);
    adrs.set_tree_address(idx_tree);

    // Extract first XMSS signature
    std::span<const uint8_t> sig_xmss = sig_ht.subspan(0, xmss_sig_len);
    size_t offset = xmss_sig_len;

    // Compute root from bottom layer
    auto node = xmss_pkFromSig(hash_funcs, idx_leaf, sig_xmss, M, pk_seed, adrs);

    // Pre-compute the index mask for safe operations
    uint32_t index_mask = safe_index_mask(hp);

    // Verify remaining layers
    for (size_t j = 1; j < d; ++j) {
        // Update indices for next layer
        idx_leaf = static_cast<uint32_t>(idx_tree & index_mask);
        idx_tree = idx_tree >> hp;

        // Update address for layer j
        adrs.set_layer_address(static_cast<uint32_t>(j));
        adrs.set_tree_address(idx_tree);

        // Extract XMSS signature for layer j
        sig_xmss = sig_ht.subspan(offset, xmss_sig_len);
        offset += xmss_sig_len;

        // Compute root using signature
        node = xmss_pkFromSig(hash_funcs, idx_leaf, sig_xmss, node, pk_seed, adrs);
    }

    // Verify computed root matches public key - CONSTANT TIME
    ct::ct_barrier();
    return ct::ct_equal(node, pk_root);
}

} // namespace slhdsa

#endif // SLHDSA_HYPERTREE_HPP
