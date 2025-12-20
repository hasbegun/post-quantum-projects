/**
 * WOTS+ (Winternitz One-Time Signature Plus) Implementation
 * FIPS 205 Section 5
 *
 * WOTS+ is the base one-time signature scheme used in SLH-DSA.
 *
 * SECURITY: This implementation uses constant-time operations to resist
 * timing-based side-channel attacks. The chain function always executes
 * the maximum number of iterations regardless of the actual chain length.
 */

#ifndef SLHDSA_WOTS_HPP
#define SLHDSA_WOTS_HPP

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
 * Algorithm 4: chain(X, i, s, PK.seed, ADRS) - CONSTANT TIME VERSION
 *
 * Compute the s-step hash chain starting at X from position i.
 *
 * SECURITY: This function executes in constant time by always performing
 * (w-1) hash operations and using conditional selection to pick the
 * correct intermediate value.
 *
 * @param hash_funcs Hash function instantiation
 * @param X Starting value (n bytes)
 * @param i Starting index in chain
 * @param s Number of steps
 * @param pk_seed Public seed
 * @param adrs Address structure (will be modified)
 * @return Chain output (n bytes)
 */
inline std::vector<uint8_t> chain(
    const HashFunctions& hash_funcs,
    std::span<const uint8_t> X,
    uint32_t i,
    uint32_t s,
    std::span<const uint8_t> pk_seed,
    ADRS& adrs) {

    const size_t w = hash_funcs.params().w();

    // Start with input value
    std::vector<uint8_t> tmp(X.begin(), X.end());

    // Result accumulator - will be updated when we reach the target position
    std::vector<uint8_t> result(X.begin(), X.end());

    // Always iterate from 0 to w-1 for constant time
    // We only update result when j is in range [i, i+s)
    for (uint32_t j = 0; j < w; ++j) {

        // Conditionally update result before hashing
        // When j == i+s-1 (last step), result gets the final value
        // We actually want result when j == i+s-1, which is after hashing at j
        // So we update result AFTER hashing, when j >= i and j < i+s

        // Set hash address
        adrs.set_hash_address(j);

        // Compute hash - always executed
        auto hashed = hash_funcs.F(pk_seed, adrs, tmp);

        // Constant-time conditional update:
        // If j >= i, update tmp with hashed value
        // If j < i, keep tmp unchanged (we haven't started yet)
        bool should_hash = (j >= i);
        tmp = ct::ct_select_bytes(hashed, tmp, should_hash);

        // Update result when we're at the final position (j == i + s - 1)
        // This is when j + 1 == i + s, i.e., after s steps from position i
        bool is_final = (s > 0) && (j == i + s - 1);
        result = ct::ct_select_bytes(tmp, result, is_final);
    }

    // Handle s == 0 case: result should be X
    result = ct::ct_select_bytes(
        std::vector<uint8_t>(X.begin(), X.end()),
        result,
        s == 0
    );

    ct::ct_barrier();
    return result;
}

/**
 * Algorithm 5: wots_pkGen(SK.seed, PK.seed, ADRS)
 *
 * Generate a WOTS+ public key.
 *
 * @param hash_funcs Hash function instantiation
 * @param sk_seed Secret seed
 * @param pk_seed Public seed
 * @param adrs Address structure
 * @return WOTS+ public key (n bytes, compressed)
 */
inline std::vector<uint8_t> wots_pkGen(
    const HashFunctions& hash_funcs,
    std::span<const uint8_t> sk_seed,
    std::span<const uint8_t> pk_seed,
    const ADRS& adrs) {

    const auto& params = hash_funcs.params();
    size_t n = params.n;
    size_t len_total = params.len_total();
    size_t w = params.w();

    // Set up address structures
    ADRS sk_adrs = adrs.copy();
    sk_adrs.set_type(AddressType::WOTS_PRF);
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    ADRS chain_adrs = adrs.copy();
    chain_adrs.set_type(AddressType::WOTS_HASH);
    chain_adrs.set_key_pair_address(adrs.get_key_pair_address());

    // Generate chain endpoints
    std::vector<uint8_t> tmp;
    tmp.reserve(len_total * n);

    for (size_t i = 0; i < len_total; ++i) {
        // Generate secret key element
        sk_adrs.set_chain_address(static_cast<uint32_t>(i));
        auto sk_i = hash_funcs.PRF(pk_seed, sk_seed, sk_adrs);

        // Compute chain endpoint (always w-1 steps, constant time)
        chain_adrs.set_chain_address(static_cast<uint32_t>(i));
        auto endpoint = chain(hash_funcs, sk_i, 0, static_cast<uint32_t>(w - 1), pk_seed, chain_adrs);
        tmp.insert(tmp.end(), endpoint.begin(), endpoint.end());
    }

    // Compress public key
    ADRS pk_adrs = adrs.copy();
    pk_adrs.set_type(AddressType::WOTS_PK);
    pk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    return hash_funcs.T_l(pk_seed, pk_adrs, tmp);
}

/**
 * Algorithm 6: wots_sign(M, SK.seed, PK.seed, ADRS) - CONSTANT TIME VERSION
 *
 * Generate a WOTS+ signature for message M.
 *
 * SECURITY: Uses constant-time chain function that always executes
 * the same number of operations regardless of message values.
 *
 * @param hash_funcs Hash function instantiation
 * @param M Message to sign (n bytes)
 * @param sk_seed Secret seed
 * @param pk_seed Public seed
 * @param adrs Address structure
 * @return WOTS+ signature (len_total * n bytes)
 */
inline std::vector<uint8_t> wots_sign(
    const HashFunctions& hash_funcs,
    std::span<const uint8_t> M,
    std::span<const uint8_t> sk_seed,
    std::span<const uint8_t> pk_seed,
    const ADRS& adrs) {

    const auto& params = hash_funcs.params();
    size_t n = params.n;
    size_t len1 = params.len1();
    size_t len2 = params.len2();
    size_t len_total = params.len_total();
    size_t w = params.w();
    size_t lg_w = params.lg_w;

    // Convert message to base-w
    auto msg = base_2b(M, lg_w, len1);

    // Compute checksum (not secret-dependent, msg values are derived from message hash)
    uint32_t csum = 0;
    for (size_t i = 0; i < len1; ++i) {
        csum += static_cast<uint32_t>(w - 1 - msg[i]);
    }

    // Append checksum in base-w
    size_t csum_bits = len2 * lg_w;
    size_t shift = (8 - (csum_bits % 8)) % 8;
    size_t csum_bytes_len = (csum_bits + 7) / 8;
    auto csum_bytes = toByte(static_cast<uint64_t>(csum) << shift, csum_bytes_len);
    auto csum_base_w = base_2b(csum_bytes, lg_w, len2);

    // Combine message and checksum
    msg.insert(msg.end(), csum_base_w.begin(), csum_base_w.end());

    // Set up address structures
    ADRS sk_adrs = adrs.copy();
    sk_adrs.set_type(AddressType::WOTS_PRF);
    sk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    ADRS chain_adrs = adrs.copy();
    chain_adrs.set_type(AddressType::WOTS_HASH);
    chain_adrs.set_key_pair_address(adrs.get_key_pair_address());

    // Generate signature
    std::vector<uint8_t> sig;
    sig.reserve(len_total * n);

    for (size_t i = 0; i < len_total; ++i) {
        sk_adrs.set_chain_address(static_cast<uint32_t>(i));
        auto sk_i = hash_funcs.PRF(pk_seed, sk_seed, sk_adrs);

        // Chain function now runs in constant time
        chain_adrs.set_chain_address(static_cast<uint32_t>(i));
        auto sig_i = chain(hash_funcs, sk_i, 0, msg[i], pk_seed, chain_adrs);
        sig.insert(sig.end(), sig_i.begin(), sig_i.end());
    }

    ct::ct_barrier();
    return sig;
}

/**
 * Algorithm 7: wots_pkFromSig(sig, M, PK.seed, ADRS) - CONSTANT TIME VERSION
 *
 * Compute WOTS+ public key from signature.
 *
 * SECURITY: Uses constant-time chain function.
 *
 * @param hash_funcs Hash function instantiation
 * @param sig WOTS+ signature
 * @param M Message (n bytes)
 * @param pk_seed Public seed
 * @param adrs Address structure
 * @return Recovered public key (n bytes)
 */
inline std::vector<uint8_t> wots_pkFromSig(
    const HashFunctions& hash_funcs,
    std::span<const uint8_t> sig,
    std::span<const uint8_t> M,
    std::span<const uint8_t> pk_seed,
    const ADRS& adrs) {

    const auto& params = hash_funcs.params();
    size_t n = params.n;
    size_t len1 = params.len1();
    size_t len2 = params.len2();
    size_t len_total = params.len_total();
    size_t w = params.w();
    size_t lg_w = params.lg_w;

    // Convert message to base-w
    auto msg = base_2b(M, lg_w, len1);

    // Compute checksum
    uint32_t csum = 0;
    for (size_t i = 0; i < len1; ++i) {
        csum += static_cast<uint32_t>(w - 1 - msg[i]);
    }

    // Append checksum in base-w
    size_t csum_bits = len2 * lg_w;
    size_t shift = (8 - (csum_bits % 8)) % 8;
    size_t csum_bytes_len = (csum_bits + 7) / 8;
    auto csum_bytes = toByte(static_cast<uint64_t>(csum) << shift, csum_bytes_len);
    auto csum_base_w = base_2b(csum_bytes, lg_w, len2);

    // Combine message and checksum
    msg.insert(msg.end(), csum_base_w.begin(), csum_base_w.end());

    // Set up address structure
    ADRS chain_adrs = adrs.copy();
    chain_adrs.set_type(AddressType::WOTS_HASH);
    chain_adrs.set_key_pair_address(adrs.get_key_pair_address());

    // Compute chain endpoints from signature
    std::vector<uint8_t> tmp;
    tmp.reserve(len_total * n);

    for (size_t i = 0; i < len_total; ++i) {
        chain_adrs.set_chain_address(static_cast<uint32_t>(i));
        std::span<const uint8_t> sig_i = sig.subspan(i * n, n);
        auto endpoint = chain(hash_funcs, sig_i, msg[i],
                              static_cast<uint32_t>(w - 1 - msg[i]), pk_seed, chain_adrs);
        tmp.insert(tmp.end(), endpoint.begin(), endpoint.end());
    }

    // Compress to get public key
    ADRS pk_adrs = adrs.copy();
    pk_adrs.set_type(AddressType::WOTS_PK);
    pk_adrs.set_key_pair_address(adrs.get_key_pair_address());

    ct::ct_barrier();
    return hash_funcs.T_l(pk_seed, pk_adrs, tmp);
}

} // namespace slhdsa

#endif // SLHDSA_WOTS_HPP
