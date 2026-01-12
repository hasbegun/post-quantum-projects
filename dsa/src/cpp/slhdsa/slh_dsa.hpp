/**
 * SLH-DSA Core Functions
 * FIPS 205 Sections 9 and 10
 *
 * Main key generation, signing, and verification functions.
 */

#ifndef SLHDSA_SLH_DSA_HPP
#define SLHDSA_SLH_DSA_HPP

#include "params.hpp"
#include "address.hpp"
#include "hash_functions.hpp"
#include "fors.hpp"
#include "hypertree.hpp"
#include "xmss.hpp"
#include "utils.hpp"
#include "ct_utils.hpp"
#include <vector>
#include <span>
#include <tuple>
#include <optional>
#include <cstdint>
#include <stdexcept>

namespace slhdsa {

// Domain separators for pure and pre-hash modes (FIPS 205 Section 10)
constexpr uint8_t PURE_MODE_PREFIX = 0x00;
constexpr uint8_t PREHASH_MODE_PREFIX = 0x01;

/**
 * Algorithm 17: slh_keygen_internal(SK.seed, SK.prf, PK.seed)
 *
 * Internal key generation.
 *
 * @param params Parameter set
 * @param sk_seed Secret seed (n bytes)
 * @param sk_prf PRF key for randomizing (n bytes)
 * @param pk_seed Public seed (n bytes)
 * @return Tuple of (secret_key, public_key)
 */
inline std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> slh_keygen_internal(
    const Params& params,
    std::span<const uint8_t> sk_seed,
    std::span<const uint8_t> sk_prf,
    std::span<const uint8_t> pk_seed) {

    auto hash_funcs = get_hash_functions(params);
    size_t n = params.n;
    size_t hp = params.hp;

    // Compute root of top-level XMSS tree
    ADRS adrs;
    adrs.set_layer_address(static_cast<uint32_t>(params.d - 1));
    adrs.set_tree_address(0);

    auto pk_root = xmss_node(*hash_funcs, sk_seed, 0, static_cast<uint32_t>(hp), pk_seed, adrs);

    // Form keys
    std::vector<uint8_t> sk;
    sk.reserve(4 * n);
    sk.insert(sk.end(), sk_seed.begin(), sk_seed.end());
    sk.insert(sk.end(), sk_prf.begin(), sk_prf.end());
    sk.insert(sk.end(), pk_seed.begin(), pk_seed.end());
    sk.insert(sk.end(), pk_root.begin(), pk_root.end());

    std::vector<uint8_t> pk;
    pk.reserve(2 * n);
    pk.insert(pk.end(), pk_seed.begin(), pk_seed.end());
    pk.insert(pk.end(), pk_root.begin(), pk_root.end());

    return {sk, pk};
}

/**
 * Algorithm 18: slh_sign_internal(M, SK, opt_rand)
 *
 * Internal signing function.
 *
 * SECURITY: This function securely zeros sensitive intermediate data
 * before returning to prevent information leakage from memory.
 *
 * @param params Parameter set
 * @param M Message to sign
 * @param sk Secret key
 * @param randomize Whether to use randomized signing
 * @param opt_rand Optional randomness (for deterministic mode, use pk_seed)
 * @return SLH-DSA signature
 */
inline std::vector<uint8_t> slh_sign_internal(
    const Params& params,
    std::span<const uint8_t> M,
    std::span<const uint8_t> sk,
    bool randomize = true,
    std::optional<std::span<const uint8_t>> opt_rand = std::nullopt) {

    auto hash_funcs = get_hash_functions(params);
    size_t n = params.n;
    size_t h = params.h;
    size_t hp = params.hp;
    size_t k = params.k;
    size_t a = params.a;

    // Parse secret key
    std::span<const uint8_t> sk_seed = sk.subspan(0, n);
    std::span<const uint8_t> sk_prf = sk.subspan(n, n);
    std::span<const uint8_t> pk_seed = sk.subspan(2 * n, n);
    std::span<const uint8_t> pk_root = sk.subspan(3 * n, n);

    // Generate randomizer
    std::vector<uint8_t> rand_bytes;
    std::span<const uint8_t> rand_span;

    if (opt_rand.has_value()) {
        rand_span = opt_rand.value();
    } else if (randomize) {
        rand_bytes = random_bytes(n);
        rand_span = rand_bytes;
    } else {
        rand_span = pk_seed;
    }

    // RAII guard to zero sensitive data on exit
    struct CleanupGuard {
        std::vector<uint8_t>& rand_ref;
        std::vector<uint8_t>& digest_ref;

        ~CleanupGuard() {
            ct::ct_zero(rand_ref);
            ct::ct_zero(digest_ref);
        }
    };

    auto R = hash_funcs->PRF_msg(sk_prf, rand_span, M);

    // Compute message digest
    std::vector<uint8_t> digest = hash_funcs->H_msg(R, pk_seed, pk_root, M);

    // Install cleanup guard
    CleanupGuard guard{rand_bytes, digest};

    // Split digest into indices
    // First part: FORS message (ceil(k*a/8) bytes)
    size_t md_len = (k * a + 7) / 8;
    std::span<const uint8_t> md = std::span(digest).subspan(0, md_len);

    // Second part: tree index (ceil((h - h'/d)/8) bytes)
    size_t tree_bits = h - hp;
    size_t tree_len = (tree_bits + 7) / 8;
    uint64_t idx_tree = toInt(std::span(digest).subspan(md_len, tree_len));
    idx_tree = idx_tree & ((1ULL << tree_bits) - 1);

    // Third part: leaf index (ceil(h'/8) bytes)
    size_t leaf_len = (hp + 7) / 8;
    uint32_t idx_leaf = static_cast<uint32_t>(toInt(std::span(digest).subspan(md_len + tree_len, leaf_len)));
    idx_leaf = idx_leaf & ((1u << hp) - 1);

    // Generate FORS signature
    ADRS adrs;
    adrs.set_layer_address(0);
    adrs.set_tree_address(idx_tree);
    adrs.set_type(AddressType::FORS_TREE);
    adrs.set_key_pair_address(idx_leaf);

    auto sig_fors = fors_sign(*hash_funcs, md, sk_seed, pk_seed, adrs);

    // Get FORS public key for HT signing
    auto pk_fors = fors_pkFromSig(*hash_funcs, sig_fors, md, pk_seed, adrs);

    // Generate hypertree signature
    auto sig_ht = ht_sign(*hash_funcs, pk_fors, sk_seed, pk_seed, idx_tree, idx_leaf);

    // Assemble signature
    std::vector<uint8_t> sig;
    sig.reserve(R.size() + sig_fors.size() + sig_ht.size());
    sig.insert(sig.end(), R.begin(), R.end());
    sig.insert(sig.end(), sig_fors.begin(), sig_fors.end());
    sig.insert(sig.end(), sig_ht.begin(), sig_ht.end());

    return sig;
    // CleanupGuard destructor runs here, zeroing rand_bytes and digest
}

/**
 * Algorithm 19: slh_verify_internal(M, SIG, PK)
 *
 * Internal verification function.
 *
 * SECURITY: This implementation uses constant-time validity tracking
 * to prevent timing-based side-channel attacks. All checks are performed
 * regardless of intermediate results.
 *
 * @param params Parameter set
 * @param M Message
 * @param sig Signature
 * @param pk Public key
 * @return True if valid, False otherwise
 */
inline bool slh_verify_internal(
    const Params& params,
    std::span<const uint8_t> M,
    std::span<const uint8_t> sig,
    std::span<const uint8_t> pk) {

    auto hash_funcs = get_hash_functions(params);
    size_t n = params.n;
    size_t h = params.h;
    size_t hp = params.hp;
    size_t k = params.k;
    size_t a = params.a;

    // Track validity in constant time - all checks continue regardless of failures
    volatile uint32_t valid = 1;

    // Check signature length (constant-time)
    uint32_t sig_len_ok = (sig.size() == params.sig_size()) ? 1 : 0;
    valid &= sig_len_ok;
    ct::ct_barrier();

    // Check public key length (constant-time)
    uint32_t pk_len_ok = (pk.size() == params.pk_size()) ? 1 : 0;
    valid &= pk_len_ok;
    ct::ct_barrier();

    // Create dummy buffers for when inputs are invalid
    // This ensures we always do the same amount of work
    std::vector<uint8_t> dummy_pk(2 * n, 0);
    std::vector<uint8_t> dummy_sig(params.sig_size(), 0);

    // Use actual inputs if valid, dummy otherwise (constant-time)
    // We can't use ct_select here easily, so we do the work with whatever we have
    // but clamp sizes to prevent out-of-bounds access

    // Safe subspan extraction - use dummy if sizes are wrong
    std::span<const uint8_t> safe_pk = (pk_len_ok == 1) ? pk : std::span<const uint8_t>(dummy_pk);
    std::span<const uint8_t> safe_sig = (sig_len_ok == 1) ? sig : std::span<const uint8_t>(dummy_sig);

    // Parse public key
    std::span<const uint8_t> pk_seed = safe_pk.subspan(0, n);
    std::span<const uint8_t> pk_root = safe_pk.subspan(n, n);

    // Parse signature
    std::span<const uint8_t> R = safe_sig.subspan(0, n);
    size_t sig_fors_len = k * (a + 1) * n;
    std::span<const uint8_t> sig_fors = safe_sig.subspan(n, sig_fors_len);
    std::span<const uint8_t> sig_ht = safe_sig.subspan(n + sig_fors_len);

    // Compute message digest
    auto digest = hash_funcs->H_msg(R, pk_seed, pk_root, M);

    // Split digest into indices
    size_t md_len = (k * a + 7) / 8;
    std::span<const uint8_t> md = std::span(digest).subspan(0, md_len);

    size_t tree_bits = h - hp;
    size_t tree_len = (tree_bits + 7) / 8;
    uint64_t idx_tree = toInt(std::span(digest).subspan(md_len, tree_len));
    idx_tree = idx_tree & ((1ULL << tree_bits) - 1);

    size_t leaf_len = (hp + 7) / 8;
    uint32_t idx_leaf = static_cast<uint32_t>(toInt(std::span(digest).subspan(md_len + tree_len, leaf_len)));
    idx_leaf = idx_leaf & ((1u << hp) - 1);

    // Recover FORS public key from signature
    ADRS adrs;
    adrs.set_layer_address(0);
    adrs.set_tree_address(idx_tree);
    adrs.set_type(AddressType::FORS_TREE);
    adrs.set_key_pair_address(idx_leaf);

    auto pk_fors = fors_pkFromSig(*hash_funcs, sig_fors, md, pk_seed, adrs);

    // Verify hypertree signature (this already uses constant-time comparison internally)
    bool ht_valid = ht_verify(*hash_funcs, pk_fors, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root);

    // Combine all validity checks
    ct::ct_barrier();
    return (valid == 1) && ht_valid;
}


// External API functions (FIPS 205 Section 10)

/**
 * Algorithm 20: slh_keygen()
 *
 * Generate an SLH-DSA key pair.
 *
 * @param params Parameter set to use
 * @return Tuple of (secret_key, public_key)
 */
inline std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> slh_keygen(const Params& params) {
    size_t n = params.n;

    // Generate random seeds
    auto sk_seed = random_bytes(n);
    auto sk_prf = random_bytes(n);
    auto pk_seed = random_bytes(n);

    return slh_keygen_internal(params, sk_seed, sk_prf, pk_seed);
}

/**
 * Algorithm 21: slh_sign(M, SK, ctx)
 *
 * Sign a message in pure mode.
 *
 * @param params Parameter set
 * @param M Message to sign
 * @param sk Secret key
 * @param ctx Context string (0-255 bytes)
 * @param randomize Whether to use randomized signing
 * @return SLH-DSA signature
 * @throws std::invalid_argument If context string is too long
 */
inline std::vector<uint8_t> slh_sign(
    const Params& params,
    std::span<const uint8_t> M,
    std::span<const uint8_t> sk,
    std::span<const uint8_t> ctx = {},
    bool randomize = true) {

    if (ctx.size() > 255) {
        throw std::invalid_argument("Context string must be at most 255 bytes");
    }

    // Form prefixed message
    std::vector<uint8_t> M_prime;
    M_prime.reserve(2 + ctx.size() + M.size());
    M_prime.push_back(PURE_MODE_PREFIX);
    M_prime.push_back(static_cast<uint8_t>(ctx.size()));
    M_prime.insert(M_prime.end(), ctx.begin(), ctx.end());
    M_prime.insert(M_prime.end(), M.begin(), M.end());

    return slh_sign_internal(params, M_prime, sk, randomize);
}

/**
 * Algorithm 23: slh_verify(M, SIG, PK, ctx)
 *
 * Verify a signature in pure mode.
 *
 * SECURITY: Uses constant-time validity tracking to prevent timing leaks.
 *
 * @param params Parameter set
 * @param M Message
 * @param sig Signature
 * @param pk Public key
 * @param ctx Context string (0-255 bytes)
 * @return True if valid, False otherwise
 */
inline bool slh_verify(
    const Params& params,
    std::span<const uint8_t> M,
    std::span<const uint8_t> sig,
    std::span<const uint8_t> pk,
    std::span<const uint8_t> ctx = {}) {

    // Check context size (constant-time validity tracking)
    volatile uint32_t ctx_valid = (ctx.size() <= 255) ? 1 : 0;
    ct::ct_barrier();

    // Use clamped context size to prevent issues, but track validity
    size_t safe_ctx_size = (ctx.size() <= 255) ? ctx.size() : 0;

    // Form prefixed message
    std::vector<uint8_t> M_prime;
    M_prime.reserve(2 + safe_ctx_size + M.size());
    M_prime.push_back(PURE_MODE_PREFIX);
    M_prime.push_back(static_cast<uint8_t>(safe_ctx_size));
    if (ctx_valid == 1) {
        M_prime.insert(M_prime.end(), ctx.begin(), ctx.end());
    }
    M_prime.insert(M_prime.end(), M.begin(), M.end());

    // Always call internal verify (does constant-time work)
    bool internal_valid = slh_verify_internal(params, M_prime, sig, pk);

    ct::ct_barrier();
    return (ctx_valid == 1) && internal_valid;
}


/**
 * Convenience class for SLH-DSA operations with a specific parameter set.
 */
template<const Params& P>
class SLHDSA {
public:
    SLHDSA() = default;

    [[nodiscard]] const Params& params() const noexcept { return P; }

    /**
     * Generate a key pair.
     */
    [[nodiscard]] std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> keygen() const {
        return slh_keygen(P);
    }

    /**
     * Generate a key pair from seeds (for KAT testing).
     * @param sk_seed Secret seed (n bytes)
     * @param sk_prf PRF key (n bytes)
     * @param pk_seed Public seed (n bytes)
     * @return Tuple of (secret_key, public_key)
     */
    [[nodiscard]] std::tuple<std::vector<uint8_t>, std::vector<uint8_t>> keygen(
        std::span<const uint8_t> sk_seed,
        std::span<const uint8_t> sk_prf,
        std::span<const uint8_t> pk_seed) const {
        if (sk_seed.size() != P.n || sk_prf.size() != P.n || pk_seed.size() != P.n) {
            throw std::invalid_argument("All seeds must be n bytes");
        }
        return slh_keygen_internal(P, sk_seed, sk_prf, pk_seed);
    }

    /**
     * Sign a message.
     */
    [[nodiscard]] std::vector<uint8_t> sign(
        std::span<const uint8_t> sk,
        std::span<const uint8_t> message,
        std::span<const uint8_t> ctx = {},
        bool randomize = true) const {
        return slh_sign(P, message, sk, ctx, randomize);
    }

    /**
     * Verify a signature.
     */
    [[nodiscard]] bool verify(
        std::span<const uint8_t> pk,
        std::span<const uint8_t> message,
        std::span<const uint8_t> signature,
        std::span<const uint8_t> ctx = {}) const {
        return slh_verify(P, message, signature, pk, ctx);
    }
};

// Pre-defined convenience types for each parameter set
using SLHDSA_SHA2_128s = SLHDSA<SLH_DSA_SHA2_128s>;
using SLHDSA_SHA2_128f = SLHDSA<SLH_DSA_SHA2_128f>;
using SLHDSA_SHA2_192s = SLHDSA<SLH_DSA_SHA2_192s>;
using SLHDSA_SHA2_192f = SLHDSA<SLH_DSA_SHA2_192f>;
using SLHDSA_SHA2_256s = SLHDSA<SLH_DSA_SHA2_256s>;
using SLHDSA_SHA2_256f = SLHDSA<SLH_DSA_SHA2_256f>;

using SLHDSA_SHAKE_128s = SLHDSA<SLH_DSA_SHAKE_128s>;
using SLHDSA_SHAKE_128f = SLHDSA<SLH_DSA_SHAKE_128f>;
using SLHDSA_SHAKE_192s = SLHDSA<SLH_DSA_SHAKE_192s>;
using SLHDSA_SHAKE_192f = SLHDSA<SLH_DSA_SHAKE_192f>;
using SLHDSA_SHAKE_256s = SLHDSA<SLH_DSA_SHAKE_256s>;
using SLHDSA_SHAKE_256f = SLHDSA<SLH_DSA_SHAKE_256f>;

} // namespace slhdsa

#endif // SLHDSA_SLH_DSA_HPP
