/**
 * K-PKE: Internal Public-Key Encryption for ML-KEM
 * Based on FIPS 203 Algorithms 13-15
 *
 * K-PKE is the internal IND-CPA secure PKE scheme used by ML-KEM.
 * It is NOT approved for standalone use - only as part of ML-KEM.
 */

#ifndef MLKEM_KPKE_HPP
#define MLKEM_KPKE_HPP

#include "params.hpp"
#include "ntt.hpp"
#include "encode.hpp"
#include "sampling.hpp"
#include "compress.hpp"
#include "utils.hpp"
#include <vector>
#include <span>
#include <tuple>
#include <cstdint>

namespace mlkem {

/**
 * Algorithm 13: K-PKE.KeyGen
 * Generate encryption key pair
 *
 * Input: d - 32-byte seed
 * Output: (ek_PKE, dk_PKE) - encryption key and decryption key
 */
[[nodiscard]] inline std::pair<std::vector<uint8_t>, std::vector<uint8_t>>
kpke_keygen(std::span<const uint8_t> d, const Params& params) {
    int k = params.k;
    int eta1 = params.eta1;

    // Step 1: Expand seed to (rho, sigma)
    auto [rho, sigma] = G(d);

    // Step 2: Generate matrix A in NTT domain
    auto A_hat = expand_a(rho, k);

    // Step 3: Sample secret vector s
    auto s = sample_secret(sigma, k, eta1, 0);

    // Step 4: Sample error vector e
    auto e = sample_error(sigma, k, eta1, static_cast<uint8_t>(k));

    // Step 5: Convert s to NTT domain
    auto s_hat = vec_ntt(s);

    // Step 6: Compute t = A*s + e
    auto As_hat = mat_vec_mul_ntt(A_hat, s_hat);
    auto As = vec_ntt_inv(As_hat);
    auto t = vec_add(As, e);

    // Step 7: Reduce t coefficients
    t = vec_reduce(t);

    // Step 8: Encode encryption key: ek_PKE = ByteEncode_12(t) || rho
    auto t_bytes = encode_vec(t, 12);
    std::vector<uint8_t> ek_pke;
    ek_pke.reserve(t_bytes.size() + rho.size());
    ek_pke.insert(ek_pke.end(), t_bytes.begin(), t_bytes.end());
    ek_pke.insert(ek_pke.end(), rho.begin(), rho.end());

    // Step 9: Encode decryption key: dk_PKE = ByteEncode_12(s)
    auto dk_pke = encode_vec(s, 12);

    return {std::move(ek_pke), std::move(dk_pke)};
}

/**
 * Algorithm 14: K-PKE.Encrypt
 * Encrypt a message
 *
 * Input: ek_PKE - encryption key
 *        m - 32-byte message (actually the pre-key)
 *        r - 32-byte randomness
 * Output: c - ciphertext
 */
[[nodiscard]] inline std::vector<uint8_t> kpke_encrypt(
    std::span<const uint8_t> ek_pke,
    std::span<const uint8_t> m,
    std::span<const uint8_t> r,
    const Params& params) {

    int k = params.k;
    int eta1 = params.eta1;
    int eta2 = params.eta2;
    int du = params.du;
    int dv = params.dv;

    // Step 1: Decode t from encryption key
    size_t t_bytes_len = 384 * k;
    auto t = decode_vec(ek_pke.subspan(0, t_bytes_len), k, 12);

    // Step 2: Extract rho from encryption key
    std::vector<uint8_t> rho(ek_pke.begin() + t_bytes_len, ek_pke.end());

    // Step 3: Generate matrix A^T in NTT domain
    // Note: We need A^T, which is expand_a with swapped indices
    PolyMat A_hat_T;
    A_hat_T.reserve(k);
    for (int i = 0; i < k; ++i) {
        PolyVec row;
        row.reserve(k);
        for (int j = 0; j < k; ++j) {
            // Swap i and j to get transpose
            auto stream = xof(rho, static_cast<uint8_t>(i), static_cast<uint8_t>(j));
            row.push_back(sample_ntt(stream));
        }
        A_hat_T.push_back(std::move(row));
    }

    // Step 4: Sample vectors r, e1, e2
    auto r_vec = sample_secret(r, k, eta1, 0);
    auto e1 = sample_error(r, k, eta2, static_cast<uint8_t>(k));

    // Sample e2 (single polynomial)
    auto e2_bytes = prf(r, static_cast<uint8_t>(2 * k), 64 * eta2);
    auto e2 = sample_poly_cbd(e2_bytes, eta2);

    // Step 5: Convert r to NTT domain
    auto r_hat = vec_ntt(r_vec);

    // Step 6: Compute u = A^T * r + e1
    auto ATr_hat = mat_vec_mul_ntt(A_hat_T, r_hat);
    auto ATr = vec_ntt_inv(ATr_hat);
    auto u = vec_add(ATr, e1);

    // Step 7: Compute t^T * r in NTT domain
    auto t_hat = vec_ntt(t);
    auto mu_hat = inner_product_ntt(t_hat, r_hat);
    auto mu = ntt_inv(mu_hat);

    // Step 8: Decode message to polynomial
    auto m_poly = byte_decode(m, 1);

    // Step 9: Decompress message and add to mu
    auto m_decomp = poly_decompress(m_poly, 1);
    auto v = poly_add(mu, m_decomp);
    v = poly_add(v, e2);

    // Step 10: Reduce coefficients
    u = vec_reduce(u);
    v = poly_reduce(v);

    // Step 11: Compress and encode ciphertext
    auto u_comp = vec_compress(u, du);
    auto v_comp = poly_compress(v, dv);

    auto c1 = encode_vec(u_comp, du);
    auto c2 = byte_encode(v_comp, dv);

    // Concatenate c1 and c2
    std::vector<uint8_t> c;
    c.reserve(c1.size() + c2.size());
    c.insert(c.end(), c1.begin(), c1.end());
    c.insert(c.end(), c2.begin(), c2.end());

    return c;
}

/**
 * Algorithm 15: K-PKE.Decrypt
 * Decrypt a ciphertext
 *
 * Input: dk_PKE - decryption key
 *        c - ciphertext
 * Output: m - 32-byte message
 */
[[nodiscard]] inline std::vector<uint8_t> kpke_decrypt(
    std::span<const uint8_t> dk_pke,
    std::span<const uint8_t> c,
    const Params& params) {

    int k = params.k;
    int du = params.du;
    int dv = params.dv;

    // Step 1: Split ciphertext into c1 and c2
    size_t c1_len = 32 * du * k;
    size_t c2_len = 32 * dv;

    // Step 2: Decode and decompress u
    auto u_comp = decode_vec(c.subspan(0, c1_len), k, du);
    auto u = vec_decompress(u_comp, du);

    // Step 3: Decode and decompress v
    auto v_comp = byte_decode(c.subspan(c1_len, c2_len), dv);
    auto v = poly_decompress(v_comp, dv);

    // Step 4: Decode secret key
    auto s = decode_vec(dk_pke, k, 12);

    // Step 5: Compute s^T * u in NTT domain
    auto s_hat = vec_ntt(s);
    auto u_hat = vec_ntt(u);
    auto su_hat = inner_product_ntt(s_hat, u_hat);
    auto su = ntt_inv(su_hat);

    // Step 6: Compute w = v - s^T * u
    auto w = poly_sub(v, su);

    // Step 7: Reduce and compress to get message
    w = poly_reduce(w);
    auto m_poly = poly_compress(w, 1);

    // Step 8: Encode message to bytes
    return byte_encode(m_poly, 1);
}

} // namespace mlkem

#endif // MLKEM_KPKE_HPP
