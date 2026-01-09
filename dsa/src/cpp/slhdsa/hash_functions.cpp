/**
 * SLH-DSA Hash Function Implementations
 *
 * Uses OpenSSL for SHAKE256, SHA-256, SHA-512, and HMAC.
 */

#include "hash_functions.hpp"
#include "utils.hpp"
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdexcept>
#include <cstring>

namespace slhdsa {

namespace {

// SHAKE256 XOF
std::vector<uint8_t> shake256(std::span<const uint8_t> data, size_t output_len) {
    std::vector<uint8_t> output(output_len);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(ctx, EVP_shake256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to init SHAKE256");
    }

    if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to update SHAKE256");
    }

    if (EVP_DigestFinalXOF(ctx, output.data(), output_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize SHAKE256");
    }

    EVP_MD_CTX_free(ctx);
    return output;
}

// SHA-256
std::vector<uint8_t> sha256(std::span<const uint8_t> data) {
    std::vector<uint8_t> output(32);
    unsigned int len = 32;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, output.data(), &len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHA-256 failed");
    }

    EVP_MD_CTX_free(ctx);
    return output;
}

// SHA-512
std::vector<uint8_t> sha512(std::span<const uint8_t> data) {
    std::vector<uint8_t> output(64);
    unsigned int len = 64;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, output.data(), &len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHA-512 failed");
    }

    EVP_MD_CTX_free(ctx);
    return output;
}

} // anonymous namespace


// SHAKE Hash Functions Implementation

SHAKEHashFunctions::SHAKEHashFunctions(const Params& params)
    : HashFunctions(params) {}

std::vector<uint8_t> SHAKEHashFunctions::H_msg(
    std::span<const uint8_t> R,
    std::span<const uint8_t> pk_seed,
    std::span<const uint8_t> pk_root,
    std::span<const uint8_t> M) const {

    std::vector<uint8_t> input;
    input.reserve(R.size() + pk_seed.size() + pk_root.size() + M.size());
    input.insert(input.end(), R.begin(), R.end());
    input.insert(input.end(), pk_seed.begin(), pk_seed.end());
    input.insert(input.end(), pk_root.begin(), pk_root.end());
    input.insert(input.end(), M.begin(), M.end());

    return shake256(input, params_.m);
}

std::vector<uint8_t> SHAKEHashFunctions::PRF_msg(
    std::span<const uint8_t> sk_prf,
    std::span<const uint8_t> opt_rand,
    std::span<const uint8_t> M) const {

    std::vector<uint8_t> input;
    input.reserve(sk_prf.size() + opt_rand.size() + M.size());
    input.insert(input.end(), sk_prf.begin(), sk_prf.end());
    input.insert(input.end(), opt_rand.begin(), opt_rand.end());
    input.insert(input.end(), M.begin(), M.end());

    return shake256(input, n_);
}

std::vector<uint8_t> SHAKEHashFunctions::PRF(
    std::span<const uint8_t> pk_seed,
    std::span<const uint8_t> sk_seed,
    const ADRS& adrs) const {

    auto adrs_bytes = adrs.to_bytes();

    std::vector<uint8_t> input;
    input.reserve(pk_seed.size() + ADRS::SIZE + sk_seed.size());
    input.insert(input.end(), pk_seed.begin(), pk_seed.end());
    input.insert(input.end(), adrs_bytes.begin(), adrs_bytes.end());
    input.insert(input.end(), sk_seed.begin(), sk_seed.end());

    return shake256(input, n_);
}

std::vector<uint8_t> SHAKEHashFunctions::F(
    std::span<const uint8_t> pk_seed,
    const ADRS& adrs,
    std::span<const uint8_t> M1) const {

    auto adrs_bytes = adrs.to_bytes();

    std::vector<uint8_t> input;
    input.reserve(pk_seed.size() + ADRS::SIZE + M1.size());
    input.insert(input.end(), pk_seed.begin(), pk_seed.end());
    input.insert(input.end(), adrs_bytes.begin(), adrs_bytes.end());
    input.insert(input.end(), M1.begin(), M1.end());

    return shake256(input, n_);
}

std::vector<uint8_t> SHAKEHashFunctions::H(
    std::span<const uint8_t> pk_seed,
    const ADRS& adrs,
    std::span<const uint8_t> M2) const {

    auto adrs_bytes = adrs.to_bytes();

    std::vector<uint8_t> input;
    input.reserve(pk_seed.size() + ADRS::SIZE + M2.size());
    input.insert(input.end(), pk_seed.begin(), pk_seed.end());
    input.insert(input.end(), adrs_bytes.begin(), adrs_bytes.end());
    input.insert(input.end(), M2.begin(), M2.end());

    return shake256(input, n_);
}

std::vector<uint8_t> SHAKEHashFunctions::T_l(
    std::span<const uint8_t> pk_seed,
    const ADRS& adrs,
    std::span<const uint8_t> M_l) const {

    auto adrs_bytes = adrs.to_bytes();

    std::vector<uint8_t> input;
    input.reserve(pk_seed.size() + ADRS::SIZE + M_l.size());
    input.insert(input.end(), pk_seed.begin(), pk_seed.end());
    input.insert(input.end(), adrs_bytes.begin(), adrs_bytes.end());
    input.insert(input.end(), M_l.begin(), M_l.end());

    return shake256(input, n_);
}


// SHA2 Hash Functions Implementation

SHA2HashFunctions::SHA2HashFunctions(const Params& params)
    : HashFunctions(params),
      use_sha512_(params.n != 16),
      block_size_(params.n == 16 ? 64 : 128) {}

std::vector<uint8_t> SHA2HashFunctions::hash(std::span<const uint8_t> data) const {
    if (use_sha512_) {
        return sha512(data);
    }
    return sha256(data);
}

std::vector<uint8_t> SHA2HashFunctions::mgf1(
    std::span<const uint8_t> seed, size_t length) const {

    std::vector<uint8_t> output;
    output.reserve(length + 64);  // Extra space for last hash

    uint32_t counter = 0;
    while (output.size() < length) {
        std::vector<uint8_t> input;
        input.reserve(seed.size() + 4);
        input.insert(input.end(), seed.begin(), seed.end());

        // Append counter as 4 bytes big-endian
        input.push_back(static_cast<uint8_t>(counter >> 24));
        input.push_back(static_cast<uint8_t>(counter >> 16));
        input.push_back(static_cast<uint8_t>(counter >> 8));
        input.push_back(static_cast<uint8_t>(counter));

        auto h = hash(input);
        output.insert(output.end(), h.begin(), h.end());
        counter++;
    }

    output.resize(length);
    return output;
}

std::vector<uint8_t> SHA2HashFunctions::hmac(
    std::span<const uint8_t> key,
    std::span<const uint8_t> data) const {

    const EVP_MD* md = use_sha512_ ? EVP_sha512() : EVP_sha256();
    size_t out_len = use_sha512_ ? 64 : 32;

    std::vector<uint8_t> output(out_len);
    unsigned int len = static_cast<unsigned int>(out_len);

    if (!HMAC(md, key.data(), static_cast<int>(key.size()),
              data.data(), data.size(), output.data(), &len)) {
        throw std::runtime_error("HMAC failed");
    }

    output.resize(len);
    return output;
}

std::vector<uint8_t> SHA2HashFunctions::H_msg(
    std::span<const uint8_t> R,
    std::span<const uint8_t> pk_seed,
    std::span<const uint8_t> pk_root,
    std::span<const uint8_t> M) const {

    // First hash to get seed for MGF1
    std::vector<uint8_t> input;
    input.reserve(R.size() + pk_seed.size() + pk_root.size() + M.size());
    input.insert(input.end(), R.begin(), R.end());
    input.insert(input.end(), pk_seed.begin(), pk_seed.end());
    input.insert(input.end(), pk_root.begin(), pk_root.end());
    input.insert(input.end(), M.begin(), M.end());

    auto seed = hash(input);

    // Combine R + pk_seed + seed for MGF1
    std::vector<uint8_t> mgf_input;
    mgf_input.reserve(R.size() + pk_seed.size() + seed.size());
    mgf_input.insert(mgf_input.end(), R.begin(), R.end());
    mgf_input.insert(mgf_input.end(), pk_seed.begin(), pk_seed.end());
    mgf_input.insert(mgf_input.end(), seed.begin(), seed.end());

    return mgf1(mgf_input, params_.m);
}

std::vector<uint8_t> SHA2HashFunctions::PRF_msg(
    std::span<const uint8_t> sk_prf,
    std::span<const uint8_t> opt_rand,
    std::span<const uint8_t> M) const {

    std::vector<uint8_t> data;
    data.reserve(opt_rand.size() + M.size());
    data.insert(data.end(), opt_rand.begin(), opt_rand.end());
    data.insert(data.end(), M.begin(), M.end());

    auto result = hmac(sk_prf, data);
    result.resize(n_);
    return result;
}

std::vector<uint8_t> SHA2HashFunctions::PRF(
    std::span<const uint8_t> pk_seed,
    std::span<const uint8_t> sk_seed,
    const ADRS& adrs) const {

    auto compressed = adrs.get_compressed_adrs();

    // PRF uses SHA-256 for n=16, SHA-512 for n=24/32
    // Padding: pk_seed || zeros(block_size-n) || ADRSc || sk_seed
    std::vector<uint8_t> data;
    size_t padding_len = block_size_ - n_;
    data.reserve(pk_seed.size() + padding_len + 22 + sk_seed.size());
    data.insert(data.end(), pk_seed.begin(), pk_seed.end());
    data.resize(data.size() + padding_len, 0);  // Add padding
    data.insert(data.end(), compressed.begin(), compressed.end());
    data.insert(data.end(), sk_seed.begin(), sk_seed.end());

    auto result = hash(data);  // Use appropriate hash based on n
    result.resize(n_);
    return result;
}

std::vector<uint8_t> SHA2HashFunctions::F(
    std::span<const uint8_t> pk_seed,
    const ADRS& adrs,
    std::span<const uint8_t> M1) const {

    auto compressed = adrs.get_compressed_adrs();

    // F uses SHA-256 for n=16, SHA-512 for n=24/32
    // Padding: pk_seed || zeros(block_size-n) || ADRSc || M1
    std::vector<uint8_t> data;
    size_t padding_len = block_size_ - n_;
    data.reserve(pk_seed.size() + padding_len + 22 + M1.size());
    data.insert(data.end(), pk_seed.begin(), pk_seed.end());
    data.resize(data.size() + padding_len, 0);  // Add padding
    data.insert(data.end(), compressed.begin(), compressed.end());
    data.insert(data.end(), M1.begin(), M1.end());

    auto result = hash(data);  // Use appropriate hash based on n
    result.resize(n_);
    return result;
}

std::vector<uint8_t> SHA2HashFunctions::H(
    std::span<const uint8_t> pk_seed,
    const ADRS& adrs,
    std::span<const uint8_t> M2) const {

    auto compressed = adrs.get_compressed_adrs();

    // H uses SHA-256 for n=16, SHA-512 for n=24/32
    // Padding: pk_seed || zeros(block_size-n) || ADRSc || M2
    std::vector<uint8_t> data;
    size_t padding_len = block_size_ - n_;
    data.reserve(pk_seed.size() + padding_len + 22 + M2.size());
    data.insert(data.end(), pk_seed.begin(), pk_seed.end());
    data.resize(data.size() + padding_len, 0);  // Add padding
    data.insert(data.end(), compressed.begin(), compressed.end());
    data.insert(data.end(), M2.begin(), M2.end());

    auto result = hash(data);
    result.resize(n_);
    return result;
}

std::vector<uint8_t> SHA2HashFunctions::T_l(
    std::span<const uint8_t> pk_seed,
    const ADRS& adrs,
    std::span<const uint8_t> M_l) const {

    auto compressed = adrs.get_compressed_adrs();

    // T_l uses SHA-256 for n=16, SHA-512 for n=24/32
    // Padding: pk_seed || zeros(block_size-n) || ADRSc || M_l
    std::vector<uint8_t> data;
    size_t padding_len = block_size_ - n_;
    data.reserve(pk_seed.size() + padding_len + 22 + M_l.size());
    data.insert(data.end(), pk_seed.begin(), pk_seed.end());
    data.resize(data.size() + padding_len, 0);  // Add padding
    data.insert(data.end(), compressed.begin(), compressed.end());
    data.insert(data.end(), M_l.begin(), M_l.end());

    auto result = hash(data);
    result.resize(n_);
    return result;
}


// Factory function

std::unique_ptr<HashFunctions> get_hash_functions(const Params& params) {
    if (params.hash_type == HashType::SHAKE) {
        return std::make_unique<SHAKEHashFunctions>(params);
    } else {
        return std::make_unique<SHA2HashFunctions>(params);
    }
}

} // namespace slhdsa
