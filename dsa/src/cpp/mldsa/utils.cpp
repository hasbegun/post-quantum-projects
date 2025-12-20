/**
 * Utility functions implementation
 * Uses OpenSSL for SHAKE128/SHAKE256 XOF
 */

#include "utils.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>

namespace mldsa {

// SHAKE128Stream implementation
SHAKE128Stream::SHAKE128Stream(std::span<const uint8_t> data) {
    seed_.assign(data.begin(), data.end());
}

SHAKE128Stream::~SHAKE128Stream() = default;

SHAKE128Stream::SHAKE128Stream(SHAKE128Stream&& other) noexcept = default;
SHAKE128Stream& SHAKE128Stream::operator=(SHAKE128Stream&& other) noexcept = default;

std::vector<uint8_t> SHAKE128Stream::read(size_t n) {
    size_t needed = total_read_ + n;
    if (buffer_.size() < needed) {
        // Generate more bytes
        buffer_ = shake128_xof(seed_, needed + 1024);
    }
    std::vector<uint8_t> result(buffer_.begin() + total_read_,
                                 buffer_.begin() + total_read_ + n);
    total_read_ += n;
    return result;
}

// SHAKE256Stream implementation
SHAKE256Stream::SHAKE256Stream(std::span<const uint8_t> data) {
    seed_.assign(data.begin(), data.end());
}

SHAKE256Stream::~SHAKE256Stream() = default;

SHAKE256Stream::SHAKE256Stream(SHAKE256Stream&& other) noexcept = default;
SHAKE256Stream& SHAKE256Stream::operator=(SHAKE256Stream&& other) noexcept = default;

std::vector<uint8_t> SHAKE256Stream::read(size_t n) {
    size_t needed = total_read_ + n;
    if (buffer_.size() < needed) {
        // Generate more bytes
        buffer_ = shake256_xof(seed_, needed + 1024);
    }
    std::vector<uint8_t> result(buffer_.begin() + total_read_,
                                 buffer_.begin() + total_read_ + n);
    total_read_ += n;
    return result;
}

std::vector<uint8_t> shake128_xof(std::span<const uint8_t> data, size_t output_len) {
    std::vector<uint8_t> output(output_len);

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(ctx, EVP_shake128(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to init SHAKE128");
    }

    if (EVP_DigestUpdate(ctx, data.data(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to update SHAKE128");
    }

    if (EVP_DigestFinalXOF(ctx, output.data(), output_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize SHAKE128");
    }

    EVP_MD_CTX_free(ctx);
    return output;
}

std::vector<uint8_t> shake256_xof(std::span<const uint8_t> data, size_t output_len) {
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

std::vector<uint8_t> random_bytes(size_t n) {
    std::vector<uint8_t> buffer(n);
    if (RAND_bytes(buffer.data(), static_cast<int>(n)) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
    return buffer;
}

} // namespace mldsa
