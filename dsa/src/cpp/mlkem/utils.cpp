/**
 * ML-KEM Utility Functions Implementation
 * OpenSSL-based cryptographic primitives
 */

#include "utils.hpp"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <cstring>

namespace mlkem {

// SHA3-256 implementation
std::vector<uint8_t> sha3_256(std::span<const uint8_t> data) {
    std::vector<uint8_t> hash(32);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, hash.data(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHA3-256 hash failed");
    }

    EVP_MD_CTX_free(ctx);
    return hash;
}

// SHA3-512 implementation
std::vector<uint8_t> sha3_512(std::span<const uint8_t> data) {
    std::vector<uint8_t> hash(64);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha3_512(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, hash.data(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHA3-512 hash failed");
    }

    EVP_MD_CTX_free(ctx);
    return hash;
}

// SHAKE128 XOF function
std::vector<uint8_t> shake128(std::span<const uint8_t> data, size_t output_len) {
    std::vector<uint8_t> output(output_len);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(ctx, EVP_shake128(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinalXOF(ctx, output.data(), output_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHAKE128 failed");
    }

    EVP_MD_CTX_free(ctx);
    return output;
}

// SHAKE256 XOF function
std::vector<uint8_t> shake256(std::span<const uint8_t> data, size_t output_len) {
    std::vector<uint8_t> output(output_len);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestInit_ex(ctx, EVP_shake256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx, data.data(), data.size()) != 1 ||
        EVP_DigestFinalXOF(ctx, output.data(), output_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("SHAKE256 failed");
    }

    EVP_MD_CTX_free(ctx);
    return output;
}

// SHAKE128Stream implementation
SHAKE128Stream::SHAKE128Stream(std::span<const uint8_t> data)
    : seed_(data.begin(), data.end()) {
    ctx_ = EVP_MD_CTX_new();
    if (!ctx_) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }
    if (EVP_DigestInit_ex(ctx_, EVP_shake128(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx_, data.data(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx_);
        ctx_ = nullptr;
        throw std::runtime_error("SHAKE128 initialization failed");
    }
}

SHAKE128Stream::~SHAKE128Stream() {
    if (ctx_) {
        EVP_MD_CTX_free(ctx_);
    }
}

SHAKE128Stream::SHAKE128Stream(SHAKE128Stream&& other) noexcept
    : ctx_(other.ctx_)
    , buffer_(std::move(other.buffer_))
    , buffer_pos_(other.buffer_pos_)
    , seed_(std::move(other.seed_))
    , finalized_(other.finalized_) {
    other.ctx_ = nullptr;
}

SHAKE128Stream& SHAKE128Stream::operator=(SHAKE128Stream&& other) noexcept {
    if (this != &other) {
        if (ctx_) {
            EVP_MD_CTX_free(ctx_);
        }
        ctx_ = other.ctx_;
        buffer_ = std::move(other.buffer_);
        buffer_pos_ = other.buffer_pos_;
        seed_ = std::move(other.seed_);
        finalized_ = other.finalized_;
        other.ctx_ = nullptr;
    }
    return *this;
}

std::vector<uint8_t> SHAKE128Stream::read(size_t n) {
    // Reasonable maximum to prevent overflow and excessive allocation
    constexpr size_t MAX_BUFFER_SIZE = 1ULL << 30;  // 1 GB

    if (n > MAX_BUFFER_SIZE) {
        throw std::runtime_error("SHAKE128 read request too large");
    }

    std::vector<uint8_t> result(n);
    size_t written = 0;

    // First, use any buffered data
    while (written < n && buffer_pos_ < buffer_.size()) {
        result[written++] = buffer_[buffer_pos_++];
    }

    // If we need more data, generate it
    if (written < n) {
        if (!finalized_) {
            // Finalize and get a large chunk
            size_t remaining = n - written;
            // Check for overflow before adding 1024
            if (remaining > MAX_BUFFER_SIZE - 1024) {
                throw std::runtime_error("SHAKE128 buffer size overflow");
            }
            size_t needed = remaining + 1024;  // Get extra for future reads
            buffer_.resize(needed);
            if (EVP_DigestFinalXOF(ctx_, buffer_.data(), needed) != 1) {
                throw std::runtime_error("SHAKE128 finalization failed");
            }
            finalized_ = true;
            buffer_pos_ = 0;
        } else {
            // Need to re-initialize and squeeze more
            EVP_MD_CTX_free(ctx_);
            ctx_ = EVP_MD_CTX_new();
            if (!ctx_) {
                throw std::runtime_error("Failed to create EVP_MD_CTX");
            }

            size_t remaining = n - written;
            // Check for overflow in total_needed calculation
            if (buffer_.size() > MAX_BUFFER_SIZE - remaining - 1024) {
                throw std::runtime_error("SHAKE128 buffer size overflow");
            }
            size_t total_needed = buffer_.size() + remaining + 1024;
            std::vector<uint8_t> new_buffer(total_needed);

            if (EVP_DigestInit_ex(ctx_, EVP_shake128(), nullptr) != 1 ||
                EVP_DigestUpdate(ctx_, seed_.data(), seed_.size()) != 1 ||
                EVP_DigestFinalXOF(ctx_, new_buffer.data(), total_needed) != 1) {
                throw std::runtime_error("SHAKE128 re-initialization failed");
            }

            // Copy from where we left off
            size_t old_pos = buffer_.size();
            buffer_ = std::move(new_buffer);
            buffer_pos_ = old_pos;
        }

        // Copy remaining needed bytes
        while (written < n && buffer_pos_ < buffer_.size()) {
            result[written++] = buffer_[buffer_pos_++];
        }
    }

    return result;
}

// SHAKE256Stream implementation
SHAKE256Stream::SHAKE256Stream(std::span<const uint8_t> data)
    : seed_(data.begin(), data.end()) {
    ctx_ = EVP_MD_CTX_new();
    if (!ctx_) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }
    if (EVP_DigestInit_ex(ctx_, EVP_shake256(), nullptr) != 1 ||
        EVP_DigestUpdate(ctx_, data.data(), data.size()) != 1) {
        EVP_MD_CTX_free(ctx_);
        ctx_ = nullptr;
        throw std::runtime_error("SHAKE256 initialization failed");
    }
}

SHAKE256Stream::~SHAKE256Stream() {
    if (ctx_) {
        EVP_MD_CTX_free(ctx_);
    }
}

SHAKE256Stream::SHAKE256Stream(SHAKE256Stream&& other) noexcept
    : ctx_(other.ctx_)
    , buffer_(std::move(other.buffer_))
    , buffer_pos_(other.buffer_pos_)
    , seed_(std::move(other.seed_))
    , finalized_(other.finalized_) {
    other.ctx_ = nullptr;
}

SHAKE256Stream& SHAKE256Stream::operator=(SHAKE256Stream&& other) noexcept {
    if (this != &other) {
        if (ctx_) {
            EVP_MD_CTX_free(ctx_);
        }
        ctx_ = other.ctx_;
        buffer_ = std::move(other.buffer_);
        buffer_pos_ = other.buffer_pos_;
        seed_ = std::move(other.seed_);
        finalized_ = other.finalized_;
        other.ctx_ = nullptr;
    }
    return *this;
}

std::vector<uint8_t> SHAKE256Stream::read(size_t n) {
    // Reasonable maximum to prevent overflow and excessive allocation
    constexpr size_t MAX_BUFFER_SIZE = 1ULL << 30;  // 1 GB

    if (n > MAX_BUFFER_SIZE) {
        throw std::runtime_error("SHAKE256 read request too large");
    }

    std::vector<uint8_t> result(n);
    size_t written = 0;

    // First, use any buffered data
    while (written < n && buffer_pos_ < buffer_.size()) {
        result[written++] = buffer_[buffer_pos_++];
    }

    // If we need more data, generate it
    if (written < n) {
        if (!finalized_) {
            // Finalize and get a large chunk
            size_t remaining = n - written;
            // Check for overflow before adding 1024
            if (remaining > MAX_BUFFER_SIZE - 1024) {
                throw std::runtime_error("SHAKE256 buffer size overflow");
            }
            size_t needed = remaining + 1024;
            buffer_.resize(needed);
            if (EVP_DigestFinalXOF(ctx_, buffer_.data(), needed) != 1) {
                throw std::runtime_error("SHAKE256 finalization failed");
            }
            finalized_ = true;
            buffer_pos_ = 0;
        } else {
            // Need to re-initialize and squeeze more
            EVP_MD_CTX_free(ctx_);
            ctx_ = EVP_MD_CTX_new();
            if (!ctx_) {
                throw std::runtime_error("Failed to create EVP_MD_CTX");
            }

            size_t remaining = n - written;
            // Check for overflow in total_needed calculation
            if (buffer_.size() > MAX_BUFFER_SIZE - remaining - 1024) {
                throw std::runtime_error("SHAKE256 buffer size overflow");
            }
            size_t total_needed = buffer_.size() + remaining + 1024;
            std::vector<uint8_t> new_buffer(total_needed);

            if (EVP_DigestInit_ex(ctx_, EVP_shake256(), nullptr) != 1 ||
                EVP_DigestUpdate(ctx_, seed_.data(), seed_.size()) != 1 ||
                EVP_DigestFinalXOF(ctx_, new_buffer.data(), total_needed) != 1) {
                throw std::runtime_error("SHAKE256 re-initialization failed");
            }

            size_t old_pos = buffer_.size();
            buffer_ = std::move(new_buffer);
            buffer_pos_ = old_pos;
        }

        // Copy remaining needed bytes
        while (written < n && buffer_pos_ < buffer_.size()) {
            result[written++] = buffer_[buffer_pos_++];
        }
    }

    return result;
}

// Random bytes generation
std::vector<uint8_t> random_bytes(size_t n) {
    std::vector<uint8_t> bytes(n);
    if (RAND_bytes(bytes.data(), static_cast<int>(n)) != 1) {
        throw std::runtime_error("Random number generation failed");
    }
    return bytes;
}

} // namespace mlkem
