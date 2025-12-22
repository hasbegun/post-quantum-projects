/**
 * Key Encryption Utilities
 *
 * Provides password-based encryption for post-quantum secret keys using:
 *   - PBKDF2-HMAC-SHA256 for key derivation
 *   - AES-256-GCM for authenticated encryption
 *
 * This is applied at the storage layer - it does not modify the FIPS 204/205
 * key generation algorithms themselves. The secret key is generated per the
 * standard, then optionally encrypted before writing to disk.
 *
 * Encrypted file format:
 *   [0-7]   Magic header "PQCRYPT1" (8 bytes)
 *   [8-11]  Version (uint32_t, little-endian) = 1
 *   [12-15] Algorithm ID (uint32_t, little-endian)
 *   [16-47] Salt (32 bytes)
 *   [48-59] IV/Nonce (12 bytes for GCM)
 *   [60-75] Auth Tag (16 bytes)
 *   [76-79] Original size (uint32_t, little-endian)
 *   [80-..] Encrypted data
 */

#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <random>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

namespace pqc {

// Magic header for encrypted keys
constexpr char MAGIC_HEADER[] = "PQCRYPT1";
constexpr size_t MAGIC_SIZE = 8;
constexpr uint32_t FORMAT_VERSION = 1;

// Algorithm IDs for the certificate metadata
constexpr uint32_t ALG_MLDSA44 = 1;
constexpr uint32_t ALG_MLDSA65 = 2;
constexpr uint32_t ALG_MLDSA87 = 3;
constexpr uint32_t ALG_SLHDSA_SHAKE_128F = 10;
constexpr uint32_t ALG_SLHDSA_SHAKE_128S = 11;
constexpr uint32_t ALG_SLHDSA_SHAKE_192F = 12;
constexpr uint32_t ALG_SLHDSA_SHAKE_192S = 13;
constexpr uint32_t ALG_SLHDSA_SHAKE_256F = 14;
constexpr uint32_t ALG_SLHDSA_SHAKE_256S = 15;
constexpr uint32_t ALG_SLHDSA_SHA2_128F = 20;
constexpr uint32_t ALG_SLHDSA_SHA2_128S = 21;
constexpr uint32_t ALG_SLHDSA_SHA2_192F = 22;
constexpr uint32_t ALG_SLHDSA_SHA2_192S = 23;
constexpr uint32_t ALG_SLHDSA_SHA2_256F = 24;
constexpr uint32_t ALG_SLHDSA_SHA2_256S = 25;

// Encryption parameters
constexpr size_t SALT_SIZE = 32;
constexpr size_t IV_SIZE = 12;      // GCM standard nonce size
constexpr size_t TAG_SIZE = 16;     // GCM auth tag size
constexpr size_t KEY_SIZE = 32;     // AES-256
constexpr int PBKDF2_ITERATIONS = 600000;  // OWASP 2023 recommendation

// Header size = magic + version + alg_id + salt + iv + tag + orig_size
constexpr size_t HEADER_SIZE = MAGIC_SIZE + 4 + 4 + SALT_SIZE + IV_SIZE + TAG_SIZE + 4;

/**
 * Get OpenSSL error string
 */
inline std::string get_openssl_error() {
    unsigned long err = ERR_get_error();
    if (err == 0) return "Unknown OpenSSL error";
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

/**
 * Derive encryption key from password using PBKDF2-HMAC-SHA256
 */
inline std::vector<uint8_t> derive_key(const std::string& password,
                                       const std::vector<uint8_t>& salt) {
    std::vector<uint8_t> key(KEY_SIZE);

    int result = PKCS5_PBKDF2_HMAC(
        password.c_str(),
        static_cast<int>(password.length()),
        salt.data(),
        static_cast<int>(salt.size()),
        PBKDF2_ITERATIONS,
        EVP_sha256(),
        static_cast<int>(KEY_SIZE),
        key.data()
    );

    if (result != 1) {
        throw std::runtime_error("PBKDF2 key derivation failed: " + get_openssl_error());
    }

    return key;
}

/**
 * Generate cryptographically secure random bytes
 */
inline std::vector<uint8_t> generate_random_bytes(size_t count) {
    std::vector<uint8_t> bytes(count);
    if (RAND_bytes(bytes.data(), static_cast<int>(count)) != 1) {
        throw std::runtime_error("Failed to generate random bytes: " + get_openssl_error());
    }
    return bytes;
}

/**
 * Write a 32-bit little-endian value to a byte vector
 */
inline void write_u32_le(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
}

/**
 * Read a 32-bit little-endian value from bytes
 */
inline uint32_t read_u32_le(const uint8_t* data) {
    return static_cast<uint32_t>(data[0]) |
           (static_cast<uint32_t>(data[1]) << 8) |
           (static_cast<uint32_t>(data[2]) << 16) |
           (static_cast<uint32_t>(data[3]) << 24);
}

/**
 * Encrypt secret key data using AES-256-GCM
 *
 * @param plaintext The secret key bytes to encrypt
 * @param password  The user's password
 * @param alg_id    Algorithm identifier for metadata
 * @return Encrypted data with header
 */
inline std::vector<uint8_t> encrypt_secret_key(
    const std::vector<uint8_t>& plaintext,
    const std::string& password,
    uint32_t alg_id = 0
) {
    // Generate salt and IV
    auto salt = generate_random_bytes(SALT_SIZE);
    auto iv = generate_random_bytes(IV_SIZE);

    // Derive encryption key
    auto key = derive_key(password, salt);

    // Create cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }

    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to init AES-GCM: " + get_openssl_error());
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set IV length: " + get_openssl_error());
    }

    // Set key and IV
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set key/IV: " + get_openssl_error());
    }

    // Encrypt
    std::vector<uint8_t> ciphertext(plaintext.size() + 16);  // Extra space for potential padding
    int len = 0;
    int ciphertext_len = 0;

    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption failed: " + get_openssl_error());
    }
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Encryption finalization failed: " + get_openssl_error());
    }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    // Get auth tag
    std::vector<uint8_t> tag(TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to get auth tag: " + get_openssl_error());
    }

    EVP_CIPHER_CTX_free(ctx);

    // Build output: header + ciphertext
    std::vector<uint8_t> output;
    output.reserve(HEADER_SIZE + ciphertext.size());

    // Magic header
    output.insert(output.end(), MAGIC_HEADER, MAGIC_HEADER + MAGIC_SIZE);

    // Version
    write_u32_le(output, FORMAT_VERSION);

    // Algorithm ID
    write_u32_le(output, alg_id);

    // Salt
    output.insert(output.end(), salt.begin(), salt.end());

    // IV
    output.insert(output.end(), iv.begin(), iv.end());

    // Auth tag
    output.insert(output.end(), tag.begin(), tag.end());

    // Original plaintext size
    write_u32_le(output, static_cast<uint32_t>(plaintext.size()));

    // Encrypted data
    output.insert(output.end(), ciphertext.begin(), ciphertext.end());

    // Clear sensitive data
    std::fill(key.begin(), key.end(), 0);

    return output;
}

/**
 * Decrypt secret key data
 *
 * @param encrypted The encrypted data with header
 * @param password  The user's password
 * @return Decrypted secret key bytes
 */
inline std::vector<uint8_t> decrypt_secret_key(
    const std::vector<uint8_t>& encrypted,
    const std::string& password
) {
    // Validate minimum size
    if (encrypted.size() < HEADER_SIZE) {
        throw std::runtime_error("Encrypted data too small");
    }

    // Check magic header
    if (std::memcmp(encrypted.data(), MAGIC_HEADER, MAGIC_SIZE) != 0) {
        throw std::runtime_error("Invalid encrypted key format (bad magic header)");
    }

    size_t offset = MAGIC_SIZE;

    // Read version
    uint32_t version = read_u32_le(encrypted.data() + offset);
    offset += 4;
    if (version != FORMAT_VERSION) {
        throw std::runtime_error("Unsupported encrypted key version: " + std::to_string(version));
    }

    // Read algorithm ID (for reference, not used in decryption)
    // uint32_t alg_id = read_u32_le(encrypted.data() + offset);
    offset += 4;

    // Read salt
    std::vector<uint8_t> salt(encrypted.data() + offset, encrypted.data() + offset + SALT_SIZE);
    offset += SALT_SIZE;

    // Read IV
    std::vector<uint8_t> iv(encrypted.data() + offset, encrypted.data() + offset + IV_SIZE);
    offset += IV_SIZE;

    // Read auth tag
    std::vector<uint8_t> tag(encrypted.data() + offset, encrypted.data() + offset + TAG_SIZE);
    offset += TAG_SIZE;

    // Read original size
    uint32_t orig_size = read_u32_le(encrypted.data() + offset);
    offset += 4;

    // Get ciphertext
    std::vector<uint8_t> ciphertext(encrypted.begin() + offset, encrypted.end());

    // Derive key
    auto key = derive_key(password, salt);

    // Create cipher context
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create cipher context");
    }

    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to init AES-GCM: " + get_openssl_error());
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_SIZE, nullptr) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set IV length: " + get_openssl_error());
    }

    // Set key and IV
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), iv.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set key/IV: " + get_openssl_error());
    }

    // Decrypt
    std::vector<uint8_t> plaintext(ciphertext.size());
    int len = 0;
    int plaintext_len = 0;

    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(),
                          static_cast<int>(ciphertext.size())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Decryption failed: " + get_openssl_error());
    }
    plaintext_len = len;

    // Set expected tag
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
                            const_cast<uint8_t*>(tag.data())) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("Failed to set auth tag: " + get_openssl_error());
    }

    // Finalize and verify tag
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret <= 0) {
        // Clear potentially corrupted data
        std::fill(plaintext.begin(), plaintext.end(), 0);
        throw std::runtime_error("Decryption failed: wrong password or corrupted data");
    }

    plaintext_len += len;
    plaintext.resize(plaintext_len);

    // Verify size matches
    if (plaintext.size() != orig_size) {
        throw std::runtime_error("Decrypted size mismatch");
    }

    // Clear sensitive data
    std::fill(key.begin(), key.end(), 0);

    return plaintext;
}

/**
 * Check if data is an encrypted key file
 */
inline bool is_encrypted_key(const std::vector<uint8_t>& data) {
    if (data.size() < MAGIC_SIZE) return false;
    return std::memcmp(data.data(), MAGIC_HEADER, MAGIC_SIZE) == 0;
}

/**
 * Get algorithm ID from algorithm name
 */
inline uint32_t get_algorithm_id(const std::string& name) {
    if (name == "MLDSA44") return ALG_MLDSA44;
    if (name == "MLDSA65") return ALG_MLDSA65;
    if (name == "MLDSA87") return ALG_MLDSA87;
    if (name == "SLH-DSA-SHAKE-128f") return ALG_SLHDSA_SHAKE_128F;
    if (name == "SLH-DSA-SHAKE-128s") return ALG_SLHDSA_SHAKE_128S;
    if (name == "SLH-DSA-SHAKE-192f") return ALG_SLHDSA_SHAKE_192F;
    if (name == "SLH-DSA-SHAKE-192s") return ALG_SLHDSA_SHAKE_192S;
    if (name == "SLH-DSA-SHAKE-256f") return ALG_SLHDSA_SHAKE_256F;
    if (name == "SLH-DSA-SHAKE-256s") return ALG_SLHDSA_SHAKE_256S;
    if (name == "SLH-DSA-SHA2-128f") return ALG_SLHDSA_SHA2_128F;
    if (name == "SLH-DSA-SHA2-128s") return ALG_SLHDSA_SHA2_128S;
    if (name == "SLH-DSA-SHA2-192f") return ALG_SLHDSA_SHA2_192F;
    if (name == "SLH-DSA-SHA2-192s") return ALG_SLHDSA_SHA2_192S;
    if (name == "SLH-DSA-SHA2-256f") return ALG_SLHDSA_SHA2_256F;
    if (name == "SLH-DSA-SHA2-256s") return ALG_SLHDSA_SHA2_256S;
    return 0;
}

} // namespace pqc
