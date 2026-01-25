/**
 * HSM Integration for Post-Quantum Cryptography
 *
 * Provides a PKCS#11-inspired interface for Hardware Security Module integration.
 * Includes a software token implementation for testing and environments without HSM.
 *
 * Key Features:
 * - Slot and token management
 * - Session handling with automatic cleanup (RAII)
 * - Key generation, import, and export
 * - Sign and verify operations
 * - Key encapsulation (ML-KEM)
 * - Software token for testing
 *
 * Usage:
 *   // Initialize HSM provider
 *   auto provider = pqc::hsm::create_software_provider();
 *
 *   // Open session
 *   auto session = provider->open_session(0);
 *   session->login("1234");
 *
 *   // Generate key pair
 *   auto key_id = session->generate_key_pair("ML-DSA-65", "my-signing-key");
 *
 *   // Sign data
 *   auto signature = session->sign(key_id, message);
 *
 *   // Verify signature
 *   bool valid = session->verify(key_id, message, signature);
 */

#ifndef PQC_COMMON_HSM_HPP
#define PQC_COMMON_HSM_HPP

#include "mldsa/mldsa.hpp"
#include "slhdsa/slh_dsa.hpp"
#include "mlkem/mlkem.hpp"
#include "algorithm_factory.hpp"
#include <memory>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <functional>
#include <cstring>
#include <random>

namespace pqc::hsm {

// ============================================================================
// Error Types
// ============================================================================

/**
 * HSM-related errors
 */
class HSMError : public std::runtime_error {
public:
    enum class Code {
        OK = 0,
        SLOT_NOT_FOUND,
        TOKEN_NOT_PRESENT,
        SESSION_CLOSED,
        SESSION_EXISTS,
        PIN_INCORRECT,
        PIN_LOCKED,
        KEY_NOT_FOUND,
        KEY_TYPE_MISMATCH,
        OPERATION_NOT_SUPPORTED,
        BUFFER_TOO_SMALL,
        DATA_INVALID,
        SIGNATURE_INVALID,
        DEVICE_ERROR,
        GENERAL_ERROR
    };

    HSMError(Code code, const std::string& message)
        : std::runtime_error(message), code_(code) {}

    Code code() const { return code_; }

private:
    Code code_;
};

// ============================================================================
// Key and Object Types
// ============================================================================

/**
 * Key types supported by the HSM
 */
enum class KeyType {
    // Digital Signature keys
    ML_DSA_44,
    ML_DSA_65,
    ML_DSA_87,
    SLH_DSA_SHA2_128s,
    SLH_DSA_SHA2_128f,
    SLH_DSA_SHA2_192s,
    SLH_DSA_SHA2_192f,
    SLH_DSA_SHA2_256s,
    SLH_DSA_SHA2_256f,
    SLH_DSA_SHAKE_128s,
    SLH_DSA_SHAKE_128f,
    SLH_DSA_SHAKE_192s,
    SLH_DSA_SHAKE_192f,
    SLH_DSA_SHAKE_256s,
    SLH_DSA_SHAKE_256f,
    // Key Encapsulation keys
    ML_KEM_512,
    ML_KEM_768,
    ML_KEM_1024
};

/**
 * Convert algorithm name to KeyType
 */
inline KeyType key_type_from_name(const std::string& name) {
    static const std::map<std::string, KeyType> mapping = {
        {"ML-DSA-44", KeyType::ML_DSA_44},
        {"ML-DSA-65", KeyType::ML_DSA_65},
        {"ML-DSA-87", KeyType::ML_DSA_87},
        {"SLH-DSA-SHA2-128s", KeyType::SLH_DSA_SHA2_128s},
        {"SLH-DSA-SHA2-128f", KeyType::SLH_DSA_SHA2_128f},
        {"SLH-DSA-SHA2-192s", KeyType::SLH_DSA_SHA2_192s},
        {"SLH-DSA-SHA2-192f", KeyType::SLH_DSA_SHA2_192f},
        {"SLH-DSA-SHA2-256s", KeyType::SLH_DSA_SHA2_256s},
        {"SLH-DSA-SHA2-256f", KeyType::SLH_DSA_SHA2_256f},
        {"SLH-DSA-SHAKE-128s", KeyType::SLH_DSA_SHAKE_128s},
        {"SLH-DSA-SHAKE-128f", KeyType::SLH_DSA_SHAKE_128f},
        {"SLH-DSA-SHAKE-192s", KeyType::SLH_DSA_SHAKE_192s},
        {"SLH-DSA-SHAKE-192f", KeyType::SLH_DSA_SHAKE_192f},
        {"SLH-DSA-SHAKE-256s", KeyType::SLH_DSA_SHAKE_256s},
        {"SLH-DSA-SHAKE-256f", KeyType::SLH_DSA_SHAKE_256f},
        {"ML-KEM-512", KeyType::ML_KEM_512},
        {"ML-KEM-768", KeyType::ML_KEM_768},
        {"ML-KEM-1024", KeyType::ML_KEM_1024}
    };

    auto it = mapping.find(name);
    if (it == mapping.end()) {
        throw HSMError(HSMError::Code::OPERATION_NOT_SUPPORTED,
                       "Unknown algorithm: " + name);
    }
    return it->second;
}

/**
 * Convert KeyType to algorithm name
 */
inline std::string key_type_to_name(KeyType type) {
    static const std::map<KeyType, std::string> mapping = {
        {KeyType::ML_DSA_44, "ML-DSA-44"},
        {KeyType::ML_DSA_65, "ML-DSA-65"},
        {KeyType::ML_DSA_87, "ML-DSA-87"},
        {KeyType::SLH_DSA_SHA2_128s, "SLH-DSA-SHA2-128s"},
        {KeyType::SLH_DSA_SHA2_128f, "SLH-DSA-SHA2-128f"},
        {KeyType::SLH_DSA_SHA2_192s, "SLH-DSA-SHA2-192s"},
        {KeyType::SLH_DSA_SHA2_192f, "SLH-DSA-SHA2-192f"},
        {KeyType::SLH_DSA_SHA2_256s, "SLH-DSA-SHA2-256s"},
        {KeyType::SLH_DSA_SHA2_256f, "SLH-DSA-SHA2-256f"},
        {KeyType::SLH_DSA_SHAKE_128s, "SLH-DSA-SHAKE-128s"},
        {KeyType::SLH_DSA_SHAKE_128f, "SLH-DSA-SHAKE-128f"},
        {KeyType::SLH_DSA_SHAKE_192s, "SLH-DSA-SHAKE-192s"},
        {KeyType::SLH_DSA_SHAKE_192f, "SLH-DSA-SHAKE-192f"},
        {KeyType::SLH_DSA_SHAKE_256s, "SLH-DSA-SHAKE-256s"},
        {KeyType::SLH_DSA_SHAKE_256f, "SLH-DSA-SHAKE-256f"},
        {KeyType::ML_KEM_512, "ML-KEM-512"},
        {KeyType::ML_KEM_768, "ML-KEM-768"},
        {KeyType::ML_KEM_1024, "ML-KEM-1024"}
    };

    auto it = mapping.find(type);
    if (it == mapping.end()) {
        return "Unknown";
    }
    return it->second;
}

/**
 * Check if key type is for digital signatures
 */
inline bool is_signature_key(KeyType type) {
    return type != KeyType::ML_KEM_512 &&
           type != KeyType::ML_KEM_768 &&
           type != KeyType::ML_KEM_1024;
}

/**
 * Check if key type is for key encapsulation
 */
inline bool is_kem_key(KeyType type) {
    return type == KeyType::ML_KEM_512 ||
           type == KeyType::ML_KEM_768 ||
           type == KeyType::ML_KEM_1024;
}

/**
 * Key attributes
 */
struct KeyAttributes {
    std::string label;              // Human-readable label
    KeyType type;                   // Algorithm type
    bool extractable = false;       // Can private key be exported?
    bool sensitive = true;          // Is this a sensitive key?
    bool sign = true;               // Can be used for signing
    bool verify = true;             // Can be used for verification
    bool encrypt = false;           // Can be used for encryption
    bool decrypt = false;           // Can be used for decryption
    bool wrap = false;              // Can wrap other keys
    bool unwrap = false;            // Can unwrap other keys
};

/**
 * Unique key identifier
 */
using KeyHandle = uint64_t;

/**
 * Key information returned by queries
 */
struct KeyInfo {
    KeyHandle handle;
    KeyAttributes attributes;
    size_t public_key_size;
    size_t private_key_size;
    bool has_private_key;
};

// ============================================================================
// Token and Slot Information
// ============================================================================

/**
 * Token information
 */
struct TokenInfo {
    std::string label;
    std::string manufacturer;
    std::string model;
    std::string serial_number;
    bool initialized = false;
    bool user_pin_initialized = false;
    bool token_present = true;
    size_t free_public_memory = 0;
    size_t free_private_memory = 0;
    size_t total_public_memory = 0;
    size_t total_private_memory = 0;
};

/**
 * Slot information
 */
struct SlotInfo {
    std::string description;
    std::string manufacturer;
    bool token_present = false;
    bool removable = false;
    bool hardware_slot = false;
};

// ============================================================================
// Session Interface
// ============================================================================

/**
 * HSM Session - represents an authenticated connection to a token
 */
class Session {
public:
    virtual ~Session() = default;

    /**
     * Login to the token
     * @param pin User PIN
     */
    virtual void login(const std::string& pin) = 0;

    /**
     * Logout from the token
     */
    virtual void logout() = 0;

    /**
     * Check if logged in
     */
    virtual bool is_logged_in() const = 0;

    /**
     * Generate a new key pair
     * @param algorithm Algorithm name (e.g., "ML-DSA-65")
     * @param label Human-readable label for the key
     * @param attrs Optional additional attributes
     * @return Handle to the generated key pair
     */
    virtual KeyHandle generate_key_pair(
        const std::string& algorithm,
        const std::string& label,
        const KeyAttributes* attrs = nullptr) = 0;

    /**
     * Import a key pair
     * @param algorithm Algorithm name
     * @param label Human-readable label
     * @param public_key Public key bytes
     * @param private_key Private key bytes (empty for public-only)
     * @return Handle to the imported key
     */
    virtual KeyHandle import_key(
        const std::string& algorithm,
        const std::string& label,
        const std::vector<uint8_t>& public_key,
        const std::vector<uint8_t>& private_key = {}) = 0;

    /**
     * Export public key
     * @param handle Key handle
     * @return Public key bytes
     */
    virtual std::vector<uint8_t> export_public_key(KeyHandle handle) = 0;

    /**
     * Export private key (if extractable)
     * @param handle Key handle
     * @return Private key bytes
     * @throws HSMError if key is not extractable
     */
    virtual std::vector<uint8_t> export_private_key(KeyHandle handle) = 0;

    /**
     * Delete a key
     * @param handle Key handle
     */
    virtual void delete_key(KeyHandle handle) = 0;

    /**
     * Find keys by label
     * @param label Label to search for (empty for all keys)
     * @return Vector of matching key handles
     */
    virtual std::vector<KeyHandle> find_keys(const std::string& label = "") = 0;

    /**
     * Get key information
     * @param handle Key handle
     * @return Key information
     */
    virtual KeyInfo get_key_info(KeyHandle handle) = 0;

    /**
     * Sign data using a private key
     * @param handle Key handle
     * @param data Data to sign
     * @return Signature
     */
    virtual std::vector<uint8_t> sign(
        KeyHandle handle,
        const std::vector<uint8_t>& data) = 0;

    /**
     * Verify a signature using a public key
     * @param handle Key handle
     * @param data Original data
     * @param signature Signature to verify
     * @return true if valid, false otherwise
     */
    virtual bool verify(
        KeyHandle handle,
        const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& signature) = 0;

    /**
     * Encapsulate a shared secret (ML-KEM)
     * @param handle Key handle (encapsulation key)
     * @param[out] ciphertext The ciphertext to send to the other party
     * @return Shared secret
     */
    virtual std::vector<uint8_t> encapsulate(
        KeyHandle handle,
        std::vector<uint8_t>& ciphertext) = 0;

    /**
     * Decapsulate a shared secret (ML-KEM)
     * @param handle Key handle (decapsulation key)
     * @param ciphertext Ciphertext from encapsulation
     * @return Shared secret
     */
    virtual std::vector<uint8_t> decapsulate(
        KeyHandle handle,
        const std::vector<uint8_t>& ciphertext) = 0;

    /**
     * Get session slot ID
     */
    virtual uint32_t slot_id() const = 0;
};

// ============================================================================
// HSM Provider Interface
// ============================================================================

/**
 * HSM Provider - manages slots, tokens, and sessions
 */
class Provider {
public:
    virtual ~Provider() = default;

    /**
     * Get provider name
     */
    virtual std::string name() const = 0;

    /**
     * Get list of available slot IDs
     */
    virtual std::vector<uint32_t> get_slot_list() = 0;

    /**
     * Get slot information
     * @param slot_id Slot ID
     */
    virtual SlotInfo get_slot_info(uint32_t slot_id) = 0;

    /**
     * Get token information for a slot
     * @param slot_id Slot ID
     */
    virtual TokenInfo get_token_info(uint32_t slot_id) = 0;

    /**
     * Initialize a token
     * @param slot_id Slot ID
     * @param so_pin Security Officer PIN
     * @param label Token label
     */
    virtual void init_token(
        uint32_t slot_id,
        const std::string& so_pin,
        const std::string& label) = 0;

    /**
     * Initialize user PIN
     * @param slot_id Slot ID
     * @param so_pin Security Officer PIN
     * @param user_pin New user PIN
     */
    virtual void init_user_pin(
        uint32_t slot_id,
        const std::string& so_pin,
        const std::string& user_pin) = 0;

    /**
     * Open a session to a token
     * @param slot_id Slot ID
     * @return Session object
     */
    virtual std::unique_ptr<Session> open_session(uint32_t slot_id) = 0;
};

// ============================================================================
// Software Token Implementation
// ============================================================================

namespace detail {

/**
 * Key storage entry
 */
struct StoredKey {
    KeyAttributes attributes;
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> private_key;  // Empty if public-only
};

/**
 * Software token state
 */
struct SoftwareTokenState {
    bool initialized = false;
    std::string label;
    std::string so_pin;
    std::string user_pin;
    bool user_pin_initialized = false;

    std::map<KeyHandle, StoredKey> keys;
    KeyHandle next_handle = 1;
    mutable std::mutex mutex;
};

} // namespace detail

/**
 * Software-based session implementation
 */
class SoftwareSession : public Session {
public:
    SoftwareSession(uint32_t slot_id, std::shared_ptr<detail::SoftwareTokenState> state)
        : slot_id_(slot_id)
        , state_(std::move(state))
        , logged_in_(false) {}

    ~SoftwareSession() override {
        if (logged_in_) {
            try { logout(); } catch (...) {}
        }
    }

    void login(const std::string& pin) override {
        std::lock_guard<std::mutex> lock(state_->mutex);

        if (!state_->initialized) {
            throw HSMError(HSMError::Code::TOKEN_NOT_PRESENT, "Token not initialized");
        }
        if (!state_->user_pin_initialized) {
            throw HSMError(HSMError::Code::PIN_INCORRECT, "User PIN not initialized");
        }
        if (pin != state_->user_pin) {
            throw HSMError(HSMError::Code::PIN_INCORRECT, "Invalid PIN");
        }
        logged_in_ = true;
    }

    void logout() override {
        logged_in_ = false;
    }

    bool is_logged_in() const override {
        return logged_in_;
    }

    KeyHandle generate_key_pair(
        const std::string& algorithm,
        const std::string& label,
        const KeyAttributes* attrs) override {

        require_login();

        KeyType type = key_type_from_name(algorithm);
        std::string algo_name = key_type_to_name(type);

        std::vector<uint8_t> pk, sk;

        // Generate key pair based on algorithm type
        if (is_signature_key(type)) {
            auto dsa = pqc::create_dsa(algo_name);
            auto [public_key, private_key] = dsa->keygen();
            pk = std::move(public_key);
            sk = std::move(private_key);
        } else {
            auto kem = pqc::create_kem(algo_name);
            auto [encaps_key, decaps_key] = kem->keygen();
            pk = std::move(encaps_key);
            sk = std::move(decaps_key);
        }

        // Create key entry
        detail::StoredKey key;
        if (attrs) {
            key.attributes = *attrs;
        } else {
            key.attributes.label = label;
            key.attributes.type = type;
            key.attributes.extractable = false;
            key.attributes.sensitive = true;
            if (is_signature_key(type)) {
                key.attributes.sign = true;
                key.attributes.verify = true;
            } else {
                key.attributes.encrypt = true;
                key.attributes.decrypt = true;
            }
        }
        key.attributes.label = label;
        key.attributes.type = type;
        key.public_key = std::move(pk);
        key.private_key = std::move(sk);

        std::lock_guard<std::mutex> lock(state_->mutex);
        KeyHandle handle = state_->next_handle++;
        state_->keys[handle] = std::move(key);

        return handle;
    }

    KeyHandle import_key(
        const std::string& algorithm,
        const std::string& label,
        const std::vector<uint8_t>& public_key,
        const std::vector<uint8_t>& private_key) override {

        require_login();

        KeyType type = key_type_from_name(algorithm);

        detail::StoredKey key;
        key.attributes.label = label;
        key.attributes.type = type;
        key.attributes.extractable = !private_key.empty();  // Imported keys can be exported
        key.attributes.sensitive = !private_key.empty();
        if (is_signature_key(type)) {
            key.attributes.sign = !private_key.empty();
            key.attributes.verify = true;
        } else {
            key.attributes.encrypt = true;
            key.attributes.decrypt = !private_key.empty();
        }
        key.public_key = public_key;
        key.private_key = private_key;

        std::lock_guard<std::mutex> lock(state_->mutex);
        KeyHandle handle = state_->next_handle++;
        state_->keys[handle] = std::move(key);

        return handle;
    }

    std::vector<uint8_t> export_public_key(KeyHandle handle) override {
        require_login();

        std::lock_guard<std::mutex> lock(state_->mutex);
        auto it = state_->keys.find(handle);
        if (it == state_->keys.end()) {
            throw HSMError(HSMError::Code::KEY_NOT_FOUND, "Key not found");
        }
        return it->second.public_key;
    }

    std::vector<uint8_t> export_private_key(KeyHandle handle) override {
        require_login();

        std::lock_guard<std::mutex> lock(state_->mutex);
        auto it = state_->keys.find(handle);
        if (it == state_->keys.end()) {
            throw HSMError(HSMError::Code::KEY_NOT_FOUND, "Key not found");
        }
        if (!it->second.attributes.extractable) {
            throw HSMError(HSMError::Code::OPERATION_NOT_SUPPORTED,
                          "Key is not extractable");
        }
        if (it->second.private_key.empty()) {
            throw HSMError(HSMError::Code::KEY_NOT_FOUND, "No private key available");
        }
        return it->second.private_key;
    }

    void delete_key(KeyHandle handle) override {
        require_login();

        std::lock_guard<std::mutex> lock(state_->mutex);
        auto it = state_->keys.find(handle);
        if (it == state_->keys.end()) {
            throw HSMError(HSMError::Code::KEY_NOT_FOUND, "Key not found");
        }

        // Secure erase
        std::memset(it->second.private_key.data(), 0, it->second.private_key.size());
        state_->keys.erase(it);
    }

    std::vector<KeyHandle> find_keys(const std::string& label) override {
        require_login();

        std::vector<KeyHandle> result;
        std::lock_guard<std::mutex> lock(state_->mutex);

        for (const auto& [handle, key] : state_->keys) {
            if (label.empty() || key.attributes.label == label) {
                result.push_back(handle);
            }
        }

        return result;
    }

    KeyInfo get_key_info(KeyHandle handle) override {
        require_login();

        std::lock_guard<std::mutex> lock(state_->mutex);
        auto it = state_->keys.find(handle);
        if (it == state_->keys.end()) {
            throw HSMError(HSMError::Code::KEY_NOT_FOUND, "Key not found");
        }

        KeyInfo info;
        info.handle = handle;
        info.attributes = it->second.attributes;
        info.public_key_size = it->second.public_key.size();
        info.private_key_size = it->second.private_key.size();
        info.has_private_key = !it->second.private_key.empty();

        return info;
    }

    std::vector<uint8_t> sign(
        KeyHandle handle,
        const std::vector<uint8_t>& data) override {

        require_login();

        detail::StoredKey key;
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            auto it = state_->keys.find(handle);
            if (it == state_->keys.end()) {
                throw HSMError(HSMError::Code::KEY_NOT_FOUND, "Key not found");
            }
            key = it->second;
        }

        if (!is_signature_key(key.attributes.type)) {
            throw HSMError(HSMError::Code::KEY_TYPE_MISMATCH,
                          "Key is not a signature key");
        }
        if (!key.attributes.sign) {
            throw HSMError(HSMError::Code::OPERATION_NOT_SUPPORTED,
                          "Key cannot be used for signing");
        }
        if (key.private_key.empty()) {
            throw HSMError(HSMError::Code::KEY_NOT_FOUND,
                          "No private key available for signing");
        }

        std::string algo_name = key_type_to_name(key.attributes.type);
        auto dsa = pqc::create_dsa(algo_name);
        return dsa->sign(key.private_key, data);
    }

    bool verify(
        KeyHandle handle,
        const std::vector<uint8_t>& data,
        const std::vector<uint8_t>& signature) override {

        require_login();

        detail::StoredKey key;
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            auto it = state_->keys.find(handle);
            if (it == state_->keys.end()) {
                throw HSMError(HSMError::Code::KEY_NOT_FOUND, "Key not found");
            }
            key = it->second;
        }

        if (!is_signature_key(key.attributes.type)) {
            throw HSMError(HSMError::Code::KEY_TYPE_MISMATCH,
                          "Key is not a signature key");
        }
        if (!key.attributes.verify) {
            throw HSMError(HSMError::Code::OPERATION_NOT_SUPPORTED,
                          "Key cannot be used for verification");
        }

        std::string algo_name = key_type_to_name(key.attributes.type);
        auto dsa = pqc::create_dsa(algo_name);
        return dsa->verify(key.public_key, data, signature);
    }

    std::vector<uint8_t> encapsulate(
        KeyHandle handle,
        std::vector<uint8_t>& ciphertext) override {

        require_login();

        detail::StoredKey key;
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            auto it = state_->keys.find(handle);
            if (it == state_->keys.end()) {
                throw HSMError(HSMError::Code::KEY_NOT_FOUND, "Key not found");
            }
            key = it->second;
        }

        if (!is_kem_key(key.attributes.type)) {
            throw HSMError(HSMError::Code::KEY_TYPE_MISMATCH,
                          "Key is not a KEM key");
        }
        if (!key.attributes.encrypt) {
            throw HSMError(HSMError::Code::OPERATION_NOT_SUPPORTED,
                          "Key cannot be used for encapsulation");
        }

        std::string algo_name = key_type_to_name(key.attributes.type);
        auto kem = pqc::create_kem(algo_name);
        auto [shared_secret, ct] = kem->encaps(key.public_key);
        ciphertext = std::move(ct);
        return shared_secret;
    }

    std::vector<uint8_t> decapsulate(
        KeyHandle handle,
        const std::vector<uint8_t>& ciphertext) override {

        require_login();

        detail::StoredKey key;
        {
            std::lock_guard<std::mutex> lock(state_->mutex);
            auto it = state_->keys.find(handle);
            if (it == state_->keys.end()) {
                throw HSMError(HSMError::Code::KEY_NOT_FOUND, "Key not found");
            }
            key = it->second;
        }

        if (!is_kem_key(key.attributes.type)) {
            throw HSMError(HSMError::Code::KEY_TYPE_MISMATCH,
                          "Key is not a KEM key");
        }
        if (!key.attributes.decrypt) {
            throw HSMError(HSMError::Code::OPERATION_NOT_SUPPORTED,
                          "Key cannot be used for decapsulation");
        }
        if (key.private_key.empty()) {
            throw HSMError(HSMError::Code::KEY_NOT_FOUND,
                          "No private key available for decapsulation");
        }

        std::string algo_name = key_type_to_name(key.attributes.type);
        auto kem = pqc::create_kem(algo_name);
        return kem->decaps(key.private_key, ciphertext);
    }

    uint32_t slot_id() const override {
        return slot_id_;
    }

private:
    uint32_t slot_id_;
    std::shared_ptr<detail::SoftwareTokenState> state_;
    bool logged_in_;

    void require_login() const {
        if (!logged_in_) {
            throw HSMError(HSMError::Code::SESSION_CLOSED, "Not logged in");
        }
    }
};

/**
 * Software-based HSM provider implementation
 */
class SoftwareProvider : public Provider {
public:
    SoftwareProvider() {
        // Create a single software slot/token
        auto state = std::make_shared<detail::SoftwareTokenState>();
        slots_[0] = state;
    }

    std::string name() const override {
        return "PQC Software Token";
    }

    std::vector<uint32_t> get_slot_list() override {
        std::vector<uint32_t> result;
        for (const auto& [id, _] : slots_) {
            result.push_back(id);
        }
        return result;
    }

    SlotInfo get_slot_info(uint32_t slot_id) override {
        if (slots_.find(slot_id) == slots_.end()) {
            throw HSMError(HSMError::Code::SLOT_NOT_FOUND, "Slot not found");
        }

        SlotInfo info;
        info.description = "PQC Software Slot " + std::to_string(slot_id);
        info.manufacturer = "PQC Library";
        info.token_present = true;
        info.removable = false;
        info.hardware_slot = false;

        return info;
    }

    TokenInfo get_token_info(uint32_t slot_id) override {
        auto it = slots_.find(slot_id);
        if (it == slots_.end()) {
            throw HSMError(HSMError::Code::SLOT_NOT_FOUND, "Slot not found");
        }

        std::lock_guard<std::mutex> lock(it->second->mutex);

        TokenInfo info;
        info.label = it->second->label;
        info.manufacturer = "PQC Library";
        info.model = "Software Token";
        info.serial_number = "SW" + std::to_string(slot_id);
        info.initialized = it->second->initialized;
        info.user_pin_initialized = it->second->user_pin_initialized;
        info.token_present = true;
        info.free_public_memory = SIZE_MAX;
        info.free_private_memory = SIZE_MAX;
        info.total_public_memory = SIZE_MAX;
        info.total_private_memory = SIZE_MAX;

        return info;
    }

    void init_token(
        uint32_t slot_id,
        const std::string& so_pin,
        const std::string& label) override {

        auto it = slots_.find(slot_id);
        if (it == slots_.end()) {
            throw HSMError(HSMError::Code::SLOT_NOT_FOUND, "Slot not found");
        }

        std::lock_guard<std::mutex> lock(it->second->mutex);

        // Clear any existing keys
        for (auto& [handle, key] : it->second->keys) {
            std::memset(key.private_key.data(), 0, key.private_key.size());
        }
        it->second->keys.clear();
        it->second->next_handle = 1;

        it->second->initialized = true;
        it->second->label = label;
        it->second->so_pin = so_pin;
        it->second->user_pin_initialized = false;
    }

    void init_user_pin(
        uint32_t slot_id,
        const std::string& so_pin,
        const std::string& user_pin) override {

        auto it = slots_.find(slot_id);
        if (it == slots_.end()) {
            throw HSMError(HSMError::Code::SLOT_NOT_FOUND, "Slot not found");
        }

        std::lock_guard<std::mutex> lock(it->second->mutex);

        if (!it->second->initialized) {
            throw HSMError(HSMError::Code::TOKEN_NOT_PRESENT, "Token not initialized");
        }
        if (so_pin != it->second->so_pin) {
            throw HSMError(HSMError::Code::PIN_INCORRECT, "Invalid SO PIN");
        }

        it->second->user_pin = user_pin;
        it->second->user_pin_initialized = true;
    }

    std::unique_ptr<Session> open_session(uint32_t slot_id) override {
        auto it = slots_.find(slot_id);
        if (it == slots_.end()) {
            throw HSMError(HSMError::Code::SLOT_NOT_FOUND, "Slot not found");
        }

        return std::make_unique<SoftwareSession>(slot_id, it->second);
    }

private:
    std::map<uint32_t, std::shared_ptr<detail::SoftwareTokenState>> slots_;
};

// ============================================================================
// Factory Functions
// ============================================================================

/**
 * Create a software-based HSM provider
 *
 * This provider stores keys in memory and performs all crypto operations
 * in software. Useful for testing and development.
 */
inline std::unique_ptr<Provider> create_software_provider() {
    return std::make_unique<SoftwareProvider>();
}

/**
 * Get list of available algorithms for key generation
 */
inline std::vector<std::string> available_hsm_algorithms() {
    return {
        // Digital Signatures
        "ML-DSA-44",
        "ML-DSA-65",
        "ML-DSA-87",
        "SLH-DSA-SHA2-128s",
        "SLH-DSA-SHA2-128f",
        "SLH-DSA-SHA2-192s",
        "SLH-DSA-SHA2-192f",
        "SLH-DSA-SHA2-256s",
        "SLH-DSA-SHA2-256f",
        "SLH-DSA-SHAKE-128s",
        "SLH-DSA-SHAKE-128f",
        "SLH-DSA-SHAKE-192s",
        "SLH-DSA-SHAKE-192f",
        "SLH-DSA-SHAKE-256s",
        "SLH-DSA-SHAKE-256f",
        // Key Encapsulation
        "ML-KEM-512",
        "ML-KEM-768",
        "ML-KEM-1024"
    };
}

// ============================================================================
// RAII Session Guard
// ============================================================================

/**
 * RAII guard for HSM sessions
 *
 * Usage:
 *   auto provider = pqc::hsm::create_software_provider();
 *   pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
 *   auto& session = guard.session();
 *   // Use session...
 */
class SessionGuard {
public:
    SessionGuard(std::unique_ptr<Session> session, const std::string& pin)
        : session_(std::move(session)) {
        session_->login(pin);
    }

    ~SessionGuard() {
        if (session_) {
            try { session_->logout(); } catch (...) {}
        }
    }

    // Non-copyable
    SessionGuard(const SessionGuard&) = delete;
    SessionGuard& operator=(const SessionGuard&) = delete;

    // Movable
    SessionGuard(SessionGuard&& other) noexcept
        : session_(std::move(other.session_)) {}

    SessionGuard& operator=(SessionGuard&& other) noexcept {
        if (this != &other) {
            if (session_) {
                try { session_->logout(); } catch (...) {}
            }
            session_ = std::move(other.session_);
        }
        return *this;
    }

    Session& session() { return *session_; }
    const Session& session() const { return *session_; }

private:
    std::unique_ptr<Session> session_;
};

} // namespace pqc::hsm

#endif // PQC_COMMON_HSM_HPP
