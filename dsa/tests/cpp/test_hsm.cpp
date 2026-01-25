/**
 * HSM Integration Tests
 *
 * Tests for the PKCS#11-inspired HSM interface with software token.
 */

#include "common/hsm.hpp"
#include <cassert>
#include <iostream>
#include <vector>

// Test counters
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    void test_##name(); \
    struct TestRunner_##name { \
        TestRunner_##name() { \
            std::cout << "Running: " #name "..." << std::flush; \
            try { \
                test_##name(); \
                std::cout << " PASSED\n"; \
                tests_passed++; \
            } catch (const std::exception& e) { \
                std::cout << " FAILED: " << e.what() << "\n"; \
                tests_failed++; \
            } \
        } \
    } test_runner_##name; \
    void test_##name()

#define ASSERT(cond) \
    do { \
        if (!(cond)) { \
            throw std::runtime_error("Assertion failed: " #cond); \
        } \
    } while(0)

#define ASSERT_EQ(a, b) \
    do { \
        if ((a) != (b)) { \
            throw std::runtime_error("Assertion failed: " #a " == " #b); \
        } \
    } while(0)

#define ASSERT_THROWS(expr, exc_type) \
    do { \
        bool threw = false; \
        try { expr; } catch (const exc_type&) { threw = true; } \
        if (!threw) { \
            throw std::runtime_error("Expected exception: " #exc_type); \
        } \
    } while(0)


// Helper to initialize a provider with default token and PIN
std::unique_ptr<pqc::hsm::Provider> create_initialized_provider() {
    auto provider = pqc::hsm::create_software_provider();
    provider->init_token(0, "so-pin", "Test Token");
    provider->init_user_pin(0, "so-pin", "1234");
    return provider;
}


// ============================================================================
// Provider Tests
// ============================================================================

TEST(create_software_provider) {
    auto provider = pqc::hsm::create_software_provider();
    ASSERT(provider != nullptr);
    ASSERT_EQ(provider->name(), std::string("PQC Software Token"));
}

TEST(provider_slot_list) {
    auto provider = pqc::hsm::create_software_provider();
    auto slots = provider->get_slot_list();
    ASSERT(slots.size() >= 1);
    ASSERT(slots[0] == 0);
}

TEST(provider_slot_info) {
    auto provider = pqc::hsm::create_software_provider();
    auto info = provider->get_slot_info(0);
    ASSERT(!info.description.empty());
    ASSERT(info.token_present);
    ASSERT(!info.hardware_slot);
}

TEST(provider_slot_not_found) {
    auto provider = pqc::hsm::create_software_provider();
    ASSERT_THROWS(provider->get_slot_info(999), pqc::hsm::HSMError);
}

// ============================================================================
// Token Initialization Tests
// ============================================================================

TEST(init_token) {
    auto provider = pqc::hsm::create_software_provider();
    provider->init_token(0, "so-pin", "My Token");

    auto info = provider->get_token_info(0);
    ASSERT(info.initialized);
    ASSERT_EQ(info.label, std::string("My Token"));
    ASSERT(!info.user_pin_initialized);
}

TEST(init_user_pin) {
    auto provider = pqc::hsm::create_software_provider();
    provider->init_token(0, "so-pin", "My Token");
    provider->init_user_pin(0, "so-pin", "user-pin");

    auto info = provider->get_token_info(0);
    ASSERT(info.user_pin_initialized);
}

TEST(init_user_pin_wrong_so_pin) {
    auto provider = pqc::hsm::create_software_provider();
    provider->init_token(0, "so-pin", "My Token");
    ASSERT_THROWS(provider->init_user_pin(0, "wrong-pin", "user-pin"), pqc::hsm::HSMError);
}

// ============================================================================
// Session Tests
// ============================================================================

TEST(open_session) {
    auto provider = create_initialized_provider();
    auto session = provider->open_session(0);
    ASSERT(session != nullptr);
    ASSERT_EQ(session->slot_id(), 0u);
}

TEST(session_login_logout) {
    auto provider = create_initialized_provider();
    auto session = provider->open_session(0);

    ASSERT(!session->is_logged_in());
    session->login("1234");
    ASSERT(session->is_logged_in());
    session->logout();
    ASSERT(!session->is_logged_in());
}

TEST(session_login_wrong_pin) {
    auto provider = create_initialized_provider();
    auto session = provider->open_session(0);
    ASSERT_THROWS(session->login("wrong-pin"), pqc::hsm::HSMError);
}

TEST(session_guard) {
    auto provider = create_initialized_provider();

    {
        pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
        ASSERT(guard.session().is_logged_in());
    }
    // Session should be logged out after guard destruction
}

// ============================================================================
// Key Generation Tests - ML-DSA
// ============================================================================

TEST(generate_mldsa44_keypair) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    auto handle = session.generate_key_pair("ML-DSA-44", "test-key");
    ASSERT(handle > 0);

    auto info = session.get_key_info(handle);
    ASSERT_EQ(info.attributes.label, std::string("test-key"));
    ASSERT(info.has_private_key);
}

TEST(generate_mldsa65_keypair) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    auto handle = session.generate_key_pair("ML-DSA-65", "ml-dsa-65-key");
    auto info = session.get_key_info(handle);
    ASSERT_EQ(info.public_key_size, 1952u);  // ML-DSA-65 public key size
}

TEST(generate_mldsa87_keypair) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    auto handle = session.generate_key_pair("ML-DSA-87", "ml-dsa-87-key");
    auto info = session.get_key_info(handle);
    ASSERT_EQ(info.public_key_size, 2592u);  // ML-DSA-87 public key size
}

// ============================================================================
// Key Generation Tests - SLH-DSA
// ============================================================================

TEST(generate_slhdsa_shake_128f_keypair) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    auto handle = session.generate_key_pair("SLH-DSA-SHAKE-128f", "slh-key");
    auto info = session.get_key_info(handle);
    ASSERT(info.has_private_key);
    ASSERT(info.public_key_size > 0);
}

TEST(generate_slhdsa_sha2_128f_keypair) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    auto handle = session.generate_key_pair("SLH-DSA-SHA2-128f", "slh-sha2-key");
    auto info = session.get_key_info(handle);
    ASSERT(info.has_private_key);
}

// ============================================================================
// Key Generation Tests - ML-KEM
// ============================================================================

TEST(generate_mlkem512_keypair) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    auto handle = session.generate_key_pair("ML-KEM-512", "kem-key");
    auto info = session.get_key_info(handle);
    ASSERT(info.has_private_key);
    ASSERT_EQ(info.public_key_size, 800u);  // ML-KEM-512 encapsulation key size
}

TEST(generate_mlkem768_keypair) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    auto handle = session.generate_key_pair("ML-KEM-768", "kem-768-key");
    auto info = session.get_key_info(handle);
    ASSERT_EQ(info.public_key_size, 1184u);
}

TEST(generate_mlkem1024_keypair) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    auto handle = session.generate_key_pair("ML-KEM-1024", "kem-1024-key");
    auto info = session.get_key_info(handle);
    ASSERT_EQ(info.public_key_size, 1568u);
}

// ============================================================================
// Sign and Verify Tests
// ============================================================================

TEST(sign_verify_mldsa65) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    auto handle = session.generate_key_pair("ML-DSA-65", "signing-key");

    std::vector<uint8_t> message = {1, 2, 3, 4, 5, 6, 7, 8};
    auto signature = session.sign(handle, message);

    ASSERT(!signature.empty());
    ASSERT(session.verify(handle, message, signature));
}

TEST(sign_verify_mldsa44) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    auto handle = session.generate_key_pair("ML-DSA-44", "mldsa44-key");

    std::vector<uint8_t> message = {10, 20, 30, 40, 50};
    auto signature = session.sign(handle, message);
    ASSERT(session.verify(handle, message, signature));
}

TEST(sign_verify_slhdsa) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    auto handle = session.generate_key_pair("SLH-DSA-SHAKE-128f", "slh-signing");

    std::vector<uint8_t> message = {0xDE, 0xAD, 0xBE, 0xEF};
    auto signature = session.sign(handle, message);
    ASSERT(session.verify(handle, message, signature));
}

TEST(verify_tampered_message) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    auto handle = session.generate_key_pair("ML-DSA-65", "key");

    std::vector<uint8_t> message = {1, 2, 3, 4, 5};
    auto signature = session.sign(handle, message);

    std::vector<uint8_t> tampered = {1, 2, 3, 4, 6};
    ASSERT(!session.verify(handle, tampered, signature));
}

TEST(verify_tampered_signature) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    auto handle = session.generate_key_pair("ML-DSA-65", "key");

    std::vector<uint8_t> message = {1, 2, 3, 4, 5};
    auto signature = session.sign(handle, message);

    signature[0] ^= 0xFF;
    ASSERT(!session.verify(handle, message, signature));
}

// ============================================================================
// KEM Tests
// ============================================================================

TEST(encapsulate_decapsulate_mlkem768) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    auto handle = session.generate_key_pair("ML-KEM-768", "kem-key");

    std::vector<uint8_t> ciphertext;
    auto shared_secret1 = session.encapsulate(handle, ciphertext);

    ASSERT(!ciphertext.empty());
    ASSERT_EQ(shared_secret1.size(), 32u);

    auto shared_secret2 = session.decapsulate(handle, ciphertext);
    ASSERT(shared_secret1 == shared_secret2);
}

TEST(encapsulate_decapsulate_mlkem512) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    auto handle = session.generate_key_pair("ML-KEM-512", "kem-512");

    std::vector<uint8_t> ciphertext;
    auto ss1 = session.encapsulate(handle, ciphertext);
    auto ss2 = session.decapsulate(handle, ciphertext);
    ASSERT(ss1 == ss2);
}

TEST(encapsulate_decapsulate_mlkem1024) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    auto handle = session.generate_key_pair("ML-KEM-1024", "kem-1024");

    std::vector<uint8_t> ciphertext;
    auto ss1 = session.encapsulate(handle, ciphertext);
    auto ss2 = session.decapsulate(handle, ciphertext);
    ASSERT(ss1 == ss2);
}

TEST(kem_wrong_key_type) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    // Generate a signature key
    auto handle = session.generate_key_pair("ML-DSA-65", "sig-key");

    // Try to use it for KEM - should fail
    std::vector<uint8_t> ciphertext;
    ASSERT_THROWS(session.encapsulate(handle, ciphertext), pqc::hsm::HSMError);
}

TEST(sign_wrong_key_type) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    // Generate a KEM key
    auto handle = session.generate_key_pair("ML-KEM-768", "kem-key");

    // Try to use it for signing - should fail
    std::vector<uint8_t> message = {1, 2, 3};
    ASSERT_THROWS(session.sign(handle, message), pqc::hsm::HSMError);
}

// ============================================================================
// Key Import/Export Tests
// ============================================================================

TEST(import_public_key_only) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    // Generate a key pair to get valid keys
    auto gen_handle = session.generate_key_pair("ML-DSA-65", "gen-key");
    auto pk = session.export_public_key(gen_handle);

    // Import just the public key
    auto import_handle = session.import_key("ML-DSA-65", "imported-pk", pk);

    auto info = session.get_key_info(import_handle);
    ASSERT(!info.has_private_key);
    ASSERT(info.attributes.verify);
    ASSERT(!info.attributes.sign);
}

TEST(import_keypair) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    // Generate extractable key pair
    pqc::hsm::KeyAttributes attrs;
    attrs.extractable = true;
    auto gen_handle = session.generate_key_pair("ML-DSA-65", "gen-key", &attrs);

    auto pk = session.export_public_key(gen_handle);
    auto sk = session.export_private_key(gen_handle);

    // Import the full key pair
    auto import_handle = session.import_key("ML-DSA-65", "imported-full", pk, sk);

    auto info = session.get_key_info(import_handle);
    ASSERT(info.has_private_key);

    // Should be able to sign with imported key
    std::vector<uint8_t> message = {1, 2, 3};
    auto signature = session.sign(import_handle, message);
    ASSERT(session.verify(import_handle, message, signature));
}

TEST(export_non_extractable_key_fails) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    // Generate non-extractable key (default)
    auto handle = session.generate_key_pair("ML-DSA-65", "non-extractable");

    // Public key export should work
    auto pk = session.export_public_key(handle);
    ASSERT(!pk.empty());

    // Private key export should fail
    ASSERT_THROWS(session.export_private_key(handle), pqc::hsm::HSMError);
}

// ============================================================================
// Key Management Tests
// ============================================================================

TEST(find_keys_by_label) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    session.generate_key_pair("ML-DSA-44", "key-a");
    session.generate_key_pair("ML-DSA-65", "key-b");
    session.generate_key_pair("ML-DSA-87", "key-a");

    auto all_keys = session.find_keys();
    ASSERT_EQ(all_keys.size(), 3u);

    auto keys_a = session.find_keys("key-a");
    ASSERT_EQ(keys_a.size(), 2u);

    auto keys_b = session.find_keys("key-b");
    ASSERT_EQ(keys_b.size(), 1u);

    auto keys_c = session.find_keys("key-c");
    ASSERT_EQ(keys_c.size(), 0u);
}

TEST(delete_key) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    auto handle = session.generate_key_pair("ML-DSA-65", "to-delete");

    auto keys_before = session.find_keys();
    ASSERT_EQ(keys_before.size(), 1u);

    session.delete_key(handle);

    auto keys_after = session.find_keys();
    ASSERT_EQ(keys_after.size(), 0u);
}

TEST(delete_nonexistent_key) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    ASSERT_THROWS(session.delete_key(9999), pqc::hsm::HSMError);
}

// ============================================================================
// Error Handling Tests
// ============================================================================

TEST(operation_without_login) {
    auto provider = create_initialized_provider();
    auto session = provider->open_session(0);

    // Not logged in - should fail
    ASSERT_THROWS(session->generate_key_pair("ML-DSA-65", "key"), pqc::hsm::HSMError);
}

TEST(unknown_algorithm) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    ASSERT_THROWS(session.generate_key_pair("UNKNOWN-ALGO", "key"), pqc::hsm::HSMError);
}

TEST(key_not_found) {
    auto provider = create_initialized_provider();
    pqc::hsm::SessionGuard guard(provider->open_session(0), "1234");
    auto& session = guard.session();

    ASSERT_THROWS(session.get_key_info(9999), pqc::hsm::HSMError);
}

// ============================================================================
// Available Algorithms Test
// ============================================================================

TEST(available_algorithms) {
    auto algorithms = pqc::hsm::available_hsm_algorithms();
    ASSERT(algorithms.size() >= 18);  // 3 ML-DSA + 12 SLH-DSA + 3 ML-KEM

    // Check some specific algorithms
    bool has_mldsa65 = false;
    bool has_mlkem768 = false;
    bool has_slhdsa = false;

    for (const auto& alg : algorithms) {
        if (alg == "ML-DSA-65") has_mldsa65 = true;
        if (alg == "ML-KEM-768") has_mlkem768 = true;
        if (alg == "SLH-DSA-SHAKE-128f") has_slhdsa = true;
    }

    ASSERT(has_mldsa65);
    ASSERT(has_mlkem768);
    ASSERT(has_slhdsa);
}

// ============================================================================
// Multi-Session Tests
// ============================================================================

TEST(multiple_sessions_same_token) {
    auto provider = create_initialized_provider();

    // Open two sessions
    auto session1 = provider->open_session(0);
    auto session2 = provider->open_session(0);

    session1->login("1234");
    session2->login("1234");

    // Generate key in session1
    auto handle = session1->generate_key_pair("ML-DSA-65", "shared-key");

    // Should be visible in session2
    auto keys = session2->find_keys("shared-key");
    ASSERT_EQ(keys.size(), 1u);

    // Sign in session1, verify in session2
    std::vector<uint8_t> message = {1, 2, 3};
    auto signature = session1->sign(handle, message);
    ASSERT(session2->verify(handle, message, signature));
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "=== HSM Integration Tests ===\n\n";

    // Tests run automatically via static initialization

    std::cout << "\n=== Results ===\n";
    std::cout << "Passed: " << tests_passed << "\n";
    std::cout << "Failed: " << tests_failed << "\n";

    return tests_failed == 0 ? 0 : 1;
}
