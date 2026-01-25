/**
 * OpenSSL Provider Tests
 *
 * Tests the OpenSSL 3.x provider integration for PQC algorithms.
 */

#include "common/ossl_provider.hpp"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <string>
#include <functional>
#include <cassert>

using namespace pqc::ossl;

// ============================================================================
// Test Framework
// ============================================================================

struct TestResult {
    std::string name;
    bool passed;
    std::string error;
};

std::vector<TestResult> results;

void run_test(const std::string& name, std::function<void()> test) {
    try {
        test();
        results.push_back({name, true, ""});
        std::cout << "  ✓ " << name << std::endl;
    } catch (const std::exception& e) {
        results.push_back({name, false, e.what()});
        std::cout << "  ✗ " << name << ": " << e.what() << std::endl;
    }
}

// ============================================================================
// Provider Tests
// ============================================================================

void test_provider_creation() {
    auto provider = PQCProvider::create();
    assert(provider != nullptr);
    assert(!provider->is_loaded());
}

void test_provider_load_unload() {
    auto provider = PQCProvider::create();
    assert(!provider->is_loaded());

    provider->load();
    assert(provider->is_loaded());

    provider->unload();
    assert(!provider->is_loaded());
}

void test_provider_name_version() {
    assert(PQCProvider::name() == "pqc");
    assert(PQCProvider::version() == "1.0.0");
}

void test_provider_algorithms_list() {
    auto provider = PQCProvider::create();
    provider->load();

    auto all_algs = provider->algorithms();
    assert(all_algs.size() == 18);  // 3 ML-DSA + 12 SLH-DSA + 3 ML-KEM

    auto sig_algs = provider->signature_algorithms();
    assert(sig_algs.size() == 15);  // 3 ML-DSA + 12 SLH-DSA

    auto kem_algs = provider->kem_algorithms();
    assert(kem_algs.size() == 3);   // 3 ML-KEM
}

void test_provider_has_algorithm() {
    auto provider = PQCProvider::create();
    provider->load();

    assert(provider->has_algorithm("ML-DSA-44"));
    assert(provider->has_algorithm("ML-DSA-65"));
    assert(provider->has_algorithm("ML-DSA-87"));
    assert(provider->has_algorithm("ML-KEM-512"));
    assert(provider->has_algorithm("ML-KEM-768"));
    assert(provider->has_algorithm("ML-KEM-1024"));
    assert(provider->has_algorithm("SLH-DSA-SHAKE-128f"));

    assert(!provider->has_algorithm("UNKNOWN"));
    assert(!provider->has_algorithm("RSA"));
}

void test_algorithm_info_mldsa() {
    auto provider = PQCProvider::create();
    provider->load();

    const auto& info = provider->algorithm_info("ML-DSA-65");
    assert(info.name == "ML-DSA-65");
    assert(info.oid == "2.16.840.1.101.3.4.3.18");
    assert(info.type == AlgorithmType::SIGNATURE);
    assert(info.level == SecurityLevel::LEVEL_3);
    assert(info.public_key_size == 1952);
    assert(info.secret_key_size == 4032);
    assert(info.signature_size == 3309);
}

void test_algorithm_info_mlkem() {
    auto provider = PQCProvider::create();
    provider->load();

    const auto& info = provider->algorithm_info("ML-KEM-768");
    assert(info.name == "ML-KEM-768");
    assert(info.oid == "2.16.840.1.101.3.4.4.2");
    assert(info.type == AlgorithmType::KEM);
    assert(info.level == SecurityLevel::LEVEL_3);
    assert(info.public_key_size == 1184);
    assert(info.secret_key_size == 2400);
    assert(info.ciphertext_size == 1088);
    assert(info.shared_secret_size == 32);
}

void test_algorithm_info_slhdsa() {
    auto provider = PQCProvider::create();
    provider->load();

    const auto& info = provider->algorithm_info("SLH-DSA-SHAKE-256f");
    assert(info.name == "SLH-DSA-SHAKE-256f");
    assert(info.type == AlgorithmType::SIGNATURE);
    assert(info.level == SecurityLevel::LEVEL_5);
}

void test_default_provider() {
    auto& provider = default_provider();
    assert(provider.is_loaded());
    assert(provider.has_algorithm("ML-DSA-65"));
}

// ============================================================================
// Key Context Tests
// ============================================================================

void test_key_context_creation() {
    auto provider = PQCProvider::create();
    provider->load();

    auto key = provider->create_key_context("ML-DSA-65");
    assert(key != nullptr);
    assert(key->algorithm() == "ML-DSA-65");
    assert(key->type() == AlgorithmType::SIGNATURE);
    assert(!key->has_private_key());
}

void test_key_generation_mldsa44() {
    auto key = keygen("ML-DSA-44");
    assert(key->has_private_key());
    assert(key->public_key().size() == 1312);
    assert(key->secret_key().size() == 2560);
}

void test_key_generation_mldsa65() {
    auto key = keygen("ML-DSA-65");
    assert(key->has_private_key());
    assert(key->public_key().size() == 1952);
    assert(key->secret_key().size() == 4032);
}

void test_key_generation_mldsa87() {
    auto key = keygen("ML-DSA-87");
    assert(key->has_private_key());
    assert(key->public_key().size() == 2592);
    assert(key->secret_key().size() == 4896);
}

void test_key_generation_mlkem512() {
    auto key = keygen("ML-KEM-512");
    assert(key->has_private_key());
    assert(key->type() == AlgorithmType::KEM);
    assert(key->public_key().size() == 800);
    assert(key->secret_key().size() == 1632);
}

void test_key_generation_mlkem768() {
    auto key = keygen("ML-KEM-768");
    assert(key->has_private_key());
    assert(key->public_key().size() == 1184);
    assert(key->secret_key().size() == 2400);
}

void test_key_generation_mlkem1024() {
    auto key = keygen("ML-KEM-1024");
    assert(key->has_private_key());
    assert(key->public_key().size() == 1568);
    assert(key->secret_key().size() == 3168);
}

void test_key_import_public() {
    // Generate a key pair
    auto original = keygen("ML-DSA-65");

    // Import only public key
    auto& provider = default_provider();
    auto imported = provider.import_public_key("ML-DSA-65", original->public_key());

    assert(!imported->has_private_key());
    assert(imported->public_key() == original->public_key());
}

void test_key_import_keypair() {
    // Generate a key pair
    auto original = keygen("ML-DSA-65");

    // Import full key pair
    auto& provider = default_provider();
    auto imported = provider.import_keypair("ML-DSA-65",
        original->public_key(), original->secret_key());

    assert(imported->has_private_key());
    assert(imported->public_key() == original->public_key());
    assert(imported->secret_key() == original->secret_key());
}

// ============================================================================
// Signature Tests
// ============================================================================

void test_sign_verify_mldsa44() {
    auto key = keygen("ML-DSA-44");

    std::vector<uint8_t> message = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
    auto signature = sign(key, message);

    assert(signature.size() == 2420);
    assert(verify(key, message, signature));
}

void test_sign_verify_mldsa65() {
    auto key = keygen("ML-DSA-65");

    std::vector<uint8_t> message = {'T', 'e', 's', 't', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'};
    auto signature = sign(key, message);

    assert(signature.size() == 3309);
    assert(verify(key, message, signature));
}

void test_sign_verify_mldsa87() {
    auto key = keygen("ML-DSA-87");

    std::vector<uint8_t> message = {'S', 'e', 'c', 'u', 'r', 'e', ' ', 'd', 'a', 't', 'a'};
    auto signature = sign(key, message);

    assert(signature.size() == 4627);
    assert(verify(key, message, signature));
}

void test_sign_with_context() {
    auto key = keygen("ML-DSA-65");

    std::vector<uint8_t> message = {'M', 'e', 's', 's', 'a', 'g', 'e'};
    std::vector<uint8_t> context = {'a', 'p', 'p', '-', 'c', 'o', 'n', 't', 'e', 'x', 't'};

    auto signature = sign(key, message, context);
    assert(verify(key, message, signature, context));

    // Wrong context should fail
    std::vector<uint8_t> wrong_context = {'w', 'r', 'o', 'n', 'g'};
    assert(!verify(key, message, signature, wrong_context));

    // No context should fail
    assert(!verify(key, message, signature));
}

void test_verify_tampered_message() {
    auto key = keygen("ML-DSA-65");

    std::vector<uint8_t> message = {'O', 'r', 'i', 'g', 'i', 'n', 'a', 'l'};
    auto signature = sign(key, message);

    // Tamper with message
    std::vector<uint8_t> tampered = {'T', 'a', 'm', 'p', 'e', 'r', 'e', 'd'};
    assert(!verify(key, message, signature));  // This should still pass with original
    assert(!verify(key, tampered, signature)); // This should fail
}

void test_verify_tampered_signature() {
    auto key = keygen("ML-DSA-65");

    std::vector<uint8_t> message = {'D', 'a', 't', 'a'};
    auto signature = sign(key, message);

    // Tamper with signature
    signature[0] ^= 0xFF;
    assert(!verify(key, message, signature));
}

void test_verify_wrong_key() {
    auto key1 = keygen("ML-DSA-65");
    auto key2 = keygen("ML-DSA-65");

    std::vector<uint8_t> message = {'T', 'e', 's', 't'};
    auto signature = sign(key1, message);

    // Verify with different key should fail
    assert(!verify(key2, message, signature));
}

void test_verify_public_key_only() {
    auto signer = keygen("ML-DSA-65");
    auto& provider = default_provider();

    // Import only public key for verification
    auto verifier = provider.import_public_key("ML-DSA-65", signer->public_key());

    std::vector<uint8_t> message = {'P', 'u', 'b', 'l', 'i', 'c'};
    auto signature = sign(signer, message);

    // Verification with public key should work
    assert(verify(verifier, message, signature));

    // Signing with public key only should fail
    try {
        sign(verifier, message);
        assert(false);  // Should not reach here
    } catch (const ProviderError& e) {
        assert(e.code() == ProviderError::Code::INVALID_KEY);
    }
}

// ============================================================================
// Sign Context Tests
// ============================================================================

void test_sign_context_incremental() {
    auto key = keygen("ML-DSA-65");
    auto ctx = default_provider().create_sign_context();

    // Sign incrementally
    ctx->init_sign(key);
    std::vector<uint8_t> part1 = {'H', 'e', 'l', 'l', 'o'};
    std::vector<uint8_t> part2 = {' '};
    std::vector<uint8_t> part3 = {'W', 'o', 'r', 'l', 'd'};
    ctx->update(part1);
    ctx->update(part2);
    ctx->update(part3);
    auto signature = ctx->sign_final();

    // Verify incrementally
    ctx->init_verify(key);
    ctx->update(part1);
    ctx->update(part2);
    ctx->update(part3);
    assert(ctx->verify_final(signature));
}

void test_sign_context_one_shot() {
    auto key = keygen("ML-DSA-65");
    auto ctx = default_provider().create_sign_context();

    std::vector<uint8_t> message = {'O', 'n', 'e', ' ', 's', 'h', 'o', 't'};
    auto signature = ctx->sign(key, message);
    assert(ctx->verify(key, message, signature));
}

void test_sign_context_with_context_string() {
    auto key = keygen("ML-DSA-65");
    auto ctx = default_provider().create_sign_context();

    std::vector<uint8_t> message = {'D', 'a', 't', 'a'};
    std::vector<uint8_t> context_str = {'c', 't', 'x'};

    auto signature = ctx->sign(key, message, context_str);
    assert(ctx->verify(key, message, signature, context_str));
}

// ============================================================================
// KEM Tests
// ============================================================================

void test_kem_encaps_decaps_512() {
    auto key = keygen("ML-KEM-512");

    auto [ciphertext, shared_secret1] = encapsulate(key);
    assert(ciphertext.size() == 768);
    assert(shared_secret1.size() == 32);

    auto shared_secret2 = decapsulate(key, ciphertext);
    assert(shared_secret2.size() == 32);
    assert(shared_secret1 == shared_secret2);
}

void test_kem_encaps_decaps_768() {
    auto key = keygen("ML-KEM-768");

    auto [ciphertext, shared_secret1] = encapsulate(key);
    assert(ciphertext.size() == 1088);
    assert(shared_secret1.size() == 32);

    auto shared_secret2 = decapsulate(key, ciphertext);
    assert(shared_secret1 == shared_secret2);
}

void test_kem_encaps_decaps_1024() {
    auto key = keygen("ML-KEM-1024");

    auto [ciphertext, shared_secret1] = encapsulate(key);
    assert(ciphertext.size() == 1568);
    assert(shared_secret1.size() == 32);

    auto shared_secret2 = decapsulate(key, ciphertext);
    assert(shared_secret1 == shared_secret2);
}

void test_kem_context() {
    auto key = keygen("ML-KEM-768");
    auto ctx = default_provider().create_kem_context();

    // Encapsulation
    ctx->init_encaps(key);
    auto [ct, ss1] = ctx->encapsulate();

    // Decapsulation
    ctx->init_decaps(key);
    auto ss2 = ctx->decapsulate(ct);

    assert(ss1 == ss2);
}

void test_kem_public_key_encaps() {
    auto keypair = keygen("ML-KEM-768");
    auto& provider = default_provider();

    // Import only public key
    auto public_only = provider.import_public_key("ML-KEM-768", keypair->public_key());

    // Encapsulation with public key should work
    auto [ct, ss1] = encapsulate(public_only);

    // Decapsulation with full keypair
    auto ss2 = decapsulate(keypair, ct);
    assert(ss1 == ss2);

    // Decapsulation with public key only should fail
    try {
        decapsulate(public_only, ct);
        assert(false);
    } catch (const ProviderError& e) {
        assert(e.code() == ProviderError::Code::INVALID_KEY);
    }
}

// ============================================================================
// SLH-DSA Tests
// ============================================================================

void test_slhdsa_shake_128f() {
    auto key = keygen("SLH-DSA-SHAKE-128f");
    assert(key->has_private_key());

    std::vector<uint8_t> message = {'S', 'L', 'H', '-', 'D', 'S', 'A'};
    auto signature = sign(key, message);

    assert(signature.size() == 17088);
    assert(verify(key, message, signature));
}

void test_slhdsa_sha2_256s() {
    auto key = keygen("SLH-DSA-SHA2-256s");
    assert(key->has_private_key());

    std::vector<uint8_t> message = {'L', 'e', 'v', 'e', 'l', '5'};
    auto signature = sign(key, message);

    assert(signature.size() == 29792);
    assert(verify(key, message, signature));
}

// ============================================================================
// Name Mapping Tests
// ============================================================================

void test_to_provider_name() {
    assert(to_provider_name("mldsa44") == "ML-DSA-44");
    assert(to_provider_name("mldsa65") == "ML-DSA-65");
    assert(to_provider_name("mldsa87") == "ML-DSA-87");
    assert(to_provider_name("mlkem512") == "ML-KEM-512");
    assert(to_provider_name("mlkem768") == "ML-KEM-768");
    assert(to_provider_name("mlkem1024") == "ML-KEM-1024");
    assert(to_provider_name("slh-shake-128f") == "SLH-DSA-SHAKE-128f");
    assert(to_provider_name("slh-sha2-256s") == "SLH-DSA-SHA2-256s");
}

void test_from_provider_name() {
    assert(from_provider_name("ML-DSA-44") == "ML-DSA-44");
    assert(from_provider_name("ML-DSA-65") == "ML-DSA-65");
    assert(from_provider_name("ML-KEM-768") == "ML-KEM-768");
    assert(from_provider_name("SLH-DSA-SHAKE-128f") == "slh-shake-128f");
    assert(from_provider_name("SLH-DSA-SHA2-256s") == "slh-sha2-256s");
}

// ============================================================================
// Error Handling Tests
// ============================================================================

void test_error_provider_not_loaded() {
    auto provider = PQCProvider::create();
    // Don't load it

    try {
        provider->create_key_context("ML-DSA-65");
        assert(false);
    } catch (const ProviderError& e) {
        assert(e.code() == ProviderError::Code::PROVIDER_NOT_LOADED);
    }
}

void test_error_algorithm_not_found() {
    try {
        keygen("UNKNOWN-ALG");
        assert(false);
    } catch (const ProviderError& e) {
        assert(e.code() == ProviderError::Code::ALGORITHM_NOT_FOUND);
    }
}

void test_error_sign_without_private_key() {
    auto keypair = keygen("ML-DSA-65");
    auto& provider = default_provider();
    auto public_only = provider.import_public_key("ML-DSA-65", keypair->public_key());

    std::vector<uint8_t> message = {'t', 'e', 's', 't'};
    try {
        sign(public_only, message);
        assert(false);
    } catch (const ProviderError& e) {
        assert(e.code() == ProviderError::Code::INVALID_KEY);
    }
}

void test_error_kem_on_signature_key() {
    auto key = keygen("ML-DSA-65");

    try {
        encapsulate(key);
        assert(false);
    } catch (const ProviderError& e) {
        assert(e.code() == ProviderError::Code::OPERATION_NOT_SUPPORTED);
    }
}

void test_error_sign_on_kem_key() {
    auto key = keygen("ML-KEM-768");

    std::vector<uint8_t> message = {'t', 'e', 's', 't'};
    try {
        sign(key, message);
        assert(false);
    } catch (const ProviderError& e) {
        assert(e.code() == ProviderError::Code::OPERATION_NOT_SUPPORTED);
    }
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "=== OpenSSL Provider Tests ===" << std::endl;
    std::cout << std::endl;

    // Provider tests
    std::cout << "Provider Management:" << std::endl;
    run_test("Provider creation", test_provider_creation);
    run_test("Provider load/unload", test_provider_load_unload);
    run_test("Provider name and version", test_provider_name_version);
    run_test("Algorithms list", test_provider_algorithms_list);
    run_test("Has algorithm", test_provider_has_algorithm);
    run_test("Algorithm info - ML-DSA", test_algorithm_info_mldsa);
    run_test("Algorithm info - ML-KEM", test_algorithm_info_mlkem);
    run_test("Algorithm info - SLH-DSA", test_algorithm_info_slhdsa);
    run_test("Default provider", test_default_provider);
    std::cout << std::endl;

    // Key context tests
    std::cout << "Key Context:" << std::endl;
    run_test("Key context creation", test_key_context_creation);
    run_test("Key generation - ML-DSA-44", test_key_generation_mldsa44);
    run_test("Key generation - ML-DSA-65", test_key_generation_mldsa65);
    run_test("Key generation - ML-DSA-87", test_key_generation_mldsa87);
    run_test("Key generation - ML-KEM-512", test_key_generation_mlkem512);
    run_test("Key generation - ML-KEM-768", test_key_generation_mlkem768);
    run_test("Key generation - ML-KEM-1024", test_key_generation_mlkem1024);
    run_test("Import public key", test_key_import_public);
    run_test("Import key pair", test_key_import_keypair);
    std::cout << std::endl;

    // Signature tests
    std::cout << "Digital Signatures:" << std::endl;
    run_test("Sign/verify - ML-DSA-44", test_sign_verify_mldsa44);
    run_test("Sign/verify - ML-DSA-65", test_sign_verify_mldsa65);
    run_test("Sign/verify - ML-DSA-87", test_sign_verify_mldsa87);
    run_test("Sign with context", test_sign_with_context);
    run_test("Verify tampered message", test_verify_tampered_message);
    run_test("Verify tampered signature", test_verify_tampered_signature);
    run_test("Verify wrong key", test_verify_wrong_key);
    run_test("Verify public key only", test_verify_public_key_only);
    std::cout << std::endl;

    // Sign context tests
    std::cout << "Sign Context:" << std::endl;
    run_test("Incremental sign/verify", test_sign_context_incremental);
    run_test("One-shot sign/verify", test_sign_context_one_shot);
    run_test("Sign context with context string", test_sign_context_with_context_string);
    std::cout << std::endl;

    // KEM tests
    std::cout << "Key Encapsulation:" << std::endl;
    run_test("Encaps/decaps - ML-KEM-512", test_kem_encaps_decaps_512);
    run_test("Encaps/decaps - ML-KEM-768", test_kem_encaps_decaps_768);
    run_test("Encaps/decaps - ML-KEM-1024", test_kem_encaps_decaps_1024);
    run_test("KEM context", test_kem_context);
    run_test("KEM public key encaps", test_kem_public_key_encaps);
    std::cout << std::endl;

    // SLH-DSA tests
    std::cout << "SLH-DSA:" << std::endl;
    run_test("SLH-DSA-SHAKE-128f", test_slhdsa_shake_128f);
    run_test("SLH-DSA-SHA2-256s", test_slhdsa_sha2_256s);
    std::cout << std::endl;

    // Name mapping tests
    std::cout << "Name Mapping:" << std::endl;
    run_test("To provider name", test_to_provider_name);
    run_test("From provider name", test_from_provider_name);
    std::cout << std::endl;

    // Error handling tests
    std::cout << "Error Handling:" << std::endl;
    run_test("Error - provider not loaded", test_error_provider_not_loaded);
    run_test("Error - algorithm not found", test_error_algorithm_not_found);
    run_test("Error - sign without private key", test_error_sign_without_private_key);
    run_test("Error - KEM on signature key", test_error_kem_on_signature_key);
    run_test("Error - sign on KEM key", test_error_sign_on_kem_key);
    std::cout << std::endl;

    // Summary
    int passed = 0, failed = 0;
    for (const auto& r : results) {
        if (r.passed) passed++;
        else failed++;
    }

    std::cout << "=== Summary ===" << std::endl;
    std::cout << "Passed: " << passed << "/" << (passed + failed) << std::endl;

    if (failed > 0) {
        std::cout << std::endl << "Failed tests:" << std::endl;
        for (const auto& r : results) {
            if (!r.passed) {
                std::cout << "  - " << r.name << ": " << r.error << std::endl;
            }
        }
        return 1;
    }

    std::cout << std::endl << "All tests passed!" << std::endl;
    return 0;
}
