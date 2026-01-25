/**
 * Runtime Algorithm Selection Tests
 *
 * Tests for the factory pattern that enables runtime algorithm selection
 * across ML-DSA, SLH-DSA, and ML-KEM parameter sets.
 */

#include <iostream>
#include <cassert>
#include <cstring>
#include "common/algorithm_factory.hpp"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    std::cout << "  Testing " << name << "..." << std::flush; \
    try {

#define TEST_END(name) \
        std::cout << " [PASS]" << std::endl; \
        tests_passed++; \
    } catch (const std::exception& e) { \
        std::cout << " [FAIL] " << e.what() << std::endl; \
        tests_failed++; \
    }

#define ASSERT(cond) \
    if (!(cond)) { \
        throw std::runtime_error("Assertion failed: " #cond); \
    }

// =============================================================================
// Algorithm Listing Tests
// =============================================================================

void test_algorithm_listing() {
    std::cout << "\n=== Algorithm Listing Tests ===" << std::endl;

    TEST("Available DSA algorithms")
    {
        auto algos = pqc::available_dsa_algorithms();
        ASSERT(algos.size() == 15);  // 3 ML-DSA + 12 SLH-DSA

        // Verify ML-DSA entries
        ASSERT(algos[0] == "ML-DSA-44");
        ASSERT(algos[1] == "ML-DSA-65");
        ASSERT(algos[2] == "ML-DSA-87");

        // Verify some SLH-DSA entries
        ASSERT(algos[3] == "SLH-DSA-SHA2-128s");
        ASSERT(algos[14] == "SLH-DSA-SHAKE-256f");

        std::cout << " (" << algos.size() << " algorithms)";
    }
    TEST_END("Available DSA algorithms")

    TEST("Available KEM algorithms")
    {
        auto algos = pqc::available_kem_algorithms();
        ASSERT(algos.size() == 3);
        ASSERT(algos[0] == "ML-KEM-512");
        ASSERT(algos[1] == "ML-KEM-768");
        ASSERT(algos[2] == "ML-KEM-1024");
    }
    TEST_END("Available KEM algorithms")

    TEST("Algorithm name validation")
    {
        ASSERT(pqc::is_dsa_algorithm("ML-DSA-65"));
        ASSERT(pqc::is_dsa_algorithm("SLH-DSA-SHA2-128s"));
        ASSERT(!pqc::is_dsa_algorithm("ML-KEM-768"));
        ASSERT(!pqc::is_dsa_algorithm("invalid"));

        ASSERT(pqc::is_kem_algorithm("ML-KEM-768"));
        ASSERT(!pqc::is_kem_algorithm("ML-DSA-65"));
        ASSERT(!pqc::is_kem_algorithm("invalid"));
    }
    TEST_END("Algorithm name validation")
}

// =============================================================================
// ML-DSA Factory Tests
// =============================================================================

void test_mldsa_factory() {
    std::cout << "\n=== ML-DSA Factory Tests ===" << std::endl;

    TEST("ML-DSA-44 via factory")
    {
        auto dsa = pqc::create_dsa("ML-DSA-44");
        ASSERT(dsa->name() == "ML-DSA-44");
        ASSERT(dsa->standard() == "FIPS 204");
        ASSERT(dsa->public_key_size() == 1312);
        ASSERT(dsa->signature_size() == 2420);

        auto [pk, sk] = dsa->keygen();
        ASSERT(pk.size() == dsa->public_key_size());
        ASSERT(sk.size() == dsa->secret_key_size());

        std::vector<uint8_t> msg = {'h', 'e', 'l', 'l', 'o'};
        auto sig = dsa->sign(sk, msg);
        ASSERT(!sig.empty());
        ASSERT(dsa->verify(pk, msg, sig));
    }
    TEST_END("ML-DSA-44 via factory")

    TEST("ML-DSA-65 via factory")
    {
        auto dsa = pqc::create_dsa("ML-DSA-65");
        ASSERT(dsa->name() == "ML-DSA-65");
        ASSERT(dsa->public_key_size() == 1952);

        auto [pk, sk] = dsa->keygen();
        std::vector<uint8_t> msg = {'t', 'e', 's', 't'};
        auto sig = dsa->sign(sk, msg);
        ASSERT(dsa->verify(pk, msg, sig));

        // Wrong message should fail
        std::vector<uint8_t> wrong_msg = {'f', 'a', 'k', 'e'};
        ASSERT(!dsa->verify(pk, wrong_msg, sig));
    }
    TEST_END("ML-DSA-65 via factory")

    TEST("ML-DSA-87 via factory")
    {
        auto dsa = pqc::create_dsa("ML-DSA-87");
        ASSERT(dsa->name() == "ML-DSA-87");
        ASSERT(dsa->public_key_size() == 2592);
        ASSERT(dsa->signature_size() == 4627);

        auto [pk, sk] = dsa->keygen();
        std::vector<uint8_t> msg = {'t', 'e', 's', 't'};
        auto sig = dsa->sign(sk, msg);
        ASSERT(dsa->verify(pk, msg, sig));
    }
    TEST_END("ML-DSA-87 via factory")
}

// =============================================================================
// SLH-DSA Factory Tests
// =============================================================================

void test_slhdsa_factory() {
    std::cout << "\n=== SLH-DSA Factory Tests ===" << std::endl;

    TEST("SLH-DSA-SHA2-128s via factory")
    {
        auto dsa = pqc::create_dsa("SLH-DSA-SHA2-128s");
        ASSERT(dsa->name() == "SLH-DSA-SHA2-128s");
        ASSERT(dsa->standard() == "FIPS 205");
        ASSERT(dsa->public_key_size() == 32);   // 2*n, n=16
        ASSERT(dsa->secret_key_size() == 64);    // 4*n, n=16

        auto [pk, sk] = dsa->keygen();
        ASSERT(pk.size() == dsa->public_key_size());
        ASSERT(sk.size() == dsa->secret_key_size());

        std::vector<uint8_t> msg = {'t', 'e', 's', 't'};
        auto sig = dsa->sign(sk, msg);
        ASSERT(!sig.empty());
        ASSERT(dsa->verify(pk, msg, sig));
    }
    TEST_END("SLH-DSA-SHA2-128s via factory")

    TEST("SLH-DSA-SHAKE-128f via factory")
    {
        auto dsa = pqc::create_dsa("SLH-DSA-SHAKE-128f");
        ASSERT(dsa->name() == "SLH-DSA-SHAKE-128f");
        ASSERT(dsa->public_key_size() == 32);

        auto [pk, sk] = dsa->keygen();
        std::vector<uint8_t> msg = {'h', 'e', 'l', 'l', 'o'};
        auto sig = dsa->sign(sk, msg);
        ASSERT(dsa->verify(pk, msg, sig));
    }
    TEST_END("SLH-DSA-SHAKE-128f via factory")

    TEST("SLH-DSA keygen returns (pk, sk) normalized")
    {
        // Verify that factory normalizes return order
        auto dsa = pqc::create_dsa("SLH-DSA-SHA2-128s");
        auto [pk, sk] = dsa->keygen();

        // pk should be 2*n = 32 bytes, sk should be 4*n = 64 bytes
        ASSERT(pk.size() == 32);
        ASSERT(sk.size() == 64);

        // Verify the key pair works for sign/verify
        std::vector<uint8_t> msg = {'t', 'e', 's', 't'};
        auto sig = dsa->sign(sk, msg);
        ASSERT(dsa->verify(pk, msg, sig));
    }
    TEST_END("SLH-DSA keygen returns (pk, sk) normalized")
}

// =============================================================================
// ML-KEM Factory Tests
// =============================================================================

void test_mlkem_factory() {
    std::cout << "\n=== ML-KEM Factory Tests ===" << std::endl;

    TEST("ML-KEM-512 via factory")
    {
        auto kem = pqc::create_kem("ML-KEM-512");
        ASSERT(kem->name() == "ML-KEM-512");
        ASSERT(kem->standard() == "FIPS 203");
        ASSERT(kem->encapsulation_key_size() == 800);
        ASSERT(kem->ciphertext_size() == 768);
        ASSERT(kem->shared_secret_size() == 32);

        auto [ek, dk] = kem->keygen();
        ASSERT(ek.size() == kem->encapsulation_key_size());
        ASSERT(dk.size() == kem->decapsulation_key_size());

        auto [K1, ct] = kem->encaps(ek);
        ASSERT(K1.size() == 32);
        ASSERT(ct.size() == kem->ciphertext_size());

        auto K2 = kem->decaps(dk, ct);
        ASSERT(K1 == K2);
    }
    TEST_END("ML-KEM-512 via factory")

    TEST("ML-KEM-768 via factory")
    {
        auto kem = pqc::create_kem("ML-KEM-768");
        ASSERT(kem->name() == "ML-KEM-768");
        ASSERT(kem->encapsulation_key_size() == 1184);
        ASSERT(kem->ciphertext_size() == 1088);

        auto [ek, dk] = kem->keygen();
        auto [K1, ct] = kem->encaps(ek);
        auto K2 = kem->decaps(dk, ct);
        ASSERT(K1 == K2);
    }
    TEST_END("ML-KEM-768 via factory")

    TEST("ML-KEM-1024 via factory")
    {
        auto kem = pqc::create_kem("ML-KEM-1024");
        ASSERT(kem->name() == "ML-KEM-1024");
        ASSERT(kem->encapsulation_key_size() == 1568);

        auto [ek, dk] = kem->keygen();
        auto [K1, ct] = kem->encaps(ek);
        auto K2 = kem->decaps(dk, ct);
        ASSERT(K1 == K2);
    }
    TEST_END("ML-KEM-1024 via factory")
}

// =============================================================================
// Polymorphism Tests
// =============================================================================

void test_polymorphism() {
    std::cout << "\n=== Polymorphism Tests ===" << std::endl;

    TEST("Iterate over all DSA algorithms")
    {
        auto algos = pqc::available_dsa_algorithms();
        // Test only ML-DSA and one SLH-DSA variant (the rest are slow)
        std::vector<std::string> test_algos = {
            "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
            "SLH-DSA-SHA2-128s"
        };

        for (const auto& name : test_algos) {
            auto dsa = pqc::create_dsa(name);
            ASSERT(dsa->name() == name);

            auto [pk, sk] = dsa->keygen();
            ASSERT(pk.size() == dsa->public_key_size());
            ASSERT(sk.size() == dsa->secret_key_size());

            std::vector<uint8_t> msg = {'d', 'a', 't', 'a'};
            auto sig = dsa->sign(sk, msg);
            ASSERT(dsa->verify(pk, msg, sig));
        }
    }
    TEST_END("Iterate over all DSA algorithms")

    TEST("Iterate over all KEM algorithms")
    {
        for (const auto& name : pqc::available_kem_algorithms()) {
            auto kem = pqc::create_kem(name);
            ASSERT(kem->name() == name);

            auto [ek, dk] = kem->keygen();
            ASSERT(ek.size() == kem->encapsulation_key_size());
            ASSERT(dk.size() == kem->decapsulation_key_size());

            auto [K1, ct] = kem->encaps(ek);
            ASSERT(ct.size() == kem->ciphertext_size());

            auto K2 = kem->decaps(dk, ct);
            ASSERT(K1 == K2);
        }
    }
    TEST_END("Iterate over all KEM algorithms")

    TEST("Store heterogeneous DSA algorithms in vector")
    {
        std::vector<std::unique_ptr<pqc::DigitalSignature>> signers;
        signers.push_back(pqc::create_dsa("ML-DSA-44"));
        signers.push_back(pqc::create_dsa("ML-DSA-65"));
        signers.push_back(pqc::create_dsa("SLH-DSA-SHA2-128s"));

        std::vector<uint8_t> msg = {'d', 'a', 't', 'a'};

        for (const auto& dsa : signers) {
            auto [pk, sk] = dsa->keygen();
            auto sig = dsa->sign(sk, msg);
            ASSERT(dsa->verify(pk, msg, sig));
        }
    }
    TEST_END("Store heterogeneous DSA algorithms in vector")
}

// =============================================================================
// Error Handling Tests
// =============================================================================

void test_error_handling() {
    std::cout << "\n=== Error Handling Tests ===" << std::endl;

    TEST("Unknown DSA algorithm throws")
    {
        bool threw = false;
        try {
            auto dsa = pqc::create_dsa("invalid-algorithm");
        } catch (const std::invalid_argument& e) {
            threw = true;
            std::string msg = e.what();
            ASSERT(msg.find("invalid-algorithm") != std::string::npos);
        }
        ASSERT(threw);
    }
    TEST_END("Unknown DSA algorithm throws")

    TEST("Unknown KEM algorithm throws")
    {
        bool threw = false;
        try {
            auto kem = pqc::create_kem("ML-KEM-256");
        } catch (const std::invalid_argument& e) {
            threw = true;
        }
        ASSERT(threw);
    }
    TEST_END("Unknown KEM algorithm throws")

    TEST("Case sensitivity")
    {
        bool threw = false;
        try {
            auto dsa = pqc::create_dsa("ml-dsa-44");  // Wrong case
        } catch (const std::invalid_argument&) {
            threw = true;
        }
        ASSERT(threw);
    }
    TEST_END("Case sensitivity")
}

// =============================================================================
// Size Metadata Tests
// =============================================================================

void test_size_metadata() {
    std::cout << "\n=== Size Metadata Tests ===" << std::endl;

    TEST("ML-DSA key/signature sizes")
    {
        auto dsa44 = pqc::create_dsa("ML-DSA-44");
        auto dsa65 = pqc::create_dsa("ML-DSA-65");
        auto dsa87 = pqc::create_dsa("ML-DSA-87");

        // Verify published sizes from FIPS 204
        ASSERT(dsa44->public_key_size() == 1312);
        ASSERT(dsa44->secret_key_size() == 2560);
        ASSERT(dsa44->signature_size() == 2420);

        ASSERT(dsa65->public_key_size() == 1952);
        ASSERT(dsa65->secret_key_size() == 4032);
        ASSERT(dsa65->signature_size() == 3309);

        ASSERT(dsa87->public_key_size() == 2592);
        ASSERT(dsa87->secret_key_size() == 4896);
        ASSERT(dsa87->signature_size() == 4627);
    }
    TEST_END("ML-DSA key/signature sizes")

    TEST("ML-KEM key/ciphertext sizes")
    {
        auto kem512 = pqc::create_kem("ML-KEM-512");
        auto kem768 = pqc::create_kem("ML-KEM-768");
        auto kem1024 = pqc::create_kem("ML-KEM-1024");

        // Verify published sizes from FIPS 203
        ASSERT(kem512->encapsulation_key_size() == 800);
        ASSERT(kem512->decapsulation_key_size() == 1632);
        ASSERT(kem512->ciphertext_size() == 768);
        ASSERT(kem512->shared_secret_size() == 32);

        ASSERT(kem768->encapsulation_key_size() == 1184);
        ASSERT(kem768->decapsulation_key_size() == 2400);
        ASSERT(kem768->ciphertext_size() == 1088);

        ASSERT(kem1024->encapsulation_key_size() == 1568);
        ASSERT(kem1024->decapsulation_key_size() == 3168);
        ASSERT(kem1024->ciphertext_size() == 1568);
    }
    TEST_END("ML-KEM key/ciphertext sizes")

    TEST("Print algorithm summary")
    {
        std::cout << std::endl;
        std::cout << "  Available DSA algorithms:" << std::endl;
        for (const auto& name : pqc::available_dsa_algorithms()) {
            auto dsa = pqc::create_dsa(name);
            std::cout << "    " << dsa->name()
                      << " (" << dsa->standard() << ")"
                      << " pk=" << dsa->public_key_size()
                      << " sk=" << dsa->secret_key_size()
                      << " sig=" << dsa->signature_size()
                      << std::endl;
        }

        std::cout << "  Available KEM algorithms:" << std::endl;
        for (const auto& name : pqc::available_kem_algorithms()) {
            auto kem = pqc::create_kem(name);
            std::cout << "    " << kem->name()
                      << " (" << kem->standard() << ")"
                      << " ek=" << kem->encapsulation_key_size()
                      << " dk=" << kem->decapsulation_key_size()
                      << " ct=" << kem->ciphertext_size()
                      << std::endl;
        }
    }
    TEST_END("Print algorithm summary")
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  Runtime Algorithm Selection Tests" << std::endl;
    std::cout << "========================================" << std::endl;

    test_algorithm_listing();
    test_mldsa_factory();
    test_slhdsa_factory();
    test_mlkem_factory();
    test_polymorphism();
    test_error_handling();
    test_size_metadata();

    std::cout << "\n========================================" << std::endl;
    std::cout << "  Results: " << tests_passed << " passed, "
              << tests_failed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
