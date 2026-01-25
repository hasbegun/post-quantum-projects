/**
 * JOSE/COSE Support Tests
 *
 * Tests for JWS (JSON Web Signature) and COSE_Sign1 with PQC algorithms.
 */

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "../../src/cpp/common/jose.hpp"
#include "../../src/cpp/common/cose.hpp"

// Simple test framework
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    void name(); \
    struct name##_registrar { \
        name##_registrar() { \
            std::cout << "Running " << #name << "... "; \
            tests_run++; \
            try { \
                name(); \
                std::cout << "PASSED" << std::endl; \
                tests_passed++; \
            } catch (const std::exception& e) { \
                std::cout << "FAILED: " << e.what() << std::endl; \
                tests_failed++; \
            } catch (...) { \
                std::cout << "FAILED: unknown exception" << std::endl; \
                tests_failed++; \
            } \
        } \
    } name##_instance; \
    void name()

#define ASSERT(cond) \
    do { \
        if (!(cond)) { \
            throw std::runtime_error("Assertion failed: " #cond); \
        } \
    } while(0)

#define ASSERT_EQ(a, b) \
    do { \
        if ((a) != (b)) { \
            std::ostringstream oss; \
            oss << "Assertion failed: " << #a << " == " << #b; \
            throw std::runtime_error(oss.str()); \
        } \
    } while(0)

// ============================================================================
// Base64url Tests
// ============================================================================

TEST(test_base64url_encode_empty) {
    std::vector<uint8_t> data;
    std::string encoded = jose::detail::base64url_encode(data);
    ASSERT_EQ(encoded, "");
}

TEST(test_base64url_encode_single_byte) {
    std::vector<uint8_t> data = {0x00};
    std::string encoded = jose::detail::base64url_encode(data);
    ASSERT_EQ(encoded, "AA");  // No padding in base64url
}

TEST(test_base64url_encode_hello) {
    std::string text = "Hello";
    std::string encoded = jose::detail::base64url_encode(text);
    ASSERT_EQ(encoded, "SGVsbG8");  // No padding
}

TEST(test_base64url_decode_roundtrip) {
    std::vector<uint8_t> original = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    std::string encoded = jose::detail::base64url_encode(original);
    auto decoded = jose::detail::base64url_decode(encoded);
    ASSERT(decoded.has_value());
    ASSERT_EQ(*decoded, original);
}

TEST(test_base64url_url_safe_chars) {
    // Test that + and / are replaced with - and _
    std::vector<uint8_t> data = {0xFB, 0xF0, 0x3F, 0xFF};  // Would produce +/ in standard base64
    std::string encoded = jose::detail::base64url_encode(data);
    ASSERT(encoded.find('+') == std::string::npos);
    ASSERT(encoded.find('/') == std::string::npos);
}

// ============================================================================
// JSON Utilities Tests
// ============================================================================

TEST(test_json_escape) {
    ASSERT_EQ(jose::json::escape("hello"), "hello");
    ASSERT_EQ(jose::json::escape("hel\"lo"), "hel\\\"lo");
    ASSERT_EQ(jose::json::escape("hel\\lo"), "hel\\\\lo");
    ASSERT_EQ(jose::json::escape("line1\nline2"), "line1\\nline2");
}

TEST(test_json_build_object) {
    std::map<std::string, std::string> values = {
        {"alg", "ML-DSA-65"},
        {"typ", "JWT"}
    };
    std::string json = jose::json::build_object(values);
    ASSERT(json.find("\"alg\":\"ML-DSA-65\"") != std::string::npos);
    ASSERT(json.find("\"typ\":\"JWT\"") != std::string::npos);
}

TEST(test_json_extract_string) {
    std::string json = R"({"alg":"ML-DSA-65","typ":"JWT"})";
    auto alg = jose::json::extract_string(json, "alg");
    ASSERT(alg.has_value());
    ASSERT_EQ(*alg, "ML-DSA-65");

    auto typ = jose::json::extract_string(json, "typ");
    ASSERT(typ.has_value());
    ASSERT_EQ(*typ, "JWT");

    auto missing = jose::json::extract_string(json, "kid");
    ASSERT(!missing.has_value());
}

// ============================================================================
// JWS Header Tests
// ============================================================================

TEST(test_jws_header_to_json) {
    jose::JWSHeader header;
    header.alg = "ML-DSA-65";
    header.typ = "JWT";

    std::string json = header.to_json();
    ASSERT(json.find("\"alg\":\"ML-DSA-65\"") != std::string::npos);
    ASSERT(json.find("\"typ\":\"JWT\"") != std::string::npos);
}

TEST(test_jws_header_from_json) {
    std::string json = R"({"alg":"ML-DSA-87","typ":"JWT","kid":"key-1"})";
    auto header = jose::JWSHeader::from_json(json);
    ASSERT(header.has_value());
    ASSERT_EQ(header->alg, "ML-DSA-87");
    ASSERT_EQ(header->typ, "JWT");
    ASSERT_EQ(header->kid, "key-1");
}

TEST(test_jws_header_roundtrip) {
    jose::JWSHeader original;
    original.alg = "ML-DSA-44";
    original.typ = "JWT";
    original.kid = "test-key";

    std::string json = original.to_json();
    auto parsed = jose::JWSHeader::from_json(json);
    ASSERT(parsed.has_value());
    ASSERT_EQ(parsed->alg, original.alg);
    ASSERT_EQ(parsed->typ, original.typ);
    ASSERT_EQ(parsed->kid, original.kid);
}

// ============================================================================
// Algorithm Mapping Tests
// ============================================================================

TEST(test_jose_supported_algorithms) {
    auto algos = jose::available_algorithms();
    ASSERT(algos.size() >= 15);  // 3 ML-DSA + 12 SLH-DSA

    // Check ML-DSA
    ASSERT(jose::is_supported_algorithm("ML-DSA-44"));
    ASSERT(jose::is_supported_algorithm("ML-DSA-65"));
    ASSERT(jose::is_supported_algorithm("ML-DSA-87"));

    // Check some SLH-DSA
    ASSERT(jose::is_supported_algorithm("SLH-DSA-SHA2-128f"));
    ASSERT(jose::is_supported_algorithm("SLH-DSA-SHAKE-256s"));
}

TEST(test_jose_algorithm_mapping) {
    auto internal = jose::get_internal_algorithm("ML-DSA-65");
    ASSERT(internal.has_value());
    ASSERT_EQ(*internal, "ML-DSA-65");

    auto jose_name = jose::get_jose_algorithm("ML-DSA-87");
    ASSERT(jose_name.has_value());
    ASSERT_EQ(*jose_name, "ML-DSA-87");
}

TEST(test_cose_algorithm_ids) {
    ASSERT_EQ(static_cast<int>(cose::Algorithm::ML_DSA_44), -48);
    ASSERT_EQ(static_cast<int>(cose::Algorithm::ML_DSA_65), -49);
    ASSERT_EQ(static_cast<int>(cose::Algorithm::ML_DSA_87), -50);
}

TEST(test_cose_algorithm_mapping) {
    auto alg = cose::algorithm_from_name("ML-DSA-65");
    ASSERT(alg.has_value());
    ASSERT_EQ(*alg, cose::Algorithm::ML_DSA_65);

    auto info = cose::algorithm_info(cose::Algorithm::ML_DSA_87);
    ASSERT(info.has_value());
    ASSERT_EQ(info->name, "ML-DSA-87");
    ASSERT_EQ(info->security_level, 5);
}

// ============================================================================
// JWS Sign/Verify Tests (ML-DSA)
// ============================================================================

TEST(test_jws_sign_verify_mldsa44) {
    auto dsa = pqc::create_dsa("ML-DSA-44");
    auto [pk, sk] = dsa->keygen();

    std::string payload = R"({"sub":"test","iat":1234567890})";

    jose::JWSBuilder builder;
    std::string jwt = builder
        .set_algorithm("ML-DSA-44")
        .set_type("JWT")
        .set_payload(payload)
        .sign(sk);

    // Verify
    jose::JWSVerifier verifier(jwt);
    ASSERT_EQ(verifier.algorithm(), "ML-DSA-44");
    ASSERT_EQ(verifier.type(), "JWT");
    ASSERT(verifier.verify(pk));
    ASSERT_EQ(verifier.payload(), payload);
}

TEST(test_jws_sign_verify_mldsa65) {
    auto dsa = pqc::create_dsa("ML-DSA-65");
    auto [pk, sk] = dsa->keygen();

    std::string payload = R"({"sub":"user@example.com","exp":1700000000})";

    std::string jwt = jose::create_jwt("ML-DSA-65", payload, sk);

    auto verified_payload = jose::verify_jwt(jwt, pk);
    ASSERT(verified_payload.has_value());
    ASSERT_EQ(*verified_payload, payload);
}

TEST(test_jws_sign_verify_mldsa87) {
    auto dsa = pqc::create_dsa("ML-DSA-87");
    auto [pk, sk] = dsa->keygen();

    std::string payload = R"({"data":"sensitive"})";

    jose::JWSBuilder builder;
    std::string jwt = builder
        .set_algorithm("ML-DSA-87")
        .set_type("JWT")
        .set_key_id("key-123")
        .set_payload(payload)
        .sign(sk);

    jose::JWSVerifier verifier(jwt);
    ASSERT_EQ(verifier.key_id(), "key-123");
    ASSERT(verifier.verify(pk));
}

// ============================================================================
// JWS Sign/Verify Tests (SLH-DSA)
// ============================================================================

TEST(test_jws_sign_verify_slhdsa_sha2_128f) {
    auto dsa = pqc::create_dsa("SLH-DSA-SHA2-128f");
    auto [pk, sk] = dsa->keygen();

    std::string payload = R"({"msg":"hello"})";

    std::string jwt = jose::create_jwt("SLH-DSA-SHA2-128f", payload, sk);

    auto verified = jose::verify_jwt(jwt, pk);
    ASSERT(verified.has_value());
    ASSERT_EQ(*verified, payload);
}

// ============================================================================
// JWS Error Handling Tests
// ============================================================================

TEST(test_jws_invalid_signature) {
    auto dsa = pqc::create_dsa("ML-DSA-65");
    auto [pk1, sk1] = dsa->keygen();
    auto [pk2, sk2] = dsa->keygen();

    std::string payload = R"({"data":"test"})";
    std::string jwt = jose::create_jwt("ML-DSA-65", payload, sk1);

    // Verify with wrong key
    auto result = jose::verify_jwt(jwt, pk2);
    ASSERT(!result.has_value());
}

TEST(test_jws_tampered_payload) {
    auto dsa = pqc::create_dsa("ML-DSA-65");
    auto [pk, sk] = dsa->keygen();

    std::string jwt = jose::create_jwt("ML-DSA-65", R"({"value":1})", sk);

    // Tamper with the payload
    size_t first_dot = jwt.find('.');
    size_t second_dot = jwt.find('.', first_dot + 1);
    std::string tampered = jwt.substr(0, first_dot + 1) +
                          jose::detail::base64url_encode(R"({"value":2})") +
                          jwt.substr(second_dot);

    auto result = jose::verify_jwt(tampered, pk);
    ASSERT(!result.has_value());
}

TEST(test_jws_malformed_token) {
    auto parsed = jose::parse_jws("not.a.valid.token");
    ASSERT(!parsed.has_value());

    auto parsed2 = jose::parse_jws("invalid");
    ASSERT(!parsed2.has_value());
}

TEST(test_jws_unsupported_algorithm) {
    try {
        jose::JWSBuilder builder;
        std::string jwt = builder
            .set_algorithm("RS256")  // Not supported
            .set_payload("{}")
            .sign({});
        ASSERT(false);  // Should have thrown
    } catch (const std::runtime_error&) {
        // Expected
    }
}

// ============================================================================
// JWS with Context Tests
// ============================================================================

TEST(test_jws_with_context) {
    auto dsa = pqc::create_dsa("ML-DSA-65");
    auto [pk, sk] = dsa->keygen();

    std::string payload = R"({"data":"context-test"})";
    std::vector<uint8_t> ctx = {'a', 'p', 'p', '-', 'c', 't', 'x'};

    jose::JWSBuilder builder;
    std::string jwt = builder
        .set_algorithm("ML-DSA-65")
        .set_type("JWT")
        .set_payload(payload)
        .set_context(ctx)
        .sign(sk);

    jose::JWSVerifier verifier(jwt);
    // Verify with correct context
    ASSERT(verifier.verify(pk, ctx));

    // Verify with wrong context should fail
    std::vector<uint8_t> wrong_ctx = {'w', 'r', 'o', 'n', 'g'};
    ASSERT(!verifier.verify(pk, wrong_ctx));
}

// ============================================================================
// CBOR Encoding Tests
// ============================================================================

TEST(test_cbor_encode_uint) {
    std::vector<uint8_t> out;
    cose::cbor::encode_uint(out, 0);
    ASSERT_EQ(out.size(), 1u);
    ASSERT_EQ(out[0], 0x00);

    out.clear();
    cose::cbor::encode_uint(out, 23);
    ASSERT_EQ(out.size(), 1u);
    ASSERT_EQ(out[0], 23);

    out.clear();
    cose::cbor::encode_uint(out, 24);
    ASSERT_EQ(out.size(), 2u);
    ASSERT_EQ(out[0], 0x18);
    ASSERT_EQ(out[1], 24);

    out.clear();
    cose::cbor::encode_uint(out, 1000);
    ASSERT_EQ(out.size(), 3u);
    ASSERT_EQ(out[0], 0x19);
}

TEST(test_cbor_encode_nint) {
    std::vector<uint8_t> out;
    cose::cbor::encode_nint(out, -1);  // -1 = 0x20
    ASSERT_EQ(out.size(), 1u);
    ASSERT_EQ(out[0], 0x20);

    out.clear();
    cose::cbor::encode_nint(out, -10);  // -10 encoded as 9 = 0x29
    ASSERT_EQ(out.size(), 1u);
    ASSERT_EQ(out[0], 0x29);
}

TEST(test_cbor_encode_bytes) {
    std::vector<uint8_t> out;
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    cose::cbor::encode_bytes(out, data);
    ASSERT_EQ(out.size(), 4u);  // 1 byte header + 3 bytes data
    ASSERT_EQ(out[0], 0x43);    // bstr(3)
    ASSERT_EQ(out[1], 0x01);
    ASSERT_EQ(out[2], 0x02);
    ASSERT_EQ(out[3], 0x03);
}

TEST(test_cbor_decode_int) {
    std::vector<uint8_t> data = {0x29};  // -10
    auto result = cose::cbor::decode_int(data);
    ASSERT(result.has_value());
    ASSERT_EQ(result->first, -10);
    ASSERT_EQ(result->second, 1u);
}

TEST(test_cbor_decode_bytes) {
    std::vector<uint8_t> data = {0x43, 0xAA, 0xBB, 0xCC};
    auto result = cose::cbor::decode_bytes(data);
    ASSERT(result.has_value());
    ASSERT_EQ(result->first.size(), 3u);
    ASSERT_EQ(result->first[0], 0xAA);
    ASSERT_EQ(result->first[1], 0xBB);
    ASSERT_EQ(result->first[2], 0xCC);
}

// ============================================================================
// COSE_Sign1 Tests (ML-DSA)
// ============================================================================

TEST(test_cose_sign1_mldsa44) {
    auto dsa = pqc::create_dsa("ML-DSA-44");
    auto [pk, sk] = dsa->keygen();

    std::vector<uint8_t> payload = {'h', 'e', 'l', 'l', 'o'};

    auto signed_msg = cose::sign1("ML-DSA-44", payload, sk);
    ASSERT(!signed_msg.empty());

    auto verified = cose::verify1(signed_msg, pk);
    ASSERT(verified.has_value());
    ASSERT_EQ(*verified, payload);
}

TEST(test_cose_sign1_mldsa65) {
    auto dsa = pqc::create_dsa("ML-DSA-65");
    auto [pk, sk] = dsa->keygen();

    std::vector<uint8_t> payload = {'t', 'e', 's', 't', ' ', 'd', 'a', 't', 'a'};

    auto signed_msg = cose::sign1("ML-DSA-65", payload, sk);

    auto verified = cose::verify1(signed_msg, pk);
    ASSERT(verified.has_value());
    ASSERT_EQ(*verified, payload);
}

TEST(test_cose_sign1_mldsa87) {
    auto dsa = pqc::create_dsa("ML-DSA-87");
    auto [pk, sk] = dsa->keygen();

    std::vector<uint8_t> payload(100, 0x42);  // 100 bytes of 0x42

    auto signed_msg = cose::sign1("ML-DSA-87", payload, sk);

    auto verified = cose::verify1(signed_msg, pk);
    ASSERT(verified.has_value());
    ASSERT_EQ(*verified, payload);
}

// ============================================================================
// COSE_Sign1 Tests (SLH-DSA)
// ============================================================================

TEST(test_cose_sign1_slhdsa_sha2_128f) {
    auto dsa = pqc::create_dsa("SLH-DSA-SHA2-128f");
    auto [pk, sk] = dsa->keygen();

    std::vector<uint8_t> payload = {'s', 'l', 'h', '-', 'd', 's', 'a'};

    auto signed_msg = cose::sign1("SLH-DSA-SHA2-128f", payload, sk);

    auto verified = cose::verify1(signed_msg, pk);
    ASSERT(verified.has_value());
    ASSERT_EQ(*verified, payload);
}

// ============================================================================
// COSE_Sign1 Error Handling Tests
// ============================================================================

TEST(test_cose_sign1_invalid_signature) {
    auto dsa = pqc::create_dsa("ML-DSA-65");
    auto [pk1, sk1] = dsa->keygen();
    auto [pk2, sk2] = dsa->keygen();

    std::vector<uint8_t> payload = {'d', 'a', 't', 'a'};

    auto signed_msg = cose::sign1("ML-DSA-65", payload, sk1);

    // Verify with wrong key
    auto verified = cose::verify1(signed_msg, pk2);
    ASSERT(!verified.has_value());
}

TEST(test_cose_sign1_malformed) {
    std::vector<uint8_t> garbage = {0x00, 0x01, 0x02, 0x03};
    auto result = cose::verify1(garbage, {});
    ASSERT(!result.has_value());
}

// ============================================================================
// COSE_Sign1 with External AAD
// ============================================================================

TEST(test_cose_sign1_with_aad) {
    auto dsa = pqc::create_dsa("ML-DSA-65");
    auto [pk, sk] = dsa->keygen();

    std::vector<uint8_t> payload = {'p', 'a', 'y', 'l', 'o', 'a', 'd'};
    std::vector<uint8_t> aad = {'a', 'a', 'd', '-', 'd', 'a', 't', 'a'};

    auto signed_msg = cose::sign1("ML-DSA-65", payload, sk, aad);

    // Verify with correct AAD
    auto verified = cose::verify1(signed_msg, pk, aad);
    ASSERT(verified.has_value());
    ASSERT_EQ(*verified, payload);

    // Verify with wrong AAD should fail
    std::vector<uint8_t> wrong_aad = {'w', 'r', 'o', 'n', 'g'};
    auto failed = cose::verify1(signed_msg, pk, wrong_aad);
    ASSERT(!failed.has_value());
}

// ============================================================================
// COSE_Sign1 Detached Payload
// ============================================================================

TEST(test_cose_sign1_detached) {
    auto dsa = pqc::create_dsa("ML-DSA-65");
    auto [pk, sk] = dsa->keygen();

    std::vector<uint8_t> payload = {'d', 'e', 't', 'a', 'c', 'h', 'e', 'd'};

    auto signed_msg = cose::sign1_detached("ML-DSA-65", payload, sk);

    // Verify with detached payload
    ASSERT(cose::verify1_detached(signed_msg, payload, pk));

    // Verify with wrong payload should fail
    std::vector<uint8_t> wrong_payload = {'w', 'r', 'o', 'n', 'g'};
    ASSERT(!cose::verify1_detached(signed_msg, wrong_payload, pk));
}

// ============================================================================
// COSE_Sign1 Structure Tests
// ============================================================================

TEST(test_cose_sign1_structure) {
    cose::Sign1 msg;
    msg.set_algorithm(cose::Algorithm::ML_DSA_65);

    auto alg = msg.algorithm();
    ASSERT(alg.has_value());
    ASSERT_EQ(*alg, cose::Algorithm::ML_DSA_65);
}

TEST(test_cose_sign1_encode_decode) {
    cose::Sign1 original;
    original.set_algorithm(cose::Algorithm::ML_DSA_44);
    original.payload = std::vector<uint8_t>{'t', 'e', 's', 't'};
    original.signature = std::vector<uint8_t>(2420, 0x55);  // Fake signature

    auto encoded = cose::encode_sign1(original);
    ASSERT(!encoded.empty());

    auto decoded = cose::decode_sign1(encoded);
    ASSERT(decoded.has_value());

    auto alg = decoded->algorithm();
    ASSERT(alg.has_value());
    ASSERT_EQ(*alg, cose::Algorithm::ML_DSA_44);

    ASSERT(decoded->payload.has_value());
    ASSERT_EQ(*decoded->payload, original.payload);
    ASSERT_EQ(decoded->signature, original.signature);
}

// ============================================================================
// All Algorithms Smoke Test
// ============================================================================

TEST(test_jose_all_mldsa_algorithms) {
    std::vector<std::string> algos = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};

    for (const auto& alg : algos) {
        auto dsa = pqc::create_dsa(alg);
        auto [pk, sk] = dsa->keygen();

        std::string payload = R"({"alg":")" + alg + R"("})";
        std::string jwt = jose::create_jwt(alg, payload, sk);

        auto verified = jose::verify_jwt(jwt, pk);
        ASSERT(verified.has_value());
        ASSERT_EQ(*verified, payload);
    }
}

TEST(test_cose_all_mldsa_algorithms) {
    std::vector<std::string> algos = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"};

    for (const auto& alg : algos) {
        auto dsa = pqc::create_dsa(alg);
        auto [pk, sk] = dsa->keygen();

        std::vector<uint8_t> payload(50, 0xAB);
        auto signed_msg = cose::sign1(alg, payload, sk);

        auto verified = cose::verify1(signed_msg, pk);
        ASSERT(verified.has_value());
        ASSERT_EQ(*verified, payload);
    }
}

// ============================================================================
// JWT Claims Tests
// ============================================================================

TEST(test_jwt_claims_extraction) {
    auto dsa = pqc::create_dsa("ML-DSA-65");
    auto [pk, sk] = dsa->keygen();

    std::string payload = R"({"sub":"user123","iss":"auth-server","exp":"1700000000"})";
    std::string jwt = jose::create_jwt("ML-DSA-65", payload, sk);

    jose::JWSVerifier verifier(jwt);
    ASSERT(verifier.verify(pk));

    auto sub = verifier.claim("sub");
    ASSERT(sub.has_value());
    ASSERT_EQ(*sub, "user123");

    auto iss = verifier.claim("iss");
    ASSERT(iss.has_value());
    ASSERT_EQ(*iss, "auth-server");

    auto missing = verifier.claim("aud");
    ASSERT(!missing.has_value());
}

// ============================================================================
// Main
// ============================================================================

int main() {
    std::cout << "\n=== JOSE/COSE Support Tests ===\n" << std::endl;

    // Tests run automatically via static initialization

    std::cout << "\n=== Test Summary ===" << std::endl;
    std::cout << "Total:  " << tests_run << std::endl;
    std::cout << "Passed: " << tests_passed << std::endl;
    std::cout << "Failed: " << tests_failed << std::endl;

    return tests_failed == 0 ? 0 : 1;
}
