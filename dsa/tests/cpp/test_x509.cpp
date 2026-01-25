/**
 * X.509 Certificate Tests
 *
 * Tests for X.509 v3 certificate generation, parsing, and verification
 * with post-quantum cryptographic algorithms.
 */

#include <iostream>
#include <cassert>
#include <cstring>
#include <iomanip>
#include "common/x509.hpp"
#include "mldsa/mldsa.hpp"
#include "slhdsa/slh_dsa.hpp"
#include "mlkem/mlkem.hpp"

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
// Distinguished Name Tests
// =============================================================================

void test_distinguished_name() {
    std::cout << "\n=== Distinguished Name Tests ===" << std::endl;

    TEST("DN encoding")
    {
        x509::DistinguishedName dn;
        dn.common_name = "Test CA";
        dn.organization = "Test Org";
        dn.country = "US";

        auto encoded = dn.encode();
        ASSERT(!encoded.empty());
        ASSERT(encoded[0] == 0x30);  // SEQUENCE tag

        // Verify string representation
        auto str = dn.to_string();
        ASSERT(str.find("CN=Test CA") != std::string::npos);
        ASSERT(str.find("O=Test Org") != std::string::npos);
        ASSERT(str.find("C=US") != std::string::npos);
    }
    TEST_END("DN encoding")

    TEST("DN with all fields")
    {
        x509::DistinguishedName dn;
        dn.common_name = "Full Test";
        dn.organization = "Org";
        dn.organizational_unit = "Dept";
        dn.locality = "City";
        dn.state = "State";
        dn.country = "US";
        dn.email = "test@example.com";

        auto encoded = dn.encode();
        ASSERT(!encoded.empty());

        auto str = dn.to_string();
        ASSERT(str.find("CN=Full Test") != std::string::npos);
        ASSERT(str.find("OU=Dept") != std::string::npos);
        ASSERT(str.find("L=City") != std::string::npos);
        ASSERT(str.find("ST=State") != std::string::npos);
        ASSERT(str.find("emailAddress=test@example.com") != std::string::npos);
    }
    TEST_END("DN with all fields")

    TEST("DN with minimal fields")
    {
        x509::DistinguishedName dn;
        dn.common_name = "Minimal";

        auto encoded = dn.encode();
        ASSERT(!encoded.empty());
    }
    TEST_END("DN with minimal fields")
}

// =============================================================================
// Time Encoding Tests
// =============================================================================

void test_time_encoding() {
    std::cout << "\n=== Time Encoding Tests ===" << std::endl;

    TEST("UTCTime format")
    {
        auto now = std::chrono::system_clock::now();
        auto utc = x509::format_utc_time(now);
        ASSERT(utc.size() == 13);  // YYMMDDHHMMSSZ
        ASSERT(utc.back() == 'Z');
    }
    TEST_END("UTCTime format")

    TEST("Validity period encoding")
    {
        auto now = std::chrono::system_clock::now();
        auto later = now + std::chrono::hours(24 * 365);
        auto encoded = x509::encode_validity(now, later);
        ASSERT(!encoded.empty());
        ASSERT(encoded[0] == 0x30);  // SEQUENCE
    }
    TEST_END("Validity period encoding")
}

// =============================================================================
// ML-DSA Certificate Tests
// =============================================================================

void test_mldsa_certificates() {
    std::cout << "\n=== ML-DSA Certificate Tests ===" << std::endl;

    TEST("ML-DSA-44 self-signed certificate")
    {
        mldsa::MLDSA44 dsa;
        auto [pk, sk] = dsa.keygen();

        x509::DistinguishedName subject;
        subject.common_name = "ML-DSA-44 Test CA";
        subject.organization = "PQC Test";
        subject.country = "US";

        // Sign callback using ML-DSA
        auto sign_fn = [&dsa, &sk](const std::vector<uint8_t>& data) {
            return dsa.sign(sk, data);
        };

        auto cert_der = x509::create_self_signed_der(
            pkcs8::Algorithm::ML_DSA_44, subject, pk, sign_fn);

        ASSERT(!cert_der.empty());
        ASSERT(cert_der[0] == 0x30);  // SEQUENCE

        // Parse the certificate
        auto cert = x509::parse_certificate_der(cert_der);
        ASSERT(cert.has_value());
        ASSERT(cert->signature_algorithm == pkcs8::Algorithm::ML_DSA_44);
        ASSERT(cert->public_key_algorithm == pkcs8::Algorithm::ML_DSA_44);
        ASSERT(cert->subject_public_key == pk);

        // Verify the certificate
        auto verify_fn = [&dsa](
            const std::vector<uint8_t>& public_key,
            const std::vector<uint8_t>& tbs,
            const std::vector<uint8_t>& sig) {
            return dsa.verify(public_key, tbs, sig);
        };

        bool valid = x509::verify_self_signed(*cert, verify_fn);
        ASSERT(valid);
    }
    TEST_END("ML-DSA-44 self-signed certificate")

    TEST("ML-DSA-65 certificate PEM round-trip")
    {
        mldsa::MLDSA65 dsa;
        auto [pk, sk] = dsa.keygen();

        x509::DistinguishedName subject;
        subject.common_name = "ML-DSA-65 PEM Test";
        subject.organization = "PQC Library";
        subject.country = "US";
        subject.state = "California";

        auto sign_fn = [&dsa, &sk](const std::vector<uint8_t>& data) {
            return dsa.sign(sk, data);
        };

        // Generate PEM certificate
        auto cert_pem = x509::create_self_signed_pem(
            pkcs8::Algorithm::ML_DSA_65, subject, pk, sign_fn);

        ASSERT(cert_pem.find("-----BEGIN CERTIFICATE-----") != std::string::npos);
        ASSERT(cert_pem.find("-----END CERTIFICATE-----") != std::string::npos);

        // Parse PEM certificate
        auto cert = x509::parse_certificate_pem(cert_pem);
        ASSERT(cert.has_value());
        ASSERT(cert->signature_algorithm == pkcs8::Algorithm::ML_DSA_65);

        // Verify
        auto verify_fn = [&dsa](
            const std::vector<uint8_t>& public_key,
            const std::vector<uint8_t>& tbs,
            const std::vector<uint8_t>& sig) {
            return dsa.verify(public_key, tbs, sig);
        };

        ASSERT(x509::verify_self_signed(*cert, verify_fn));
    }
    TEST_END("ML-DSA-65 certificate PEM round-trip")

    TEST("ML-DSA-87 certificate verification")
    {
        mldsa::MLDSA87 dsa;
        auto [pk, sk] = dsa.keygen();

        x509::DistinguishedName subject;
        subject.common_name = "ML-DSA-87 Verify Test";
        subject.organization = "Security Testing";
        subject.country = "DE";

        auto sign_fn = [&dsa, &sk](const std::vector<uint8_t>& data) {
            return dsa.sign(sk, data);
        };

        auto cert_der = x509::create_self_signed_der(
            pkcs8::Algorithm::ML_DSA_87, subject, pk, sign_fn);

        auto cert = x509::parse_certificate_der(cert_der);
        ASSERT(cert.has_value());

        // Verify with correct key
        auto verify_fn = [&dsa](
            const std::vector<uint8_t>& public_key,
            const std::vector<uint8_t>& tbs,
            const std::vector<uint8_t>& sig) {
            return dsa.verify(public_key, tbs, sig);
        };
        ASSERT(x509::verify_self_signed(*cert, verify_fn));

        // Verify with wrong key should fail
        auto [pk2, sk2] = dsa.keygen();
        auto verify_wrong = [&dsa, &pk2](
            const std::vector<uint8_t>& /*public_key*/,
            const std::vector<uint8_t>& tbs,
            const std::vector<uint8_t>& sig) {
            return dsa.verify(pk2, tbs, sig);
        };
        ASSERT(!x509::verify_certificate(*cert, verify_wrong));
    }
    TEST_END("ML-DSA-87 certificate verification")
}

// =============================================================================
// SLH-DSA Certificate Tests
// =============================================================================

void test_slhdsa_certificates() {
    std::cout << "\n=== SLH-DSA Certificate Tests ===" << std::endl;

    TEST("SLH-DSA-SHA2-128s self-signed certificate")
    {
        slhdsa::SLHDSA_SHA2_128s dsa;
        auto [sk, pk] = dsa.keygen();

        x509::DistinguishedName subject;
        subject.common_name = "SLH-DSA SHA2-128s Test";
        subject.organization = "Hash-Based Sigs";
        subject.country = "JP";

        auto sign_fn = [&dsa, &sk](const std::vector<uint8_t>& data) {
            return dsa.sign(sk, data);
        };

        auto cert_der = x509::create_self_signed_der(
            pkcs8::Algorithm::SLH_DSA_SHA2_128s, subject, pk, sign_fn);

        ASSERT(!cert_der.empty());

        auto cert = x509::parse_certificate_der(cert_der);
        ASSERT(cert.has_value());
        ASSERT(cert->signature_algorithm == pkcs8::Algorithm::SLH_DSA_SHA2_128s);
        ASSERT(cert->subject_public_key == pk);

        auto verify_fn = [&dsa](
            const std::vector<uint8_t>& public_key,
            const std::vector<uint8_t>& tbs,
            const std::vector<uint8_t>& sig) {
            return dsa.verify(public_key, tbs, sig);
        };
        ASSERT(x509::verify_self_signed(*cert, verify_fn));
    }
    TEST_END("SLH-DSA-SHA2-128s self-signed certificate")

    TEST("SLH-DSA-SHAKE-128f certificate PEM")
    {
        slhdsa::SLHDSA_SHAKE_128f dsa;
        auto [sk, pk] = dsa.keygen();

        x509::DistinguishedName subject;
        subject.common_name = "SLH-DSA SHAKE-128f";
        subject.country = "CH";

        auto sign_fn = [&dsa, &sk](const std::vector<uint8_t>& data) {
            return dsa.sign(sk, data);
        };

        auto cert_pem = x509::create_self_signed_pem(
            pkcs8::Algorithm::SLH_DSA_SHAKE_128f, subject, pk, sign_fn);

        ASSERT(cert_pem.find("-----BEGIN CERTIFICATE-----") != std::string::npos);

        auto cert = x509::parse_certificate_pem(cert_pem);
        ASSERT(cert.has_value());

        auto verify_fn = [&dsa](
            const std::vector<uint8_t>& public_key,
            const std::vector<uint8_t>& tbs,
            const std::vector<uint8_t>& sig) {
            return dsa.verify(public_key, tbs, sig);
        };
        ASSERT(x509::verify_self_signed(*cert, verify_fn));
    }
    TEST_END("SLH-DSA-SHAKE-128f certificate PEM")
}

// =============================================================================
// ML-KEM Certificate Tests
// =============================================================================

void test_mlkem_certificates() {
    std::cout << "\n=== ML-KEM Certificate Tests ===" << std::endl;

    TEST("ML-KEM-768 encapsulation key certificate")
    {
        // ML-KEM certs use ML-DSA for the signature, ML-KEM for the subject key
        mlkem::MLKEM768 kem;
        mldsa::MLDSA65 dsa;

        auto [ek, dk] = kem.keygen();
        auto [dsa_pk, dsa_sk] = dsa.keygen();

        // Use CertificateParams directly for mixed-algorithm cert
        x509::CertificateParams params;
        params.algorithm = pkcs8::Algorithm::ML_DSA_65;  // Signing algorithm
        params.issuer.common_name = "PQC CA";
        params.issuer.country = "US";
        params.subject.common_name = "KEM Endpoint";
        params.subject.country = "US";
        params.not_before = std::chrono::system_clock::now();
        params.not_after = params.not_before + std::chrono::hours(24 * 365);
        params.public_key = ek;
        params.is_ca = false;

        auto sign_fn = [&dsa, &dsa_sk](const std::vector<uint8_t>& data) {
            return dsa.sign(dsa_sk, data);
        };

        // Build certificate - note: SPKI will use the signing algorithm OID
        // In practice, KEM certs would use a different OID for SPKI
        auto cert_der = x509::build_certificate_der(params, sign_fn);
        ASSERT(!cert_der.empty());

        auto cert = x509::parse_certificate_der(cert_der);
        ASSERT(cert.has_value());
        ASSERT(cert->signature_algorithm == pkcs8::Algorithm::ML_DSA_65);

        // For proper CA-signed verification, we need the issuer's key
        auto verify_with_ca = [&dsa, &dsa_pk](
            const std::vector<uint8_t>& /*public_key*/,
            const std::vector<uint8_t>& tbs,
            const std::vector<uint8_t>& sig) {
            return dsa.verify(dsa_pk, tbs, sig);
        };
        ASSERT(x509::verify_certificate(*cert, verify_with_ca));
    }
    TEST_END("ML-KEM-768 encapsulation key certificate")
}

// =============================================================================
// CertificateParams Builder Tests
// =============================================================================

void test_certificate_builder() {
    std::cout << "\n=== Certificate Builder Tests ===" << std::endl;

    TEST("Custom serial number")
    {
        mldsa::MLDSA44 dsa;
        auto [pk, sk] = dsa.keygen();

        x509::CertificateParams params;
        params.algorithm = pkcs8::Algorithm::ML_DSA_44;
        params.serial_number = {0x01, 0x02, 0x03, 0x04};
        params.issuer.common_name = "Custom Serial Test";
        params.subject.common_name = "Custom Serial Test";
        params.not_before = std::chrono::system_clock::now();
        params.not_after = params.not_before + std::chrono::hours(24 * 30);
        params.public_key = pk;
        params.is_ca = false;

        auto sign_fn = [&dsa, &sk](const std::vector<uint8_t>& data) {
            return dsa.sign(sk, data);
        };

        auto cert_der = x509::build_certificate_der(params, sign_fn);
        auto cert = x509::parse_certificate_der(cert_der);

        ASSERT(cert.has_value());
        ASSERT(cert->serial_number == params.serial_number);
    }
    TEST_END("Custom serial number")

    TEST("Auto-generated serial number")
    {
        mldsa::MLDSA44 dsa;
        auto [pk, sk] = dsa.keygen();

        x509::DistinguishedName subject;
        subject.common_name = "Auto Serial";

        auto sign_fn = [&dsa, &sk](const std::vector<uint8_t>& data) {
            return dsa.sign(sk, data);
        };

        auto cert1 = x509::create_self_signed_der(
            pkcs8::Algorithm::ML_DSA_44, subject, pk, sign_fn);
        auto cert2 = x509::create_self_signed_der(
            pkcs8::Algorithm::ML_DSA_44, subject, pk, sign_fn);

        auto parsed1 = x509::parse_certificate_der(cert1);
        auto parsed2 = x509::parse_certificate_der(cert2);

        ASSERT(parsed1.has_value());
        ASSERT(parsed2.has_value());
        // Serial numbers should be different (random)
        ASSERT(parsed1->serial_number != parsed2->serial_number);
    }
    TEST_END("Auto-generated serial number")
}

// =============================================================================
// Error Handling Tests
// =============================================================================

void test_error_handling() {
    std::cout << "\n=== Error Handling Tests ===" << std::endl;

    TEST("Invalid DER certificate")
    {
        std::vector<uint8_t> garbage = {0x30, 0x03, 0x01, 0x02, 0x03};
        auto result = x509::parse_certificate_der(garbage);
        ASSERT(!result.has_value());
    }
    TEST_END("Invalid DER certificate")

    TEST("Invalid PEM certificate")
    {
        auto result = x509::parse_certificate_pem("not a certificate");
        ASSERT(!result.has_value());
    }
    TEST_END("Invalid PEM certificate")

    TEST("Tampered certificate fails verification")
    {
        mldsa::MLDSA44 dsa;
        auto [pk, sk] = dsa.keygen();

        x509::DistinguishedName subject;
        subject.common_name = "Tamper Test";
        subject.country = "US";

        auto sign_fn = [&dsa, &sk](const std::vector<uint8_t>& data) {
            return dsa.sign(sk, data);
        };

        auto cert_der = x509::create_self_signed_der(
            pkcs8::Algorithm::ML_DSA_44, subject, pk, sign_fn);

        // Tamper with certificate (flip a byte in the middle)
        auto tampered = cert_der;
        if (tampered.size() > 100) {
            tampered[100] ^= 0xFF;
        }

        // Try to parse (may or may not succeed depending on what was modified)
        auto cert = x509::parse_certificate_der(tampered);
        if (cert.has_value()) {
            // If parsing succeeds, verification should fail
            auto verify_fn = [&dsa](
                const std::vector<uint8_t>& public_key,
                const std::vector<uint8_t>& tbs,
                const std::vector<uint8_t>& sig) {
                return dsa.verify(public_key, tbs, sig);
            };
            bool valid = x509::verify_self_signed(*cert, verify_fn);
            ASSERT(!valid);
        }
        // If parsing fails, that's also an acceptable outcome
    }
    TEST_END("Tampered certificate fails verification")
}

// =============================================================================
// Output Format Tests
// =============================================================================

void test_output_format() {
    std::cout << "\n=== Output Format Tests ===" << std::endl;

    TEST("Print sample certificate PEM")
    {
        mldsa::MLDSA44 dsa;
        auto [pk, sk] = dsa.keygen();

        x509::DistinguishedName subject;
        subject.common_name = "PQC Demo CA";
        subject.organization = "Post-Quantum Cryptography";
        subject.country = "US";

        auto sign_fn = [&dsa, &sk](const std::vector<uint8_t>& data) {
            return dsa.sign(sk, data);
        };

        auto cert_pem = x509::create_self_signed_pem(
            pkcs8::Algorithm::ML_DSA_44, subject, pk, sign_fn, 365);

        std::cout << std::endl;
        std::cout << "  Sample ML-DSA-44 self-signed certificate:" << std::endl;
        // Print first few lines
        size_t pos = 0;
        int lines = 0;
        while (pos < cert_pem.size() && lines < 6) {
            size_t end = cert_pem.find('\n', pos);
            if (end == std::string::npos) end = cert_pem.size();
            std::cout << "  " << cert_pem.substr(pos, end - pos) << std::endl;
            pos = end + 1;
            lines++;
        }
        std::cout << "  ... (" << cert_pem.size() << " bytes total)" << std::endl;
    }
    TEST_END("Print sample certificate PEM")
}

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "  X.509 Certificate Tests" << std::endl;
    std::cout << "========================================" << std::endl;

    test_distinguished_name();
    test_time_encoding();
    test_mldsa_certificates();
    test_slhdsa_certificates();
    test_mlkem_certificates();
    test_certificate_builder();
    test_error_handling();
    test_output_format();

    std::cout << "\n========================================" << std::endl;
    std::cout << "  Results: " << tests_passed << " passed, "
              << tests_failed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
