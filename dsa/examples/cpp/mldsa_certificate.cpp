/**
 * ML-DSA Certificate Example
 * Demonstrates creating and verifying certificates with ML-DSA (FIPS 204)
 */

#include "mldsa/mldsa.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <chrono>

using namespace mldsa;

/**
 * Simple certificate structure for ML-DSA
 */
struct Certificate {
    std::string subject_cn;
    std::string issuer_cn;
    std::string algorithm;
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> signature;
    time_t not_before;
    time_t not_after;
    bool is_ca;

    std::vector<uint8_t> to_bytes() const {
        std::ostringstream oss;
        oss << subject_cn << "|" << issuer_cn << "|" << algorithm << "|";
        oss << not_before << "|" << not_after << "|" << is_ca << "|";
        for (auto b : public_key) {
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
        }
        std::string s = oss.str();
        return std::vector<uint8_t>(s.begin(), s.end());
    }

    void print() const {
        std::cout << "  Subject: " << subject_cn << std::endl;
        std::cout << "  Issuer: " << issuer_cn << std::endl;
        std::cout << "  Algorithm: " << algorithm << std::endl;
        std::cout << "  Is CA: " << (is_ca ? "Yes" : "No") << std::endl;
        std::cout << "  Public Key Size: " << public_key.size() << " bytes" << std::endl;
        std::cout << "  Signature Size: " << signature.size() << " bytes" << std::endl;

        char buf[64];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d", std::localtime(&not_before));
        std::cout << "  Valid From: " << buf << std::endl;
        std::strftime(buf, sizeof(buf), "%Y-%m-%d", std::localtime(&not_after));
        std::cout << "  Valid Until: " << buf << std::endl;
    }
};

/**
 * Certificate Authority using ML-DSA
 */
template<typename DSA>
class CertificateAuthority {
public:
    CertificateAuthority(const std::string& name) : name_(name) {
        auto [pk, sk] = dsa_.keygen();
        ca_pk_ = pk;
        ca_sk_ = sk;

        // Create self-signed CA certificate
        ca_cert_.subject_cn = name;
        ca_cert_.issuer_cn = name;
        ca_cert_.algorithm = std::string(dsa_.params().name);
        ca_cert_.public_key = pk;
        ca_cert_.is_ca = true;
        ca_cert_.not_before = time(nullptr);
        ca_cert_.not_after = ca_cert_.not_before + (10L * 365 * 24 * 3600); // 10 years

        auto tbs = ca_cert_.to_bytes();
        ca_cert_.signature = dsa_.sign(sk, tbs);
    }

    Certificate issue_certificate(
        const std::string& subject_cn,
        const std::vector<uint8_t>& subject_pk,
        const std::string& algorithm,
        int validity_days = 365,
        bool is_ca = false
    ) {
        Certificate cert;
        cert.subject_cn = subject_cn;
        cert.issuer_cn = name_;
        cert.algorithm = algorithm;
        cert.public_key = subject_pk;
        cert.is_ca = is_ca;
        cert.not_before = time(nullptr);
        cert.not_after = cert.not_before + (validity_days * 24L * 3600);

        auto tbs = cert.to_bytes();
        cert.signature = dsa_.sign(ca_sk_, tbs);

        return cert;
    }

    bool verify_certificate(const Certificate& cert) const {
        auto tbs = cert.to_bytes();
        return dsa_.verify(ca_pk_, tbs, cert.signature);
    }

    const Certificate& ca_certificate() const { return ca_cert_; }
    const std::vector<uint8_t>& public_key() const { return ca_pk_; }

private:
    DSA dsa_;
    std::string name_;
    std::vector<uint8_t> ca_pk_;
    std::vector<uint8_t> ca_sk_;
    Certificate ca_cert_;
};

void print_hex(const std::vector<uint8_t>& data, size_t max_len = 16) {
    for (size_t i = 0; i < std::min(data.size(), max_len); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]);
    }
    if (data.size() > max_len) std::cout << "...";
    std::cout << std::dec;
}

int main() {
    std::cout << std::string(60, '=') << std::endl;
    std::cout << "  ML-DSA Certificate Example (FIPS 204)" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    try {
        // Create Root CA with ML-DSA-65
        std::cout << "\n1. Creating Root CA with ML-DSA-65..." << std::endl;
        auto start = std::chrono::high_resolution_clock::now();
        CertificateAuthority<MLDSA65> root_ca("Example Root CA");
        auto end = std::chrono::high_resolution_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        std::cout << "   CA created in " << ms << " ms" << std::endl;
        std::cout << "\n   Root CA Certificate:" << std::endl;
        root_ca.ca_certificate().print();

        // Verify CA certificate (self-signed)
        bool valid = root_ca.verify_certificate(root_ca.ca_certificate());
        std::cout << "   Self-signature valid: " << (valid ? "YES" : "NO") << std::endl;

        // Create Intermediate CA with ML-DSA-65
        std::cout << "\n2. Creating Intermediate CA..." << std::endl;
        MLDSA65 int_dsa;
        auto [int_pk, int_sk] = int_dsa.keygen();

        auto int_cert = root_ca.issue_certificate(
            "Intermediate CA",
            int_pk,
            "ML-DSA-65",
            3650,  // 10 years
            true   // is CA
        );

        std::cout << "\n   Intermediate CA Certificate:" << std::endl;
        int_cert.print();

        valid = root_ca.verify_certificate(int_cert);
        std::cout << "   Signature valid: " << (valid ? "YES" : "NO") << std::endl;

        // Create end-entity certificate with ML-DSA-44 (faster for end entities)
        std::cout << "\n3. Creating TLS Server Certificate with ML-DSA-44..." << std::endl;
        MLDSA44 entity_dsa;
        auto [entity_pk, entity_sk] = entity_dsa.keygen();

        // For simplicity, we'll have root CA sign it directly
        // In practice, intermediate CA would sign
        auto server_cert = root_ca.issue_certificate(
            "api.example.com",
            entity_pk,
            "ML-DSA-44",
            365,   // 1 year
            false  // not a CA
        );

        std::cout << "\n   Server Certificate:" << std::endl;
        server_cert.print();

        valid = root_ca.verify_certificate(server_cert);
        std::cout << "   Signature valid: " << (valid ? "YES" : "NO") << std::endl;

        // Use server certificate to sign a message (simulating TLS handshake)
        std::cout << "\n4. Simulating TLS Handshake Signature..." << std::endl;
        std::string handshake = "ClientHello|ServerHello|Certificate|ServerKeyExchange";
        std::vector<uint8_t> handshake_data(handshake.begin(), handshake.end());

        start = std::chrono::high_resolution_clock::now();
        auto handshake_sig = entity_dsa.sign(entity_sk, handshake_data);
        end = std::chrono::high_resolution_clock::now();
        auto sign_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

        std::cout << "   Handshake signed in " << sign_us << " us" << std::endl;
        std::cout << "   Signature size: " << handshake_sig.size() << " bytes" << std::endl;

        // Client verifies handshake using server's public key from certificate
        start = std::chrono::high_resolution_clock::now();
        valid = entity_dsa.verify(server_cert.public_key, handshake_data, handshake_sig);
        end = std::chrono::high_resolution_clock::now();
        auto verify_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

        std::cout << "   Handshake verified in " << verify_us << " us" << std::endl;
        std::cout << "   Valid: " << (valid ? "YES" : "NO") << std::endl;

        // Summary
        std::cout << "\n" << std::string(60, '=') << std::endl;
        std::cout << "  Summary - ML-DSA Certificate Sizes" << std::endl;
        std::cout << std::string(60, '=') << std::endl;
        std::cout << std::setfill(' ');
        std::cout << "\n  " << std::setw(20) << "Certificate"
                  << std::setw(12) << "PK Size"
                  << std::setw(12) << "Sig Size" << std::endl;
        std::cout << "  " << std::string(44, '-') << std::endl;
        std::cout << "  " << std::setw(20) << "Root CA (65)"
                  << std::setw(12) << std::to_string(root_ca.ca_certificate().public_key.size()) + " B"
                  << std::setw(12) << std::to_string(root_ca.ca_certificate().signature.size()) + " B" << std::endl;
        std::cout << "  " << std::setw(20) << "Intermediate (65)"
                  << std::setw(12) << std::to_string(int_cert.public_key.size()) + " B"
                  << std::setw(12) << std::to_string(int_cert.signature.size()) + " B" << std::endl;
        std::cout << "  " << std::setw(20) << "Server (44)"
                  << std::setw(12) << std::to_string(server_cert.public_key.size()) + " B"
                  << std::setw(12) << std::to_string(server_cert.signature.size()) + " B" << std::endl;

        std::cout << "\n  ML-DSA is ideal for:" << std::endl;
        std::cout << "  - TLS/HTTPS servers (fast handshakes)" << std::endl;
        std::cout << "  - API authentication (high volume)" << std::endl;
        std::cout << "  - IoT devices (constrained resources)" << std::endl;

        std::cout << "\n" << std::string(60, '=') << std::endl;
        std::cout << "  Example completed successfully!" << std::endl;
        std::cout << std::string(60, '=') << std::endl;

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\nError: " << e.what() << std::endl;
        return 1;
    }
}
