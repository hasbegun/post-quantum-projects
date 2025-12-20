/**
 * SLH-DSA Certificate Example
 * Demonstrates creating and verifying certificates with SLH-DSA (FIPS 205)
 */

#include "slhdsa/slh_dsa.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <chrono>

using namespace slhdsa;

/**
 * Simple certificate structure for SLH-DSA
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
    std::string key_usage;

    std::vector<uint8_t> to_bytes() const {
        std::ostringstream oss;
        oss << subject_cn << "|" << issuer_cn << "|" << algorithm << "|";
        oss << not_before << "|" << not_after << "|" << is_ca << "|" << key_usage << "|";
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
        if (!key_usage.empty()) {
            std::cout << "  Key Usage: " << key_usage << std::endl;
        }
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
 * Certificate Authority using SLH-DSA
 */
template<typename DSA>
class SLHDSACertificateAuthority {
public:
    SLHDSACertificateAuthority(const std::string& name, int validity_years = 30) : name_(name) {
        std::cout << "   Generating key pair..." << std::flush;

        auto start = std::chrono::high_resolution_clock::now();
        auto [sk, pk] = dsa_.keygen();
        auto end = std::chrono::high_resolution_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        std::cout << " done (" << ms << " ms)" << std::endl;

        ca_pk_ = pk;
        ca_sk_ = sk;

        // Create self-signed CA certificate
        ca_cert_.subject_cn = name;
        ca_cert_.issuer_cn = name;
        ca_cert_.algorithm = std::string(dsa_.params().name);
        ca_cert_.public_key = pk;
        ca_cert_.is_ca = true;
        ca_cert_.key_usage = "keyCertSign, cRLSign";
        ca_cert_.not_before = time(nullptr);
        ca_cert_.not_after = ca_cert_.not_before + (validity_years * 365L * 24 * 3600);

        std::cout << "   Signing certificate..." << std::flush;
        start = std::chrono::high_resolution_clock::now();
        auto tbs = ca_cert_.to_bytes();
        ca_cert_.signature = dsa_.sign(sk, tbs);
        end = std::chrono::high_resolution_clock::now();
        ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        std::cout << " done (" << ms << " ms)" << std::endl;
    }

    template<typename EntityDSA>
    Certificate issue_certificate(
        const std::string& subject_cn,
        const std::vector<uint8_t>& subject_pk,
        const std::string& algorithm,
        int validity_years = 10,
        bool is_ca = false,
        const std::string& key_usage = ""
    ) {
        Certificate cert;
        cert.subject_cn = subject_cn;
        cert.issuer_cn = name_;
        cert.algorithm = algorithm;
        cert.public_key = subject_pk;
        cert.is_ca = is_ca;
        cert.key_usage = key_usage;
        cert.not_before = time(nullptr);
        cert.not_after = cert.not_before + (validity_years * 365L * 24 * 3600);

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
    const std::vector<uint8_t>& secret_key() const { return ca_sk_; }

private:
    DSA dsa_;
    std::string name_;
    std::vector<uint8_t> ca_pk_;
    std::vector<uint8_t> ca_sk_;
    Certificate ca_cert_;
};

int main() {
    std::cout << std::string(60, '=') << std::endl;
    std::cout << "  SLH-DSA Certificate Example (FIPS 205)" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    std::cout << "\nNote: SLH-DSA provides security based only on hash functions." << std::endl;
    std::cout << "This is ideal for long-term certificates (Root CAs, code signing).\n" << std::endl;

    try {
        // Create Root CA with SLH-DSA-SHAKE-128f (faster variant for demo)
        std::cout << "1. Creating Root CA with SLH-DSA-SHAKE-128f..." << std::endl;
        SLHDSACertificateAuthority<SLHDSA_SHAKE_128f> root_ca("Global Root CA", 30);

        std::cout << "\n   Root CA Certificate:" << std::endl;
        root_ca.ca_certificate().print();

        // Verify CA certificate
        bool valid = root_ca.verify_certificate(root_ca.ca_certificate());
        std::cout << "   Self-signature valid: " << (valid ? "YES" : "NO") << std::endl;

        // Create Code Signing Certificate
        std::cout << "\n2. Creating Code Signing Certificate..." << std::endl;
        SLHDSA_SHAKE_128f code_signer;
        auto [cs_sk, cs_pk] = code_signer.keygen();

        auto cs_cert = root_ca.issue_certificate<SLHDSA_SHAKE_128f>(
            "Software Vendor Code Signing",
            cs_pk,
            "SLH-DSA-SHAKE-128f",
            5,     // 5 years
            false, // not a CA
            "digitalSignature, codeSigning"
        );

        std::cout << "\n   Code Signing Certificate:" << std::endl;
        cs_cert.print();

        valid = root_ca.verify_certificate(cs_cert);
        std::cout << "   Signature valid: " << (valid ? "YES" : "NO") << std::endl;

        // Sign some firmware
        std::cout << "\n3. Signing Firmware with Code Signing Certificate..." << std::endl;
        std::vector<uint8_t> firmware(50000, 0x42); // 50KB simulated firmware
        firmware[0] = 0x7F; // ELF magic
        firmware[1] = 'E';
        firmware[2] = 'L';
        firmware[3] = 'F';

        std::cout << "   Firmware size: " << firmware.size() << " bytes" << std::endl;

        auto start = std::chrono::high_resolution_clock::now();
        auto fw_sig = code_signer.sign(cs_sk, firmware);
        auto end = std::chrono::high_resolution_clock::now();
        auto sign_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        std::cout << "   Signing time: " << sign_ms << " ms" << std::endl;
        std::cout << "   Signature size: " << fw_sig.size() << " bytes" << std::endl;

        // Verify firmware signature
        start = std::chrono::high_resolution_clock::now();
        valid = code_signer.verify(cs_pk, firmware, fw_sig);
        end = std::chrono::high_resolution_clock::now();
        auto verify_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        std::cout << "   Verify time: " << verify_ms << " ms" << std::endl;
        std::cout << "   Valid: " << (valid ? "YES" : "NO") << std::endl;

        // Test tampered firmware
        std::cout << "\n4. Testing Tampered Firmware Detection..." << std::endl;
        firmware[100] ^= 0xFF; // Corrupt one byte
        valid = code_signer.verify(cs_pk, firmware, fw_sig);
        std::cout << "   Tampered firmware valid: " << (valid ? "YES (BAD!)" : "NO (Correct!)") << std::endl;

        // Create Document Signing Certificate (using 's' variant for smaller sigs)
        std::cout << "\n5. Creating Document Signing Certificate (SLH-DSA-SHAKE-128s)..." << std::endl;
        SLHDSA_SHAKE_128s doc_signer;
        auto [doc_sk, doc_pk] = doc_signer.keygen();

        auto doc_cert = root_ca.issue_certificate<SLHDSA_SHAKE_128s>(
            "Legal Document Signing",
            doc_pk,
            "SLH-DSA-SHAKE-128s",
            10,    // 10 years
            false,
            "digitalSignature, nonRepudiation"
        );

        std::cout << "\n   Document Signing Certificate:" << std::endl;
        doc_cert.print();

        // Sign a document
        std::string document = R"(
            AGREEMENT

            This legally binding agreement is made between Party A and Party B.

            Terms and Conditions:
            1. Both parties agree to the terms herein.
            2. This agreement is valid for 10 years.

            Electronically signed with SLH-DSA.
        )";
        std::vector<uint8_t> doc_data(document.begin(), document.end());

        std::cout << "\n6. Signing Legal Document..." << std::endl;
        std::cout << "   Document size: " << doc_data.size() << " bytes" << std::endl;

        start = std::chrono::high_resolution_clock::now();
        auto doc_sig = doc_signer.sign(doc_sk, doc_data);
        end = std::chrono::high_resolution_clock::now();
        sign_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        std::cout << "   Signing time: " << sign_ms << " ms" << std::endl;
        std::cout << "   Signature size: " << doc_sig.size() << " bytes (smaller than 'f' variant!)" << std::endl;

        valid = doc_signer.verify(doc_pk, doc_data, doc_sig);
        std::cout << "   Valid: " << (valid ? "YES" : "NO") << std::endl;

        // Summary
        std::cout << "\n" << std::string(60, '=') << std::endl;
        std::cout << "  Summary - SLH-DSA Certificate Sizes" << std::endl;
        std::cout << std::string(60, '=') << std::endl;
        std::cout << std::setfill(' ');
        std::cout << "\n  " << std::setw(25) << "Certificate"
                  << std::setw(10) << "PK Size"
                  << std::setw(12) << "Sig Size" << std::endl;
        std::cout << "  " << std::string(47, '-') << std::endl;
        std::cout << "  " << std::setw(25) << "Root CA (SHAKE-128f)"
                  << std::setw(10) << std::to_string(root_ca.ca_certificate().public_key.size()) + " B"
                  << std::setw(12) << std::to_string(root_ca.ca_certificate().signature.size()) + " B" << std::endl;
        std::cout << "  " << std::setw(25) << "Code Signing (SHAKE-128f)"
                  << std::setw(10) << std::to_string(cs_cert.public_key.size()) + " B"
                  << std::setw(12) << std::to_string(cs_cert.signature.size()) + " B" << std::endl;
        std::cout << "  " << std::setw(25) << "Document (SHAKE-128s)"
                  << std::setw(10) << std::to_string(doc_cert.public_key.size()) + " B"
                  << std::setw(12) << std::to_string(doc_cert.signature.size()) + " B" << std::endl;

        std::cout << "\n  SLH-DSA Variant Comparison:" << std::endl;
        std::cout << "  - 'f' (fast): Larger signatures, faster signing" << std::endl;
        std::cout << "  - 's' (small): Smaller signatures, slower signing" << std::endl;

        std::cout << "\n  SLH-DSA is ideal for:" << std::endl;
        std::cout << "  - Root CA certificates (30+ year validity)" << std::endl;
        std::cout << "  - Code/firmware signing (decades of validity)" << std::endl;
        std::cout << "  - Legal documents (long-term archival)" << std::endl;
        std::cout << "  - Maximum security (hash-only assumptions)" << std::endl;

        std::cout << "\n" << std::string(60, '=') << std::endl;
        std::cout << "  Example completed successfully!" << std::endl;
        std::cout << std::string(60, '=') << std::endl;

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\nError: " << e.what() << std::endl;
        return 1;
    }
}
