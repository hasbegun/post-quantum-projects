/**
 * Post-Quantum DSA Demo
 * Demonstrates ML-DSA (FIPS 204) and SLH-DSA (FIPS 205)
 * Key generation, signing, and verification
 */

#include "mldsa/mldsa.hpp"
#include "slhdsa/slh_dsa.hpp"
#include <iostream>
#include <iomanip>
#include <string>
#include <chrono>

void print_hex(const std::vector<uint8_t>& data, size_t max_len = 32) {
    for (size_t i = 0; i < std::min(data.size(), max_len); ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]);
    }
    if (data.size() > max_len) {
        std::cout << "...";
    }
    std::cout << std::dec;
}

template<typename DSA>
void demo_mldsa(const std::string& name) {
    std::cout << "\n=== " << name << " Demo ===" << std::endl;

    DSA dsa;
    const auto& params = dsa.params();

    std::cout << "\nParameter set: " << params.name << std::endl;
    std::cout << "  k = " << params.k << ", l = " << params.l << std::endl;
    std::cout << "  eta = " << params.eta << ", tau = " << params.tau << std::endl;
    std::cout << "  Security level: " << params.lambda << " bits" << std::endl;

    // Generate keys
    std::cout << "\n1. Generating key pair..." << std::endl;
    auto [pk, sk] = dsa.keygen();
    std::cout << "   Public key size: " << pk.size() << " bytes" << std::endl;
    std::cout << "   Secret key size: " << sk.size() << " bytes" << std::endl;
    std::cout << "   Public key (first 32 bytes): ";
    print_hex(pk);
    std::cout << std::endl;

    // Sign a message
    std::string message_str = "Hello, ML-DSA! This is a test message for post-quantum signatures.";
    std::vector<uint8_t> message(message_str.begin(), message_str.end());

    std::cout << "\n2. Signing message..." << std::endl;
    std::cout << "   Message: \"" << message_str << "\"" << std::endl;

    auto signature = dsa.sign(sk, message);
    std::cout << "   Signature size: " << signature.size() << " bytes" << std::endl;
    std::cout << "   Signature (first 32 bytes): ";
    print_hex(signature);
    std::cout << std::endl;

    // Verify signature
    std::cout << "\n3. Verifying signature..." << std::endl;
    bool valid = dsa.verify(pk, message, signature);
    std::cout << "   Valid: " << (valid ? "YES" : "NO") << std::endl;

    // Test with modified message
    std::cout << "\n4. Testing with modified message..." << std::endl;
    std::vector<uint8_t> modified_message = message;
    modified_message[0] ^= 0x01;  // Flip one bit
    bool invalid = dsa.verify(pk, modified_message, signature);
    std::cout << "   Valid (should be NO): " << (invalid ? "YES" : "NO") << std::endl;

    // Deterministic signing
    std::cout << "\n5. Deterministic signing test..." << std::endl;
    auto sig1 = dsa.sign(sk, message, {}, true);
    auto sig2 = dsa.sign(sk, message, {}, true);
    std::cout << "   Signatures match: " << (sig1 == sig2 ? "YES" : "NO") << std::endl;

    // Context string
    std::cout << "\n6. Signing with context string..." << std::endl;
    std::vector<uint8_t> ctx = {'m', 'y', '-', 'a', 'p', 'p'};
    auto ctx_sig = dsa.sign(sk, message, ctx);
    bool ctx_valid = dsa.verify(pk, message, ctx_sig, ctx);
    std::cout << "   Valid with correct context: " << (ctx_valid ? "YES" : "NO") << std::endl;

    std::vector<uint8_t> wrong_ctx = {'o', 't', 'h', 'e', 'r'};
    bool wrong_ctx_valid = dsa.verify(pk, message, ctx_sig, wrong_ctx);
    std::cout << "   Valid with wrong context (should be NO): "
              << (wrong_ctx_valid ? "YES" : "NO") << std::endl;
}

template<typename DSA>
void demo_slhdsa(const std::string& name) {
    std::cout << "\n=== " << name << " Demo ===" << std::endl;

    DSA dsa;
    const auto& params = dsa.params();

    std::cout << "\nParameter set: " << params.name << std::endl;
    std::cout << "  n = " << params.n << " (security parameter)" << std::endl;
    std::cout << "  h = " << params.h << " (tree height)" << std::endl;
    std::cout << "  d = " << params.d << " (hypertree layers)" << std::endl;
    std::cout << "  k = " << params.k << ", a = " << params.a << " (FORS parameters)" << std::endl;
    std::cout << "  Hash type: " << (params.hash_type == slhdsa::HashType::SHAKE ? "SHAKE" : "SHA2") << std::endl;

    // Generate keys
    std::cout << "\n1. Generating key pair..." << std::endl;
    auto start = std::chrono::high_resolution_clock::now();
    auto [sk, pk] = dsa.keygen();
    auto end = std::chrono::high_resolution_clock::now();
    auto keygen_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::cout << "   Public key size: " << pk.size() << " bytes" << std::endl;
    std::cout << "   Secret key size: " << sk.size() << " bytes" << std::endl;
    std::cout << "   KeyGen time: " << keygen_ms << " ms" << std::endl;
    std::cout << "   Public key (first 32 bytes): ";
    print_hex(pk);
    std::cout << std::endl;

    // Sign a message
    std::string message_str = "Hello, SLH-DSA! This is a test message for hash-based signatures.";
    std::vector<uint8_t> message(message_str.begin(), message_str.end());

    std::cout << "\n2. Signing message..." << std::endl;
    std::cout << "   Message: \"" << message_str << "\"" << std::endl;

    start = std::chrono::high_resolution_clock::now();
    auto signature = dsa.sign(sk, message);
    end = std::chrono::high_resolution_clock::now();
    auto sign_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::cout << "   Signature size: " << signature.size() << " bytes" << std::endl;
    std::cout << "   Sign time: " << sign_ms << " ms" << std::endl;
    std::cout << "   Signature (first 32 bytes): ";
    print_hex(signature);
    std::cout << std::endl;

    // Verify signature
    std::cout << "\n3. Verifying signature..." << std::endl;
    start = std::chrono::high_resolution_clock::now();
    bool valid = dsa.verify(pk, message, signature);
    end = std::chrono::high_resolution_clock::now();
    auto verify_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::cout << "   Valid: " << (valid ? "YES" : "NO") << std::endl;
    std::cout << "   Verify time: " << verify_ms << " ms" << std::endl;

    // Test with modified message
    std::cout << "\n4. Testing with modified message..." << std::endl;
    std::vector<uint8_t> modified_message = message;
    modified_message[0] ^= 0x01;  // Flip one bit
    bool invalid = dsa.verify(pk, modified_message, signature);
    std::cout << "   Valid (should be NO): " << (invalid ? "YES" : "NO") << std::endl;

    // Deterministic signing
    std::cout << "\n5. Deterministic signing test..." << std::endl;
    auto sig1 = dsa.sign(sk, message, {}, false);  // deterministic = false means randomize=false
    auto sig2 = dsa.sign(sk, message, {}, false);
    std::cout << "   Signatures match: " << (sig1 == sig2 ? "YES" : "NO") << std::endl;

    // Context string
    std::cout << "\n6. Signing with context string..." << std::endl;
    std::vector<uint8_t> ctx = {'m', 'y', '-', 'a', 'p', 'p'};
    auto ctx_sig = dsa.sign(sk, message, ctx);
    bool ctx_valid = dsa.verify(pk, message, ctx_sig, ctx);
    std::cout << "   Valid with correct context: " << (ctx_valid ? "YES" : "NO") << std::endl;

    std::vector<uint8_t> wrong_ctx = {'o', 't', 'h', 'e', 'r'};
    bool wrong_ctx_valid = dsa.verify(pk, message, ctx_sig, wrong_ctx);
    std::cout << "   Valid with wrong context (should be NO): "
              << (wrong_ctx_valid ? "YES" : "NO") << std::endl;
}

void print_comparison() {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "  Algorithm Comparison" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    std::cout << "\n  ML-DSA (FIPS 204) - Lattice-Based:" << std::endl;
    std::cout << "  + Fast signing and verification" << std::endl;
    std::cout << "  + Smaller signatures (~2-5 KB)" << std::endl;
    std::cout << "  - Larger public keys (~1-3 KB)" << std::endl;
    std::cout << "  Best for: APIs, real-time systems, blockchain" << std::endl;

    std::cout << "\n  SLH-DSA (FIPS 205) - Hash-Based:" << std::endl;
    std::cout << "  + Tiny public keys (32-64 bytes)" << std::endl;
    std::cout << "  + Security based only on hash functions" << std::endl;
    std::cout << "  - Larger signatures (~7-50 KB)" << std::endl;
    std::cout << "  - Slower signing" << std::endl;
    std::cout << "  Best for: Root CAs, firmware, long-term documents" << std::endl;

    std::cout << "\n  Size Comparison (128-bit security):" << std::endl;
    std::cout << std::setfill(' ');  // Reset fill character
    std::cout << "  " << std::setw(20) << "Algorithm" << std::setw(12) << "PK Size"
              << std::setw(12) << "SK Size" << std::setw(12) << "Sig Size" << std::endl;
    std::cout << "  " << std::string(56, '-') << std::endl;
    std::cout << "  " << std::setw(20) << "ML-DSA-44" << std::setw(12) << "1,312 B"
              << std::setw(12) << "2,560 B" << std::setw(12) << "2,420 B" << std::endl;
    std::cout << "  " << std::setw(20) << "SLH-DSA-SHAKE-128f" << std::setw(12) << "32 B"
              << std::setw(12) << "64 B" << std::setw(12) << "17,088 B" << std::endl;
}

int main() {
    std::cout << std::string(60, '=') << std::endl;
    std::cout << "  Post-Quantum Digital Signatures Demo" << std::endl;
    std::cout << "  ML-DSA (FIPS 204) & SLH-DSA (FIPS 205)" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    try {
        // ML-DSA demos
        std::cout << "\n" << std::string(60, '-') << std::endl;
        std::cout << "  ML-DSA (Module-Lattice Digital Signature Algorithm)" << std::endl;
        std::cout << std::string(60, '-') << std::endl;

        demo_mldsa<mldsa::MLDSA44>("ML-DSA-44 (Security Category 2)");

        // SLH-DSA demos
        std::cout << "\n" << std::string(60, '-') << std::endl;
        std::cout << "  SLH-DSA (Stateless Hash-Based Digital Signature)" << std::endl;
        std::cout << std::string(60, '-') << std::endl;

        demo_slhdsa<slhdsa::SLHDSA_SHAKE_128f>("SLH-DSA-SHAKE-128f (Fast, 128-bit security)");

        // Comparison
        print_comparison();

        std::cout << "\n" << std::string(60, '=') << std::endl;
        std::cout << "  All demos completed successfully!" << std::endl;
        std::cout << std::string(60, '=') << std::endl;

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\nError: " << e.what() << std::endl;
        return 1;
    }
}
