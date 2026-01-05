/**
 * ML-KEM Demo
 * Demonstrates post-quantum key encapsulation using ML-KEM (FIPS 203)
 */

#include "mlkem/mlkem.hpp"
#include <iostream>
#include <iomanip>

using namespace mlkem;

void print_hex(const std::vector<uint8_t>& data, size_t max_bytes = 32) {
    size_t to_print = std::min(data.size(), max_bytes);
    for (size_t i = 0; i < to_print; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(data[i]);
    }
    if (data.size() > max_bytes) {
        std::cout << "...";
    }
    std::cout << std::dec;
}

template<typename KEM>
void demo_kem(const std::string& name) {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << name << " Key Encapsulation Demo" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    KEM kem;

    // Alice generates key pair
    std::cout << "\n[1] Alice generates key pair..." << std::endl;
    auto [ek, dk] = kem.keygen();
    std::cout << "    Encapsulation Key (public): " << ek.size() << " bytes" << std::endl;
    std::cout << "    Decapsulation Key (secret): " << dk.size() << " bytes" << std::endl;
    std::cout << "    EK prefix: ";
    print_hex(ek, 16);
    std::cout << std::endl;

    // Bob encapsulates using Alice's public key
    std::cout << "\n[2] Bob encapsulates using Alice's public key..." << std::endl;
    auto [K_bob, ciphertext] = kem.encaps(ek);
    std::cout << "    Ciphertext: " << ciphertext.size() << " bytes" << std::endl;
    std::cout << "    Shared Secret (Bob): ";
    print_hex(K_bob);
    std::cout << std::endl;

    // Alice decapsulates using her secret key
    std::cout << "\n[3] Alice decapsulates using her secret key..." << std::endl;
    auto K_alice = kem.decaps(dk, ciphertext);
    std::cout << "    Shared Secret (Alice): ";
    print_hex(K_alice);
    std::cout << std::endl;

    // Verify both have the same shared secret
    bool match = (K_bob == K_alice);
    std::cout << "\n[4] Shared secrets match: " << (match ? "YES" : "NO") << std::endl;

    // Demonstrate implicit rejection
    std::cout << "\n[5] Testing implicit rejection (tampered ciphertext)..." << std::endl;
    std::vector<uint8_t> tampered = ciphertext;
    tampered[0] ^= 0xFF;  // Flip bits in first byte

    auto K_tampered = kem.decaps(dk, tampered);
    bool tamper_detected = (K_tampered != K_bob);
    std::cout << "    Tampered ciphertext rejected: " << (tamper_detected ? "YES" : "NO") << std::endl;
    std::cout << "    Returned pseudorandom value: ";
    print_hex(K_tampered);
    std::cout << std::endl;
}

int main() {
    std::cout << std::string(60, '=') << std::endl;
    std::cout << "    Post-Quantum Key Encapsulation (ML-KEM / FIPS 203)" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    std::cout << "\nML-KEM provides quantum-resistant key exchange using" << std::endl;
    std::cout << "Module-Lattice-Based cryptography (MLWE problem)." << std::endl;
    std::cout << "\nUse cases:" << std::endl;
    std::cout << "  - TLS key exchange" << std::endl;
    std::cout << "  - Hybrid encryption (ML-KEM + AES)" << std::endl;
    std::cout << "  - Key wrapping" << std::endl;

    // Demo all three parameter sets
    demo_kem<MLKEM512>("ML-KEM-512 (Category 1, 128-bit)");
    demo_kem<MLKEM768>("ML-KEM-768 (Category 3, 192-bit)");
    demo_kem<MLKEM1024>("ML-KEM-1024 (Category 5, 256-bit)");

    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "Parameter Set Comparison:" << std::endl;
    std::cout << std::string(60, '-') << std::endl;
    std::cout << std::left << std::setw(15) << "Parameter"
              << std::setw(15) << "EK (bytes)"
              << std::setw(15) << "DK (bytes)"
              << std::setw(15) << "CT (bytes)"
              << std::endl;
    std::cout << std::string(60, '-') << std::endl;

    std::cout << std::setw(15) << "ML-KEM-512"
              << std::setw(15) << MLKEM512_PARAMS.ek_size()
              << std::setw(15) << MLKEM512_PARAMS.dk_size()
              << std::setw(15) << MLKEM512_PARAMS.ct_size()
              << std::endl;

    std::cout << std::setw(15) << "ML-KEM-768"
              << std::setw(15) << MLKEM768_PARAMS.ek_size()
              << std::setw(15) << MLKEM768_PARAMS.dk_size()
              << std::setw(15) << MLKEM768_PARAMS.ct_size()
              << std::endl;

    std::cout << std::setw(15) << "ML-KEM-1024"
              << std::setw(15) << MLKEM1024_PARAMS.ek_size()
              << std::setw(15) << MLKEM1024_PARAMS.dk_size()
              << std::setw(15) << MLKEM1024_PARAMS.ct_size()
              << std::endl;

    std::cout << std::string(60, '=') << std::endl;
    std::cout << "ML-KEM: Post-quantum key exchange for the future!" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    return 0;
}
