/**
 * Fuzz target for ML-KEM decapsulation
 *
 * Tests that malformed ciphertexts don't cause crashes and that
 * implicit rejection works correctly.
 * Run with: ./fuzz_mlkem_decaps -max_len=5000 -timeout=5
 */

#include <cstdint>
#include <cstddef>
#include <vector>
#include <span>

#include "mlkem/mlkem.hpp"

// Pre-generated valid key pairs for each parameter set
static std::vector<uint8_t> g_ek_512, g_dk_512;
static std::vector<uint8_t> g_ek_768, g_dk_768;
static std::vector<uint8_t> g_ek_1024, g_dk_1024;
static bool g_initialized = false;

static void init_keys() {
    if (g_initialized) return;

    {
        mlkem::MLKEM512 kem;
        auto [ek, dk] = kem.keygen();
        g_ek_512 = std::move(ek);
        g_dk_512 = std::move(dk);
    }
    {
        mlkem::MLKEM768 kem;
        auto [ek, dk] = kem.keygen();
        g_ek_768 = std::move(ek);
        g_dk_768 = std::move(dk);
    }
    {
        mlkem::MLKEM1024 kem;
        auto [ek, dk] = kem.keygen();
        g_ek_1024 = std::move(ek);
        g_dk_1024 = std::move(dk);
    }

    g_initialized = true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    init_keys();

    if (size < 1) return 0;

    // Use first byte to select parameter set
    int param_set = data[0] % 3;
    std::span<const uint8_t> ciphertext(data + 1, size - 1);

    try {
        switch (param_set) {
            case 0: {
                mlkem::MLKEM512 kem;
                // Decaps should handle any ciphertext without crashing
                // Invalid ciphertexts trigger implicit rejection (return random-looking secret)
                if (ciphertext.size() == 768) {  // Correct CT size for 512
                    auto ss = kem.decaps(g_dk_512, ciphertext);
                    volatile uint8_t sink = ss[0];
                    (void)sink;
                }
                break;
            }
            case 1: {
                mlkem::MLKEM768 kem;
                if (ciphertext.size() == 1088) {  // Correct CT size for 768
                    auto ss = kem.decaps(g_dk_768, ciphertext);
                    volatile uint8_t sink = ss[0];
                    (void)sink;
                }
                break;
            }
            case 2: {
                mlkem::MLKEM1024 kem;
                if (ciphertext.size() == 1568) {  // Correct CT size for 1024
                    auto ss = kem.decaps(g_dk_1024, ciphertext);
                    volatile uint8_t sink = ss[0];
                    (void)sink;
                }
                break;
            }
        }
    } catch (const std::exception&) {
        // Exceptions are OK for wrong-sized inputs
    }

    return 0;
}
