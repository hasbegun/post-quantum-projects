/**
 * Fuzz target for ML-KEM encapsulation
 *
 * Tests that malformed encapsulation keys don't cause crashes or memory corruption.
 * This complements fuzz_mlkem_decaps by testing the encapsulation path.
 * Run with: ./fuzz_mlkem_encaps -max_len=2000 -timeout=5
 */

#include <cstdint>
#include <cstddef>
#include <vector>
#include <span>

#include "mlkem/mlkem.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2) return 0;

    // Use first byte to select parameter set
    int param_set = data[0] % 3;
    std::span<const uint8_t> fuzz_ek(data + 1, size - 1);

    try {
        switch (param_set) {
            case 0: {
                mlkem::MLKEM512 kem;
                // Test encapsulation with potentially malformed public key
                if (fuzz_ek.size() == 800) {  // Correct EK size for 512
                    std::vector<uint8_t> ek(fuzz_ek.begin(), fuzz_ek.end());
                    auto [ct, ss] = kem.encaps(ek);
                    // Use the outputs to prevent optimization
                    volatile uint8_t sink = ct[0] ^ ss[0];
                    (void)sink;
                }
                break;
            }
            case 1: {
                mlkem::MLKEM768 kem;
                if (fuzz_ek.size() == 1184) {  // Correct EK size for 768
                    std::vector<uint8_t> ek(fuzz_ek.begin(), fuzz_ek.end());
                    auto [ct, ss] = kem.encaps(ek);
                    volatile uint8_t sink = ct[0] ^ ss[0];
                    (void)sink;
                }
                break;
            }
            case 2: {
                mlkem::MLKEM1024 kem;
                if (fuzz_ek.size() == 1568) {  // Correct EK size for 1024
                    std::vector<uint8_t> ek(fuzz_ek.begin(), fuzz_ek.end());
                    auto [ct, ss] = kem.encaps(ek);
                    volatile uint8_t sink = ct[0] ^ ss[0];
                    (void)sink;
                }
                break;
            }
        }
    } catch (const std::exception&) {
        // Exceptions are OK for invalid keys
    }

    return 0;
}
