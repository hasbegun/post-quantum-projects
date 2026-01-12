/**
 * Fuzz target for SLH-DSA signature verification
 *
 * Tests that malformed signatures don't cause crashes, hangs, or memory corruption.
 * Run with: ./fuzz_slhdsa_verify -max_len=50000 -timeout=30
 */

#include <cstdint>
#include <cstddef>
#include <vector>
#include <span>

#include "slhdsa/slh_dsa.hpp"

// Pre-generated valid key pair
static std::vector<uint8_t> g_pk;
static std::vector<uint8_t> g_sk;
static bool g_initialized = false;

static void init_keys() {
    if (g_initialized) return;

    slhdsa::SLHDSA_SHAKE_128f dsa;
    auto [pk, sk] = dsa.keygen();
    g_pk = std::move(pk);
    g_sk = std::move(sk);
    g_initialized = true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    init_keys();

    if (size < 10) return 0;

    size_t msg_len = size / 4;
    size_t sig_len = size - msg_len;

    std::span<const uint8_t> message(data, msg_len);
    std::span<const uint8_t> signature(data + msg_len, sig_len);

    // Test SHAKE-128f (fastest variant for fuzzing)
    slhdsa::SLHDSA_SHAKE_128f dsa;

    try {
        volatile bool result = dsa.verify(g_pk, message, signature);
        (void)result;
    } catch (const std::exception&) {
        // Exceptions are OK
    }

    return 0;
}
