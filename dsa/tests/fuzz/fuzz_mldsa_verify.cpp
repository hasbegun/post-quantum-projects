/**
 * Fuzz target for ML-DSA signature verification
 *
 * Tests that malformed signatures don't cause crashes, hangs, or memory corruption.
 * Run with: ./fuzz_mldsa_verify -max_len=10000 -timeout=5
 */

#include <cstdint>
#include <cstddef>
#include <vector>
#include <span>

#include "mldsa/mldsa.hpp"

// Pre-generated valid key pair (generated once at startup)
static std::vector<uint8_t> g_pk;
static std::vector<uint8_t> g_sk;
static bool g_initialized = false;

static void init_keys() {
    if (g_initialized) return;

    mldsa::MLDSA dsa(mldsa::MLDSA65_PARAMS);
    auto [pk, sk] = dsa.keygen();
    g_pk = std::move(pk);
    g_sk = std::move(sk);
    g_initialized = true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    init_keys();

    // Split fuzz input: first part is "message", rest is "signature"
    if (size < 10) return 0;  // Need some data

    size_t msg_len = size / 4;  // Use 1/4 for message
    size_t sig_len = size - msg_len;

    std::span<const uint8_t> message(data, msg_len);
    std::span<const uint8_t> signature(data + msg_len, sig_len);

    // Test all parameter sets
    for (const auto* params : {&mldsa::MLDSA44_PARAMS, &mldsa::MLDSA65_PARAMS, &mldsa::MLDSA87_PARAMS}) {
        mldsa::MLDSA dsa(*params);

        try {
            // This should never crash, even with garbage input
            volatile bool result = dsa.verify(g_pk, message, signature);
            (void)result;
        } catch (const std::exception&) {
            // Exceptions are OK (e.g., invalid input length)
        }
    }

    return 0;
}
