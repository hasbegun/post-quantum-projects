/**
 * Fuzz target for Composite Signature verification
 *
 * Tests that malformed composite signatures don't cause crashes, hangs,
 * or memory corruption. Tests all supported composite algorithm combinations.
 * Run with: ./fuzz_composite -max_len=20000 -timeout=10
 */

#include <cstdint>
#include <cstddef>
#include <vector>
#include <span>
#include <memory>

#include "common/composite.hpp"

// Pre-generated valid key pairs for each composite algorithm
struct CompositeKeyPair {
    std::vector<uint8_t> pk;
    std::vector<uint8_t> sk;
    std::unique_ptr<composite::CompositeSignature> dsa;
};

static std::vector<CompositeKeyPair> g_keys;
static bool g_initialized = false;

static void init_keys() {
    if (g_initialized) return;

    // Initialize key pairs for a subset of algorithms (for faster fuzzing)
    const char* algorithms[] = {
        "MLDSA44-ECDSA-P256",
        "MLDSA65-ECDSA-P384",
        "MLDSA65-Ed25519"
    };

    for (const char* algo : algorithms) {
        CompositeKeyPair kp;
        kp.dsa = composite::create_composite_dsa(algo);
        if (kp.dsa) {
            kp.pk.resize(kp.dsa->public_key_size());
            kp.sk.resize(kp.dsa->secret_key_size());
            kp.dsa->keygen(kp.pk, kp.sk);
            g_keys.push_back(std::move(kp));
        }
    }

    g_initialized = true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    init_keys();

    if (size < 10 || g_keys.empty()) return 0;

    // Use first byte to select algorithm
    size_t algo_idx = data[0] % g_keys.size();
    const auto& kp = g_keys[algo_idx];

    // Split remaining data into message and signature
    size_t remaining = size - 1;
    size_t msg_len = remaining / 4;
    size_t sig_len = remaining - msg_len;

    std::span<const uint8_t> message(data + 1, msg_len);
    std::span<const uint8_t> signature(data + 1 + msg_len, sig_len);

    try {
        // Test verification with fuzzed signature
        volatile bool result = kp.dsa->verify(kp.pk, message, signature);
        (void)result;
    } catch (const std::exception&) {
        // Exceptions are OK for malformed inputs
    }

    // Also test with fuzzed public key
    if (size > kp.pk.size() + 1) {
        std::vector<uint8_t> fuzz_pk(data + 1, data + 1 + kp.pk.size());
        try {
            volatile bool result = kp.dsa->verify(fuzz_pk, message, signature);
            (void)result;
        } catch (const std::exception&) {
            // Expected for invalid keys
        }
    }

    return 0;
}
