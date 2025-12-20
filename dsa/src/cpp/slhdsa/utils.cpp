/**
 * SLH-DSA Utility Functions Implementation
 */

#include "utils.hpp"
#include <openssl/rand.h>
#include <stdexcept>

namespace slhdsa {

std::vector<uint8_t> random_bytes(size_t n) {
    std::vector<uint8_t> buffer(n);
    if (RAND_bytes(buffer.data(), static_cast<int>(n)) != 1) {
        throw std::runtime_error("Failed to generate random bytes");
    }
    return buffer;
}

} // namespace slhdsa
