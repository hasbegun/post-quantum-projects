/**
 * @file pqc_token.cpp
 * @brief Post-Quantum Cryptographic Token Creation Tool
 *
 * Creates JWT-like tokens using post-quantum digital signatures.
 *
 * Token Format:
 *     <base64url(header)>.<base64url(payload)>.<base64url(signature)>
 *
 * Usage:
 *     pqc_token_create --key <secret_key> --payload '{"sub": "user123"}'
 *     pqc_token_create --key <secret_key> --payload '{"role": "admin"}' --expires 3600
 *
 * Exit codes:
 *     0 - Success
 *     1 - Error
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <stdexcept>
#include <getopt.h>

#include "mldsa/mldsa.hpp"
#include "slhdsa/slh_dsa.hpp"

// Base64url alphabet
static const char BASE64URL_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/**
 * Encode bytes to base64url without padding
 */
std::string base64url_encode(const uint8_t* data, size_t length) {
    std::string result;
    result.reserve((length * 4 + 2) / 3);

    uint32_t val = 0;
    int bits = 0;

    for (size_t i = 0; i < length; i++) {
        val = (val << 8) | data[i];
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            result += BASE64URL_CHARS[(val >> bits) & 0x3F];
        }
    }

    if (bits > 0) {
        val <<= (6 - bits);
        result += BASE64URL_CHARS[val & 0x3F];
    }

    return result;
}

/**
 * Encode string to base64url
 */
std::string base64url_encode(const std::string& str) {
    return base64url_encode(reinterpret_cast<const uint8_t*>(str.data()), str.length());
}

// Read binary file
std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + path);
    }
    return std::vector<uint8_t>(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()
    );
}

/**
 * Get algorithm name from key size
 */
std::string detect_algorithm(size_t key_size) {
    switch (key_size) {
        case 2560: return "mldsa44";
        case 4032: return "mldsa65";
        case 4896: return "mldsa87";
        default: return "";
    }
}

/**
 * Convert algorithm to uppercase for header
 */
std::string algorithm_upper(const std::string& alg) {
    std::string result;
    for (char c : alg) {
        result += toupper(c);
    }
    return result;
}

/**
 * Sign function template for ML-DSA
 */
template<typename DSA>
std::vector<uint8_t> sign_mldsa(const std::vector<uint8_t>& sk,
                                 const std::vector<uint8_t>& message,
                                 const std::vector<uint8_t>& ctx) {
    DSA dsa;
    return dsa.sign(sk, message, ctx);
}

void print_usage(const char* progname) {
    std::cout << "Post-Quantum Token Creation Tool\n\n"
              << "Usage: " << progname << " [OPTIONS]\n\n"
              << "Required:\n"
              << "  -k, --key FILE          Secret key file for signing\n"
              << "  -p, --payload JSON      Token payload as JSON string\n\n"
              << "Options:\n"
              << "  -a, --algorithm ALG     Signing algorithm (auto-detected)\n"
              << "  --expires SECONDS       Token expiration in seconds\n"
              << "  --issuer STRING         Token issuer (iss claim)\n"
              << "  --subject STRING        Token subject (sub claim)\n"
              << "  -h, --help              Show this help\n\n"
              << "Examples:\n"
              << "  " << progname << " -k keys/token_secret.key -p '{\"sub\": \"user123\"}'\n"
              << "  " << progname << " -k keys/token_secret.key -p '{\"role\": \"admin\"}' --expires 3600\n";
}

int main(int argc, char* argv[]) {
    std::string key_file;
    std::string payload;
    std::string algorithm;
    std::string issuer;
    std::string subject;
    int64_t expires_in = -1;

    static struct option long_options[] = {
        {"key", required_argument, 0, 'k'},
        {"payload", required_argument, 0, 'p'},
        {"algorithm", required_argument, 0, 'a'},
        {"expires", required_argument, 0, 'e'},
        {"issuer", required_argument, 0, 'i'},
        {"subject", required_argument, 0, 's'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "k:p:a:h", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'k':
                key_file = optarg;
                break;
            case 'p':
                payload = optarg;
                break;
            case 'a':
                algorithm = optarg;
                break;
            case 'e':
                expires_in = std::stoll(optarg);
                break;
            case 'i':
                issuer = optarg;
                break;
            case 's':
                subject = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // Validate required arguments
    if (key_file.empty()) {
        std::cerr << "Error: Secret key is required (-k/--key)\n";
        return 1;
    }
    if (payload.empty()) {
        std::cerr << "Error: Payload is required (-p/--payload)\n";
        return 1;
    }

    try {
        // Read secret key
        auto secret_key = read_file(key_file);

        // Auto-detect algorithm
        if (algorithm.empty()) {
            algorithm = detect_algorithm(secret_key.size());
            if (algorithm.empty()) {
                std::cerr << "Error: Cannot detect algorithm from key size: "
                          << secret_key.size() << "\n";
                return 1;
            }
        }

        // Get current time
        time_t now = time(nullptr);

        // Build payload JSON with claims
        // Note: This is a simplified JSON builder - for production use a proper JSON library
        std::string full_payload = payload;

        // Remove closing brace to add claims
        if (full_payload.back() == '}') {
            full_payload.pop_back();

            // Add iat claim
            full_payload += ",\"iat\":" + std::to_string(now);

            // Add exp claim if specified
            if (expires_in >= 0) {
                full_payload += ",\"exp\":" + std::to_string(now + expires_in);
            }

            // Add issuer if specified
            if (!issuer.empty()) {
                full_payload += ",\"iss\":\"" + issuer + "\"";
            }

            // Add subject if specified
            if (!subject.empty()) {
                full_payload += ",\"sub\":\"" + subject + "\"";
            }

            full_payload += "}";
        }

        // Build header JSON
        std::string header = "{\"alg\":\"" + algorithm_upper(algorithm) + "\",\"typ\":\"PQT\"}";

        // Base64url encode header and payload
        std::string header_b64 = base64url_encode(header);
        std::string payload_b64 = base64url_encode(full_payload);

        // Create signing input
        std::string signing_input = header_b64 + "." + payload_b64;
        std::vector<uint8_t> message(signing_input.begin(), signing_input.end());

        // Prepare context
        std::string ctx_str = "pqc-token";
        std::vector<uint8_t> ctx(ctx_str.begin(), ctx_str.end());

        // Sign with appropriate algorithm
        std::vector<uint8_t> signature;

        if (algorithm == "mldsa44") {
            signature = sign_mldsa<mldsa::MLDSA44>(secret_key, message, ctx);
        } else if (algorithm == "mldsa65") {
            signature = sign_mldsa<mldsa::MLDSA65>(secret_key, message, ctx);
        } else if (algorithm == "mldsa87") {
            signature = sign_mldsa<mldsa::MLDSA87>(secret_key, message, ctx);
        } else {
            std::cerr << "Error: Unsupported algorithm: " << algorithm << "\n";
            return 1;
        }

        // Base64url encode signature
        std::string signature_b64 = base64url_encode(signature.data(), signature.size());

        // Output token
        std::cout << header_b64 << "." << payload_b64 << "." << signature_b64 << "\n";

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
