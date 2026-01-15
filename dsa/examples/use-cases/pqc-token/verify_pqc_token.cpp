/**
 * @file verify_pqc_token.cpp
 * @brief Post-Quantum Cryptographic Token Verification Tool
 *
 * Verifies JWT-like tokens using post-quantum digital signatures.
 *
 * Usage:
 *     pqc_token_verify --key <public_key> --token <token_string>
 *
 * Exit codes:
 *     0 - Token valid
 *     1 - Token invalid (signature, expired, etc.)
 *     2 - Input error
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

// Base64url decode table
static const int BASE64URL_DECODE[256] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,
    52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
    15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,63,
    -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
    41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
};

/**
 * Decode base64url string
 */
std::vector<uint8_t> base64url_decode(const std::string& input) {
    std::vector<uint8_t> result;
    result.reserve(input.length() * 3 / 4);

    uint32_t val = 0;
    int bits = 0;

    for (char c : input) {
        if (c == '=') break;

        int v = BASE64URL_DECODE[static_cast<uint8_t>(c)];
        if (v < 0) continue;

        val = (val << 6) | v;
        bits += 6;

        if (bits >= 8) {
            bits -= 8;
            result.push_back((val >> bits) & 0xFF);
        }
    }

    return result;
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
 * Get algorithm name from public key size
 */
std::string detect_algorithm(size_t key_size) {
    switch (key_size) {
        case 1312: return "mldsa44";
        case 1952: return "mldsa65";
        case 2592: return "mldsa87";
        default: return "";
    }
}

/**
 * Convert string to lowercase
 */
std::string to_lower(const std::string& str) {
    std::string result;
    for (char c : str) {
        result += tolower(c);
    }
    return result;
}

/**
 * Simple JSON value extraction (for demonstration - use proper JSON library in production)
 */
std::string extract_json_string(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":\"";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return "";

    pos += search.length();
    size_t end = json.find("\"", pos);
    if (end == std::string::npos) return "";

    return json.substr(pos, end - pos);
}

/**
 * Extract JSON number value
 */
int64_t extract_json_number(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":";
    size_t pos = json.find(search);
    if (pos == std::string::npos) return -1;

    pos += search.length();

    // Skip whitespace
    while (pos < json.length() && isspace(json[pos])) pos++;

    // Parse number
    std::string num_str;
    while (pos < json.length() && (isdigit(json[pos]) || json[pos] == '-')) {
        num_str += json[pos++];
    }

    if (num_str.empty()) return -1;
    return std::stoll(num_str);
}

/**
 * Verify function template for ML-DSA
 */
template<typename DSA>
bool verify_mldsa(const std::vector<uint8_t>& pk,
                  const std::vector<uint8_t>& message,
                  const std::vector<uint8_t>& signature,
                  const std::vector<uint8_t>& ctx) {
    DSA dsa;
    return dsa.verify(pk, message, signature, ctx);
}

void print_usage(const char* progname) {
    std::cout << "Post-Quantum Token Verification Tool\n\n"
              << "Usage: " << progname << " [OPTIONS]\n\n"
              << "Required:\n"
              << "  -k, --key FILE          Public key file\n"
              << "  -t, --token STRING      Token to verify\n\n"
              << "Options:\n"
              << "  -a, --algorithm ALG     Expected algorithm (auto-detected)\n"
              << "  --no-exp                Skip expiration check\n"
              << "  --leeway SECONDS        Clock skew allowance\n"
              << "  -q, --quiet             Exit code only\n"
              << "  -h, --help              Show this help\n\n"
              << "Exit Codes:\n"
              << "  0 - Token valid\n"
              << "  1 - Token invalid\n"
              << "  2 - Input error\n\n"
              << "Examples:\n"
              << "  " << progname << " -k keys/token_public.key -t \"eyJhbGciOi...\"\n";
}

int main(int argc, char* argv[]) {
    std::string key_file;
    std::string token;
    std::string algorithm;
    bool no_exp = false;
    int64_t leeway = 0;
    bool quiet = false;

    static struct option long_options[] = {
        {"key", required_argument, 0, 'k'},
        {"token", required_argument, 0, 't'},
        {"algorithm", required_argument, 0, 'a'},
        {"no-exp", no_argument, 0, 'n'},
        {"leeway", required_argument, 0, 'l'},
        {"quiet", no_argument, 0, 'q'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "k:t:a:qh", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'k':
                key_file = optarg;
                break;
            case 't':
                token = optarg;
                break;
            case 'a':
                algorithm = optarg;
                break;
            case 'n':
                no_exp = true;
                break;
            case 'l':
                leeway = std::stoll(optarg);
                break;
            case 'q':
                quiet = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 2;
        }
    }

    // Validate required arguments
    if (key_file.empty()) {
        std::cerr << "Error: Public key is required (-k/--key)\n";
        return 2;
    }
    if (token.empty()) {
        std::cerr << "Error: Token is required (-t/--token)\n";
        return 2;
    }

    try {
        // Read public key
        auto public_key = read_file(key_file);

        // Auto-detect algorithm
        if (algorithm.empty()) {
            algorithm = detect_algorithm(public_key.size());
            if (algorithm.empty()) {
                std::cerr << "Error: Cannot detect algorithm from key size: "
                          << public_key.size() << "\n";
                return 2;
            }
        }

        // Parse token (header.payload.signature)
        size_t dot1 = token.find('.');
        size_t dot2 = token.find('.', dot1 + 1);

        if (dot1 == std::string::npos || dot2 == std::string::npos) {
            std::cerr << "Error: Invalid token format\n";
            return 2;
        }

        std::string header_b64 = token.substr(0, dot1);
        std::string payload_b64 = token.substr(dot1 + 1, dot2 - dot1 - 1);
        std::string signature_b64 = token.substr(dot2 + 1);

        // Decode parts
        std::vector<uint8_t> header_bytes = base64url_decode(header_b64);
        std::vector<uint8_t> payload_bytes = base64url_decode(payload_b64);
        std::vector<uint8_t> signature = base64url_decode(signature_b64);

        std::string header(header_bytes.begin(), header_bytes.end());
        std::string payload(payload_bytes.begin(), payload_bytes.end());

        // Verify token type
        std::string typ = extract_json_string(header, "typ");
        if (typ != "PQT") {
            if (!quiet) {
                std::cerr << "Error: Invalid token type: " << typ << "\n";
            }
            return 1;
        }

        // Verify algorithm matches
        std::string token_alg = to_lower(extract_json_string(header, "alg"));
        if (token_alg != algorithm) {
            if (!quiet) {
                std::cerr << "Error: Algorithm mismatch - expected " << algorithm
                          << ", got " << token_alg << "\n";
            }
            return 1;
        }

        // Prepare signing input and context
        std::string signing_input = header_b64 + "." + payload_b64;
        std::vector<uint8_t> message(signing_input.begin(), signing_input.end());

        std::string ctx_str = "pqc-token";
        std::vector<uint8_t> ctx(ctx_str.begin(), ctx_str.end());

        // Verify signature with appropriate algorithm
        bool valid = false;

        if (algorithm == "mldsa44") {
            valid = verify_mldsa<mldsa::MLDSA44>(public_key, message, signature, ctx);
        } else if (algorithm == "mldsa65") {
            valid = verify_mldsa<mldsa::MLDSA65>(public_key, message, signature, ctx);
        } else if (algorithm == "mldsa87") {
            valid = verify_mldsa<mldsa::MLDSA87>(public_key, message, signature, ctx);
        } else {
            if (!quiet) {
                std::cerr << "Error: Unsupported algorithm: " << algorithm << "\n";
            }
            return 2;
        }

        if (!valid) {
            if (!quiet) {
                std::cerr << "Error: Invalid signature\n";
            }
            return 1;
        }

        // Check expiration
        if (!no_exp) {
            int64_t exp = extract_json_number(payload, "exp");
            if (exp > 0) {
                time_t now = time(nullptr);
                if (now > exp + leeway) {
                    if (!quiet) {
                        std::cerr << "Error: Token has expired\n";
                    }
                    return 1;
                }
            }
        }

        // Token is valid
        if (!quiet) {
            std::cout << "Token verification result:\n";
            std::cout << "  Status:    VALID\n";
            std::cout << "  Algorithm: " << token_alg << "\n";

            // Print claims
            std::string sub = extract_json_string(payload, "sub");
            std::string iss = extract_json_string(payload, "iss");
            int64_t iat = extract_json_number(payload, "iat");
            int64_t exp = extract_json_number(payload, "exp");

            if (!sub.empty()) std::cout << "  Subject:   " << sub << "\n";
            if (!iss.empty()) std::cout << "  Issuer:    " << iss << "\n";
            if (iat > 0) {
                time_t iat_time = static_cast<time_t>(iat);
                char* time_str = ctime(&iat_time);
                if (time_str) {
                    std::string ts(time_str);
                    if (!ts.empty() && ts.back() == '\n') ts.pop_back();
                    std::cout << "  Issued:    " << iat << " (" << ts << ")\n";
                }
            }
            if (exp > 0) {
                time_t exp_time = static_cast<time_t>(exp);
                char* time_str = ctime(&exp_time);
                if (time_str) {
                    std::string ts(time_str);
                    if (!ts.empty() && ts.back() == '\n') ts.pop_back();
                    std::cout << "  Expires:   " << exp << " (" << ts << ")\n";
                }
            }
        }

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 2;
    }
}
