/**
 * Post-Quantum Code Signature Verification Tool (C++)
 *
 * Verifies software release signatures created with sign_release.
 *
 * Usage:
 *   ./verify_release <public_key> <file> [options]
 *
 * Options:
 *   --signature <file>     Signature file (default: <file>.sig)
 *   --quiet                Suppress output, exit code only
 *   --json                 Output result as JSON
 *
 * Exit codes:
 *   0 - Signature valid
 *   1 - Signature invalid
 *   2 - Input error
 *
 * Example:
 *   ./verify_release keys/release_public.key dist/myapp-1.0.0.tar.gz
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <string>
#include <algorithm>
#include <stdexcept>
#include <regex>

#include "mldsa/mldsa.hpp"
#include "slhdsa/slh_dsa.hpp"

#include <openssl/sha.h>

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

// Read text file
std::string read_text_file(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + path);
    }
    return std::string(
        std::istreambuf_iterator<char>(file),
        std::istreambuf_iterator<char>()
    );
}

// Convert hex string to bytes
std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        bytes.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16)));
    }
    return bytes;
}

// Convert bytes to hex string
std::string to_hex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (uint8_t b : data) {
        oss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

// Compute SHA-256 hash
std::vector<uint8_t> sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

// Extract filename from path
std::string get_filename(const std::string& path) {
    size_t pos = path.find_last_of("/\\");
    return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

// Simple JSON value extraction
std::string json_get_string(const std::string& json, const std::string& key) {
    std::regex pattern("\"" + key + "\"\\s*:\\s*\"([^\"]+)\"");
    std::smatch match;
    if (std::regex_search(json, match, pattern)) {
        return match[1].str();
    }
    return "";
}

size_t json_get_int(const std::string& json, const std::string& key) {
    std::regex pattern("\"" + key + "\"\\s*:\\s*(\\d+)");
    std::smatch match;
    if (std::regex_search(json, match, pattern)) {
        return std::stoull(match[1].str());
    }
    return 0;
}

// JSON escape string
std::string json_escape(const std::string& s) {
    std::string result;
    for (char c : s) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            default: result += c;
        }
    }
    return result;
}

// Detect algorithm from public key size
std::string detect_algorithm(size_t pk_size) {
    switch (pk_size) {
        case 1312: return "mldsa44";
        case 1952: return "mldsa65";
        case 2592: return "mldsa87";
        case 32: return "slh-shake-128f";
        case 48: return "slh-shake-192f";
        case 64: return "slh-shake-256f";
        default:
            throw std::invalid_argument("Cannot detect algorithm from key size: " +
                                        std::to_string(pk_size));
    }
}

// Verify function template for ML-DSA
template<typename DSA>
bool verify_mldsa(const std::vector<uint8_t>& pk,
                  const std::vector<uint8_t>& message,
                  const std::vector<uint8_t>& signature,
                  const std::vector<uint8_t>& ctx) {
    DSA dsa;
    return dsa.verify(pk, message, signature, ctx);
}

// Verify function template for SLH-DSA
template<typename DSA>
bool verify_slhdsa(const std::vector<uint8_t>& pk,
                   const std::vector<uint8_t>& message,
                   const std::vector<uint8_t>& signature,
                   const std::vector<uint8_t>& ctx) {
    DSA dsa;
    return dsa.verify(pk, message, signature, ctx);
}

struct VerificationResult {
    bool valid = false;
    bool hash_valid = false;
    bool size_valid = false;
    bool signature_valid = false;
    std::string algorithm;
    std::string filename;
    size_t file_size = 0;
    std::string timestamp;
    std::string signer_name;
    std::string error;
};

void print_usage() {
    std::cout << "Post-Quantum Code Signature Verification Tool (C++)\n";
    std::cout << std::string(60, '=') << "\n\n";
    std::cout << "Usage: verify_release <public_key> <file> [options]\n\n";
    std::cout << "Required:\n";
    std::cout << "  <public_key>          Public key file\n";
    std::cout << "  <file>                File to verify\n\n";
    std::cout << "Options:\n";
    std::cout << "  --signature <file>    Signature file (default: <file>.sig)\n";
    std::cout << "  --quiet               Exit code only\n";
    std::cout << "  --json                Output result as JSON\n";
    std::cout << "  --help                Show this help\n\n";
    std::cout << "Exit Codes:\n";
    std::cout << "  0 - Signature valid\n";
    std::cout << "  1 - Signature invalid\n";
    std::cout << "  2 - Input error\n\n";
    std::cout << "Example:\n";
    std::cout << "  ./verify_release keys/release_public.key dist/myapp-1.0.0.tar.gz\n";
}

void print_json_result(const VerificationResult& result) {
    std::cout << "{\n";
    std::cout << "  \"valid\": " << (result.valid ? "true" : "false") << ",\n";
    std::cout << "  \"checks\": {\n";
    std::cout << "    \"hash\": " << (result.hash_valid ? "true" : "false") << ",\n";
    std::cout << "    \"size\": " << (result.size_valid ? "true" : "false") << ",\n";
    std::cout << "    \"signature\": " << (result.signature_valid ? "true" : "false") << "\n";
    std::cout << "  },\n";
    std::cout << "  \"file\": {\n";
    std::cout << "    \"name\": \"" << json_escape(result.filename) << "\",\n";
    std::cout << "    \"size\": " << result.file_size << "\n";
    std::cout << "  },\n";
    std::cout << "  \"algorithm\": \"" << result.algorithm << "\",\n";
    std::cout << "  \"timestamp\": \"" << result.timestamp << "\"";
    if (!result.signer_name.empty()) {
        std::cout << ",\n  \"signer\": \"" << json_escape(result.signer_name) << "\"";
    }
    if (!result.error.empty()) {
        std::cout << ",\n  \"error\": \"" << json_escape(result.error) << "\"";
    }
    std::cout << "\n}\n";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage();
        return (argc == 1) ? 0 : 2;
    }

    std::string pk_file;
    std::string file_path;
    std::string sig_file;
    bool quiet = false;
    bool json_output = false;

    // Parse arguments
    int i = 1;
    while (i < argc) {
        std::string arg = argv[i];

        if (arg == "--signature" && i + 1 < argc) {
            sig_file = argv[++i];
        } else if (arg == "--quiet" || arg == "-q") {
            quiet = true;
        } else if (arg == "--json") {
            json_output = true;
        } else if (arg == "--help" || arg == "-h") {
            print_usage();
            return 0;
        } else if (arg[0] != '-') {
            if (pk_file.empty()) {
                pk_file = arg;
            } else if (file_path.empty()) {
                file_path = arg;
            }
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            return 2;
        }
        ++i;
    }

    if (pk_file.empty() || file_path.empty()) {
        std::cerr << "Error: Public key and file are required\n";
        return 2;
    }

    if (sig_file.empty()) {
        sig_file = file_path + ".sig";
    }

    VerificationResult result;

    try {
        // Read public key
        if (!quiet && !json_output) std::cerr << "Reading public key: " << pk_file << "\n";
        auto pk = read_file(pk_file);

        // Read file to verify
        if (!quiet && !json_output) std::cerr << "Reading file: " << file_path << "\n";
        auto file_data = read_file(file_path);
        result.file_size = file_data.size();
        result.filename = get_filename(file_path);

        // Read signature manifest
        if (!quiet && !json_output) std::cerr << "Reading signature: " << sig_file << "\n";
        std::string manifest = read_text_file(sig_file);

        // Extract values from manifest
        std::string alg_id = json_get_string(manifest, "id");
        std::string sig_hex = json_get_string(manifest, "value");
        std::string hash_hex = json_get_string(manifest, "hash");
        std::string context_hex = json_get_string(manifest, "context");
        std::string timestamp = json_get_string(manifest, "timestamp");
        std::string signer = json_get_string(manifest, "name");
        size_t expected_size = json_get_int(manifest, "size");

        result.algorithm = alg_id;
        result.timestamp = timestamp;
        result.signer_name = signer;

        // Detect algorithm from key if not in manifest
        if (alg_id.empty()) {
            alg_id = detect_algorithm(pk.size());
            result.algorithm = alg_id;
        }

        // Verify file size
        result.size_valid = (file_data.size() == expected_size);

        // Verify hash
        auto computed_hash = sha256(file_data);
        std::string computed_hash_hex = to_hex(computed_hash);
        result.hash_valid = (computed_hash_hex == hash_hex);

        // Build message to verify
        std::string file_name = json_get_string(manifest, "name");
        if (file_name.empty()) file_name = result.filename;

        std::ostringstream msg_stream;
        msg_stream << "{\"file_hash\":\"" << hash_hex << "\",";
        msg_stream << "\"file_name\":\"" << file_name << "\",";
        msg_stream << "\"file_size\":" << expected_size << ",";
        msg_stream << "\"timestamp\":\"" << timestamp << "\"}";
        std::string msg_str = msg_stream.str();
        std::vector<uint8_t> message(msg_str.begin(), msg_str.end());

        // Decode signature
        std::vector<uint8_t> signature = from_hex(sig_hex);

        // Decode context
        std::vector<uint8_t> ctx;
        if (!context_hex.empty()) {
            ctx = from_hex(context_hex);
        }

        // Verify signature
        if (!quiet && !json_output) std::cerr << "Verifying signature with " << alg_id << "...\n";

        if (alg_id == "mldsa44") {
            result.signature_valid = verify_mldsa<mldsa::MLDSA44>(pk, message, signature, ctx);
        } else if (alg_id == "mldsa65") {
            result.signature_valid = verify_mldsa<mldsa::MLDSA65>(pk, message, signature, ctx);
        } else if (alg_id == "mldsa87") {
            result.signature_valid = verify_mldsa<mldsa::MLDSA87>(pk, message, signature, ctx);
        } else if (alg_id == "slh-shake-128f") {
            result.signature_valid = verify_slhdsa<slhdsa::SLHDSA_SHAKE_128f>(pk, message, signature, ctx);
        } else if (alg_id == "slh-shake-192f") {
            result.signature_valid = verify_slhdsa<slhdsa::SLHDSA_SHAKE_192f>(pk, message, signature, ctx);
        } else if (alg_id == "slh-shake-256f") {
            result.signature_valid = verify_slhdsa<slhdsa::SLHDSA_SHAKE_256f>(pk, message, signature, ctx);
        } else {
            throw std::invalid_argument("Unsupported algorithm: " + alg_id);
        }

        // Final result
        result.valid = result.hash_valid && result.size_valid && result.signature_valid;

    } catch (const std::exception& e) {
        result.error = e.what();
        if (json_output) {
            print_json_result(result);
        } else if (!quiet) {
            std::cerr << "Error: " << e.what() << "\n";
        }
        return 2;
    }

    // Output result
    if (json_output) {
        print_json_result(result);
    } else if (!quiet) {
        std::cout << "\n" << std::string(50, '=') << "\n";
        std::cout << "  Verification Result\n";
        std::cout << std::string(50, '=') << "\n\n";

        std::cout << "File:      " << result.filename << "\n";
        std::cout << "Size:      " << result.file_size << " bytes\n";
        std::cout << "Algorithm: " << result.algorithm << "\n";
        std::cout << "Timestamp: " << result.timestamp << "\n";
        if (!result.signer_name.empty()) {
            std::cout << "Signer:    " << result.signer_name << "\n";
        }

        std::cout << "\nChecks:\n";
        std::cout << "  Hash:      " << (result.hash_valid ? "PASS" : "FAIL") << "\n";
        std::cout << "  Size:      " << (result.size_valid ? "PASS" : "FAIL") << "\n";
        std::cout << "  Signature: " << (result.signature_valid ? "PASS" : "FAIL") << "\n";

        std::cout << "\n" << std::string(50, '=') << "\n";
        if (result.valid) {
            std::cout << "  SIGNATURE VALID\n";
        } else {
            std::cout << "  SIGNATURE INVALID\n";
        }
        std::cout << std::string(50, '=') << "\n";
    }

    return result.valid ? 0 : 1;
}
