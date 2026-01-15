/**
 * Post-Quantum Document Signature Verification Tool (C++)
 *
 * Verifies document signatures created with sign_document.
 *
 * Usage:
 *   ./verify_document <public_key> <document> [options]
 *
 * Options:
 *   --signature <file>     Signature file (default: <document>.docsig)
 *   --quiet                Exit code only
 *   --json                 Output result as JSON
 *
 * Exit codes:
 *   0 - Signature valid
 *   1 - Signature invalid
 *   2 - Input error
 *
 * Example:
 *   ./verify_document keys/signer_public.key contract.pdf
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

// Compute SHA-512 hash
std::vector<uint8_t> sha512(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(SHA512_DIGEST_LENGTH);
    SHA512(data.data(), data.size(), hash.data());
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

// Verify templates
template<typename DSA>
bool verify_mldsa(const std::vector<uint8_t>& pk,
                  const std::vector<uint8_t>& message,
                  const std::vector<uint8_t>& signature,
                  const std::vector<uint8_t>& ctx) {
    DSA dsa;
    return dsa.verify(pk, message, signature, ctx);
}

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
    std::string signer_email;
    std::string reason;
    std::string location;
    std::string error;
};

void print_usage() {
    std::cout << "Post-Quantum Document Signature Verification Tool (C++)\n";
    std::cout << std::string(60, '=') << "\n\n";
    std::cout << "Usage: verify_document <public_key> <document> [options]\n\n";
    std::cout << "Required:\n";
    std::cout << "  <public_key>          Public key file\n";
    std::cout << "  <document>            Document to verify\n\n";
    std::cout << "Options:\n";
    std::cout << "  --signature <file>    Signature file (default: <doc>.docsig)\n";
    std::cout << "  --quiet               Exit code only\n";
    std::cout << "  --json                Output result as JSON\n";
    std::cout << "  --help                Show this help\n\n";
    std::cout << "Exit Codes:\n";
    std::cout << "  0 - Signature valid\n";
    std::cout << "  1 - Signature invalid\n";
    std::cout << "  2 - Input error\n\n";
    std::cout << "Example:\n";
    std::cout << "  ./verify_document keys/signer_public.key contract.pdf\n";
}

void print_json_result(const VerificationResult& result) {
    std::cout << "{\n";
    std::cout << "  \"valid\": " << (result.valid ? "true" : "false") << ",\n";
    std::cout << "  \"checks\": {\n";
    std::cout << "    \"hash\": " << (result.hash_valid ? "true" : "false") << ",\n";
    std::cout << "    \"size\": " << (result.size_valid ? "true" : "false") << ",\n";
    std::cout << "    \"signature\": " << (result.signature_valid ? "true" : "false") << "\n";
    std::cout << "  },\n";
    std::cout << "  \"document\": {\n";
    std::cout << "    \"name\": \"" << json_escape(result.filename) << "\",\n";
    std::cout << "    \"size\": " << result.file_size << "\n";
    std::cout << "  },\n";
    std::cout << "  \"algorithm\": \"" << result.algorithm << "\",\n";
    std::cout << "  \"timestamp\": \"" << result.timestamp << "\"";

    if (!result.signer_name.empty()) {
        std::cout << ",\n  \"signer\": {\n";
        std::cout << "    \"name\": \"" << json_escape(result.signer_name) << "\"";
        if (!result.signer_email.empty()) {
            std::cout << ",\n    \"email\": \"" << json_escape(result.signer_email) << "\"";
        }
        std::cout << "\n  }";
    }

    if (!result.reason.empty() || !result.location.empty()) {
        std::cout << ",\n  \"signing_details\": {\n";
        bool first = true;
        if (!result.reason.empty()) {
            std::cout << "    \"reason\": \"" << json_escape(result.reason) << "\"";
            first = false;
        }
        if (!result.location.empty()) {
            if (!first) std::cout << ",\n";
            std::cout << "    \"location\": \"" << json_escape(result.location) << "\"";
        }
        std::cout << "\n  }";
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
    std::string doc_file;
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
            } else if (doc_file.empty()) {
                doc_file = arg;
            }
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            return 2;
        }
        ++i;
    }

    if (pk_file.empty() || doc_file.empty()) {
        std::cerr << "Error: Public key and document are required\n";
        return 2;
    }

    if (sig_file.empty()) {
        sig_file = doc_file + ".docsig";
    }

    VerificationResult result;

    try {
        // Read public key
        if (!quiet && !json_output) std::cerr << "Reading public key: " << pk_file << "\n";
        auto pk = read_file(pk_file);

        // Read document
        if (!quiet && !json_output) std::cerr << "Reading document: " << doc_file << "\n";
        auto doc_data = read_file(doc_file);
        result.file_size = doc_data.size();
        result.filename = get_filename(doc_file);

        // Read signature manifest
        if (!quiet && !json_output) std::cerr << "Reading signature: " << sig_file << "\n";
        std::string manifest = read_text_file(sig_file);

        // Extract values from manifest
        std::string alg_id = json_get_string(manifest, "id");
        std::string sig_hex = json_get_string(manifest, "value");
        std::string sha256_hex = json_get_string(manifest, "sha256");
        std::string sha512_hex = json_get_string(manifest, "sha512");
        std::string context_hex = json_get_string(manifest, "context");
        std::string timestamp = json_get_string(manifest, "timestamp");
        size_t expected_size = json_get_int(manifest, "size");

        // Extract signer info
        result.signer_name = json_get_string(manifest, "name");
        result.signer_email = json_get_string(manifest, "email");
        result.reason = json_get_string(manifest, "reason");
        result.location = json_get_string(manifest, "location");

        result.algorithm = alg_id;
        result.timestamp = timestamp;

        // Detect algorithm from key if not in manifest
        if (alg_id.empty()) {
            alg_id = detect_algorithm(pk.size());
            result.algorithm = alg_id;
        }

        // Verify hashes
        auto computed_sha256 = sha256(doc_data);
        auto computed_sha512 = sha512(doc_data);
        std::string computed_sha256_hex = to_hex(computed_sha256);
        std::string computed_sha512_hex = to_hex(computed_sha512);

        result.hash_valid = (computed_sha256_hex == sha256_hex);
        if (!sha512_hex.empty()) {
            result.hash_valid = result.hash_valid && (computed_sha512_hex == sha512_hex);
        }

        // Verify size
        result.size_valid = (doc_data.size() == expected_size);

        if (!result.hash_valid) {
            result.error = "Document hash mismatch - document may have been modified";
        } else if (!result.size_valid) {
            result.error = "Document size mismatch";
        }

        // Build message to verify
        std::string doc_name = json_get_string(manifest, "name");
        if (doc_name.empty()) doc_name = result.filename;

        std::ostringstream msg_stream;
        msg_stream << "{\"document_hash\":\"" << sha256_hex << "\",";
        msg_stream << "\"document_name\":\"" << doc_name << "\",";
        msg_stream << "\"document_size\":" << expected_size << ",";
        msg_stream << "\"timestamp\":\"" << timestamp << "\"";
        if (!result.signer_name.empty()) {
            msg_stream << ",\"signer_name\":\"" << result.signer_name << "\"";
        }
        if (!result.reason.empty()) {
            msg_stream << ",\"reason\":\"" << result.reason << "\"";
        }
        if (!result.location.empty()) {
            msg_stream << ",\"location\":\"" << result.location << "\"";
        }
        msg_stream << "}";
        std::string msg_str = msg_stream.str();
        std::vector<uint8_t> message(msg_str.begin(), msg_str.end());

        // Decode signature and context
        std::vector<uint8_t> signature = from_hex(sig_hex);
        std::vector<uint8_t> ctx = from_hex(context_hex);

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
        std::cout << "  Document Signature Verification\n";
        std::cout << std::string(50, '=') << "\n\n";

        std::cout << "Document:   " << result.filename << "\n";
        std::cout << "Size:       " << result.file_size << " bytes\n";
        std::cout << "Algorithm:  " << result.algorithm << "\n";
        std::cout << "Timestamp:  " << result.timestamp << "\n";

        if (!result.signer_name.empty()) {
            std::cout << "Signer:     " << result.signer_name << "\n";
        }
        if (!result.signer_email.empty()) {
            std::cout << "Email:      " << result.signer_email << "\n";
        }
        if (!result.reason.empty()) {
            std::cout << "Reason:     " << result.reason << "\n";
        }
        if (!result.location.empty()) {
            std::cout << "Location:   " << result.location << "\n";
        }

        std::cout << "\nChecks:\n";
        std::cout << "  Hash:       " << (result.hash_valid ? "PASS" : "FAIL") << "\n";
        std::cout << "  Size:       " << (result.size_valid ? "PASS" : "FAIL") << "\n";
        std::cout << "  Signature:  " << (result.signature_valid ? "PASS" : "FAIL") << "\n";

        if (!result.error.empty()) {
            std::cout << "\nError: " << result.error << "\n";
        }

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
