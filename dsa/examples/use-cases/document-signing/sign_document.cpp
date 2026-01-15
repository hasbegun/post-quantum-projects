/**
 * Post-Quantum Document Signing Tool (C++)
 *
 * Signs documents with post-quantum signatures, including signer identity
 * and signing details (reason, location).
 *
 * Usage:
 *   ./sign_document <secret_key> <document> [options]
 *
 * Options:
 *   --algorithm <alg>        Algorithm (auto-detected from key if omitted)
 *   --output <file>          Output signature file (default: <document>.docsig)
 *   --signer-name <name>     Signer's name
 *   --signer-email <email>   Signer's email
 *   --signer-org <org>       Signer's organization
 *   --reason <reason>        Reason for signing
 *   --location <location>    Signing location
 *   --context <str>          Context for domain separation
 *   --quiet                  Suppress output
 *
 * Example:
 *   ./sign_document keys/signer_secret.key contract.pdf --signer-name "John Doe"
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <string>
#include <algorithm>
#include <stdexcept>

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

// Write text file
bool write_text_file(const std::string& path, const std::string& content) {
    std::ofstream file(path);
    if (!file) return false;
    file << content;
    return file.good();
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

// Get current ISO timestamp
std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time), "%Y-%m-%dT%H:%M:%S+00:00");
    return ss.str();
}

// Extract filename from path
std::string get_filename(const std::string& path) {
    size_t pos = path.find_last_of("/\\");
    return (pos == std::string::npos) ? path : path.substr(pos + 1);
}

// JSON escape string
std::string json_escape(const std::string& s) {
    std::string result;
    for (char c : s) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default: result += c;
        }
    }
    return result;
}

// Detect algorithm from secret key size
std::string detect_algorithm(size_t sk_size) {
    switch (sk_size) {
        case 2560: return "mldsa44";
        case 4032: return "mldsa65";
        case 4896: return "mldsa87";
        case 64: return "slh-shake-128f";
        case 96: return "slh-shake-192f";
        case 128: return "slh-shake-256f";
        default:
            throw std::invalid_argument("Cannot detect algorithm from key size: " +
                                        std::to_string(sk_size));
    }
}

// Algorithm info structure
struct AlgorithmInfo {
    std::string id;
    std::string name;
    std::string security_level;
    std::string standard;
};

// Get algorithm info
AlgorithmInfo get_algorithm_info(const std::string& alg) {
    std::string lower = alg;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    if (lower == "mldsa44") {
        return {"mldsa44", "ML-DSA-44", "NIST Level 2", "FIPS 204"};
    } else if (lower == "mldsa65") {
        return {"mldsa65", "ML-DSA-65", "NIST Level 3", "FIPS 204"};
    } else if (lower == "mldsa87") {
        return {"mldsa87", "ML-DSA-87", "NIST Level 5", "FIPS 204"};
    } else if (lower == "slh-shake-128f") {
        return {"slh-shake-128f", "SLH-DSA-SHAKE-128f", "NIST Level 1", "FIPS 205"};
    } else if (lower == "slh-shake-192f") {
        return {"slh-shake-192f", "SLH-DSA-SHAKE-192f", "NIST Level 3", "FIPS 205"};
    } else if (lower == "slh-shake-256f") {
        return {"slh-shake-256f", "SLH-DSA-SHAKE-256f", "NIST Level 5", "FIPS 205"};
    }
    throw std::invalid_argument("Unknown algorithm: " + alg);
}

// Sign templates
template<typename DSA>
std::vector<uint8_t> sign_mldsa(const std::vector<uint8_t>& sk,
                                 const std::vector<uint8_t>& message,
                                 const std::vector<uint8_t>& ctx) {
    DSA dsa;
    return dsa.sign(sk, message, ctx);
}

template<typename DSA>
std::vector<uint8_t> sign_slhdsa(const std::vector<uint8_t>& sk,
                                  const std::vector<uint8_t>& message,
                                  const std::vector<uint8_t>& ctx) {
    DSA dsa;
    return dsa.sign(sk, message, ctx);
}

// Signer info
struct SignerInfo {
    std::string name;
    std::string email;
    std::string org;
};

// Signing details
struct SigningDetails {
    std::string reason;
    std::string location;
};

// Create manifest JSON
std::string create_manifest(const std::string& filename,
                           size_t file_size,
                           const std::string& sha256_hash,
                           const std::string& sha512_hash,
                           const std::string& timestamp,
                           const AlgorithmInfo& alg,
                           const std::vector<uint8_t>& signature,
                           const std::string& context,
                           const SignerInfo& signer,
                           const SigningDetails& details) {
    std::ostringstream json;
    json << "{\n";
    json << "  \"manifest_version\": \"1.0\",\n";
    json << "  \"type\": \"document-signature\",\n";
    json << "  \"algorithm\": {\n";
    json << "    \"id\": \"" << alg.id << "\",\n";
    json << "    \"name\": \"" << alg.name << "\",\n";
    json << "    \"security_level\": \"" << alg.security_level << "\",\n";
    json << "    \"standard\": \"" << alg.standard << "\"\n";
    json << "  },\n";
    json << "  \"document\": {\n";
    json << "    \"name\": \"" << json_escape(filename) << "\",\n";
    json << "    \"size\": " << file_size << ",\n";
    json << "    \"hashes\": {\n";
    json << "      \"sha256\": \"" << sha256_hash << "\",\n";
    json << "      \"sha512\": \"" << sha512_hash << "\"\n";
    json << "    }\n";
    json << "  },\n";
    json << "  \"signature\": {\n";
    json << "    \"value\": \"" << to_hex(signature) << "\",\n";
    json << "    \"encoding\": \"hex\",\n";
    json << "    \"context\": \"" << to_hex(std::vector<uint8_t>(context.begin(), context.end())) << "\"\n";
    json << "  },\n";
    json << "  \"timestamp\": \"" << timestamp << "\"";

    // Signer info
    if (!signer.name.empty() || !signer.email.empty() || !signer.org.empty()) {
        json << ",\n  \"signer\": {\n";
        bool first = true;
        if (!signer.name.empty()) {
            json << "    \"name\": \"" << json_escape(signer.name) << "\"";
            first = false;
        }
        if (!signer.email.empty()) {
            if (!first) json << ",\n";
            json << "    \"email\": \"" << json_escape(signer.email) << "\"";
            first = false;
        }
        if (!signer.org.empty()) {
            if (!first) json << ",\n";
            json << "    \"organization\": \"" << json_escape(signer.org) << "\"";
        }
        json << "\n  }";
    }

    // Signing details
    if (!details.reason.empty() || !details.location.empty()) {
        json << ",\n  \"signing_details\": {\n";
        bool first = true;
        if (!details.reason.empty()) {
            json << "    \"reason\": \"" << json_escape(details.reason) << "\"";
            first = false;
        }
        if (!details.location.empty()) {
            if (!first) json << ",\n";
            json << "    \"location\": \"" << json_escape(details.location) << "\"";
        }
        json << "\n  }";
    }

    json << "\n}\n";
    return json.str();
}

void print_usage() {
    std::cout << "Post-Quantum Document Signing Tool (C++)\n";
    std::cout << std::string(60, '=') << "\n\n";
    std::cout << "Usage: sign_document <secret_key> <document> [options]\n\n";
    std::cout << "Required:\n";
    std::cout << "  <secret_key>            Secret key file\n";
    std::cout << "  <document>              Document to sign\n\n";
    std::cout << "Options:\n";
    std::cout << "  --algorithm <alg>       Algorithm (auto-detected from key)\n";
    std::cout << "  --output <file>         Output signature (default: <doc>.docsig)\n";
    std::cout << "  --signer-name <name>    Signer's name\n";
    std::cout << "  --signer-email <email>  Signer's email\n";
    std::cout << "  --signer-org <org>      Signer's organization\n";
    std::cout << "  --reason <reason>       Reason for signing\n";
    std::cout << "  --location <location>   Signing location\n";
    std::cout << "  --context <str>         Context for domain separation\n";
    std::cout << "  --quiet                 Suppress output\n";
    std::cout << "  --help                  Show this help\n\n";
    std::cout << "Example:\n";
    std::cout << "  ./sign_document keys/signer_secret.key contract.pdf --signer-name \"John Doe\"\n";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage();
        return (argc == 1) ? 0 : 1;
    }

    std::string sk_file;
    std::string doc_file;
    std::string algorithm;
    std::string output_file;
    std::string context = "document";
    SignerInfo signer;
    SigningDetails details;
    bool quiet = false;

    // Parse arguments
    int i = 1;
    while (i < argc) {
        std::string arg = argv[i];

        if (arg == "--algorithm" && i + 1 < argc) {
            algorithm = argv[++i];
        } else if (arg == "--output" && i + 1 < argc) {
            output_file = argv[++i];
        } else if (arg == "--signer-name" && i + 1 < argc) {
            signer.name = argv[++i];
        } else if (arg == "--signer-email" && i + 1 < argc) {
            signer.email = argv[++i];
        } else if (arg == "--signer-org" && i + 1 < argc) {
            signer.org = argv[++i];
        } else if (arg == "--reason" && i + 1 < argc) {
            details.reason = argv[++i];
        } else if (arg == "--location" && i + 1 < argc) {
            details.location = argv[++i];
        } else if (arg == "--context" && i + 1 < argc) {
            context = argv[++i];
        } else if (arg == "--quiet" || arg == "-q") {
            quiet = true;
        } else if (arg == "--help" || arg == "-h") {
            print_usage();
            return 0;
        } else if (arg[0] != '-') {
            if (sk_file.empty()) {
                sk_file = arg;
            } else if (doc_file.empty()) {
                doc_file = arg;
            }
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            return 1;
        }
        ++i;
    }

    if (sk_file.empty() || doc_file.empty()) {
        std::cerr << "Error: Secret key and document are required\n";
        return 1;
    }

    try {
        // Read secret key
        if (!quiet) std::cerr << "Reading secret key: " << sk_file << "\n";
        auto sk = read_file(sk_file);

        // Auto-detect algorithm
        if (algorithm.empty()) {
            algorithm = detect_algorithm(sk.size());
            if (!quiet) std::cerr << "Detected algorithm: " << algorithm << "\n";
        }

        // Read document
        if (!quiet) std::cerr << "Reading document: " << doc_file << "\n";
        auto doc_data = read_file(doc_file);

        // Compute hashes
        auto hash256 = sha256(doc_data);
        auto hash512 = sha512(doc_data);
        std::string hash256_hex = to_hex(hash256);
        std::string hash512_hex = to_hex(hash512);

        // Get timestamp
        std::string timestamp = get_timestamp();

        // Build signed message
        std::string filename = get_filename(doc_file);
        std::ostringstream msg_stream;
        msg_stream << "{\"document_hash\":\"" << hash256_hex << "\",";
        msg_stream << "\"document_name\":\"" << json_escape(filename) << "\",";
        msg_stream << "\"document_size\":" << doc_data.size() << ",";
        msg_stream << "\"timestamp\":\"" << timestamp << "\"";
        if (!signer.name.empty()) {
            msg_stream << ",\"signer_name\":\"" << json_escape(signer.name) << "\"";
        }
        if (!details.reason.empty()) {
            msg_stream << ",\"reason\":\"" << json_escape(details.reason) << "\"";
        }
        if (!details.location.empty()) {
            msg_stream << ",\"location\":\"" << json_escape(details.location) << "\"";
        }
        msg_stream << "}";
        std::string msg_str = msg_stream.str();
        std::vector<uint8_t> message(msg_str.begin(), msg_str.end());

        // Context bytes
        std::vector<uint8_t> ctx_bytes(context.begin(), context.end());

        // Sign
        if (!quiet) std::cerr << "Signing with " << algorithm << "...\n";
        std::vector<uint8_t> signature;
        AlgorithmInfo alg_info = get_algorithm_info(algorithm);

        if (algorithm == "mldsa44") {
            signature = sign_mldsa<mldsa::MLDSA44>(sk, message, ctx_bytes);
        } else if (algorithm == "mldsa65") {
            signature = sign_mldsa<mldsa::MLDSA65>(sk, message, ctx_bytes);
        } else if (algorithm == "mldsa87") {
            signature = sign_mldsa<mldsa::MLDSA87>(sk, message, ctx_bytes);
        } else if (algorithm == "slh-shake-128f") {
            signature = sign_slhdsa<slhdsa::SLHDSA_SHAKE_128f>(sk, message, ctx_bytes);
        } else if (algorithm == "slh-shake-192f") {
            signature = sign_slhdsa<slhdsa::SLHDSA_SHAKE_192f>(sk, message, ctx_bytes);
        } else if (algorithm == "slh-shake-256f") {
            signature = sign_slhdsa<slhdsa::SLHDSA_SHAKE_256f>(sk, message, ctx_bytes);
        } else {
            throw std::invalid_argument("Unsupported algorithm: " + algorithm);
        }

        if (!quiet) std::cerr << "Signature size: " << signature.size() << " bytes\n";

        // Create manifest
        std::string manifest = create_manifest(
            filename, doc_data.size(), hash256_hex, hash512_hex, timestamp,
            alg_info, signature, context, signer, details
        );

        // Write output
        if (output_file.empty()) {
            output_file = doc_file + ".docsig";
        }

        if (!write_text_file(output_file, manifest)) {
            std::cerr << "Error: Failed to write signature file\n";
            return 1;
        }

        if (!quiet) {
            std::cerr << "Signature written to: " << output_file << "\n";
            std::cerr << "Document signed successfully!\n";
        }

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
