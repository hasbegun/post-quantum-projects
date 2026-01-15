/**
 * Post-Quantum Code Signing Tool (C++)
 *
 * Signs software releases using ML-DSA or SLH-DSA, producing a detached
 * JSON signature manifest for distribution.
 *
 * Usage:
 *   ./sign_release <secret_key> <file> [options]
 *
 * Options:
 *   --algorithm <alg>      Algorithm (auto-detected from key size if omitted)
 *   --output <file>        Output signature file (default: <file>.sig)
 *   --context <str>        Context string for domain separation
 *   --signer-name <name>   Signer name
 *   --signer-email <email> Signer email
 *   --quiet                Suppress output
 *
 * Example:
 *   ./sign_release keys/release_secret.key dist/myapp-1.0.0.tar.gz
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
#include <cstring>

#include "mldsa/mldsa.hpp"
#include "slhdsa/slh_dsa.hpp"

// SHA-256 implementation (simplified for demonstration)
#include <openssl/sha.h>
#include <openssl/evp.h>

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

// Algorithm info structure
struct AlgorithmInfo {
    std::string id;
    std::string name;
    std::string security_level;
    std::string standard;
    size_t pk_size;
    size_t sk_size;
};

// Get algorithm info from name
AlgorithmInfo get_algorithm_info(const std::string& alg) {
    std::string lower = alg;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    if (lower == "mldsa44") {
        return {"mldsa44", "ML-DSA-44", "NIST Level 2", "FIPS 204", 1312, 2560};
    } else if (lower == "mldsa65") {
        return {"mldsa65", "ML-DSA-65", "NIST Level 3", "FIPS 204", 1952, 4032};
    } else if (lower == "mldsa87") {
        return {"mldsa87", "ML-DSA-87", "NIST Level 5", "FIPS 204", 2592, 4896};
    } else if (lower == "slh-shake-128f") {
        return {"slh-shake-128f", "SLH-DSA-SHAKE-128f", "NIST Level 1", "FIPS 205", 32, 64};
    } else if (lower == "slh-shake-192f") {
        return {"slh-shake-192f", "SLH-DSA-SHAKE-192f", "NIST Level 3", "FIPS 205", 48, 96};
    } else if (lower == "slh-shake-256f") {
        return {"slh-shake-256f", "SLH-DSA-SHAKE-256f", "NIST Level 5", "FIPS 205", 64, 128};
    }
    throw std::invalid_argument("Unknown algorithm: " + alg);
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

// Sign function template for ML-DSA
template<typename DSA>
std::vector<uint8_t> sign_mldsa(const std::vector<uint8_t>& sk,
                                 const std::vector<uint8_t>& message,
                                 const std::vector<uint8_t>& ctx) {
    DSA dsa;
    return dsa.sign(sk, message, ctx);
}

// Sign function template for SLH-DSA
template<typename DSA>
std::vector<uint8_t> sign_slhdsa(const std::vector<uint8_t>& sk,
                                  const std::vector<uint8_t>& message,
                                  const std::vector<uint8_t>& ctx) {
    DSA dsa;
    return dsa.sign(sk, message, ctx);
}

// Create signature manifest JSON
std::string create_manifest(const std::string& filename,
                           size_t file_size,
                           const std::string& file_hash,
                           const std::string& timestamp,
                           const AlgorithmInfo& alg,
                           const std::vector<uint8_t>& signature,
                           const std::string& context,
                           const std::string& signer_name,
                           const std::string& signer_email) {
    std::ostringstream json;
    json << "{\n";
    json << "  \"manifest_version\": \"1.0\",\n";
    json << "  \"type\": \"code-signature\",\n";
    json << "  \"algorithm\": {\n";
    json << "    \"id\": \"" << alg.id << "\",\n";
    json << "    \"name\": \"" << alg.name << "\",\n";
    json << "    \"security_level\": \"" << alg.security_level << "\",\n";
    json << "    \"standard\": \"" << alg.standard << "\"\n";
    json << "  },\n";
    json << "  \"file\": {\n";
    json << "    \"name\": \"" << json_escape(filename) << "\",\n";
    json << "    \"size\": " << file_size << ",\n";
    json << "    \"hash\": \"" << file_hash << "\",\n";
    json << "    \"hash_algorithm\": \"sha256\"\n";
    json << "  },\n";
    json << "  \"signature\": {\n";
    json << "    \"value\": \"" << to_hex(signature) << "\",\n";
    json << "    \"encoding\": \"hex\"";
    if (!context.empty()) {
        json << ",\n    \"context\": \"" << to_hex(std::vector<uint8_t>(context.begin(), context.end())) << "\"";
    }
    json << "\n  },\n";
    json << "  \"timestamp\": \"" << timestamp << "\"";

    if (!signer_name.empty() || !signer_email.empty()) {
        json << ",\n  \"signer\": {\n";
        if (!signer_name.empty()) {
            json << "    \"name\": \"" << json_escape(signer_name) << "\"";
            if (!signer_email.empty()) json << ",\n";
            else json << "\n";
        }
        if (!signer_email.empty()) {
            json << "    \"email\": \"" << json_escape(signer_email) << "\"\n";
        }
        json << "  }";
    }

    json << "\n}\n";
    return json.str();
}

void print_usage() {
    std::cout << "Post-Quantum Code Signing Tool (C++)\n";
    std::cout << std::string(60, '=') << "\n\n";
    std::cout << "Usage: sign_release <secret_key> <file> [options]\n\n";
    std::cout << "Required:\n";
    std::cout << "  <secret_key>          Secret key file\n";
    std::cout << "  <file>                File to sign\n\n";
    std::cout << "Options:\n";
    std::cout << "  --algorithm <alg>     Algorithm (auto-detected from key)\n";
    std::cout << "  --output <file>       Output signature file (default: <file>.sig)\n";
    std::cout << "  --context <str>       Context string for domain separation\n";
    std::cout << "  --signer-name <name>  Signer name\n";
    std::cout << "  --signer-email <email> Signer email\n";
    std::cout << "  --quiet               Suppress output\n";
    std::cout << "  --help                Show this help\n\n";
    std::cout << "Algorithms:\n";
    std::cout << "  mldsa44, mldsa65, mldsa87 (ML-DSA, FIPS 204)\n";
    std::cout << "  slh-shake-128f, slh-shake-192f, slh-shake-256f (SLH-DSA, FIPS 205)\n\n";
    std::cout << "Example:\n";
    std::cout << "  ./sign_release keys/release_secret.key dist/myapp-1.0.0.tar.gz\n";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage();
        return (argc == 1) ? 0 : 1;
    }

    std::string sk_file;
    std::string file_path;
    std::string algorithm;
    std::string output_file;
    std::string context;
    std::string signer_name;
    std::string signer_email;
    bool quiet = false;

    // Parse arguments
    int i = 1;
    while (i < argc) {
        std::string arg = argv[i];

        if (arg == "--algorithm" && i + 1 < argc) {
            algorithm = argv[++i];
        } else if (arg == "--output" && i + 1 < argc) {
            output_file = argv[++i];
        } else if (arg == "--context" && i + 1 < argc) {
            context = argv[++i];
        } else if (arg == "--signer-name" && i + 1 < argc) {
            signer_name = argv[++i];
        } else if (arg == "--signer-email" && i + 1 < argc) {
            signer_email = argv[++i];
        } else if (arg == "--quiet" || arg == "-q") {
            quiet = true;
        } else if (arg == "--help" || arg == "-h") {
            print_usage();
            return 0;
        } else if (arg[0] != '-') {
            if (sk_file.empty()) {
                sk_file = arg;
            } else if (file_path.empty()) {
                file_path = arg;
            }
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            return 1;
        }
        ++i;
    }

    if (sk_file.empty() || file_path.empty()) {
        std::cerr << "Error: Secret key and file are required\n";
        return 1;
    }

    try {
        // Read secret key
        if (!quiet) std::cerr << "Reading secret key: " << sk_file << "\n";
        auto sk = read_file(sk_file);

        // Auto-detect algorithm if not specified
        if (algorithm.empty()) {
            algorithm = detect_algorithm(sk.size());
            if (!quiet) std::cerr << "Detected algorithm: " << algorithm << "\n";
        }

        // Read file to sign
        if (!quiet) std::cerr << "Reading file: " << file_path << "\n";
        auto file_data = read_file(file_path);

        // Compute hash
        auto hash = sha256(file_data);
        std::string hash_hex = to_hex(hash);

        // Get timestamp
        std::string timestamp = get_timestamp();

        // Build signed message (hash + filename + size + timestamp)
        std::string filename = get_filename(file_path);
        std::ostringstream msg_stream;
        msg_stream << "{\"file_hash\":\"" << hash_hex << "\",";
        msg_stream << "\"file_name\":\"" << json_escape(filename) << "\",";
        msg_stream << "\"file_size\":" << file_data.size() << ",";
        msg_stream << "\"timestamp\":\"" << timestamp << "\"}";
        std::string msg_str = msg_stream.str();
        std::vector<uint8_t> message(msg_str.begin(), msg_str.end());

        // Prepare context
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
            filename, file_data.size(), hash_hex, timestamp,
            alg_info, signature, context, signer_name, signer_email
        );

        // Write output
        if (output_file.empty()) {
            output_file = file_path + ".sig";
        }

        if (!write_text_file(output_file, manifest)) {
            std::cerr << "Error: Failed to write signature file\n";
            return 1;
        }

        if (!quiet) {
            std::cerr << "Signature written to: " << output_file << "\n";
            std::cerr << "Signing complete.\n";
        }

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
