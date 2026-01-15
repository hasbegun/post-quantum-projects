/**
 * Post-Quantum Firmware Verification Tool (C++)
 *
 * Verifies firmware signatures, including rollback protection and
 * device compatibility checks for secure boot and OTA updates.
 *
 * Usage:
 *   ./verify_firmware <public_key> <firmware> [options]
 *
 * Options:
 *   --manifest <file>        Manifest file (default: <firmware>.fwsig)
 *   --current-version <code> Current version code for rollback check
 *   --device-type <type>     Device type for compatibility check
 *   --device-model <model>   Device model for compatibility check
 *   --quiet                  Exit code only
 *   --json                   Output result as JSON
 *
 * Exit codes:
 *   0 - Verification successful, safe to install
 *   1 - Signature or integrity verification failed
 *   2 - Input error
 *   3 - Rollback protection triggered
 *   4 - Device compatibility error
 *
 * Example:
 *   ./verify_firmware keys/fw_public.key firmware.bin --current-version 2000000
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

// Exit codes
constexpr int EXIT_VALID = 0;
constexpr int EXIT_INVALID = 1;
constexpr int EXIT_ERROR = 2;
constexpr int EXIT_ROLLBACK = 3;
constexpr int EXIT_COMPATIBILITY = 4;

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

int json_get_int(const std::string& json, const std::string& key) {
    std::regex pattern("\"" + key + "\"\\s*:\\s*(-?\\d+)");
    std::smatch match;
    if (std::regex_search(json, match, pattern)) {
        return std::stoi(match[1].str());
    }
    return 0;
}

// Extract array from JSON
std::vector<std::string> json_get_array(const std::string& json, const std::string& key) {
    std::vector<std::string> result;
    std::regex pattern("\"" + key + "\"\\s*:\\s*\\[([^\\]]+)\\]");
    std::smatch match;
    if (std::regex_search(json, match, pattern)) {
        std::string array_content = match[1].str();
        std::regex item_pattern("\"([^\"]+)\"");
        auto begin = std::sregex_iterator(array_content.begin(), array_content.end(), item_pattern);
        auto end = std::sregex_iterator();
        for (auto it = begin; it != end; ++it) {
            result.push_back((*it)[1].str());
        }
    }
    return result;
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
    bool rollback_ok = true;
    bool compatibility_ok = true;
    std::string algorithm;
    std::string filename;
    size_t file_size = 0;
    std::string version;
    int version_code = 0;
    std::string device_type;
    std::string timestamp;
    std::string error;
    int exit_code = 0;
};

void print_usage() {
    std::cout << "Post-Quantum Firmware Verification Tool (C++)\n";
    std::cout << std::string(60, '=') << "\n\n";
    std::cout << "Usage: verify_firmware <public_key> <firmware> [options]\n\n";
    std::cout << "Required:\n";
    std::cout << "  <public_key>            Public key file\n";
    std::cout << "  <firmware>              Firmware binary to verify\n\n";
    std::cout << "Options:\n";
    std::cout << "  --manifest <file>       Manifest file (default: <firmware>.fwsig)\n";
    std::cout << "  --current-version <code> Current version code for rollback check\n";
    std::cout << "  --device-type <type>    Device type for compatibility check\n";
    std::cout << "  --device-model <model>  Device model for compatibility check\n";
    std::cout << "  --quiet                 Exit code only\n";
    std::cout << "  --json                  Output result as JSON\n";
    std::cout << "  --help                  Show this help\n\n";
    std::cout << "Exit Codes:\n";
    std::cout << "  0 - Verification successful, safe to install\n";
    std::cout << "  1 - Signature or integrity verification failed\n";
    std::cout << "  2 - Input error\n";
    std::cout << "  3 - Rollback protection triggered\n";
    std::cout << "  4 - Device compatibility error\n\n";
    std::cout << "Example:\n";
    std::cout << "  ./verify_firmware keys/fw_public.key firmware.bin --current-version 2000000\n";
}

void print_json_result(const VerificationResult& result) {
    std::cout << "{\n";
    std::cout << "  \"valid\": " << (result.valid ? "true" : "false") << ",\n";
    std::cout << "  \"checks\": {\n";
    std::cout << "    \"hash\": " << (result.hash_valid ? "true" : "false") << ",\n";
    std::cout << "    \"size\": " << (result.size_valid ? "true" : "false") << ",\n";
    std::cout << "    \"signature\": " << (result.signature_valid ? "true" : "false") << ",\n";
    std::cout << "    \"rollback\": " << (result.rollback_ok ? "true" : "false") << ",\n";
    std::cout << "    \"compatibility\": " << (result.compatibility_ok ? "true" : "false") << "\n";
    std::cout << "  },\n";
    std::cout << "  \"firmware\": {\n";
    std::cout << "    \"name\": \"" << json_escape(result.filename) << "\",\n";
    std::cout << "    \"size\": " << result.file_size << ",\n";
    std::cout << "    \"version\": \"" << json_escape(result.version) << "\",\n";
    std::cout << "    \"version_code\": " << result.version_code << "\n";
    std::cout << "  },\n";
    std::cout << "  \"device_type\": \"" << json_escape(result.device_type) << "\",\n";
    std::cout << "  \"algorithm\": \"" << result.algorithm << "\",\n";
    std::cout << "  \"timestamp\": \"" << result.timestamp << "\"";
    if (!result.error.empty()) {
        std::cout << ",\n  \"error\": \"" << json_escape(result.error) << "\"";
    }
    std::cout << "\n}\n";
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage();
        return (argc == 1) ? 0 : EXIT_ERROR;
    }

    std::string pk_file;
    std::string fw_file;
    std::string manifest_file;
    int current_version = -1;
    std::string device_type;
    std::string device_model;
    bool quiet = false;
    bool json_output = false;

    // Parse arguments
    int i = 1;
    while (i < argc) {
        std::string arg = argv[i];

        if (arg == "--manifest" && i + 1 < argc) {
            manifest_file = argv[++i];
        } else if (arg == "--current-version" && i + 1 < argc) {
            current_version = std::stoi(argv[++i]);
        } else if (arg == "--device-type" && i + 1 < argc) {
            device_type = argv[++i];
        } else if (arg == "--device-model" && i + 1 < argc) {
            device_model = argv[++i];
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
            } else if (fw_file.empty()) {
                fw_file = arg;
            }
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            return EXIT_ERROR;
        }
        ++i;
    }

    if (pk_file.empty() || fw_file.empty()) {
        std::cerr << "Error: Public key and firmware file are required\n";
        return EXIT_ERROR;
    }

    if (manifest_file.empty()) {
        manifest_file = fw_file + ".fwsig";
    }

    VerificationResult result;

    try {
        // Read public key
        if (!quiet && !json_output) std::cerr << "Reading public key: " << pk_file << "\n";
        auto pk = read_file(pk_file);

        // Read firmware
        if (!quiet && !json_output) std::cerr << "Reading firmware: " << fw_file << "\n";
        auto fw_data = read_file(fw_file);
        result.file_size = fw_data.size();
        result.filename = get_filename(fw_file);

        // Read manifest
        if (!quiet && !json_output) std::cerr << "Reading manifest: " << manifest_file << "\n";
        std::string manifest = read_text_file(manifest_file);

        // Extract values from manifest
        std::string alg_id = json_get_string(manifest, "id");
        std::string sig_hex = json_get_string(manifest, "value");
        std::string sha256_hex = json_get_string(manifest, "sha256");
        std::string sha512_hex = json_get_string(manifest, "sha512");
        std::string version = json_get_string(manifest, "version");
        int version_code = json_get_int(manifest, "version_code");
        std::string manifest_device_type = json_get_string(manifest, "device_type");
        std::string timestamp = json_get_string(manifest, "timestamp");
        size_t expected_size = json_get_int(manifest, "size");
        std::vector<std::string> compatibility = json_get_array(manifest, "compatibility");

        result.algorithm = alg_id;
        result.version = version;
        result.version_code = version_code;
        result.device_type = manifest_device_type;
        result.timestamp = timestamp;

        // Detect algorithm from key if not in manifest
        if (alg_id.empty()) {
            alg_id = detect_algorithm(pk.size());
            result.algorithm = alg_id;
        }

        // Verify file size
        result.size_valid = (fw_data.size() == expected_size);

        // Verify hashes
        auto computed_sha256 = sha256(fw_data);
        auto computed_sha512 = sha512(fw_data);
        std::string computed_sha256_hex = to_hex(computed_sha256);
        std::string computed_sha512_hex = to_hex(computed_sha512);

        result.hash_valid = (computed_sha256_hex == sha256_hex);
        if (!sha512_hex.empty()) {
            result.hash_valid = result.hash_valid && (computed_sha512_hex == sha512_hex);
        }

        // Check rollback protection
        if (current_version >= 0) {
            if (version_code < current_version) {
                result.rollback_ok = false;
                result.error = "Rollback blocked: firmware version " + std::to_string(version_code) +
                              " is older than current " + std::to_string(current_version);
            }
        }

        // Check device compatibility
        if (!device_type.empty()) {
            if (device_type != manifest_device_type) {
                result.compatibility_ok = false;
                result.error = "Device type mismatch: expected " + manifest_device_type +
                              ", got " + device_type;
            }
        }

        if (!device_model.empty() && !compatibility.empty()) {
            bool model_found = std::find(compatibility.begin(), compatibility.end(), device_model) != compatibility.end();
            if (!model_found) {
                result.compatibility_ok = false;
                result.error = "Device model " + device_model + " not in compatibility list";
            }
        }

        // Build message to verify
        std::string fw_name = json_get_string(manifest, "name");
        if (fw_name.empty()) fw_name = result.filename;

        std::ostringstream msg_stream;
        msg_stream << "{\"firmware_hash\":\"" << sha256_hex << "\",";
        msg_stream << "\"firmware_name\":\"" << fw_name << "\",";
        msg_stream << "\"firmware_size\":" << expected_size << ",";
        msg_stream << "\"version\":\"" << version << "\",";
        msg_stream << "\"version_code\":" << version_code << ",";
        msg_stream << "\"device_type\":\"" << manifest_device_type << "\",";
        msg_stream << "\"timestamp\":\"" << timestamp << "\"}";
        std::string msg_str = msg_stream.str();
        std::vector<uint8_t> message(msg_str.begin(), msg_str.end());

        // Decode signature
        std::vector<uint8_t> signature = from_hex(sig_hex);

        // Firmware context
        std::vector<uint8_t> ctx = {'f', 'i', 'r', 'm', 'w', 'a', 'r', 'e'};

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

        // Determine final result and exit code
        if (!result.rollback_ok) {
            result.exit_code = EXIT_ROLLBACK;
        } else if (!result.compatibility_ok) {
            result.exit_code = EXIT_COMPATIBILITY;
        } else if (!result.hash_valid || !result.size_valid || !result.signature_valid) {
            result.exit_code = EXIT_INVALID;
        } else {
            result.exit_code = EXIT_VALID;
        }

        result.valid = (result.exit_code == EXIT_VALID);

    } catch (const std::exception& e) {
        result.error = e.what();
        result.exit_code = EXIT_ERROR;
        if (json_output) {
            print_json_result(result);
        } else if (!quiet) {
            std::cerr << "Error: " << e.what() << "\n";
        }
        return EXIT_ERROR;
    }

    // Output result
    if (json_output) {
        print_json_result(result);
    } else if (!quiet) {
        std::cout << "\n" << std::string(50, '=') << "\n";
        std::cout << "  Firmware Verification Result\n";
        std::cout << std::string(50, '=') << "\n\n";

        std::cout << "Firmware:     " << result.filename << "\n";
        std::cout << "Size:         " << result.file_size << " bytes\n";
        std::cout << "Version:      " << result.version << " (code: " << result.version_code << ")\n";
        std::cout << "Device Type:  " << result.device_type << "\n";
        std::cout << "Algorithm:    " << result.algorithm << "\n";
        std::cout << "Timestamp:    " << result.timestamp << "\n";

        std::cout << "\nChecks:\n";
        std::cout << "  Hash:          " << (result.hash_valid ? "PASS" : "FAIL") << "\n";
        std::cout << "  Size:          " << (result.size_valid ? "PASS" : "FAIL") << "\n";
        std::cout << "  Signature:     " << (result.signature_valid ? "PASS" : "FAIL") << "\n";
        std::cout << "  Rollback:      " << (result.rollback_ok ? "PASS" : "BLOCKED") << "\n";
        std::cout << "  Compatibility: " << (result.compatibility_ok ? "PASS" : "FAIL") << "\n";

        if (!result.error.empty()) {
            std::cout << "\nError: " << result.error << "\n";
        }

        std::cout << "\n" << std::string(50, '=') << "\n";
        if (result.valid) {
            std::cout << "  VERIFICATION SUCCESSFUL - SAFE TO INSTALL\n";
        } else {
            std::cout << "  VERIFICATION FAILED - DO NOT INSTALL\n";
        }
        std::cout << std::string(50, '=') << "\n";
    }

    return result.exit_code;
}
