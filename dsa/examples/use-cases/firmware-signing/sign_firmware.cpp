/**
 * Post-Quantum Firmware Signing Tool (C++)
 *
 * Signs firmware images for secure boot and OTA updates, producing a
 * JSON manifest with rollback protection and device compatibility info.
 *
 * Usage:
 *   ./sign_firmware <secret_key> <firmware> --version <ver> --device-type <type> [options]
 *
 * Options:
 *   --version, -v <ver>      Firmware version (e.g., 2.1.0) [required]
 *   --device-type <type>     Device type identifier [required]
 *   --algorithm <alg>        Algorithm (auto-detected from key if omitted)
 *   --output <file>          Output manifest file (default: <firmware>.fwsig)
 *   --hardware-rev <rev>     Hardware revision
 *   --build-id <id>          Build identifier
 *   --description <desc>     Firmware description
 *   --min-bootloader <ver>   Minimum bootloader version
 *   --compatible <model>     Compatible device model (repeatable)
 *   --signer-name <name>     Signer name
 *   --signer-org <org>       Signer organization
 *   --quiet                  Suppress output
 *
 * Example:
 *   ./sign_firmware keys/fw_secret.key firmware.bin -v 2.1.0 --device-type "IoT-Sensor"
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

// Parse version string to numeric code (MAJOR*1000000 + MINOR*1000 + PATCH)
int parse_version(const std::string& version) {
    int major = 0, minor = 0, patch = 0;
    size_t start = 0;
    size_t dot1 = version.find('.');

    if (dot1 != std::string::npos) {
        major = std::stoi(version.substr(0, dot1));
        size_t dot2 = version.find('.', dot1 + 1);
        if (dot2 != std::string::npos) {
            minor = std::stoi(version.substr(dot1 + 1, dot2 - dot1 - 1));
            // Parse patch, ignoring any suffix like -beta
            std::string patch_str = version.substr(dot2 + 1);
            size_t suffix = patch_str.find_first_not_of("0123456789");
            if (suffix != std::string::npos) {
                patch_str = patch_str.substr(0, suffix);
            }
            if (!patch_str.empty()) {
                patch = std::stoi(patch_str);
            }
        } else {
            minor = std::stoi(version.substr(dot1 + 1));
        }
    } else {
        major = std::stoi(version);
    }

    return major * 1000000 + minor * 1000 + patch;
}

// Algorithm info structure
struct AlgorithmInfo {
    std::string id;
    std::string name;
    std::string security_level;
    std::string standard;
};

// Get algorithm info from name
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

// Firmware metadata structure
struct FirmwareMetadata {
    std::string version;
    int version_code = 0;
    std::string device_type;
    std::string hardware_rev;
    std::string build_id;
    std::string description;
    std::string min_bootloader;
    std::vector<std::string> compatible;
    std::string signer_name;
    std::string signer_org;
};

// Create firmware manifest JSON
std::string create_manifest(const std::string& filename,
                           size_t file_size,
                           const std::string& sha256_hash,
                           const std::string& sha512_hash,
                           const std::string& timestamp,
                           const AlgorithmInfo& alg,
                           const std::vector<uint8_t>& signature,
                           const FirmwareMetadata& metadata) {
    std::ostringstream json;
    json << "{\n";
    json << "  \"manifest_version\": \"1.0\",\n";
    json << "  \"type\": \"firmware-signature\",\n";
    json << "  \"algorithm\": {\n";
    json << "    \"id\": \"" << alg.id << "\",\n";
    json << "    \"name\": \"" << alg.name << "\",\n";
    json << "    \"security_level\": \"" << alg.security_level << "\",\n";
    json << "    \"standard\": \"" << alg.standard << "\"\n";
    json << "  },\n";
    json << "  \"firmware\": {\n";
    json << "    \"name\": \"" << json_escape(filename) << "\",\n";
    json << "    \"size\": " << file_size << ",\n";
    json << "    \"hashes\": {\n";
    json << "      \"sha256\": \"" << sha256_hash << "\",\n";
    json << "      \"sha512\": \"" << sha512_hash << "\"\n";
    json << "    }\n";
    json << "  },\n";
    json << "  \"metadata\": {\n";
    json << "    \"version\": \"" << json_escape(metadata.version) << "\",\n";
    json << "    \"version_code\": " << metadata.version_code << ",\n";
    json << "    \"device_type\": \"" << json_escape(metadata.device_type) << "\"";

    if (!metadata.hardware_rev.empty()) {
        json << ",\n    \"hardware_rev\": \"" << json_escape(metadata.hardware_rev) << "\"";
    }
    if (!metadata.build_id.empty()) {
        json << ",\n    \"build_id\": \"" << json_escape(metadata.build_id) << "\"";
    }
    if (!metadata.description.empty()) {
        json << ",\n    \"description\": \"" << json_escape(metadata.description) << "\"";
    }
    if (!metadata.min_bootloader.empty()) {
        json << ",\n    \"min_bootloader_version\": \"" << json_escape(metadata.min_bootloader) << "\"";
    }
    if (!metadata.compatible.empty()) {
        json << ",\n    \"compatibility\": [";
        for (size_t i = 0; i < metadata.compatible.size(); ++i) {
            if (i > 0) json << ", ";
            json << "\"" << json_escape(metadata.compatible[i]) << "\"";
        }
        json << "]";
    }

    json << "\n  },\n";
    json << "  \"signature\": {\n";
    json << "    \"value\": \"" << to_hex(signature) << "\",\n";
    json << "    \"encoding\": \"hex\",\n";
    json << "    \"context\": \"" << to_hex(std::vector<uint8_t>{'f','i','r','m','w','a','r','e'}) << "\"\n";
    json << "  },\n";
    json << "  \"timestamp\": \"" << timestamp << "\"";

    if (!metadata.signer_name.empty() || !metadata.signer_org.empty()) {
        json << ",\n  \"signer\": {\n";
        if (!metadata.signer_name.empty()) {
            json << "    \"name\": \"" << json_escape(metadata.signer_name) << "\"";
            if (!metadata.signer_org.empty()) json << ",\n";
            else json << "\n";
        }
        if (!metadata.signer_org.empty()) {
            json << "    \"organization\": \"" << json_escape(metadata.signer_org) << "\"\n";
        }
        json << "  }";
    }

    json << ",\n  \"security\": {\n";
    json << "    \"rollback_protection\": true,\n";
    json << "    \"minimum_version_code\": " << metadata.version_code << "\n";
    json << "  }";

    json << "\n}\n";
    return json.str();
}

void print_usage() {
    std::cout << "Post-Quantum Firmware Signing Tool (C++)\n";
    std::cout << std::string(60, '=') << "\n\n";
    std::cout << "Usage: sign_firmware <secret_key> <firmware> -v <version> --device-type <type> [options]\n\n";
    std::cout << "Required:\n";
    std::cout << "  <secret_key>          Secret key file\n";
    std::cout << "  <firmware>            Firmware binary to sign\n";
    std::cout << "  -v, --version <ver>   Firmware version (e.g., 2.1.0)\n";
    std::cout << "  --device-type <type>  Device type identifier\n\n";
    std::cout << "Options:\n";
    std::cout << "  --algorithm <alg>        Algorithm (auto-detected from key)\n";
    std::cout << "  --output <file>          Output manifest (default: <firmware>.fwsig)\n";
    std::cout << "  --hardware-rev <rev>     Hardware revision\n";
    std::cout << "  --build-id <id>          Build identifier\n";
    std::cout << "  --description <desc>     Firmware description\n";
    std::cout << "  --min-bootloader <ver>   Minimum bootloader version\n";
    std::cout << "  --compatible <model>     Compatible device model (repeatable)\n";
    std::cout << "  --signer-name <name>     Signer name\n";
    std::cout << "  --signer-org <org>       Signer organization\n";
    std::cout << "  --quiet                  Suppress output\n";
    std::cout << "  --help                   Show this help\n\n";
    std::cout << "Algorithms:\n";
    std::cout << "  mldsa44, mldsa65, mldsa87 (ML-DSA, FIPS 204)\n";
    std::cout << "  slh-shake-128f, slh-shake-192f, slh-shake-256f (SLH-DSA, FIPS 205)\n\n";
    std::cout << "Example:\n";
    std::cout << "  ./sign_firmware keys/fw_secret.key firmware.bin -v 2.1.0 --device-type \"IoT-Sensor\"\n";
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        print_usage();
        return (argc == 1) ? 0 : 1;
    }

    std::string sk_file;
    std::string fw_file;
    std::string algorithm;
    std::string output_file;
    FirmwareMetadata metadata;
    bool quiet = false;

    // Parse arguments
    int i = 1;
    while (i < argc) {
        std::string arg = argv[i];

        if ((arg == "-v" || arg == "--version") && i + 1 < argc) {
            metadata.version = argv[++i];
        } else if (arg == "--device-type" && i + 1 < argc) {
            metadata.device_type = argv[++i];
        } else if (arg == "--algorithm" && i + 1 < argc) {
            algorithm = argv[++i];
        } else if (arg == "--output" && i + 1 < argc) {
            output_file = argv[++i];
        } else if (arg == "--hardware-rev" && i + 1 < argc) {
            metadata.hardware_rev = argv[++i];
        } else if (arg == "--build-id" && i + 1 < argc) {
            metadata.build_id = argv[++i];
        } else if (arg == "--description" && i + 1 < argc) {
            metadata.description = argv[++i];
        } else if (arg == "--min-bootloader" && i + 1 < argc) {
            metadata.min_bootloader = argv[++i];
        } else if (arg == "--compatible" && i + 1 < argc) {
            metadata.compatible.push_back(argv[++i]);
        } else if (arg == "--signer-name" && i + 1 < argc) {
            metadata.signer_name = argv[++i];
        } else if (arg == "--signer-org" && i + 1 < argc) {
            metadata.signer_org = argv[++i];
        } else if (arg == "--quiet" || arg == "-q") {
            quiet = true;
        } else if (arg == "--help" || arg == "-h") {
            print_usage();
            return 0;
        } else if (arg[0] != '-') {
            if (sk_file.empty()) {
                sk_file = arg;
            } else if (fw_file.empty()) {
                fw_file = arg;
            }
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            return 1;
        }
        ++i;
    }

    // Validate required arguments
    if (sk_file.empty()) {
        std::cerr << "Error: Secret key is required\n";
        return 1;
    }
    if (fw_file.empty()) {
        std::cerr << "Error: Firmware file is required\n";
        return 1;
    }
    if (metadata.version.empty()) {
        std::cerr << "Error: Version is required (-v/--version)\n";
        return 1;
    }
    if (metadata.device_type.empty()) {
        std::cerr << "Error: Device type is required (--device-type)\n";
        return 1;
    }

    try {
        // Parse version to code
        metadata.version_code = parse_version(metadata.version);

        // Read secret key
        if (!quiet) std::cerr << "Reading secret key: " << sk_file << "\n";
        auto sk = read_file(sk_file);

        // Auto-detect algorithm if not specified
        if (algorithm.empty()) {
            algorithm = detect_algorithm(sk.size());
            if (!quiet) std::cerr << "Detected algorithm: " << algorithm << "\n";
        }

        // Read firmware
        if (!quiet) std::cerr << "Reading firmware: " << fw_file << "\n";
        auto fw_data = read_file(fw_file);

        // Compute hashes
        auto hash256 = sha256(fw_data);
        auto hash512 = sha512(fw_data);
        std::string hash256_hex = to_hex(hash256);
        std::string hash512_hex = to_hex(hash512);

        // Get timestamp
        std::string timestamp = get_timestamp();

        // Build signed message
        std::string filename = get_filename(fw_file);
        std::ostringstream msg_stream;
        msg_stream << "{\"firmware_hash\":\"" << hash256_hex << "\",";
        msg_stream << "\"firmware_name\":\"" << json_escape(filename) << "\",";
        msg_stream << "\"firmware_size\":" << fw_data.size() << ",";
        msg_stream << "\"version\":\"" << json_escape(metadata.version) << "\",";
        msg_stream << "\"version_code\":" << metadata.version_code << ",";
        msg_stream << "\"device_type\":\"" << json_escape(metadata.device_type) << "\",";
        msg_stream << "\"timestamp\":\"" << timestamp << "\"}";
        std::string msg_str = msg_stream.str();
        std::vector<uint8_t> message(msg_str.begin(), msg_str.end());

        // Firmware context for domain separation
        std::vector<uint8_t> ctx = {'f', 'i', 'r', 'm', 'w', 'a', 'r', 'e'};

        // Sign
        if (!quiet) std::cerr << "Signing with " << algorithm << "...\n";
        std::vector<uint8_t> signature;
        AlgorithmInfo alg_info = get_algorithm_info(algorithm);

        if (algorithm == "mldsa44") {
            signature = sign_mldsa<mldsa::MLDSA44>(sk, message, ctx);
        } else if (algorithm == "mldsa65") {
            signature = sign_mldsa<mldsa::MLDSA65>(sk, message, ctx);
        } else if (algorithm == "mldsa87") {
            signature = sign_mldsa<mldsa::MLDSA87>(sk, message, ctx);
        } else if (algorithm == "slh-shake-128f") {
            signature = sign_slhdsa<slhdsa::SLHDSA_SHAKE_128f>(sk, message, ctx);
        } else if (algorithm == "slh-shake-192f") {
            signature = sign_slhdsa<slhdsa::SLHDSA_SHAKE_192f>(sk, message, ctx);
        } else if (algorithm == "slh-shake-256f") {
            signature = sign_slhdsa<slhdsa::SLHDSA_SHAKE_256f>(sk, message, ctx);
        } else {
            throw std::invalid_argument("Unsupported algorithm: " + algorithm);
        }

        if (!quiet) std::cerr << "Signature size: " << signature.size() << " bytes\n";

        // Create manifest
        std::string manifest = create_manifest(
            filename, fw_data.size(), hash256_hex, hash512_hex, timestamp,
            alg_info, signature, metadata
        );

        // Write output
        if (output_file.empty()) {
            output_file = fw_file + ".fwsig";
        }

        if (!write_text_file(output_file, manifest)) {
            std::cerr << "Error: Failed to write manifest file\n";
            return 1;
        }

        if (!quiet) {
            std::cerr << "Manifest written to: " << output_file << "\n";
            std::cerr << "\nFirmware Signing Summary:\n";
            std::cerr << "  Version:      " << metadata.version << " (code: " << metadata.version_code << ")\n";
            std::cerr << "  Device Type:  " << metadata.device_type << "\n";
            std::cerr << "  Size:         " << fw_data.size() << " bytes\n";
            std::cerr << "  Algorithm:    " << alg_info.name << "\n";
            std::cerr << "\nFirmware signed successfully!\n";
        }

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
