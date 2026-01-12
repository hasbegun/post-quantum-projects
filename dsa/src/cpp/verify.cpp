/**
 * Post-Quantum Signature Verification Tool
 *
 * Verifies signatures using ML-DSA or SLH-DSA public keys.
 *
 * Usage:
 *   ./verify <algorithm> <public_key_file> <message_file> <signature_file> [options]
 *   ./verify <algorithm> <public_key_file> --message <text> <signature_file> [options]
 *
 * Options:
 *   --message <text>     Verify this text instead of reading from file
 *   --format <fmt>       Signature format: binary (default), hex, base64
 *   --quiet              Only output VALID or INVALID
 *
 * Exit codes:
 *   0 - Signature is valid
 *   1 - Signature is invalid or error occurred
 *
 * Examples:
 *   ./verify mldsa65 public.key firmware.bin firmware.sig
 *   ./verify mldsa65 public.key --message "Hello" signature.hex --format hex
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <algorithm>

#include "mldsa/mldsa.hpp"
#include "slhdsa/slh_dsa.hpp"

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

// Read text file and return as string
std::string read_text_file(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + path);
    }
    std::ostringstream ss;
    ss << file.rdbuf();
    std::string content = ss.str();
    // Trim trailing newline if present
    while (!content.empty() && (content.back() == '\n' || content.back() == '\r')) {
        content.pop_back();
    }
    return content;
}

// Convert hex string to bytes
std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(std::strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// Base64 decoding
std::vector<uint8_t> from_base64(const std::string& encoded) {
    static const std::string base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    std::vector<uint8_t> result;
    int val = 0, valb = -8;

    for (char c : encoded) {
        if (c == '=') break;
        size_t pos = base64_chars.find(c);
        if (pos == std::string::npos) continue;  // Skip invalid chars

        val = (val << 6) + static_cast<int>(pos);
        valb += 6;
        if (valb >= 0) {
            result.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return result;
}

// Verify with ML-DSA
template<typename DSA>
bool verify_mldsa(const std::vector<uint8_t>& pk,
                  const std::vector<uint8_t>& message,
                  const std::vector<uint8_t>& signature) {
    DSA dsa;
    return dsa.verify(pk, message, signature);
}

// Verify with SLH-DSA
template<typename DSA>
bool verify_slhdsa(const std::vector<uint8_t>& pk,
                   const std::vector<uint8_t>& message,
                   const std::vector<uint8_t>& signature) {
    DSA dsa;
    return dsa.verify(pk, message, signature);
}

void print_usage() {
    std::cout << "Post-Quantum Signature Verification Tool" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
    std::cout << "\nUsage: verify <algorithm> <public_key> <message_file> <signature_file> [options]" << std::endl;
    std::cout << "       verify <algorithm> <public_key> --message <text> <signature_file> [options]" << std::endl;

    std::cout << "\nML-DSA algorithms (FIPS 204):" << std::endl;
    std::cout << "  mldsa44, mldsa65, mldsa87" << std::endl;

    std::cout << "\nSLH-DSA algorithms (FIPS 205):" << std::endl;
    std::cout << "  slh-shake-128f/s, slh-shake-192f/s, slh-shake-256f/s" << std::endl;
    std::cout << "  slh-sha2-128f/s, slh-sha2-192f/s, slh-sha2-256f/s" << std::endl;

    std::cout << "\nOptions:" << std::endl;
    std::cout << "  --message <text>     Verify this text instead of reading from file" << std::endl;
    std::cout << "  --format <fmt>       Signature format: binary (default), hex, base64" << std::endl;
    std::cout << "  --quiet              Only output VALID or INVALID" << std::endl;

    std::cout << "\nExit codes:" << std::endl;
    std::cout << "  0 - Signature is VALID" << std::endl;
    std::cout << "  1 - Signature is INVALID or error occurred" << std::endl;

    std::cout << "\nExamples:" << std::endl;
    std::cout << "  # Verify a firmware signature" << std::endl;
    std::cout << "  verify mldsa65 firmware_public.key firmware.bin firmware.sig" << std::endl;
    std::cout << std::endl;
    std::cout << "  # Verify with hex-encoded signature" << std::endl;
    std::cout << "  verify mldsa65 public.key document.txt signature.hex --format hex" << std::endl;
    std::cout << std::endl;
    std::cout << "  # Verify inline text" << std::endl;
    std::cout << "  verify mldsa65 public.key --message \"Hello World\" signature.sig" << std::endl;
    std::cout << std::endl;
    std::cout << "  # Quiet mode for scripts" << std::endl;
    std::cout << "  verify mldsa65 public.key file.bin file.sig --quiet && echo OK" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 4) {
        print_usage();
        return 1;
    }

    std::string algorithm = argv[1];
    std::string pk_file = argv[2];
    std::string message_file;
    std::string message_text;
    std::string sig_file;
    std::string format = "binary";
    bool quiet = false;

    // Parse arguments
    int i = 3;
    while (i < argc) {
        std::string arg = argv[i];

        if (arg == "--message" && i + 1 < argc) {
            message_text = argv[++i];
        } else if (arg == "--format" && i + 1 < argc) {
            format = argv[++i];
        } else if (arg == "--quiet" || arg == "-q") {
            quiet = true;
        } else if (arg == "--help" || arg == "-h") {
            print_usage();
            return 0;
        } else if (arg[0] != '-') {
            // Positional arguments: message_file and sig_file
            if (message_file.empty() && message_text.empty()) {
                message_file = arg;
            } else if (sig_file.empty()) {
                sig_file = arg;
            }
        } else {
            std::cerr << "Unknown option: " << arg << std::endl;
            return 1;
        }
        ++i;
    }

    // Check we have message and signature
    if (message_file.empty() && message_text.empty()) {
        std::cerr << "Error: No message provided. Use <message_file> or --message <text>" << std::endl;
        return 1;
    }
    if (sig_file.empty()) {
        std::cerr << "Error: No signature file provided" << std::endl;
        return 1;
    }

    // Convert algorithm to lowercase
    std::transform(algorithm.begin(), algorithm.end(), algorithm.begin(), ::tolower);

    try {
        // Read public key
        if (!quiet) std::cerr << "Reading public key from: " << pk_file << std::endl;
        auto pk = read_file(pk_file);
        if (!quiet) std::cerr << "Public key size: " << pk.size() << " bytes" << std::endl;

        // Read message
        std::vector<uint8_t> message;
        if (!message_text.empty()) {
            message = std::vector<uint8_t>(message_text.begin(), message_text.end());
            if (!quiet) std::cerr << "Message: \"" << message_text << "\" (" << message.size() << " bytes)" << std::endl;
        } else {
            message = read_file(message_file);
            if (!quiet) std::cerr << "Message file: " << message_file << " (" << message.size() << " bytes)" << std::endl;
        }

        // Read signature
        std::vector<uint8_t> signature;
        if (format == "binary") {
            signature = read_file(sig_file);
        } else if (format == "hex") {
            std::string hex_content = read_text_file(sig_file);
            signature = from_hex(hex_content);
        } else if (format == "base64") {
            std::string b64_content = read_text_file(sig_file);
            signature = from_base64(b64_content);
        } else {
            std::cerr << "Error: Unknown format '" << format << "'. Use: binary, hex, base64" << std::endl;
            return 1;
        }
        if (!quiet) std::cerr << "Signature size: " << signature.size() << " bytes" << std::endl;

        // Verify based on algorithm
        if (!quiet) std::cerr << "Verifying with " << algorithm << "..." << std::endl;
        bool valid = false;

        // ML-DSA algorithms
        if (algorithm == "mldsa44") {
            valid = verify_mldsa<mldsa::MLDSA44>(pk, message, signature);
        } else if (algorithm == "mldsa65") {
            valid = verify_mldsa<mldsa::MLDSA65>(pk, message, signature);
        } else if (algorithm == "mldsa87") {
            valid = verify_mldsa<mldsa::MLDSA87>(pk, message, signature);
        }
        // SLH-DSA SHAKE algorithms
        else if (algorithm == "slh-shake-128f") {
            valid = verify_slhdsa<slhdsa::SLHDSA_SHAKE_128f>(pk, message, signature);
        } else if (algorithm == "slh-shake-128s") {
            valid = verify_slhdsa<slhdsa::SLHDSA_SHAKE_128s>(pk, message, signature);
        } else if (algorithm == "slh-shake-192f") {
            valid = verify_slhdsa<slhdsa::SLHDSA_SHAKE_192f>(pk, message, signature);
        } else if (algorithm == "slh-shake-192s") {
            valid = verify_slhdsa<slhdsa::SLHDSA_SHAKE_192s>(pk, message, signature);
        } else if (algorithm == "slh-shake-256f") {
            valid = verify_slhdsa<slhdsa::SLHDSA_SHAKE_256f>(pk, message, signature);
        } else if (algorithm == "slh-shake-256s") {
            valid = verify_slhdsa<slhdsa::SLHDSA_SHAKE_256s>(pk, message, signature);
        }
        // SLH-DSA SHA2 algorithms
        else if (algorithm == "slh-sha2-128f") {
            valid = verify_slhdsa<slhdsa::SLHDSA_SHA2_128f>(pk, message, signature);
        } else if (algorithm == "slh-sha2-128s") {
            valid = verify_slhdsa<slhdsa::SLHDSA_SHA2_128s>(pk, message, signature);
        } else if (algorithm == "slh-sha2-192f") {
            valid = verify_slhdsa<slhdsa::SLHDSA_SHA2_192f>(pk, message, signature);
        } else if (algorithm == "slh-sha2-192s") {
            valid = verify_slhdsa<slhdsa::SLHDSA_SHA2_192s>(pk, message, signature);
        } else if (algorithm == "slh-sha2-256f") {
            valid = verify_slhdsa<slhdsa::SLHDSA_SHA2_256f>(pk, message, signature);
        } else if (algorithm == "slh-sha2-256s") {
            valid = verify_slhdsa<slhdsa::SLHDSA_SHA2_256s>(pk, message, signature);
        } else {
            std::cerr << "Error: Unknown algorithm '" << algorithm << "'" << std::endl;
            return 1;
        }

        // Output result
        if (valid) {
            std::cout << "VALID" << std::endl;
            if (!quiet) {
                std::cerr << "Signature verification successful." << std::endl;
            }
            return 0;
        } else {
            std::cout << "INVALID" << std::endl;
            if (!quiet) {
                std::cerr << "Signature verification FAILED." << std::endl;
            }
            return 1;
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
