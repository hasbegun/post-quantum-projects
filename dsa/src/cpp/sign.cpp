/**
 * Post-Quantum Signing Tool
 *
 * Signs messages using ML-DSA or SLH-DSA secret keys.
 * Supports password-protected (encrypted) secret keys.
 *
 * Usage:
 *   ./sign <algorithm> <secret_key_file> <message_file> [options]
 *   ./sign <algorithm> <secret_key_file> --message <text> [options]
 *
 * Options:
 *   --message <text>     Sign this text instead of reading from file
 *   --output <file>      Write signature to file (default: stdout)
 *   --format <fmt>       Output format: hex (default), base64, binary
 *   --password <pass>    Password for encrypted key
 *   --password-stdin     Read password from stdin
 *
 * Examples:
 *   ./sign mldsa65 mykey_secret.key document.txt
 *   ./sign mldsa65 mykey_secret.key --message "Hello World"
 *   ./sign mldsa65 mykey_secret.key document.txt --output signature.sig
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <termios.h>
#include <unistd.h>

#include "mldsa/mldsa.hpp"
#include "slhdsa/slh_dsa.hpp"
#include "key_encryption.hpp"

// Read password from terminal with echo disabled
std::string read_password_from_terminal(const std::string& prompt) {
    std::cerr << prompt << std::flush;

    struct termios old_term, new_term;
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;
    new_term.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

    std::string password;
    std::getline(std::cin, password);

    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    std::cerr << std::endl;

    return password;
}

// Read password from stdin
std::string read_password_from_stdin() {
    std::string password;
    std::getline(std::cin, password);
    if (!password.empty() && password.back() == '\n') password.pop_back();
    if (!password.empty() && password.back() == '\r') password.pop_back();
    return password;
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

// Write binary file
bool write_file(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) return false;
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
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

// Base64 encoding
static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string to_base64(const std::vector<uint8_t>& data) {
    std::string result;
    int val = 0, valb = -6;
    for (uint8_t c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            result.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) result.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    while (result.size() % 4) result.push_back('=');
    return result;
}

// Sign with ML-DSA
template<typename DSA>
std::vector<uint8_t> sign_mldsa(const std::vector<uint8_t>& sk, const std::vector<uint8_t>& message) {
    DSA dsa;
    return dsa.sign(sk, message);
}

// Sign with SLH-DSA
template<typename DSA>
std::vector<uint8_t> sign_slhdsa(const std::vector<uint8_t>& sk, const std::vector<uint8_t>& message) {
    DSA dsa;
    return dsa.sign(sk, message);
}

void print_usage() {
    std::cout << "Post-Quantum Signing Tool" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
    std::cout << "\nUsage: sign <algorithm> <secret_key_file> <message_file> [options]" << std::endl;
    std::cout << "       sign <algorithm> <secret_key_file> --message <text> [options]" << std::endl;

    std::cout << "\nML-DSA algorithms (FIPS 204):" << std::endl;
    std::cout << "  mldsa44, mldsa65, mldsa87" << std::endl;

    std::cout << "\nSLH-DSA algorithms (FIPS 205):" << std::endl;
    std::cout << "  slh-shake-128f/s, slh-shake-192f/s, slh-shake-256f/s" << std::endl;
    std::cout << "  slh-sha2-128f/s, slh-sha2-192f/s, slh-sha2-256f/s" << std::endl;

    std::cout << "\nOptions:" << std::endl;
    std::cout << "  --message <text>     Sign this text instead of reading from file" << std::endl;
    std::cout << "  --output <file>      Write signature to file (default: stdout)" << std::endl;
    std::cout << "  --format <fmt>       Output format: hex (default), base64, binary" << std::endl;
    std::cout << "  --password <pass>    Password for encrypted secret key" << std::endl;
    std::cout << "  --password-stdin     Read password from stdin (first line)" << std::endl;

    std::cout << "\nExamples:" << std::endl;
    std::cout << "  # Sign a file (prompts for password if key is encrypted)" << std::endl;
    std::cout << "  sign mldsa65 mykey_secret.key document.txt" << std::endl;
    std::cout << std::endl;
    std::cout << "  # Sign inline text" << std::endl;
    std::cout << "  sign mldsa65 mykey_secret.key --message \"Hello World\"" << std::endl;
    std::cout << std::endl;
    std::cout << "  # Output to file in base64 format" << std::endl;
    std::cout << "  sign mldsa65 mykey_secret.key doc.txt --output sig.b64 --format base64" << std::endl;
    std::cout << std::endl;
    std::cout << "  # With password on command line" << std::endl;
    std::cout << "  sign mldsa65 mykey_secret.key doc.txt --password mysecret" << std::endl;
    std::cout << std::endl;
    std::cout << "  # Password from stdin (for scripts)" << std::endl;
    std::cout << "  echo 'mypassword' | sign mldsa65 mykey_secret.key doc.txt --password-stdin" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        print_usage();
        return 0;
    }

    std::string algorithm = argv[1];
    std::string sk_file = argv[2];
    std::string message_file;
    std::string message_text;
    std::string output_file;
    std::string format = "hex";
    std::string password;
    bool password_stdin = false;

    // Parse arguments
    int i = 3;
    while (i < argc) {
        std::string arg = argv[i];

        if (arg == "--message" && i + 1 < argc) {
            message_text = argv[++i];
        } else if (arg == "--output" && i + 1 < argc) {
            output_file = argv[++i];
        } else if (arg == "--format" && i + 1 < argc) {
            format = argv[++i];
        } else if (arg == "--password" && i + 1 < argc) {
            password = argv[++i];
        } else if (arg == "--password-stdin") {
            password_stdin = true;
        } else if (arg == "--help" || arg == "-h") {
            print_usage();
            return 0;
        } else if (arg[0] != '-' && message_file.empty()) {
            message_file = arg;
        } else if (arg[0] == '-') {
            std::cerr << "Unknown option: " << arg << std::endl;
            return 1;
        }
        ++i;
    }

    // Check we have a message source
    if (message_file.empty() && message_text.empty()) {
        std::cerr << "Error: No message provided. Use <message_file> or --message <text>" << std::endl;
        return 1;
    }

    // Convert algorithm to lowercase
    std::transform(algorithm.begin(), algorithm.end(), algorithm.begin(), ::tolower);

    try {
        // Read secret key
        std::cerr << "Reading secret key from: " << sk_file << std::endl;
        auto sk_data = read_file(sk_file);

        // Check if key is encrypted
        std::vector<uint8_t> sk;
        if (pqc::is_encrypted_key(sk_data)) {
            std::cerr << "Secret key is encrypted." << std::endl;

            // Get password
            if (password_stdin) {
                password = read_password_from_stdin();
            } else if (password.empty()) {
                password = read_password_from_terminal("Enter password: ");
            }

            if (password.empty()) {
                std::cerr << "Error: Password required for encrypted key" << std::endl;
                return 1;
            }

            // Decrypt
            std::cerr << "Decrypting secret key..." << std::endl;
            try {
                sk = pqc::decrypt_secret_key(sk_data, password);
                std::cerr << "Decryption successful." << std::endl;
            } catch (const std::exception& e) {
                std::cerr << "Error: " << e.what() << std::endl;
                return 1;
            }
        } else {
            sk = sk_data;
        }

        // Read message
        std::vector<uint8_t> message;
        if (!message_text.empty()) {
            message = std::vector<uint8_t>(message_text.begin(), message_text.end());
            std::cerr << "Message: \"" << message_text << "\" (" << message.size() << " bytes)" << std::endl;
        } else {
            message = read_file(message_file);
            std::cerr << "Message file: " << message_file << " (" << message.size() << " bytes)" << std::endl;
        }

        // Sign based on algorithm
        std::cerr << "Signing with " << algorithm << "..." << std::endl;
        std::vector<uint8_t> signature;

        // ML-DSA algorithms
        if (algorithm == "mldsa44") {
            signature = sign_mldsa<mldsa::MLDSA44>(sk, message);
        } else if (algorithm == "mldsa65") {
            signature = sign_mldsa<mldsa::MLDSA65>(sk, message);
        } else if (algorithm == "mldsa87") {
            signature = sign_mldsa<mldsa::MLDSA87>(sk, message);
        }
        // SLH-DSA SHAKE algorithms
        else if (algorithm == "slh-shake-128f") {
            signature = sign_slhdsa<slhdsa::SLHDSA_SHAKE_128f>(sk, message);
        } else if (algorithm == "slh-shake-128s") {
            signature = sign_slhdsa<slhdsa::SLHDSA_SHAKE_128s>(sk, message);
        } else if (algorithm == "slh-shake-192f") {
            signature = sign_slhdsa<slhdsa::SLHDSA_SHAKE_192f>(sk, message);
        } else if (algorithm == "slh-shake-192s") {
            signature = sign_slhdsa<slhdsa::SLHDSA_SHAKE_192s>(sk, message);
        } else if (algorithm == "slh-shake-256f") {
            signature = sign_slhdsa<slhdsa::SLHDSA_SHAKE_256f>(sk, message);
        } else if (algorithm == "slh-shake-256s") {
            signature = sign_slhdsa<slhdsa::SLHDSA_SHAKE_256s>(sk, message);
        }
        // SLH-DSA SHA2 algorithms
        else if (algorithm == "slh-sha2-128f") {
            signature = sign_slhdsa<slhdsa::SLHDSA_SHA2_128f>(sk, message);
        } else if (algorithm == "slh-sha2-128s") {
            signature = sign_slhdsa<slhdsa::SLHDSA_SHA2_128s>(sk, message);
        } else if (algorithm == "slh-sha2-192f") {
            signature = sign_slhdsa<slhdsa::SLHDSA_SHA2_192f>(sk, message);
        } else if (algorithm == "slh-sha2-192s") {
            signature = sign_slhdsa<slhdsa::SLHDSA_SHA2_192s>(sk, message);
        } else if (algorithm == "slh-sha2-256f") {
            signature = sign_slhdsa<slhdsa::SLHDSA_SHA2_256f>(sk, message);
        } else if (algorithm == "slh-sha2-256s") {
            signature = sign_slhdsa<slhdsa::SLHDSA_SHA2_256s>(sk, message);
        } else {
            std::cerr << "Error: Unknown algorithm '" << algorithm << "'" << std::endl;
            return 1;
        }

        std::cerr << "Signature size: " << signature.size() << " bytes" << std::endl;

        // Output signature
        if (format == "binary") {
            if (!output_file.empty()) {
                if (!write_file(output_file, signature)) {
                    std::cerr << "Error: Failed to write signature to " << output_file << std::endl;
                    return 1;
                }
                std::cerr << "Signature written to: " << output_file << std::endl;
            } else {
                std::cout.write(reinterpret_cast<const char*>(signature.data()), signature.size());
            }
        } else {
            std::string output;
            if (format == "base64") {
                output = to_base64(signature);
            } else {
                output = to_hex(signature);
            }

            if (!output_file.empty()) {
                std::ofstream file(output_file);
                if (!file) {
                    std::cerr << "Error: Failed to write to " << output_file << std::endl;
                    return 1;
                }
                file << output << std::endl;
                std::cerr << "Signature written to: " << output_file << std::endl;
            } else {
                std::cout << output << std::endl;
            }
        }

        std::cerr << "Signing complete." << std::endl;
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
