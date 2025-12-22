/**
 * Post-Quantum Key Generation Tool
 *
 * Generates ML-DSA or SLH-DSA key pairs with certificate metadata,
 * similar to OpenSSL RSA key generation.
 *
 * Usage:
 *   ./keygen <algorithm> <output_prefix> [options]
 *
 * The output_prefix is used as the base filename. Generated files:
 *   <output_prefix>_public.key      - Public key (binary)
 *   <output_prefix>_secret.key      - Secret key (binary)
 *   <output_prefix>_certificate.json - Certificate metadata (JSON)
 *
 * Options:
 *   --cn <name>         Common Name (e.g., "example.com")
 *   --org <name>        Organization (e.g., "My Company")
 *   --ou <name>         Organizational Unit (e.g., "Engineering")
 *   --country <code>    Country code (e.g., "US")
 *   --state <name>      State/Province (e.g., "California")
 *   --locality <name>   City/Locality (e.g., "San Francisco")
 *   --email <email>     Email address
 *   --days <n>          Validity period in days (default: 365)
 *   --serial <n>        Serial number (default: auto-generated)
 *
 * Examples:
 *   ./keygen mldsa65 myserver
 *   # Creates: myserver_public.key, myserver_secret.key, myserver_certificate.json
 *
 *   ./keygen mldsa65 keys/api --cn "api.example.com" --org "My Corp"
 *   # Creates: keys/api_public.key, keys/api_secret.key, keys/api_certificate.json
 */

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <random>
#include <optional>
#include <termios.h>
#include <unistd.h>

#include "mldsa/mldsa.hpp"
#include "slhdsa/slh_dsa.hpp"
#include "key_encryption.hpp"

namespace fs = std::filesystem;

// Read password from terminal with echo disabled
std::string read_password_from_terminal(const std::string& prompt) {
    std::cout << prompt << std::flush;

    // Disable echo
    struct termios old_term, new_term;
    tcgetattr(STDIN_FILENO, &old_term);
    new_term = old_term;
    new_term.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_term);

    std::string password;
    std::getline(std::cin, password);

    // Restore terminal
    tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
    std::cout << std::endl;

    return password;
}

// Read password from stdin (for piping)
std::string read_password_from_stdin() {
    std::string password;
    std::getline(std::cin, password);
    // Remove trailing newline if present
    if (!password.empty() && password.back() == '\n') {
        password.pop_back();
    }
    if (!password.empty() && password.back() == '\r') {
        password.pop_back();
    }
    return password;
}

// Certificate subject information
struct Subject {
    std::string common_name;        // CN
    std::string organization;       // O
    std::string organizational_unit; // OU
    std::string country;            // C
    std::string state;              // ST
    std::string locality;           // L
    std::string email;              // emailAddress

    std::string to_dn() const {
        std::vector<std::string> parts;
        if (!country.empty()) parts.push_back("C=" + country);
        if (!state.empty()) parts.push_back("ST=" + state);
        if (!locality.empty()) parts.push_back("L=" + locality);
        if (!organization.empty()) parts.push_back("O=" + organization);
        if (!organizational_unit.empty()) parts.push_back("OU=" + organizational_unit);
        if (!common_name.empty()) parts.push_back("CN=" + common_name);
        if (!email.empty()) parts.push_back("emailAddress=" + email);

        std::string dn;
        for (size_t i = 0; i < parts.size(); ++i) {
            if (i > 0) dn += ", ";
            dn += parts[i];
        }
        return dn;
    }

    bool empty() const {
        return common_name.empty() && organization.empty() &&
               organizational_unit.empty() && country.empty() &&
               state.empty() && locality.empty() && email.empty();
    }
};

// Encryption info for certificate
struct EncryptionInfo {
    bool encrypted = false;
    std::string cipher = "";
    std::string kdf = "";
    int kdf_iterations = 0;
};

// Certificate metadata
struct CertificateInfo {
    Subject subject;
    int validity_days = 365;
    uint64_t serial_number = 0;
    EncryptionInfo encryption;
};

// Get current ISO timestamp
std::string get_timestamp() {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

// Get timestamp offset by days
std::string get_timestamp_offset(int days) {
    auto now = std::chrono::system_clock::now();
    auto offset = now + std::chrono::hours(24 * days);
    auto time = std::chrono::system_clock::to_time_t(offset);
    std::stringstream ss;
    ss << std::put_time(std::gmtime(&time), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

// Generate random serial number
uint64_t generate_serial() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(1, UINT64_MAX);
    return dis(gen);
}

// Escape JSON string
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

// Write binary file
bool write_file(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream file(path, std::ios::binary);
    if (!file) return false;
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
    return file.good();
}

// Write comprehensive JSON metadata (certificate-like)
bool write_metadata(const std::string& path,
                    const std::string& algorithm,
                    const std::string& type,
                    size_t pk_size,
                    size_t sk_size,
                    size_t sig_size,
                    const std::string& pk_file,
                    const std::string& sk_file,
                    const CertificateInfo& cert_info) {
    std::ofstream file(path);
    if (!file) return false;

    std::string created = get_timestamp();
    std::string not_after = get_timestamp_offset(cert_info.validity_days);

    file << "{\n";
    file << "  \"version\": 1,\n";
    file << "  \"algorithm\": \"" << algorithm << "\",\n";
    file << "  \"type\": \"" << type << "\",\n";
    file << "  \"standard\": \"" << (type.find("ML-DSA") != std::string::npos ? "FIPS 204" : "FIPS 205") << "\",\n";
    file << "\n";
    file << "  \"subject\": {\n";
    file << "    \"commonName\": \"" << json_escape(cert_info.subject.common_name) << "\",\n";
    file << "    \"organization\": \"" << json_escape(cert_info.subject.organization) << "\",\n";
    file << "    \"organizationalUnit\": \"" << json_escape(cert_info.subject.organizational_unit) << "\",\n";
    file << "    \"country\": \"" << json_escape(cert_info.subject.country) << "\",\n";
    file << "    \"state\": \"" << json_escape(cert_info.subject.state) << "\",\n";
    file << "    \"locality\": \"" << json_escape(cert_info.subject.locality) << "\",\n";
    file << "    \"email\": \"" << json_escape(cert_info.subject.email) << "\",\n";
    file << "    \"dn\": \"" << json_escape(cert_info.subject.to_dn()) << "\"\n";
    file << "  },\n";
    file << "\n";
    file << "  \"validity\": {\n";
    file << "    \"notBefore\": \"" << created << "\",\n";
    file << "    \"notAfter\": \"" << not_after << "\",\n";
    file << "    \"days\": " << cert_info.validity_days << "\n";
    file << "  },\n";
    file << "\n";
    file << "  \"serialNumber\": \"" << std::hex << std::setfill('0') << std::setw(16) << cert_info.serial_number << std::dec << "\",\n";
    file << "\n";
    file << "  \"keyInfo\": {\n";
    file << "    \"publicKeySize\": " << pk_size << ",\n";
    file << "    \"secretKeySize\": " << sk_size << ",\n";
    file << "    \"signatureSize\": " << sig_size << ",\n";
    file << "    \"publicKeyFile\": \"" << pk_file << "\",\n";
    file << "    \"secretKeyFile\": \"" << sk_file << "\"\n";
    file << "  },\n";
    file << "\n";

    // Encryption info
    file << "  \"encryption\": {\n";
    file << "    \"encrypted\": " << (cert_info.encryption.encrypted ? "true" : "false");
    if (cert_info.encryption.encrypted) {
        file << ",\n";
        file << "    \"cipher\": \"" << cert_info.encryption.cipher << "\",\n";
        file << "    \"kdf\": \"" << cert_info.encryption.kdf << "\",\n";
        file << "    \"kdfIterations\": " << cert_info.encryption.kdf_iterations << "\n";
    } else {
        file << "\n";
    }
    file << "  },\n";
    file << "\n";
    file << "  \"created\": \"" << created << "\"\n";
    file << "}\n";

    return file.good();
}

// Generate ML-DSA keys
template<typename DSA>
bool generate_mldsa(const std::string& name, const std::string& output_prefix,
                    CertificateInfo& cert_info, const std::string& password = "") {
    DSA dsa;

    std::cout << "Generating " << name << " key pair..." << std::endl;

    auto start = std::chrono::high_resolution_clock::now();
    auto [pk, sk] = dsa.keygen();
    auto end = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::cout << "  Key generation completed in " << ms << " ms" << std::endl;

    // Get signature size from params
    size_t sig_size = dsa.params().sig_size();

    // Create file paths using the output prefix
    std::string pk_path = output_prefix + "_public.key";
    std::string sk_path = output_prefix + "_secret.key";
    std::string meta_path = output_prefix + "_certificate.json";

    // Extract just the filename for the certificate JSON
    std::string pk_file = fs::path(pk_path).filename().string();
    std::string sk_file = fs::path(sk_path).filename().string();

    // Write public key (never encrypted)
    if (!write_file(pk_path, pk)) {
        std::cerr << "Error: Failed to write public key" << std::endl;
        return false;
    }

    // Write secret key (optionally encrypted)
    if (!password.empty()) {
        std::cout << "  Encrypting secret key..." << std::endl;
        try {
            uint32_t alg_id = pqc::get_algorithm_id(name);
            auto encrypted_sk = pqc::encrypt_secret_key(sk, password, alg_id);
            if (!write_file(sk_path, encrypted_sk)) {
                std::cerr << "Error: Failed to write encrypted secret key" << std::endl;
                return false;
            }
            // Update certificate info
            cert_info.encryption.encrypted = true;
            cert_info.encryption.cipher = "AES-256-GCM";
            cert_info.encryption.kdf = "PBKDF2-HMAC-SHA256";
            cert_info.encryption.kdf_iterations = pqc::PBKDF2_ITERATIONS;
        } catch (const std::exception& e) {
            std::cerr << "Error: Encryption failed: " << e.what() << std::endl;
            return false;
        }
    } else {
        if (!write_file(sk_path, sk)) {
            std::cerr << "Error: Failed to write secret key" << std::endl;
            return false;
        }
    }

    if (!write_metadata(meta_path, name, "ML-DSA",
                        pk.size(), sk.size(), sig_size,
                        pk_file, sk_file, cert_info)) {
        std::cerr << "Error: Failed to write certificate metadata" << std::endl;
        return false;
    }

    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "Key Pair Generated Successfully" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    std::cout << "\nAlgorithm:       " << name << std::endl;
    std::cout << "Type:            ML-DSA (FIPS 204)" << std::endl;
    std::cout << "Public Key:      " << pk.size() << " bytes" << std::endl;
    std::cout << "Secret Key:      " << sk.size() << " bytes";
    if (cert_info.encryption.encrypted) {
        std::cout << " (encrypted)";
    }
    std::cout << std::endl;
    std::cout << "Signature Size:  " << sig_size << " bytes" << std::endl;

    if (cert_info.encryption.encrypted) {
        std::cout << "\nEncryption:" << std::endl;
        std::cout << "  Cipher:        " << cert_info.encryption.cipher << std::endl;
        std::cout << "  KDF:           " << cert_info.encryption.kdf << std::endl;
        std::cout << "  Iterations:    " << cert_info.encryption.kdf_iterations << std::endl;
    }

    if (!cert_info.subject.empty()) {
        std::cout << "\nSubject:" << std::endl;
        if (!cert_info.subject.common_name.empty())
            std::cout << "  Common Name:   " << cert_info.subject.common_name << std::endl;
        if (!cert_info.subject.organization.empty())
            std::cout << "  Organization:  " << cert_info.subject.organization << std::endl;
        if (!cert_info.subject.organizational_unit.empty())
            std::cout << "  Org Unit:      " << cert_info.subject.organizational_unit << std::endl;
        if (!cert_info.subject.country.empty())
            std::cout << "  Country:       " << cert_info.subject.country << std::endl;
        if (!cert_info.subject.state.empty())
            std::cout << "  State:         " << cert_info.subject.state << std::endl;
        if (!cert_info.subject.locality.empty())
            std::cout << "  Locality:      " << cert_info.subject.locality << std::endl;
        if (!cert_info.subject.email.empty())
            std::cout << "  Email:         " << cert_info.subject.email << std::endl;
    }

    std::cout << "\nValidity:" << std::endl;
    std::cout << "  Not Before:    " << get_timestamp() << std::endl;
    std::cout << "  Not After:     " << get_timestamp_offset(cert_info.validity_days) << std::endl;
    std::cout << "  Duration:      " << cert_info.validity_days << " days" << std::endl;

    std::cout << "\nSerial Number:   " << std::hex << std::setfill('0')
              << std::setw(16) << cert_info.serial_number << std::dec << std::endl;

    std::cout << "\nOutput Files:" << std::endl;
    std::cout << "  " << pk_path << std::endl;
    std::cout << "  " << sk_path << std::endl;
    std::cout << "  " << meta_path << std::endl;

    return true;
}

// Generate SLH-DSA keys
template<typename DSA>
bool generate_slhdsa(const std::string& name, const std::string& output_prefix,
                     CertificateInfo& cert_info, const std::string& password = "") {
    DSA dsa;

    std::cout << "Generating " << name << " key pair..." << std::endl;

    auto start = std::chrono::high_resolution_clock::now();
    auto [sk, pk] = dsa.keygen();  // Note: SLH-DSA returns (sk, pk)
    auto end = std::chrono::high_resolution_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    std::cout << "  Key generation completed in " << ms << " ms" << std::endl;

    // Get signature size from params
    size_t sig_size = dsa.params().sig_size();

    // Create file paths using the output prefix
    std::string pk_path = output_prefix + "_public.key";
    std::string sk_path = output_prefix + "_secret.key";
    std::string meta_path = output_prefix + "_certificate.json";

    // Extract just the filename for the certificate JSON
    std::string pk_file = fs::path(pk_path).filename().string();
    std::string sk_file = fs::path(sk_path).filename().string();

    // Write public key (never encrypted)
    if (!write_file(pk_path, pk)) {
        std::cerr << "Error: Failed to write public key" << std::endl;
        return false;
    }

    // Write secret key (optionally encrypted)
    if (!password.empty()) {
        std::cout << "  Encrypting secret key..." << std::endl;
        try {
            uint32_t alg_id = pqc::get_algorithm_id(name);
            auto encrypted_sk = pqc::encrypt_secret_key(sk, password, alg_id);
            if (!write_file(sk_path, encrypted_sk)) {
                std::cerr << "Error: Failed to write encrypted secret key" << std::endl;
                return false;
            }
            // Update certificate info
            cert_info.encryption.encrypted = true;
            cert_info.encryption.cipher = "AES-256-GCM";
            cert_info.encryption.kdf = "PBKDF2-HMAC-SHA256";
            cert_info.encryption.kdf_iterations = pqc::PBKDF2_ITERATIONS;
        } catch (const std::exception& e) {
            std::cerr << "Error: Encryption failed: " << e.what() << std::endl;
            return false;
        }
    } else {
        if (!write_file(sk_path, sk)) {
            std::cerr << "Error: Failed to write secret key" << std::endl;
            return false;
        }
    }

    if (!write_metadata(meta_path, name, "SLH-DSA",
                        pk.size(), sk.size(), sig_size,
                        pk_file, sk_file, cert_info)) {
        std::cerr << "Error: Failed to write certificate metadata" << std::endl;
        return false;
    }

    std::cout << "\n" << std::string(60, '=') << std::endl;
    std::cout << "Key Pair Generated Successfully" << std::endl;
    std::cout << std::string(60, '=') << std::endl;

    std::cout << "\nAlgorithm:       " << name << std::endl;
    std::cout << "Type:            SLH-DSA (FIPS 205)" << std::endl;
    std::cout << "Public Key:      " << pk.size() << " bytes" << std::endl;
    std::cout << "Secret Key:      " << sk.size() << " bytes";
    if (cert_info.encryption.encrypted) {
        std::cout << " (encrypted)";
    }
    std::cout << std::endl;
    std::cout << "Signature Size:  " << sig_size << " bytes" << std::endl;

    if (cert_info.encryption.encrypted) {
        std::cout << "\nEncryption:" << std::endl;
        std::cout << "  Cipher:        " << cert_info.encryption.cipher << std::endl;
        std::cout << "  KDF:           " << cert_info.encryption.kdf << std::endl;
        std::cout << "  Iterations:    " << cert_info.encryption.kdf_iterations << std::endl;
    }

    if (!cert_info.subject.empty()) {
        std::cout << "\nSubject:" << std::endl;
        if (!cert_info.subject.common_name.empty())
            std::cout << "  Common Name:   " << cert_info.subject.common_name << std::endl;
        if (!cert_info.subject.organization.empty())
            std::cout << "  Organization:  " << cert_info.subject.organization << std::endl;
        if (!cert_info.subject.organizational_unit.empty())
            std::cout << "  Org Unit:      " << cert_info.subject.organizational_unit << std::endl;
        if (!cert_info.subject.country.empty())
            std::cout << "  Country:       " << cert_info.subject.country << std::endl;
        if (!cert_info.subject.state.empty())
            std::cout << "  State:         " << cert_info.subject.state << std::endl;
        if (!cert_info.subject.locality.empty())
            std::cout << "  Locality:      " << cert_info.subject.locality << std::endl;
        if (!cert_info.subject.email.empty())
            std::cout << "  Email:         " << cert_info.subject.email << std::endl;
    }

    std::cout << "\nValidity:" << std::endl;
    std::cout << "  Not Before:    " << get_timestamp() << std::endl;
    std::cout << "  Not After:     " << get_timestamp_offset(cert_info.validity_days) << std::endl;
    std::cout << "  Duration:      " << cert_info.validity_days << " days" << std::endl;

    std::cout << "\nSerial Number:   " << std::hex << std::setfill('0')
              << std::setw(16) << cert_info.serial_number << std::dec << std::endl;

    std::cout << "\nOutput Files:" << std::endl;
    std::cout << "  " << pk_path << std::endl;
    std::cout << "  " << sk_path << std::endl;
    std::cout << "  " << meta_path << std::endl;

    return true;
}

void print_usage() {
    std::cout << "Post-Quantum Key Generator" << std::endl;
    std::cout << std::string(60, '=') << std::endl;
    std::cout << "\nUsage: keygen <algorithm> <output_prefix> [options]" << std::endl;
    std::cout << "\nThe output_prefix is the base filename for generated files:" << std::endl;
    std::cout << "  <prefix>_public.key       - Public key (binary)" << std::endl;
    std::cout << "  <prefix>_secret.key       - Secret key (binary)" << std::endl;
    std::cout << "  <prefix>_certificate.json - Certificate metadata (JSON)" << std::endl;
    std::cout << "\nML-DSA algorithms (FIPS 204 - fast, smaller signatures):" << std::endl;
    std::cout << "  mldsa44          - Category 1 (128-bit security)" << std::endl;
    std::cout << "  mldsa65          - Category 3 (192-bit security)" << std::endl;
    std::cout << "  mldsa87          - Category 5 (256-bit security)" << std::endl;
    std::cout << "\nSLH-DSA algorithms (FIPS 205 - hash-based, conservative):" << std::endl;
    std::cout << "  slh-shake-128f   - SHAKE, fast variant" << std::endl;
    std::cout << "  slh-shake-128s   - SHAKE, small signatures" << std::endl;
    std::cout << "  slh-shake-192f   - SHAKE, Category 3, fast" << std::endl;
    std::cout << "  slh-shake-192s   - SHAKE, Category 3, small" << std::endl;
    std::cout << "  slh-shake-256f   - SHAKE, Category 5, fast" << std::endl;
    std::cout << "  slh-shake-256s   - SHAKE, Category 5, small" << std::endl;
    std::cout << "  slh-sha2-128f    - SHA2, fast variant" << std::endl;
    std::cout << "  slh-sha2-128s    - SHA2, small signatures" << std::endl;
    std::cout << "  slh-sha2-192f    - SHA2, Category 3, fast" << std::endl;
    std::cout << "  slh-sha2-192s    - SHA2, Category 3, small" << std::endl;
    std::cout << "  slh-sha2-256f    - SHA2, Category 5, fast" << std::endl;
    std::cout << "  slh-sha2-256s    - SHA2, Category 5, small" << std::endl;

    std::cout << "\nCertificate Options (similar to OpenSSL):" << std::endl;
    std::cout << "  --cn <name>        Common Name (e.g., \"example.com\")" << std::endl;
    std::cout << "  --org <name>       Organization (e.g., \"My Company\")" << std::endl;
    std::cout << "  --ou <name>        Organizational Unit (e.g., \"Engineering\")" << std::endl;
    std::cout << "  --country <code>   2-letter country code (e.g., \"US\")" << std::endl;
    std::cout << "  --state <name>     State or Province (e.g., \"California\")" << std::endl;
    std::cout << "  --locality <name>  City or Locality (e.g., \"San Francisco\")" << std::endl;
    std::cout << "  --email <email>    Email address" << std::endl;
    std::cout << "  --days <n>         Validity period in days (default: 365)" << std::endl;
    std::cout << "  --serial <hex>     Serial number in hex (default: random)" << std::endl;

    std::cout << "\nPassword Protection:" << std::endl;
    std::cout << "  --password <pass>  Encrypt secret key with password" << std::endl;
    std::cout << "  --password-stdin   Read password from stdin (for scripts)" << std::endl;
    std::cout << "  --password-prompt  Prompt for password interactively" << std::endl;
    std::cout << std::endl;
    std::cout << "  The secret key is encrypted using AES-256-GCM with a key derived" << std::endl;
    std::cout << "  from the password using PBKDF2-HMAC-SHA256 (600,000 iterations)." << std::endl;

    std::cout << "\nExamples:" << std::endl;
    std::cout << "  # Basic key generation (creates myserver_*.key files)" << std::endl;
    std::cout << "  keygen mldsa65 myserver" << std::endl;
    std::cout << std::endl;
    std::cout << "  # Keys in a subdirectory (creates keys/api_*.key files)" << std::endl;
    std::cout << "  keygen mldsa65 keys/api --cn \"api.example.com\"" << std::endl;
    std::cout << std::endl;
    std::cout << "  # Password-protected secret key (prompted)" << std::endl;
    std::cout << "  keygen mldsa65 secure-key --password-prompt" << std::endl;
    std::cout << std::endl;
    std::cout << "  # Password-protected from stdin (for scripts)" << std::endl;
    std::cout << "  echo 'mypassword' | keygen mldsa65 key --password-stdin" << std::endl;
    std::cout << std::endl;
    std::cout << "  # TLS server certificate" << std::endl;
    std::cout << "  keygen mldsa65 tls-server \\" << std::endl;
    std::cout << "      --cn \"api.example.com\" \\" << std::endl;
    std::cout << "      --org \"Example Corp\" \\" << std::endl;
    std::cout << "      --country \"US\" \\" << std::endl;
    std::cout << "      --days 730" << std::endl;
    std::cout << std::endl;
    std::cout << "  # Code signing with password protection" << std::endl;
    std::cout << "  keygen slh-shake-256f code-signer \\" << std::endl;
    std::cout << "      --cn \"Code Signing\" \\" << std::endl;
    std::cout << "      --org \"My Company\" \\" << std::endl;
    std::cout << "      --password-prompt \\" << std::endl;
    std::cout << "      --days 1825" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 0;
    }

    std::string algorithm = argv[1];
    std::string output_prefix;
    std::string password;
    bool password_stdin = false;
    bool password_prompt = false;

    // Parse certificate options
    CertificateInfo cert_info;
    cert_info.serial_number = generate_serial();

    int i = 2;
    while (i < argc) {
        std::string arg = argv[i];

        if (arg[0] != '-' && output_prefix.empty()) {
            // First non-option argument is output prefix
            output_prefix = arg;
            ++i;
            continue;
        }

        if (arg == "--cn" && i + 1 < argc) {
            cert_info.subject.common_name = argv[++i];
        } else if (arg == "--org" && i + 1 < argc) {
            cert_info.subject.organization = argv[++i];
        } else if (arg == "--ou" && i + 1 < argc) {
            cert_info.subject.organizational_unit = argv[++i];
        } else if (arg == "--country" && i + 1 < argc) {
            cert_info.subject.country = argv[++i];
        } else if (arg == "--state" && i + 1 < argc) {
            cert_info.subject.state = argv[++i];
        } else if (arg == "--locality" && i + 1 < argc) {
            cert_info.subject.locality = argv[++i];
        } else if (arg == "--email" && i + 1 < argc) {
            cert_info.subject.email = argv[++i];
        } else if (arg == "--days" && i + 1 < argc) {
            cert_info.validity_days = std::stoi(argv[++i]);
        } else if (arg == "--serial" && i + 1 < argc) {
            cert_info.serial_number = std::stoull(argv[++i], nullptr, 16);
        } else if (arg == "--password" && i + 1 < argc) {
            password = argv[++i];
        } else if (arg == "--password-stdin") {
            password_stdin = true;
        } else if (arg == "--password-prompt") {
            password_prompt = true;
        } else if (arg == "--help" || arg == "-h") {
            print_usage();
            return 0;
        } else if (arg[0] == '-') {
            std::cerr << "Unknown option: " << arg << std::endl;
            return 1;
        }
        ++i;
    }

    // Handle password input methods
    if (password_stdin) {
        password = read_password_from_stdin();
        if (password.empty()) {
            std::cerr << "Error: No password provided via stdin" << std::endl;
            return 1;
        }
    } else if (password_prompt) {
        password = read_password_from_terminal("Enter password for secret key: ");
        if (password.empty()) {
            std::cerr << "Error: Password cannot be empty" << std::endl;
            return 1;
        }
        // Confirm password
        std::string confirm = read_password_from_terminal("Confirm password: ");
        if (password != confirm) {
            std::cerr << "Error: Passwords do not match" << std::endl;
            return 1;
        }
    }

    // Check output prefix is provided
    if (output_prefix.empty()) {
        std::cerr << "Error: Output prefix is required" << std::endl;
        std::cerr << "Usage: keygen <algorithm> <output_prefix> [options]" << std::endl;
        return 1;
    }

    // Convert algorithm to lowercase
    std::transform(algorithm.begin(), algorithm.end(), algorithm.begin(), ::tolower);

    // Create parent directory if output_prefix includes a path
    fs::path prefix_path(output_prefix);
    if (prefix_path.has_parent_path()) {
        fs::create_directories(prefix_path.parent_path());
    }

    std::cout << "Output prefix: " << output_prefix << std::endl;
    std::cout << std::endl;

    bool success = false;

    // ML-DSA algorithms
    if (algorithm == "mldsa44") {
        success = generate_mldsa<mldsa::MLDSA44>("MLDSA44", output_prefix, cert_info, password);
    } else if (algorithm == "mldsa65") {
        success = generate_mldsa<mldsa::MLDSA65>("MLDSA65", output_prefix, cert_info, password);
    } else if (algorithm == "mldsa87") {
        success = generate_mldsa<mldsa::MLDSA87>("MLDSA87", output_prefix, cert_info, password);
    }
    // SLH-DSA SHAKE algorithms
    else if (algorithm == "slh-shake-128f") {
        success = generate_slhdsa<slhdsa::SLHDSA_SHAKE_128f>("SLH-DSA-SHAKE-128f", output_prefix, cert_info, password);
    } else if (algorithm == "slh-shake-128s") {
        success = generate_slhdsa<slhdsa::SLHDSA_SHAKE_128s>("SLH-DSA-SHAKE-128s", output_prefix, cert_info, password);
    } else if (algorithm == "slh-shake-192f") {
        success = generate_slhdsa<slhdsa::SLHDSA_SHAKE_192f>("SLH-DSA-SHAKE-192f", output_prefix, cert_info, password);
    } else if (algorithm == "slh-shake-192s") {
        success = generate_slhdsa<slhdsa::SLHDSA_SHAKE_192s>("SLH-DSA-SHAKE-192s", output_prefix, cert_info, password);
    } else if (algorithm == "slh-shake-256f") {
        success = generate_slhdsa<slhdsa::SLHDSA_SHAKE_256f>("SLH-DSA-SHAKE-256f", output_prefix, cert_info, password);
    } else if (algorithm == "slh-shake-256s") {
        success = generate_slhdsa<slhdsa::SLHDSA_SHAKE_256s>("SLH-DSA-SHAKE-256s", output_prefix, cert_info, password);
    }
    // SLH-DSA SHA2 algorithms
    else if (algorithm == "slh-sha2-128f") {
        success = generate_slhdsa<slhdsa::SLHDSA_SHA2_128f>("SLH-DSA-SHA2-128f", output_prefix, cert_info, password);
    } else if (algorithm == "slh-sha2-128s") {
        success = generate_slhdsa<slhdsa::SLHDSA_SHA2_128s>("SLH-DSA-SHA2-128s", output_prefix, cert_info, password);
    } else if (algorithm == "slh-sha2-192f") {
        success = generate_slhdsa<slhdsa::SLHDSA_SHA2_192f>("SLH-DSA-SHA2-192f", output_prefix, cert_info, password);
    } else if (algorithm == "slh-sha2-192s") {
        success = generate_slhdsa<slhdsa::SLHDSA_SHA2_192s>("SLH-DSA-SHA2-192s", output_prefix, cert_info, password);
    } else if (algorithm == "slh-sha2-256f") {
        success = generate_slhdsa<slhdsa::SLHDSA_SHA2_256f>("SLH-DSA-SHA2-256f", output_prefix, cert_info, password);
    } else if (algorithm == "slh-sha2-256s") {
        success = generate_slhdsa<slhdsa::SLHDSA_SHA2_256s>("SLH-DSA-SHA2-256s", output_prefix, cert_info, password);
    } else {
        std::cerr << "Error: Unknown algorithm '" << algorithm << "'" << std::endl;
        std::cerr << "\nRun with --help to see available algorithms." << std::endl;
        return 1;
    }

    if (success) {
        std::cout << "\n" << std::string(60, '=') << std::endl;
        if (cert_info.encryption.encrypted) {
            std::cout << "Secret key is password-protected (encrypted)." << std::endl;
            std::cout << "You will need the password to use the secret key." << std::endl;
        } else {
            std::cout << "WARNING: Secret key is NOT encrypted!" << std::endl;
            std::cout << "         Consider using --password-prompt for protection." << std::endl;
        }
        std::cout << "         chmod 600 " << output_prefix << "_secret.key" << std::endl;
        std::cout << std::string(60, '=') << std::endl;
        return 0;
    }

    return 1;
}
