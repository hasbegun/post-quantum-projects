/**
 * Keygen Certificate Parameter Test Suite
 *
 * Tests that certificate parameters (CN, ORG, COUNTRY, etc.) are properly
 * written to the generated certificate JSON file.
 */

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <filesystem>
#include <cstdlib>
#include <regex>

namespace fs = std::filesystem;

// Simple test framework
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    std::cout << "Testing " << name << "... " << std::flush; \
    try

#define TEST_END \
    std::cout << "PASSED" << std::endl; \
    ++tests_passed; \
    } catch (const std::exception& e) { \
        std::cout << "FAILED: " << e.what() << std::endl; \
        ++tests_failed; \
    } catch (...) { \
        std::cout << "FAILED: Unknown exception" << std::endl; \
        ++tests_failed; \
    }

#define ASSERT_TRUE(cond) \
    if (!(cond)) throw std::runtime_error("Assertion failed: " #cond)

#define ASSERT_FALSE(cond) \
    if (cond) throw std::runtime_error("Assertion failed: NOT " #cond)

#define ASSERT_EQ(a, b) \
    if ((a) != (b)) { \
        std::ostringstream oss; \
        oss << "Assertion failed: expected '" << (b) << "' but got '" << (a) << "'"; \
        throw std::runtime_error(oss.str()); \
    }

// Read entire file content
std::string read_file(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error("Cannot open file: " + path);
    }
    std::ostringstream ss;
    ss << file.rdbuf();
    return ss.str();
}

// Simple JSON value extraction (handles strings and numbers)
std::string get_json_value(const std::string& json, const std::string& key) {
    // Search for "key": "value" or "key": value
    std::regex string_pattern("\"" + key + "\"\\s*:\\s*\"([^\"]*)\"");
    std::regex number_pattern("\"" + key + "\"\\s*:\\s*([0-9]+)");

    std::smatch match;
    if (std::regex_search(json, match, string_pattern)) {
        return match[1].str();
    }
    if (std::regex_search(json, match, number_pattern)) {
        return match[1].str();
    }
    return "";
}

// Check if JSON contains a key with specific value
bool json_contains(const std::string& json, const std::string& key, const std::string& value) {
    return get_json_value(json, key) == value;
}

// Check if JSON contains a substring
bool json_contains_text(const std::string& json, const std::string& text) {
    return json.find(text) != std::string::npos;
}

// Get path to keygen binary (assumes it's in ./build relative to test)
std::string get_keygen_path() {
    // Try common locations
    std::vector<std::string> paths = {
        "./build/keygen",
        "../build/keygen",
        "./keygen",
        "/app/build/keygen"  // Docker container path
    };

    for (const auto& path : paths) {
        if (fs::exists(path)) {
            return path;
        }
    }

    // Fall back to assuming it's in PATH
    return "keygen";
}

// Create a temporary directory for test output
class TempDir {
public:
    TempDir() {
        path_ = fs::temp_directory_path() / ("keygen_test_" + std::to_string(std::rand()));
        fs::create_directories(path_);
    }

    ~TempDir() {
        try {
            fs::remove_all(path_);
        } catch (...) {}
    }

    std::string path() const { return path_.string(); }

private:
    fs::path path_;
};

// Run keygen with given arguments
int run_keygen(const std::string& args) {
    std::string cmd = get_keygen_path() + " " + args + " 2>&1";
    return std::system(cmd.c_str());
}

// Test basic key generation without certificate parameters
void test_basic_keygen() {
    TEST("basic keygen creates files") {
        TempDir tmpdir;
        std::string prefix = tmpdir.path() + "/testkey";
        int ret = run_keygen("mldsa44 " + prefix);
        ASSERT_EQ(ret, 0);

        ASSERT_TRUE(fs::exists(prefix + "_public.key"));
        ASSERT_TRUE(fs::exists(prefix + "_secret.key"));
        ASSERT_TRUE(fs::exists(prefix + "_certificate.json"));
    TEST_END

    TEST("certificate JSON has required structure") {
        TempDir tmpdir;
        std::string prefix = tmpdir.path() + "/testkey";
        run_keygen("mldsa65 " + prefix);

        std::string json = read_file(prefix + "_certificate.json");

        ASSERT_TRUE(json_contains(json, "algorithm", "MLDSA65"));
        ASSERT_TRUE(json_contains(json, "type", "ML-DSA"));
        ASSERT_TRUE(json_contains(json, "standard", "FIPS 204"));
        ASSERT_TRUE(json_contains_text(json, "\"subject\""));
        ASSERT_TRUE(json_contains_text(json, "\"validity\""));
        ASSERT_TRUE(json_contains_text(json, "\"keyInfo\""));
        ASSERT_TRUE(json_contains_text(json, "\"serialNumber\""));
    TEST_END
}

// Test Common Name (--cn) parameter
void test_common_name() {
    TEST("--cn parameter is written to certificate") {
        TempDir tmpdir;
        std::string prefix = tmpdir.path() + "/testkey";
        run_keygen("mldsa44 " + prefix + " --cn \"api.example.com\"");

        std::string json = read_file(prefix + "_certificate.json");

        ASSERT_TRUE(json_contains(json, "commonName", "api.example.com"));
        ASSERT_TRUE(json_contains_text(json, "CN=api.example.com"));
    TEST_END

    TEST("--cn with spaces is preserved") {
        TempDir tmpdir;
        std::string prefix = tmpdir.path() + "/testkey";
        run_keygen("mldsa44 " + prefix + " --cn \"My Test Server\"");

        std::string json = read_file(prefix + "_certificate.json");

        ASSERT_TRUE(json_contains(json, "commonName", "My Test Server"));
    TEST_END
}

// Test Organization (--org) parameter
void test_organization() {
    TEST("--org parameter is written to certificate") {
        TempDir tmpdir;
        std::string prefix = tmpdir.path() + "/testkey";
        run_keygen("mldsa44 " + prefix + " --org \"Example Corp\"");

        std::string json = read_file(prefix + "_certificate.json");

        ASSERT_TRUE(json_contains(json, "organization", "Example Corp"));
        ASSERT_TRUE(json_contains_text(json, "O=Example Corp"));
    TEST_END
}

// Test Organizational Unit (--ou) parameter
void test_organizational_unit() {
    TEST("--ou parameter is written to certificate") {
        TempDir tmpdir;
        std::string prefix = tmpdir.path() + "/testkey";
        run_keygen("mldsa44 " + prefix + " --ou \"Engineering\"");

        std::string json = read_file(prefix + "_certificate.json");

        ASSERT_TRUE(json_contains(json, "organizationalUnit", "Engineering"));
        ASSERT_TRUE(json_contains_text(json, "OU=Engineering"));
    TEST_END
}

// Test Country (--country) parameter
void test_country() {
    TEST("--country parameter is written to certificate") {
        TempDir tmpdir;
        std::string prefix = tmpdir.path() + "/testkey";
        run_keygen("mldsa44 " + prefix + " --country US");

        std::string json = read_file(prefix + "_certificate.json");

        ASSERT_TRUE(json_contains(json, "country", "US"));
        ASSERT_TRUE(json_contains_text(json, "C=US"));
    TEST_END
}

// Test State (--state) parameter
void test_state() {
    TEST("--state parameter is written to certificate") {
        TempDir tmpdir;
        std::string prefix = tmpdir.path() + "/testkey";
        run_keygen("mldsa44 " + prefix + " --state California");

        std::string json = read_file(prefix + "_certificate.json");

        ASSERT_TRUE(json_contains(json, "state", "California"));
        ASSERT_TRUE(json_contains_text(json, "ST=California"));
    TEST_END
}

// Test Locality (--locality) parameter
void test_locality() {
    TEST("--locality parameter is written to certificate") {
        TempDir tmpdir;
        std::string prefix = tmpdir.path() + "/testkey";
        run_keygen("mldsa44 " + prefix + " --locality \"San Francisco\"");

        std::string json = read_file(prefix + "_certificate.json");

        ASSERT_TRUE(json_contains(json, "locality", "San Francisco"));
        ASSERT_TRUE(json_contains_text(json, "L=San Francisco"));
    TEST_END
}

// Test Email (--email) parameter
void test_email() {
    TEST("--email parameter is written to certificate") {
        TempDir tmpdir;
        std::string prefix = tmpdir.path() + "/testkey";
        run_keygen("mldsa44 " + prefix + " --email security@example.com");

        std::string json = read_file(prefix + "_certificate.json");

        ASSERT_TRUE(json_contains(json, "email", "security@example.com"));
        ASSERT_TRUE(json_contains_text(json, "emailAddress=security@example.com"));
    TEST_END
}

// Test Validity Days (--days) parameter
void test_validity_days() {
    TEST("--days parameter is written to certificate") {
        TempDir tmpdir;
        std::string prefix = tmpdir.path() + "/testkey";
        run_keygen("mldsa44 " + prefix + " --days 730");

        std::string json = read_file(prefix + "_certificate.json");

        ASSERT_TRUE(json_contains(json, "days", "730"));
    TEST_END

    TEST("default validity is 365 days") {
        TempDir tmpdir;
        std::string prefix = tmpdir.path() + "/testkey";
        run_keygen("mldsa44 " + prefix);

        std::string json = read_file(prefix + "_certificate.json");

        ASSERT_TRUE(json_contains(json, "days", "365"));
    TEST_END
}

// Test Serial Number (--serial) parameter
void test_serial_number() {
    TEST("--serial parameter is written to certificate") {
        TempDir tmpdir;
        std::string prefix = tmpdir.path() + "/testkey";
        run_keygen("mldsa44 " + prefix + " --serial abcd1234");

        std::string json = read_file(prefix + "_certificate.json");

        // Serial is stored as hex, padded to 16 chars
        ASSERT_TRUE(json_contains_text(json, "00000000abcd1234"));
    TEST_END

    TEST("auto-generated serial is non-empty") {
        TempDir tmpdir;
        std::string prefix = tmpdir.path() + "/testkey";
        run_keygen("mldsa44 " + prefix);

        std::string json = read_file(prefix + "_certificate.json");

        std::string serial = get_json_value(json, "serialNumber");
        ASSERT_FALSE(serial.empty());
        ASSERT_EQ(serial.length(), size_t(16));
    TEST_END
}

// Test combined parameters (full certificate subject)
void test_full_subject() {
    TEST("all parameters combined in DN string") {
        TempDir tmpdir;
        std::string prefix = tmpdir.path() + "/testkey";
        run_keygen("mldsa65 " + prefix +
            " --cn \"api.example.com\""
            " --org \"Example Corp\""
            " --ou \"Engineering\""
            " --country US"
            " --state California"
            " --locality \"San Francisco\""
            " --email security@example.com"
            " --days 730");

        std::string json = read_file(prefix + "_certificate.json");

        // Verify all individual fields
        ASSERT_TRUE(json_contains(json, "commonName", "api.example.com"));
        ASSERT_TRUE(json_contains(json, "organization", "Example Corp"));
        ASSERT_TRUE(json_contains(json, "organizationalUnit", "Engineering"));
        ASSERT_TRUE(json_contains(json, "country", "US"));
        ASSERT_TRUE(json_contains(json, "state", "California"));
        ASSERT_TRUE(json_contains(json, "locality", "San Francisco"));
        ASSERT_TRUE(json_contains(json, "email", "security@example.com"));
        ASSERT_TRUE(json_contains(json, "days", "730"));

        // Verify DN contains all components in correct order
        std::string dn = get_json_value(json, "dn");
        ASSERT_TRUE(dn.find("C=US") != std::string::npos);
        ASSERT_TRUE(dn.find("ST=California") != std::string::npos);
        ASSERT_TRUE(dn.find("L=San Francisco") != std::string::npos);
        ASSERT_TRUE(dn.find("O=Example Corp") != std::string::npos);
        ASSERT_TRUE(dn.find("OU=Engineering") != std::string::npos);
        ASSERT_TRUE(dn.find("CN=api.example.com") != std::string::npos);
        ASSERT_TRUE(dn.find("emailAddress=security@example.com") != std::string::npos);

        // Verify DN order: C < ST < L < O < OU < CN < emailAddress
        size_t c_pos = dn.find("C=US");
        size_t st_pos = dn.find("ST=California");
        size_t l_pos = dn.find("L=San Francisco");
        size_t o_pos = dn.find("O=Example Corp");
        size_t ou_pos = dn.find("OU=Engineering");
        size_t cn_pos = dn.find("CN=api.example.com");
        size_t email_pos = dn.find("emailAddress=");

        ASSERT_TRUE(c_pos < st_pos);
        ASSERT_TRUE(st_pos < l_pos);
        ASSERT_TRUE(l_pos < o_pos);
        ASSERT_TRUE(o_pos < ou_pos);
        ASSERT_TRUE(ou_pos < cn_pos);
        ASSERT_TRUE(cn_pos < email_pos);
    TEST_END
}

// Test SLH-DSA algorithms with certificate parameters
void test_slhdsa_certificate() {
    TEST("SLH-DSA keygen with certificate parameters") {
        TempDir tmpdir;
        std::string prefix = tmpdir.path() + "/testkey";
        run_keygen("slh-shake-128f " + prefix +
            " --cn \"firmware-signer\""
            " --org \"Security Team\"");

        std::string json = read_file(prefix + "_certificate.json");

        ASSERT_TRUE(json_contains(json, "algorithm", "SLH-DSA-SHAKE-128f"));
        ASSERT_TRUE(json_contains(json, "type", "SLH-DSA"));
        ASSERT_TRUE(json_contains(json, "standard", "FIPS 205"));
        ASSERT_TRUE(json_contains(json, "commonName", "firmware-signer"));
        ASSERT_TRUE(json_contains(json, "organization", "Security Team"));
    TEST_END
}

// Test key info matches actual key sizes
void test_key_info_accuracy() {
    TEST("keyInfo sizes match actual key files") {
        TempDir tmpdir;
        std::string prefix = tmpdir.path() + "/testkey";
        run_keygen("mldsa65 " + prefix);

        std::string json = read_file(prefix + "_certificate.json");

        // Get reported sizes from JSON
        std::string pk_size_str = get_json_value(json, "publicKeySize");
        std::string sk_size_str = get_json_value(json, "secretKeySize");

        size_t reported_pk_size = std::stoul(pk_size_str);
        size_t reported_sk_size = std::stoul(sk_size_str);

        // Get actual file sizes
        size_t actual_pk_size = fs::file_size(prefix + "_public.key");
        size_t actual_sk_size = fs::file_size(prefix + "_secret.key");

        ASSERT_EQ(reported_pk_size, actual_pk_size);
        ASSERT_EQ(reported_sk_size, actual_sk_size);

        // Verify expected ML-DSA-65 sizes
        ASSERT_EQ(actual_pk_size, size_t(1952));  // ML-DSA-65 public key
        ASSERT_EQ(actual_sk_size, size_t(4032));  // ML-DSA-65 secret key
    TEST_END
}

// Test JSON special character escaping
void test_json_escaping() {
    TEST("special characters are properly escaped in JSON") {
        TempDir tmpdir;
        std::string prefix = tmpdir.path() + "/testkey";
        // Note: Testing with quotes and backslashes in values
        run_keygen("mldsa44 " + prefix + " --cn \"Test\\\\Server\"");

        std::string json = read_file(prefix + "_certificate.json");

        // Should be valid JSON - no parsing errors
        // The backslash should be escaped
        ASSERT_TRUE(json_contains_text(json, "Test\\\\Server"));
    TEST_END
}

// Test empty subject fields are included as empty strings
void test_empty_fields() {
    TEST("empty subject fields are included as empty strings") {
        TempDir tmpdir;
        std::string prefix = tmpdir.path() + "/testkey";
        run_keygen("mldsa44 " + prefix + " --cn \"test\"");

        std::string json = read_file(prefix + "_certificate.json");

        // All fields should exist, just be empty
        ASSERT_TRUE(json_contains(json, "commonName", "test"));
        ASSERT_TRUE(json_contains(json, "organization", ""));
        ASSERT_TRUE(json_contains(json, "organizationalUnit", ""));
        ASSERT_TRUE(json_contains(json, "country", ""));
        ASSERT_TRUE(json_contains(json, "state", ""));
        ASSERT_TRUE(json_contains(json, "locality", ""));
        ASSERT_TRUE(json_contains(json, "email", ""));
    TEST_END
}

int main() {
    std::cout << "=== Keygen Certificate Parameter Test Suite ===" << std::endl << std::endl;

    std::cout << "--- Basic Tests ---" << std::endl;
    test_basic_keygen();

    std::cout << std::endl << "--- Individual Parameter Tests ---" << std::endl;
    test_common_name();
    test_organization();
    test_organizational_unit();
    test_country();
    test_state();
    test_locality();
    test_email();
    test_validity_days();
    test_serial_number();

    std::cout << std::endl << "--- Combined Parameter Tests ---" << std::endl;
    test_full_subject();
    test_slhdsa_certificate();
    test_key_info_accuracy();

    std::cout << std::endl << "--- Edge Case Tests ---" << std::endl;
    test_json_escaping();
    test_empty_fields();

    std::cout << std::endl << "=== Test Results ===" << std::endl;
    std::cout << "Passed: " << tests_passed << std::endl;
    std::cout << "Failed: " << tests_failed << std::endl;

    return tests_failed > 0 ? 1 : 0;
}
