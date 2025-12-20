/**
 * Post-Quantum Signature Client (C++)
 *
 * This client holds a secret key and signs messages.
 * It registers its public key with servers and sends signed messages.
 *
 * Usage:
 *     ./demo_client --algorithm <alg> --servers <host:port,...> --messages <n>
 */

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <cstring>

// Network headers
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

// DSA headers
#include "mldsa/mldsa.hpp"
#include "slhdsa/slh_dsa.hpp"

// Simple hex encoding
std::string to_hex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (uint8_t b : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return oss.str();
}

// Simple JSON helpers
std::string get_json_string(const std::string& json, const std::string& key) {
    std::string search = "\"" + key + "\":";
    auto pos = json.find(search);
    if (pos == std::string::npos) return "";

    pos = json.find("\"", pos + search.length());
    if (pos == std::string::npos) return "";

    auto end = json.find("\"", pos + 1);
    if (end == std::string::npos) return "";

    return json.substr(pos + 1, end - pos - 1);
}

struct ServerInfo {
    std::string host;
    int port;
};

std::vector<ServerInfo> parse_servers(const std::string& servers_str) {
    std::vector<ServerInfo> servers;
    std::istringstream iss(servers_str);
    std::string server;
    while (std::getline(iss, server, ',')) {
        auto pos = server.find(':');
        if (pos != std::string::npos) {
            servers.push_back({
                server.substr(0, pos),
                std::stoi(server.substr(pos + 1))
            });
        }
    }
    return servers;
}

class SigningClient {
public:
    SigningClient(const std::string& algorithm, const std::vector<ServerInfo>& servers, int num_messages)
        : algorithm_(algorithm), servers_(servers), num_messages_(num_messages) {}

    void run() {
        print_header();

        // Generate keys
        generate_keys();

        // Wait for servers
        wait_for_servers();

        // Register public key with servers
        register_key();

        // Sign and verify messages
        sign_and_verify();

        // Test tamper detection
        test_tamper_detection();

        print_footer();
    }

private:
    void print_header() {
        std::cout << "============================================================\n"
                  << "  Post-Quantum Digital Signature Demo (C++)\n"
                  << "============================================================\n\n";

        std::cout << "Algorithm: " << algorithm_ << "\n";
        std::cout << "Servers: ";
        for (size_t i = 0; i < servers_.size(); ++i) {
            if (i > 0) std::cout << ",";
            std::cout << servers_[i].host << ":" << servers_[i].port;
        }
        std::cout << "\n\n";
    }

    void generate_keys() {
        std::cout << "[Client] Generating " << algorithm_ << " key pair...\n";

        auto start = std::chrono::high_resolution_clock::now();

        if (algorithm_.find("mldsa") == 0) {
            if (algorithm_ == "mldsa44") {
                mldsa::MLDSA44 dsa;
                auto [pk, sk] = dsa.keygen();
                public_key_ = std::move(pk);
                secret_key_ = std::move(sk);
            } else if (algorithm_ == "mldsa65") {
                mldsa::MLDSA65 dsa;
                auto [pk, sk] = dsa.keygen();
                public_key_ = std::move(pk);
                secret_key_ = std::move(sk);
            } else if (algorithm_ == "mldsa87") {
                mldsa::MLDSA87 dsa;
                auto [pk, sk] = dsa.keygen();
                public_key_ = std::move(pk);
                secret_key_ = std::move(sk);
            }
        } else if (algorithm_.find("slh-") == 0) {
            // Note: SLH-DSA keygen returns (sk, pk) unlike ML-DSA which returns (pk, sk)
            if (algorithm_ == "slh-shake-128f") {
                slhdsa::SLHDSA_SHAKE_128f dsa;
                auto [sk, pk] = dsa.keygen();
                public_key_ = std::move(pk);
                secret_key_ = std::move(sk);
            } else if (algorithm_ == "slh-shake-128s") {
                slhdsa::SLHDSA_SHAKE_128s dsa;
                auto [sk, pk] = dsa.keygen();
                public_key_ = std::move(pk);
                secret_key_ = std::move(sk);
            }
        }

        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

        std::cout << "[Client] Key generation completed in " << duration.count() << " ms\n";
        std::cout << "[Client] Public key:  " << public_key_.size() << " bytes\n";
        std::cout << "[Client] Secret key:  " << secret_key_.size() << " bytes\n";
    }

    std::vector<uint8_t> sign_message(const std::vector<uint8_t>& message) {
        if (algorithm_.find("mldsa") == 0) {
            if (algorithm_ == "mldsa44") {
                mldsa::MLDSA44 dsa;
                return dsa.sign(secret_key_, message);
            } else if (algorithm_ == "mldsa65") {
                mldsa::MLDSA65 dsa;
                return dsa.sign(secret_key_, message);
            } else if (algorithm_ == "mldsa87") {
                mldsa::MLDSA87 dsa;
                return dsa.sign(secret_key_, message);
            }
        } else if (algorithm_.find("slh-") == 0) {
            if (algorithm_ == "slh-shake-128f") {
                slhdsa::SLHDSA_SHAKE_128f dsa;
                return dsa.sign(secret_key_, message);
            } else if (algorithm_ == "slh-shake-128s") {
                slhdsa::SLHDSA_SHAKE_128s dsa;
                return dsa.sign(secret_key_, message);
            }
        }
        return {};
    }

    bool verify_locally(const std::vector<uint8_t>& message, const std::vector<uint8_t>& signature) {
        if (algorithm_.find("mldsa") == 0) {
            if (algorithm_ == "mldsa44") {
                mldsa::MLDSA44 dsa;
                return dsa.verify(public_key_, message, signature);
            } else if (algorithm_ == "mldsa65") {
                mldsa::MLDSA65 dsa;
                return dsa.verify(public_key_, message, signature);
            } else if (algorithm_ == "mldsa87") {
                mldsa::MLDSA87 dsa;
                return dsa.verify(public_key_, message, signature);
            }
        } else if (algorithm_.find("slh-") == 0) {
            if (algorithm_ == "slh-shake-128f") {
                slhdsa::SLHDSA_SHAKE_128f dsa;
                return dsa.verify(public_key_, message, signature);
            } else if (algorithm_ == "slh-shake-128s") {
                slhdsa::SLHDSA_SHAKE_128s dsa;
                return dsa.verify(public_key_, message, signature);
            }
        }
        return false;
    }

    bool wait_for_servers() {
        std::cout << "[Client] Waiting for servers to be ready...\n";

        for (const auto& server : servers_) {
            int retries = 10;
            bool ready = false;

            while (retries-- > 0 && !ready) {
                int sock = connect_to_server(server);
                if (sock >= 0) {
                    std::string request = "{\"action\":\"ping\"}\n\n";
                    ::send(sock, request.c_str(), request.size(), 0);  // Small message, single send ok

                    char buffer[1024];
                    ssize_t n = recv(sock, buffer, sizeof(buffer) - 1, 0);
                    if (n > 0) {
                        buffer[n] = '\0';
                        std::string response(buffer);
                        if (response.find("\"status\":\"ok\"") != std::string::npos) {
                            ready = true;
                            std::cout << "[Client] Server " << server.host << ":" << server.port << " is ready\n";
                        }
                    }
                    close(sock);
                }

                if (!ready) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                }
            }

            if (!ready) {
                std::cerr << "[Client] Failed to connect to " << server.host << ":" << server.port << "\n";
                return false;
            }
        }
        return true;
    }

    void register_key() {
        std::cout << "\n------------------------------------------------------------\n"
                  << "Step 1: Registering public key with servers\n"
                  << "------------------------------------------------------------\n";

        for (const auto& server : servers_) {
            int sock = connect_to_server(server);
            if (sock < 0) {
                std::cout << "  -> " << server.host << ":" << server.port << ": FAILED (connection)\n";
                continue;
            }

            std::string request = "{\"action\":\"register_key\",\"public_key\":\"" + to_hex(public_key_) + "\"}\n\n";
            send_all(sock, request);

            char buffer[1024];
            ssize_t n = recv(sock, buffer, sizeof(buffer) - 1, 0);
            close(sock);

            if (n > 0) {
                buffer[n] = '\0';
                std::string response(buffer);
                if (response.find("\"status\":\"ok\"") != std::string::npos) {
                    std::cout << "  -> " << server.host << ":" << server.port << ": OK\n";
                } else {
                    std::cout << "  -> " << server.host << ":" << server.port << ": FAILED\n";
                }
            }
        }
    }

    // Helper function to send all data
    bool send_all(int sock, const std::string& data) {
        size_t total_sent = 0;
        while (total_sent < data.size()) {
            ssize_t sent = send(sock, data.c_str() + total_sent, data.size() - total_sent, 0);
            if (sent <= 0) return false;
            total_sent += sent;
        }
        return true;
    }

    std::string send_verify_request(const ServerInfo& server, const std::string& message,
                                    const std::vector<uint8_t>& signature) {
        int sock = connect_to_server(server);
        if (sock < 0) return "error";

        std::string request = "{\"action\":\"verify\",\"message\":\"" + message +
                              "\",\"signature\":\"" + to_hex(signature) + "\"}\n\n";
        if (!send_all(sock, request)) {
            close(sock);
            return "error";
        }

        char buffer[1024];
        ssize_t n = recv(sock, buffer, sizeof(buffer) - 1, 0);
        close(sock);

        if (n > 0) {
            buffer[n] = '\0';
            std::string response(buffer);
            std::string valid = get_json_string(response, "valid");
            std::string server_name = get_json_string(response, "server");
            return server_name + ":" + valid;
        }
        return "error";
    }

    void sign_and_verify() {
        std::cout << "\n------------------------------------------------------------\n"
                  << "Step 2: Signing and verifying messages\n"
                  << "------------------------------------------------------------\n\n";

        std::vector<std::string> messages = {
            "Hello, Post-Quantum World!",
            "Transaction: Transfer $1000 to Alice at 2025-12-20 10:30:00 UTC",
            "This message is signed with quantum-resistant cryptography"
        };

        for (int i = 0; i < num_messages_ && i < static_cast<int>(messages.size()); ++i) {
            const std::string& msg = messages[i];
            std::vector<uint8_t> msg_bytes(msg.begin(), msg.end());

            auto start = std::chrono::high_resolution_clock::now();
            auto signature = sign_message(msg_bytes);
            auto end = std::chrono::high_resolution_clock::now();
            auto sign_time = std::chrono::duration<double, std::milli>(end - start);

            std::string content_preview = msg.length() > 50 ? msg.substr(0, 50) + "..." : msg;
            std::cout << "[Message " << (i + 1) << "]\n"
                      << "  Content: " << content_preview << "\n"
                      << "  Signature: " << signature.size() << " bytes (signed in "
                      << std::fixed << std::setprecision(1) << sign_time.count() << " ms)\n";

            // Verify with each server
            for (const auto& server : servers_) {
                auto verify_start = std::chrono::high_resolution_clock::now();
                std::string result = send_verify_request(server, msg, signature);
                auto verify_end = std::chrono::high_resolution_clock::now();
                auto verify_time = std::chrono::duration<double, std::milli>(verify_end - verify_start);

                auto colon_pos = result.find(':');
                std::string server_name = colon_pos != std::string::npos ? result.substr(0, colon_pos) : server.host;
                std::string valid = colon_pos != std::string::npos ? result.substr(colon_pos + 1) : result;

                std::cout << "  -> " << server_name << ": " << (valid == "true" ? "VALID" : "INVALID")
                          << " (" << std::fixed << std::setprecision(1) << verify_time.count() << " ms)\n";
            }
            std::cout << "\n";
        }
    }

    void test_tamper_detection() {
        std::cout << "------------------------------------------------------------\n"
                  << "Step 3: Testing tamper detection\n"
                  << "------------------------------------------------------------\n\n";

        std::string original = "Send $100 to Bob";
        std::string tampered = "Send $999 to Eve";

        std::vector<uint8_t> orig_bytes(original.begin(), original.end());
        auto signature = sign_message(orig_bytes);

        std::cout << "  Original: " << original << "\n"
                  << "  Tampered: " << tampered << "\n"
                  << "  Signature of original: " << signature.size() << " bytes\n";

        // Try to verify tampered message with original signature
        for (const auto& server : servers_) {
            std::string result = send_verify_request(server, tampered, signature);
            auto colon_pos = result.find(':');
            std::string server_name = colon_pos != std::string::npos ? result.substr(0, colon_pos) : server.host;
            std::string valid = colon_pos != std::string::npos ? result.substr(colon_pos + 1) : result;

            std::cout << "  -> " << server_name << ": Tampered message "
                      << (valid == "true" ? "ACCEPTED (WRONG!)" : "REJECTED (Correct!)") << "\n";
        }
    }

    void print_footer() {
        std::cout << "\n============================================================\n"
                  << "  Demo completed successfully!\n"
                  << "============================================================\n\n"
                  << "Key takeaways:\n"
                  << "  - Client holds the SECRET key (for signing)\n"
                  << "  - Servers hold the PUBLIC key (for verification)\n"
                  << "  - Signatures are quantum-resistant\n"
                  << "  - Tampered messages are detected\n\n";
    }

    int connect_to_server(const ServerInfo& server) {
        struct addrinfo hints{}, *result;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        std::string port_str = std::to_string(server.port);
        int ret = getaddrinfo(server.host.c_str(), port_str.c_str(), &hints, &result);
        if (ret != 0) {
            return -1;
        }

        int sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
        if (sock < 0) {
            freeaddrinfo(result);
            return -1;
        }

        // Set timeout
        struct timeval tv;
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        if (connect(sock, result->ai_addr, result->ai_addrlen) < 0) {
            close(sock);
            freeaddrinfo(result);
            return -1;
        }

        freeaddrinfo(result);
        return sock;
    }

    std::string algorithm_;
    std::vector<ServerInfo> servers_;
    int num_messages_;
    std::vector<uint8_t> public_key_;
    std::vector<uint8_t> secret_key_;
};

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [options]\n"
              << "Options:\n"
              << "  --algorithm <alg>        Algorithm (mldsa44, mldsa65, slh-shake-128f)\n"
              << "  --servers <host:port,..> Comma-separated list of servers\n"
              << "  --messages <n>           Number of messages to sign (default: 3)\n"
              << std::endl;
}

int main(int argc, char* argv[]) {
    std::string algorithm = "mldsa44";
    std::string servers_str = "server1:5001,server2:5002";
    int num_messages = 3;

    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--algorithm" && i + 1 < argc) {
            algorithm = argv[++i];
        } else if (arg == "--servers" && i + 1 < argc) {
            servers_str = argv[++i];
        } else if (arg == "--messages" && i + 1 < argc) {
            num_messages = std::stoi(argv[++i]);
        } else if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        }
    }

    auto servers = parse_servers(servers_str);
    if (servers.empty()) {
        std::cerr << "Error: No valid servers specified\n";
        return 1;
    }

    try {
        SigningClient client(algorithm, servers, num_messages);
        client.run();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
