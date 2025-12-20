/**
 * Post-Quantum Signature Verification Server (C++)
 *
 * This server holds a public key and verifies signatures from clients.
 * Demonstrates the verification side of post-quantum digital signatures.
 *
 * Usage:
 *     ./demo_server --name <server_name> --port <port> --algorithm <alg>
 */

#include <iostream>
#include <string>
#include <vector>
#include <cstring>
#include <csignal>
#include <thread>
#include <atomic>
#include <sstream>
#include <iomanip>
#include <optional>
#include <chrono>

// Network headers
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// DSA headers
#include "mldsa/mldsa.hpp"
#include "slhdsa/slh_dsa.hpp"

// Global shutdown flag
std::atomic<bool> g_running{true};

// Signal handler
void signal_handler(int signum) {
    std::cout << "\n[Server] Received shutdown signal, stopping..." << std::endl;
    g_running = false;
}

// Simple hex encoding/decoding
std::string to_hex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    for (uint8_t b : data) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    }
    return oss.str();
}

std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> result;
    result.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        uint8_t byte = static_cast<uint8_t>(std::stoi(hex.substr(i, 2), nullptr, 16));
        result.push_back(byte);
    }
    return result;
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

std::string make_json_response(const std::vector<std::pair<std::string, std::string>>& fields) {
    std::ostringstream oss;
    oss << "{";
    for (size_t i = 0; i < fields.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << fields[i].first << "\":\"" << fields[i].second << "\"";
    }
    oss << "}\n";
    return oss.str();
}

class VerificationServer {
public:
    VerificationServer(const std::string& name, int port, const std::string& algorithm)
        : name_(name), port_(port), algorithm_(algorithm) {
        setup_algorithm();
    }

    void set_public_key(const std::vector<uint8_t>& pk) {
        public_key_ = pk;
    }

    bool verify_signature(const std::vector<uint8_t>& message,
                          const std::vector<uint8_t>& signature) {
        if (public_key_.empty()) return false;

        try {
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
        } catch (const std::exception& e) {
            std::cerr << "[" << name_ << "] Verification error: " << e.what() << std::endl;
        }
        return false;
    }

    void handle_client(int client_fd) {
        // Receive data
        std::vector<char> buffer(65536);
        std::string data;

        while (true) {
            ssize_t n = recv(client_fd, buffer.data(), buffer.size(), 0);
            if (n <= 0) break;
            data.append(buffer.data(), n);
            if (data.find("\n\n") != std::string::npos) break;
        }

        if (data.empty()) {
            close(client_fd);
            return;
        }

        // Parse action
        std::string action = get_json_string(data, "action");
        std::string response;

        if (action == "register_key") {
            std::string key_hex = get_json_string(data, "public_key");
            if (!key_hex.empty()) {
                public_key_ = from_hex(key_hex);
                response = make_json_response({
                    {"status", "ok"},
                    {"message", "Public key registered (" + std::to_string(public_key_.size()) + " bytes)"}
                });
                std::cout << "[" << name_ << "] Registered public key from client" << std::endl;
            } else {
                response = make_json_response({{"status", "error"}, {"message", "No public key provided"}});
            }
        } else if (action == "verify") {
            std::string msg_str = get_json_string(data, "message");
            std::string sig_hex = get_json_string(data, "signature");

            std::vector<uint8_t> message(msg_str.begin(), msg_str.end());
            std::vector<uint8_t> signature = from_hex(sig_hex);

            bool valid = verify_signature(message, signature);
            response = make_json_response({
                {"status", "ok"},
                {"valid", valid ? "true" : "false"},
                {"server", name_},
                {"algorithm", algorithm_}
            });
            std::cout << "[" << name_ << "] Signature verification: "
                      << (valid ? "VALID" : "INVALID") << std::endl;
        } else if (action == "ping") {
            response = make_json_response({
                {"status", "ok"},
                {"server", name_},
                {"algorithm", algorithm_}
            });
        } else {
            response = make_json_response({{"status", "error"}, {"message", "Unknown action"}});
        }

        send(client_fd, response.c_str(), response.size(), 0);
        close(client_fd);
    }

    void start() {
        int server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) {
            std::cerr << "Failed to create socket" << std::endl;
            return;
        }

        int opt = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port_);

        if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            std::cerr << "Failed to bind to port " << port_ << std::endl;
            close(server_fd);
            return;
        }

        listen(server_fd, 5);

        // Set socket timeout for accept
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        std::cout << "[" << name_ << "] Server started on port " << port_ << std::endl;
        std::cout << "[" << name_ << "] Algorithm: " << algorithm_ << std::endl;
        std::cout << "[" << name_ << "] Waiting for connections..." << std::endl;

        while (g_running) {
            struct sockaddr_in client_addr{};
            socklen_t client_len = sizeof(client_addr);
            int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);

            if (client_fd < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;  // Timeout, check g_running
                }
                if (g_running) {
                    std::cerr << "[" << name_ << "] Accept error: " << strerror(errno) << std::endl;
                }
                continue;
            }

            char client_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
            std::cout << "[" << name_ << "] Connection from " << client_ip << std::endl;

            // Handle in thread
            std::thread([this, client_fd]() {
                handle_client(client_fd);
            }).detach();
        }

        close(server_fd);
    }

private:
    void setup_algorithm() {
        // Validate algorithm
        if (algorithm_.find("mldsa") != 0 && algorithm_.find("slh-") != 0) {
            throw std::runtime_error("Unknown algorithm: " + algorithm_);
        }
    }

    std::string name_;
    int port_;
    std::string algorithm_;
    std::vector<uint8_t> public_key_;
};

void print_usage(const char* prog) {
    std::cout << "Usage: " << prog << " [options]\n"
              << "Options:\n"
              << "  --name <name>       Server name (default: Server)\n"
              << "  --port <port>       Port to listen on (default: 5000)\n"
              << "  --algorithm <alg>   Algorithm (mldsa44, mldsa65, slh-shake-128f)\n"
              << std::endl;
}

int main(int argc, char* argv[]) {
    std::string name = "Server";
    int port = 5000;
    std::string algorithm = "mldsa44";

    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--name" && i + 1 < argc) {
            name = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            port = std::stoi(argv[++i]);
        } else if (arg == "--algorithm" && i + 1 < argc) {
            algorithm = argv[++i];
        } else if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return 0;
        }
    }

    // Setup signal handlers
    signal(SIGTERM, signal_handler);
    signal(SIGINT, signal_handler);

    try {
        VerificationServer server(name, port, algorithm);
        server.start();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "[" << name << "] Server stopped." << std::endl;
    return 0;
}
