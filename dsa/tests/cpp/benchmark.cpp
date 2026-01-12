/**
 * @file benchmark.cpp
 * @brief Comprehensive C++ benchmarks for ML-DSA, SLH-DSA, and ML-KEM
 *
 * This benchmark suite provides accurate timing measurements for all
 * post-quantum cryptographic operations in this library.
 *
 * Build: cmake && make benchmark
 * Run: ./benchmark [--json] [--iterations N]
 */

#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <numeric>
#include <cmath>
#include <string>
#include <sstream>

#include "mldsa/mldsa.hpp"
#include "slhdsa/slh_dsa.hpp"
#include "mlkem/mlkem.hpp"

using Clock = std::chrono::high_resolution_clock;
using Duration = std::chrono::duration<double, std::micro>;

// Benchmark result structure
struct BenchmarkResult {
    std::string name;
    std::string algorithm;
    std::string operation;
    size_t iterations;
    double mean_us;      // microseconds
    double stddev_us;
    double min_us;
    double max_us;
    double ops_per_sec;
    size_t data_size;    // key/signature/ciphertext size
};

// Calculate statistics from timing data
BenchmarkResult calculate_stats(
    const std::string& name,
    const std::string& algorithm,
    const std::string& operation,
    const std::vector<double>& timings_us,
    size_t data_size = 0
) {
    BenchmarkResult result;
    result.name = name;
    result.algorithm = algorithm;
    result.operation = operation;
    result.iterations = timings_us.size();
    result.data_size = data_size;

    // Calculate mean
    double sum = std::accumulate(timings_us.begin(), timings_us.end(), 0.0);
    result.mean_us = sum / timings_us.size();

    // Calculate standard deviation
    double sq_sum = 0.0;
    for (double t : timings_us) {
        sq_sum += (t - result.mean_us) * (t - result.mean_us);
    }
    result.stddev_us = std::sqrt(sq_sum / timings_us.size());

    // Min and max
    result.min_us = *std::min_element(timings_us.begin(), timings_us.end());
    result.max_us = *std::max_element(timings_us.begin(), timings_us.end());

    // Operations per second
    result.ops_per_sec = 1000000.0 / result.mean_us;

    return result;
}

// Print result in table format
void print_result(const BenchmarkResult& r) {
    std::cout << std::left << std::setw(35) << r.name
              << std::right << std::setw(12) << std::fixed << std::setprecision(2) << r.mean_us << " us"
              << std::setw(12) << r.stddev_us << " us"
              << std::setw(12) << r.min_us << " us"
              << std::setw(12) << r.max_us << " us"
              << std::setw(14) << std::setprecision(1) << r.ops_per_sec << " ops/s";
    if (r.data_size > 0) {
        std::cout << std::setw(10) << r.data_size << " B";
    }
    std::cout << "\n";
}

// Print result as JSON
void print_json(const std::vector<BenchmarkResult>& results) {
    std::cout << "{\n  \"benchmarks\": [\n";
    for (size_t i = 0; i < results.size(); ++i) {
        const auto& r = results[i];
        std::cout << "    {\n"
                  << "      \"name\": \"" << r.name << "\",\n"
                  << "      \"algorithm\": \"" << r.algorithm << "\",\n"
                  << "      \"operation\": \"" << r.operation << "\",\n"
                  << "      \"iterations\": " << r.iterations << ",\n"
                  << "      \"mean_us\": " << std::fixed << std::setprecision(3) << r.mean_us << ",\n"
                  << "      \"stddev_us\": " << r.stddev_us << ",\n"
                  << "      \"min_us\": " << r.min_us << ",\n"
                  << "      \"max_us\": " << r.max_us << ",\n"
                  << "      \"ops_per_sec\": " << std::setprecision(1) << r.ops_per_sec << ",\n"
                  << "      \"data_size_bytes\": " << r.data_size << "\n"
                  << "    }";
        if (i < results.size() - 1) std::cout << ",";
        std::cout << "\n";
    }
    std::cout << "  ]\n}\n";
}

// ============================================================================
// ML-DSA Benchmarks
// ============================================================================

template<typename DSA>
std::vector<BenchmarkResult> benchmark_mldsa(const std::string& param_name, size_t iterations) {
    std::vector<BenchmarkResult> results;
    DSA dsa;

    // Warm-up
    std::vector<uint8_t> warmup_msg = {0x00, 0x01, 0x02, 0x03};
    auto [pk_warmup, sk_warmup] = dsa.keygen();
    auto sig_warmup = dsa.sign(sk_warmup, warmup_msg);
    (void)dsa.verify(pk_warmup, warmup_msg, sig_warmup);

    // Benchmark keygen
    std::vector<double> keygen_times;
    keygen_times.reserve(iterations);
    for (size_t i = 0; i < iterations; ++i) {
        auto start = Clock::now();
        auto [pk, sk] = dsa.keygen();
        auto end = Clock::now();
        keygen_times.push_back(Duration(end - start).count());
        (void)pk; (void)sk;
    }
    results.push_back(calculate_stats(
        param_name + " keygen", param_name, "keygen",
        keygen_times, dsa.params().pk_size() + dsa.params().sk_size()
    ));

    // Generate keys for sign/verify benchmarks
    auto [pk, sk] = dsa.keygen();
    std::vector<uint8_t> message = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64};

    // Benchmark sign
    std::vector<double> sign_times;
    sign_times.reserve(iterations);
    for (size_t i = 0; i < iterations; ++i) {
        auto start = Clock::now();
        auto sig = dsa.sign(sk, message);
        auto end = Clock::now();
        sign_times.push_back(Duration(end - start).count());
        (void)sig;
    }
    results.push_back(calculate_stats(
        param_name + " sign", param_name, "sign",
        sign_times, dsa.params().sig_size()
    ));

    // Generate signature for verify benchmark
    auto signature = dsa.sign(sk, message);

    // Benchmark verify
    std::vector<double> verify_times;
    verify_times.reserve(iterations);
    for (size_t i = 0; i < iterations; ++i) {
        auto start = Clock::now();
        bool valid = dsa.verify(pk, message, signature);
        auto end = Clock::now();
        verify_times.push_back(Duration(end - start).count());
        (void)valid;
    }
    results.push_back(calculate_stats(
        param_name + " verify", param_name, "verify",
        verify_times, 0
    ));

    return results;
}

// ============================================================================
// SLH-DSA Benchmarks
// ============================================================================

template<typename DSA>
std::vector<BenchmarkResult> benchmark_slhdsa(const std::string& param_name, size_t iterations) {
    std::vector<BenchmarkResult> results;
    DSA dsa;

    // Warm-up - note SLH-DSA returns (sk, pk)
    std::vector<uint8_t> warmup_msg = {0x00, 0x01, 0x02, 0x03};
    auto [sk_warmup, pk_warmup] = dsa.keygen();
    auto sig_warmup = dsa.sign(sk_warmup, warmup_msg);
    (void)dsa.verify(pk_warmup, warmup_msg, sig_warmup);

    // Benchmark keygen
    std::vector<double> keygen_times;
    keygen_times.reserve(iterations);
    for (size_t i = 0; i < iterations; ++i) {
        auto start = Clock::now();
        auto [sk, pk] = dsa.keygen();
        auto end = Clock::now();
        keygen_times.push_back(Duration(end - start).count());
        (void)pk; (void)sk;
    }
    results.push_back(calculate_stats(
        param_name + " keygen", param_name, "keygen",
        keygen_times, dsa.params().pk_size() + dsa.params().sk_size()
    ));

    // Generate keys for sign/verify benchmarks - note (sk, pk) order
    auto [sk, pk] = dsa.keygen();
    std::vector<uint8_t> message = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64};

    // Benchmark sign (fewer iterations due to slow performance)
    size_t sign_iterations = std::min(iterations, (size_t)10);
    std::vector<double> sign_times;
    sign_times.reserve(sign_iterations);
    for (size_t i = 0; i < sign_iterations; ++i) {
        auto start = Clock::now();
        auto sig = dsa.sign(sk, message);
        auto end = Clock::now();
        sign_times.push_back(Duration(end - start).count());
        (void)sig;
    }
    results.push_back(calculate_stats(
        param_name + " sign", param_name, "sign",
        sign_times, dsa.params().sig_size()
    ));

    // Generate signature for verify benchmark
    auto signature = dsa.sign(sk, message);

    // Benchmark verify
    std::vector<double> verify_times;
    verify_times.reserve(iterations);
    for (size_t i = 0; i < iterations; ++i) {
        auto start = Clock::now();
        bool valid = dsa.verify(pk, message, signature);
        auto end = Clock::now();
        verify_times.push_back(Duration(end - start).count());
        (void)valid;
    }
    results.push_back(calculate_stats(
        param_name + " verify", param_name, "verify",
        verify_times, 0
    ));

    return results;
}

// ============================================================================
// ML-KEM Benchmarks
// ============================================================================

template<typename KEM>
std::vector<BenchmarkResult> benchmark_mlkem(const std::string& param_name, size_t iterations) {
    std::vector<BenchmarkResult> results;
    KEM kem;

    // Warm-up
    auto [ek_warmup, dk_warmup] = kem.keygen();
    auto [ss_warmup, ct_warmup] = kem.encaps(ek_warmup);
    auto ss_dec_warmup = kem.decaps(dk_warmup, ct_warmup);
    (void)ss_warmup; (void)ss_dec_warmup;

    // Benchmark keygen
    std::vector<double> keygen_times;
    keygen_times.reserve(iterations);
    for (size_t i = 0; i < iterations; ++i) {
        auto start = Clock::now();
        auto [ek, dk] = kem.keygen();
        auto end = Clock::now();
        keygen_times.push_back(Duration(end - start).count());
        (void)ek; (void)dk;
    }
    results.push_back(calculate_stats(
        param_name + " keygen", param_name, "keygen",
        keygen_times, kem.params().ek_size() + kem.params().dk_size()
    ));

    // Generate keys for encaps/decaps benchmarks
    auto [ek, dk] = kem.keygen();

    // Benchmark encaps
    std::vector<double> encaps_times;
    encaps_times.reserve(iterations);
    for (size_t i = 0; i < iterations; ++i) {
        auto start = Clock::now();
        auto [ss, ct] = kem.encaps(ek);
        auto end = Clock::now();
        encaps_times.push_back(Duration(end - start).count());
        (void)ss; (void)ct;
    }
    results.push_back(calculate_stats(
        param_name + " encaps", param_name, "encaps",
        encaps_times, kem.params().ct_size()
    ));

    // Generate ciphertext for decaps benchmark
    auto [shared_secret, ciphertext] = kem.encaps(ek);
    (void)shared_secret;

    // Benchmark decaps
    std::vector<double> decaps_times;
    decaps_times.reserve(iterations);
    for (size_t i = 0; i < iterations; ++i) {
        auto start = Clock::now();
        auto ss = kem.decaps(dk, ciphertext);
        auto end = Clock::now();
        decaps_times.push_back(Duration(end - start).count());
        (void)ss;
    }
    results.push_back(calculate_stats(
        param_name + " decaps", param_name, "decaps",
        decaps_times, kem.params().ss_size()
    ));

    return results;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    bool json_output = false;
    size_t iterations = 100;

    // Parse arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--json") {
            json_output = true;
        } else if (arg == "--iterations" && i + 1 < argc) {
            iterations = std::stoul(argv[++i]);
        } else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: " << argv[0] << " [OPTIONS]\n"
                      << "Options:\n"
                      << "  --json           Output results as JSON\n"
                      << "  --iterations N   Number of iterations per benchmark (default: 100)\n"
                      << "  --help, -h       Show this help\n";
            return 0;
        }
    }

    std::vector<BenchmarkResult> all_results;

    if (!json_output) {
        std::cout << "=== Post-Quantum Cryptography Benchmark Suite ===\n";
        std::cout << "Iterations per test: " << iterations << "\n\n";

        std::cout << std::left << std::setw(35) << "Benchmark"
                  << std::right << std::setw(15) << "Mean"
                  << std::setw(15) << "Std Dev"
                  << std::setw(15) << "Min"
                  << std::setw(15) << "Max"
                  << std::setw(17) << "Throughput"
                  << std::setw(13) << "Size"
                  << "\n";
        std::cout << std::string(125, '-') << "\n";
    }

    // ML-DSA Benchmarks
    if (!json_output) std::cout << "\n--- ML-DSA (FIPS 204) ---\n";

    auto mldsa44_results = benchmark_mldsa<mldsa::MLDSA44>("ML-DSA-44", iterations);
    for (const auto& r : mldsa44_results) {
        all_results.push_back(r);
        if (!json_output) print_result(r);
    }

    auto mldsa65_results = benchmark_mldsa<mldsa::MLDSA65>("ML-DSA-65", iterations);
    for (const auto& r : mldsa65_results) {
        all_results.push_back(r);
        if (!json_output) print_result(r);
    }

    auto mldsa87_results = benchmark_mldsa<mldsa::MLDSA87>("ML-DSA-87", iterations);
    for (const auto& r : mldsa87_results) {
        all_results.push_back(r);
        if (!json_output) print_result(r);
    }

    // SLH-DSA Benchmarks
    if (!json_output) std::cout << "\n--- SLH-DSA (FIPS 205) ---\n";

    auto slhdsa_shake128f_results = benchmark_slhdsa<slhdsa::SLHDSA_SHAKE_128f>("SLH-DSA-SHAKE-128f", iterations);
    for (const auto& r : slhdsa_shake128f_results) {
        all_results.push_back(r);
        if (!json_output) print_result(r);
    }

    auto slhdsa_sha2128f_results = benchmark_slhdsa<slhdsa::SLHDSA_SHA2_128f>("SLH-DSA-SHA2-128f", iterations);
    for (const auto& r : slhdsa_sha2128f_results) {
        all_results.push_back(r);
        if (!json_output) print_result(r);
    }

    // ML-KEM Benchmarks
    if (!json_output) std::cout << "\n--- ML-KEM (FIPS 203) ---\n";

    auto mlkem512_results = benchmark_mlkem<mlkem::MLKEM512>("ML-KEM-512", iterations);
    for (const auto& r : mlkem512_results) {
        all_results.push_back(r);
        if (!json_output) print_result(r);
    }

    auto mlkem768_results = benchmark_mlkem<mlkem::MLKEM768>("ML-KEM-768", iterations);
    for (const auto& r : mlkem768_results) {
        all_results.push_back(r);
        if (!json_output) print_result(r);
    }

    auto mlkem1024_results = benchmark_mlkem<mlkem::MLKEM1024>("ML-KEM-1024", iterations);
    for (const auto& r : mlkem1024_results) {
        all_results.push_back(r);
        if (!json_output) print_result(r);
    }

    if (json_output) {
        print_json(all_results);
    } else {
        std::cout << "\n" << std::string(125, '-') << "\n";
        std::cout << "Benchmark complete. Total benchmarks: " << all_results.size() << "\n";
    }

    return 0;
}
