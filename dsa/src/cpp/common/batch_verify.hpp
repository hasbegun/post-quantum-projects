/**
 * Batch Signature Verification
 *
 * Provides efficient batch verification of multiple PQC signatures.
 * Supports both parallel (multi-threaded) and sequential verification modes.
 *
 * Usage:
 *   // Homogeneous batch (same algorithm)
 *   auto dsa = pqc::create_dsa("ML-DSA-65");
 *   std::vector<pqc::VerificationItem> items = {...};
 *   auto result = pqc::batch_verify(*dsa, items);
 *
 *   // Heterogeneous batch (mixed algorithms)
 *   std::vector<pqc::HeterogeneousItem> mixed = {...};
 *   auto result = pqc::batch_verify_heterogeneous(mixed);
 *
 *   // Sequential (single-threaded) for embedded systems
 *   auto result = pqc::batch_verify_sequential(*dsa, items);
 */

#ifndef COMMON_BATCH_VERIFY_HPP
#define COMMON_BATCH_VERIFY_HPP

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <future>
#include <memory>
#include <span>
#include <thread>
#include <vector>

#include "algorithm_factory.hpp"

namespace pqc {

// ============================================================================
// Data Structures
// ============================================================================

/**
 * Represents a single signature verification request.
 *
 * For homogeneous batches where all signatures use the same algorithm.
 */
struct VerificationItem {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> message;
    std::vector<uint8_t> signature;
    std::vector<uint8_t> context;  // Optional context string

    // Convenience constructors
    VerificationItem() = default;

    VerificationItem(
        std::vector<uint8_t> pk,
        std::vector<uint8_t> msg,
        std::vector<uint8_t> sig,
        std::vector<uint8_t> ctx = {})
        : public_key(std::move(pk))
        , message(std::move(msg))
        , signature(std::move(sig))
        , context(std::move(ctx)) {}

    // Constructor from spans (copies data)
    VerificationItem(
        std::span<const uint8_t> pk,
        std::span<const uint8_t> msg,
        std::span<const uint8_t> sig,
        std::span<const uint8_t> ctx = {})
        : public_key(pk.begin(), pk.end())
        , message(msg.begin(), msg.end())
        , signature(sig.begin(), sig.end())
        , context(ctx.begin(), ctx.end()) {}
};

/**
 * Represents a verification request with its own algorithm specification.
 *
 * For heterogeneous batches where signatures may use different algorithms.
 */
struct HeterogeneousItem {
    std::string algorithm;          // Algorithm name (e.g., "ML-DSA-65")
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> message;
    std::vector<uint8_t> signature;
    std::vector<uint8_t> context;

    HeterogeneousItem() = default;

    HeterogeneousItem(
        std::string algo,
        std::vector<uint8_t> pk,
        std::vector<uint8_t> msg,
        std::vector<uint8_t> sig,
        std::vector<uint8_t> ctx = {})
        : algorithm(std::move(algo))
        , public_key(std::move(pk))
        , message(std::move(msg))
        , signature(std::move(sig))
        , context(std::move(ctx)) {}
};

/**
 * Result of batch verification.
 */
struct BatchResult {
    bool all_valid;                 // True if all signatures verified successfully
    std::vector<bool> results;      // Individual verification results (same order as input)
    size_t valid_count;             // Number of valid signatures
    size_t invalid_count;           // Number of invalid signatures
    size_t total_count;             // Total number of signatures verified

    // Indices of failed verifications (for diagnostic purposes)
    [[nodiscard]] std::vector<size_t> failed_indices() const {
        std::vector<size_t> failed;
        for (size_t i = 0; i < results.size(); ++i) {
            if (!results[i]) {
                failed.push_back(i);
            }
        }
        return failed;
    }

    // Check if a specific index passed verification
    [[nodiscard]] bool is_valid(size_t index) const {
        return index < results.size() && results[index];
    }
};

/**
 * Options for batch verification.
 */
struct BatchOptions {
    size_t num_threads = 0;     // 0 = auto-detect (use hardware_concurrency)
    bool fail_fast = false;     // If true, stop on first failure (parallel mode may still complete in-flight work)
    size_t chunk_size = 0;      // 0 = auto (items / num_threads), or specify items per thread
};

// ============================================================================
// Implementation Details
// ============================================================================

namespace detail {

/**
 * Worker function for parallel verification.
 * Verifies a range of items and stores results.
 */
inline void verify_range(
    const DigitalSignature& dsa,
    const std::vector<VerificationItem>& items,
    std::vector<bool>& results,
    size_t start,
    size_t end,
    std::atomic<bool>& should_stop,
    std::atomic<size_t>& valid_count) {

    for (size_t i = start; i < end && !should_stop.load(std::memory_order_relaxed); ++i) {
        const auto& item = items[i];
        bool valid = dsa.verify(item.public_key, item.message, item.signature, item.context);
        results[i] = valid;
        if (valid) {
            valid_count.fetch_add(1, std::memory_order_relaxed);
        }
    }
}

/**
 * Worker function for heterogeneous parallel verification.
 */
inline void verify_heterogeneous_range(
    const std::vector<HeterogeneousItem>& items,
    std::vector<bool>& results,
    size_t start,
    size_t end,
    std::atomic<bool>& should_stop,
    std::atomic<size_t>& valid_count) {

    // Cache created DSA instances to avoid recreating for repeated algorithms
    std::unordered_map<std::string, std::unique_ptr<DigitalSignature>> dsa_cache;

    for (size_t i = start; i < end && !should_stop.load(std::memory_order_relaxed); ++i) {
        const auto& item = items[i];

        // Get or create DSA instance
        auto it = dsa_cache.find(item.algorithm);
        if (it == dsa_cache.end()) {
            try {
                auto dsa = create_dsa(item.algorithm);
                it = dsa_cache.emplace(item.algorithm, std::move(dsa)).first;
            } catch (const std::invalid_argument&) {
                // Unknown algorithm - mark as invalid
                results[i] = false;
                continue;
            }
        }

        bool valid = it->second->verify(item.public_key, item.message, item.signature, item.context);
        results[i] = valid;
        if (valid) {
            valid_count.fetch_add(1, std::memory_order_relaxed);
        }
    }
}

/**
 * Determine optimal number of threads.
 */
inline size_t optimal_threads(size_t num_items, size_t requested_threads) {
    if (num_items == 0) return 1;

    size_t max_threads = std::thread::hardware_concurrency();
    if (max_threads == 0) max_threads = 4;  // Fallback

    size_t threads = (requested_threads == 0) ? max_threads : requested_threads;

    // Don't use more threads than items
    threads = std::min(threads, num_items);

    // For small batches, use fewer threads to avoid overhead
    if (num_items < 4) threads = 1;
    else if (num_items < threads * 2) threads = std::max(size_t(1), num_items / 2);

    return threads;
}

} // namespace detail

// ============================================================================
// Batch Verification Functions
// ============================================================================

/**
 * Verify multiple signatures in parallel using the same algorithm.
 *
 * This is the most efficient batch verification mode when all signatures
 * use the same algorithm (e.g., all ML-DSA-65).
 *
 * @param dsa The digital signature algorithm to use
 * @param items Vector of verification items
 * @param options Batch verification options
 * @return BatchResult containing verification outcomes
 */
inline BatchResult batch_verify(
    const DigitalSignature& dsa,
    const std::vector<VerificationItem>& items,
    const BatchOptions& options = {}) {

    BatchResult result;
    result.total_count = items.size();
    result.results.resize(items.size(), false);

    if (items.empty()) {
        result.all_valid = true;
        result.valid_count = 0;
        result.invalid_count = 0;
        return result;
    }

    size_t num_threads = detail::optimal_threads(items.size(), options.num_threads);

    // For single-threaded case, just verify sequentially
    if (num_threads == 1) {
        size_t valid = 0;
        for (size_t i = 0; i < items.size(); ++i) {
            const auto& item = items[i];
            bool v = dsa.verify(item.public_key, item.message, item.signature, item.context);
            result.results[i] = v;
            if (v) ++valid;
            else if (options.fail_fast) break;
        }
        result.valid_count = valid;
        result.invalid_count = items.size() - valid;
        result.all_valid = (result.invalid_count == 0);
        return result;
    }

    // Multi-threaded verification
    std::atomic<bool> should_stop{false};
    std::atomic<size_t> valid_count{0};
    std::vector<std::future<void>> futures;

    size_t chunk_size = options.chunk_size > 0
        ? options.chunk_size
        : (items.size() + num_threads - 1) / num_threads;

    // Calculate number of tasks needed to cover all items
    size_t num_tasks = (items.size() + chunk_size - 1) / chunk_size;
    futures.reserve(num_tasks);

    for (size_t t = 0; t < num_tasks; ++t) {
        size_t start = t * chunk_size;
        size_t end = std::min(start + chunk_size, items.size());

        if (start >= items.size()) break;

        futures.push_back(std::async(std::launch::async, [&, start, end]() {
            detail::verify_range(dsa, items, result.results, start, end, should_stop, valid_count);

            // If fail_fast is enabled, check if any verification failed
            if (options.fail_fast) {
                for (size_t i = start; i < end; ++i) {
                    if (!result.results[i]) {
                        should_stop.store(true, std::memory_order_relaxed);
                        break;
                    }
                }
            }
        }));
    }

    // Wait for all threads to complete
    for (auto& f : futures) {
        f.get();
    }

    result.valid_count = valid_count.load();
    result.invalid_count = items.size() - result.valid_count;
    result.all_valid = (result.invalid_count == 0);

    return result;
}

/**
 * Verify multiple signatures sequentially using the same algorithm.
 *
 * Single-threaded version for embedded or constrained environments
 * where threading is unavailable or undesirable.
 *
 * @param dsa The digital signature algorithm to use
 * @param items Vector of verification items
 * @param fail_fast If true, stop on first failure
 * @return BatchResult containing verification outcomes
 */
inline BatchResult batch_verify_sequential(
    const DigitalSignature& dsa,
    const std::vector<VerificationItem>& items,
    bool fail_fast = false) {

    BatchOptions options;
    options.num_threads = 1;
    options.fail_fast = fail_fast;
    return batch_verify(dsa, items, options);
}

/**
 * Verify multiple signatures with potentially different algorithms.
 *
 * Each item specifies its own algorithm. Useful for verifying certificate
 * chains or mixed-algorithm batches.
 *
 * @param items Vector of heterogeneous verification items
 * @param options Batch verification options
 * @return BatchResult containing verification outcomes
 */
inline BatchResult batch_verify_heterogeneous(
    const std::vector<HeterogeneousItem>& items,
    const BatchOptions& options = {}) {

    BatchResult result;
    result.total_count = items.size();
    result.results.resize(items.size(), false);

    if (items.empty()) {
        result.all_valid = true;
        result.valid_count = 0;
        result.invalid_count = 0;
        return result;
    }

    size_t num_threads = detail::optimal_threads(items.size(), options.num_threads);

    // For single-threaded case
    if (num_threads == 1) {
        std::unordered_map<std::string, std::unique_ptr<DigitalSignature>> dsa_cache;
        size_t valid = 0;

        for (size_t i = 0; i < items.size(); ++i) {
            const auto& item = items[i];

            // Get or create DSA instance
            auto it = dsa_cache.find(item.algorithm);
            if (it == dsa_cache.end()) {
                try {
                    auto dsa = create_dsa(item.algorithm);
                    it = dsa_cache.emplace(item.algorithm, std::move(dsa)).first;
                } catch (const std::invalid_argument&) {
                    result.results[i] = false;
                    if (options.fail_fast) break;
                    continue;
                }
            }

            bool v = it->second->verify(item.public_key, item.message, item.signature, item.context);
            result.results[i] = v;
            if (v) ++valid;
            else if (options.fail_fast) break;
        }

        result.valid_count = valid;
        result.invalid_count = items.size() - valid;
        result.all_valid = (result.invalid_count == 0);
        return result;
    }

    // Multi-threaded heterogeneous verification
    std::atomic<bool> should_stop{false};
    std::atomic<size_t> valid_count{0};
    std::vector<std::future<void>> futures;

    size_t chunk_size = options.chunk_size > 0
        ? options.chunk_size
        : (items.size() + num_threads - 1) / num_threads;

    // Calculate number of tasks needed to cover all items
    size_t num_tasks = (items.size() + chunk_size - 1) / chunk_size;
    futures.reserve(num_tasks);

    for (size_t t = 0; t < num_tasks; ++t) {
        size_t start = t * chunk_size;
        size_t end = std::min(start + chunk_size, items.size());

        if (start >= items.size()) break;

        futures.push_back(std::async(std::launch::async, [&, start, end]() {
            detail::verify_heterogeneous_range(items, result.results, start, end, should_stop, valid_count);

            if (options.fail_fast) {
                for (size_t i = start; i < end; ++i) {
                    if (!result.results[i]) {
                        should_stop.store(true, std::memory_order_relaxed);
                        break;
                    }
                }
            }
        }));
    }

    for (auto& f : futures) {
        f.get();
    }

    result.valid_count = valid_count.load();
    result.invalid_count = items.size() - result.valid_count;
    result.all_valid = (result.invalid_count == 0);

    return result;
}

/**
 * Convenience function for heterogeneous sequential verification.
 */
inline BatchResult batch_verify_heterogeneous_sequential(
    const std::vector<HeterogeneousItem>& items,
    bool fail_fast = false) {

    BatchOptions options;
    options.num_threads = 1;
    options.fail_fast = fail_fast;
    return batch_verify_heterogeneous(items, options);
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Get the number of hardware threads available.
 */
inline size_t hardware_threads() {
    size_t n = std::thread::hardware_concurrency();
    return n > 0 ? n : 4;  // Fallback to 4 if detection fails
}

/**
 * Create a verification item from components.
 */
inline VerificationItem make_verification_item(
    std::span<const uint8_t> pk,
    std::span<const uint8_t> msg,
    std::span<const uint8_t> sig,
    std::span<const uint8_t> ctx = {}) {

    return VerificationItem(pk, msg, sig, ctx);
}

/**
 * Create a heterogeneous verification item from components.
 */
inline HeterogeneousItem make_heterogeneous_item(
    const std::string& algorithm,
    std::span<const uint8_t> pk,
    std::span<const uint8_t> msg,
    std::span<const uint8_t> sig,
    std::span<const uint8_t> ctx = {}) {

    return HeterogeneousItem(
        algorithm,
        std::vector<uint8_t>(pk.begin(), pk.end()),
        std::vector<uint8_t>(msg.begin(), msg.end()),
        std::vector<uint8_t>(sig.begin(), sig.end()),
        std::vector<uint8_t>(ctx.begin(), ctx.end())
    );
}

} // namespace pqc

#endif // COMMON_BATCH_VERIFY_HPP
