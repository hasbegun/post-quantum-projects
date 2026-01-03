#!/usr/bin/env python3
"""
Post-Quantum DSA Comparison

Compares ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) performance and characteristics.
Helps choose the right algorithm for your use case.
"""

import time
from mldsa import MLDSA44, MLDSA65, MLDSA87
from slhdsa import SLHDSA_SHAKE_128f, SLHDSA_SHAKE_128s


def benchmark_mldsa(name: str, dsa_class, iterations: int = 10):
    """Benchmark ML-DSA operations."""
    dsa = dsa_class()
    message = b"Benchmark message for post-quantum signatures"

    # Keygen
    start = time.time()
    for _ in range(iterations):
        pk, sk = dsa.keygen()
    keygen_time = (time.time() - start) / iterations * 1000

    # Sign
    pk, sk = dsa.keygen()
    start = time.time()
    for _ in range(iterations):
        sig = dsa.sign(sk, message)
    sign_time = (time.time() - start) / iterations * 1000

    # Verify
    sig = dsa.sign(sk, message)
    start = time.time()
    for _ in range(iterations):
        dsa.verify(pk, message, sig)
    verify_time = (time.time() - start) / iterations * 1000

    return {
        "name": name,
        "pk_size": len(pk),
        "sk_size": len(sk),
        "sig_size": len(sig),
        "keygen_ms": keygen_time,
        "sign_ms": sign_time,
        "verify_ms": verify_time,
    }


def benchmark_slhdsa(name: str, dsa_class, iterations: int = 5):
    """Benchmark SLH-DSA operations."""
    dsa = dsa_class()
    message = b"Benchmark message for post-quantum signatures"

    # Keygen
    start = time.time()
    for _ in range(iterations):
        pk, sk = dsa.keygen()
    keygen_time = (time.time() - start) / iterations * 1000

    # Sign
    pk, sk = dsa.keygen()
    start = time.time()
    for _ in range(iterations):
        sig = dsa.sign(sk, message)
    sign_time = (time.time() - start) / iterations * 1000

    # Verify
    sig = dsa.sign(sk, message)
    start = time.time()
    for _ in range(iterations):
        dsa.verify(pk, message, sig)
    verify_time = (time.time() - start) / iterations * 1000

    return {
        "name": name,
        "pk_size": len(pk),
        "sk_size": len(sk),
        "sig_size": len(sig),
        "keygen_ms": keygen_time,
        "sign_ms": sign_time,
        "verify_ms": verify_time,
    }


def main():
    print("=" * 70)
    print("Post-Quantum Digital Signature Algorithm Comparison")
    print("=" * 70)

    print("\nBenchmarking algorithms (this may take a moment)...\n")

    results = []

    # ML-DSA benchmarks
    print("  ML-DSA-44...", end=" ", flush=True)
    results.append(benchmark_mldsa("ML-DSA-44", MLDSA44))
    print("done")

    print("  ML-DSA-65...", end=" ", flush=True)
    results.append(benchmark_mldsa("ML-DSA-65", MLDSA65))
    print("done")

    print("  ML-DSA-87...", end=" ", flush=True)
    results.append(benchmark_mldsa("ML-DSA-87", MLDSA87))
    print("done")

    # SLH-DSA benchmarks
    print("  SLH-DSA-SHAKE-128f...", end=" ", flush=True)
    results.append(benchmark_slhdsa("SLH-DSA-128f", SLHDSA_SHAKE_128f))
    print("done")

    print("  SLH-DSA-SHAKE-128s...", end=" ", flush=True)
    results.append(benchmark_slhdsa("SLH-DSA-128s", SLHDSA_SHAKE_128s, iterations=2))
    print("done")

    # Print results table
    print("\n" + "=" * 70)
    print("RESULTS")
    print("=" * 70)

    print("\nKey and Signature Sizes:")
    print("-" * 60)
    print(f"{'Algorithm':<20} {'PK (bytes)':<12} {'SK (bytes)':<12} {'Sig (bytes)':<12}")
    print("-" * 60)
    for r in results:
        print(f"{r['name']:<20} {r['pk_size']:<12} {r['sk_size']:<12} {r['sig_size']:<12}")

    print("\nPerformance (milliseconds):")
    print("-" * 60)
    print(f"{'Algorithm':<20} {'KeyGen':<12} {'Sign':<12} {'Verify':<12}")
    print("-" * 60)
    for r in results:
        print(f"{r['name']:<20} {r['keygen_ms']:<12.1f} {r['sign_ms']:<12.1f} {r['verify_ms']:<12.1f}")

    print("\n" + "=" * 70)
    print("RECOMMENDATIONS")
    print("=" * 70)

    print("""
    ML-DSA (FIPS 204) - Lattice-based
    ---------------------------------
    + Fast signing and verification
    + Smaller signatures (2.4-4.6 KB)
    + Ideal for: APIs, messaging, blockchain, real-time apps
    - Newer mathematical foundations

    SLH-DSA (FIPS 205) - Hash-based
    -------------------------------
    + Conservative security (hash functions only)
    + 40+ years of cryptanalysis on hash functions
    + Ideal for: Root CAs, legal documents, firmware signing
    - Larger signatures (7.8-50 KB)
    - Slower signing

    Security Level Guide:
    --------------------
    Category 1 (128-bit): ML-DSA-44, SLH-DSA-128*  -> General use
    Category 3 (192-bit): ML-DSA-65, SLH-DSA-192*  -> Sensitive data
    Category 5 (256-bit): ML-DSA-87, SLH-DSA-256*  -> Top secret
    """)

    print("=" * 70)


if __name__ == "__main__":
    main()
