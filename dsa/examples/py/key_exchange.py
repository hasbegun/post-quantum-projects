#!/usr/bin/env python3
"""
Post-Quantum Key Exchange using ML-KEM

Demonstrates ML-KEM (FIPS 203) for quantum-resistant key encapsulation.
ML-KEM is ideal for establishing shared secrets for symmetric encryption.
"""

from mlkem import MLKEM512, MLKEM768, MLKEM1024


def demo_key_exchange(kem_class, name: str):
    """Demonstrate key exchange with a specific ML-KEM parameter set."""
    print(f"\n{'=' * 60}")
    print(f"{name} Key Exchange Demo")
    print("=" * 60)

    kem = kem_class()

    # Alice generates key pair
    print("\n[1] Alice generates key pair...")
    ek, dk = kem.keygen()
    print(f"    Encapsulation Key (public): {len(ek)} bytes")
    print(f"    Decapsulation Key (secret): {len(dk)} bytes")
    print(f"    EK prefix: {ek[:16].hex()}...")

    # Bob encapsulates using Alice's public key
    print("\n[2] Bob encapsulates using Alice's public key...")
    shared_secret_bob, ciphertext = kem.encaps(ek)
    print(f"    Ciphertext: {len(ciphertext)} bytes")
    print(f"    Shared Secret (Bob): {shared_secret_bob.hex()}")

    # Alice decapsulates using her secret key
    print("\n[3] Alice decapsulates using her secret key...")
    shared_secret_alice = kem.decaps(dk, ciphertext)
    print(f"    Shared Secret (Alice): {shared_secret_alice.hex()}")

    # Verify both have the same shared secret
    match = shared_secret_bob == shared_secret_alice
    print(f"\n[4] Shared secrets match: {'YES' if match else 'NO'}")

    # Demonstrate implicit rejection
    print("\n[5] Testing implicit rejection (tampered ciphertext)...")
    tampered = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]
    rejected_secret = kem.decaps(dk, tampered)
    tamper_detected = rejected_secret != shared_secret_bob
    print(f"    Tampered ciphertext rejected: {'YES' if tamper_detected else 'NO'}")
    print(f"    Returned pseudorandom value: {rejected_secret.hex()}")


def main():
    print("=" * 60)
    print("    Post-Quantum Key Encapsulation (ML-KEM / FIPS 203)")
    print("=" * 60)

    print("\nML-KEM provides quantum-resistant key exchange using")
    print("Module-Lattice-Based cryptography (MLWE problem).")
    print("\nUse cases:")
    print("  - TLS key exchange")
    print("  - Hybrid encryption (ML-KEM + AES)")
    print("  - Key wrapping")

    # Demo all three parameter sets
    demo_key_exchange(MLKEM512, "ML-KEM-512 (Category 1, 128-bit)")
    demo_key_exchange(MLKEM768, "ML-KEM-768 (Category 3, 192-bit)")
    demo_key_exchange(MLKEM1024, "ML-KEM-1024 (Category 5, 256-bit)")

    # Parameter comparison
    print("\n" + "=" * 60)
    print("Parameter Set Comparison:")
    print("-" * 60)
    print(f"{'Parameter':<15} {'EK (bytes)':<12} {'DK (bytes)':<12} {'CT (bytes)':<12}")
    print("-" * 60)

    for kem_class, name in [
        (MLKEM512, "ML-KEM-512"),
        (MLKEM768, "ML-KEM-768"),
        (MLKEM1024, "ML-KEM-1024"),
    ]:
        kem = kem_class()
        p = kem.params
        print(f"{name:<15} {p.ek_size:<12} {p.dk_size:<12} {p.ct_size:<12}")

    print("=" * 60)
    print("ML-KEM: Post-quantum key exchange for the future!")
    print("=" * 60)


if __name__ == "__main__":
    main()
