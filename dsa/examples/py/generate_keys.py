#!/usr/bin/env python3
"""
Post-Quantum Key Generation Tool

Generates ML-DSA or SLH-DSA key pairs with certificate metadata,
similar to OpenSSL RSA key generation.

Usage:
    python generate_keys.py <algorithm> [output_dir] [options]

Options:
    --cn <name>         Common Name (e.g., "example.com")
    --org <name>        Organization (e.g., "My Company")
    --ou <name>         Organizational Unit (e.g., "Engineering")
    --country <code>    Country code (e.g., "US")
    --state <name>      State/Province (e.g., "California")
    --locality <name>   City/Locality (e.g., "San Francisco")
    --email <email>     Email address
    --days <n>          Validity period in days (default: 365)
    --serial <hex>      Serial number in hex (default: auto-generated)

Examples:
    python generate_keys.py mldsa65 /keys --cn "api.example.com" --org "My Corp" --days 730
    python generate_keys.py slh-shake-128f /keys --cn "firmware-signer" --ou "Security"
"""

import os
import sys
import json
import argparse
import secrets
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class Subject:
    """X.509-like subject information."""
    common_name: str = ""        # CN
    organization: str = ""       # O
    organizational_unit: str = ""  # OU
    country: str = ""            # C
    state: str = ""              # ST
    locality: str = ""           # L
    email: str = ""              # emailAddress

    def to_dn(self) -> str:
        """Generate Distinguished Name string."""
        parts = []
        if self.country:
            parts.append(f"C={self.country}")
        if self.state:
            parts.append(f"ST={self.state}")
        if self.locality:
            parts.append(f"L={self.locality}")
        if self.organization:
            parts.append(f"O={self.organization}")
        if self.organizational_unit:
            parts.append(f"OU={self.organizational_unit}")
        if self.common_name:
            parts.append(f"CN={self.common_name}")
        if self.email:
            parts.append(f"emailAddress={self.email}")
        return ", ".join(parts)

    def is_empty(self) -> bool:
        """Check if all fields are empty."""
        return not any([
            self.common_name, self.organization, self.organizational_unit,
            self.country, self.state, self.locality, self.email
        ])


@dataclass
class CertificateInfo:
    """Certificate metadata."""
    subject: Subject
    validity_days: int = 365
    serial_number: str = ""

    def __post_init__(self):
        if not self.serial_number:
            self.serial_number = secrets.token_hex(8)


def generate_mldsa_keys(level: str, output_dir: str, cert_info: CertificateInfo):
    """Generate ML-DSA key pair with certificate metadata."""
    from dsa import MLDSA44, MLDSA65, MLDSA87

    algorithms = {
        "mldsa44": (MLDSA44, 2420),   # (class, signature_size)
        "mldsa65": (MLDSA65, 3309),
        "mldsa87": (MLDSA87, 4627),
    }

    if level not in algorithms:
        print(f"Unknown ML-DSA level: {level}")
        print(f"Available: {', '.join(algorithms.keys())}")
        sys.exit(1)

    dsa_class, sig_size = algorithms[level]
    dsa = dsa_class()

    import time
    start = time.time()
    public_key, secret_key = dsa.keygen()
    elapsed = (time.time() - start) * 1000

    print(f"  Key generation completed in {elapsed:.0f} ms")

    # Create filenames
    prefix = os.path.join(output_dir, level)
    pk_file = f"{level}_public.key"
    sk_file = f"{level}_secret.key"
    cert_file = f"{level}_certificate.json"

    # Save keys
    with open(f"{prefix}_public.key", "wb") as f:
        f.write(public_key)

    with open(f"{prefix}_secret.key", "wb") as f:
        f.write(secret_key)

    # Create certificate metadata
    now = datetime.now(timezone.utc)
    not_after = now + timedelta(days=cert_info.validity_days)

    certificate = {
        "version": 1,
        "algorithm": level.upper(),
        "type": "ML-DSA",
        "standard": "FIPS 204",
        "subject": {
            "commonName": cert_info.subject.common_name,
            "organization": cert_info.subject.organization,
            "organizationalUnit": cert_info.subject.organizational_unit,
            "country": cert_info.subject.country,
            "state": cert_info.subject.state,
            "locality": cert_info.subject.locality,
            "email": cert_info.subject.email,
            "dn": cert_info.subject.to_dn(),
        },
        "validity": {
            "notBefore": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "notAfter": not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "days": cert_info.validity_days,
        },
        "serialNumber": cert_info.serial_number,
        "keyInfo": {
            "publicKeySize": len(public_key),
            "secretKeySize": len(secret_key),
            "signatureSize": sig_size,
            "publicKeyFile": pk_file,
            "secretKeyFile": sk_file,
        },
        "created": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    with open(f"{prefix}_certificate.json", "w") as f:
        json.dump(certificate, f, indent=2)

    return public_key, secret_key, certificate


def generate_slhdsa_keys(variant: str, output_dir: str, cert_info: CertificateInfo):
    """Generate SLH-DSA key pair with certificate metadata."""
    from dsa import slh_keygen
    from dsa.slhdsa.parameters import PARAMETER_SETS

    # Map friendly names to parameter sets
    variant_map = {
        "slh-shake-128f": "SLH-DSA-SHAKE-128f",
        "slh-shake-128s": "SLH-DSA-SHAKE-128s",
        "slh-shake-192f": "SLH-DSA-SHAKE-192f",
        "slh-shake-192s": "SLH-DSA-SHAKE-192s",
        "slh-shake-256f": "SLH-DSA-SHAKE-256f",
        "slh-shake-256s": "SLH-DSA-SHAKE-256s",
        "slh-sha2-128f": "SLH-DSA-SHA2-128f",
        "slh-sha2-128s": "SLH-DSA-SHA2-128s",
        "slh-sha2-192f": "SLH-DSA-SHA2-192f",
        "slh-sha2-192s": "SLH-DSA-SHA2-192s",
        "slh-sha2-256f": "SLH-DSA-SHA2-256f",
        "slh-sha2-256s": "SLH-DSA-SHA2-256s",
    }

    if variant not in variant_map:
        print(f"Unknown SLH-DSA variant: {variant}")
        print(f"Available: {', '.join(variant_map.keys())}")
        sys.exit(1)

    param_name = variant_map[variant]
    params = PARAMETER_SETS[param_name]

    import time
    start = time.time()
    secret_key, public_key = slh_keygen(params)
    elapsed = (time.time() - start) * 1000

    print(f"  Key generation completed in {elapsed:.0f} ms")

    # Create filenames
    safe_name = variant.replace("-", "_")
    prefix = os.path.join(output_dir, safe_name)
    pk_file = f"{safe_name}_public.key"
    sk_file = f"{safe_name}_secret.key"
    cert_file = f"{safe_name}_certificate.json"

    # Get signature size from parameters
    sig_size = params.sig_size

    # Save keys
    with open(f"{prefix}_public.key", "wb") as f:
        f.write(public_key)

    with open(f"{prefix}_secret.key", "wb") as f:
        f.write(secret_key)

    # Create certificate metadata
    now = datetime.now(timezone.utc)
    not_after = now + timedelta(days=cert_info.validity_days)

    certificate = {
        "version": 1,
        "algorithm": param_name,
        "type": "SLH-DSA",
        "standard": "FIPS 205",
        "subject": {
            "commonName": cert_info.subject.common_name,
            "organization": cert_info.subject.organization,
            "organizationalUnit": cert_info.subject.organizational_unit,
            "country": cert_info.subject.country,
            "state": cert_info.subject.state,
            "locality": cert_info.subject.locality,
            "email": cert_info.subject.email,
            "dn": cert_info.subject.to_dn(),
        },
        "validity": {
            "notBefore": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "notAfter": not_after.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "days": cert_info.validity_days,
        },
        "serialNumber": cert_info.serial_number,
        "keyInfo": {
            "publicKeySize": len(public_key),
            "secretKeySize": len(secret_key),
            "signatureSize": sig_size,
            "publicKeyFile": pk_file,
            "secretKeyFile": sk_file,
        },
        "created": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    with open(f"{prefix}_certificate.json", "w") as f:
        json.dump(certificate, f, indent=2)

    return public_key, secret_key, certificate


def print_usage():
    """Print usage information."""
    print("Post-Quantum Key Generator")
    print("=" * 60)
    print("\nUsage: python generate_keys.py <algorithm> [output_dir] [options]")
    print("\nML-DSA algorithms (FIPS 204 - fast, smaller signatures):")
    print("  mldsa44          - Category 1 (128-bit security)")
    print("  mldsa65          - Category 3 (192-bit security)")
    print("  mldsa87          - Category 5 (256-bit security)")
    print("\nSLH-DSA algorithms (FIPS 205 - hash-based, conservative):")
    print("  slh-shake-128f   - SHAKE, fast variant")
    print("  slh-shake-128s   - SHAKE, small signatures")
    print("  slh-shake-192f   - SHAKE, Category 3, fast")
    print("  slh-shake-192s   - SHAKE, Category 3, small")
    print("  slh-shake-256f   - SHAKE, Category 5, fast")
    print("  slh-shake-256s   - SHAKE, Category 5, small")
    print("  slh-sha2-128f    - SHA2, fast variant")
    print("  slh-sha2-128s    - SHA2, small signatures")
    print("  slh-sha2-192f    - SHA2, Category 3, fast")
    print("  slh-sha2-192s    - SHA2, Category 3, small")
    print("  slh-sha2-256f    - SHA2, Category 5, fast")
    print("  slh-sha2-256s    - SHA2, Category 5, small")
    print("\nCertificate Options (similar to OpenSSL):")
    print("  --cn <name>        Common Name (e.g., \"example.com\")")
    print("  --org <name>       Organization (e.g., \"My Company\")")
    print("  --ou <name>        Organizational Unit (e.g., \"Engineering\")")
    print("  --country <code>   2-letter country code (e.g., \"US\")")
    print("  --state <name>     State or Province (e.g., \"California\")")
    print("  --locality <name>  City or Locality (e.g., \"San Francisco\")")
    print("  --email <email>    Email address")
    print("  --days <n>         Validity period in days (default: 365)")
    print("  --serial <hex>     Serial number in hex (default: random)")
    print("\nExamples:")
    print("  # Basic key generation")
    print("  python generate_keys.py mldsa65 /keys")
    print()
    print("  # TLS server certificate")
    print("  python generate_keys.py mldsa65 /keys \\")
    print("      --cn \"api.example.com\" \\")
    print("      --org \"Example Corp\" \\")
    print("      --country \"US\" \\")
    print("      --days 730")
    print()
    print("  # Code signing certificate")
    print("  python generate_keys.py slh-shake-256f /keys \\")
    print("      --cn \"Code Signing\" \\")
    print("      --org \"My Company\" \\")
    print("      --ou \"Release Engineering\" \\")
    print("      --email \"security@example.com\" \\")
    print("      --days 1825")


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ["-h", "--help"]:
        print_usage()
        sys.exit(0)

    # Parse arguments manually to match C++ behavior
    algorithm = sys.argv[1].lower()
    output_dir = "/keys"

    # Certificate info
    subject = Subject()
    validity_days = 365
    serial_number = ""

    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]

        if not arg.startswith("-") and output_dir == "/keys":
            output_dir = arg
            i += 1
            continue

        if arg == "--cn" and i + 1 < len(sys.argv):
            subject.common_name = sys.argv[i + 1]
            i += 2
        elif arg == "--org" and i + 1 < len(sys.argv):
            subject.organization = sys.argv[i + 1]
            i += 2
        elif arg == "--ou" and i + 1 < len(sys.argv):
            subject.organizational_unit = sys.argv[i + 1]
            i += 2
        elif arg == "--country" and i + 1 < len(sys.argv):
            subject.country = sys.argv[i + 1]
            i += 2
        elif arg == "--state" and i + 1 < len(sys.argv):
            subject.state = sys.argv[i + 1]
            i += 2
        elif arg == "--locality" and i + 1 < len(sys.argv):
            subject.locality = sys.argv[i + 1]
            i += 2
        elif arg == "--email" and i + 1 < len(sys.argv):
            subject.email = sys.argv[i + 1]
            i += 2
        elif arg == "--days" and i + 1 < len(sys.argv):
            validity_days = int(sys.argv[i + 1])
            i += 2
        elif arg == "--serial" and i + 1 < len(sys.argv):
            serial_number = sys.argv[i + 1]
            i += 2
        else:
            print(f"Unknown option: {arg}")
            sys.exit(1)

    cert_info = CertificateInfo(
        subject=subject,
        validity_days=validity_days,
        serial_number=serial_number,
    )

    os.makedirs(output_dir, exist_ok=True)

    print(f"Output directory: {output_dir}")
    print()
    print(f"Generating {algorithm.upper()} key pair...")

    if algorithm.startswith("mldsa"):
        pk, sk, cert = generate_mldsa_keys(algorithm, output_dir, cert_info)
        algo_type = "ML-DSA (FIPS 204)"
    elif algorithm.startswith("slh-"):
        pk, sk, cert = generate_slhdsa_keys(algorithm, output_dir, cert_info)
        algo_type = "SLH-DSA (FIPS 205)"
    else:
        print(f"Unknown algorithm: {algorithm}")
        print("Use 'mldsa44', 'mldsa65', 'mldsa87', or 'slh-shake-128f', etc.")
        sys.exit(1)

    # Print summary
    print()
    print("=" * 60)
    print("Key Pair Generated Successfully")
    print("=" * 60)
    print()
    print(f"Algorithm:       {cert['algorithm']}")
    print(f"Type:            {algo_type}")
    print(f"Public Key:      {cert['keyInfo']['publicKeySize']} bytes")
    print(f"Secret Key:      {cert['keyInfo']['secretKeySize']} bytes")
    print(f"Signature Size:  {cert['keyInfo']['signatureSize']} bytes")

    if not subject.is_empty():
        print()
        print("Subject:")
        if subject.common_name:
            print(f"  Common Name:   {subject.common_name}")
        if subject.organization:
            print(f"  Organization:  {subject.organization}")
        if subject.organizational_unit:
            print(f"  Org Unit:      {subject.organizational_unit}")
        if subject.country:
            print(f"  Country:       {subject.country}")
        if subject.state:
            print(f"  State:         {subject.state}")
        if subject.locality:
            print(f"  Locality:      {subject.locality}")
        if subject.email:
            print(f"  Email:         {subject.email}")

    print()
    print("Validity:")
    print(f"  Not Before:    {cert['validity']['notBefore']}")
    print(f"  Not After:     {cert['validity']['notAfter']}")
    print(f"  Duration:      {cert['validity']['days']} days")

    print()
    print(f"Serial Number:   {cert['serialNumber']}")

    print()
    print("Output Files:")
    print(f"  {cert['keyInfo']['publicKeyFile']}")
    print(f"  {cert['keyInfo']['secretKeyFile']}")
    print(f"  {algorithm.replace('-', '_')}_certificate.json")

    print()
    print("=" * 60)
    print("WARNING: Keep your secret key file secure!")
    print(f"         chmod 600 {output_dir}/*_secret.key")
    print("=" * 60)


if __name__ == "__main__":
    main()
