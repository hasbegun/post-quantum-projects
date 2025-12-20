#!/usr/bin/env python3
"""Debug script to compare PRF outputs between expected and actual."""

import hashlib

def hex_to_bytes(h):
    return bytes.fromhex(h)

def bytes_to_hex(b):
    return b.hex()

# Test inputs from KAT test case 1
sk_seed = hex_to_bytes("173D04C938C1C36BF289C3C022D04B14")
pk_seed = hex_to_bytes("0D794777914C99766827F0F09CA972BE")

# ADRS for first PRF call (from debug output)
# Full ADRS: 0000000600000000000000000000000500000000000000000000000000000000
full_adrs = hex_to_bytes("0000000600000000000000000000000500000000000000000000000000000000")

print(f"sk_seed: {bytes_to_hex(sk_seed)}")
print(f"pk_seed: {bytes_to_hex(pk_seed)}")
print(f"Full ADRS: {bytes_to_hex(full_adrs)}")

# Extract compressed ADRS (22 bytes)
# compressed[0..2] = ADRS[1..3]
# compressed[3..10] = ADRS[4..11]
# compressed[11] = ADRS[15]
# compressed[12..21] = ADRS[16..25]
compressed_adrs = bytearray(22)
compressed_adrs[0:3] = full_adrs[1:4]      # layer address (3 LSB)
compressed_adrs[3:11] = full_adrs[4:12]    # tree address
compressed_adrs[11] = full_adrs[15]        # type (LSB)
compressed_adrs[12:22] = full_adrs[16:26]  # type-specific (10 bytes)

print(f"Compressed ADRS: {bytes_to_hex(compressed_adrs)}")

# For SHA2-128s, n=16, block_size=64
n = 16
block_size = 64

# PRF = Trunc_n(SHA-256(pk_seed || ADRSc || sk_seed || padding))
data = pk_seed + bytes(compressed_adrs) + sk_seed

# Pad to block size
if len(data) < block_size:
    data = data + bytes(block_size - len(data))

print(f"PRF input length: {len(data)}")
print(f"PRF input: {bytes_to_hex(data)}")

# Compute SHA-256
h = hashlib.sha256(data)
prf_output = h.digest()[:n]

print(f"PRF output: {bytes_to_hex(prf_output)}")
print()

# Compare with C++ output
cpp_output = "63da4639a2d3704a70a582f8970c08c0"
print(f"C++ output: {cpp_output}")
print(f"Match: {bytes_to_hex(prf_output) == cpp_output}")

print("\n" + "="*60)
print("Computing full WOTS+ public key (leaf 0)")
print("="*60)

# Parameters for SHA2-128s
w = 16  # Winternitz parameter (2^4)
lg_w = 4
len1 = 32  # ceil(8*16 / 4) = 32
len2 = 3   # floor(log16(32*15)) + 1 = floor(log16(480)) + 1 = 2 + 1 = 3
len_total = len1 + len2  # 35

print(f"len1={len1}, len2={len2}, len_total={len_total}")

def make_adrs(layer, tree, addr_type, keypair=0, chain=0, hash_addr=0):
    """Create a 32-byte ADRS."""
    adrs = bytearray(32)
    # Layer (big-endian)
    adrs[0:4] = layer.to_bytes(4, 'big')
    # Tree address (big-endian)
    adrs[4:12] = tree.to_bytes(8, 'big')
    # Type (big-endian)
    adrs[12:16] = addr_type.to_bytes(4, 'big')
    # Key pair (big-endian)
    adrs[16:20] = keypair.to_bytes(4, 'big')
    # Chain (big-endian)
    adrs[20:24] = chain.to_bytes(4, 'big')
    # Hash (big-endian)
    adrs[24:28] = hash_addr.to_bytes(4, 'big')
    return bytes(adrs)

def get_compressed_adrs(adrs):
    """Extract 22-byte compressed ADRS for SHA2."""
    compressed = bytearray(22)
    compressed[0:3] = adrs[1:4]      # layer address (3 LSB)
    compressed[3:11] = adrs[4:12]    # tree address
    compressed[11] = adrs[15]        # type (LSB)
    compressed[12:22] = adrs[16:26]  # type-specific (10 bytes)
    return bytes(compressed)

def prf(pk_seed, sk_seed, adrs):
    """PRF for SHA2."""
    compressed = get_compressed_adrs(adrs)
    data = pk_seed + compressed + sk_seed
    if len(data) < 64:
        data = data + bytes(64 - len(data))
    return hashlib.sha256(data).digest()[:16]

def f_hash(pk_seed, adrs, m1):
    """F function for SHA2."""
    compressed = get_compressed_adrs(adrs)
    data = pk_seed + compressed + m1
    if len(data) < 64:
        data = data + bytes(64 - len(data))
    return hashlib.sha256(data).digest()[:16]

def t_l(pk_seed, adrs, m_l):
    """T_l function for SHA2."""
    compressed = get_compressed_adrs(adrs)
    data = pk_seed + compressed + m_l
    return hashlib.sha256(data).digest()[:16]

def chain(pk_seed, x, i, s, adrs):
    """WOTS+ chain function."""
    if s == 0:
        return x
    tmp = x
    for j in range(i, i + s):
        # Set hash address
        adrs_bytes = bytearray(adrs)
        adrs_bytes[24:28] = j.to_bytes(4, 'big')
        tmp = f_hash(pk_seed, bytes(adrs_bytes), tmp)
    return tmp

# Constants for address types
WOTS_HASH = 0
WOTS_PK = 1
TREE = 2
FORS_TREE = 3
FORS_ROOTS = 4
WOTS_PRF = 5
FORS_PRF = 6

# Compute wots_pkGen for leaf 0
layer = 6  # d-1 = 7-1 = 6
tree_addr = 0
keypair = 0

# Generate all chain endpoints
tmp = b""
for i in range(len_total):
    # PRF to get sk[i]
    sk_adrs = make_adrs(layer, tree_addr, WOTS_PRF, keypair=keypair, chain=i)
    sk_i = prf(pk_seed, sk_seed, sk_adrs)

    if i == 0:
        print(f"sk[0] = {bytes_to_hex(sk_i)}")

    # Chain to get endpoint
    chain_adrs = make_adrs(layer, tree_addr, WOTS_HASH, keypair=keypair, chain=i)
    endpoint = chain(pk_seed, sk_i, 0, w - 1, chain_adrs)

    if i == 0:
        print(f"endpoint[0] = {bytes_to_hex(endpoint)}")

    tmp += endpoint

print(f"tmp length: {len(tmp)} (expected: {len_total * n})")

# Compress to get public key
pk_adrs = make_adrs(layer, tree_addr, WOTS_PK, keypair=keypair)
wots_pk = t_l(pk_seed, pk_adrs, tmp)

print(f"WOTS+ pk (leaf 0): {bytes_to_hex(wots_pk)}")

# Compare with C++ output
cpp_wots_pk = "5201d0a4c201ae75971411076eebe4ed"
print(f"C++ WOTS+ pk: {cpp_wots_pk}")
print(f"Match: {bytes_to_hex(wots_pk) == cpp_wots_pk}")
