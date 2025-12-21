"""
SLH-DSA Hash Function Instantiations (FIPS 205 Sections 11.1 and 11.2)

Implements the hash functions for both SHAKE and SHA2 variants.
"""

import hashlib
import hmac
from typing import Callable

from .address import ADRS
from .parameters import SLHDSAParameterSet
from .utils import toByte


class HashFunctions:
    """Base class for SLH-DSA hash function instantiations."""

    def __init__(self, params: SLHDSAParameterSet):
        self.params = params
        self.n = params.n

    def H_msg(self, R: bytes, pk_seed: bytes, pk_root: bytes, M: bytes) -> bytes:
        """Hash message to produce m-byte digest."""
        raise NotImplementedError

    def PRF_msg(self, sk_prf: bytes, opt_rand: bytes, M: bytes) -> bytes:
        """PRF for randomizing message hash."""
        raise NotImplementedError

    def PRF(self, pk_seed: bytes, sk_seed: bytes, adrs: ADRS) -> bytes:
        """PRF for generating secret values."""
        raise NotImplementedError

    def F(self, pk_seed: bytes, adrs: ADRS, M1: bytes) -> bytes:
        """Tweakable hash function F (single n-byte input)."""
        raise NotImplementedError

    def H(self, pk_seed: bytes, adrs: ADRS, M2: bytes) -> bytes:
        """Tweakable hash function H (two n-byte inputs)."""
        raise NotImplementedError

    def T_l(self, pk_seed: bytes, adrs: ADRS, M_l: bytes) -> bytes:
        """Tweakable hash function T_l (l n-byte inputs)."""
        raise NotImplementedError


class SHAKEHashFunctions(HashFunctions):
    """
    SHAKE-based hash functions (FIPS 205 Section 11.1)

    Uses SHAKE256 for all operations.
    """

    def H_msg(self, R: bytes, pk_seed: bytes, pk_root: bytes, M: bytes) -> bytes:
        """FIPS 205 Section 11.1: H_msg using SHAKE256."""
        shake = hashlib.shake_256()
        shake.update(R)
        shake.update(pk_seed)
        shake.update(pk_root)
        shake.update(M)
        return shake.digest(self.params.m)

    def PRF_msg(self, sk_prf: bytes, opt_rand: bytes, M: bytes) -> bytes:
        """FIPS 205 Section 11.1: PRF_msg using SHAKE256."""
        shake = hashlib.shake_256()
        shake.update(sk_prf)
        shake.update(opt_rand)
        shake.update(M)
        return shake.digest(self.n)

    def PRF(self, pk_seed: bytes, sk_seed: bytes, adrs: ADRS) -> bytes:
        """FIPS 205 Section 11.1: PRF using SHAKE256."""
        shake = hashlib.shake_256()
        shake.update(pk_seed)
        shake.update(adrs.to_bytes())
        shake.update(sk_seed)
        return shake.digest(self.n)

    def F(self, pk_seed: bytes, adrs: ADRS, M1: bytes) -> bytes:
        """FIPS 205 Section 11.1: F using SHAKE256."""
        shake = hashlib.shake_256()
        shake.update(pk_seed)
        shake.update(adrs.to_bytes())
        shake.update(M1)
        return shake.digest(self.n)

    def H(self, pk_seed: bytes, adrs: ADRS, M2: bytes) -> bytes:
        """FIPS 205 Section 11.1: H using SHAKE256."""
        shake = hashlib.shake_256()
        shake.update(pk_seed)
        shake.update(adrs.to_bytes())
        shake.update(M2)
        return shake.digest(self.n)

    def T_l(self, pk_seed: bytes, adrs: ADRS, M_l: bytes) -> bytes:
        """FIPS 205 Section 11.1: T_l using SHAKE256."""
        shake = hashlib.shake_256()
        shake.update(pk_seed)
        shake.update(adrs.to_bytes())
        shake.update(M_l)
        return shake.digest(self.n)


class SHA2HashFunctions(HashFunctions):
    """
    SHA2-based hash functions (FIPS 205 Section 11.2)

    Uses SHA-256 for n=16, SHA-512 for n=24 and n=32.
    """

    def __init__(self, params: SLHDSAParameterSet):
        super().__init__(params)
        # Choose hash function based on security level
        if self.n == 16:
            self._hash_func = hashlib.sha256
            self._block_size = 64
        else:
            self._hash_func = hashlib.sha512
            self._block_size = 128

    def _mgf1(self, seed: bytes, length: int) -> bytes:
        """MGF1 mask generation function (FIPS 205 Section 11.2.2)."""
        output = b""
        counter = 0
        while len(output) < length:
            h = self._hash_func()
            h.update(seed)
            h.update(toByte(counter, 4))
            output += h.digest()
            counter += 1
        return output[:length]

    def _hmac(self, key: bytes, data: bytes) -> bytes:
        """HMAC using the appropriate hash function."""
        return hmac.new(key, data, self._hash_func).digest()

    def H_msg(self, R: bytes, pk_seed: bytes, pk_root: bytes, M: bytes) -> bytes:
        """FIPS 205 Section 11.2.2: H_msg using MGF1."""
        # First hash to get seed for MGF1
        h = self._hash_func()
        h.update(R)
        h.update(pk_seed)
        h.update(pk_root)
        h.update(M)
        seed = h.digest()
        # Use MGF1 to expand to m bytes
        return self._mgf1(R + pk_seed + seed, self.params.m)

    def PRF_msg(self, sk_prf: bytes, opt_rand: bytes, M: bytes) -> bytes:
        """FIPS 205 Section 11.2.2: PRF_msg using HMAC."""
        return self._hmac(sk_prf, opt_rand + M)[:self.n]

    def PRF(self, pk_seed: bytes, sk_seed: bytes, adrs: ADRS) -> bytes:
        """FIPS 205 Section 11.2.2: PRF using compressed ADRS."""
        compressed = adrs.get_compressed_adrs()
        data = pk_seed + compressed + sk_seed
        if self.n == 16:
            # SHA-256: pad to 64 bytes
            data = data + bytes(64 - len(data)) if len(data) < 64 else data
            h = hashlib.sha256(data)
            return h.digest()[:self.n]
        else:
            # SHA-512: pad to 128 bytes
            data = data + bytes(128 - len(data)) if len(data) < 128 else data
            h = hashlib.sha512(data)
            return h.digest()[:self.n]

    def F(self, pk_seed: bytes, adrs: ADRS, M1: bytes) -> bytes:
        """FIPS 205 Section 11.2.2: F using compressed ADRS."""
        compressed = adrs.get_compressed_adrs()
        data = pk_seed + compressed + M1
        if self.n == 16:
            # SHA-256
            data = data + bytes(64 - len(data)) if len(data) < 64 else data
            h = hashlib.sha256(data)
            return h.digest()[:self.n]
        else:
            # SHA-512
            data = data + bytes(128 - len(data)) if len(data) < 128 else data
            h = hashlib.sha512(data)
            return h.digest()[:self.n]

    def H(self, pk_seed: bytes, adrs: ADRS, M2: bytes) -> bytes:
        """FIPS 205 Section 11.2.2: H using compressed ADRS."""
        compressed = adrs.get_compressed_adrs()
        data = pk_seed + compressed + M2
        h = self._hash_func()
        h.update(data)
        return h.digest()[:self.n]

    def T_l(self, pk_seed: bytes, adrs: ADRS, M_l: bytes) -> bytes:
        """FIPS 205 Section 11.2.2: T_l using compressed ADRS."""
        compressed = adrs.get_compressed_adrs()
        data = pk_seed + compressed + M_l
        h = self._hash_func()
        h.update(data)
        return h.digest()[:self.n]


def get_hash_functions(params: SLHDSAParameterSet) -> HashFunctions:
    """Factory function to get appropriate hash functions for parameter set."""
    if params.hash_type == "shake":
        return SHAKEHashFunctions(params)
    elif params.hash_type == "sha2":
        return SHA2HashFunctions(params)
    else:
        raise ValueError(f"Unknown hash type: {params.hash_type}")
