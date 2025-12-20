"""
ML-DSA Core Implementation
Based on FIPS 204 Algorithms 1-8

This module implements the main ML-DSA operations:
- Key Generation (Algorithm 1, 6)
- Signing (Algorithm 2, 7)
- Verification (Algorithm 3, 8)
- HashML-DSA variants (Algorithms 4, 5)
"""

import os
from typing import Tuple, Optional, List
from hashlib import shake_256

from .params import Q, D, MLDSAParams, MLDSA44_PARAMS, MLDSA65_PARAMS, MLDSA87_PARAMS
from .ntt import (
    ntt, ntt_inv, ntt_multiply, vec_ntt, vec_ntt_inv,
    vec_add, vec_sub, mat_vec_mul_ntt, poly_add, poly_sub
)
from .encoding import (
    pk_encode, pk_decode, sk_encode, sk_decode, sig_encode, sig_decode,
    vec_power2round, vec_high_bits, vec_low_bits, vec_make_hint, vec_use_hint,
    poly_use_hint
)
from .sampling import (
    expand_a, expand_s, expand_mask, sample_in_ball,
    h_function, w1_encode, compute_tr, compute_mu
)
from .utils import infinity_norm_vec, mod_pm


class MLDSA:
    """
    ML-DSA Digital Signature Algorithm

    Provides key generation, signing, and verification operations
    based on NIST FIPS 204.
    """

    def __init__(self, params: MLDSAParams):
        """Initialize ML-DSA with given parameter set"""
        self.params = params

    def keygen(self, seed: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Algorithm 1: ML-DSA.KeyGen
        Generate public/private key pair

        Input: seed (optional 32-byte seed for deterministic generation)
        Output: (pk, sk) public and private keys
        """
        # Generate or use provided seed
        if seed is None:
            xi = os.urandom(32)
        else:
            if len(seed) != 32:
                raise ValueError("Seed must be 32 bytes")
            xi = seed

        return self._keygen_internal(xi)

    def _keygen_internal(self, xi: bytes) -> Tuple[bytes, bytes]:
        """
        Algorithm 6: ML-DSA.KeyGen_internal
        Internal key generation algorithm

        Input: xi in B^32 (seed)
        Output: (pk, sk)
        """
        params = self.params
        k, l = params.k, params.l

        # Step 1: Expand seed to (rho, rho', K)
        expanded = h_function(xi, 128)
        rho = expanded[:32]      # Public seed for A
        rho_prime = expanded[32:96]  # Secret seed for s1, s2
        K = expanded[96:128]     # Secret key for signing

        # Step 2: Expand A matrix in NTT domain
        A_hat = expand_a(rho, params)

        # Step 3: Expand secret vectors s1, s2
        s1, s2 = expand_s(rho_prime, params)

        # Step 4: Compute t = NTT^-1(A_hat * NTT(s1)) + s2
        s1_hat = vec_ntt(s1)
        As1_hat = mat_vec_mul_ntt(A_hat, s1_hat)
        As1 = vec_ntt_inv(As1_hat)
        t = vec_add(As1, s2)

        # Step 5: Compress t into (t1, t0) using Power2Round
        t1, t0 = vec_power2round(t)

        # Step 6: Encode public key
        pk = pk_encode(rho, t1, params)

        # Step 7: Compute tr = H(pk)
        tr = compute_tr(pk)

        # Step 8: Encode private key
        sk = sk_encode(rho, K, tr, s1, s2, t0, params)

        return pk, sk

    def sign(self, sk: bytes, message: bytes, ctx: bytes = b"",
             deterministic: bool = False) -> bytes:
        """
        Algorithm 2: ML-DSA.Sign
        Sign a message

        Input:
            sk: Private key
            message: Message to sign
            ctx: Context string (max 255 bytes)
            deterministic: Use deterministic signing if True

        Output: Signature sigma
        """
        if len(ctx) > 255:
            raise ValueError("Context string must be at most 255 bytes")

        # Construct M' = (0, |ctx|, ctx, M) for pure ML-DSA
        M_prime = bytes([0, len(ctx)]) + ctx + message

        # Generate randomness
        if deterministic:
            rnd = bytes(32)
        else:
            rnd = os.urandom(32)

        return self._sign_internal(sk, M_prime, rnd)

    def _sign_internal(self, sk: bytes, M_prime: bytes, rnd: bytes) -> bytes:
        """
        Algorithm 7: ML-DSA.Sign_internal
        Internal signing algorithm

        Input: sk, M' (formatted message), rnd (randomness)
        Output: sigma (signature)
        """
        params = self.params
        k, l = params.k, params.l
        gamma1, gamma2 = params.gamma1, params.gamma2
        beta = params.beta
        omega = params.omega

        # Step 1: Decode private key
        rho, K, tr, s1, s2, t0 = sk_decode(sk, params)

        # Step 2: Compute message representative
        mu = h_function(tr + M_prime, 64)

        # Step 3: Compute rho' for mask generation
        rho_prime = h_function(K + rnd + mu, 64)

        # Step 4: Precompute NTT forms
        s1_hat = vec_ntt(s1)
        s2_hat = vec_ntt(s2)
        t0_hat = vec_ntt(t0)
        A_hat = expand_a(rho, params)

        # Step 5: Signing loop (rejection sampling)
        kappa = 0
        max_attempts = 1000  # Prevent infinite loop

        while kappa < max_attempts:
            # Step 5a: Generate mask y
            y = expand_mask(rho_prime, kappa * l, params)
            y_hat = vec_ntt(y)

            # Step 5b: Compute w = A*y
            w_hat = mat_vec_mul_ntt(A_hat, y_hat)
            w = vec_ntt_inv(w_hat)

            # Step 5c: Compute w1 (high bits of w)
            w1 = vec_high_bits(w, gamma2)

            # Step 5d: Compute challenge
            c_tilde = h_function(mu + w1_encode(w1, params), params.lambda_ // 4)
            c = sample_in_ball(c_tilde, params.tau)
            c_hat = ntt(c)

            # Step 5e: Compute z = y + c*s1
            cs1_hat = [ntt_multiply(c_hat, s1_hat[i]) for i in range(l)]
            cs1 = vec_ntt_inv(cs1_hat)
            z = vec_add(y, cs1)

            # Step 5f: Compute r0 = LowBits(w - c*s2)
            cs2_hat = [ntt_multiply(c_hat, s2_hat[i]) for i in range(k)]
            cs2 = vec_ntt_inv(cs2_hat)
            r = vec_sub(w, cs2)
            r0 = vec_low_bits(r, gamma2)

            # Step 5g: Check bounds
            # z must have infinity norm < gamma1 - beta
            z_norm = infinity_norm_vec([[mod_pm(c) for c in poly] for poly in z])
            r0_norm = infinity_norm_vec([[mod_pm(c) for c in poly] for poly in r0])

            if z_norm >= gamma1 - beta or r0_norm >= gamma2 - beta:
                kappa += 1
                continue

            # Step 5h: Compute hints
            # h := MakeHint(-ct0, w - cs2 + ct0) = MakeHint(-ct0, r + ct0)
            ct0_hat = [ntt_multiply(c_hat, t0_hat[i]) for i in range(k)]
            ct0 = vec_ntt_inv(ct0_hat)
            ct0_neg = [[-c % Q for c in poly] for poly in ct0]

            h, hints_count = vec_make_hint(ct0_neg, vec_add(r, ct0), gamma2)

            # Check hint count
            if hints_count > omega:
                kappa += 1
                continue

            # Step 5i: Signature found!
            # Reduce z coefficients to proper range
            z_reduced = [[mod_pm(c) for c in poly] for poly in z]
            sigma = sig_encode(c_tilde, z_reduced, h, params)
            return sigma

        raise RuntimeError("Signing failed: too many rejection attempts")

    def verify(self, pk: bytes, message: bytes, sigma: bytes, ctx: bytes = b"") -> bool:
        """
        Algorithm 3: ML-DSA.Verify
        Verify a signature

        Input:
            pk: Public key
            message: Message
            sigma: Signature
            ctx: Context string (max 255 bytes)

        Output: True if valid, False otherwise
        """
        if len(ctx) > 255:
            return False

        # Construct M' = (0, |ctx|, ctx, M) for pure ML-DSA
        M_prime = bytes([0, len(ctx)]) + ctx + message

        return self._verify_internal(pk, M_prime, sigma)

    def _verify_internal(self, pk: bytes, M_prime: bytes, sigma: bytes) -> bool:
        """
        Algorithm 8: ML-DSA.Verify_internal
        Internal verification algorithm

        Input: pk, M' (formatted message), sigma (signature)
        Output: True if valid, False otherwise
        """
        params = self.params
        k, l = params.k, params.l
        gamma1, gamma2 = params.gamma1, params.gamma2
        beta = params.beta
        omega = params.omega

        # Step 1: Decode public key
        rho, t1 = pk_decode(pk, params)

        # Step 2: Decode signature
        decoded = sig_decode(sigma, params)
        if decoded is None:
            return False
        c_tilde, z, h = decoded

        # Step 3: Check z norm
        z_norm = infinity_norm_vec([[mod_pm(c) for c in poly] for poly in z])
        if z_norm >= gamma1 - beta:
            return False

        # Step 4: Check hint count
        hints_count = sum(sum(poly) for poly in h)
        if hints_count > omega:
            return False

        # Step 5: Expand A matrix
        A_hat = expand_a(rho, params)

        # Step 6: Compute message representative
        tr = compute_tr(pk)
        mu = h_function(tr + M_prime, 64)

        # Step 7: Compute c from c_tilde
        c = sample_in_ball(c_tilde, params.tau)
        c_hat = ntt(c)

        # Step 8: Compute t1 * 2^d in NTT domain
        t1_scaled = [[coef << D for coef in poly] for poly in t1]
        t1_hat = vec_ntt(t1_scaled)

        # Step 9: Compute w' = A*z - c*t1*2^d
        z_hat = vec_ntt(z)
        Az_hat = mat_vec_mul_ntt(A_hat, z_hat)

        ct1_hat = [ntt_multiply(c_hat, t1_hat[i]) for i in range(k)]

        w_prime_hat = [poly_sub(Az_hat[i], ct1_hat[i]) for i in range(k)]
        w_prime = vec_ntt_inv(w_prime_hat)

        # Step 10: Use hint to recover w1'
        w1_prime = vec_use_hint(h, w_prime, gamma2)

        # Step 11: Compute challenge and compare
        c_tilde_prime = h_function(mu + w1_encode(w1_prime, params), params.lambda_ // 4)

        return c_tilde == c_tilde_prime

    def hash_sign(self, sk: bytes, message: bytes, ctx: bytes = b"",
                  hash_oid: bytes = b"", ph: bytes = b"",
                  deterministic: bool = False) -> bytes:
        """
        Algorithm 4: HashML-DSA.Sign
        Sign a pre-hashed message

        Input:
            sk: Private key
            message: Pre-hashed message (PH)
            ctx: Context string
            hash_oid: OID of hash function used
            ph: Pre-hash (should be hash of original message)
            deterministic: Use deterministic signing if True

        Output: Signature
        """
        if len(ctx) > 255:
            raise ValueError("Context string must be at most 255 bytes")

        # M' = (1, |ctx|, ctx, OID, PH)
        M_prime = bytes([1, len(ctx)]) + ctx + hash_oid + ph

        if deterministic:
            rnd = bytes(32)
        else:
            rnd = os.urandom(32)

        return self._sign_internal(sk, M_prime, rnd)

    def hash_verify(self, pk: bytes, message: bytes, sigma: bytes,
                    ctx: bytes = b"", hash_oid: bytes = b"", ph: bytes = b"") -> bool:
        """
        Algorithm 5: HashML-DSA.Verify
        Verify a pre-hash signature

        Input:
            pk: Public key
            message: Pre-hashed message
            sigma: Signature
            ctx: Context string
            hash_oid: OID of hash function used
            ph: Pre-hash

        Output: True if valid, False otherwise
        """
        if len(ctx) > 255:
            return False

        # M' = (1, |ctx|, ctx, OID, PH)
        M_prime = bytes([1, len(ctx)]) + ctx + hash_oid + ph

        return self._verify_internal(pk, M_prime, sigma)


# Convenience classes for specific parameter sets
class MLDSA44(MLDSA):
    """ML-DSA-44: Security Category 2"""
    def __init__(self):
        super().__init__(MLDSA44_PARAMS)


class MLDSA65(MLDSA):
    """ML-DSA-65: Security Category 3"""
    def __init__(self):
        super().__init__(MLDSA65_PARAMS)


class MLDSA87(MLDSA):
    """ML-DSA-87: Security Category 5"""
    def __init__(self):
        super().__init__(MLDSA87_PARAMS)
