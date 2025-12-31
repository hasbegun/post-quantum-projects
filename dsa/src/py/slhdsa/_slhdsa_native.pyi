"""
Type stubs for SLH-DSA native bindings
"""

from typing import Optional, Tuple

class SLHDSAParams:
    """SLH-DSA parameter set containing algorithm constants."""

    @property
    def name(self) -> str:
        """Parameter set name."""
        ...

    @property
    def n(self) -> int:
        """Security parameter (hash output bytes)."""
        ...

    @property
    def h(self) -> int:
        """Total tree height."""
        ...

    @property
    def d(self) -> int:
        """Number of hypertree layers."""
        ...

    @property
    def hp(self) -> int:
        """Height per layer (h/d)."""
        ...

    @property
    def a(self) -> int:
        """FORS tree height."""
        ...

    @property
    def k(self) -> int:
        """Number of FORS trees."""
        ...

    @property
    def lg_w(self) -> int:
        """Log2 of Winternitz parameter."""
        ...

    @property
    def m(self) -> int:
        """Message digest length."""
        ...

    @property
    def w(self) -> int:
        """Winternitz parameter (2^lg_w)."""
        ...

    @property
    def pk_size(self) -> int:
        """Public key size in bytes."""
        ...

    @property
    def sk_size(self) -> int:
        """Secret key size in bytes."""
        ...

    @property
    def sig_size(self) -> int:
        """Signature size in bytes."""
        ...


# Parameter set constants
SLH_DSA_SHA2_128s: SLHDSAParams
SLH_DSA_SHA2_128f: SLHDSAParams
SLH_DSA_SHA2_192s: SLHDSAParams
SLH_DSA_SHA2_192f: SLHDSAParams
SLH_DSA_SHA2_256s: SLHDSAParams
SLH_DSA_SHA2_256f: SLHDSAParams
SLH_DSA_SHAKE_128s: SLHDSAParams
SLH_DSA_SHAKE_128f: SLHDSAParams
SLH_DSA_SHAKE_192s: SLHDSAParams
SLH_DSA_SHAKE_192f: SLHDSAParams
SLH_DSA_SHAKE_256s: SLHDSAParams
SLH_DSA_SHAKE_256f: SLHDSAParams


class SLHDSA_SHA2_128s:
    """SLH-DSA-SHA2-128s: 128-bit security, small signatures."""

    def __init__(self) -> None: ...

    def keygen(self) -> Tuple[bytes, bytes]:
        """
        Generate a key pair.

        Returns:
            Tuple of (public_key, secret_key) as bytes.
        """
        ...

    def keygen_from_seeds(
        self, sk_seed: bytes, sk_prf: bytes, pk_seed: bytes
    ) -> Tuple[bytes, bytes]:
        """
        Generate a key pair from seeds (for testing/KAT).

        Args:
            sk_seed: Secret seed (n bytes).
            sk_prf: PRF key for randomization (n bytes).
            pk_seed: Public seed (n bytes).

        Returns:
            Tuple of (public_key, secret_key) as bytes.
        """
        ...

    def sign(
        self,
        sk: bytes,
        message: bytes,
        ctx: Optional[bytes] = None,
        randomize: bool = True,
    ) -> bytes:
        """
        Sign a message.

        Args:
            sk: Secret key (bytes).
            message: Message to sign (bytes).
            ctx: Optional context string (bytes, max 255 bytes).
            randomize: If True (default), use randomized signing.

        Returns:
            Signature as bytes.
        """
        ...

    def verify(
        self,
        pk: bytes,
        message: bytes,
        signature: bytes,
        ctx: Optional[bytes] = None,
    ) -> bool:
        """
        Verify a signature.

        Args:
            pk: Public key (bytes).
            message: Message (bytes).
            signature: Signature to verify (bytes).
            ctx: Optional context string (bytes).

        Returns:
            True if signature is valid, False otherwise.
        """
        ...

    @property
    def params(self) -> SLHDSAParams:
        """Get the parameter set for this instance."""
        ...


class SLHDSA_SHA2_128f:
    """SLH-DSA-SHA2-128f: 128-bit security, fast signing."""
    def __init__(self) -> None: ...
    def keygen(self) -> Tuple[bytes, bytes]: ...
    def keygen_from_seeds(self, sk_seed: bytes, sk_prf: bytes, pk_seed: bytes) -> Tuple[bytes, bytes]: ...
    def sign(self, sk: bytes, message: bytes, ctx: Optional[bytes] = None, randomize: bool = True) -> bytes: ...
    def verify(self, pk: bytes, message: bytes, signature: bytes, ctx: Optional[bytes] = None) -> bool: ...
    @property
    def params(self) -> SLHDSAParams: ...


class SLHDSA_SHA2_192s:
    """SLH-DSA-SHA2-192s: 192-bit security, small signatures."""
    def __init__(self) -> None: ...
    def keygen(self) -> Tuple[bytes, bytes]: ...
    def keygen_from_seeds(self, sk_seed: bytes, sk_prf: bytes, pk_seed: bytes) -> Tuple[bytes, bytes]: ...
    def sign(self, sk: bytes, message: bytes, ctx: Optional[bytes] = None, randomize: bool = True) -> bytes: ...
    def verify(self, pk: bytes, message: bytes, signature: bytes, ctx: Optional[bytes] = None) -> bool: ...
    @property
    def params(self) -> SLHDSAParams: ...


class SLHDSA_SHA2_192f:
    """SLH-DSA-SHA2-192f: 192-bit security, fast signing."""
    def __init__(self) -> None: ...
    def keygen(self) -> Tuple[bytes, bytes]: ...
    def keygen_from_seeds(self, sk_seed: bytes, sk_prf: bytes, pk_seed: bytes) -> Tuple[bytes, bytes]: ...
    def sign(self, sk: bytes, message: bytes, ctx: Optional[bytes] = None, randomize: bool = True) -> bytes: ...
    def verify(self, pk: bytes, message: bytes, signature: bytes, ctx: Optional[bytes] = None) -> bool: ...
    @property
    def params(self) -> SLHDSAParams: ...


class SLHDSA_SHA2_256s:
    """SLH-DSA-SHA2-256s: 256-bit security, small signatures."""
    def __init__(self) -> None: ...
    def keygen(self) -> Tuple[bytes, bytes]: ...
    def keygen_from_seeds(self, sk_seed: bytes, sk_prf: bytes, pk_seed: bytes) -> Tuple[bytes, bytes]: ...
    def sign(self, sk: bytes, message: bytes, ctx: Optional[bytes] = None, randomize: bool = True) -> bytes: ...
    def verify(self, pk: bytes, message: bytes, signature: bytes, ctx: Optional[bytes] = None) -> bool: ...
    @property
    def params(self) -> SLHDSAParams: ...


class SLHDSA_SHA2_256f:
    """SLH-DSA-SHA2-256f: 256-bit security, fast signing."""
    def __init__(self) -> None: ...
    def keygen(self) -> Tuple[bytes, bytes]: ...
    def keygen_from_seeds(self, sk_seed: bytes, sk_prf: bytes, pk_seed: bytes) -> Tuple[bytes, bytes]: ...
    def sign(self, sk: bytes, message: bytes, ctx: Optional[bytes] = None, randomize: bool = True) -> bytes: ...
    def verify(self, pk: bytes, message: bytes, signature: bytes, ctx: Optional[bytes] = None) -> bool: ...
    @property
    def params(self) -> SLHDSAParams: ...


class SLHDSA_SHAKE_128s:
    """SLH-DSA-SHAKE-128s: 128-bit security, small signatures."""
    def __init__(self) -> None: ...
    def keygen(self) -> Tuple[bytes, bytes]: ...
    def keygen_from_seeds(self, sk_seed: bytes, sk_prf: bytes, pk_seed: bytes) -> Tuple[bytes, bytes]: ...
    def sign(self, sk: bytes, message: bytes, ctx: Optional[bytes] = None, randomize: bool = True) -> bytes: ...
    def verify(self, pk: bytes, message: bytes, signature: bytes, ctx: Optional[bytes] = None) -> bool: ...
    @property
    def params(self) -> SLHDSAParams: ...


class SLHDSA_SHAKE_128f:
    """SLH-DSA-SHAKE-128f: 128-bit security, fast signing."""
    def __init__(self) -> None: ...
    def keygen(self) -> Tuple[bytes, bytes]: ...
    def keygen_from_seeds(self, sk_seed: bytes, sk_prf: bytes, pk_seed: bytes) -> Tuple[bytes, bytes]: ...
    def sign(self, sk: bytes, message: bytes, ctx: Optional[bytes] = None, randomize: bool = True) -> bytes: ...
    def verify(self, pk: bytes, message: bytes, signature: bytes, ctx: Optional[bytes] = None) -> bool: ...
    @property
    def params(self) -> SLHDSAParams: ...


class SLHDSA_SHAKE_192s:
    """SLH-DSA-SHAKE-192s: 192-bit security, small signatures."""
    def __init__(self) -> None: ...
    def keygen(self) -> Tuple[bytes, bytes]: ...
    def keygen_from_seeds(self, sk_seed: bytes, sk_prf: bytes, pk_seed: bytes) -> Tuple[bytes, bytes]: ...
    def sign(self, sk: bytes, message: bytes, ctx: Optional[bytes] = None, randomize: bool = True) -> bytes: ...
    def verify(self, pk: bytes, message: bytes, signature: bytes, ctx: Optional[bytes] = None) -> bool: ...
    @property
    def params(self) -> SLHDSAParams: ...


class SLHDSA_SHAKE_192f:
    """SLH-DSA-SHAKE-192f: 192-bit security, fast signing."""
    def __init__(self) -> None: ...
    def keygen(self) -> Tuple[bytes, bytes]: ...
    def keygen_from_seeds(self, sk_seed: bytes, sk_prf: bytes, pk_seed: bytes) -> Tuple[bytes, bytes]: ...
    def sign(self, sk: bytes, message: bytes, ctx: Optional[bytes] = None, randomize: bool = True) -> bytes: ...
    def verify(self, pk: bytes, message: bytes, signature: bytes, ctx: Optional[bytes] = None) -> bool: ...
    @property
    def params(self) -> SLHDSAParams: ...


class SLHDSA_SHAKE_256s:
    """SLH-DSA-SHAKE-256s: 256-bit security, small signatures."""
    def __init__(self) -> None: ...
    def keygen(self) -> Tuple[bytes, bytes]: ...
    def keygen_from_seeds(self, sk_seed: bytes, sk_prf: bytes, pk_seed: bytes) -> Tuple[bytes, bytes]: ...
    def sign(self, sk: bytes, message: bytes, ctx: Optional[bytes] = None, randomize: bool = True) -> bytes: ...
    def verify(self, pk: bytes, message: bytes, signature: bytes, ctx: Optional[bytes] = None) -> bool: ...
    @property
    def params(self) -> SLHDSAParams: ...


class SLHDSA_SHAKE_256f:
    """SLH-DSA-SHAKE-256f: 256-bit security, fast signing."""
    def __init__(self) -> None: ...
    def keygen(self) -> Tuple[bytes, bytes]: ...
    def keygen_from_seeds(self, sk_seed: bytes, sk_prf: bytes, pk_seed: bytes) -> Tuple[bytes, bytes]: ...
    def sign(self, sk: bytes, message: bytes, ctx: Optional[bytes] = None, randomize: bool = True) -> bytes: ...
    def verify(self, pk: bytes, message: bytes, signature: bytes, ctx: Optional[bytes] = None) -> bool: ...
    @property
    def params(self) -> SLHDSAParams: ...


__version__: str
