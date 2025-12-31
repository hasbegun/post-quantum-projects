"""
Type stubs for ML-DSA native bindings
"""

from typing import Optional, Tuple

class MLDSAParams:
    """ML-DSA parameter set containing algorithm constants."""

    @property
    def name(self) -> str:
        """Parameter set name."""
        ...

    @property
    def k(self) -> int:
        """Matrix rows."""
        ...

    @property
    def l(self) -> int:
        """Matrix columns."""
        ...

    @property
    def eta(self) -> int:
        """Secret key range."""
        ...

    @property
    def tau(self) -> int:
        """Challenge weight."""
        ...

    @property
    def beta(self) -> int:
        """Signature bound."""
        ...

    @property
    def gamma1(self) -> int:
        """Mask range."""
        ...

    @property
    def gamma2(self) -> int:
        """Decomposition low bits."""
        ...

    @property
    def omega(self) -> int:
        """Max hint weight."""
        ...

    @property
    def lambda_(self) -> int:
        """Security parameter (bits)."""
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
MLDSA44_PARAMS: MLDSAParams
MLDSA65_PARAMS: MLDSAParams
MLDSA87_PARAMS: MLDSAParams


class MLDSA44:
    """ML-DSA-44: Security Category 2 (NIST Level 2)."""

    def __init__(self) -> None: ...

    def keygen(self, seed: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Generate a key pair.

        Args:
            seed: Optional 32-byte seed for deterministic key generation.
                  If None, random keys are generated.

        Returns:
            Tuple of (public_key, secret_key) as bytes.

        Raises:
            ValueError: If seed is provided but not 32 bytes.
        """
        ...

    def sign(
        self,
        sk: bytes,
        message: bytes,
        ctx: Optional[bytes] = None,
        deterministic: bool = False,
    ) -> bytes:
        """
        Sign a message.

        Args:
            sk: Secret key (bytes).
            message: Message to sign (bytes).
            ctx: Optional context string (bytes, max 255 bytes).
            deterministic: If True, use deterministic signing.

        Returns:
            Signature as bytes.

        Raises:
            ValueError: If context string exceeds 255 bytes.
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
    def params(self) -> MLDSAParams:
        """Get the parameter set for this instance."""
        ...


class MLDSA65:
    """ML-DSA-65: Security Category 3 (NIST Level 3)."""

    def __init__(self) -> None: ...

    def keygen(self, seed: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Generate a key pair."""
        ...

    def sign(
        self,
        sk: bytes,
        message: bytes,
        ctx: Optional[bytes] = None,
        deterministic: bool = False,
    ) -> bytes:
        """Sign a message."""
        ...

    def verify(
        self,
        pk: bytes,
        message: bytes,
        signature: bytes,
        ctx: Optional[bytes] = None,
    ) -> bool:
        """Verify a signature."""
        ...

    @property
    def params(self) -> MLDSAParams:
        """Get the parameter set for this instance."""
        ...


class MLDSA87:
    """ML-DSA-87: Security Category 5 (NIST Level 5)."""

    def __init__(self) -> None: ...

    def keygen(self, seed: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Generate a key pair."""
        ...

    def sign(
        self,
        sk: bytes,
        message: bytes,
        ctx: Optional[bytes] = None,
        deterministic: bool = False,
    ) -> bytes:
        """Sign a message."""
        ...

    def verify(
        self,
        pk: bytes,
        message: bytes,
        signature: bytes,
        ctx: Optional[bytes] = None,
    ) -> bool:
        """Verify a signature."""
        ...

    @property
    def params(self) -> MLDSAParams:
        """Get the parameter set for this instance."""
        ...


__version__: str
