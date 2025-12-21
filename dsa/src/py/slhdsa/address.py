"""
SLH-DSA Address Scheme (FIPS 205 Section 4.2)

The ADRS structure is a 32-byte address used for domain separation
in hash function calls.
"""

from .utils import toByte, toInt


# Address types (FIPS 205 Table 1)
WOTS_HASH = 0       # WOTS+ hash address
WOTS_PK = 1         # WOTS+ public key compression
TREE = 2            # Main tree hashing
FORS_TREE = 3       # FORS tree hashing
FORS_ROOTS = 4      # FORS roots compression
WOTS_PRF = 5        # WOTS+ PRF
FORS_PRF = 6        # FORS PRF


class ADRS:
    """
    32-byte address structure for domain separation.

    Layout:
        Bytes 0-3:   Layer address
        Bytes 4-11:  Tree address (8 bytes)
        Bytes 12-15: Type
        Bytes 16-19: Type-specific field 1
        Bytes 20-23: Type-specific field 2
        Bytes 24-27: Type-specific field 3
        Bytes 28-31: Type-specific field 4
    """

    def __init__(self):
        """Initialize a zeroed address."""
        self._data = bytearray(32)

    def copy(self) -> "ADRS":
        """Create a copy of this address."""
        new_adrs = ADRS()
        new_adrs._data = bytearray(self._data)
        return new_adrs

    def to_bytes(self) -> bytes:
        """Return the address as bytes."""
        return bytes(self._data)

    # Layer address (bytes 0-3)
    def get_layer_address(self) -> int:
        return toInt(bytes(self._data[0:4]), 4)

    def set_layer_address(self, value: int) -> "ADRS":
        self._data[0:4] = toByte(value, 4)
        return self

    # Tree address (bytes 4-11)
    def get_tree_address(self) -> int:
        return toInt(bytes(self._data[4:12]), 8)

    def set_tree_address(self, value: int) -> "ADRS":
        self._data[4:12] = toByte(value, 8)
        return self

    # Type (bytes 12-15)
    def get_type(self) -> int:
        return toInt(bytes(self._data[12:16]), 4)

    def set_type(self, value: int) -> "ADRS":
        self._data[12:16] = toByte(value, 4)
        # Clear type-specific bytes when type changes
        self._data[16:32] = bytes(16)
        return self

    # Key pair address (bytes 16-19) - for WOTS+ types
    def get_key_pair_address(self) -> int:
        return toInt(bytes(self._data[16:20]), 4)

    def set_key_pair_address(self, value: int) -> "ADRS":
        self._data[16:20] = toByte(value, 4)
        return self

    # Chain address (bytes 20-23) - for WOTS_HASH
    def get_chain_address(self) -> int:
        return toInt(bytes(self._data[20:24]), 4)

    def set_chain_address(self, value: int) -> "ADRS":
        self._data[20:24] = toByte(value, 4)
        return self

    # Hash address (bytes 24-27) - for WOTS_HASH
    def get_hash_address(self) -> int:
        return toInt(bytes(self._data[24:28]), 4)

    def set_hash_address(self, value: int) -> "ADRS":
        self._data[24:28] = toByte(value, 4)
        return self

    # Tree height (bytes 20-23) - for TREE and FORS_TREE
    def get_tree_height(self) -> int:
        return toInt(bytes(self._data[20:24]), 4)

    def set_tree_height(self, value: int) -> "ADRS":
        self._data[20:24] = toByte(value, 4)
        return self

    # Tree index (bytes 24-27) - for TREE and FORS_TREE
    def get_tree_index(self) -> int:
        return toInt(bytes(self._data[24:28]), 4)

    def set_tree_index(self, value: int) -> "ADRS":
        self._data[24:28] = toByte(value, 4)
        return self

    def get_compressed_adrs(self) -> bytes:
        """
        Get 22-byte compressed address for SHA2 variants.

        Layout (FIPS 205 Section 11.2.1):
            Bytes 0-2:   Offset 1-3 (layer address, 3 LSB)
            Bytes 3-10:  Offset 4-11 (tree address)
            Bytes 11:    Offset 15 (type, LSB)
            Bytes 12-21: Offset 16-25 (type-specific fields)
        """
        compressed = bytearray(22)
        # Layer address (3 bytes from offset 1-3)
        compressed[0:3] = self._data[1:4]
        # Tree address (8 bytes from offset 4-11)
        compressed[3:11] = self._data[4:12]
        # Type (1 byte from offset 15)
        compressed[11] = self._data[15]
        # Type-specific (10 bytes from offset 16-25)
        compressed[12:22] = self._data[16:26]
        return bytes(compressed)


def make_wots_hash_adrs(layer: int, tree: int, keypair: int) -> ADRS:
    """Create a WOTS+ hash address."""
    adrs = ADRS()
    adrs.set_layer_address(layer)
    adrs.set_tree_address(tree)
    adrs.set_type(WOTS_HASH)
    adrs.set_key_pair_address(keypair)
    return adrs


def make_wots_pk_adrs(layer: int, tree: int, keypair: int) -> ADRS:
    """Create a WOTS+ public key compression address."""
    adrs = ADRS()
    adrs.set_layer_address(layer)
    adrs.set_tree_address(tree)
    adrs.set_type(WOTS_PK)
    adrs.set_key_pair_address(keypair)
    return adrs


def make_tree_adrs(layer: int, tree: int) -> ADRS:
    """Create a tree hashing address."""
    adrs = ADRS()
    adrs.set_layer_address(layer)
    adrs.set_tree_address(tree)
    adrs.set_type(TREE)
    return adrs


def make_fors_tree_adrs(tree: int, keypair: int) -> ADRS:
    """Create a FORS tree hashing address."""
    adrs = ADRS()
    adrs.set_layer_address(0)
    adrs.set_tree_address(tree)
    adrs.set_type(FORS_TREE)
    adrs.set_key_pair_address(keypair)
    return adrs


def make_fors_roots_adrs(tree: int, keypair: int) -> ADRS:
    """Create a FORS roots compression address."""
    adrs = ADRS()
    adrs.set_layer_address(0)
    adrs.set_tree_address(tree)
    adrs.set_type(FORS_ROOTS)
    adrs.set_key_pair_address(keypair)
    return adrs


def make_wots_prf_adrs(layer: int, tree: int, keypair: int) -> ADRS:
    """Create a WOTS+ PRF address."""
    adrs = ADRS()
    adrs.set_layer_address(layer)
    adrs.set_tree_address(tree)
    adrs.set_type(WOTS_PRF)
    adrs.set_key_pair_address(keypair)
    return adrs


def make_fors_prf_adrs(tree: int, keypair: int) -> ADRS:
    """Create a FORS PRF address."""
    adrs = ADRS()
    adrs.set_layer_address(0)
    adrs.set_tree_address(tree)
    adrs.set_type(FORS_PRF)
    adrs.set_key_pair_address(keypair)
    return adrs
