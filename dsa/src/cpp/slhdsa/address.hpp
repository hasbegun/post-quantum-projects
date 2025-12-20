/**
 * SLH-DSA Address Structure (FIPS 205 Section 4.2)
 *
 * The ADRS structure is used for domain separation in hash function calls.
 * It is a 32-byte array with different fields depending on the address type.
 */

#ifndef SLHDSA_ADDRESS_HPP
#define SLHDSA_ADDRESS_HPP

#include <cstdint>
#include <cstddef>
#include <array>
#include <cstring>
#include <vector>

namespace slhdsa {

/**
 * Address types as defined in FIPS 205 Table 2
 */
enum class AddressType : uint32_t {
    WOTS_HASH = 0,
    WOTS_PK = 1,
    TREE = 2,
    FORS_TREE = 3,
    FORS_ROOTS = 4,
    WOTS_PRF = 5,
    FORS_PRF = 6
};

/**
 * ADRS - 32-byte address structure for domain separation
 *
 * Layout per FIPS 205 Section 4.2 Table 1 (all fields are big-endian):
 * Bytes 0-3:   Layer address (4 bytes)
 * Bytes 4-15:  Tree address (12 bytes)
 * Bytes 16-19: Type (4 bytes)
 * Bytes 20-23: Key pair address / unused (4 bytes)
 * Bytes 24-27: Chain address / Tree height (4 bytes)
 * Bytes 28-31: Hash address / Tree index (4 bytes)
 */
class ADRS {
public:
    static constexpr size_t SIZE = 32;

    ADRS() noexcept {
        data_.fill(0);
    }

    // Get raw bytes
    [[nodiscard]] const std::array<uint8_t, SIZE>& bytes() const noexcept {
        return data_;
    }

    [[nodiscard]] std::array<uint8_t, SIZE>& bytes() noexcept {
        return data_;
    }

    // Return as bytes vector
    [[nodiscard]] std::vector<uint8_t> to_bytes() const {
        return std::vector<uint8_t>(data_.begin(), data_.end());
    }

    // Copy constructor and assignment
    ADRS(const ADRS&) = default;
    ADRS& operator=(const ADRS&) = default;

    // Create a copy
    [[nodiscard]] ADRS copy() const {
        return ADRS(*this);
    }

    // Layer address (bytes 0-3)
    void set_layer_address(uint32_t layer) noexcept {
        set_u32(0, layer);
    }

    [[nodiscard]] uint32_t get_layer_address() const noexcept {
        return get_u32(0);
    }

    // Tree address (bytes 4-15, 96 bits stored in 12 bytes)
    // FIPS 205: tree address is 12 bytes, but we only use lower 64 bits
    void set_tree_address(uint64_t tree) noexcept {
        // Clear upper 4 bytes (4-7) and set lower 8 bytes (8-15)
        set_u32(4, 0);  // Upper 32 bits always 0
        set_u64(8, tree);  // Lower 64 bits of tree address
    }

    [[nodiscard]] uint64_t get_tree_address() const noexcept {
        return get_u64(8);
    }

    // Type (bytes 16-19)
    void set_type(AddressType type) noexcept {
        set_u32(16, static_cast<uint32_t>(type));
        // When type changes, clear type-specific fields (bytes 20-31)
        std::memset(&data_[20], 0, 12);
    }

    [[nodiscard]] AddressType get_type() const noexcept {
        return static_cast<AddressType>(get_u32(16));
    }

    // Key pair address (bytes 20-23) - for WOTS and FORS types
    void set_key_pair_address(uint32_t kp) noexcept {
        set_u32(20, kp);
    }

    [[nodiscard]] uint32_t get_key_pair_address() const noexcept {
        return get_u32(20);
    }

    // Chain address (bytes 24-27) - for WOTS types
    void set_chain_address(uint32_t chain) noexcept {
        set_u32(24, chain);
    }

    [[nodiscard]] uint32_t get_chain_address() const noexcept {
        return get_u32(24);
    }

    // Hash address (bytes 28-31) - for WOTS_HASH
    void set_hash_address(uint32_t hash) noexcept {
        set_u32(28, hash);
    }

    [[nodiscard]] uint32_t get_hash_address() const noexcept {
        return get_u32(28);
    }

    // Tree height (bytes 24-27) - for TREE and FORS_TREE types
    void set_tree_height(uint32_t height) noexcept {
        set_u32(24, height);
    }

    [[nodiscard]] uint32_t get_tree_height() const noexcept {
        return get_u32(24);
    }

    // Tree index (bytes 28-31) - for TREE and FORS types
    void set_tree_index(uint32_t index) noexcept {
        set_u32(28, index);
    }

    [[nodiscard]] uint32_t get_tree_index() const noexcept {
        return get_u32(28);
    }

    /**
     * Get 22-byte compressed address for SHA2 variants.
     *
     * Layout (FIPS 205 Section 11.2.1):
     *   Byte 0:      Layer address LSB (ADRS[3])
     *   Bytes 1-8:   Tree address lower 8 bytes (ADRS[8:16])
     *   Byte 9:      Type LSB (ADRS[19])
     *   Bytes 10-21: Type-specific fields (ADRS[20:32])
     */
    [[nodiscard]] std::array<uint8_t, 22> get_compressed_adrs() const noexcept {
        std::array<uint8_t, 22> compressed{};
        // Layer address LSB (1 byte from offset 3)
        compressed[0] = data_[3];
        // Tree address (8 bytes from offset 8-15)
        std::memcpy(&compressed[1], &data_[8], 8);
        // Type LSB (1 byte from offset 19)
        compressed[9] = data_[19];
        // Type-specific fields (12 bytes from offset 20-31)
        std::memcpy(&compressed[10], &data_[20], 12);
        return compressed;
    }

private:
    std::array<uint8_t, SIZE> data_;

    // Helper: set 32-bit big-endian value
    void set_u32(size_t offset, uint32_t value) noexcept {
        data_[offset + 0] = static_cast<uint8_t>(value >> 24);
        data_[offset + 1] = static_cast<uint8_t>(value >> 16);
        data_[offset + 2] = static_cast<uint8_t>(value >> 8);
        data_[offset + 3] = static_cast<uint8_t>(value);
    }

    // Helper: get 32-bit big-endian value
    [[nodiscard]] uint32_t get_u32(size_t offset) const noexcept {
        return (static_cast<uint32_t>(data_[offset + 0]) << 24) |
               (static_cast<uint32_t>(data_[offset + 1]) << 16) |
               (static_cast<uint32_t>(data_[offset + 2]) << 8) |
               (static_cast<uint32_t>(data_[offset + 3]));
    }

    // Helper: set 64-bit big-endian value
    void set_u64(size_t offset, uint64_t value) noexcept {
        data_[offset + 0] = static_cast<uint8_t>(value >> 56);
        data_[offset + 1] = static_cast<uint8_t>(value >> 48);
        data_[offset + 2] = static_cast<uint8_t>(value >> 40);
        data_[offset + 3] = static_cast<uint8_t>(value >> 32);
        data_[offset + 4] = static_cast<uint8_t>(value >> 24);
        data_[offset + 5] = static_cast<uint8_t>(value >> 16);
        data_[offset + 6] = static_cast<uint8_t>(value >> 8);
        data_[offset + 7] = static_cast<uint8_t>(value);
    }

    // Helper: get 64-bit big-endian value
    [[nodiscard]] uint64_t get_u64(size_t offset) const noexcept {
        return (static_cast<uint64_t>(data_[offset + 0]) << 56) |
               (static_cast<uint64_t>(data_[offset + 1]) << 48) |
               (static_cast<uint64_t>(data_[offset + 2]) << 40) |
               (static_cast<uint64_t>(data_[offset + 3]) << 32) |
               (static_cast<uint64_t>(data_[offset + 4]) << 24) |
               (static_cast<uint64_t>(data_[offset + 5]) << 16) |
               (static_cast<uint64_t>(data_[offset + 6]) << 8) |
               (static_cast<uint64_t>(data_[offset + 7]));
    }
};

// Factory functions for creating specific address types

inline ADRS make_wots_hash_adrs(uint32_t layer, uint64_t tree, uint32_t keypair) {
    ADRS adrs;
    adrs.set_layer_address(layer);
    adrs.set_tree_address(tree);
    adrs.set_type(AddressType::WOTS_HASH);
    adrs.set_key_pair_address(keypair);
    return adrs;
}

inline ADRS make_wots_pk_adrs(uint32_t layer, uint64_t tree, uint32_t keypair) {
    ADRS adrs;
    adrs.set_layer_address(layer);
    adrs.set_tree_address(tree);
    adrs.set_type(AddressType::WOTS_PK);
    adrs.set_key_pair_address(keypair);
    return adrs;
}

inline ADRS make_tree_adrs(uint32_t layer, uint64_t tree) {
    ADRS adrs;
    adrs.set_layer_address(layer);
    adrs.set_tree_address(tree);
    adrs.set_type(AddressType::TREE);
    return adrs;
}

inline ADRS make_fors_tree_adrs(uint64_t tree, uint32_t keypair) {
    ADRS adrs;
    adrs.set_layer_address(0);
    adrs.set_tree_address(tree);
    adrs.set_type(AddressType::FORS_TREE);
    adrs.set_key_pair_address(keypair);
    return adrs;
}

inline ADRS make_fors_roots_adrs(uint64_t tree, uint32_t keypair) {
    ADRS adrs;
    adrs.set_layer_address(0);
    adrs.set_tree_address(tree);
    adrs.set_type(AddressType::FORS_ROOTS);
    adrs.set_key_pair_address(keypair);
    return adrs;
}

inline ADRS make_wots_prf_adrs(uint32_t layer, uint64_t tree, uint32_t keypair) {
    ADRS adrs;
    adrs.set_layer_address(layer);
    adrs.set_tree_address(tree);
    adrs.set_type(AddressType::WOTS_PRF);
    adrs.set_key_pair_address(keypair);
    return adrs;
}

inline ADRS make_fors_prf_adrs(uint64_t tree, uint32_t keypair) {
    ADRS adrs;
    adrs.set_layer_address(0);
    adrs.set_tree_address(tree);
    adrs.set_type(AddressType::FORS_PRF);
    adrs.set_key_pair_address(keypair);
    return adrs;
}

} // namespace slhdsa

#endif // SLHDSA_ADDRESS_HPP
