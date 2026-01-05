"""
ML-KEM Test Suite (Python)
Tests for ML-KEM-512, ML-KEM-768, and ML-KEM-1024
"""

import pytest
from mlkem import (
    MLKEM512, MLKEM768, MLKEM1024,
    MLKEM512_PARAMS, MLKEM768_PARAMS, MLKEM1024_PARAMS,
)


class TestMLKEM512:
    """Tests for ML-KEM-512"""

    def test_keygen_sizes(self):
        """Test that keygen produces correct key sizes"""
        kem = MLKEM512()
        ek, dk = kem.keygen()
        assert len(ek) == MLKEM512_PARAMS.ek_size
        assert len(dk) == MLKEM512_PARAMS.dk_size

    def test_keygen_deterministic(self):
        """Test that keygen with seed is deterministic"""
        kem = MLKEM512()
        seed = b'\x42' * 64
        ek1, dk1 = kem.keygen(seed)
        ek2, dk2 = kem.keygen(seed)
        assert ek1 == ek2
        assert dk1 == dk2

    def test_keygen_random(self):
        """Test that keygen without seed produces random keys"""
        kem = MLKEM512()
        ek1, dk1 = kem.keygen()
        ek2, dk2 = kem.keygen()
        assert ek1 != ek2
        assert dk1 != dk2

    def test_encaps_decaps_roundtrip(self):
        """Test basic encaps/decaps round-trip"""
        kem = MLKEM512()
        ek, dk = kem.keygen()
        K1, c = kem.encaps(ek)
        K2 = kem.decaps(dk, c)
        assert K1 == K2
        assert len(K1) == MLKEM512_PARAMS.ss_size

    def test_ciphertext_size(self):
        """Test that ciphertext has correct size"""
        kem = MLKEM512()
        ek, dk = kem.keygen()
        K, c = kem.encaps(ek)
        assert len(c) == MLKEM512_PARAMS.ct_size

    def test_encaps_deterministic(self):
        """Test that encaps with randomness is deterministic"""
        kem = MLKEM512()
        ek, dk = kem.keygen()
        rand = b'\xAB' * 32
        K1, c1 = kem.encaps(ek, rand)
        K2, c2 = kem.encaps(ek, rand)
        assert K1 == K2
        assert c1 == c2

    def test_encaps_random(self):
        """Test that encaps without randomness is random"""
        kem = MLKEM512()
        ek, dk = kem.keygen()
        K1, c1 = kem.encaps(ek)
        K2, c2 = kem.encaps(ek)
        assert K1 != K2
        assert c1 != c2

    def test_implicit_rejection_wrong_dk(self):
        """Test that wrong dk produces different shared secret"""
        kem = MLKEM512()
        ek1, dk1 = kem.keygen()
        ek2, dk2 = kem.keygen()
        K_expected, c = kem.encaps(ek1)
        K_wrong = kem.decaps(dk2, c)
        assert len(K_wrong) == MLKEM512_PARAMS.ss_size
        assert K_wrong != K_expected

    def test_implicit_rejection_tampered_ct(self):
        """Test that tampered ciphertext produces different shared secret"""
        kem = MLKEM512()
        ek, dk = kem.keygen()
        K_expected, c = kem.encaps(ek)
        c_tampered = bytes([c[0] ^ 0xFF]) + c[1:]
        K_wrong = kem.decaps(dk, c_tampered)
        assert len(K_wrong) == MLKEM512_PARAMS.ss_size
        assert K_wrong != K_expected

    def test_params(self):
        """Test parameter access"""
        kem = MLKEM512()
        assert kem.params.name == "ML-KEM-512"
        assert kem.params.k == 2
        assert kem.params.ek_size == 800
        assert kem.params.dk_size == 1632
        assert kem.params.ct_size == 768
        assert kem.params.ss_size == 32


class TestMLKEM768:
    """Tests for ML-KEM-768"""

    def test_keygen_sizes(self):
        """Test that keygen produces correct key sizes"""
        kem = MLKEM768()
        ek, dk = kem.keygen()
        assert len(ek) == MLKEM768_PARAMS.ek_size
        assert len(dk) == MLKEM768_PARAMS.dk_size

    def test_encaps_decaps_roundtrip(self):
        """Test basic encaps/decaps round-trip"""
        kem = MLKEM768()
        ek, dk = kem.keygen()
        K1, c = kem.encaps(ek)
        K2 = kem.decaps(dk, c)
        assert K1 == K2
        assert len(K1) == MLKEM768_PARAMS.ss_size

    def test_ciphertext_size(self):
        """Test that ciphertext has correct size"""
        kem = MLKEM768()
        ek, dk = kem.keygen()
        K, c = kem.encaps(ek)
        assert len(c) == MLKEM768_PARAMS.ct_size

    def test_params(self):
        """Test parameter access"""
        kem = MLKEM768()
        assert kem.params.name == "ML-KEM-768"
        assert kem.params.k == 3
        assert kem.params.ek_size == 1184
        assert kem.params.dk_size == 2400
        assert kem.params.ct_size == 1088
        assert kem.params.ss_size == 32


class TestMLKEM1024:
    """Tests for ML-KEM-1024"""

    def test_keygen_sizes(self):
        """Test that keygen produces correct key sizes"""
        kem = MLKEM1024()
        ek, dk = kem.keygen()
        assert len(ek) == MLKEM1024_PARAMS.ek_size
        assert len(dk) == MLKEM1024_PARAMS.dk_size

    def test_encaps_decaps_roundtrip(self):
        """Test basic encaps/decaps round-trip"""
        kem = MLKEM1024()
        ek, dk = kem.keygen()
        K1, c = kem.encaps(ek)
        K2 = kem.decaps(dk, c)
        assert K1 == K2
        assert len(K1) == MLKEM1024_PARAMS.ss_size

    def test_ciphertext_size(self):
        """Test that ciphertext has correct size"""
        kem = MLKEM1024()
        ek, dk = kem.keygen()
        K, c = kem.encaps(ek)
        assert len(c) == MLKEM1024_PARAMS.ct_size

    def test_params(self):
        """Test parameter access"""
        kem = MLKEM1024()
        assert kem.params.name == "ML-KEM-1024"
        assert kem.params.k == 4
        assert kem.params.ek_size == 1568
        assert kem.params.dk_size == 3168
        assert kem.params.ct_size == 1568
        assert kem.params.ss_size == 32


class TestInputValidation:
    """Test input validation"""

    def test_keygen_wrong_seed_size(self):
        """Test that keygen rejects wrong seed size"""
        kem = MLKEM768()
        with pytest.raises(ValueError):
            kem.keygen(b'\x00' * 32)  # Should be 64 bytes

    def test_encaps_wrong_ek_size(self):
        """Test that encaps rejects wrong encapsulation key size"""
        kem = MLKEM768()
        with pytest.raises(ValueError):
            kem.encaps(b'\x00' * 100)

    def test_decaps_wrong_dk_size(self):
        """Test that decaps rejects wrong decapsulation key size"""
        kem = MLKEM768()
        ek, dk = kem.keygen()
        K, c = kem.encaps(ek)
        with pytest.raises(ValueError):
            kem.decaps(b'\x00' * 100, c)

    def test_decaps_wrong_ct_size(self):
        """Test that decaps rejects wrong ciphertext size"""
        kem = MLKEM768()
        ek, dk = kem.keygen()
        with pytest.raises(ValueError):
            kem.decaps(dk, b'\x00' * 100)
