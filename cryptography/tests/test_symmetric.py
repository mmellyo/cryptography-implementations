"""TP2 - Tests des chiffrements symetriques."""
import pytest

Crypto_AES = pytest.importorskip("Crypto.Cipher.AES")
Crypto_DES = pytest.importorskip("Crypto.Cipher.DES")
Padding = pytest.importorskip("Crypto.Util.Padding")

from symmetric.block.aes import chiffrer_cbc, chiffrer_ctr, dechiffrer_cbc
from symmetric.block.aes_finalists import RC6, Serpent, valider_rc6, valider_serpent
from symmetric.block.des import (
    chiffrer_3des_cbc,
    chiffrer_des_cbc,
    dechiffrer_des_cbc,
)
from symmetric.stream.rc4 import ksa, prga, rc4


class TestRC4:
    def test_vecteur_wikipedia_wiki_pedia(self):
        # RC4("Wiki", "pedia") = 1021BF0420
        assert rc4(b"Wiki", b"pedia").hex() == "1021bf0420"

    def test_vecteur_wikipedia_secret_attack(self):
        # RC4("Secret", "Attack at dawn")
        attendu = "45a01f645fc35b383552544b9bf5"
        assert rc4(b"Secret", b"Attack at dawn").hex() == attendu

    def test_round_trip(self):
        msg = b"Donnees a chiffrer puis dechiffrer"
        cle = b"unecledetest"
        assert rc4(cle, rc4(cle, msg)) == msg

    def test_ksa_permutation_valide(self):
        S = ksa(b"clef")
        assert sorted(S) == list(range(256))

    def test_prga_deterministe(self):
        S = ksa(b"clef")
        a = prga(S, 32)
        b = prga(ksa(b"clef"), 32)
        assert a == b

    def test_rejette_cle_vide(self):
        with pytest.raises(ValueError):
            ksa(b"")


class TestDES:
    def test_round_trip(self):
        from Crypto.Random import get_random_bytes
        msg = b"Donnees TP2 - DES en mode CBC + PKCS7"
        cle, iv = get_random_bytes(8), get_random_bytes(8)
        chiffre = chiffrer_des_cbc(msg, cle, iv)
        assert dechiffrer_des_cbc(chiffre, cle, iv) == msg

    def test_3des_chiffre_correctement_en_cbc(self):
        from Crypto.Cipher import DES3
        from Crypto.Random import get_random_bytes
        from Crypto.Util.Padding import pad, unpad
        msg = b"Hello 3DES"
        cle = DES3.adjust_key_parity(get_random_bytes(24))
        iv = get_random_bytes(8)
        chiffre = chiffrer_3des_cbc(msg, cle, iv)
        clair = unpad(DES3.new(cle, DES3.MODE_CBC, iv=iv).decrypt(chiffre), 8)
        assert clair == msg

    def test_ecb_revele_motifs_repetitifs(self):
        from Crypto.Cipher import DES
        from Crypto.Random import get_random_bytes
        from Crypto.Util.Padding import pad
        msg = b"A" * 64 + b"B" * 64
        chiffre = DES.new(get_random_bytes(8), DES.MODE_ECB).encrypt(pad(msg, 8))
        blocs = [chiffre[i:i + 8] for i in range(0, len(chiffre), 8)]
        assert len(set(blocs)) < len(blocs)


class TestAES:
    def test_round_trip_cbc(self):
        from Crypto.Random import get_random_bytes
        msg = b"Donnees AES en CBC"
        cle, iv = get_random_bytes(32), get_random_bytes(16)
        assert dechiffrer_cbc(chiffrer_cbc(msg, cle, iv), cle, iv) == msg

    def test_aes_128_ecb_vecteur_nist(self):
        # NIST FIPS 197 Annexe C.1 - AES-128 known answer
        from Crypto.Cipher import AES
        cle = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        clair = bytes.fromhex("00112233445566778899aabbccddeeff")
        attendu = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        assert AES.new(cle, AES.MODE_ECB).encrypt(clair) == attendu

    def test_aes_128_cbc_vecteur_nist(self):
        # NIST SP 800-38A F.2.1
        from Crypto.Cipher import AES
        cle = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        clair = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
        attendu = bytes.fromhex("7649abac8119b246cee98e9b12e9197d")
        assert AES.new(cle, AES.MODE_CBC, iv=iv).encrypt(clair) == attendu

    def test_ctr_round_trip(self):
        from Crypto.Random import get_random_bytes
        msg = b"AES-CTR comme un chiffrement par flot"
        cle, nonce = get_random_bytes(32), get_random_bytes(8)
        chiffre = chiffrer_ctr(msg, cle, nonce)
        from Crypto.Cipher import AES
        clair = AES.new(cle, AES.MODE_CTR, nonce=nonce).decrypt(chiffre)
        assert clair == msg

    def test_avalanche_cbc_un_bit_iv_modifie_premier_bloc(self):
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        cle = b"\x00" * 32
        iv1 = bytes(16)
        iv2 = bytes([1]) + b"\x00" * 15
        msg = pad(b"Test avalanche AES en CBC", 16)
        c1 = AES.new(cle, AES.MODE_CBC, iv=iv1).encrypt(msg)
        c2 = AES.new(cle, AES.MODE_CBC, iv=iv2).encrypt(msg)
        diff = sum(bin(a ^ b).count("1") for a, b in zip(c1[:16], c2[:16]))
        assert diff > 40  # ~64 bits changes en moyenne


class TestRC6:
    def test_vecteur_officiel_rfc(self):
        assert valider_rc6()

    def test_vecteur_cle_arc_en_ciel(self):
        cle = bytes.fromhex("0123456789abcdef0112233445566778")
        clair = bytes.fromhex("02132435465768798a9bacbdcedfe0f1")
        attendu = bytes.fromhex("524e192f4715c6231f51f6367ea43f18")
        assert RC6(cle).chiffrer_bloc(clair) == attendu

    def test_rejette_cle_invalide(self):
        with pytest.raises(ValueError):
            RC6(b"trop court")

    def test_rejette_bloc_invalide(self):
        cipher = RC6(b"\x00" * 16)
        with pytest.raises(ValueError):
            cipher.chiffrer_bloc(b"\x00" * 8)

    def test_chiffrer_ecb_padding_aligne(self):
        cipher = RC6(b"\x00" * 16)
        chiffre = cipher.chiffrer_ecb(b"Hello, RC6!")
        assert len(chiffre) % 16 == 0
        assert len(chiffre) >= 16


class TestSerpent:
    def test_vecteurs_aes_original(self):
        assert valider_serpent()

    def test_serpent_128_set1(self):
        cle = bytes.fromhex("80000000000000000000000000000000")
        attendu = bytes.fromhex("264e5481eff42a4606abda06c0bfda3d")
        assert Serpent(cle).chiffrer_bloc(bytes(16)) == attendu

    def test_serpent_256_set1(self):
        cle = bytes.fromhex("8000000000000000000000000000000000000000000000000000000000000000")
        attendu = bytes.fromhex("a223aa1288463c0e2be38ebd825616c0")
        assert Serpent(cle).chiffrer_bloc(bytes(16)) == attendu

    def test_serpent_128_set4(self):
        cle = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        clair = bytes.fromhex("00112233445566778899aabbccddeeff")
        attendu = bytes.fromhex("563e2cf8740a27c164804560391e9b27")
        assert Serpent(cle).chiffrer_bloc(clair) == attendu

    def test_rejette_cle_vide(self):
        with pytest.raises(ValueError):
            Serpent(b"")

    def test_rejette_cle_trop_longue(self):
        with pytest.raises(ValueError):
            Serpent(b"\x00" * 33)

    def test_rejette_bloc_invalide(self):
        with pytest.raises(ValueError):
            Serpent(b"\x00" * 16).chiffrer_bloc(b"\x00" * 8)
