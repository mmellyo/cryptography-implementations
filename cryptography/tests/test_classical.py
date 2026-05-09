"""TP1 - Tests des chiffrements classiques."""
import pytest

from classical.caesar import (
    attaque_force_brute,
    calculer_ic,
    chiffrer_cesar,
    dechiffrer_cesar,
)
from classical.hill import (
    attaque_clair_connu,
    chiffrer_hill,
    dechiffrer_hill,
    inverse_mat_mod,
    verifier_mat,
)
from classical.otp import chiffrer_otp, dechiffrer_otp, generer_cle
from classical.vigenere import (
    chiffrer_vigenere,
    dechiffrer_vigenere,
    trouver_longueur_cle_ic,
)
from classical.vigenere import test_kasiski as kasiski


class TestCesar:
    def test_chiffrer_vecteur_connu(self):
        assert chiffrer_cesar("ATTACKATDAWN", 3) == "DWWDFNDWGDZQ"

    def test_chiffrer_rot13_involutif(self):
        msg = "HELLOWORLD"
        assert dechiffrer_cesar(chiffrer_cesar(msg, 13), 13) == msg

    def test_chiffrer_ignore_non_alpha(self):
        assert chiffrer_cesar("Hello, World!", 1) == "IFMMPXPSME"

    def test_dechiffrer_inverse_chiffrer(self):
        msg = "BONJOURTOUTLEMONDE"
        for k in range(26):
            assert dechiffrer_cesar(chiffrer_cesar(msg, k), k) == msg

    def test_force_brute_retrouve_cle(self):
        msg = (
            "LECHIFFREDECESARESTUNCHIFFREMENTPARSUBSTITUTIONUTILISEDANSLA"
            "ROMEANTIQUEETILESTRESTERPOURLAPLUPARTDESCOMMUNICATIONSDESARMES"
        )
        chiffre = chiffrer_cesar(msg, 7)
        cle, _, _ = attaque_force_brute(chiffre)
        assert cle == 7

    def test_ic_texte_uniforme(self):
        ic = calculer_ic("ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 10)
        assert 0.03 <= ic <= 0.045


class TestVigenere:
    def test_vecteur_lemon(self):
        assert chiffrer_vigenere("ATTACKATDAWN", "LEMON") == "LXFOPVEFRNHR"

    def test_dechiffrer_inverse(self):
        msg = "MESSAGESECRETPOURALICEETBOB"
        cle = "CRYPTO"
        assert dechiffrer_vigenere(chiffrer_vigenere(msg, cle), cle) == msg

    def test_kasiski_detecte_longueur(self):
        msg = ("LECRYPTAGEDEVIGENEREESTPLUSROBUSTEQUECELUIDECESAR" * 4).upper()
        chiffre = chiffrer_vigenere(msg, "ABC")
        longueur = kasiski(chiffre)
        assert longueur >= 1

    def test_ic_retrouve_longueur_cle(self):
        msg = ("LACRYPTOGRAPHIECONSISTEACHIFFRERETDECHIFFRERDESINFORMATIONS" * 6).upper()
        chiffre = chiffrer_vigenere(msg, "CLEF")
        longueur = trouver_longueur_cle_ic(chiffre, max_len=10)
        assert longueur in (4, 8)


class TestHill:
    @pytest.fixture
    def cle_2x2(self):
        return [[3, 3], [2, 5]]

    @pytest.fixture
    def cle_3x3(self):
        return [[6, 24, 1], [13, 16, 10], [20, 17, 15]]

    def test_chiffrer_3x3_vecteur_wikipedia(self, cle_3x3):
        assert chiffrer_hill("ACT", cle_3x3, 3) == "POH"

    def test_dechiffrer_inverse_chiffrer_2x2(self, cle_2x2):
        msg = "BONJOUR"
        chiffre = chiffrer_hill(msg, cle_2x2, 2)
        clair = dechiffrer_hill(chiffre, cle_2x2, 2)
        assert clair.startswith(msg.upper())

    def test_dechiffrer_inverse_chiffrer_3x3(self, cle_3x3):
        msg = "ATTACKATDAWN"
        chiffre = chiffrer_hill(msg, cle_3x3, 3)
        clair = dechiffrer_hill(chiffre, cle_3x3, 3)
        assert clair.startswith(msg)

    def test_attaque_clair_connu_recupere_cle_equivalente(self, cle_2x2):
        clair = "HELP"
        chiffre = chiffrer_hill(clair, cle_2x2, 2)
        retrouvee = attaque_clair_connu(clair, chiffre, 2)
        autre_clair = "WORLDDATA"
        assert chiffrer_hill(autre_clair, retrouvee, 2) == chiffrer_hill(autre_clair, cle_2x2, 2)

    def test_verifier_mat_rejette_non_inversible(self):
        assert not verifier_mat([[2, 4], [4, 8]], 2)

    def test_inverse_mat_mod_correctness(self, cle_2x2):
        inv = inverse_mat_mod(cle_2x2, 2)
        produit = [[(cle_2x2[i][0] * inv[0][j] + cle_2x2[i][1] * inv[1][j]) % 26
                    for j in range(2)] for i in range(2)]
        assert produit == [[1, 0], [0, 1]]


class TestOTP:
    def test_chiffrer_dechiffrer_round_trip(self):
        msg = b"Message tres tres tres secret"
        cle = generer_cle(len(msg))
        chiffre = chiffrer_otp(msg, cle)
        assert dechiffrer_otp(chiffre, cle) == msg

    def test_double_xor_identite(self):
        msg = b"hello"
        cle = generer_cle(len(msg))
        assert chiffrer_otp(chiffrer_otp(msg, cle), cle) == msg

    def test_rejette_cle_de_longueur_differente(self):
        with pytest.raises(ValueError):
            chiffrer_otp(b"hello", b"ab")

    def test_reutilisation_revele_xor_des_clairs(self):
        m1 = b"AAAAAAAAAA"
        m2 = b"BBBBBBBBBB"
        cle = generer_cle(len(m1))
        c1 = chiffrer_otp(m1, cle)
        c2 = chiffrer_otp(m2, cle)
        xor_chiffres = bytes(a ^ b for a, b in zip(c1, c2))
        xor_clairs = bytes(a ^ b for a, b in zip(m1, m2))
        assert xor_chiffres == xor_clairs

    def test_generer_cle_longueur_negative_rejete(self):
        with pytest.raises(ValueError):
            generer_cle(-1)
