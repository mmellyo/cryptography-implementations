"""TP3 - Tests crypto asymetrique."""
import pytest

pytest.importorskip("sympy")
pytest.importorskip("cryptography")

from asymmetric.diffie_hellman import (
    MIN_BITS,
    attaque_mitm,
    cle_privee,
    echange,
    echange_authentifie,
    generer_p_g,
)
from asymmetric.ecc import Courbe, Point
from asymmetric.elgamal import (
    chiffrer as elgamal_chiffrer,
    dechiffrer as elgamal_dechiffrer,
    generer_cles as elgamal_cles,
)
from asymmetric.rsa import chiffrer as rsa_chiffrer
from asymmetric.rsa import dechiffrer as rsa_dechiffrer
from asymmetric.rsa import generer_cles as rsa_cles


class TestDiffieHellman:
    def test_echange_partage_le_meme_secret(self):
        # Petit (p, g) deterministe pour test rapide
        p, g = 2147483647, 7  # 2^31 - 1, premier de Mersenne, g=7 generateur
        _, _, _, _, Ka, Kb = echange(p, g)
        assert Ka == Kb

    def test_attaque_mitm_separe_les_secrets(self):
        p, g = 2147483647, 7
        Ka, Kb, _, _ = attaque_mitm(p, g)
        assert Ka != Kb

    def test_min_bits_enforced(self):
        with pytest.raises(ValueError):
            generer_p_g(256)

    def test_cle_privee_dans_intervalle(self):
        p = 2147483647
        for _ in range(20):
            x = cle_privee(p)
            assert 2 <= x <= p - 2

    @pytest.mark.slow
    def test_generer_p_g_taille_minimale(self):
        p, _ = generer_p_g(MIN_BITS)
        assert p.bit_length() >= MIN_BITS

    def test_echange_authentifie_succes(self):
        p, g = 2147483647, 7
        ok, K = echange_authentifie(p, g)
        assert ok
        assert K is not None and 0 < K < p


class TestRSA:
    def test_round_trip_oaep(self):
        priv, pub = rsa_cles(1024)
        msg = b"Message court pour RSA-OAEP"
        chiffre = rsa_chiffrer(pub, msg)
        assert rsa_dechiffrer(priv, chiffre) == msg

    def test_oaep_non_deterministe(self):
        _, pub = rsa_cles(1024)
        msg = b"Test determinisme"
        assert rsa_chiffrer(pub, msg) != rsa_chiffrer(pub, msg)

    def test_taille_invalide_rejete(self):
        with pytest.raises(ValueError):
            rsa_cles(123)


class TestElGamal:
    @pytest.fixture(scope="class")
    def cles(self):
        # Mersenne 2^31-1 (premier), generateur 7. Evite la primitive_root
        # de sympy qui est lente sur 512+ bits.
        import secrets
        p, g = 2147483647, 7
        x = secrets.randbelow(p - 3) + 2
        y = pow(g, x, p)
        return p, g, x, y

    def test_round_trip(self, cles):
        p, g, x, y = cles
        M = 12345
        c1, c2 = elgamal_chiffrer(p, g, y, M)
        assert elgamal_dechiffrer(p, x, c1, c2) == M

    def test_non_deterministe(self, cles):
        p, g, _, y = cles
        a = elgamal_chiffrer(p, g, y, 42)
        b = elgamal_chiffrer(p, g, y, 42)
        assert a != b

    def test_malleabilite_homomorphie_multiplicative(self, cles):
        p, g, x, y = cles
        c1, c2 = elgamal_chiffrer(p, g, y, 7)
        d1, d2 = elgamal_chiffrer(p, g, y, 11)
        produit = elgamal_dechiffrer(p, x, (c1 * d1) % p, (c2 * d2) % p)
        assert produit == 77

    def test_M_invalide_rejete(self, cles):
        p, g, _, y = cles
        with pytest.raises(ValueError):
            elgamal_chiffrer(p, g, y, 0)
        with pytest.raises(ValueError):
            elgamal_chiffrer(p, g, y, p)

    @pytest.mark.slow
    def test_gen_cles_taille_minimale(self):
        p, _, _, _ = elgamal_cles(MIN_BITS)
        assert p.bit_length() >= MIN_BITS


class TestECC:
    @pytest.fixture
    def courbe(self):
        return Courbe(0, 7, 97)  # y^2 = x^3 + 7 mod 97

    def test_courbe_singuliere_rejetee(self):
        # 4*0 + 27*0 = 0 mod p -> singuliere
        with pytest.raises(ValueError):
            Courbe(0, 0, 97)

    def test_O_neutre(self, courbe):
        pts = courbe.points()
        P = pts[1]
        assert courbe.add(P, courbe.O()) == P
        assert courbe.add(courbe.O(), P) == P

    def test_addition_commutative(self, courbe):
        pts = courbe.points()
        P, Q = pts[1], pts[2]
        assert courbe.add(P, Q) == courbe.add(Q, P)

    def test_addition_oppose_donne_O(self, courbe):
        pts = courbe.points()
        P = pts[1]
        Q = Point(P.x, (-P.y) % courbe.p, courbe)
        assert courbe.add(P, Q).inf

    def test_est_sur_courbe(self, courbe):
        for P in courbe.points():
            assert courbe.est_sur(P)

    def test_point_hors_courbe_detecte(self, courbe):
        faux = Point(1, 1, courbe)
        assert not courbe.est_sur(faux)

    def test_multiplication_scalaire_associativite(self, courbe):
        pts = courbe.points()
        P = pts[1]
        # (2+3)P == 2P + 3P
        gauche = courbe.mul(5, P)
        droite = courbe.add(courbe.mul(2, P), courbe.mul(3, P))
        assert gauche == droite

    def test_multiplication_par_zero(self, courbe):
        pts = courbe.points()
        assert courbe.mul(0, pts[1]).inf
