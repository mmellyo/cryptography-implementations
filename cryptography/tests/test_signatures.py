"""TP5 - Tests des signatures numeriques."""
import pytest

pytest.importorskip("cryptography")
pytest.importorskip("sympy")

from cryptography.hazmat.primitives.asymmetric import ec

from signatures.elgamal_sig import (
    signer as elgamal_signer,
    verifier as elgamal_verifier,
)
from signatures.rsa_signature import (
    generer_cles,
    signer_pkcs1v15,
    signer_pss,
    verifier_pkcs1v15,
    verifier_pss,
)


class TestRSAPKCS1v15:
    @pytest.fixture(scope="class")
    def cles(self):
        return generer_cles(2048)

    def test_signer_verifier(self, cles):
        priv, pub = cles
        msg = b"Document a signer"
        sig = signer_pkcs1v15(priv, msg)
        assert verifier_pkcs1v15(pub, msg, sig)

    def test_deterministe(self, cles):
        priv, _ = cles
        msg = b"Test PKCS1 v1.5"
        assert signer_pkcs1v15(priv, msg) == signer_pkcs1v15(priv, msg)

    def test_message_modifie_rejete(self, cles):
        priv, pub = cles
        sig = signer_pkcs1v15(priv, b"original")
        assert not verifier_pkcs1v15(pub, b"modifie", sig)

    def test_signature_alteree_rejete(self, cles):
        priv, pub = cles
        sig = bytearray(signer_pkcs1v15(priv, b"texte"))
        sig[0] ^= 1
        assert not verifier_pkcs1v15(pub, b"texte", bytes(sig))


class TestRSAPSS:
    @pytest.fixture(scope="class")
    def cles(self):
        return generer_cles(2048)

    def test_signer_verifier(self, cles):
        priv, pub = cles
        msg = b"PSS test"
        assert verifier_pss(pub, msg, signer_pss(priv, msg))

    def test_probabiliste(self, cles):
        priv, _ = cles
        msg = b"Test PSS"
        assert signer_pss(priv, msg) != signer_pss(priv, msg)

    def test_message_modifie_rejete(self, cles):
        priv, pub = cles
        sig = signer_pss(priv, b"original")
        assert not verifier_pss(pub, b"modifie", sig)


class TestElGamalSignature:
    @pytest.fixture(scope="class")
    def cles(self):
        # Mersenne 2^31-1 + generateur 7. Pas de securite mais arithmetique
        # exacte ; evite primitive_root sur 512+ bits (lent en sympy).
        import secrets
        p, g = 2147483647, 7
        x = secrets.randbelow(p - 3) + 2
        y = pow(g, x, p)
        return p, g, x, y

    def test_signer_verifier(self, cles):
        p, g, x, y = cles
        msg = b"ElGamal signature test"
        r, s = elgamal_signer(p, g, x, msg)
        assert elgamal_verifier(p, g, y, msg, r, s)

    def test_message_modifie_rejete(self, cles):
        p, g, x, y = cles
        r, s = elgamal_signer(p, g, x, b"original")
        assert not elgamal_verifier(p, g, y, b"modifie", r, s)

    def test_non_deterministe(self, cles):
        p, g, x, _ = cles
        msg = b"non-determinisme"
        sig1 = elgamal_signer(p, g, x, msg)
        sig2 = elgamal_signer(p, g, x, msg)
        assert sig1 != sig2

    def test_r_hors_intervalle_rejete(self, cles):
        p, g, _, y = cles
        assert not elgamal_verifier(p, g, y, b"x", 0, 1)
        assert not elgamal_verifier(p, g, y, b"x", p, 1)

    def test_s_hors_intervalle_rejete(self, cles):
        p, g, _, y = cles
        assert not elgamal_verifier(p, g, y, b"x", 1, 0)
        assert not elgamal_verifier(p, g, y, b"x", 1, p - 1)


class TestECDSA:
    def test_round_trip_p256(self):
        from cryptography.hazmat.primitives import hashes
        from cryptography.exceptions import InvalidSignature
        priv = ec.generate_private_key(ec.SECP256R1())
        pub = priv.public_key()
        msg = b"ECDSA P-256 round trip"
        sig = priv.sign(msg, ec.ECDSA(hashes.SHA256()))
        pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        with pytest.raises(InvalidSignature):
            pub.verify(sig, b"autre", ec.ECDSA(hashes.SHA256()))
