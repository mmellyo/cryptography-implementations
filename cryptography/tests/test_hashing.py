"""TP4 - Tests des fonctions de hachage."""
import hashlib

import pytest

from hashing.md5 import md5
from hashing.sha256 import sha256_manuel


# RFC 1321 - MD5 Test Suite (Section A.5)
MD5_VECTEURS = [
    (b"", "d41d8cd98f00b204e9800998ecf8427e"),
    (b"a", "0cc175b9c0f1b6a831c399e269772661"),
    (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
    (b"message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
    (b"abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"),
    (
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "d174ab98d277d9f5a5611c2c9f419d9f",
    ),
]

# NIST FIPS 180-4 - SHA-256 Short Messages
SHA256_VECTEURS = [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"a", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    ),
    (
        (
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
            b"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
        ),
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
    ),
]


class TestMD5:
    @pytest.mark.parametrize("entree,attendu", MD5_VECTEURS)
    def test_vecteurs_rfc_1321(self, entree, attendu):
        assert md5(entree) == attendu

    def test_md5_aligne_avec_hashlib(self):
        for v, _ in MD5_VECTEURS:
            assert md5(v) == hashlib.md5(v).hexdigest()


class TestSHA256:
    @pytest.mark.parametrize("entree,attendu", SHA256_VECTEURS)
    def test_vecteurs_nist_fips_180_4(self, entree, attendu):
        assert sha256_manuel(entree) == attendu

    def test_aligne_avec_hashlib_sur_messages_aleatoires(self):
        import os
        for _ in range(10):
            n = (os.urandom(1)[0] % 200) + 1
            msg = os.urandom(n)
            assert sha256_manuel(msg) == hashlib.sha256(msg).hexdigest()

    def test_avalanche_un_bit(self):
        msg = b"Avalanche check sur SHA-256."
        modifie = bytearray(msg)
        modifie[0] ^= 1
        h1 = sha256_manuel(msg)
        h2 = sha256_manuel(bytes(modifie))
        diff = sum(bin(int(a, 16) ^ int(b, 16)).count("1") for a, b in zip(h1, h2))
        assert diff > 100  # ~128 bits attendus

    def test_message_long_aligne(self):
        msg = b"A" * 5000
        assert sha256_manuel(msg) == hashlib.sha256(msg).hexdigest()


class TestHMAC:
    """Vecteurs RFC 4231 pour HMAC-SHA256."""

    def _import(self):
        from hashing.hmac import comparer_constant_time, hmac_manuel, hmac_stdlib, verifier
        return hmac_manuel, hmac_stdlib, verifier, comparer_constant_time

    def test_rfc4231_vector1(self):
        hmac_manuel, _, _, _ = self._import()
        cle = b"\x0b" * 20
        msg = b"Hi There"
        attendu = bytes.fromhex(
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        )
        assert hmac_manuel(cle, msg, "sha256") == attendu

    def test_rfc4231_vector2(self):
        hmac_manuel, _, _, _ = self._import()
        cle = b"Jefe"
        msg = b"what do ya want for nothing?"
        attendu = bytes.fromhex(
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        )
        assert hmac_manuel(cle, msg, "sha256") == attendu

    def test_rfc4231_vector3_long_data(self):
        hmac_manuel, _, _, _ = self._import()
        cle = b"\xaa" * 20
        msg = b"\xdd" * 50
        attendu = bytes.fromhex(
            "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"
        )
        assert hmac_manuel(cle, msg, "sha256") == attendu

    def test_rfc4231_vector6_long_key(self):
        hmac_manuel, _, _, _ = self._import()
        cle = b"\xaa" * 131  # > block_size de SHA-256 (64), donc cle hashee
        msg = b"Test Using Larger Than Block-Size Key - Hash Key First"
        attendu = bytes.fromhex(
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        )
        assert hmac_manuel(cle, msg, "sha256") == attendu

    def test_aligne_avec_hashlib_md5_sha256_sha512(self):
        import os
        hmac_manuel, hmac_stdlib, _, _ = self._import()
        for algo in ("md5", "sha256", "sha512"):
            cle = os.urandom(32)
            msg = os.urandom(100)
            assert hmac_manuel(cle, msg, algo) == hmac_stdlib(cle, msg, algo)

    def test_verification_constant_time(self):
        import os
        _, _, verifier, _ = self._import()
        cle = os.urandom(32)
        msg = b"Authentic message"
        from hashing.hmac import authentifier
        _, tag = authentifier(cle, msg)
        assert verifier(cle, msg, tag)
        assert not verifier(cle, msg + b"!", tag)
        assert not verifier(os.urandom(32), msg, tag)

    def test_rejette_algo_inconnu(self):
        hmac_manuel, _, _, _ = self._import()
        with pytest.raises(ValueError):
            hmac_manuel(b"k", b"m", "ripemd160")


class TestSHA512:
    def test_vecteur_chaine_vide(self):
        attendu = (
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        )
        assert hashlib.sha512(b"").hexdigest() == attendu

    def test_vecteur_abc(self):
        attendu = (
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )
        assert hashlib.sha512(b"abc").hexdigest() == attendu
