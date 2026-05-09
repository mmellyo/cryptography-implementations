"""Elliptic-curve cryptography: arithmetic on a small Weierstrass curve, ECDH and ECIES."""
import hashlib
import os

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


class Point:
    def __init__(self, x, y, courbe):
        self.x, self.y, self.courbe = x, y, courbe
        self.inf = x is None

    def __repr__(self):
        return "O" if self.inf else f"({self.x},{self.y})"

    def __eq__(self, autre):
        if not isinstance(autre, Point):
            return NotImplemented
        if self.inf and autre.inf:
            return True
        return not self.inf and not autre.inf and self.x == autre.x and self.y == autre.y

    def __hash__(self):
        return hash((self.x, self.y))


class Courbe:
    def __init__(self, a: int, b: int, p: int):
        if (4 * a ** 3 + 27 * b ** 2) % p == 0:
            raise ValueError("Courbe singuliere : 4a^3 + 27b^2 == 0 mod p")
        self.a, self.b, self.p = a, b, p

    def O(self) -> Point:
        return Point(None, None, self)

    def est_sur(self, P: Point) -> bool:
        if P.inf:
            return True
        return (P.y * P.y) % self.p == (pow(P.x, 3, self.p) + self.a * P.x + self.b) % self.p

    def add(self, P: Point, Q: Point) -> Point:
        if P.inf:
            return Q
        if Q.inf:
            return P
        if P.x == Q.x and (P.y + Q.y) % self.p == 0:
            return self.O()
        if P == Q:
            num, den = (3 * P.x * P.x + self.a) % self.p, (2 * P.y) % self.p
        else:
            num, den = (Q.y - P.y) % self.p, (Q.x - P.x) % self.p
        lam = (num * pow(den, self.p - 2, self.p)) % self.p
        x3 = (lam * lam - P.x - Q.x) % self.p
        return Point(x3, (lam * (P.x - x3) - P.y) % self.p, self)

    def mul(self, k: int, P: Point) -> Point:
        R, T = self.O(), P
        while k > 0:
            if k & 1:
                R = self.add(R, T)
            T = self.add(T, T)
            k >>= 1
        return R

    def points(self):
        pts = [self.O()]
        for x in range(self.p):
            rhs = (pow(x, 3, self.p) + self.a * x + self.b) % self.p
            for y in range(self.p):
                if (y * y) % self.p == rhs:
                    pts.append(Point(x, y, self))
        return pts


def ecdh_p256():
    a = ec.generate_private_key(ec.SECP256R1())
    b = ec.generate_private_key(ec.SECP256R1())
    sa = a.exchange(ec.ECDH(), b.public_key())
    sb = b.exchange(ec.ECDH(), a.public_key())
    return sa, sb


def ecies_chiffrer(message: bytes, pk_destinataire):
    eph = ec.generate_private_key(ec.SECP256R1())
    s = eph.exchange(ec.ECDH(), pk_destinataire)
    cle_aes = hashlib.sha256(s).digest()
    nonce = os.urandom(16)
    chiffreur = Cipher(algorithms.AES(cle_aes), modes.CTR(nonce)).encryptor()
    chiffre = chiffreur.update(message) + chiffreur.finalize()
    return eph.public_key(), nonce, chiffre


def ecies_dechiffrer(sk_destinataire, pk_eph, nonce: bytes, chiffre: bytes) -> bytes:
    s = sk_destinataire.exchange(ec.ECDH(), pk_eph)
    cle_aes = hashlib.sha256(s).digest()
    dechiffreur = Cipher(algorithms.AES(cle_aes), modes.CTR(nonce)).decryptor()
    return dechiffreur.update(chiffre) + dechiffreur.finalize()


def demo():
    print("\n" + "=" * 50)
    print("  Elliptic-curve cryptography")
    print("=" * 50)
    courbe = Courbe(0, 7, 97)
    pts = courbe.points()
    print(f"\n  Courbe y^2 = x^3 + 7 mod 97 : {len(pts)} points")
    P, Q = pts[1], pts[2]
    print(f"  Premiers points : {pts[1:5]}")
    print(f"  P + O == P  : {courbe.add(P, courbe.O()) == P}")
    print(f"  P + Q == Q + P : {courbe.add(P, Q) == courbe.add(Q, P)}")
    print(f"  est_sur (5)P : {courbe.est_sur(courbe.mul(5, P))}")

    print("\n  ECDH P-256 + AES-256 :")
    sa, sb = ecdh_p256()
    cle_aes = hashlib.sha256(sa).digest()
    print(f"  Cles partagees identiques : {sa == sb}")
    print(f"  Cle AES (sha256) : {cle_aes.hex()[:32]}...")

    print("\n  ECIES :")
    sk_bob = ec.generate_private_key(ec.SECP256R1())
    pk_eph, nonce, chiffre = ecies_chiffrer(b"Message a Bob", sk_bob.public_key())
    clair = ecies_dechiffrer(sk_bob, pk_eph, nonce, chiffre)
    print(f"  Round-trip ECIES : {clair == b'Message a Bob'}")


if __name__ == "__main__":
    demo()
