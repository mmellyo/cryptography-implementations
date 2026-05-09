"""ElGamal digital signature scheme (DLP-based)."""
import hashlib
import secrets
from math import gcd

from sympy import nextprime, primitive_root

MIN_BITS = 512


def _eea(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x, y = _eea(b % a, a)
    return g, y - (b // a) * x, x


def inv_mod(a: int, m: int) -> int:
    g, x, _ = _eea(a % m, m)
    if g != 1:
        raise ValueError("Pas d'inverse")
    return x % m


def gen_cles(bits: int = MIN_BITS):
    if bits < 64:
        raise ValueError("ElGamal-sig : taille minimale 64 bits (demo) / 512 en production")
    seed = secrets.randbits(bits) | (1 << (bits - 1)) | 1
    p = int(nextprime(seed))
    g = int(primitive_root(p))
    x = secrets.randbelow(p - 3) + 2
    return p, g, x, pow(g, x, p)


def hacher(msg: bytes, p: int) -> int:
    return int(hashlib.sha256(msg).hexdigest(), 16) % (p - 1)


def signer(p: int, g: int, x: int, msg: bytes):
    h = hacher(msg, p)
    while True:
        k = secrets.randbelow(p - 2) + 1
        if gcd(k, p - 1) == 1:
            break
    r = pow(g, k, p)
    s = ((h - x * r) * inv_mod(k, p - 1)) % (p - 1)
    return r, s


def verifier(p: int, g: int, y: int, msg: bytes, r: int, s: int) -> bool:
    if not (0 < r < p):
        return False
    if not (0 < s < p - 1):
        return False
    return (pow(y, r, p) * pow(r, s, p)) % p == pow(g, hacher(msg, p), p)


def demo():
    print("\n" + "=" * 50)
    print("  ElGamal signature")
    print("=" * 50)
    # Petit p pour la demo (sympy.primitive_root est lent au-dela de 64 bits).
    p, g = 2147483647, 7
    x = secrets.randbelow(p - 3) + 2
    y = pow(g, x, p)
    print(f"\n  Parametres demo : p = {p} ({p.bit_length()} bits), g = {g}")

    msg = b"Document a signer en ElGamal"
    r, s = signer(p, g, x, msg)
    print(f"  Signature : (r={r}, s={s})")
    print(f"  Verif     : {verifier(p, g, y, msg, r, s)}")
    print(f"  Tamper    : {verifier(p, g, y, b'autre message', r, s)}")
    r2, s2 = signer(p, g, x, msg)
    print(f"  Non-deterministe : {(r, s) != (r2, s2)}")


if __name__ == "__main__":
    demo()
