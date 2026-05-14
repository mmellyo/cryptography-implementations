"""ElGamal digital signature scheme (DLP-based)."""
import hashlib
import secrets
from math import gcd

from cryptography.hazmat.primitives.asymmetric import dh

MIN_BITS = 512


def _eea(a: int, b: int):
    # Iterative: recursion depth ~log2(a) blows Python's stack at 2048 bits.
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def inv_mod(a: int, m: int) -> int:
    g, x, _ = _eea(a % m, m)
    if g != 1:
        raise ValueError("Pas d'inverse")
    return x % m


def gen_cles(bits: int = MIN_BITS):
    # 2048+ : RFC 7919 well-known safe primes (instant). 512/1024: fresh via
    # OpenSSL. Safe-prime gen has a fat tail past 2048 bits which used to
    # appear as a "hang" -- the fixed groups remove that variance.
    if bits < MIN_BITS:
        raise ValueError(f"ElGamal-sig : taille minimale {MIN_BITS} bits")
    from asymmetric._rfc7919 import well_known
    pg = well_known(bits)
    if pg is None:
        params = dh.generate_parameters(generator=2, key_size=bits)
        nums = params.parameter_numbers()
        p, g = int(nums.p), int(nums.g)
    else:
        p, g = pg
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
