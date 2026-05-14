"""ElGamal public-key encryption with malleability and size comparison demos."""
import secrets
from math import gcd

from cryptography.hazmat.primitives.asymmetric import dh

from asymmetric._rfc7919 import well_known

MIN_BITS = 512


def generer_cles(bits: int = MIN_BITS):
    # 2048+ : RFC 7919 well-known safe primes (instant, TLS-grade).
    # 512/1024: generate fresh via OpenSSL (fast enough at those sizes, ~0.3s).
    # OpenSSL's safe-prime search has a fat tail at 2048+ (5-60s), which is why
    # we prefer fixed RFC 7919 groups there. Fresh-vs-fixed p doesn't weaken
    # ElGamal: each session still draws fresh x, k.
    if bits < MIN_BITS:
        raise ValueError(f"ElGamal : taille minimale {MIN_BITS} bits")
    pg = well_known(bits)
    if pg is None:
        params = dh.generate_parameters(generator=2, key_size=bits)
        nums = params.parameter_numbers()
        p, g = int(nums.p), int(nums.g)
    else:
        p, g = pg
    x = secrets.randbelow(p - 3) + 2
    y = pow(g, x, p)
    return p, g, x, y


def chiffrer(p: int, g: int, y: int, M: int):
    if not 0 < M < p:
        raise ValueError("M doit verifier 0 < M < p")
    while True:
        k = secrets.randbelow(p - 2) + 1
        if gcd(k, p - 1) == 1:
            break
    c1 = pow(g, k, p)
    c2 = (M * pow(y, k, p)) % p
    return c1, c2


def dechiffrer(p: int, x: int, c1: int, c2: int) -> int:
    return (c2 * pow(c1, p - 1 - x, p)) % p


def comparer_tailles_rsa_2048(M: int = 12345):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa as _rsa
    p, g, _, y = generer_cles(2048)
    c1, c2 = chiffrer(p, g, y, M)
    n = (p.bit_length() + 7) // 8
    elgamal_octets = 2 * n

    pub = _rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    msg = M.to_bytes((M.bit_length() + 7) // 8 or 1, "big")
    rsa_chiffre = pub.encrypt(
        msg,
        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

    print(f"  Message clair : {M}")
    print(f"  RSA-2048 OAEP : {len(rsa_chiffre)} octets")
    print(f"  ElGamal-2048  : {elgamal_octets} octets (paire (c1, c2))")
    print(f"  Ratio         : ElGamal = {elgamal_octets / len(rsa_chiffre):.1f}x RSA")
    return c1, c2


def demo():
    print("\n" + "=" * 50)
    print("  ElGamal")
    print("=" * 50)
    # Petit (p, g) pour la demo (la generation 512+ bits via sympy est lente).
    p, g = 2147483647, 7
    x = secrets.randbelow(p - 3) + 2
    y = pow(g, x, p)
    print(f"\n  Parametres demo : p = {p} ({p.bit_length()} bits), g = {g}")

    M = 12345
    c1, c2 = chiffrer(p, g, y, M)
    print(f"  Round-trip : {dechiffrer(p, x, c1, c2) == M}")

    print(f"\n  Non-determinisme : {chiffrer(p, g, y, 42) != chiffrer(p, g, y, 42)}")

    a1, a2 = chiffrer(p, g, y, 7)
    b1, b2 = chiffrer(p, g, y, 11)
    produit = dechiffrer(p, x, (a1 * b1) % p, (a2 * b2) % p)
    print(f"  Malleabilite : D(E(7)*E(11)) = {produit} (attendu 77)")

    print("\n  Comparaison taille chiffres RSA-2048 vs ElGamal-2048 :")
    comparer_tailles_rsa_2048(M)


if __name__ == "__main__":
    demo()
