"""RC4 stream cipher with WEP/FMS attack and 2nd-byte bias demonstration."""
import os
from collections import Counter


def ksa(cle: bytes) -> list:
    if not cle:
        raise ValueError("RC4 : cle vide interdite")
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + cle[i % len(cle)]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def prga(S: list, n: int) -> list:
    S = list(S)
    i = j = 0
    flux = []
    for _ in range(n):
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        flux.append(S[(S[i] + S[j]) % 256])
    return flux


def chiffrer(cle: bytes, donnees: bytes) -> bytes:
    return bytes(d ^ k for d, k in zip(donnees, prga(ksa(cle), len(donnees))))


# Compat ancien nom.
rc4 = chiffrer


def vulnerabilite_wep(cle_wep: bytes = b"SECRET", n_iv: int = 8):
    print(f"  Cle WEP (cachee) : {cle_wep!r}")
    print(f"  IV          | premier octet keystream")
    for v in range(n_iv):
        iv = bytes([v, 0xFF, v + 3])
        premier = prga(ksa(iv + cle_wep), 1)[0]
        print(f"  {iv.hex():12s}|     0x{premier:02x}")
    print("  -> attaque FMS : IV concatenes a la cle revelent l'octet n+3 de la cle.")


def biais_statistiques(n: int = 10000) -> Counter:
    cpt = Counter()
    for _ in range(n):
        cpt[prga(ksa(os.urandom(16)), 3)[1]] += 1
    return cpt


def demo():
    print("\n" + "=" * 50)
    print("  RC4")
    print("=" * 50)
    cle = b"unecledetest"
    msg = b"Donnees confidentielles a chiffrer."
    chiffre = chiffrer(cle, msg)
    print(f"\n  Chiffre (hex) : {chiffre.hex()}")
    print(f"  Round-trip    : {chiffrer(cle, chiffre) == msg}")

    print("\n  Vulnerabilite WEP (FMS) :")
    vulnerabilite_wep()

    print("\n  Biais statistiques (10000 keystreams) :")
    cpt = biais_statistiques(10000)
    attendu = 10000 / 256
    print(f"  2e octet = 0  : {cpt[0]:4d} (attendu {attendu:.0f}, ratio {cpt[0] / attendu:.2f}x)")
    plus_eleve = max(cpt.items(), key=lambda x: x[1])
    print(f"  octet le plus frequent : 0x{plus_eleve[0]:02x} ({plus_eleve[1]} occurrences)")


if __name__ == "__main__":
    demo()
