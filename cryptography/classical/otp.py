"""One-Time Pad (Vernam) with key-reuse and crib-dragging demonstrations."""
import os
import string


def generer_cle(n: int) -> bytes:
    if n < 0:
        raise ValueError("OTP : longueur negative interdite")
    return os.urandom(n)


def chiffrer(msg: bytes, cle: bytes) -> bytes:
    if len(cle) != len(msg):
        raise ValueError("OTP : la cle doit avoir la meme longueur que le message")
    return bytes(m ^ k for m, k in zip(msg, cle))


def dechiffrer(c: bytes, cle: bytes) -> bytes:
    return chiffrer(c, cle)


def crib_drag(xor_data: bytes, crib: bytes):
    resultats = []
    for i in range(len(xor_data) - len(crib) + 1):
        frag = bytes(c ^ b for c, b in zip(xor_data[i:], crib))
        try:
            t = frag.decode("ascii", errors="strict")
            if all(c in string.printable for c in t):
                resultats.append((i, t))
        except UnicodeDecodeError:
            pass
    return resultats


# Compat anciens noms.
chiffrer_otp = chiffrer
dechiffrer_otp = dechiffrer


def demo():
    print("\n" + "=" * 50)
    print("  One-Time Pad")
    print("=" * 50)
    msg = b"Message confidentiel"
    cle = generer_cle(len(msg))
    chiffre = chiffrer(msg, cle)
    print(f"\n  Cle (hex)     : {cle.hex()}")
    print(f"  Chiffre (hex) : {chiffre.hex()}")
    print(f"  Round-trip    : {dechiffrer(chiffre, cle) == msg}")

    print("\n  Vulnerabilite par reutilisation de cle :")
    m1 = b"attaque a midi"
    m2 = b"reunion 14h00 "
    cle2 = generer_cle(len(m1))
    c1 = chiffrer(m1, cle2)
    c2 = chiffrer(m2, cle2)
    xor_chiffres = bytes(a ^ b for a, b in zip(c1, c2))
    xor_clairs = bytes(a ^ b for a, b in zip(m1, m2))
    print(f"  C1 XOR C2 == M1 XOR M2 : {xor_chiffres == xor_clairs}")
    print("  -> la cle est annulee, les clairs s'XOR-ent entre eux.")

    print("\n  Crib dragging avec 'attaque' :")
    for pos, frag in crib_drag(xor_chiffres, b"attaque")[:5]:
        print(f"    pos {pos:2d} -> {frag!r}")


if __name__ == "__main__":
    demo()
