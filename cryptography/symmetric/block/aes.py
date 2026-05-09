"""AES (ECB / CBC / CTR) with image leakage, avalanche and nonce-reuse demos."""
import os
import time

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from common.pgm import chemin_asset, ecrire, lire


def chiffrer_cbc(message: bytes, cle: bytes, iv: bytes) -> bytes:
    return AES.new(cle, AES.MODE_CBC, iv=iv).encrypt(pad(message, 16))


def dechiffrer_cbc(chiffre: bytes, cle: bytes, iv: bytes) -> bytes:
    return unpad(AES.new(cle, AES.MODE_CBC, iv=iv).decrypt(chiffre), 16)


def chiffrer_ctr(message: bytes, cle: bytes, nonce: bytes) -> bytes:
    return AES.new(cle, AES.MODE_CTR, nonce=nonce).encrypt(message)


def dechiffrer_ctr(chiffre: bytes, cle: bytes, nonce: bytes) -> bytes:
    return AES.new(cle, AES.MODE_CTR, nonce=nonce).decrypt(chiffre)


def visualiser_modes_image():
    src = chemin_asset("image_originale.pgm")
    if not src.exists():
        print(f"  Image absente : {src}")
        return
    largeur, hauteur, pixels = lire(src)
    n = largeur * hauteur

    k128, k256 = get_random_bytes(16), get_random_bytes(32)
    iv, nonce = get_random_bytes(16), get_random_bytes(8)
    ecb = AES.new(k128, AES.MODE_ECB).encrypt(pad(pixels, 16))[:n]
    cbc = AES.new(k256, AES.MODE_CBC, iv=iv).encrypt(pad(pixels, 16))[:n]
    ctr = AES.new(k256, AES.MODE_CTR, nonce=nonce).encrypt(pixels)

    for nom, contenu in (("aes128_ecb", ecb), ("aes256_cbc", cbc), ("aes256_ctr", ctr)):
        ecrire(chemin_asset(f"image_{nom}.pgm"), largeur, hauteur, contenu)

    def _uniques(buf: bytes) -> str:
        blocs = [buf[i:i + 16] for i in range(0, len(buf), 16)]
        return f"{len(set(blocs))}/{len(blocs)}"

    print(f"  Image {largeur}x{hauteur}")
    print(f"  AES-128-ECB : {_uniques(ecb)} blocs uniques (fuite de structure)")
    print(f"  AES-256-CBC : {_uniques(cbc)} blocs uniques")
    print(f"  AES-256-CTR : {_uniques(ctr)} blocs uniques")


_DEFAUT_AVALANCHE = b"Test avalanche AES en mode CBC sur plusieurs blocs." * 4


def avalanche_cbc(message: bytes = _DEFAUT_AVALANCHE):
    cle = get_random_bytes(32)
    iv1 = get_random_bytes(16)
    iv2 = bytearray(iv1)
    iv2[0] ^= 1
    iv2 = bytes(iv2)
    msg = pad(message, 16)
    c1 = AES.new(cle, AES.MODE_CBC, iv=iv1).encrypt(msg)
    c2 = AES.new(cle, AES.MODE_CBC, iv=iv2).encrypt(msg)
    print(f"  IV initial / modifie : 1 bit flip")
    for i in range(min(len(c1) // 16, 4)):
        a = c1[i * 16:(i + 1) * 16]
        b = c2[i * 16:(i + 1) * 16]
        diff = sum(bin(x ^ y).count("1") for x, y in zip(a, b))
        print(f"  Bloc {i:2d} : {diff:3d}/128 bits differents ({diff * 100 // 128}%)")


def nonce_reuse_ctr(m1: bytes, m2: bytes):
    if not m1 or not m2:
        raise ValueError("Messages vides interdits")
    cle = get_random_bytes(32)
    nonce = get_random_bytes(8)
    n = min(len(m1), len(m2))
    c1 = chiffrer_ctr(m1[:n], cle, nonce)
    c2 = chiffrer_ctr(m2[:n], cle, nonce)
    xor_chiffres = bytes(a ^ b for a, b in zip(c1, c2))
    xor_clairs = bytes(a ^ b for a, b in zip(m1[:n], m2[:n]))
    print(f"  C1 XOR C2 == M1 XOR M2 : {xor_chiffres == xor_clairs}")
    print("  -> nonce reutilise : revele M1 XOR M2 (crib dragging exploitable).")


def benchmark_tailles_cle(taille_octets: int = 10 * 1024 * 1024):
    data = os.urandom(taille_octets)
    print(f"  Donnees : {taille_octets / 1024 / 1024:.0f} Mo")
    for sz, nom in [(16, "128"), (24, "192"), (32, "256")]:
        cle = get_random_bytes(sz)
        nonce = get_random_bytes(8)
        t0 = time.perf_counter()
        AES.new(cle, AES.MODE_CTR, nonce=nonce).encrypt(data)
        dt = time.perf_counter() - t0
        debit = taille_octets / (1024 * 1024) / dt
        print(f"  AES-{nom} : {dt:.4f}s ({debit:.1f} Mo/s)")


def demo():
    print("\n" + "=" * 50)
    print("  AES")
    print("=" * 50)

    msg = b"Donnees AES a chiffrer en CBC puis CTR."
    cle, iv = get_random_bytes(32), get_random_bytes(16)
    nonce = get_random_bytes(8)
    print(f"\n  Round-trip CBC : {dechiffrer_cbc(chiffrer_cbc(msg, cle, iv), cle, iv) == msg}")
    print(f"  Round-trip CTR : {dechiffrer_ctr(chiffrer_ctr(msg, cle, nonce), cle, nonce) == msg}")

    print("\n  Modes ECB / CBC / CTR sur image PGM :")
    visualiser_modes_image()

    print("\n  Avalanche en CBC (1 bit IV) :")
    avalanche_cbc()

    print("\n  Nonce-reuse en CTR :")
    nonce_reuse_ctr(b"attaque a midi", b"reunion 14h00 ")

    print("\n  Benchmark AES-128 / 192 / 256 :")
    benchmark_tailles_cle()


if __name__ == "__main__":
    demo()
