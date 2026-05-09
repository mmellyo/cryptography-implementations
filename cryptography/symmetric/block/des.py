"""DES and Triple-DES with ECB pattern leakage demo on PGM images."""
import os
import time

from Crypto.Cipher import DES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from common.pgm import chemin_asset, ecrire, lire


def chiffrer_cbc(message: bytes, cle: bytes, iv: bytes) -> bytes:
    return DES.new(cle, DES.MODE_CBC, iv=iv).encrypt(pad(message, 8))


def dechiffrer_cbc(chiffre: bytes, cle: bytes, iv: bytes) -> bytes:
    return unpad(DES.new(cle, DES.MODE_CBC, iv=iv).decrypt(chiffre), 8)


def chiffrer_3des_cbc(message: bytes, cle: bytes, iv: bytes) -> bytes:
    return DES3.new(cle, DES3.MODE_CBC, iv=iv).encrypt(pad(message, 8))


def dechiffrer_3des_cbc(chiffre: bytes, cle: bytes, iv: bytes) -> bytes:
    return unpad(DES3.new(cle, DES3.MODE_CBC, iv=iv).decrypt(chiffre), 8)


# Compat anciens noms.
chiffrer_des_cbc = chiffrer_cbc
dechiffrer_des_cbc = dechiffrer_cbc


def comparer_ecb_cbc_128o():
    msg = b"A" * 64 + b"B" * 64
    cle, iv = get_random_bytes(8), get_random_bytes(8)
    ecb = DES.new(cle, DES.MODE_ECB).encrypt(pad(msg, 8))
    cbc = DES.new(cle, DES.MODE_CBC, iv=iv).encrypt(pad(msg, 8))
    blocs_ecb = [ecb[i:i + 8] for i in range(0, len(ecb), 8)]
    blocs_cbc = [cbc[i:i + 8] for i in range(0, len(cbc), 8)]
    print(f"  Message : 128 octets ({len(blocs_ecb)} blocs DES)")
    print(f"  ECB : {len(set(blocs_ecb))}/{len(blocs_ecb)} blocs uniques (motifs visibles)")
    print(f"  CBC : {len(set(blocs_cbc))}/{len(blocs_cbc)} blocs uniques")


def visualiser_faiblesse_ecb():
    src = chemin_asset("image_originale.pgm")
    if not src.exists():
        print(f"  Image absente : {src}")
        return
    largeur, hauteur, pixels = lire(src)
    cle, iv = get_random_bytes(8), get_random_bytes(8)
    n = largeur * hauteur
    ecb = DES.new(cle, DES.MODE_ECB).encrypt(pad(pixels, 8))[:n]
    cbc = DES.new(cle, DES.MODE_CBC, iv=iv).encrypt(pad(pixels, 8))[:n]
    out_ecb = chemin_asset("image_des_ecb.pgm")
    out_cbc = chemin_asset("image_des_cbc.pgm")
    ecrire(out_ecb, largeur, hauteur, ecb)
    ecrire(out_cbc, largeur, hauteur, cbc)
    blocs_clair = [pixels[i:i + 8] for i in range(0, len(pixels), 8)]
    blocs_ecb = [ecb[i:i + 8] for i in range(0, len(ecb), 8)]
    print(f"  Image {largeur}x{hauteur} ({n} pixels)")
    print(f"  Clair : {len(set(blocs_clair))}/{len(blocs_clair)} blocs uniques")
    print(f"  ECB   : {len(set(blocs_ecb))}/{len(blocs_ecb)} blocs uniques (motifs preserves)")
    print(f"  Sorties : {out_ecb.name}, {out_cbc.name}")


def benchmark_des_vs_3des(taille_octets: int = 1024 * 1024):
    data = pad(os.urandom(taille_octets), 8)
    k1 = get_random_bytes(8)
    k3 = DES3.adjust_key_parity(get_random_bytes(24))
    iv = get_random_bytes(8)
    t0 = time.perf_counter()
    DES.new(k1, DES.MODE_CBC, iv=iv).encrypt(data)
    td = time.perf_counter() - t0
    t0 = time.perf_counter()
    DES3.new(k3, DES3.MODE_CBC, iv=iv).encrypt(data)
    t3 = time.perf_counter() - t0
    print(f"  Donnees : {taille_octets / 1024 / 1024:.1f} Mo")
    print(f"  DES  : {td:.4f}s  ({taille_octets / 1024 / 1024 / td:.1f} Mo/s)")
    print(f"  3DES : {t3:.4f}s  ({taille_octets / 1024 / 1024 / t3:.1f} Mo/s)")
    print(f"  Ratio 3DES/DES : {t3 / td:.1f}x")


def demo():
    print("\n" + "=" * 50)
    print("  DES / Triple-DES")
    print("=" * 50)

    msg = b"Donnees a chiffrer en DES-CBC."
    cle, iv = get_random_bytes(8), get_random_bytes(8)
    chiffre = chiffrer_cbc(msg, cle, iv)
    print(f"\n  Round-trip CBC : {dechiffrer_cbc(chiffre, cle, iv) == msg}")

    print("\n  ECB vs CBC sur 128 octets :")
    comparer_ecb_cbc_128o()

    print("\n  Faiblesse ECB sur image PGM :")
    visualiser_faiblesse_ecb()

    print("\n  Benchmark DES vs 3DES :")
    benchmark_des_vs_3des()


if __name__ == "__main__":
    demo()
