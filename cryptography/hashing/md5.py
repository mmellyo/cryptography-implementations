"""MD5 hashing with avalanche effect demo and 5-message size pipeline."""
import hashlib
import os
import tempfile
from pathlib import Path


def md5(donnees: bytes) -> str:
    return hashlib.md5(donnees).hexdigest()


def md5_fichier(chemin) -> str:
    h = hashlib.md5()
    with open(chemin, "rb") as f:
        for bloc in iter(lambda: f.read(65536), b""):
            h.update(bloc)
    return h.hexdigest()


def hash_5_messages():
    chemin_bin = Path(tempfile.gettempdir()) / "md5_demo.bin"
    chemin_bin.write_bytes(os.urandom(2048))
    try:
        cas = [
            ("chaine vide",                            b""),
            ("1 octet",                                b"A"),
            ("1 Ko aleatoire",                         os.urandom(1024)),
            ("1 Mo aleatoire",                         os.urandom(1024 * 1024)),
            (f"fichier binaire ({chemin_bin.name})",   None),
        ]
        for libelle, donnees in cas:
            h = md5_fichier(chemin_bin) if donnees is None else md5(donnees)
            print(f"  {libelle:40s} -> {h}  ({len(h) * 4} bits)")
    finally:
        chemin_bin.unlink(missing_ok=True)


def avalanche(message: bytes):
    h1 = md5(message)
    modifie = bytearray(message) if message else bytearray(b"\x00")
    modifie[0] ^= 1
    h2 = md5(bytes(modifie))
    diff_bits = sum(bin(int(a, 16) ^ int(b, 16)).count("1") for a, b in zip(h1, h2))
    return h1, h2, diff_bits


def demo():
    print("\n" + "=" * 50)
    print("  MD5")
    print("=" * 50)
    print("\n  Hash de 5 messages :")
    hash_5_messages()

    print("\n  Effet avalanche (1 bit modifie) :")
    msg = b"Cryptographie appliquee"
    h1, h2, diff = avalanche(msg)
    print(f"  Original  : {h1}")
    print(f"  Modifie   : {h2}")
    print(f"  Diff      : {diff}/128 bits ({diff * 100 // 128}%)")


if __name__ == "__main__":
    demo()
