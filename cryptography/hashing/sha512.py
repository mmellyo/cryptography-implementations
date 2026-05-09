"""SHA-512 with comparative benchmarking against MD5 and SHA-256."""
import hashlib
import os
import time

ALGOS = (("MD5", hashlib.md5), ("SHA-256", hashlib.sha256), ("SHA-512", hashlib.sha512))


def empreintes(message: bytes) -> dict:
    return {nom: f(message).hexdigest() for nom, f in ALGOS}


def benchmark(taille_octets: int = 100 * 1024 * 1024) -> dict:
    data = os.urandom(taille_octets)
    resultats = {}
    for nom, f in ALGOS:
        t0 = time.perf_counter()
        f(data).hexdigest()
        resultats[nom] = time.perf_counter() - t0
    return resultats


def avalanche(message: bytes) -> dict:
    modifie = bytearray(message)
    if not modifie:
        modifie = bytearray(b"\x00")
    modifie[0] ^= 1
    modifie = bytes(modifie)
    out = {}
    for nom, f in ALGOS:
        h1 = f(message).hexdigest()
        h2 = f(modifie).hexdigest()
        bits_total = len(h1) * 4
        bits_diff = sum(bin(int(a, 16) ^ int(b, 16)).count("1") for a, b in zip(h1, h2))
        out[nom] = (bits_total, bits_diff)
    return out


def demo():
    print("\n" + "=" * 50)
    print("  SHA-512 et comparaison")
    print("=" * 50)
    msg = b"Cryptographie appliquee : analyse des fonctions de hachage."

    print("\n  Empreintes sur le meme message :")
    for nom, h in empreintes(msg).items():
        print(f"  {nom:8s} : {h[:48]}{'...' if len(h) > 48 else ''} ({len(h) * 4} bits)")

    print("\n  Effet avalanche (1 bit modifie) :")
    for nom, (total, diff) in avalanche(msg).items():
        print(f"  {nom:8s} : {diff}/{total} bits ({diff * 100 // total}%)")

    print("\n  Benchmark sur 100 Mo :")
    res = benchmark(100 * 1024 * 1024)
    for nom, dt in res.items():
        debit = 100 / dt
        print(f"  {nom:8s} : {dt:.4f}s ({debit:.1f} Mo/s)")


if __name__ == "__main__":
    demo()
