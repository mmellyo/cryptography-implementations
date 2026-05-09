"""SHA-256 implementation with file integrity verification."""
import hashlib
import struct
import tempfile
from pathlib import Path


K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]
H0 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]


def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def ch(x, y, z):
    return (x & y) ^ (~x & 0xFFFFFFFF & z)


def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def s0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)


def s1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)


def g0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)


def g1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)


def sha256_manuel(message: bytes) -> str:
    L = len(message) * 8
    message = message + b"\x80"
    while len(message) % 64 != 56:
        message += b"\x00"
    message += struct.pack(">Q", L)
    H = list(H0)
    for i in range(0, len(message), 64):
        W = list(struct.unpack(">16I", message[i:i + 64]))
        for j in range(16, 64):
            W.append((g1(W[j - 2]) + W[j - 7] + g0(W[j - 15]) + W[j - 16]) & 0xFFFFFFFF)
        a, b, c, d, e, f, g, h = H
        for j in range(64):
            T1 = (h + s1(e) + ch(e, f, g) + K[j] + W[j]) & 0xFFFFFFFF
            T2 = (s0(a) + maj(a, b, c)) & 0xFFFFFFFF
            h, g, f, e = g, f, e, (d + T1) & 0xFFFFFFFF
            d, c, b, a = c, b, a, (T1 + T2) & 0xFFFFFFFF
        H = [(H[idx] + v) & 0xFFFFFFFF for idx, v in enumerate([a, b, c, d, e, f, g, h])]
    return "".join(f"{v:08x}" for v in H)


def sha256_fichier(chemin) -> str:
    h = hashlib.sha256()
    with open(chemin, "rb") as f:
        for bloc in iter(lambda: f.read(65536), b""):
            h.update(bloc)
    return h.hexdigest()


def verifier_integrite(chemin, hash_attendu: str) -> bool:
    """Compare le SHA-256 d'un fichier avec un hash officiel (hex). Constant-time."""
    chemin = Path(chemin)
    if not chemin.is_file():
        raise FileNotFoundError(chemin)
    obtenu = bytes.fromhex(sha256_fichier(chemin))
    try:
        attendu = bytes.fromhex(hash_attendu.strip())
    except ValueError as e:
        raise ValueError(f"Hash attendu invalide : {e}") from e
    import hmac
    return hmac.compare_digest(obtenu, attendu)


VECTEURS_NIST = [
    (b"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    (b"a", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"),
    (b"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    (b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
     "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    (b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
     b"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
     "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"),
    (b"The quick brown fox jumps over the lazy dog",
     "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"),
    (b"\x00" * 64,
     "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"),
    (b"\xff" * 100,
     "da6f14970ce356ce01a5b340291e9d8b2652eb63fbf8f328ca6a87a727fde4d9"),
    (b"a" * 1000,
     "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"),
    (b"Cryptographie",
     "0073e8c7fe96e38eda71395f43511288c7b76108d45590a6f5570e4a5994f3d6"),
]


def valider_vecteurs_nist():
    """Renvoie le nombre de vecteurs validés sur 10 + le détail."""
    succes = 0
    for msg, attendu in VECTEURS_NIST:
        obtenu = sha256_manuel(msg)
        ok = obtenu == attendu
        succes += int(ok)
        affichage = msg[:30] + (b"..." if len(msg) > 30 else b"")
        print(f"  {'OK  ' if ok else 'FAIL'} : {affichage!r}")
        if not ok:
            print(f"         attendu : {attendu}")
            print(f"         obtenu  : {obtenu}")
    print(f"\n  {succes}/{len(VECTEURS_NIST)} vecteurs valides")


def demo():
    print("\n" + "=" * 50)
    print("  SHA-256")
    print("=" * 50)
    print("\n  Validation contre 10 vecteurs NIST FIPS 180-4 :")
    valider_vecteurs_nist()

    chemin = Path(tempfile.gettempdir()) / "sha256_demo.bin"
    chemin.write_bytes(b"Donnees du fichier de test pour la verification d'integrite.")
    try:
        attendu = sha256_fichier(chemin)
        print(f"\n  Verification d'integrite (simulation telechargement) :")
        print(f"  Fichier  : {chemin}")
        print(f"  Attendu  : {attendu}")
        print(f"  Resultat : {'OK' if verifier_integrite(chemin, attendu) else 'CORROMPU'}")
        print(f"  Tamper   : {verifier_integrite(chemin, '0' * 64)}")
    finally:
        chemin.unlink(missing_ok=True)


if __name__ == "__main__":
    demo()
