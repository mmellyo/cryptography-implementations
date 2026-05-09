"""TP2 - Ex2.4 : Finalistes du concours AES (NIST 1997-2000)."""
import os
import struct
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes

from symmetric.block import _serpent

try:
    import twofish as _twofish
except ImportError:
    _twofish = None


def _rotl32(v, n):
    n &= 31
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


class RC6:
    """RC6-32/20/16 (Rivest, Robshaw, Sidney, Yin - 1998). Bloc 128 bits."""

    _R = 20
    _P = 0xB7E15163
    _Q = 0x9E3779B9

    def __init__(self, cle: bytes):
        if len(cle) not in (16, 24, 32):
            raise ValueError("RC6 : cle 128/192/256 bits")
        c = len(cle) // 4
        L = list(struct.unpack(f"<{c}I", cle))
        n = 2 * self._R + 4
        S = [(self._P + i * self._Q) & 0xFFFFFFFF for i in range(n)]
        a = b = i = j = 0
        for _ in range(3 * max(n, c)):
            a = S[i] = _rotl32((S[i] + a + b) & 0xFFFFFFFF, 3)
            b = L[j] = _rotl32((L[j] + a + b) & 0xFFFFFFFF, a + b)
            i = (i + 1) % n
            j = (j + 1) % c
        self._S = S

    def chiffrer_bloc(self, bloc: bytes) -> bytes:
        if len(bloc) != 16:
            raise ValueError("RC6 : bloc 16 octets")
        A, B, C, D = struct.unpack("<4I", bloc)
        S = self._S
        B = (B + S[0]) & 0xFFFFFFFF
        D = (D + S[1]) & 0xFFFFFFFF
        for i in range(1, self._R + 1):
            t = _rotl32((B * (2 * B + 1)) & 0xFFFFFFFF, 5)
            u = _rotl32((D * (2 * D + 1)) & 0xFFFFFFFF, 5)
            A = (_rotl32(A ^ t, u) + S[2 * i]) & 0xFFFFFFFF
            C = (_rotl32(C ^ u, t) + S[2 * i + 1]) & 0xFFFFFFFF
            A, B, C, D = B, C, D, A
        A = (A + S[2 * self._R + 2]) & 0xFFFFFFFF
        C = (C + S[2 * self._R + 3]) & 0xFFFFFFFF
        return struct.pack("<4I", A, B, C, D)

    def chiffrer_ecb(self, donnees: bytes) -> bytes:
        donnees = pad(donnees, 16)
        return b"".join(self.chiffrer_bloc(donnees[i:i + 16]) for i in range(0, len(donnees), 16))


class Serpent:
    """Serpent (Anderson, Biham, Knudsen). Bloc 128 bits, cle 1..256 bits."""

    def __init__(self, cle: bytes):
        if not 0 < len(cle) <= 32:
            raise ValueError("Serpent : cle 1..256 bits")
        self._K = _serpent.expand_key(cle)

    def chiffrer_bloc(self, bloc: bytes) -> bytes:
        return _serpent.encrypt_block(bloc, self._K)


# Vecteurs de test officiels Serpent (soumission AES-original).
_SERPENT_TESTS = [
    (
        "Serpent-128 Set 1 #0",
        bytes.fromhex("80000000000000000000000000000000"),
        bytes(16),
        bytes.fromhex("264e5481eff42a4606abda06c0bfda3d"),
    ),
    (
        "Serpent-256 Set 1 #0",
        bytes.fromhex("8000000000000000000000000000000000000000000000000000000000000000"),
        bytes(16),
        bytes.fromhex("a223aa1288463c0e2be38ebd825616c0"),
    ),
    (
        "Serpent-128 Set 4 #0",
        bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        bytes.fromhex("00112233445566778899aabbccddeeff"),
        bytes.fromhex("563e2cf8740a27c164804560391e9b27"),
    ),
    (
        "Serpent-256 Set 4 #0",
        bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"),
        bytes.fromhex("00112233445566778899aabbccddeeff"),
        bytes.fromhex("2868b7a2d28ecd5e4fdefac3c4330074"),
    ),
]


# Vecteurs RC6 officiels (Annexe 4 de la specification RC6).
_RC6_TESTS = [
    (
        bytes.fromhex("00000000000000000000000000000000"),
        bytes.fromhex("00000000000000000000000000000000"),
        bytes.fromhex("8fc3a53656b1f778c129df4e9848a41e"),
    ),
    (
        bytes.fromhex("0123456789abcdef0112233445566778"),
        bytes.fromhex("02132435465768798a9bacbdcedfe0f1"),
        bytes.fromhex("524e192f4715c6231f51f6367ea43f18"),
    ),
]


def valider_rc6() -> bool:
    return all(RC6(k).chiffrer_bloc(p) == c for k, p, c in _RC6_TESTS)


def valider_serpent() -> bool:
    return all(Serpent(k).chiffrer_bloc(p) == c for _, k, p, c in _SERPENT_TESTS)


def _bench_aes(donnees: bytes) -> float:
    cle = get_random_bytes(16)
    t0 = time.perf_counter()
    AES.new(cle, AES.MODE_ECB).encrypt(donnees)
    return time.perf_counter() - t0


def _bench_twofish(donnees: bytes):
    if _twofish is None:
        return None
    cle = get_random_bytes(16)
    chiffreur = _twofish.Twofish(cle)
    t0 = time.perf_counter()
    for i in range(0, len(donnees), 16):
        chiffreur.encrypt(donnees[i:i + 16])
    return time.perf_counter() - t0


def _bench_rc6(donnees: bytes) -> float:
    chiffreur = RC6(get_random_bytes(16))
    t0 = time.perf_counter()
    for i in range(0, len(donnees), 16):
        chiffreur.chiffrer_bloc(donnees[i:i + 16])
    return time.perf_counter() - t0


def _bench_serpent(donnees: bytes) -> float:
    chiffreur = Serpent(get_random_bytes(16))
    t0 = time.perf_counter()
    for i in range(0, len(donnees), 16):
        chiffreur.chiffrer_bloc(donnees[i:i + 16])
    return time.perf_counter() - t0


def chiffrer_meme_bloc():
    cle = get_random_bytes(16)
    bloc = b"Texte 16 octets."
    print(f"  Cle  : {cle.hex()}")
    print(f"  Clair: {bloc.hex()} ({bloc!r})")
    aes = AES.new(cle, AES.MODE_ECB).encrypt(bloc)
    print(f"  Rijndael (AES) : {aes.hex()}")
    print(f"  Serpent        : {Serpent(cle).chiffrer_bloc(bloc).hex()}")
    if _twofish is not None:
        tf = _twofish.Twofish(cle).encrypt(bloc)
        print(f"  Twofish        : {tf.hex()}")
    else:
        print("  Twofish        : (paquet 'twofish' absent)")
    print(f"  RC6            : {RC6(cle).chiffrer_bloc(bloc).hex()}")
    print("  MARS (IBM)     : pas d'implementation Python validee disponible")


def benchmark(taille=256 * 1024, sortie="bench_finalistes.png"):
    """Benchmark sur taille (defaut 256 Ko car Serpent est lent en pur Python).

    AES, Twofish et RC6 atteignent leur regime stable des cette taille ; Serpent
    en column-lookup S-box affiche son cout reel sans saturer le temps total.
    """
    donnees = pad(os.urandom(taille), 16)
    mesures = {}
    mesures["AES (Rijndael)"] = _bench_aes(donnees)
    tf = _bench_twofish(donnees)
    if tf is not None:
        mesures["Twofish"] = tf
    mesures["Serpent"] = _bench_serpent(donnees)
    mesures["RC6"] = _bench_rc6(donnees)

    mo = taille / (1024 * 1024)
    print(f"  Donnees : {taille / 1024:.0f} Ko")
    for nom, dt in mesures.items():
        debit = mo / dt if dt > 0 else float("inf")
        print(f"  {nom:18s}: {dt:7.4f} s  ({debit:8.4f} Mo/s)")
    print("  MARS               : non benchmarke (pas d'implementation disponible)")

    fig, ax = plt.subplots(figsize=(7, 4))
    noms = list(mesures.keys())
    debits = [mo / mesures[n] for n in noms]
    couleurs = ["#1f77b4", "#2ca02c", "#9467bd", "#d62728"][:len(noms)]
    ax.bar(noms, debits, color=couleurs)
    ax.set_ylabel("Debit (Mo/s)")
    ax.set_yscale("log")
    ax.set_title(f"Finalistes AES - chiffrement de {taille / 1024:.0f} Ko (echelle log)")
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    fig.tight_layout()
    chemin = Path(sortie).resolve()
    fig.savefig(chemin, dpi=110)
    plt.close(fig)
    print(f"  Graphique : {chemin}")


def etude_architecturale():
    print(
        """
  Rijndael (AES) - vainqueur, oct. 2000
    Structure  : SPN
    Bloc / cle : 128 / 128, 192, 256 bits
    Tours      : 10 / 12 / 14
    Particules : SubBytes (S-box AES), ShiftRows, MixColumns

  Serpent
    Structure  : SPN bitslice
    Bloc / cle : 128 / 1..256 bits
    Tours      : 32
    Particules : 8 S-boxes 4x4, transformation lineaire
    Note       : implemente ici en pur Python, valide sur 4 vecteurs officiels
                 (AES-original Set 1 et Set 4 pour cles 128 et 256 bits)

  Twofish
    Structure  : Feistel
    Bloc / cle : 128 / 128, 192, 256 bits
    Tours      : 16
    Particules : S-boxes dependantes de la cle, MDS, Pseudo-Hadamard

  RC6
    Structure  : Feistel generalise (4 mots de 32 bits)
    Bloc / cle : 128 / 128, 192, 256 bits
    Tours      : 20
    Particules : multiplications entieres et rotations data-dependantes
    Note       : implemente from-scratch, valide contre 2 vecteurs officiels

  MARS (IBM)
    Structure  : heterogene (8 melange + 16 cryptographique + 8 melange)
    Bloc / cle : 128 / 128 a 448 bits
    Tours      : 32
    Particules : 2 S-boxes 256x32, multiplication, rotations data-dependantes
    Note       : pas d'implementation Python publiquement validee disponible.
                 Une reimplementation pure-Python necessiterait ~750 lignes de
                 constantes (S-boxes, tables de tours) ; le risque de typo
                 silencieux empeche une certification "production-grade".

  Critere du choix Rijndael par le NIST :
    - performance superieure sur logiciel et materiel (incluant smartcards)
    - simplicite de description, faible empreinte memoire
    - flexibilite des longueurs de cle / bloc
    Serpent restait plus securise (32 tours, marge anti-cryptanalyse) mais
    environ 3x plus lent que Rijndael.
    """
    )


def demo():
    print("\n" + "=" * 50)
    print("  AES finalists")
    print("=" * 50)
    etude_architecturale()
    print("\n  Vecteurs officiels :")
    print(f"  RC6     : {'OK' if valider_rc6() else 'ECHEC'}")
    print(f"  Serpent : {'OK' if valider_serpent() else 'ECHEC'}")
    print("\n  Chiffrement d'un meme bloc 128 bits :")
    chiffrer_meme_bloc()
    print("\n  Benchmark :")
    benchmark()


if __name__ == "__main__":
    demo()
