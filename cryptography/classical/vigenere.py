"""Vigenere cipher with Kasiski test and IC-based key length recovery."""
import string
from collections import Counter
from functools import reduce
from math import gcd

FREQ_FR = {
    "A": 0.0815, "B": 0.0097, "C": 0.0315, "D": 0.0373, "E": 0.1739,
    "F": 0.0106, "G": 0.0087, "H": 0.0074, "I": 0.0758, "J": 0.0064,
    "K": 0.0005, "L": 0.0546, "M": 0.0297, "N": 0.0713, "O": 0.0527,
    "P": 0.0252, "Q": 0.0136, "R": 0.0643, "S": 0.0795, "T": 0.0711,
    "U": 0.0637, "V": 0.0163, "W": 0.0011, "X": 0.0038, "Y": 0.0028,
    "Z": 0.0015,
}


def _normalise(texte: str) -> str:
    return "".join(c for c in texte.upper() if c in string.ascii_uppercase)


def chiffrer(texte: str, cle: str) -> str:
    if not cle.isalpha():
        raise ValueError("Vigenere : la cle doit etre alphabetique")
    cle = cle.upper()
    out = []
    j = 0
    for c in texte.upper():
        if c in string.ascii_uppercase:
            out.append(chr((ord(c) + ord(cle[j % len(cle)]) - 2 * ord("A")) % 26 + ord("A")))
            j += 1
    return "".join(out)


def dechiffrer(texte: str, cle: str) -> str:
    if not cle.isalpha():
        raise ValueError("Vigenere : la cle doit etre alphabetique")
    cle = cle.upper()
    out = []
    j = 0
    for c in texte.upper():
        if c in string.ascii_uppercase:
            out.append(chr((ord(c) - ord(cle[j % len(cle)])) % 26 + ord("A")))
            j += 1
    return "".join(out)


def kasiski(cryptogramme: str, taille_min: int = 3) -> int:
    texte = _normalise(cryptogramme)
    positions = {}
    for i in range(len(texte) - taille_min + 1):
        tri = texte[i:i + taille_min]
        positions.setdefault(tri, []).append(i)
    distances = []
    for pos in positions.values():
        if len(pos) > 1:
            for i in range(len(pos)):
                for j in range(i + 1, len(pos)):
                    distances.append(pos[j] - pos[i])
    if not distances:
        return 1
    longueur = reduce(gcd, distances)
    if longueur == 1:
        facteurs = Counter()
        for d in distances:
            for f in range(2, min(d + 1, 30)):
                if d % f == 0:
                    facteurs[f] += 1
        if facteurs:
            longueur = facteurs.most_common(1)[0][0]
    return longueur


def calculer_ic(texte: str) -> float:
    t = _normalise(texte)
    n = len(t)
    if n <= 1:
        return 0.0
    return sum(f * (f - 1) for f in Counter(t).values()) / (n * (n - 1))


def trouver_longueur_cle_ic(cryptogramme: str, max_len: int = 20) -> int:
    texte = _normalise(cryptogramme)
    meilleure_diff, meilleure_l = float("inf"), 1
    for k in range(1, max_len + 1):
        ic_moy = sum(calculer_ic(texte[i::k]) for i in range(k)) / k
        if ic_moy > 0.05:
            diff = abs(ic_moy - 0.074)
            if diff < meilleure_diff:
                meilleure_diff, meilleure_l = diff, k
    return meilleure_l


def retrouver_cle(cryptogramme: str, longueur: int) -> str:
    texte = _normalise(cryptogramme)
    cle = []
    for i in range(longueur):
        ss = texte[i::longueur]
        n = len(ss)
        cpt = Counter(ss)
        meilleur_k, meilleure_correlation = 0, -1.0
        for k in range(26):
            corr = sum(
                cpt.get(chr(j + ord("A")), 0) / n * FREQ_FR[chr((j - k) % 26 + ord("A"))]
                for j in range(26)
            )
            if corr > meilleure_correlation:
                meilleure_correlation, meilleur_k = corr, k
        cle.append(chr(meilleur_k + ord("A")))
    return "".join(cle)


# Compat anciens noms.
chiffrer_vigenere = chiffrer
dechiffrer_vigenere = dechiffrer
test_kasiski = kasiski


def demo():
    print("\n" + "=" * 50)
    print("  Vigenere cipher")
    print("=" * 50)
    clair = "La cryptographie est la pratique et l etude des techniques de communication securisee"
    cle = "SECRET"
    chiffre = chiffrer(clair, cle)
    print(f"\n  Clair   : {clair}")
    print(f"  Cle     : {cle}")
    print(f"  Chiffre : {chiffre}")
    print(f"  Verifie : {dechiffrer(chiffre, cle).startswith(_normalise(clair))}")

    sample = (
        "LACRYPTOGRAPHIECONSISTEACHIFFRERETDECHIFFRERDESINFORMATIONS"
        "POURPROTEGERDESCOMMUNICATIONSSECURISEES" * 3
    )
    cible = chiffrer(sample, "CLEF")
    print(f"\n  Kasiski (longueur estimee) : {kasiski(cible)}")
    longueur = trouver_longueur_cle_ic(cible, max_len=10)
    cle_retrouvee = retrouver_cle(cible, longueur)
    print(f"  IC      (longueur, cle)    : {longueur}, {cle_retrouvee}")


if __name__ == "__main__":
    demo()
