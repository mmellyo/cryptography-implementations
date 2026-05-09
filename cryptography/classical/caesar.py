"""Caesar cipher with brute-force and index-of-coincidence cryptanalysis."""
import string
from collections import Counter

FREQUENCES_FR = {
    "A": 0.0815, "B": 0.0097, "C": 0.0315, "D": 0.0373, "E": 0.1739,
    "F": 0.0106, "G": 0.0087, "H": 0.0074, "I": 0.0758, "J": 0.0064,
    "K": 0.0005, "L": 0.0546, "M": 0.0297, "N": 0.0713, "O": 0.0527,
    "P": 0.0252, "Q": 0.0136, "R": 0.0643, "S": 0.0795, "T": 0.0711,
    "U": 0.0637, "V": 0.0163, "W": 0.0011, "X": 0.0038, "Y": 0.0028,
    "Z": 0.0015,
}

MOTS_FR = {
    "LE", "LA", "LES", "DE", "DES", "DU", "UN", "UNE", "ET", "EST",
    "EN", "QUE", "QUI", "IL", "ELLE", "NOUS", "VOUS", "CE", "SE", "NE",
    "PAS", "POUR", "DANS", "SUR", "AVEC", "PAR", "PLUS", "TOUT", "COMME",
    "SONT", "ONT", "CETTE", "BIEN", "PEUT", "TOUS", "JE", "TU", "ON",
    "AU", "AUX", "MA", "TA", "SA", "MON", "MES", "SES",
}


def chiffrer(texte: str, k: int) -> str:
    return "".join(
        chr((ord(c) - ord("A") + k) % 26 + ord("A"))
        for c in texte.upper()
        if c in string.ascii_uppercase
    )


def dechiffrer(texte: str, k: int) -> str:
    return chiffrer(texte, 26 - k)


def attaque_force_brute(cryptogramme: str):
    print("  Attaque par force brute (26 cles)")
    print("  " + "-" * 50)
    meilleur_score, meilleure_cle, meilleur_texte = 0, 0, ""
    for k in range(26):
        candidat = dechiffrer(cryptogramme, k)
        score = sum(
            lg
            for lg in range(2, 7)
            for i in range(len(candidat) - lg + 1)
            if candidat[i:i + lg] in MOTS_FR
        )
        marqueur = " <-- probable" if score > meilleur_score else ""
        print(f"  k={k:2d} : {candidat[:55]}{marqueur}")
        if score > meilleur_score:
            meilleur_score, meilleure_cle, meilleur_texte = score, k, candidat
    return meilleure_cle, meilleur_texte, meilleur_score


def calculer_ic(texte: str) -> float:
    t = "".join(c for c in texte.upper() if c in string.ascii_uppercase)
    n = len(t)
    if n <= 1:
        return 0.0
    return sum(f * (f - 1) for f in Counter(t).values()) / (n * (n - 1))


def analyse_frequences(cryptogramme: str) -> int:
    t = "".join(c for c in cryptogramme.upper() if c in string.ascii_uppercase)
    n = len(t)
    if n == 0:
        return 0
    cpt = Counter(t)
    print(f"  IC du cryptogramme : {calculer_ic(t):.4f}  (francais ~ 0.074)")
    meilleure_cle, meilleure_correlation = 0, -1.0
    for k in range(26):
        correlation = sum(
            cpt.get(chr(i + ord("A")), 0) / n * FREQUENCES_FR[chr((i - k) % 26 + ord("A"))]
            for i in range(26)
        )
        if correlation > meilleure_correlation:
            meilleure_correlation, meilleure_cle = correlation, k
    print(f"  Cle deduite : k = {meilleure_cle}")
    print(f"  Dechiffre   : {dechiffrer(cryptogramme, meilleure_cle)[:70]}")
    return meilleure_cle


# Aliases pour compatibilite avec les anciens noms.
chiffrer_cesar = chiffrer
dechiffrer_cesar = dechiffrer


def demo():
    print("\n" + "=" * 50)
    print("  Caesar cipher")
    print("=" * 50)
    clair = "La cryptographie est la science du secret"
    cle = 7
    chiffre = chiffrer(clair, cle)
    print(f"\n  Clair    : {clair}")
    print(f"  Cle      : {cle}")
    print(f"  Chiffre  : {chiffre}")
    print(f"  Verifie  : {dechiffrer(chiffre, cle) == ''.join(c for c in clair.upper() if c.isalpha())}")

    cible = chiffrer(
        "Le chiffre de Cesar est un chiffrement par substitution monoalphabetique",
        13,
    )
    print()
    attaque_force_brute(cible)

    print("\n  Analyse de frequences :")
    analyse_frequences(cible)


if __name__ == "__main__":
    demo()
