"""TP1 - Ex1.1 : Chiffre de César (from scratch)"""

import string
from collections import Counter

FREQUENCES_FR = {
    'A': 0.0815, 'B': 0.0097, 'C': 0.0315, 'D': 0.0373, 'E': 0.1739,
    'F': 0.0106, 'G': 0.0087, 'H': 0.0074, 'I': 0.0758, 'J': 0.0064,
    'K': 0.0005, 'L': 0.0546, 'M': 0.0297, 'N': 0.0713, 'O': 0.0527,
    'P': 0.0252, 'Q': 0.0136, 'R': 0.0643, 'S': 0.0795, 'T': 0.0711,
    'U': 0.0637, 'V': 0.0163, 'W': 0.0011, 'X': 0.0038, 'Y': 0.0028,
    'Z': 0.0015
}

MOTS_FR = {
    "LE", "LA", "LES", "DE", "DES", "DU", "UN", "UNE", "ET", "EST",
    "EN", "QUE", "QUI", "IL", "ELLE", "NOUS", "VOUS", "CE", "SE", "NE",
    "PAS", "POUR", "DANS", "SUR", "AVEC", "PAR", "PLUS", "TOUT", "COMME",
    "SONT", "ONT", "CETTE", "BIEN", "PEUT", "TOUS", "JE", "TU", "ON",
    "AU", "AUX", "MA", "TA", "SA", "MON", "MES", "SES"
}


def chiffrer_cesar(texte: str, k: int) -> str:
    resultat = []
    for c in texte.upper():
        if c in string.ascii_uppercase:
            resultat.append(chr((ord(c) - ord('A') + k) % 26 + ord('A')))
    return ''.join(resultat)

def dechiffrer_cesar(texte: str, k: int) -> str:
    return chiffrer_cesar(texte, 26 - k)

def attaque_force_brute(cryptogramme: str) -> tuple:
    meilleur_score, meilleure_cle, meilleur_texte = 0, 0, ""
    print("\n  ATTAQUE PAR FORCE BRUTE - 26 cles")
    print("  " + "-" * 50)
    for k in range(26):
        td = dechiffrer_cesar(cryptogramme, k)
        score = sum(lg for lg in range(2, 7)
                    for i in range(len(td) - lg + 1)
                    if td[i:i+lg] in MOTS_FR)
        marqueur = " <-- PROBABLE" if score > meilleur_score and score > 0 else ""
        print(f"  k={k:2d} : {td[:55]}{marqueur}")
        if score > meilleur_score:
            meilleur_score, meilleure_cle, meilleur_texte = score, k, td
    print(f"\n  >> Cle probable : k = {meilleure_cle}")
    print(f"  >> Texte : {meilleur_texte}")
    return meilleure_cle, meilleur_texte, meilleur_score

def calculer_ic(texte: str) -> float:
    t = ''.join(c for c in texte.upper() if c in string.ascii_uppercase)
    n = len(t)
    if n <= 1:
        return 0.0
    cpt = Counter(t)
    return sum(f * (f - 1) for f in cpt.values()) / (n * (n - 1))

def analyse_frequences(cryptogramme: str) -> int:
    t = ''.join(c for c in cryptogramme.upper() if c in string.ascii_uppercase)
    n = len(t)
    if n == 0:
        return 0
    cpt = Counter(t)
    ic = calculer_ic(t)
    print(f"\n  IC du cryptogramme : {ic:.4f}  (francais ~ 0.074)")
    meilleur_score, meilleure_cle = -1, 0
    for k in range(26):
        correlation = 0.0
        for i in range(26):
            obs = cpt.get(chr(i + ord('A')), 0) / n
            att = FREQUENCES_FR[chr((i - k) % 26 + ord('A'))]
            correlation += obs * att
        if correlation > meilleur_score:
            meilleur_score, meilleure_cle = correlation, k
    print(f"  Cle deduite : k = {meilleure_cle}")
    print(f"  Dechiffre : {dechiffrer_cesar(cryptogramme, meilleure_cle)[:70]}")
    return meilleure_cle


def mode_interactif():
    while True:
        print("\n" + "=" * 50)
        print("  CHIFFRE DE CESAR")
        print("=" * 50)
        print("  1. Chiffrer un message")
        print("  2. Dechiffrer un message")
        print("  3. Attaque force brute")
        print("  4. Analyse de frequences")
        print("  5. Reponses theoriques")
        print("  6. Demo automatique")
        print("  0. Quitter")
        choix = input("\n  Choix : ").strip()

        if choix == "1":
            texte = input("  Message : ")
            try: k = int(input("  Cle (0-25) : "))
            except ValueError: print("  Erreur."); continue
            print(f"  Chiffre : {chiffrer_cesar(texte, k)}")

        elif choix == "2":
            texte = input("  Message chiffre : ")
            try: k = int(input("  Cle (0-25) : "))
            except ValueError: print("  Erreur."); continue
            print(f"  Dechiffre : {dechiffrer_cesar(texte, k)}")

        elif choix == "3":
            texte = input("  Cryptogramme : ")
            attaque_force_brute(texte)

        elif choix == "4":
            texte = input("  Cryptogramme : ")
            analyse_frequences(texte)

        elif choix == "5":
            print("""
  - Espace de cles : 26 -> force brute triviale
  - Substitution monoalphabetique : preserve les frequences
  - IC reste identique apres chiffrement (~0.074 pour le francais)
  - Force brute : simple, necessite dictionnaire
  - Frequences : mathematique, generalisable
            """)

        elif choix == "6":
            texte = "La cryptographie est la science du secret"
            k = 7
            c = chiffrer_cesar(texte, k)
            d = dechiffrer_cesar(c, k)
            print(f"  {texte} -> {c} -> {d}")
            crypto = chiffrer_cesar("Le chiffre de cesar est un chiffrement par substitution", 13)
            attaque_force_brute(crypto)

        elif choix == "0":
            break

def main():
    print("\n  TP1 - EXERCICE 1.1 : CHIFFRE DE CESAR")
    mode_interactif()

if __name__ == "__main__":
    main()
