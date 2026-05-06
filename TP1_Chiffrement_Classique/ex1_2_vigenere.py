"""TP1 - Ex1.2 : Chiffre de Vigenere (from scratch)"""

import string
from collections import Counter
from math import gcd
from functools import reduce

FREQ_FR = {
    'A': 0.0815, 'B': 0.0097, 'C': 0.0315, 'D': 0.0373, 'E': 0.1739,
    'F': 0.0106, 'G': 0.0087, 'H': 0.0074, 'I': 0.0758, 'J': 0.0064,
    'K': 0.0005, 'L': 0.0546, 'M': 0.0297, 'N': 0.0713, 'O': 0.0527,
    'P': 0.0252, 'Q': 0.0136, 'R': 0.0643, 'S': 0.0795, 'T': 0.0711,
    'U': 0.0637, 'V': 0.0163, 'W': 0.0011, 'X': 0.0038, 'Y': 0.0028,
    'Z': 0.0015
}


def chiffrer_vigenere(texte: str, cle: str) -> str:
    resultat, cle, j = [], cle.upper(), 0
    for c in texte.upper():
        if c in string.ascii_uppercase:
            resultat.append(chr((ord(c) - ord('A') + ord(cle[j % len(cle)]) - ord('A')) % 26 + ord('A')))
            j += 1
    return ''.join(resultat)

def dechiffrer_vigenere(texte: str, cle: str) -> str:
    resultat, cle, j = [], cle.upper(), 0
    for c in texte.upper():
        if c in string.ascii_uppercase:
            resultat.append(chr((ord(c) - ord('A') - (ord(cle[j % len(cle)]) - ord('A'))) % 26 + ord('A')))
            j += 1
    return ''.join(resultat)

def test_kasiski(cryptogramme: str, taille_min: int = 3) -> int:
    texte = ''.join(c for c in cryptogramme.upper() if c in string.ascii_uppercase)
    positions = {}
    for i in range(len(texte) - taille_min + 1):
        tri = texte[i:i + taille_min]
        positions.setdefault(tri, []).append(i)
    repetes = {k: v for k, v in positions.items() if len(v) > 1}
    if not repetes:
        print("  Aucun trigramme repete."); return 1
    distances = []
    for tri, pos in sorted(repetes.items()):
        for i in range(len(pos)):
            for j in range(i + 1, len(pos)):
                distances.append(pos[j] - pos[i])
    if distances:
        longueur = reduce(gcd, distances)
        if longueur == 1:
            facteurs = Counter()
            for d in distances:
                for f in range(2, min(d + 1, 30)):
                    if d % f == 0: facteurs[f] += 1
            if facteurs: longueur = facteurs.most_common(1)[0][0]
        print(f"  Longueur estimee (Kasiski) : {longueur}")
        return longueur
    return 1

def calculer_ic(texte: str) -> float:
    t = ''.join(c for c in texte.upper() if c in string.ascii_uppercase)
    n = len(t)
    if n <= 1: return 0.0
    cpt = Counter(t)
    return sum(f * (f - 1) for f in cpt.values()) / (n * (n - 1))

def trouver_longueur_cle_ic(cryptogramme: str, max_len: int = 20) -> int:
    texte = ''.join(c for c in cryptogramme.upper() if c in string.ascii_uppercase)
    meilleur_diff, meilleure_l = float('inf'), 1
    for k in range(1, max_len + 1):
        ic_moy = sum(calculer_ic(texte[i::k]) for i in range(k)) / k
        diff = abs(ic_moy - 0.074)
        m = " <--" if diff < meilleur_diff and ic_moy > 0.05 else ""
        print(f"    k={k:2d} : IC={ic_moy:.4f}{m}")
        if diff < meilleur_diff and ic_moy > 0.05:
            meilleur_diff, meilleure_l = diff, k
    print(f"  Longueur estimee (IC) : {meilleure_l}")
    return meilleure_l

def retrouver_cle(cryptogramme: str, longueur: int) -> str:
    texte = ''.join(c for c in cryptogramme.upper() if c in string.ascii_uppercase)
    cle = []
    for i in range(longueur):
        ss = texte[i::longueur]
        n, cpt = len(ss), Counter(ss)
        best_corr, best_k = -1, 0
        for k in range(26):
            corr = sum(cpt.get(chr(j + ord('A')), 0) / n * FREQ_FR[chr((j - k) % 26 + ord('A'))] for j in range(26))
            if corr > best_corr: best_corr, best_k = corr, k
        cle.append(chr(best_k + ord('A')))
    return ''.join(cle)


def mode_interactif():
    while True:
        print("\n" + "=" * 50)
        print("  CHIFFRE DE VIGENERE")
        print("=" * 50)
        print("  1. Chiffrer")
        print("  2. Dechiffrer")
        print("  3. Cryptanalyse (casser sans la cle)")
        print("  4. Reponses theoriques")
        print("  5. Demo automatique")
        print("  0. Quitter")
        choix = input("\n  Choix : ").strip()

        if choix == "1":
            texte = input("  Message : ")
            cle = input("  Cle : ")
            if not cle.isalpha(): print("  Erreur : cle alphabetique."); continue
            print(f"  Chiffre : {chiffrer_vigenere(texte, cle)}")

        elif choix == "2":
            texte = input("  Message chiffre : ")
            cle = input("  Cle : ")
            if not cle.isalpha(): print("  Erreur : cle alphabetique."); continue
            print(f"  Dechiffre : {dechiffrer_vigenere(texte, cle)}")

        elif choix == "3":
            texte = input("  Cryptogramme : ")
            print("\n  Kasiski :")
            test_kasiski(texte)
            print("\n  Analyse IC :")
            longueur = trouver_longueur_cle_ic(texte)
            cle = retrouver_cle(texte, longueur)
            print(f"  Cle retrouvee : {cle}")
            print(f"  Dechiffre : {dechiffrer_vigenere(texte, cle)[:80]}")

        elif choix == "4":
            print("""
  - Cle courte -> sous-sequences longues -> statistiques exploitables
  - Cle longue -> plus resistant
  - |K| = |M| et cle aleatoire -> OTP (securite parfaite)
            """)

        elif choix == "5":
            texte = "La cryptographie est la pratique et l etude des techniques de communication securisee"
            cle = "SECRET"
            c = chiffrer_vigenere(texte, cle)
            d = dechiffrer_vigenere(c, cle)
            print(f"  {texte}\n  Cle={cle} -> {c}\n  Dechiffre : {d}")

        elif choix == "0":
            break

def main():
    print("\n  TP1 - EXERCICE 1.2 : CHIFFRE DE VIGENERE")
    mode_interactif()

if __name__ == "__main__":
    main()
