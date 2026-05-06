"""TP1 - Ex1.3 : Chiffre de Hill (from scratch)"""
from math import gcd

def inverse_mod(a, m):
    g, x, _ = _eea(a % m, m)
    if g != 1: raise ValueError(f"Pas d'inverse")
    return x % m

def _eea(a, b):
    if a == 0: return b, 0, 1
    g, x, y = _eea(b % a, a)
    return g, y - (b // a) * x, x

def det_mat(m, n):
    if n == 1: return m[0][0]
    if n == 2: return m[0][0]*m[1][1] - m[0][1]*m[1][0]
    return sum(((-1)**j)*m[0][j]*det_mat([[m[i][k] for k in range(n) if k!=j] for i in range(1,n)], n-1) for j in range(n))

def cofacteur(m, n, i, j):
    sous = [[m[r][c] for c in range(n) if c!=j] for r in range(n) if r!=i]
    return ((-1)**(i+j)) * det_mat(sous, n-1)

def inverse_mat_mod(mat, n, mod=26):
    det = det_mat(mat, n) % mod
    if gcd(det, mod) != 1: raise ValueError(f"Non inversible mod {mod}")
    di = inverse_mod(det, mod)
    adj = [[cofacteur(mat, n, i, j) for i in range(n)] for j in range(n)]
    return [[(di * adj[i][j]) % mod for j in range(n)] for i in range(n)]

def verifier_mat(mat, n): return gcd(det_mat(mat, n) % 26, 26) == 1
def mult_mv(mat, vec, n): return [sum(mat[i][j]*vec[j] for j in range(n)) % 26 for i in range(n)]
def mult_mm(a, b, n): return [[sum(a[i][k]*b[k][j] for k in range(n)) % 26 for j in range(n)] for i in range(n)]
def txt2num(t): return [ord(c)-65 for c in t.upper() if c.isalpha()]
def num2txt(n): return ''.join(chr(v%26+65) for v in n)

def chiffrer_hill(texte, cle, n):
    nums = txt2num(texte)
    while len(nums) % n: nums.append(23)
    r = []
    for i in range(0, len(nums), n): r.extend(mult_mv(cle, nums[i:i+n], n))
    return num2txt(r)

def dechiffrer_hill(texte, cle, n):
    ki = inverse_mat_mod(cle, n)
    nums = txt2num(texte)
    r = []
    for i in range(0, len(nums), n): r.extend(mult_mv(ki, nums[i:i+n], n))
    return num2txt(r)

def attaque_clair_connu(clair, chiffre, n):
    pn, cn = txt2num(clair), txt2num(chiffre)
    P = [[pn[c*n+r] for c in range(n)] for r in range(n)]
    C = [[cn[c*n+r] for c in range(n)] for r in range(n)]
    return mult_mm(C, inverse_mat_mod(P, n), n)

def lire_matrice(n):
    print(f"  Matrice {n}x{n} :")
    mat = []
    for i in range(n):
        while True:
            try:
                l = input(f"    Ligne {i+1} : ").split()
                if len(l) != n: print(f"    {n} nombres."); continue
                mat.append([int(x) for x in l]); break
            except ValueError: print("    Entiers requis.")
    return mat

def mode_interactif():
    while True:
        print("\n" + "=" * 50)
        print("  CHIFFRE DE HILL")
        print("=" * 50)
        print("  1. Chiffrer\n  2. Dechiffrer\n  3. Attaque clair connu")
        print("  4. Theorie\n  5. Demo\n  0. Quitter")
        choix = input("\n  Choix : ").strip()
        if choix == "1":
            try: n = int(input("  Taille (2/3) : "))
            except ValueError: continue
            mat = lire_matrice(n)
            if not verifier_mat(mat, n): print("  Non inversible."); continue
            print(f"  Chiffre : {chiffrer_hill(input('  Message : '), mat, n)}")
        elif choix == "2":
            try: n = int(input("  Taille (2/3) : "))
            except ValueError: continue
            mat = lire_matrice(n)
            if not verifier_mat(mat, n): print("  Non inversible."); continue
            print(f"  Dechiffre : {dechiffrer_hill(input('  Chiffre : '), mat, n)}")
        elif choix == "3":
            try: n = int(input("  Taille (2/3) : "))
            except ValueError: continue
            nb = n*n
            clair = input(f"  {nb} lettres clair : ")
            chiffre = input(f"  {nb} lettres chiffre : ")
            try: print(f"  Cle : {attaque_clair_connu(clair, chiffre, n)}")
            except Exception as e: print(f"  Erreur : {e}")
        elif choix == "4":
            print("  C=KP mod 26, n^2 paires suffisent, attaque O(n^3)")
        elif choix == "5":
            cle = [[3,3],[2,5]]
            c = chiffrer_hill("BONJOUR", cle, 2)
            print(f"  BONJOUR -> {c} -> {dechiffrer_hill(c, cle, 2)}")
        elif choix == "0": break

def main():
    print("\n  TP1 - EXERCICE 1.3 : CHIFFRE DE HILL")
    mode_interactif()

if __name__ == "__main__":
    main()
