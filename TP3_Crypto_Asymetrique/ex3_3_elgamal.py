"""TP3 - Ex3.3 : ElGamal (from scratch)"""
import os
from sympy import nextprime, primitive_root
from math import gcd

def gen_cles(bits=64):
    seed = int.from_bytes(os.urandom(max(bits//8,8)), 'big') | (1<<(bits-1))
    p = nextprime(seed); g = primitive_root(p)
    nb = (p.bit_length()+7)//8
    x = int.from_bytes(os.urandom(nb), 'big') % (p-3) + 2
    return p, g, x, pow(g, x, p)

def chiffrer(p, g, y, M):
    nb = (p.bit_length()+7)//8
    while True:
        k = int.from_bytes(os.urandom(nb), 'big') % (p-2) + 1
        if gcd(k, p-1) == 1: break
    return pow(g, k, p), (M * pow(y, k, p)) % p

def dechiffrer(p, x, c1, c2):
    return (c2 * pow(pow(c1, x, p), p-2, p)) % p

def mode_interactif():
    p = g = x = y = None
    while True:
        print("\n" + "=" * 50)
        print("  ELGAMAL")
        print("=" * 50)
        print("  1. Generer cles\n  2. Chiffrer\n  3. Dechiffrer")
        print("  4. Non-determinisme\n  5. Malleabilite\n  0. Quitter")
        choix = input("\n  Choix : ").strip()
        if choix == "1":
            try: bits = int(input("  Bits (ex: 64) : "))
            except ValueError: bits = 64
            p, g, x, y = gen_cles(bits)
            print(f"  p={p}\n  g={g}\n  x(privee)={x}\n  y(publique)={y}")
        elif choix == "2":
            if not p: p, g, x, y = gen_cles()
            try: M = int(input(f"  M (entier < {p}) : "))
            except ValueError: continue
            c1, c2 = chiffrer(p, g, y, M)
            print(f"  C1={c1}, C2={c2}")
        elif choix == "3":
            if not p: print("  Generez les cles."); continue
            try: c1, c2 = int(input("  C1: ")), int(input("  C2: "))
            except ValueError: continue
            print(f"  M = {dechiffrer(p, x, c1, c2)}")
        elif choix == "4":
            if not p: p, g, x, y = gen_cles()
            a = chiffrer(p, g, y, 42); b = chiffrer(p, g, y, 42)
            print(f"  E(42) = {a}\n  E(42) = {b}\n  Identiques: {a==b}")
        elif choix == "5":
            if not p: p, g, x, y = gen_cles()
            c1, c2 = chiffrer(p, g, y, 100); d1, d2 = chiffrer(p, g, y, 200)
            M = dechiffrer(p, x, (c1*d1)%p, (c2*d2)%p)
            print(f"  D(E(100)*E(200)) = {M}, 100*200 mod p = {(100*200)%p}")
        elif choix == "0": break

def main():
    print("\n  TP3 - EXERCICE 3.3 : ELGAMAL")
    mode_interactif()

if __name__ == "__main__":
    main()
