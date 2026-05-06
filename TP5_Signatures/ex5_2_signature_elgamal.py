"""TP5 - Ex5.2 : Signature ElGamal (from scratch)"""
import os, hashlib
from sympy import nextprime, primitive_root
from math import gcd

def _eea(a, b):
    if a == 0: return b, 0, 1
    g, x, y = _eea(b%a, a)
    return g, y-(b//a)*x, x

def inv_mod(a, m):
    g, x, _ = _eea(a%m, m)
    if g != 1: raise ValueError("Pas d'inverse")
    return x % m

def gen_cles(bits=64):
    seed = int.from_bytes(os.urandom(max(bits//8,8)),'big') | (1<<(bits-1))
    p = nextprime(seed); g = primitive_root(p)
    x = int.from_bytes(os.urandom((p.bit_length()+7)//8),'big') % (p-3) + 2
    return p, g, x, pow(g, x, p)

def hacher(msg, p):
    return int(hashlib.sha256(msg).hexdigest(), 16) % (p-1)

def signer(p, g, x, msg):
    h = hacher(msg, p)
    nb = (p.bit_length()+7)//8
    while True:
        k = int.from_bytes(os.urandom(nb),'big')%(p-2)+1
        if gcd(k,p-1)==1: break
    r = pow(g, k, p)
    return r, ((h - x*r) * inv_mod(k, p-1)) % (p-1)

def verifier(p, g, y, msg, r, s):
    if not (0 < r < p): return False
    return (pow(y,r,p)*pow(r,s,p))%p == pow(g, hacher(msg,p), p)

def mode_interactif():
    p = g = x = y = None
    while True:
        print("\n" + "=" * 50)
        print("  SIGNATURE ELGAMAL")
        print("=" * 50)
        print("  1. Generer cles\n  2. Signer\n  3. Verifier")
        print("  4. Demo falsification\n  0. Quitter")
        choix = input("\n  Choix : ").strip()
        if choix == "1":
            try: bits = int(input("  Bits (ex: 64) : "))
            except ValueError: bits = 64
            p, g, x, y = gen_cles(bits)
            print(f"  p={p}, g={g}, x={x}, y={y}")
        elif choix == "2":
            if not p: p, g, x, y = gen_cles()
            msg = input("  Message : ").encode()
            r, s = signer(p, g, x, msg)
            print(f"  (r={r}, s={s})\n  Valide: {verifier(p,g,y,msg,r,s)}")
        elif choix == "3":
            if not p: print("  Generez les cles."); continue
            msg = input("  Message : ").encode()
            try: r, s = int(input("  r: ")), int(input("  s: "))
            except ValueError: continue
            print(f"  Valide: {verifier(p,g,y,msg,r,s)}")
        elif choix == "4":
            if not p: p, g, x, y = gen_cles()
            msg = b"Test"
            r, s = signer(p, g, x, msg)
            print(f"  Original: {verifier(p,g,y,msg,r,s)}")
            print(f"  Modifie: {verifier(p,g,y,b'X',r,s)}")
            r2, s2 = signer(p, g, x, msg)
            print(f"  Non-deterministe: {(r,s)!=(r2,s2)}")
        elif choix == "0": break

def main():
    print("\n  TP5 - EXERCICE 5.2 : SIGNATURE ELGAMAL")
    mode_interactif()

if __name__ == "__main__":
    main()
