"""TP3 - Ex3.1 : Diffie-Hellman (from scratch)"""
import os
from sympy import nextprime, primitive_root

def gen_priv(p):
    return int.from_bytes(os.urandom((p.bit_length()+7)//8), 'big') % (p-2) + 2

def mode_interactif():
    p = g = None
    while True:
        print("\n" + "=" * 50)
        print("  DIFFIE-HELLMAN")
        print("=" * 50)
        print("  1. Generer (p, g)\n  2. Echange Alice-Bob\n  3. Attaque MITM")
        print("  4. Calcul manuel\n  0. Quitter")
        choix = input("\n  Choix : ").strip()
        if choix == "1":
            try: bits = int(input("  Bits (ex: 64) : "))
            except ValueError: bits = 64
            seed = int.from_bytes(os.urandom(max(bits//8,8)), 'big') | (1<<(bits-1))
            p = nextprime(seed); g = primitive_root(p)
            print(f"  p = {p}\n  g = {g}")
        elif choix == "2":
            if not p: print("  Generez d'abord (option 1)"); continue
            a, b = gen_priv(p), gen_priv(p)
            A, B = pow(g,a,p), pow(g,b,p)
            Ka, Kb = pow(B,a,p), pow(A,b,p)
            print(f"  A={A}, B={B}\n  K_alice={Ka}, K_bob={Kb}, Match={Ka==Kb}")
        elif choix == "3":
            if not p: print("  Generez d'abord (option 1)"); continue
            a, b = gen_priv(p), gen_priv(p)
            e1, e2 = gen_priv(p), gen_priv(p)
            A, B = pow(g,a,p), pow(g,b,p)
            Ka = pow(pow(g,e1,p),a,p); Kb = pow(pow(g,e2,p),b,p)
            print(f"  K_alice={Ka}, K_bob={Kb}, Match={Ka==Kb}")
            print(f"  -> Eve intercepte, Alice et Bob ont des cles DIFFERENTES")
        elif choix == "4":
            try:
                pi = int(input("  p = ")); gi = int(input("  g = "))
                x = int(input("  Cle privee = "))
                print(f"  Cle publique = {pow(gi,x,pi)}")
                o = input("  Cle publique de l'autre (vide=skip) : ").strip()
                if o: print(f"  Secret = {pow(int(o),x,pi)}")
            except Exception as e: print(f"  Erreur : {e}")
        elif choix == "0": break

def main():
    print("\n  TP3 - EXERCICE 3.1 : DIFFIE-HELLMAN")
    mode_interactif()

if __name__ == "__main__":
    main()
