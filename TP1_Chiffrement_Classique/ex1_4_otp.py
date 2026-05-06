"""TP1 - Ex1.4 : One-Time Pad (from scratch)"""
import os, string

def generer_cle(n): return os.urandom(n)
def chiffrer_otp(msg, cle): return bytes(m ^ k for m, k in zip(msg, cle))
def dechiffrer_otp(c, cle): return chiffrer_otp(c, cle)

def crib_drag(xor_data, crib):
    results = []
    for i in range(len(xor_data) - len(crib) + 1):
        frag = bytes(c ^ b for c, b in zip(xor_data[i:], crib))
        try:
            t = frag[:len(crib)].decode('ascii', errors='strict')
            if all(c in string.printable for c in t): results.append((i, t))
        except: pass
    return results

def mode_interactif():
    while True:
        print("\n" + "=" * 50)
        print("  ONE-TIME PAD")
        print("=" * 50)
        print("  1. Chiffrer\n  2. Dechiffrer (hex)\n  3. Demo reutilisation")
        print("  4. Theorie\n  0. Quitter")
        choix = input("\n  Choix : ").strip()
        if choix == "1":
            msg = input("  Message : ").encode()
            cle = generer_cle(len(msg))
            c = chiffrer_otp(msg, cle)
            print(f"  Cle (hex)    : {cle.hex()}")
            print(f"  Chiffre (hex): {c.hex()}")
        elif choix == "2":
            try:
                c = bytes.fromhex(input("  Chiffre (hex) : ").strip())
                k = bytes.fromhex(input("  Cle (hex) : ").strip())
                print(f"  Dechiffre : {dechiffrer_otp(c, k).decode('utf-8', errors='replace')}")
            except Exception as e: print(f"  Erreur : {e}")
        elif choix == "3":
            m1 = input("  Message 1 : ").encode()
            m2 = input("  Message 2 : ").encode()
            ml = max(len(m1), len(m2))
            m1, m2 = m1.ljust(ml), m2.ljust(ml)
            cle = generer_cle(ml)
            c1, c2 = chiffrer_otp(m1, cle), chiffrer_otp(m2, cle)
            xor = bytes(a^b for a,b in zip(c1,c2))
            print(f"  C1 XOR C2 == M1 XOR M2 : {xor == bytes(a^b for a,b in zip(m1,m2))}")
            print(f"  -> La cle est eliminee !")
            crib = input("  Mot a tester (crib) : ").encode()
            for pos, t in crib_drag(xor, crib)[:5]:
                print(f"    Pos {pos} -> '{t}'")
        elif choix == "4":
            print("  - Cle = |message|, aleatoire, usage unique -> securite parfaite")
            print("  - Reutilisation -> C1 XOR C2 = M1 XOR M2, crib dragging")
        elif choix == "0": break

def main():
    print("\n  TP1 - EXERCICE 1.4 : ONE-TIME PAD")
    mode_interactif()

if __name__ == "__main__":
    main()
