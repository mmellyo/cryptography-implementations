"""TP2 - Ex2.1 : RC4 (from scratch)"""
import os
from collections import Counter

def ksa(cle):
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + cle[i % len(cle)]) % 256
        S[i], S[j] = S[j], S[i]
    return S

def prga(S, n):
    i = j = 0
    ks = []
    for _ in range(n):
        i = (i+1) % 256; j = (j+S[i]) % 256
        S[i], S[j] = S[j], S[i]
        ks.append(S[(S[i]+S[j]) % 256])
    return ks

def rc4(cle, data):
    return bytes(d ^ k for d, k in zip(data, prga(ksa(cle), len(data))))

def mode_interactif():
    while True:
        print("\n" + "=" * 50)
        print("  RC4")
        print("=" * 50)
        print("  1. Chiffrer\n  2. Dechiffrer (hex)\n  3. Biais statistiques")
        print("  4. Theorie\n  0. Quitter")
        choix = input("\n  Choix : ").strip()
        if choix == "1":
            msg = input("  Message : ")
            cle = input("  Cle : ")
            c = rc4(cle.encode(), msg.encode())
            print(f"  Chiffre (hex): {c.hex()}")
        elif choix == "2":
            try:
                c = bytes.fromhex(input("  Chiffre (hex) : ").strip())
                k = input("  Cle : ")
                print(f"  Dechiffre : {rc4(k.encode(), c).decode('utf-8', errors='replace')}")
            except Exception as e: print(f"  Erreur : {e}")
        elif choix == "3":
            cpt = Counter()
            for _ in range(10000):
                cpt[prga(ksa(os.urandom(16)), 3)[1]] += 1
            att = 10000/256
            print(f"  2e octet=0 : {cpt[0]} (attendu {att:.0f}, ratio {cpt[0]/att:.2f}x)")
            print(f"  -> Biais confirme (raison du ban dans TLS 1.3)")
        elif choix == "4":
            print("  KSA+PRGA from scratch, banni pour biais statistiques et WEP")
        elif choix == "0": break

def main():
    print("\n  TP2 - EXERCICE 2.1 : RC4")
    mode_interactif()

if __name__ == "__main__":
    main()
