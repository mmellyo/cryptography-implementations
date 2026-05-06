"""TP4 - Ex4.1 : MD5 (hashlib)"""
import hashlib

def mode_interactif():
    while True:
        print("\n" + "=" * 50)
        print("  MD5")
        print("=" * 50)
        print("  1. Calculer MD5\n  2. Verifier integrite\n  3. Effet avalanche")
        print("  4. Theorie\n  0. Quitter")
        choix = input("\n  Choix : ").strip()
        if choix == "1":
            msg = input("  Message : ")
            print(f"  MD5 = {hashlib.md5(msg.encode()).hexdigest()}")
        elif choix == "2":
            h1 = input("  Hash attendu : ").strip()
            h2 = input("  Hash a verifier : ").strip()
            print(f"  {'MATCH' if h1.lower()==h2.lower() else 'ECHEC'}")
        elif choix == "3":
            msg = input("  Message : ").encode()
            h1 = hashlib.md5(msg).hexdigest()
            mod = bytearray(msg); mod[0] ^= 1
            h2 = hashlib.md5(bytes(mod)).hexdigest()
            bits = sum(bin(int(a,16)^int(b,16)).count('1') for a,b in zip(h1,h2))
            print(f"  {bits}/128 bits differents ({bits*100//128}%)")
        elif choix == "4":
            print("  128 bits, Merkle-Damgard, CASSE (Wang 2004), checksums uniquement")
        elif choix == "0": break

def main():
    print("\n  TP4 - EXERCICE 4.1 : MD5")
    mode_interactif()

if __name__ == "__main__":
    main()
