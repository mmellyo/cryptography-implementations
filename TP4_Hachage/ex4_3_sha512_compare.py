"""TP4 - Ex4.3 : SHA-512 et comparaison"""
import hashlib, os, time

def mode_interactif():
    while True:
        print("\n" + "=" * 50)
        print("  SHA-512 ET COMPARAISON")
        print("=" * 50)
        print("  1. Calculer (MD5/SHA-256/SHA-512)\n  2. Benchmark 100 Mo")
        print("  3. Effet avalanche\n  0. Quitter")
        choix = input("\n  Choix : ").strip()
        if choix == "1":
            msg = input("  Message : ").encode()
            print(f"  MD5    : {hashlib.md5(msg).hexdigest()}")
            print(f"  SHA-256: {hashlib.sha256(msg).hexdigest()}")
            print(f"  SHA-512: {hashlib.sha512(msg).hexdigest()}")
        elif choix == "2":
            print("  Generation 100 Mo...")
            data = os.urandom(100*1024*1024)
            for n, f in [("MD5",hashlib.md5),("SHA-256",hashlib.sha256),("SHA-512",hashlib.sha512)]:
                t0 = time.perf_counter(); f(data).hexdigest()
                print(f"  {n:10s}: {time.perf_counter()-t0:.4f}s")
        elif choix == "3":
            msg = input("  Message : ").encode()
            mod = bytearray(msg); mod[0] ^= 1; mod = bytes(mod)
            for n, f in [("MD5",hashlib.md5),("SHA-256",hashlib.sha256),("SHA-512",hashlib.sha512)]:
                h1, h2 = f(msg).hexdigest(), f(mod).hexdigest()
                bits = sum(bin(int(a,16)^int(b,16)).count('1') for a,b in zip(h1,h2))
                print(f"  {n:10s}: {bits}/{len(h1)*4} bits ({bits*100//(len(h1)*4)}%)")
        elif choix == "0": break

def main():
    print("\n  TP4 - EXERCICE 4.3 : SHA-512 ET COMPARAISON")
    mode_interactif()

if __name__ == "__main__":
    main()
