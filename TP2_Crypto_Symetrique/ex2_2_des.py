"""TP2 - Ex2.2 : DES / Triple-DES (pycryptodome)"""
import os, time
from Crypto.Cipher import DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def mode_interactif():
    while True:
        print("\n" + "=" * 50)
        print("  DES / TRIPLE-DES")
        print("=" * 50)
        print("  1. Chiffrer DES-CBC\n  2. Dechiffrer DES-CBC\n  3. Chiffrer 3DES-CBC")
        print("  4. Faiblesse ECB\n  5. Benchmark\n  0. Quitter")
        choix = input("\n  Choix : ").strip()
        if choix == "1":
            msg = input("  Message : ")
            k, iv = get_random_bytes(8), get_random_bytes(8)
            c = DES.new(k, DES.MODE_CBC, iv=iv).encrypt(pad(msg.encode(), 8))
            print(f"  Cle: {k.hex()}\n  IV: {iv.hex()}\n  Chiffre: {c.hex()}")
        elif choix == "2":
            try:
                c = bytes.fromhex(input("  Chiffre (hex) : "))
                k = bytes.fromhex(input("  Cle (hex) : "))
                iv = bytes.fromhex(input("  IV (hex) : "))
                print(f"  Dechiffre : {unpad(DES.new(k, DES.MODE_CBC, iv=iv).decrypt(c), 8).decode()}")
            except Exception as e: print(f"  Erreur : {e}")
        elif choix == "3":
            msg = input("  Message : ")
            k = DES3.adjust_key_parity(get_random_bytes(24))
            iv = get_random_bytes(8)
            c = DES3.new(k, DES3.MODE_CBC, iv=iv).encrypt(pad(msg.encode(), 8))
            print(f"  Cle: {k.hex()}\n  IV: {iv.hex()}\n  Chiffre: {c.hex()}")
        elif choix == "4":
            msg = b"A"*64 + b"B"*64
            k = get_random_bytes(8)
            ecb = DES.new(k, DES.MODE_ECB).encrypt(pad(msg, 8))
            be = [ecb[i:i+8] for i in range(0, len(ecb), 8)]
            print(f"  ECB: {len(be)} blocs, {len(set(be))} uniques -> motifs visibles !")
        elif choix == "5":
            data = pad(os.urandom(1024*1024), 8)
            k1, k3 = get_random_bytes(8), DES3.adjust_key_parity(get_random_bytes(24))
            t0 = time.perf_counter()
            DES.new(k1, DES.MODE_CBC, iv=get_random_bytes(8)).encrypt(data)
            td = time.perf_counter()-t0
            t0 = time.perf_counter()
            DES3.new(k3, DES3.MODE_CBC, iv=get_random_bytes(8)).encrypt(data)
            t3 = time.perf_counter()-t0
            print(f"  DES: {td:.4f}s | 3DES: {t3:.4f}s | Ratio: {t3/td:.1f}x")
        elif choix == "0": break

def main():
    print("\n  TP2 - EXERCICE 2.2 : DES / TRIPLE-DES")
    mode_interactif()

if __name__ == "__main__":
    main()
