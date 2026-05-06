"""TP2 - Ex2.3 : AES (pycryptodome)"""
import os, time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def mode_interactif():
    while True:
        print("\n" + "=" * 50)
        print("  AES")
        print("=" * 50)
        print("  1. Chiffrer (CBC)\n  2. Dechiffrer (CBC)\n  3. Chiffrer (CTR)")
        print("  4. Dechiffrer (CTR)\n  5. Avalanche CBC\n  6. Nonce-reuse CTR")
        print("  7. Benchmark\n  8. ECB vs CBC\n  0. Quitter")
        choix = input("\n  Choix : ").strip()
        if choix == "1":
            msg = input("  Message : ")
            k, iv = get_random_bytes(32), get_random_bytes(16)
            c = AES.new(k, AES.MODE_CBC, iv=iv).encrypt(pad(msg.encode(), 16))
            print(f"  Cle: {k.hex()}\n  IV: {iv.hex()}\n  Chiffre: {c.hex()}")
        elif choix == "2":
            try:
                c = bytes.fromhex(input("  Chiffre: "))
                k = bytes.fromhex(input("  Cle: "))
                iv = bytes.fromhex(input("  IV: "))
                print(f"  Dechiffre: {unpad(AES.new(k, AES.MODE_CBC, iv=iv).decrypt(c), 16).decode()}")
            except Exception as e: print(f"  Erreur: {e}")
        elif choix == "3":
            msg = input("  Message : ")
            k = get_random_bytes(32)
            ci = AES.new(k, AES.MODE_CTR)
            c = ci.encrypt(msg.encode())
            print(f"  Cle: {k.hex()}\n  Nonce: {ci.nonce.hex()}\n  Chiffre: {c.hex()}")
        elif choix == "4":
            try:
                c = bytes.fromhex(input("  Chiffre: "))
                k = bytes.fromhex(input("  Cle: "))
                n = bytes.fromhex(input("  Nonce: "))
                print(f"  Dechiffre: {AES.new(k, AES.MODE_CTR, nonce=n).decrypt(c).decode()}")
            except Exception as e: print(f"  Erreur: {e}")
        elif choix == "5":
            k = get_random_bytes(32)
            iv1 = get_random_bytes(16)
            iv2 = bytearray(iv1); iv2[0] ^= 1; iv2 = bytes(iv2)
            msg = pad(b"Test avalanche CBC!", 16)
            c1 = AES.new(k, AES.MODE_CBC, iv=iv1).encrypt(msg)
            c2 = AES.new(k, AES.MODE_CBC, iv=iv2).encrypt(msg)
            for i in range(len(c1)//16):
                diff = sum(bin(a^b).count('1') for a,b in zip(c1[i*16:(i+1)*16], c2[i*16:(i+1)*16]))
                print(f"  Bloc {i}: {diff}/128 bits ({diff*100//128}%)")
        elif choix == "6":
            k, n = get_random_bytes(32), get_random_bytes(8)
            m1 = input("  Msg 1: ").encode()
            m2 = input("  Msg 2: ").encode()
            ml = min(len(m1), len(m2))
            c1 = AES.new(k, AES.MODE_CTR, nonce=n).encrypt(m1[:ml])
            c2 = AES.new(k, AES.MODE_CTR, nonce=n).encrypt(m2[:ml])
            print(f"  C1^C2 == M1^M2: {bytes(a^b for a,b in zip(c1,c2)) == bytes(a^b for a,b in zip(m1[:ml],m2[:ml]))}")
            print(f"  -> JAMAIS reutiliser un nonce !")
        elif choix == "7":
            data = os.urandom(10*1024*1024)
            for sz, nm in [(16,"128"),(24,"192"),(32,"256")]:
                t0 = time.perf_counter()
                AES.new(get_random_bytes(sz), AES.MODE_CTR).encrypt(data)
                print(f"  AES-{nm}: {time.perf_counter()-t0:.4f}s")
        elif choix == "8":
            msg = b"A"*48
            k = get_random_bytes(16)
            ecb = AES.new(k, AES.MODE_ECB).encrypt(pad(msg, 16))
            cbc = AES.new(k, AES.MODE_CBC, iv=get_random_bytes(16)).encrypt(pad(msg, 16))
            be = [ecb[i:i+16] for i in range(0,len(ecb),16)]
            bc = [cbc[i:i+16] for i in range(0,len(cbc),16)]
            print(f"  ECB: {len(set(be))}/{len(be)} uniques | CBC: {len(set(bc))}/{len(bc)} uniques")
        elif choix == "0": break

def main():
    print("\n  TP2 - EXERCICE 2.3 : AES")
    mode_interactif()

if __name__ == "__main__":
    main()
