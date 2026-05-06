"""TP2 - Ex2.4 : Finalistes AES (NIST)"""
import os, time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
try:
    import twofish as tf
    HAS_TF = True
except ImportError:
    HAS_TF = False

def mode_interactif():
    while True:
        print("\n" + "=" * 50)
        print("  FINALISTES AES")
        print("=" * 50)
        print("  1. Chiffrer Rijndael (AES)\n  2. Chiffrer Twofish")
        print("  3. Benchmark\n  4. Etude comparative\n  0. Quitter")
        choix = input("\n  Choix : ").strip()
        if choix == "1":
            msg = input("  Message : ").encode()
            k = get_random_bytes(16)
            c = AES.new(k, AES.MODE_ECB).encrypt(pad(msg, 16))
            print(f"  Cle: {k.hex()}\n  Chiffre: {c.hex()}")
        elif choix == "2":
            if not HAS_TF: print("  pip install twofish"); continue
            msg = input("  Message : ").encode()
            k = get_random_bytes(16)
            t = tf.Twofish(k)
            blocs = pad(msg, 16)
            c = b"".join(t.encrypt(blocs[i:i+16]) for i in range(0, len(blocs), 16))
            print(f"  Cle: {k.hex()}\n  Chiffre: {c.hex()}")
        elif choix == "3":
            data = pad(os.urandom(1024*1024), 16)
            k = get_random_bytes(16)
            t0 = time.perf_counter()
            AES.new(k, AES.MODE_ECB).encrypt(data)
            print(f"  Rijndael: {time.perf_counter()-t0:.4f}s")
            if HAS_TF:
                t_obj = tf.Twofish(k)
                t0 = time.perf_counter()
                for i in range(0, len(data), 16): t_obj.encrypt(data[i:i+16])
                print(f"  Twofish: {time.perf_counter()-t0:.4f}s")
        elif choix == "4":
            print("""
  Rijndael (AES) : SPN, 10/12/14 tours, gagnant NIST
  Serpent : 32 tours, plus conservateur, plus lent
  Twofish : Feistel, 16 tours, S-boxes dynamiques
  RC6 : 20 tours, brevete (frein adoption)
  MARS : structure heterogene (IBM)
  -> Rijndael gagne pour son ratio performance/securite
            """)
        elif choix == "0": break

def main():
    print("\n  TP2 - EXERCICE 2.4 : FINALISTES AES")
    mode_interactif()

if __name__ == "__main__":
    main()
