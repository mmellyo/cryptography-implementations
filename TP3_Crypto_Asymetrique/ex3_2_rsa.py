"""TP3 - Ex3.2 : RSA (cryptography lib)"""
import os, time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def gen_cles(sz=2048):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=sz)
    return priv, priv.public_key()

def enc_rsa(pub, msg):
    return pub.encrypt(msg, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def dec_rsa(priv, c):
    return priv.decrypt(c, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))

def mode_interactif():
    priv = pub = None
    while True:
        print("\n" + "=" * 50)
        print("  RSA")
        print("=" * 50)
        print("  1. Generer cles\n  2. Chiffrer\n  3. Dechiffrer")
        print("  4. Hybride RSA+AES (1 Mo)\n  5. Theorie\n  0. Quitter")
        choix = input("\n  Choix : ").strip()
        if choix == "1":
            try: sz = int(input("  Taille (1024/2048) : "))
            except ValueError: sz = 2048
            priv, pub = gen_cles(sz)
            print(f"  Cles RSA-{sz} generees.")
        elif choix == "2":
            if not pub: priv, pub = gen_cles(); print("  Cles auto-generees.")
            msg = input("  Message (max ~190 car) : ")
            try:
                c = enc_rsa(pub, msg.encode())
                print(f"  Chiffre: {c.hex()[:80]}...")
            except Exception as e: print(f"  Erreur: {e}")
        elif choix == "3":
            if not priv: print("  Generez les cles d'abord."); continue
            try:
                d = dec_rsa(priv, bytes.fromhex(input("  Chiffre (hex): ")))
                print(f"  Dechiffre: {d.decode()}")
            except Exception as e: print(f"  Erreur: {e}")
        elif choix == "4":
            if not pub: priv, pub = gen_cles()
            data = os.urandom(1024*1024)
            ka = os.urandom(32); nonce = os.urandom(16)
            kc = enc_rsa(pub, ka)
            dc = Cipher(algorithms.AES(ka), modes.CTR(nonce)).encryptor().update(data)
            kd = dec_rsa(priv, kc)
            dd = Cipher(algorithms.AES(kd), modes.CTR(nonce)).decryptor().update(dc)
            print(f"  1 Mo chiffre/dechiffre, integrite: {data == dd}")
        elif choix == "5":
            print("  RSA-OAEP: probabiliste, IND-CCA2, max ~190o pour RSA-2048")
            print("  Hybride RSA+AES pour les grands messages")
        elif choix == "0": break

def main():
    print("\n  TP3 - EXERCICE 3.2 : RSA")
    mode_interactif()

if __name__ == "__main__":
    main()
