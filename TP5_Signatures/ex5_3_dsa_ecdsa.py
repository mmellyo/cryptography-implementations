"""TP5 - Ex5.3 : DSA et ECDSA (cryptography lib)"""
import time
from cryptography.hazmat.primitives.asymmetric import dsa, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

def mode_interactif():
    while True:
        print("\n" + "=" * 50)
        print("  DSA / ECDSA")
        print("=" * 50)
        print("  1. Signer DSA\n  2. Signer ECDSA P-256\n  3. ECDSA multi-courbes")
        print("  4. Benchmark\n  0. Quitter")
        choix = input("\n  Choix : ").strip()
        if choix == "1":
            msg = input("  Message : ").encode()
            priv = dsa.generate_private_key(key_size=2048)
            pub = priv.public_key()
            sig = priv.sign(msg, hashes.SHA256())
            print(f"  Signature: {sig.hex()[:50]}... ({len(sig)} octets)")
            try: pub.verify(sig, msg, hashes.SHA256()); print("  Valide: True")
            except InvalidSignature: print("  Valide: False")
        elif choix == "2":
            msg = input("  Message : ").encode()
            priv = ec.generate_private_key(ec.SECP256R1())
            pub = priv.public_key()
            sig = priv.sign(msg, ec.ECDSA(hashes.SHA256()))
            print(f"  Signature: {sig.hex()[:50]}... ({len(sig)} octets)")
            try: pub.verify(sig, msg, ec.ECDSA(hashes.SHA256())); print("  Valide: True")
            except InvalidSignature: print("  Valide: False")
        elif choix == "3":
            courbes = {"1":(ec.SECP256R1(),"P-256"),"2":(ec.SECP384R1(),"P-384"),"3":(ec.SECP521R1(),"P-521")}
            print("  1. P-256  2. P-384  3. P-521")
            c = input("  Courbe : ").strip()
            if c not in courbes: continue
            msg = input("  Message : ").encode()
            priv = ec.generate_private_key(courbes[c][0])
            sig = priv.sign(msg, ec.ECDSA(hashes.SHA256()))
            pk = priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
            print(f"  {courbes[c][1]}: cle {len(pk)}o, sig {len(sig)}o")
        elif choix == "4":
            msg = b"Benchmark"
            pd = dsa.generate_private_key(key_size=2048)
            pe = ec.generate_private_key(ec.SECP256R1())
            t0 = time.perf_counter()
            for _ in range(100): sd = pd.sign(msg, hashes.SHA256())
            td = (time.perf_counter()-t0)/100*1000
            t0 = time.perf_counter()
            for _ in range(100): se = pe.sign(msg, ec.ECDSA(hashes.SHA256()))
            te = (time.perf_counter()-t0)/100*1000
            print(f"  DSA-2048: {td:.2f}ms | ECDSA P-256: {te:.2f}ms")
        elif choix == "0": break

def main():
    print("\n  TP5 - EXERCICE 5.3 : DSA ET ECDSA")
    mode_interactif()

if __name__ == "__main__":
    main()
