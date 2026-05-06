"""TP5 - Ex5.1 : Signature RSA-PSS (cryptography lib)"""
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

def gen_cles(sz=2048):
    p = rsa.generate_private_key(public_exponent=65537, key_size=sz)
    return p, p.public_key()

def signer(priv, msg):
    return priv.sign(msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())

def verifier(pub, msg, sig):
    try:
        pub.verify(sig, msg, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True
    except InvalidSignature: return False

def mode_interactif():
    priv = pub = None
    while True:
        print("\n" + "=" * 50)
        print("  SIGNATURE RSA-PSS")
        print("=" * 50)
        print("  1. Generer cles\n  2. Signer\n  3. Verifier")
        print("  4. Demo falsification\n  0. Quitter")
        choix = input("\n  Choix : ").strip()
        if choix == "1":
            priv, pub = gen_cles(); print("  Cles RSA-2048 generees.")
        elif choix == "2":
            if not priv: priv, pub = gen_cles()
            msg = input("  Message : ").encode()
            sig = signer(priv, msg)
            print(f"  Signature: {sig.hex()[:60]}...\n  Valide: {verifier(pub, msg, sig)}")
        elif choix == "3":
            if not pub: print("  Generez les cles."); continue
            msg = input("  Message : ").encode()
            try:
                sig = bytes.fromhex(input("  Signature (hex) : "))
                print(f"  Valide : {verifier(pub, msg, sig)}")
            except Exception as e: print(f"  Erreur : {e}")
        elif choix == "4":
            if not priv: priv, pub = gen_cles()
            msg = b"Message original"
            sig = signer(priv, msg)
            print(f"  Original: {verifier(pub, msg, sig)}")
            print(f"  Modifie: {verifier(pub, b'Modifie', sig)}")
            s2 = bytearray(sig); s2[0] ^= 0xFF
            print(f"  Sig alteree: {verifier(pub, msg, bytes(s2))}")
            print(f"  PSS probabiliste: {signer(priv,msg) != signer(priv,msg)}")
        elif choix == "0": break

def main():
    print("\n  TP5 - EXERCICE 5.1 : SIGNATURE RSA-PSS")
    mode_interactif()

if __name__ == "__main__":
    main()
