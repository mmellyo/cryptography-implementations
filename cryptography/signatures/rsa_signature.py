"""RSA digital signatures: PKCS#1 v1.5 (deterministic) and PSS (probabilistic)."""
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def generer_cles(taille_bits: int = 2048):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=taille_bits)
    return priv, priv.public_key()


def signer_pkcs1v15(priv, message: bytes) -> bytes:
    return priv.sign(message, padding.PKCS1v15(), hashes.SHA256())


def verifier_pkcs1v15(pub, message: bytes, signature: bytes) -> bool:
    try:
        pub.verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def signer_pss(priv, message: bytes) -> bytes:
    return priv.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verifier_pss(pub, message: bytes, signature: bytes) -> bool:
    try:
        pub.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def demo():
    print("\n" + "=" * 50)
    print("  RSA signatures (PKCS#1 v1.5 + PSS)")
    print("=" * 50)
    priv, pub = generer_cles()
    msg = b"Document a signer"

    sig_pkcs = signer_pkcs1v15(priv, msg)
    sig_pss = signer_pss(priv, msg)

    print(f"\n  PKCS#1 v1.5 deterministe : {sig_pkcs == signer_pkcs1v15(priv, msg)}")
    print(f"  PSS probabiliste         : {sig_pss != signer_pss(priv, msg)}")
    print(f"  Verif PKCS#1 v1.5        : {verifier_pkcs1v15(pub, msg, sig_pkcs)}")
    print(f"  Verif PSS                : {verifier_pss(pub, msg, sig_pss)}")
    print(f"  Tamper PKCS#1 v1.5       : {verifier_pkcs1v15(pub, b'modifie', sig_pkcs)}")
    print(f"  Tamper PSS               : {verifier_pss(pub, b'modifie', sig_pss)}")


if __name__ == "__main__":
    demo()
