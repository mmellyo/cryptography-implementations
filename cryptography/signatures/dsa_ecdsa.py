"""DSA and ECDSA signatures with multi-curve benchmarking."""
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec


COURBES = {
    "P-256": ec.SECP256R1(),
    "P-384": ec.SECP384R1(),
    "P-521": ec.SECP521R1(),
}


def signer_dsa(message: bytes, taille_bits: int = 2048):
    priv = dsa.generate_private_key(key_size=taille_bits)
    return priv, priv.public_key(), priv.sign(message, hashes.SHA256())


def verifier_dsa(pub, message: bytes, signature: bytes) -> bool:
    try:
        pub.verify(signature, message, hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def signer_ecdsa(message: bytes, courbe_nom: str = "P-256"):
    if courbe_nom not in COURBES:
        raise ValueError(f"Courbe inconnue : {courbe_nom}")
    priv = ec.generate_private_key(COURBES[courbe_nom])
    return priv, priv.public_key(), priv.sign(message, ec.ECDSA(hashes.SHA256()))


def verifier_ecdsa(pub, message: bytes, signature: bytes) -> bool:
    try:
        pub.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def benchmark(message: bytes = b"Benchmark", iterations: int = 100):
    pd = dsa.generate_private_key(key_size=2048)
    pe = ec.generate_private_key(ec.SECP256R1())
    t0 = time.perf_counter()
    for _ in range(iterations):
        pd.sign(message, hashes.SHA256())
    td = (time.perf_counter() - t0) / iterations * 1000
    t0 = time.perf_counter()
    for _ in range(iterations):
        pe.sign(message, ec.ECDSA(hashes.SHA256()))
    te = (time.perf_counter() - t0) / iterations * 1000
    return {"DSA-2048": td, "ECDSA P-256": te}


def demo():
    print("\n" + "=" * 50)
    print("  DSA / ECDSA")
    print("=" * 50)
    msg = b"Document a signer"

    print("\n  DSA-2048 :")
    _, pub_d, sig_d = signer_dsa(msg)
    print(f"  Signature : {len(sig_d)} octets")
    print(f"  Verif     : {verifier_dsa(pub_d, msg, sig_d)}")
    print(f"  Tamper    : {verifier_dsa(pub_d, b'autre', sig_d)}")

    print("\n  ECDSA multi-courbes :")
    for nom in COURBES:
        _, pub, sig = signer_ecdsa(msg, nom)
        pk_octets = pub.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )
        print(f"  {nom:6s} : cle pub {len(pk_octets):3d}o | sig {len(sig):3d}o | verif {verifier_ecdsa(pub, msg, sig)}")

    print("\n  Benchmark (100 iterations) :")
    for nom, dt in benchmark(msg).items():
        print(f"  {nom:12s} : {dt:.2f} ms / signature")


if __name__ == "__main__":
    demo()
