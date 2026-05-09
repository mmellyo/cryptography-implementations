"""Diffie-Hellman key exchange with MITM attack and ECDSA-authenticated variant."""
import secrets

from sympy import nextprime, primitive_root

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

MIN_BITS = 512


def generer_p_g(bits: int = MIN_BITS):
    if bits < MIN_BITS:
        raise ValueError(f"DH : taille minimale {MIN_BITS} bits")
    seed = secrets.randbits(bits) | (1 << (bits - 1)) | 1
    p = int(nextprime(seed))
    g = int(primitive_root(p))
    return p, g


def cle_privee(p: int) -> int:
    return secrets.randbelow(p - 3) + 2


def echange(p: int, g: int):
    a = cle_privee(p)
    b = cle_privee(p)
    A = pow(g, a, p)
    B = pow(g, b, p)
    Ka = pow(B, a, p)
    Kb = pow(A, b, p)
    return a, b, A, B, Ka, Kb


def attaque_mitm(p: int, g: int):
    a, b = cle_privee(p), cle_privee(p)
    e1, e2 = cle_privee(p), cle_privee(p)
    Ap = pow(g, e1, p)
    Bp = pow(g, e2, p)
    Ka = pow(Bp, a, p)
    Kb = pow(Ap, b, p)
    Ke_alice = pow(pow(g, a, p), e1, p)
    Ke_bob = pow(pow(g, b, p), e2, p)
    return Ka, Kb, Ke_alice, Ke_bob


def echange_authentifie(p: int, g: int):
    sk_alice = ec.generate_private_key(ec.SECP256R1())
    sk_bob = ec.generate_private_key(ec.SECP256R1())
    pk_alice, pk_bob = sk_alice.public_key(), sk_bob.public_key()

    a, b = cle_privee(p), cle_privee(p)
    A, B = pow(g, a, p), pow(g, b, p)

    sig_a = sk_alice.sign(_int_bytes(A), ec.ECDSA(hashes.SHA256()))
    sig_b = sk_bob.sign(_int_bytes(B), ec.ECDSA(hashes.SHA256()))

    if not (_verifier(pk_alice, A, sig_a) and _verifier(pk_bob, B, sig_b)):
        return False, None
    return True, pow(B, a, p)


def _int_bytes(v: int) -> bytes:
    return v.to_bytes((v.bit_length() + 7) // 8, "big")


def _verifier(pk, valeur, signature) -> bool:
    try:
        pk.verify(signature, _int_bytes(valeur), ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def demo():
    print("\n" + "=" * 50)
    print("  Diffie-Hellman")
    print("=" * 50)
    # On utilise le premier de Mersenne 2^31-1 pour la demo (rapidite).
    # En production : generer_p_g(MIN_BITS) avec MIN_BITS = 512 ou plus.
    p, g = 2147483647, 7
    print(f"\n  Parametres demo : p = {p} ({p.bit_length()} bits), g = {g}")
    _, _, _, _, Ka, Kb = echange(p, g)
    print(f"  A = g^a mod p, B = g^b mod p")
    print(f"  K_alice = K_bob : {Ka == Kb}")

    print("\n  Attaque Man-in-the-Middle :")
    Ka, Kb, _, _ = attaque_mitm(p, g)
    print(f"  Cles cote Alice et cote Bob coincident : {Ka == Kb}")
    print("  -> Eve possede deux secrets partages distincts.")

    print("\n  Contre-mesure ECDSA :")
    ok, K = echange_authentifie(p, g)
    if ok and K is not None:
        print(f"  Signatures verifiees -> echange protege.")
        print(f"  K (mod 10^15) : {K % 10**15}")


if __name__ == "__main__":
    demo()
