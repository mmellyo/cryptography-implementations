"""Homomorphic e-voting using ElGamal additive homomorphism (in the exponent).

Each ballot v in {0, 1} is encoded as M = g^v then encrypted with ElGamal :
    E(v) = (c1, c2) = (g^k, g^v . y^k)
The product of ciphertexts is the encryption of the sum of votes (mod p-1) :
    E(v1) (x) E(v2) = (g^(k1+k2), g^(v1+v2) . y^(k1+k2)) = E(v1+v2)
The election authority decrypts the aggregate to obtain g^total and recovers
the total by brute-forcing the discrete log over [0, n_voters].

Anonymat : les bulletins individuels restent chiffres ; seul le total est
revele. Pour un vrai systeme il faut en plus :
- preuves zero-knowledge de validite des bulletins (vote in {0, 1})
- dechiffrement a seuil (multi-autorite)
- canaux d'envoi anonymes
"""
import secrets
from math import gcd

from sympy import nextprime, primitive_root


def generer_election(bits: int = 256):
    """(p, g, y, x) : x est conserve par l'autorite, (p, g, y) public."""
    if bits < 64:
        raise ValueError("Vote : taille minimale 64 bits (demo) / 2048 en production")
    seed = secrets.randbits(bits) | (1 << (bits - 1)) | 1
    p = int(nextprime(seed))
    g = int(primitive_root(p))
    x = secrets.randbelow(p - 3) + 2
    y = pow(g, x, p)
    return p, g, y, x


def chiffrer_vote(p: int, g: int, y: int, vote: int):
    if vote not in (0, 1):
        raise ValueError("Vote : seules les valeurs 0 et 1 sont acceptees")
    while True:
        k = secrets.randbelow(p - 2) + 1
        if gcd(k, p - 1) == 1:
            break
    M = pow(g, vote, p)
    c1 = pow(g, k, p)
    c2 = (M * pow(y, k, p)) % p
    return c1, c2


def agreger(chiffres, p: int):
    """Multiplie les ciphertexts componentwise -> chiffre de la somme."""
    c1_total, c2_total = 1, 1
    for c1, c2 in chiffres:
        c1_total = (c1_total * c1) % p
        c2_total = (c2_total * c2) % p
    return c1_total, c2_total


def decompter(p: int, g: int, x: int, chiffres, max_votants: int) -> int:
    """API publique : agrege puis decrypte avec g connu."""
    c1, c2 = agreger(chiffres, p)
    M_total = (c2 * pow(c1, p - 1 - x, p)) % p
    cible = 1
    for total in range(max_votants + 1):
        if cible == M_total:
            return total
        cible = (cible * g) % p
    raise ValueError(f"Total > {max_votants} ; election mal dimensionnee")


def demo():
    print("\n" + "=" * 50)
    print("  Homomorphic e-voting (ElGamal)")
    print("=" * 50)

    p, g, y, x = generer_election(64)  # bits reduits pour la demo
    print(f"\n  Parametres : p ({p.bit_length()} bits), g, (y publique, x privee)")

    # Tirage des bulletins.
    n = 50
    votes = [secrets.randbelow(2) for _ in range(n)]
    chiffres = [chiffrer_vote(p, g, y, v) for v in votes]
    print(f"  Bulletins  : {n} votants ; {sum(votes)} OUI attendus")

    # Verification : individual ballots are not the same plaintext when v=1.
    nb_unique = len({c for c in chiffres if c[0] != 1})
    print(f"  Bulletins distincts : {nb_unique}/{n} (non-determinisme ElGamal)")

    # Decompte par l'autorite.
    total_decompte = decompter(p, g, x, chiffres, max_votants=n)
    print(f"  Total decompte : {total_decompte} OUI / {n} bulletins")
    print(f"  Match attendu  : {total_decompte == sum(votes)}")

    # Test : un seul bulletin chiffre ne revele pas le vote.
    print("\n  Verification anonymat :")
    v0 = chiffrer_vote(p, g, y, 0)
    v1 = chiffrer_vote(p, g, y, 1)
    v0_bis = chiffrer_vote(p, g, y, 0)
    print(f"    E(0) #1 != E(0) #2     : {v0 != v0_bis}")
    print(f"    E(0) et E(1) distincts : {v0 != v1}")
    print("    -> impossibilite de distinguer un OUI d'un NON sans la cle privee.")


if __name__ == "__main__":
    demo()
