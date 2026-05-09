"""Hill cipher (2x2 / 3x3) with known-plaintext attack."""
from math import gcd


def _eea(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x, y = _eea(b % a, a)
    return g, y - (b // a) * x, x


def inverse_mod(a: int, m: int) -> int:
    g, x, _ = _eea(a % m, m)
    if g != 1:
        raise ValueError(f"{a} non inversible modulo {m}")
    return x % m


def determinant(m, n: int) -> int:
    if n == 1:
        return m[0][0]
    if n == 2:
        return m[0][0] * m[1][1] - m[0][1] * m[1][0]
    return sum(
        ((-1) ** j)
        * m[0][j]
        * determinant([[m[i][k] for k in range(n) if k != j] for i in range(1, n)], n - 1)
        for j in range(n)
    )


def _cofacteur(m, n: int, i: int, j: int) -> int:
    sous = [[m[r][c] for c in range(n) if c != j] for r in range(n) if r != i]
    return ((-1) ** (i + j)) * determinant(sous, n - 1)


def inverse_mat_mod(mat, n: int, mod: int = 26):
    det = determinant(mat, n) % mod
    if gcd(det, mod) != 1:
        raise ValueError(f"Determinant {det} non inversible modulo {mod}")
    di = inverse_mod(det, mod)
    adj = [[_cofacteur(mat, n, i, j) for i in range(n)] for j in range(n)]
    return [[(di * adj[i][j]) % mod for j in range(n)] for i in range(n)]


def matrice_valide(mat, n: int) -> bool:
    return gcd(determinant(mat, n) % 26, 26) == 1


def _mult_mv(mat, vec, n: int):
    return [sum(mat[i][j] * vec[j] for j in range(n)) % 26 for i in range(n)]


def _mult_mm(a, b, n: int):
    return [[sum(a[i][k] * b[k][j] for k in range(n)) % 26 for j in range(n)] for i in range(n)]


def _txt2num(t: str):
    return [ord(c) - ord("A") for c in t.upper() if c.isalpha()]


def _num2txt(seq) -> str:
    return "".join(chr(v % 26 + ord("A")) for v in seq)


def chiffrer(texte: str, cle, n: int) -> str:
    if not matrice_valide(cle, n):
        raise ValueError("Matrice cle non inversible mod 26")
    nums = _txt2num(texte)
    while len(nums) % n:
        nums.append(23)  # padding 'X'
    out = []
    for i in range(0, len(nums), n):
        out.extend(_mult_mv(cle, nums[i:i + n], n))
    return _num2txt(out)


def dechiffrer(texte: str, cle, n: int) -> str:
    inv = inverse_mat_mod(cle, n)
    nums = _txt2num(texte)
    out = []
    for i in range(0, len(nums), n):
        out.extend(_mult_mv(inv, nums[i:i + n], n))
    return _num2txt(out)


def attaque_clair_connu(clair: str, chiffre: str, n: int):
    pn = _txt2num(clair)
    cn = _txt2num(chiffre)
    if len(pn) < n * n or len(cn) < n * n:
        raise ValueError(f"Il faut au moins {n*n} lettres pour reconstituer la cle")
    P = [[pn[c * n + r] for c in range(n)] for r in range(n)]
    C = [[cn[c * n + r] for c in range(n)] for r in range(n)]
    return _mult_mm(C, inverse_mat_mod(P, n), n)


# Compat anciens noms.
chiffrer_hill = chiffrer
dechiffrer_hill = dechiffrer
verifier_mat = matrice_valide


def demo():
    print("\n" + "=" * 50)
    print("  Hill cipher")
    print("=" * 50)
    cle2 = [[3, 3], [2, 5]]
    cle3 = [[6, 24, 1], [13, 16, 10], [20, 17, 15]]

    msg2 = "BONJOUR"
    c2 = chiffrer(msg2, cle2, 2)
    print(f"\n  2x2 : {msg2} -> {c2} -> {dechiffrer(c2, cle2, 2)}")

    msg3 = "ATTACKATDAWN"
    c3 = chiffrer(msg3, cle3, 3)
    print(f"  3x3 : {msg3} -> {c3} -> {dechiffrer(c3, cle3, 3)}")

    clair = "HELP"
    chiffre = chiffrer(clair, cle2, 2)
    cle_retrouvee = attaque_clair_connu(clair, chiffre, 2)
    print(f"\n  Attaque clair connu (2x2) :")
    print(f"    Cle originale  : {cle2}")
    print(f"    Cle retrouvee  : {cle_retrouvee}")


if __name__ == "__main__":
    demo()
