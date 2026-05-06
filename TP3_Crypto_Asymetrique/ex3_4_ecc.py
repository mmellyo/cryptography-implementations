"""TP3 - Ex3.4 : ECC (from scratch + cryptography lib)"""
import os, hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class Point:
    def __init__(self, x, y, c):
        self.x, self.y, self.c, self.inf = x, y, c, (x is None)
    def __repr__(self): return "O" if self.inf else f"({self.x},{self.y})"
    def __eq__(self, o):
        if self.inf and o.inf: return True
        return not self.inf and not o.inf and self.x==o.x and self.y==o.y

class Courbe:
    def __init__(self, a, b, p): self.a, self.b, self.p = a, b, p
    def O(self): return Point(None, None, self)
    def add(self, P, Q):
        if P.inf: return Q
        if Q.inf: return P
        if P.x==Q.x and (P.y+Q.y)%self.p==0: return self.O()
        if P==Q: num, den = (3*P.x*P.x+self.a)%self.p, (2*P.y)%self.p
        else: num, den = (Q.y-P.y)%self.p, (Q.x-P.x)%self.p
        lam = (num*pow(den, self.p-2, self.p))%self.p
        x3 = (lam*lam-P.x-Q.x)%self.p
        return Point(x3, (lam*(P.x-x3)-P.y)%self.p, self)
    def mul(self, k, P):
        R, T = self.O(), P
        while k > 0:
            if k&1: R = self.add(R, T)
            T = self.add(T, T); k >>= 1
        return R
    def points(self):
        pts = [self.O()]
        for x in range(self.p):
            rhs = (x**3+self.a*x+self.b)%self.p
            for y in range(self.p):
                if (y*y)%self.p == rhs: pts.append(Point(x, y, self))
        return pts

def mode_interactif():
    while True:
        print("\n" + "=" * 50)
        print("  COURBES ELLIPTIQUES")
        print("=" * 50)
        print("  1. ECC from scratch (y^2=x^3+7 mod 97)")
        print("  2. kP scalaire\n  3. ECDH P-256\n  4. ECIES\n  0. Quitter")
        choix = input("\n  Choix : ").strip()
        if choix == "1":
            c = Courbe(0, 7, 97)
            pts = c.points()
            print(f"  {len(pts)} points, premiers: {pts[1:5]}")
            P, Q = pts[2], pts[3]
            print(f"  P+O=P: {c.add(P,c.O())==P}, P+Q=Q+P: {c.add(P,Q)==c.add(Q,P)}")
        elif choix == "2":
            c = Courbe(0, 7, 97)
            G = c.points()[1]
            try: k = int(input(f"  k (G={G}): "))
            except ValueError: continue
            print(f"  {k}G = {c.mul(k, G)}")
        elif choix == "3":
            a = ec.generate_private_key(ec.SECP256R1())
            b = ec.generate_private_key(ec.SECP256R1())
            sa = a.exchange(ec.ECDH(), b.public_key())
            sb = b.exchange(ec.ECDH(), a.public_key())
            print(f"  Match: {sa==sb}\n  Cle AES: {hashlib.sha256(sa).hexdigest()}")
        elif choix == "4":
            msg = input("  Message : ").encode()
            bp = ec.generate_private_key(ec.SECP256R1())
            eph = ec.generate_private_key(ec.SECP256R1())
            s = eph.exchange(ec.ECDH(), bp.public_key())
            k = hashlib.sha256(s).digest(); n = os.urandom(16)
            c = Cipher(algorithms.AES(k), modes.CTR(n)).encryptor().update(msg)
            print(f"  Chiffre: {c.hex()}")
            s2 = bp.exchange(ec.ECDH(), eph.public_key())
            d = Cipher(algorithms.AES(hashlib.sha256(s2).digest()), modes.CTR(n)).decryptor().update(c)
            print(f"  Dechiffre: {d.decode()}")
        elif choix == "0": break

def main():
    print("\n  TP3 - EXERCICE 3.4 : COURBES ELLIPTIQUES")
    mode_interactif()

if __name__ == "__main__":
    main()
