"""TP4 - Ex4.2 : SHA-256 (from scratch)"""
import struct, hashlib

K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
]
H0 = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]

def rotr(x,n): return ((x>>n)|(x<<(32-n)))&0xFFFFFFFF
def ch(x,y,z): return (x&y)^(~x&z)&0xFFFFFFFF
def maj(x,y,z): return (x&y)^(x&z)^(y&z)
def s0(x): return rotr(x,2)^rotr(x,13)^rotr(x,22)
def s1(x): return rotr(x,6)^rotr(x,11)^rotr(x,25)
def g0(x): return rotr(x,7)^rotr(x,18)^(x>>3)
def g1(x): return rotr(x,17)^rotr(x,19)^(x>>10)

def sha256_manuel(message: bytes) -> str:
    L = len(message)*8
    message += b'\x80'
    while len(message)%64 != 56: message += b'\x00'
    message += struct.pack('>Q', L)
    H = list(H0)
    for i in range(0, len(message), 64):
        W = list(struct.unpack('>16I', message[i:i+64]))
        for j in range(16,64): W.append((g1(W[j-2])+W[j-7]+g0(W[j-15])+W[j-16])&0xFFFFFFFF)
        a,b,c,d,e,f,g,h = H
        for j in range(64):
            T1 = (h+s1(e)+ch(e,f,g)+K[j]+W[j])&0xFFFFFFFF
            T2 = (s0(a)+maj(a,b,c))&0xFFFFFFFF
            h,g,f,e,d,c,b,a = g,f,e,(d+T1)&0xFFFFFFFF,c,b,a,(T1+T2)&0xFFFFFFFF
        H = [(H[i]+v)&0xFFFFFFFF for i,v in enumerate([a,b,c,d,e,f,g,h])]
    return ''.join(f'{v:08x}' for v in H)

def mode_interactif():
    while True:
        print("\n" + "=" * 50)
        print("  SHA-256 (FROM SCRATCH)")
        print("=" * 50)
        print("  1. Calculer SHA-256\n  2. Verifier vs hashlib\n  3. Integrite")
        print("  4. Valider 10 vecteurs\n  0. Quitter")
        choix = input("\n  Choix : ").strip()
        if choix == "1":
            print(f"  SHA-256 = {sha256_manuel(input('  Message : ').encode())}")
        elif choix == "2":
            msg = input("  Message : ").encode()
            m, r = sha256_manuel(msg), hashlib.sha256(msg).hexdigest()
            print(f"  Manuel : {m}\n  hashlib: {r}\n  Match: {m==r}")
        elif choix == "3":
            h1 = sha256_manuel(input("  Original : ").encode())
            h2 = sha256_manuel(input("  A verifier : ").encode())
            print(f"  Integre : {h1==h2}")
        elif choix == "4":
            vecs = [b"",b"abc",b"hello world",b"SHA-256",b"Cryptographie",
                    b"The quick brown fox jumps over the lazy dog",
                    b"\x00"*64,b"\xFF"*100,b"a"*1000,b"Test final"]
            ok = all(sha256_manuel(v)==hashlib.sha256(v).hexdigest() for v in vecs)
            for v in vecs:
                m = sha256_manuel(v)==hashlib.sha256(v).hexdigest()
                print(f"  {'OK' if m else 'FAIL'} : {v[:20]}")
            print(f"\n  {'Tous OK !' if ok else 'Echecs !'}")
        elif choix == "0": break

def main():
    print("\n  TP4 - EXERCICE 4.2 : SHA-256 (FROM SCRATCH)")
    mode_interactif()

if __name__ == "__main__":
    main()
