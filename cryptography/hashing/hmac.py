"""HMAC implementation following RFC 2104, validated against RFC 4231."""
import hashlib
import hmac as _hmac_stdlib


_BLOCK_SIZES = {
    "md5": 64,
    "sha1": 64,
    "sha256": 64,
    "sha384": 128,
    "sha512": 128,
}


def hmac_manuel(cle: bytes, message: bytes, algo: str = "sha256") -> bytes:
    """HMAC(K, m) = H((K' XOR opad) || H((K' XOR ipad) || m))."""
    algo = algo.lower()
    if algo not in _BLOCK_SIZES:
        raise ValueError(f"HMAC : algorithme non supporte ({algo})")
    block = _BLOCK_SIZES[algo]
    if len(cle) > block:
        cle = hashlib.new(algo, cle).digest()
    cle = cle.ljust(block, b"\x00")
    ipad = bytes(b ^ 0x36 for b in cle)
    opad = bytes(b ^ 0x5c for b in cle)
    interne = hashlib.new(algo, ipad + message).digest()
    return hashlib.new(algo, opad + interne).digest()


def hmac_stdlib(cle: bytes, message: bytes, algo: str = "sha256") -> bytes:
    return _hmac_stdlib.new(cle, message, algo).digest()


def comparer_constant_time(a: bytes, b: bytes) -> bool:
    return _hmac_stdlib.compare_digest(a, b)


def authentifier(cle: bytes, message: bytes, algo: str = "sha256"):
    return message, hmac_manuel(cle, message, algo)


def verifier(cle: bytes, message: bytes, tag: bytes, algo: str = "sha256") -> bool:
    return comparer_constant_time(hmac_manuel(cle, message, algo), tag)


# Vecteurs RFC 4231.
RFC4231 = [
    (
        b"\x0b" * 20,
        b"Hi There",
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    ),
    (
        b"Jefe",
        b"what do ya want for nothing?",
        "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
    ),
    (
        b"\xaa" * 20,
        b"\xdd" * 50,
        "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
    ),
    (
        b"\xaa" * 131,
        b"Test Using Larger Than Block-Size Key - Hash Key First",
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    ),
]


def demo():
    print("\n" + "=" * 50)
    print("  HMAC")
    print("=" * 50)
    print("\n  Validation contre RFC 4231 (HMAC-SHA256) :")
    for i, (cle, msg, attendu) in enumerate(RFC4231, 1):
        obtenu = hmac_manuel(cle, msg, "sha256").hex()
        print(f"  Vecteur #{i} : {'OK' if obtenu == attendu else 'FAIL'}")

    print("\n  Authentification + verification :")
    cle = b"cle-de-test"
    msg = b"Transaction : Alice -> Bob, 100 EUR"
    _, tag = authentifier(cle, msg)
    print(f"  Tag        : {tag.hex()[:48]}...")
    print(f"  Verif OK   : {verifier(cle, msg, tag)}")
    print(f"  Tag falsif : {verifier(cle, msg, tag[:-1] + b'\\x00')}")
    print(f"  Msg modif  : {verifier(cle, msg + b'!', tag)}")


if __name__ == "__main__":
    demo()
