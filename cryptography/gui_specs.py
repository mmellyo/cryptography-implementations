"""Input descriptors for the GUI 'test with my own values' panel.

Each entry in SPECS maps a module path (e.g. "classical.caesar") to a Spec
that describes the form fields and a runner() returning a printable result.
The GUI builds a generic form from the field list and calls runner() with
the parsed values when the user clicks "Lancer avec ces valeurs".
"""
import io
from contextlib import redirect_stdout
from dataclasses import dataclass, field as _field
from typing import Any, Callable

# Field types used in Champ.type
TEXT = "text"           # str (single line)
MULTILINE = "multiline" # str (multi-line)
INT = "int"             # int
BYTES_UTF8 = "bytes_utf8"  # str -> bytes via utf-8
BYTES_HEX = "bytes_hex"    # hex str -> bytes
CHOICE = "choice"          # str (one of options)


@dataclass
class Champ:
    cle: str
    label: str
    type: str
    defaut: Any = ""
    options: list = _field(default_factory=list)
    minimum: int = 0
    maximum: int = 1_000_000
    note: str = ""


@dataclass
class Spec:
    champs: list
    runner: Callable[[dict], str]


# -- Runners --------------------------------------------------------------

def _run_caesar(v):
    from classical import caesar
    texte, cle = v["texte"], v["cle"]
    chiffre = caesar.chiffrer(texte, cle)
    dechiffre = caesar.dechiffrer(chiffre, cle)
    out = [
        f"Clair      : {texte}",
        f"Cle        : {cle}",
        f"Chiffre    : {chiffre}",
        f"Dechiffre  : {dechiffre}",
    ]
    if v.get("attaque") == "oui":
        buf = io.StringIO()
        with redirect_stdout(buf):
            caesar.attaque_force_brute(chiffre)
            print()
            caesar.analyse_frequences(chiffre)
        out += ["", buf.getvalue().rstrip()]
    return "\n".join(out)


def _run_vigenere(v):
    from classical import vigenere
    texte, cle = v["texte"], v["cle"]
    if not cle.replace(" ", "").isalpha():
        return "Erreur : la cle doit contenir uniquement des lettres."
    chiffre = vigenere.chiffrer(texte, cle)
    dechiffre = vigenere.dechiffrer(chiffre, cle)
    return (f"Clair      : {texte}\n"
            f"Cle        : {cle}\n"
            f"Chiffre    : {chiffre}\n"
            f"Dechiffre  : {dechiffre}")


def _run_otp(v):
    from classical import otp
    msg = v["message"]
    cle = v.get("cle") or otp.generer_cle(len(msg))
    if len(cle) < len(msg):
        return f"Erreur : cle ({len(cle)} octets) < message ({len(msg)} octets)."
    cle = cle[:len(msg)]
    chiffre = otp.chiffrer(msg, cle)
    dechiffre = otp.dechiffrer(chiffre, cle)
    return (f"Message    : {msg!r}\n"
            f"Cle (hex)  : {cle.hex()}\n"
            f"Chiffre    : {chiffre.hex()}\n"
            f"Dechiffre  : {dechiffre!r}")


def _run_rc4(v):
    from symmetric.stream import rc4
    cle, donnees = v["cle"], v["donnees"]
    if not cle:
        return "Erreur : cle vide."
    chiffre = rc4.chiffrer(cle, donnees)
    dechiffre = rc4.chiffrer(cle, chiffre)
    return (f"Cle (hex)     : {cle.hex()}\n"
            f"Donnees       : {donnees!r}\n"
            f"Chiffre (hex) : {chiffre.hex()}\n"
            f"Dechiffre     : {dechiffre!r}")


def _run_des(v):
    from symmetric.block import des
    msg, cle, iv = v["message"], v["cle"], v["iv"]
    if len(cle) not in (8, 16, 24):
        return f"Erreur : cle DES doit faire 8/16/24 octets (recue {len(cle)})."
    if len(iv) != 8:
        return f"Erreur : IV DES doit faire 8 octets (recu {len(iv)})."
    if len(cle) == 8:
        chiffre = des.chiffrer_cbc(msg, cle, iv)
        dechiffre = des.dechiffrer_cbc(chiffre, cle, iv)
        algo = "DES-CBC"
    else:
        chiffre = des.chiffrer_3des_cbc(msg, cle, iv)
        dechiffre = des.dechiffrer_3des_cbc(chiffre, cle, iv)
        algo = "3DES-CBC"
    return (f"Algo          : {algo}\n"
            f"Message       : {msg!r}\n"
            f"Cle (hex)     : {cle.hex()}\n"
            f"IV (hex)      : {iv.hex()}\n"
            f"Chiffre (hex) : {chiffre.hex()}\n"
            f"Dechiffre     : {dechiffre!r}")


def _run_aes(v):
    from symmetric.block import aes
    msg, cle, iv, mode = v["message"], v["cle"], v["iv"], v["mode"]
    if len(cle) not in (16, 24, 32):
        return f"Erreur : cle AES doit faire 16/24/32 octets (recue {len(cle)})."
    if len(iv) != 16:
        return f"Erreur : IV/Nonce AES doit faire 16 octets (recu {len(iv)})."
    if mode == "CBC":
        chiffre = aes.chiffrer_cbc(msg, cle, iv)
        dechiffre = aes.dechiffrer_cbc(chiffre, cle, iv)
    else:
        chiffre = aes.chiffrer_ctr(msg, cle, iv)
        dechiffre = aes.dechiffrer_ctr(chiffre, cle, iv)
    return (f"Mode          : AES-{mode}\n"
            f"Message       : {msg!r}\n"
            f"Cle (hex)     : {cle.hex()}\n"
            f"IV/Nonce (hex): {iv.hex()}\n"
            f"Chiffre (hex) : {chiffre.hex()}\n"
            f"Dechiffre     : {dechiffre!r}")


def _run_md5(v):
    from hashing import md5
    msg = v["message"]
    return f"Message  : {msg!r}\nMD5      : {md5.md5(msg)}"


def _run_sha256(v):
    from hashing import sha256
    msg = v["message"]
    return f"Message  : {msg!r}\nSHA-256  : {sha256.sha256_manuel(msg)}"


def _run_sha512(v):
    from hashing import sha512
    msg = v["message"]
    res = sha512.empreintes(msg)
    out = [f"Message  : {msg!r}", ""]
    for nom, val in res.items():
        out.append(f"{nom:8s} : {val}")
    return "\n".join(out)


def _run_hmac(v):
    from hashing import hmac as h
    cle, msg, algo = v["cle"], v["message"], v["algo"]
    try:
        tag_man = h.hmac_manuel(cle, msg, algo)
        tag_std = h.hmac_stdlib(cle, msg, algo)
    except ValueError as e:
        return f"Erreur : {e}"
    return (f"Algo            : {algo}\n"
            f"Cle (hex)       : {cle.hex()}\n"
            f"Message         : {msg!r}\n"
            f"HMAC manuel     : {tag_man.hex()}\n"
            f"HMAC stdlib     : {tag_std.hex()}\n"
            f"Identiques      : {tag_man == tag_std}")


def _run_rsa(v):
    from asymmetric import rsa as rsa_mod
    msg, bits = v["message"], int(v["bits"])
    mode = v.get("mode", "OAEP")
    try:
        priv, pub = rsa_mod.generer_cles(bits)
    except ValueError as e:
        return f"Erreur : {e}"
    limite = rsa_mod.taille_max_oaep(bits)
    if mode == "OAEP" and len(msg) > limite:
        return (
            f"Erreur : message {len(msg)} octets > limite OAEP-SHA256 "
            f"({limite} octets pour RSA-{bits}).\n"
            f"Choisissez le mode 'Hybride' pour chiffrer du texte long."
        )
    try:
        if mode == "Hybride":
            chiffre = rsa_mod.chiffrer_hybride(pub, msg)
            dechiffre = rsa_mod.dechiffrer_hybride(priv, chiffre)
            schema = f"RSA-OAEP + AES-256-GCM"
        else:
            chiffre = rsa_mod.chiffrer(pub, msg)
            dechiffre = rsa_mod.dechiffrer(priv, chiffre)
            schema = "RSA-OAEP-SHA256"
    except Exception as e:
        return f"Erreur chiffrement : {e}"

    pub_nums = pub.public_numbers()
    priv_nums = priv.private_numbers()

    def court(n: int, lim: int = 80) -> str:
        s = hex(n)
        return s if len(s) <= lim else s[:lim] + "..."

    hex_c = chiffre.hex()
    return (
        f"=== Parametres ===\n"
        f"Taille cle     : {bits} bits\n"
        f"Schema         : {schema}\n"
        f"Limite OAEP    : {limite} octets (par appel)\n"
        f"\n=== Cle publique (n, e) ===\n"
        f"n (hex)        : {court(pub_nums.n)}\n"
        f"e              : {pub_nums.e}\n"
        f"\n=== Cle privee (d, p, q) ===\n"
        f"d (hex)        : {court(priv_nums.d)}\n"
        f"p (hex)        : {court(priv_nums.p, 60)}\n"
        f"q (hex)        : {court(priv_nums.q, 60)}\n"
        f"\n=== Chiffrement {schema} ===\n"
        f"Message ({len(msg)} o) : {msg!r}\n"
        f"Longueur c     : {len(chiffre)} octets\n"
        f"Chiffre (hex)  : {hex_c[:80]}{'...' if len(hex_c) > 80 else ''}\n"
        f"Dechiffre      : {dechiffre!r}\n"
        f"Match          : {dechiffre == msg}"
    )


def _run_dh(v):
    from asymmetric import diffie_hellman as dh
    bits = v["bits"]
    try:
        p, g = dh.generer_p_g(bits)
    except ValueError as e:
        return f"Erreur : {e}"
    a, b, A, B, Ka, Kb = dh.echange(p, g)

    def court(n):
        s = hex(n)
        return s if len(s) <= 60 else s[:60] + "..."

    return (f"Taille p     : {bits} bits\n"
            f"p            : {court(p)}\n"
            f"g            : {g}\n"
            f"a (Alice)    : {court(a)}\n"
            f"b (Bob)      : {court(b)}\n"
            f"A = g^a      : {court(A)}\n"
            f"B = g^b      : {court(B)}\n"
            f"K_alice      : {court(Ka)}\n"
            f"K_bob        : {court(Kb)}\n"
            f"Match        : {Ka == Kb}")


def _run_elgamal(v):
    from asymmetric import elgamal
    bits, M = v["bits"], v["message"]
    try:
        p, g, x, y = elgamal.generer_cles(bits)
    except ValueError as e:
        return f"Erreur : {e}"
    if M >= p:
        return f"Erreur : M ({M}) doit etre < p (~{p.bit_length()} bits)."
    c1, c2 = elgamal.chiffrer(p, g, y, M)
    M_d = elgamal.dechiffrer(p, x, c1, c2)

    def court(n):
        s = hex(n)
        return s if len(s) <= 60 else s[:60] + "..."

    return (
        f"=== Parametres ===\n"
        f"Taille p   : {bits} bits\n"
        f"\n=== Cle publique (p, g, y) ===\n"
        f"p          : {court(p)}\n"
        f"g          : {g}\n"
        f"y = g^x    : {court(y)}\n"
        f"\n=== Cle privee (x) ===\n"
        f"x          : {court(x)}\n"
        f"\n=== Chiffrement ElGamal ===\n"
        f"M (clair)  : {M}\n"
        f"c1 = g^k   : {court(c1)}\n"
        f"c2 = M*y^k : {court(c2)}\n"
        f"Dechiffre  : {M_d}\n"
        f"Match      : {M_d == M}"
    )


def _run_rsa_signature(v):
    from signatures import rsa_signature
    msg, bits, schema = v["message"], int(v["bits"]), v["schema"]
    priv, pub = rsa_signature.generer_cles(bits)
    if schema == "PKCS1v15":
        sig = rsa_signature.signer_pkcs1v15(priv, msg)
        ok = rsa_signature.verifier_pkcs1v15(pub, msg, sig)
        ok_alt = rsa_signature.verifier_pkcs1v15(pub, msg + b"x", sig)
    else:
        sig = rsa_signature.signer_pss(priv, msg)
        ok = rsa_signature.verifier_pss(pub, msg, sig)
        ok_alt = rsa_signature.verifier_pss(pub, msg + b"x", sig)

    pub_nums = pub.public_numbers()
    priv_nums = priv.private_numbers()

    def court(n: int, lim: int = 80) -> str:
        s = hex(n)
        return s if len(s) <= lim else s[:lim] + "..."

    hex_s = sig.hex()
    return (
        f"=== Parametres ===\n"
        f"Schema           : {schema}\n"
        f"Taille cle       : {bits} bits\n"
        f"\n=== Cle publique (n, e) ===\n"
        f"n (hex)          : {court(pub_nums.n)}\n"
        f"e                : {pub_nums.e}\n"
        f"\n=== Cle privee (d, p, q) ===\n"
        f"d (hex)          : {court(priv_nums.d)}\n"
        f"p (hex)          : {court(priv_nums.p, 60)}\n"
        f"q (hex)          : {court(priv_nums.q, 60)}\n"
        f"\n=== Signature ===\n"
        f"Message          : {msg!r}\n"
        f"Signature        : {len(sig)} octets\n"
        f"Signature (hex)  : {hex_s[:80]}{'...' if len(hex_s) > 80 else ''}\n"
        f"Verif (legitime) : {ok}\n"
        f"Verif (modifie)  : {ok_alt}"
    )


def _run_dsa_ecdsa(v):
    from signatures import dsa_ecdsa
    msg, algo = v["message"], v["algo"]
    try:
        if algo == "DSA":
            priv, pub, sig = dsa_ecdsa.signer_dsa(msg)
            ok = dsa_ecdsa.verifier_dsa(pub, msg, sig)
            ok_alt = dsa_ecdsa.verifier_dsa(pub, msg + b"x", sig)
        else:
            priv, pub, sig = dsa_ecdsa.signer_ecdsa(msg, algo)
            ok = dsa_ecdsa.verifier_ecdsa(pub, msg, sig)
            ok_alt = dsa_ecdsa.verifier_ecdsa(pub, msg + b"x", sig)
    except ValueError as e:
        return f"Erreur : {e}"

    def court(n: int, lim: int = 80) -> str:
        s = hex(n)
        return s if len(s) <= lim else s[:lim] + "..."

    if algo == "DSA":
        params = pub.parameters().parameter_numbers()
        pub_nums = pub.public_numbers()
        priv_nums = priv.private_numbers()
        cles_str = (
            f"\n=== Parametres DSA (p, q, g) ===\n"
            f"p (hex)          : {court(params.p)}\n"
            f"q (hex)          : {court(params.q, 60)}\n"
            f"g (hex)          : {court(params.g)}\n"
            f"\n=== Cle publique y = g^x mod p ===\n"
            f"y (hex)          : {court(pub_nums.y)}\n"
            f"\n=== Cle privee x ===\n"
            f"x (hex)          : {court(priv_nums.x, 60)}\n"
        )
    else:
        pub_nums = pub.public_numbers()
        priv_nums = priv.private_numbers()
        cles_str = (
            f"\n=== Cle publique (point sur courbe {algo}) ===\n"
            f"x (hex)          : {court(pub_nums.x, 70)}\n"
            f"y (hex)          : {court(pub_nums.y, 70)}\n"
            f"\n=== Cle privee (scalaire d) ===\n"
            f"d (hex)          : {court(priv_nums.private_value, 70)}\n"
        )

    hex_s = sig.hex()
    return (
        f"=== Algo : {algo} ==="
        f"{cles_str}"
        f"\n=== Signature ===\n"
        f"Message          : {msg!r}\n"
        f"Signature        : {len(sig)} octets\n"
        f"Signature (hex)  : {hex_s[:80]}{'...' if len(hex_s) > 80 else ''}\n"
        f"Verif (legitime) : {ok}\n"
        f"Verif (modifie)  : {ok_alt}"
    )


def _run_elgamal_sig(v):
    from signatures import elgamal_sig
    msg, bits = v["message"], v["bits"]
    p, g, x, y = elgamal_sig.gen_cles(bits)
    r, s = elgamal_sig.signer(p, g, x, msg)
    ok = elgamal_sig.verifier(p, g, y, msg, r, s)
    ok_alt = elgamal_sig.verifier(p, g, y, msg + b"x", r, s)

    def court(n):
        h = hex(n)
        return h if len(h) <= 60 else h[:60] + "..."

    return (
        f"=== Parametres ===\n"
        f"Taille p         : {bits} bits\n"
        f"\n=== Cle publique (p, g, y) ===\n"
        f"p                : {court(p)}\n"
        f"g                : {g}\n"
        f"y = g^x          : {court(y)}\n"
        f"\n=== Cle privee (x) ===\n"
        f"x                : {court(x)}\n"
        f"\n=== Signature ElGamal ===\n"
        f"Message          : {msg!r}\n"
        f"r                : {court(r)}\n"
        f"s                : {court(s)}\n"
        f"Verif (legitime) : {ok}\n"
        f"Verif (modifie)  : {ok_alt}"
    )


# -- Specs ----------------------------------------------------------------

SPECS = {
    "classical.caesar": Spec(
        champs=[
            Champ("texte", "Texte clair", MULTILINE, "La cryptographie est la science du secret"),
            Champ("cle", "Cle (0-25)", INT, 7, minimum=0, maximum=25),
            Champ("attaque", "Inclure attaque (force brute + freq)", CHOICE, "non", options=["oui", "non"]),
        ],
        runner=_run_caesar,
    ),
    "classical.vigenere": Spec(
        champs=[
            Champ("texte", "Texte clair", MULTILINE, "La cryptographie est essentielle a la securite"),
            Champ("cle", "Cle (lettres)", TEXT, "CRYPTO"),
        ],
        runner=_run_vigenere,
    ),
    "classical.otp": Spec(
        champs=[
            Champ("message", "Message", BYTES_UTF8, "Hello, OTP!"),
            Champ("cle", "Cle (hex)", BYTES_HEX, "", note="Vide = generer aleatoirement"),
        ],
        runner=_run_otp,
    ),
    "symmetric.stream.rc4": Spec(
        champs=[
            Champ("cle", "Cle (hex)", BYTES_HEX, "5365637265744b6579"),
            Champ("donnees", "Donnees", BYTES_UTF8, "Message via RC4"),
        ],
        runner=_run_rc4,
    ),
    "symmetric.block.des": Spec(
        champs=[
            Champ("message", "Message", BYTES_UTF8, "Hello DES"),
            Champ("cle", "Cle (hex, 8/16/24 octets)", BYTES_HEX, "0123456789abcdef"),
            Champ("iv", "IV (hex, 8 octets)", BYTES_HEX, "0102030405060708"),
        ],
        runner=_run_des,
    ),
    "symmetric.block.aes": Spec(
        champs=[
            Champ("message", "Message", BYTES_UTF8, "Hello AES"),
            Champ("cle", "Cle (hex, 16/24/32 octets)", BYTES_HEX, "00112233445566778899aabbccddeeff"),
            Champ("iv", "IV/Nonce (hex, 16 octets)", BYTES_HEX, "0f0e0d0c0b0a09080706050403020100"),
            Champ("mode", "Mode", CHOICE, "CBC", options=["CBC", "CTR"]),
        ],
        runner=_run_aes,
    ),
    "hashing.md5": Spec(
        champs=[Champ("message", "Message", BYTES_UTF8, "Hello, MD5!")],
        runner=_run_md5,
    ),
    "hashing.sha256": Spec(
        champs=[Champ("message", "Message", BYTES_UTF8, "Hello, SHA-256!")],
        runner=_run_sha256,
    ),
    "hashing.sha512": Spec(
        champs=[Champ("message", "Message", BYTES_UTF8, "Hello, SHA-512!")],
        runner=_run_sha512,
    ),
    "hashing.hmac": Spec(
        champs=[
            Champ("cle", "Cle (hex)", BYTES_HEX, "0102030405060708090a0b0c0d0e0f10"),
            Champ("message", "Message", BYTES_UTF8, "Message a authentifier"),
            Champ("algo", "Algo", CHOICE, "sha256", options=["sha256", "sha512", "md5"]),
        ],
        runner=_run_hmac,
    ),
    "asymmetric.rsa": Spec(
        champs=[
            Champ("message", "Message", BYTES_UTF8, "Message via RSA"),
            Champ("bits", "Taille cle", CHOICE, "2048", options=["512", "1024", "2048", "3072", "4096"]),
            Champ("mode", "Mode", CHOICE, "OAEP", options=["OAEP", "Hybride"],
                  note="OAEP : court (<= taille/8-66 o). Hybride : long texte (RSA + AES-GCM)."),
        ],
        runner=_run_rsa,
    ),
    "asymmetric.diffie_hellman": Spec(
        champs=[
            Champ("bits", "Taille p (bits)", INT, 512, minimum=512, maximum=2048),
        ],
        runner=_run_dh,
    ),
    "asymmetric.elgamal": Spec(
        champs=[
            Champ("bits", "Taille p (bits)", INT, 512, minimum=512, maximum=2048),
            Champ("message", "M (entier > 0)", INT, 12345, minimum=1, maximum=10**9),
        ],
        runner=_run_elgamal,
    ),
    "signatures.rsa_signature": Spec(
        champs=[
            Champ("message", "Message a signer", BYTES_UTF8, "Document a signer"),
            Champ("bits", "Taille cle", CHOICE, "2048", options=["1024", "2048", "3072", "4096"]),
            Champ("schema", "Schema", CHOICE, "PSS", options=["PSS", "PKCS1v15"]),
        ],
        runner=_run_rsa_signature,
    ),
    "signatures.dsa_ecdsa": Spec(
        champs=[
            Champ("message", "Message a signer", BYTES_UTF8, "Document a signer"),
            Champ("algo", "Algo / Courbe", CHOICE, "P-256", options=["DSA", "P-256", "P-384", "P-521"]),
        ],
        runner=_run_dsa_ecdsa,
    ),
    "signatures.elgamal_sig": Spec(
        champs=[
            Champ("message", "Message a signer", BYTES_UTF8, "Document a signer"),
            Champ("bits", "Taille p (bits)", INT, 512, minimum=512, maximum=2048,
                  note="512 mini (OpenSSL safe prime)"),
        ],
        runner=_run_elgamal_sig,
    ),
}
