"""Cryptography implementations launcher."""
import importlib
import sys


MODULES = {
    ("classical",  "caesar"):    ("classical.caesar",            "Caesar"),
    ("classical",  "vigenere"):  ("classical.vigenere",          "Vigenere"),
    ("classical",  "hill"):      ("classical.hill",              "Hill"),
    ("classical",  "otp"):       ("classical.otp",               "One-Time Pad"),
    ("symmetric",  "rc4"):       ("symmetric.stream.rc4",        "RC4"),
    ("symmetric",  "des"):       ("symmetric.block.des",         "DES / 3DES"),
    ("symmetric",  "aes"):       ("symmetric.block.aes",         "AES"),
    ("symmetric",  "finalists"): ("symmetric.block.aes_finalists", "AES finalists"),
    ("asymmetric", "dh"):        ("asymmetric.diffie_hellman",   "Diffie-Hellman"),
    ("asymmetric", "rsa"):       ("asymmetric.rsa",              "RSA"),
    ("asymmetric", "elgamal"):   ("asymmetric.elgamal",          "ElGamal"),
    ("asymmetric", "ecc"):       ("asymmetric.ecc",              "Elliptic curves"),
    ("hashing",    "md5"):       ("hashing.md5",                 "MD5"),
    ("hashing",    "sha256"):    ("hashing.sha256",              "SHA-256"),
    ("hashing",    "sha512"):    ("hashing.sha512",              "SHA-512 + comparison"),
    ("hashing",    "hmac"):      ("hashing.hmac",                "HMAC"),
    ("signatures", "rsa"):       ("signatures.rsa_signature",    "RSA (PKCS#1 v1.5 + PSS)"),
    ("signatures", "elgamal"):   ("signatures.elgamal_sig",      "ElGamal signature"),
    ("signatures",   "dsa_ecdsa"): ("signatures.dsa_ecdsa",         "DSA / ECDSA"),
    ("applications", "tcp"):       ("applications.tcp_secure",      "TCP/IP secure channel"),
    ("applications", "udp"):       ("applications.udp_chat",        "UDP secure chat"),
    ("applications", "bluetooth"): ("applications.bluetooth_secure","Bluetooth (RFCOMM) secure channel"),
    ("applications", "voting"):    ("applications.voting",          "Homomorphic e-voting"),
}


THEMES = {
    "classical":    "Classical ciphers",
    "symmetric":    "Symmetric cryptography",
    "asymmetric":   "Asymmetric cryptography",
    "hashing":      "Hash functions",
    "signatures":   "Digital signatures",
    "applications": "Secure communication applications",
}

THEME_ORDER = ["classical", "symmetric", "asymmetric", "hashing", "signatures", "applications"]


# Aliases pour utilisateurs venant des fiches du cours.
ALIASES = {
    "1.1": ("classical", "caesar"),
    "1.2": ("classical", "vigenere"),
    "1.3": ("classical", "hill"),
    "1.4": ("classical", "otp"),
    "2.1": ("symmetric", "rc4"),
    "2.2": ("symmetric", "des"),
    "2.3": ("symmetric", "aes"),
    "2.4": ("symmetric", "finalists"),
    "3.1": ("asymmetric", "dh"),
    "3.2": ("asymmetric", "rsa"),
    "3.3": ("asymmetric", "elgamal"),
    "3.4": ("asymmetric", "ecc"),
    "4.1": ("hashing", "md5"),
    "4.2": ("hashing", "sha256"),
    "4.3": ("hashing", "sha512"),
    "4.4": ("hashing", "hmac"),
    "5.1": ("signatures", "rsa"),
    "5.2": ("signatures", "elgamal"),
    "5.3": ("signatures", "dsa_ecdsa"),
    "6.1": ("applications", "tcp"),
    "6.2": ("applications", "bluetooth"),
    "6.3": ("applications", "udp"),
    "6.4": ("applications", "voting"),
}


def afficher_menu():
    print("\n" + "=" * 50)
    print("  Cryptography implementations")
    print("=" * 50)
    for theme in THEME_ORDER:
        print(f"\n  {THEMES[theme]}")
        for (t, slug), (_, label) in MODULES.items():
            if t == theme:
                print(f"    {theme}.{slug:<10s}  {label}")
    print("\n    all   run every demo")
    print("    q     quit")


def _resoudre(token):
    if isinstance(token, tuple):
        return MODULES.get(token)
    if token in ALIASES:
        return MODULES.get(ALIASES[token])
    if "." in token:
        theme, slug = token.split(".", 1)
        return MODULES.get((theme, slug))
    return None


def lancer(token):
    cle = _resoudre(token)
    if cle is None:
        print(f"  Inconnu : {token}")
        return
    chemin, _ = cle
    try:
        module = importlib.import_module(chemin)
        if not hasattr(module, "demo"):
            print(f"  {chemin} : pas de fonction demo()")
            return
        module.demo()
    except ImportError as exc:
        print(f"  Import error : {exc}\n  pip install -r requirements.txt")
    except Exception as exc:
        print(f"  Erreur : {exc}")


def lancer_tout():
    for cle in MODULES:
        lancer(cle)


def main():
    if len(sys.argv) > 1:
        token = sys.argv[1].strip().lower()
        if token == "all":
            lancer_tout()
        else:
            lancer(token)
        return
    while True:
        afficher_menu()
        choix = input("\n  > ").strip().lower()
        if choix in ("q", "quit", "exit"):
            break
        if choix == "all":
            lancer_tout()
        elif choix:
            lancer(choix)


if __name__ == "__main__":
    main()
