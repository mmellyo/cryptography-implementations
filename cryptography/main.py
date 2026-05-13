"""Cryptography implementations launcher.

CLI front-end mirroring the desktop GUI layout :
- Branded header in French Blue.
- Modules grouped by theme, displayed as a sidebar-style list.
- Per-module choice between the pre-defined scenario and the
  'Tester avec mes valeurs' interactive form (same SPECS as the GUI/TUI).
"""
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


# ---------------------------------------------------------------------------
# Palette (approximated for the 256-color terminal palette).
#   French Blue #003f91 -> 25 (deep blue), used for brand / titles / actions
#   Cool Sky    #5da9e9 -> 75 (light blue), used for hints / focus
#   Honeydew    #e5f4e3 -> 194 (very light green), used for success surfaces
# ---------------------------------------------------------------------------
_USE_COLOR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    if not _USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def _subtitle(text: str) -> str: return _c("38;5;245", text)
def _accent(text: str) -> str:   return _c("38;5;75", text)
def _brand(text: str) -> str:    return _c("1;97;48;5;25", text)
def _label(text: str) -> str:    return _c("1;38;5;25", text)
def _err(text: str) -> str:      return _c("38;5;160", text)
def _muted(text: str) -> str:    return _c("38;5;244", text)


def _term_width(default: int = 78) -> int:
    try:
        import shutil
        return max(40, min(shutil.get_terminal_size().columns, 100))
    except Exception:
        return default


def _divider() -> str:
    return _muted("-" * _term_width())


def _afficher_entete():
    largeur = _term_width()
    print()
    print(_brand(" Cryptography ".ljust(largeur)))
    print(_subtitle("  Implementations interactives - scenario ou tes propres valeurs"))
    print(_divider())


def afficher_menu():
    _afficher_entete()
    for theme in THEME_ORDER:
        print()
        print(_label(f"  {THEMES[theme]}"))
        for (t, slug), (_, label) in MODULES.items():
            if t == theme:
                ref = f"{theme}.{slug}"
                print(f"    {_accent(ref.ljust(28))} {label}")
    print()
    print(_divider())
    print(f"  {_accent('all')}   {_muted('lance tous les scenarios')}")
    print(f"  {_accent('q')}     {_muted('quitter')}")
    print()


def _resoudre(token):
    if isinstance(token, tuple):
        return MODULES.get(token)
    if token in ALIASES:
        return MODULES.get(ALIASES[token])
    if "." in token:
        theme, slug = token.split(".", 1)
        return MODULES.get((theme, slug))
    return None


def _executer_scenario(chemin: str) -> None:
    print()
    print(_label(f"=== {chemin} ==="))
    print(_subtitle("Scenario pre-defini"))
    print(_divider())
    try:
        module = importlib.import_module(chemin)
        if not hasattr(module, "demo"):
            print(_err(f"  {chemin} : pas de fonction demo()"))
            return
        module.demo()
    except ImportError as exc:
        print(_err(f"  Import error : {exc}"))
        print(_subtitle("  pip install -r requirements.txt"))
    except Exception as exc:
        print(_err(f"  Erreur : {type(exc).__name__}: {exc}"))


def _formulaire_perso(chemin: str, label: str) -> None:
    """GUI's 'Tester avec mes valeurs' equivalent for the terminal."""
    try:
        from gui_specs import (
            BYTES_HEX,
            BYTES_UTF8,
            CHOICE,
            INT,
            MULTILINE,
            SPECS,
            TEXT,
        )
    except ImportError as exc:
        print(_err(f"  Erreur : module gui_specs introuvable ({exc})"))
        return

    spec = SPECS.get(chemin)
    if spec is None:
        print()
        print(_label(label))
        print(_subtitle(
            "Pas de saisie personnalisee pour ce module.\n"
            "Choisissez 's' pour lancer le scenario pre-defini."
        ))
        return

    print()
    print(_label(label))
    print(_subtitle("Renseignez les valeurs ci-dessous (Entree = defaut)."))
    print(_divider())
    print(_label("PARAMETRES"))

    valeurs: dict = {}
    for champ in spec.champs:
        note = f" {_muted('- ' + champ.note)}" if champ.note else ""
        defaut_aff = champ.defaut
        if champ.type == CHOICE and champ.options:
            note = f" {_muted('[' + '/'.join(champ.options) + ']')}" if not note else note
        prompt = f"  {_accent(champ.label)}{note}\n    [{_muted(str(defaut_aff))}] > "
        try:
            saisie = input(prompt)
        except EOFError:
            print()
            return

        if saisie == "" and champ.defaut != "":
            saisie = str(champ.defaut)

        try:
            if champ.type == TEXT:
                valeurs[champ.cle] = saisie
            elif champ.type == MULTILINE:
                valeurs[champ.cle] = saisie
            elif champ.type == BYTES_UTF8:
                valeurs[champ.cle] = saisie.encode("utf-8")
            elif champ.type == INT:
                valeurs[champ.cle] = int(saisie or 0)
            elif champ.type == BYTES_HEX:
                txt = saisie.strip().replace(" ", "")
                valeurs[champ.cle] = bytes.fromhex(txt) if txt else b""
            elif champ.type == CHOICE:
                if champ.options and saisie not in champ.options:
                    saisie = champ.options[0]
                valeurs[champ.cle] = saisie
            else:
                valeurs[champ.cle] = saisie
        except ValueError as e:
            print(_err(f"  [ERREUR ENTREE] {champ.label}: {e}"))
            return

    print()
    print(_label("RESULTAT"))
    print(_divider())
    try:
        res = spec.runner(valeurs)
    except Exception as e:
        print(_err(f"  [ERREUR EXECUTION] {type(e).__name__}: {e}"))
        return
    print(res)


def _ouvrir_module(chemin: str, label: str) -> None:
    print()
    print(_label(label))
    print(_subtitle("Comment veux-tu lancer ce module ?"))
    print(f"  {_accent('s')}   Scenario pre-defini")
    print(f"  {_accent('i')}   Tester avec mes valeurs")
    print(f"  {_accent('q')}   Retour au menu")
    try:
        choix = input(f"\n  > ").strip().lower()
    except EOFError:
        print()
        return
    if choix in ("", "s", "scenario"):
        _executer_scenario(chemin)
    elif choix in ("i", "input", "valeurs"):
        _formulaire_perso(chemin, label)
    elif choix in ("q", "quit", "back"):
        return
    else:
        print(_err(f"  Inconnu : {choix}"))


def lancer(token):
    cle = _resoudre(token)
    if cle is None:
        print(_err(f"  Inconnu : {token}"))
        return
    chemin, label = cle
    # In non-interactive mode (CLI argument) keep scenario behaviour for back-compat.
    if not sys.stdin.isatty():
        _executer_scenario(chemin)
        return
    _ouvrir_module(chemin, label)


def lancer_tout():
    for cle in MODULES:
        chemin, _ = MODULES[cle]
        _executer_scenario(chemin)


def main():
    if len(sys.argv) > 1:
        token = sys.argv[1].strip().lower()
        if token == "all":
            lancer_tout()
        elif token in ("-h", "--help", "help"):
            print("Usage: python main.py [<module> | all]")
            print("  module : alias (e.g. 2.3) or theme.slug (e.g. symmetric.aes)")
        else:
            cle = _resoudre(token)
            if cle is None:
                print(_err(f"  Inconnu : {token}"))
                return
            _executer_scenario(cle[0])
        return
    while True:
        afficher_menu()
        try:
            choix = input(f"  {_accent('>')} ").strip().lower()
        except EOFError:
            print()
            break
        if choix in ("q", "quit", "exit"):
            print(_subtitle("  Au revoir."))
            break
        if choix == "all":
            lancer_tout()
        elif choix:
            lancer(choix)


if __name__ == "__main__":
    main()
