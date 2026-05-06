"""Menu principal - TPs Cryptographie"""
import importlib, sys

EXERCICES = {
    "1.1": ("TP1_Chiffrement_Classique.ex1_1_cesar", "Cesar"),
    "1.2": ("TP1_Chiffrement_Classique.ex1_2_vigenere", "Vigenere"),
    "1.3": ("TP1_Chiffrement_Classique.ex1_3_hill", "Hill"),
    "1.4": ("TP1_Chiffrement_Classique.ex1_4_otp", "OTP"),
    "2.1": ("TP2_Crypto_Symetrique.ex2_1_rc4", "RC4"),
    "2.2": ("TP2_Crypto_Symetrique.ex2_2_des", "DES/3DES"),
    "2.3": ("TP2_Crypto_Symetrique.ex2_3_aes", "AES"),
    "2.4": ("TP2_Crypto_Symetrique.ex2_4_finalistes_aes", "Finalistes AES"),
    "3.1": ("TP3_Crypto_Asymetrique.ex3_1_diffie_hellman", "Diffie-Hellman"),
    "3.2": ("TP3_Crypto_Asymetrique.ex3_2_rsa", "RSA"),
    "3.3": ("TP3_Crypto_Asymetrique.ex3_3_elgamal", "ElGamal"),
    "3.4": ("TP3_Crypto_Asymetrique.ex3_4_ecc", "ECC"),
    "4.1": ("TP4_Hachage.ex4_1_md5", "MD5"),
    "4.2": ("TP4_Hachage.ex4_2_sha256", "SHA-256"),
    "4.3": ("TP4_Hachage.ex4_3_sha512_compare", "SHA-512"),
    "5.1": ("TP5_Signatures.ex5_1_signature_rsa", "RSA-PSS"),
    "5.2": ("TP5_Signatures.ex5_2_signature_elgamal", "ElGamal Sig"),
    "5.3": ("TP5_Signatures.ex5_3_dsa_ecdsa", "DSA/ECDSA"),
}

TPS = {
    "1": "TP1 - Chiffrement Classique",
    "2": "TP2 - Crypto Symetrique",
    "3": "TP3 - Crypto Asymetrique",
    "4": "TP4 - Hachage",
    "5": "TP5 - Signatures",
}

def afficher_menu():
    print("\n" + "=" * 50)
    print("  TRAVAUX PRATIQUES - CRYPTOGRAPHIE")
    print("=" * 50)
    tp = ""
    for num, (_, nom) in EXERCICES.items():
        if num[0] != tp:
            tp = num[0]
            print(f"\n  -- {TPS[tp]} --")
        print(f"    [{num}] {nom}")
    print(f"\n    [q] Quitter")

def lancer(num):
    if num not in EXERCICES:
        print(f"  Inconnu : {num}"); return
    mod, nom = EXERCICES[num]
    try:
        importlib.import_module(mod).main()
    except ImportError as e:
        print(f"  Erreur d'import : {e}\n  pip install -r requirements.txt")
    except Exception as e:
        print(f"  Erreur : {e}")

def main():
    if len(sys.argv) > 1:
        lancer(sys.argv[1]); return
    while True:
        afficher_menu()
        c = input("\n  Choix : ").strip().lower()
        if c == 'q': break
        elif c in EXERCICES: lancer(c)
        else: print(f"  Invalide : {c}")

if __name__ == "__main__":
    main()
