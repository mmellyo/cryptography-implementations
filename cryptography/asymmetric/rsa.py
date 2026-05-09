"""RSA-OAEP with hybrid RSA + AES encryption and timing comparison."""
import os
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

TAILLES_VALIDES = (512, 1024, 2048, 3072, 4096)


def generer_cles(taille_bits: int = 2048):
    if taille_bits not in TAILLES_VALIDES:
        raise ValueError(f"RSA : taille parmi {TAILLES_VALIDES}")
    priv = rsa.generate_private_key(public_exponent=65537, key_size=taille_bits)
    return priv, priv.public_key()


def _padding_oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def chiffrer(pub, message: bytes) -> bytes:
    return pub.encrypt(message, _padding_oaep())


def dechiffrer(priv, chiffre: bytes) -> bytes:
    return priv.decrypt(chiffre, _padding_oaep())


def hybride_rsa_aes(taille_donnees: int = 1024 * 1024, taille_rsa: int = 2048):
    priv, pub = generer_cles(taille_rsa)
    donnees = os.urandom(taille_donnees)
    cle_aes = os.urandom(32)
    nonce = os.urandom(16)

    t0 = time.perf_counter()
    cle_chiffree = chiffrer(pub, cle_aes)
    t_rsa_enc = time.perf_counter() - t0

    t0 = time.perf_counter()
    chiffreur = Cipher(algorithms.AES(cle_aes), modes.CTR(nonce)).encryptor()
    donnees_chiffrees = chiffreur.update(donnees) + chiffreur.finalize()
    t_aes_enc = time.perf_counter() - t0

    t0 = time.perf_counter()
    cle_recue = dechiffrer(priv, cle_chiffree)
    t_rsa_dec = time.perf_counter() - t0

    t0 = time.perf_counter()
    dechiffreur = Cipher(algorithms.AES(cle_recue), modes.CTR(nonce)).decryptor()
    donnees_recues = dechiffreur.update(donnees_chiffrees) + dechiffreur.finalize()
    t_aes_dec = time.perf_counter() - t0

    print(f"  Donnees       : {taille_donnees // 1024} Ko")
    print(f"  RSA-{taille_rsa}      : enc {t_rsa_enc * 1000:7.2f} ms | dec {t_rsa_dec * 1000:7.2f} ms")
    print(f"  AES-256-CTR   : enc {t_aes_enc * 1000:7.2f} ms | dec {t_aes_dec * 1000:7.2f} ms")
    debit = taille_donnees / (1024 * 1024) / max(t_aes_enc, 1e-9)
    print(f"  Debit AES     : {debit:.1f} Mo/s")
    print(f"  Integre       : {donnees == donnees_recues}")


def demo():
    print("\n" + "=" * 50)
    print("  RSA")
    print("=" * 50)
    priv, pub = generer_cles(2048)
    msg = b"Message court chiffre par RSA-OAEP"
    chiffre = chiffrer(pub, msg)
    print(f"\n  Round-trip OAEP : {dechiffrer(priv, chiffre) == msg}")
    print(f"  Non-determinisme : {chiffrer(pub, msg) != chiffrer(pub, msg)}")
    print("\n  Hybride RSA + AES sur 1 Mo :")
    hybride_rsa_aes()


if __name__ == "__main__":
    demo()
