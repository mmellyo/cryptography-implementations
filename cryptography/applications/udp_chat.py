"""UDP chat with AES-CTR + HMAC-SHA256 envelope per packet."""
import hmac as _hmac
import os
import socket
import threading

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

NONCE_SIZE = 16
TAG_SIZE = 32
AES_KEY_SIZE = 32
HMAC_KEY_SIZE = 32


def _hmac_sha256(cle: bytes, data: bytes) -> bytes:
    import hashlib
    return _hmac.new(cle, data, hashlib.sha256).digest()


def chiffrer_paquet(message: bytes, cle_aes: bytes, cle_hmac: bytes) -> bytes:
    """Frame UDP : nonce(16) || ciphertext || tag(32). Tag couvre nonce+chiffre."""
    if len(cle_aes) != AES_KEY_SIZE or len(cle_hmac) != HMAC_KEY_SIZE:
        raise ValueError("Tailles de cles invalides")
    nonce = os.urandom(NONCE_SIZE)
    chiffreur = Cipher(algorithms.AES(cle_aes), modes.CTR(nonce)).encryptor()
    chiffre = chiffreur.update(message) + chiffreur.finalize()
    tag = _hmac_sha256(cle_hmac, nonce + chiffre)
    return nonce + chiffre + tag


def dechiffrer_paquet(paquet: bytes, cle_aes: bytes, cle_hmac: bytes) -> bytes:
    if len(paquet) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Paquet trop court")
    nonce = paquet[:NONCE_SIZE]
    tag = paquet[-TAG_SIZE:]
    chiffre = paquet[NONCE_SIZE:-TAG_SIZE]
    attendu = _hmac_sha256(cle_hmac, nonce + chiffre)
    if not _hmac.compare_digest(tag, attendu):
        raise ValueError("HMAC invalide : paquet falsifie ou cle incorrecte")
    dechiffreur = Cipher(algorithms.AES(cle_aes), modes.CTR(nonce)).decryptor()
    return dechiffreur.update(chiffre) + dechiffreur.finalize()


def serveur_chat(port: int = 0, cle_aes: bytes = b"", cle_hmac: bytes = b""):
    """Demarre un echo-serveur UDP qui reflete les messages dechiffres."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    sock.settimeout(0.5)
    port_attribue = sock.getsockname()[1]
    stop = threading.Event()

    def boucle():
        while not stop.is_set():
            try:
                data, addr = sock.recvfrom(65536)
            except socket.timeout:
                continue
            try:
                clair = dechiffrer_paquet(data, cle_aes, cle_hmac)
                reponse = chiffrer_paquet(b"echo: " + clair, cle_aes, cle_hmac)
                sock.sendto(reponse, addr)
            except ValueError:
                continue
        sock.close()

    thread = threading.Thread(target=boucle, daemon=True)
    thread.start()
    return port_attribue, stop, thread


def demo():
    print("\n" + "=" * 50)
    print("  UDP secure chat")
    print("=" * 50)

    cle_aes = os.urandom(AES_KEY_SIZE)
    cle_hmac = os.urandom(HMAC_KEY_SIZE)
    port, stop, thread = serveur_chat(0, cle_aes, cle_hmac)
    print(f"\n  Serveur UDP demarre sur 127.0.0.1:{port}")
    print(f"  Cle AES (hex)  : {cle_aes.hex()[:32]}...")
    print(f"  Cle HMAC (hex) : {cle_hmac.hex()[:32]}...")

    try:
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(2.0)
        for msg in (b"hello via UDP", b"second message", b"binaire \x00\xff\x10"):
            client.sendto(chiffrer_paquet(msg, cle_aes, cle_hmac), ("127.0.0.1", port))
            data, _ = client.recvfrom(65536)
            print(f"    -> {msg!r} | <- {dechiffrer_paquet(data, cle_aes, cle_hmac)!r}")

        print("\n  Test tampering :")
        paquet = bytearray(chiffrer_paquet(b"piege", cle_aes, cle_hmac))
        paquet[20] ^= 0xFF  # corrompt le ciphertext
        try:
            dechiffrer_paquet(bytes(paquet), cle_aes, cle_hmac)
            print("    NON DETECTE")
        except ValueError as e:
            print(f"    Detecte : {e}")

        print("\n  Test mauvaise cle :")
        try:
            dechiffrer_paquet(chiffrer_paquet(b"x", cle_aes, cle_hmac),
                              cle_aes, os.urandom(HMAC_KEY_SIZE))
            print("    NON DETECTE")
        except ValueError as e:
            print(f"    Detecte : {e}")

        client.close()
    finally:
        stop.set()
        thread.join(timeout=2.0)


if __name__ == "__main__":
    demo()
