"""Transport-agnostic secure channel: RSA-OAEP handshake + AES-CTR + HMAC-SHA256.

Frame format on the wire:
    [4-byte big-endian length of ciphertext]
    [16-byte nonce]
    [ciphertext]
    [32-byte HMAC-SHA256(nonce || ciphertext)]

This is an educational protocol (no replay protection, no forward secrecy,
no certificate validation). For real deployments use TLS via `ssl`.
"""
import hmac as _hmac
import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

NONCE_SIZE = 16
TAG_SIZE = 32
AES_KEY_SIZE = 32
HMAC_KEY_SIZE = 32
LEN_PREFIX = 4


def _padding_oaep():
    return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def _hmac_sha256(cle: bytes, data: bytes) -> bytes:
    import hashlib
    return _hmac.new(cle, data, hashlib.sha256).digest()


class SecureChannel:
    """Encrypts-then-MACs frames over any (.send/.recv) byte-oriented transport."""

    def __init__(self, transport, cle_aes: bytes, cle_hmac: bytes):
        if len(cle_aes) != AES_KEY_SIZE:
            raise ValueError(f"AES key must be {AES_KEY_SIZE} bytes")
        if len(cle_hmac) != HMAC_KEY_SIZE:
            raise ValueError(f"HMAC key must be {HMAC_KEY_SIZE} bytes")
        self.transport = transport
        self.cle_aes = cle_aes
        self.cle_hmac = cle_hmac

    def envoyer(self, message: bytes) -> None:
        nonce = os.urandom(NONCE_SIZE)
        chiffreur = Cipher(algorithms.AES(self.cle_aes), modes.CTR(nonce)).encryptor()
        chiffre = chiffreur.update(message) + chiffreur.finalize()
        tag = _hmac_sha256(self.cle_hmac, nonce + chiffre)
        frame = struct.pack(">I", len(chiffre)) + nonce + chiffre + tag
        _send_all(self.transport, frame)

    def recevoir(self) -> bytes:
        header = _recv_exact(self.transport, LEN_PREFIX)
        n = struct.unpack(">I", header)[0]
        nonce = _recv_exact(self.transport, NONCE_SIZE)
        chiffre = _recv_exact(self.transport, n)
        tag = _recv_exact(self.transport, TAG_SIZE)
        attendu = _hmac_sha256(self.cle_hmac, nonce + chiffre)
        if not _hmac.compare_digest(tag, attendu):
            raise ValueError("HMAC verification failed: frame tampered or wrong key")
        dechiffreur = Cipher(algorithms.AES(self.cle_aes), modes.CTR(nonce)).decryptor()
        return dechiffreur.update(chiffre) + dechiffreur.finalize()


def _send_all(transport, data: bytes) -> None:
    if hasattr(transport, "sendall"):
        transport.sendall(data)
    else:
        envoye = 0
        while envoye < len(data):
            envoye += transport.send(data[envoye:])


def _recv_exact(transport, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = transport.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("transport closed before reading expected bytes")
        buf += chunk
    return buf


def serveur_handshake(transport):
    """Server side: send RSA pubkey, receive encrypted (aes_key || hmac_key)."""
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _send_all(transport, struct.pack(">I", len(pub_pem)) + pub_pem)

    n = struct.unpack(">I", _recv_exact(transport, LEN_PREFIX))[0]
    enveloppe = _recv_exact(transport, n)
    cles = priv.decrypt(enveloppe, _padding_oaep())
    if len(cles) != AES_KEY_SIZE + HMAC_KEY_SIZE:
        raise ValueError("Handshake: invalid key bundle length")
    return SecureChannel(transport, cles[:AES_KEY_SIZE], cles[AES_KEY_SIZE:])


def client_handshake(transport):
    """Client side: receive RSA pubkey, send encrypted random (aes_key || hmac_key)."""
    n = struct.unpack(">I", _recv_exact(transport, LEN_PREFIX))[0]
    pub_pem = _recv_exact(transport, n)
    pub = serialization.load_pem_public_key(pub_pem)
    if not isinstance(pub, rsa.RSAPublicKey):
        raise ValueError("Handshake: server did not send an RSA key")
    cle_aes = os.urandom(AES_KEY_SIZE)
    cle_hmac = os.urandom(HMAC_KEY_SIZE)
    enveloppe = pub.encrypt(cle_aes + cle_hmac, _padding_oaep())
    _send_all(transport, struct.pack(">I", len(enveloppe)) + enveloppe)
    return SecureChannel(transport, cle_aes, cle_hmac)
