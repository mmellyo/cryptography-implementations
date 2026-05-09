"""Serpent (Anderson, Biham, Knudsen, 1998) - finaliste AES.

Implementation pure-Python en mode bitslice (saute IP/FP). Les S-boxes
sont appliquees colonne par colonne via le tableau de lookup ; cette
approche privilegie la lisibilite et la verifiabilite (les constantes
sont visibles) au detriment de la performance.

Validation : vecteurs officiels NESSIE Set 1 vector #0 pour Serpent-128
et Serpent-256.

Reference :
- Specification Serpent (cl.cam.ac.uk/~rja14/Papers/serpent.pdf)
- NESSIE test vectors (cosic.esat.kuleuven.be/nessie/testvectors/)
"""
import struct

PHI = 0x9E3779B9

SBOXES = (
    (3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12),
    (15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4),
    (8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2),
    (0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14),
    (1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13),
    (15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1),
    (7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0),
    (1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6),
)


def _rotl32(v, n):
    n &= 31
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def _sbox(idx, a, b, c, d):
    s = SBOXES[idx]
    out_a = out_b = out_c = out_d = 0
    for col in range(32):
        n = ((a >> col) & 1) | (((b >> col) & 1) << 1) | (((c >> col) & 1) << 2) | (((d >> col) & 1) << 3)
        m = s[n]
        out_a |= (m & 1) << col
        out_b |= ((m >> 1) & 1) << col
        out_c |= ((m >> 2) & 1) << col
        out_d |= ((m >> 3) & 1) << col
    return out_a, out_b, out_c, out_d


def _linear(a, b, c, d):
    a = _rotl32(a, 13)
    c = _rotl32(c, 3)
    b ^= a ^ c
    d ^= c ^ ((a << 3) & 0xFFFFFFFF)
    b = _rotl32(b, 1)
    d = _rotl32(d, 7)
    a ^= b ^ d
    c ^= d ^ ((b << 7) & 0xFFFFFFFF)
    a = _rotl32(a, 5)
    c = _rotl32(c, 22)
    return a, b, c, d


def expand_key(cle: bytes):
    if len(cle) > 32:
        raise ValueError("Serpent : cle 1..32 octets")
    pad = bytearray(cle)
    if len(pad) < 32:
        pad.append(0x01)
        while len(pad) < 32:
            pad.append(0x00)
    w = list(struct.unpack("<8I", bytes(pad)))
    for i in range(132):
        v = (w[i] ^ w[i + 3] ^ w[i + 5] ^ w[i + 7] ^ PHI ^ i) & 0xFFFFFFFF
        w.append(_rotl32(v, 11))
    prekeys = w[8:]
    K = []
    for i in range(33):
        sbox_idx = (3 - i) % 8
        a, b, c, d = prekeys[4 * i], prekeys[4 * i + 1], prekeys[4 * i + 2], prekeys[4 * i + 3]
        K.append(_sbox(sbox_idx, a, b, c, d))
    return K


def encrypt_block(bloc: bytes, K) -> bytes:
    if len(bloc) != 16:
        raise ValueError("Serpent : bloc 16 octets")
    a, b, c, d = struct.unpack("<4I", bloc)
    for i in range(31):
        ka, kb, kc, kd = K[i]
        a ^= ka
        b ^= kb
        c ^= kc
        d ^= kd
        a, b, c, d = _sbox(i % 8, a, b, c, d)
        a, b, c, d = _linear(a, b, c, d)
    ka, kb, kc, kd = K[31]
    a ^= ka; b ^= kb; c ^= kc; d ^= kd
    a, b, c, d = _sbox(7, a, b, c, d)
    ka, kb, kc, kd = K[32]
    a ^= ka; b ^= kb; c ^= kc; d ^= kd
    return struct.pack("<4I", a, b, c, d)
