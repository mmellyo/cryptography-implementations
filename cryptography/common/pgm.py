"""Lecture et ecriture d'images PGM (P5, niveaux de gris)."""
from pathlib import Path

ASSETS = Path(__file__).resolve().parent.parent / "assets"


def lire(chemin):
    data = Path(chemin).read_bytes()
    pos = 0
    def _token():
        nonlocal pos
        while pos < len(data) and data[pos:pos+1] in (b" ", b"\t", b"\n", b"\r"):
            pos += 1
        if pos < len(data) and data[pos:pos+1] == b"#":
            while pos < len(data) and data[pos:pos+1] != b"\n":
                pos += 1
            return _token()
        debut = pos
        while pos < len(data) and data[pos:pos+1] not in (b" ", b"\t", b"\n", b"\r"):
            pos += 1
        return data[debut:pos]
    magic = _token()
    if magic != b"P5":
        raise ValueError(f"Format PGM non supporte : {magic}")
    largeur = int(_token())
    hauteur = int(_token())
    maxval = int(_token())
    if maxval > 255:
        raise ValueError("PGM 16-bits non supporte")
    pos += 1
    pixels = data[pos:pos + largeur * hauteur]
    if len(pixels) != largeur * hauteur:
        raise ValueError("Donnees pixels incompletes")
    return largeur, hauteur, pixels


def ecrire(chemin, largeur, hauteur, pixels):
    entete = f"P5\n{largeur} {hauteur}\n255\n".encode("ascii")
    Path(chemin).write_bytes(entete + bytes(pixels[:largeur * hauteur]))


def chemin_asset(nom):
    return ASSETS / nom
