"""Bluetooth RFCOMM secure communication.

Le protocole reutilise SecureChannel (RSA-OAEP + AES-CTR + HMAC-SHA256). La
couche transport utilise le module `socket` de la bibliotheque standard via
`AF_BLUETOOTH` + `BTPROTO_RFCOMM`. C'est supporte nativement sous Linux
(noyau + BlueZ) ; pybluez n'est plus necessaire ni utilise (il ne compile
plus sur Python 3.12+).

Limitations connues :
  - Linux uniquement. macOS / Windows n'exposent pas `AF_BLUETOOTH` via
    le module `socket` de CPython. Sur ces plateformes, `disponible()`
    renvoie False et les appels echouent avec NotImplementedError.
  - Pas d'enregistrement SDP : le client doit connaitre l'adresse MAC du
    serveur et le canal RFCOMM (1 par defaut). Pour publier le service
    dans la base SDP, utiliser `sdptool add SP` ou BlueZ via D-Bus.
"""
import socket

from applications.secure_channel import client_handshake, serveur_handshake


def _bluetooth_supporte() -> bool:
    return hasattr(socket, "AF_BLUETOOTH") and hasattr(socket, "BTPROTO_RFCOMM")


def disponible() -> bool:
    return _bluetooth_supporte()


def _nouveau_socket_rfcomm():
    if not _bluetooth_supporte():
        raise NotImplementedError(
            "AF_BLUETOOTH / BTPROTO_RFCOMM indisponible sur cette plateforme. "
            "RFCOMM via socket stdlib est supporte sous Linux uniquement."
        )
    return socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)


def serveur_rfcomm(uuid: str, port: int = 1):  # noqa: ARG001 - uuid conserve pour compat API
    sock = _nouveau_socket_rfcomm()
    sock.bind(("", port))
    sock.listen(1)
    return sock


def accepter(sock):
    conn, _ = sock.accept()
    return serveur_handshake(conn), conn


def client_rfcomm(adresse_mac: str, port: int = 1):
    sock = _nouveau_socket_rfcomm()
    sock.connect((adresse_mac, port))
    return client_handshake(sock), sock


def demo():
    print("\n" + "=" * 50)
    print("  Bluetooth (RFCOMM) secure communication")
    print("=" * 50)
    if not disponible():
        print("\n  AF_BLUETOOTH indisponible. Cette demo necessite Linux + BlueZ.")
        print("  Sur macOS / Windows, le module socket de CPython n'expose pas")
        print("  RFCOMM ; pas de solution stdlib disponible.")
        return
    print("\n  Stack disponible. Cote serveur :")
    print("    sock = serveur_rfcomm('00112233-4455-6677-8899-aabbccddeeff')")
    print("    canal, conn = accepter(sock)")
    print("\n  Cote client (adresse MAC + canal du serveur) :")
    print("    canal, _ = client_rfcomm('AA:BB:CC:DD:EE:FF', port=1)")


if __name__ == "__main__":
    demo()
