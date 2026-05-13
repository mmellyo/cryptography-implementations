"""TP6 - Test d'integration : protocole Bluetooth simule sur socketpair.

`socket.socketpair()` est API-equivalent a un BluetoothSocket(RFCOMM) du
point de vue du SecureChannel : meme send/recv stream-oriented. Ce test
prouve que le scenario complet (handshake + envoi/reception chiffre +
verification HMAC) fonctionne sur n'importe quel transport socket-like,
donc fonctionnera identiquement sur RFCOMM reel.
"""
import socket
import threading

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("sympy")

from applications.secure_channel import client_handshake, serveur_handshake


def test_scenario_bluetooth_complet_via_socketpair():
    """Simule une session Bluetooth complete : handshake + echange
    bidirectionnel + integrite preservee."""
    a, b = socket.socketpair()
    try:
        canaux = {}

        def cote_serveur():
            canaux["serveur"] = serveur_handshake(a)

        t = threading.Thread(target=cote_serveur, daemon=True)
        t.start()
        canaux["client"] = client_handshake(b)
        t.join(timeout=10.0)

        # Echange bidirectionnel comme dans une vraie session BT
        for msg in (b"hello bluetooth", b"\x00\xff binaire", b"x" * 1000):
            canaux["client"].envoyer(msg)
            assert canaux["serveur"].recevoir() == msg

            canaux["serveur"].envoyer(b"reponse: " + msg)
            assert canaux["client"].recevoir() == b"reponse: " + msg

        # Verifie que les cles negociees sont identiques cote a cote
        assert canaux["client"].cle_aes == canaux["serveur"].cle_aes
        assert canaux["client"].cle_hmac == canaux["serveur"].cle_hmac
    finally:
        a.close()
        b.close()
