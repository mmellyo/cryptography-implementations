"""TP6 - Verifie le wrapper Bluetooth via mock socket.

Ces tests prouvent que `bluetooth_secure` cree un socket RFCOMM
(AF_BLUETOOTH + BTPROTO_RFCOMM), fait bind/listen/connect aux bons
parametres, et enchaine sur le handshake SecureChannel. Aucune carte
Bluetooth ni dependance externe n'est requise : on monkeypatch la
fabrique de socket. La couche cryptographique est deja testee dans
test_applications.py via socket.socketpair().
"""
from unittest.mock import MagicMock

import pytest

from applications import bluetooth_secure


@pytest.fixture
def fake_socket(monkeypatch):
    """Remplace la fabrique de socket RFCOMM par un mock."""
    sock = MagicMock(name="rfcomm_socket")
    factory = MagicMock(return_value=sock)
    monkeypatch.setattr(bluetooth_secure, "_nouveau_socket_rfcomm", factory)
    monkeypatch.setattr(bluetooth_secure, "_bluetooth_supporte", lambda: True)
    return sock, factory


def test_disponible_reflete_support_plateforme(monkeypatch):
    monkeypatch.setattr(bluetooth_secure, "_bluetooth_supporte", lambda: True)
    assert bluetooth_secure.disponible() is True
    monkeypatch.setattr(bluetooth_secure, "_bluetooth_supporte", lambda: False)
    assert bluetooth_secure.disponible() is False


def test_serveur_rfcomm_sans_support_leve_notimplemented(monkeypatch):
    monkeypatch.setattr(bluetooth_secure, "_bluetooth_supporte", lambda: False)
    with pytest.raises(NotImplementedError, match="AF_BLUETOOTH"):
        bluetooth_secure.serveur_rfcomm("uuid")


def test_client_rfcomm_sans_support_leve_notimplemented(monkeypatch):
    monkeypatch.setattr(bluetooth_secure, "_bluetooth_supporte", lambda: False)
    with pytest.raises(NotImplementedError, match="AF_BLUETOOTH"):
        bluetooth_secure.client_rfcomm("AA:BB:CC:DD:EE:FF")


def test_serveur_rfcomm_bind_et_listen(fake_socket):
    sock_mock, factory = fake_socket
    uuid = "00112233-4455-6677-8899-aabbccddeeff"
    sock = bluetooth_secure.serveur_rfcomm(uuid, port=1)

    factory.assert_called_once_with()
    sock_mock.bind.assert_called_once_with(("", 1))
    sock_mock.listen.assert_called_once_with(1)
    assert sock is sock_mock


def test_client_rfcomm_appelle_connect(fake_socket, monkeypatch):
    sock_mock, factory = fake_socket
    fake_handshake = MagicMock(return_value="canal_factice")
    monkeypatch.setattr(bluetooth_secure, "client_handshake", fake_handshake)

    canal, sock = bluetooth_secure.client_rfcomm("AA:BB:CC:DD:EE:FF", port=1)

    factory.assert_called_once_with()
    sock_mock.connect.assert_called_once_with(("AA:BB:CC:DD:EE:FF", 1))
    fake_handshake.assert_called_once_with(sock_mock)
    assert canal == "canal_factice"
    assert sock is sock_mock


def test_accepter_appelle_handshake_serveur(monkeypatch):
    conn = MagicMock()
    sock = MagicMock()
    sock.accept.return_value = (conn, ("AA:BB:CC:DD:EE:FF", 1))
    fake_handshake = MagicMock(return_value="canal_serveur")
    monkeypatch.setattr(bluetooth_secure, "serveur_handshake", fake_handshake)

    canal, returned_conn = bluetooth_secure.accepter(sock)

    sock.accept.assert_called_once()
    fake_handshake.assert_called_once_with(conn)
    assert canal == "canal_serveur"
    assert returned_conn is conn
