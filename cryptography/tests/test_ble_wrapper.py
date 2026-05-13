"""TP6 - Verifie le pont sync/async BLE sans necessiter bleak/bless.

Le coeur de la couche BLE est `_BleTransport` : il faut s'assurer que
.feed() / .recv() / .send() respectent la semantique socket attendue par
SecureChannel, et que la fragmentation par chunks fonctionne. On
monkeypatch la coroutine d'envoi pour eviter tout I/O reseau.
"""
import asyncio
import threading
from unittest.mock import MagicMock

import pytest

from applications import ble_secure
from applications.ble_secure import (
    DEFAULT_CHUNK_SIZE,
    _BleTransport,
)


@pytest.fixture
def loop_thread():
    """Boucle asyncio dans un thread daemon, fermee a la fin du test."""
    loop = asyncio.new_event_loop()
    t = threading.Thread(target=loop.run_forever, daemon=True)
    t.start()
    yield loop
    loop.call_soon_threadsafe(loop.stop)
    t.join(timeout=2.0)
    loop.close()


def test_disponible_reflete_imports(monkeypatch):
    # Sans aucune dependance BLE installee, disponible() peut retourner True
    # (si bleak ou bless est installe). On verifie au moins que les helpers
    # retournent un booleen.
    assert isinstance(ble_secure.disponible_central(), bool)
    assert isinstance(ble_secure.disponible_peripheral(), bool)
    assert isinstance(ble_secure.disponible(), bool)


def test_feed_puis_recv_retourne_les_octets(loop_thread):
    transport = _BleTransport(loop_thread, send_coro_factory=MagicMock())
    transport.feed(b"hello world")
    assert transport.recv(5) == b"hello"
    assert transport.recv(100) == b" world"


def test_recv_bloque_jusqu_a_feed(loop_thread):
    transport = _BleTransport(loop_thread, send_coro_factory=MagicMock())
    resultat = []

    def lecteur():
        resultat.append(transport.recv(4))

    t = threading.Thread(target=lecteur)
    t.start()
    # Le thread doit etre en attente (pas encore de donnees)
    t.join(timeout=0.2)
    assert t.is_alive()
    transport.feed(b"abcd")
    t.join(timeout=2.0)
    assert not t.is_alive()
    assert resultat == [b"abcd"]


def test_recv_apres_close_leve_connectionerror(loop_thread):
    transport = _BleTransport(loop_thread, send_coro_factory=MagicMock())
    transport.close()
    with pytest.raises(ConnectionError):
        transport.recv(1)


def test_send_fragmente_par_chunks(loop_thread):
    """Un envoi > DEFAULT_CHUNK_SIZE doit etre decoupe en plusieurs writes."""
    chunks_envoyes = []
    event = threading.Event()

    async def fake_send(chunk: bytes):
        chunks_envoyes.append(bytes(chunk))

    transport = _BleTransport(loop_thread, send_coro_factory=fake_send)
    payload = b"X" * (DEFAULT_CHUNK_SIZE * 2 + 50)
    transport.send(payload)
    event.wait(timeout=0.1)

    assert b"".join(chunks_envoyes) == payload
    assert len(chunks_envoyes) == 3
    assert len(chunks_envoyes[0]) == DEFAULT_CHUNK_SIZE
    assert len(chunks_envoyes[1]) == DEFAULT_CHUNK_SIZE
    assert len(chunks_envoyes[2]) == 50


def test_send_apres_close_leve(loop_thread):
    transport = _BleTransport(loop_thread, send_coro_factory=MagicMock())
    transport.close()
    with pytest.raises(ConnectionError):
        transport.send(b"x")


def test_sendall_alias_send(loop_thread):
    """SecureChannel utilise sendall() en priorite : doit aussi marcher."""
    chunks_envoyes = []

    async def fake_send(chunk: bytes):
        chunks_envoyes.append(bytes(chunk))

    transport = _BleTransport(loop_thread, send_coro_factory=fake_send)
    transport.sendall(b"hello")
    assert b"".join(chunks_envoyes) == b"hello"


def test_handshake_complet_sur_paire_de_transports(loop_thread):
    """Scenario d'integration : deux _BleTransport relies cote a cote
    valident que SecureChannel handshake puis echange chiffre fonctionne.

    Equivaut a `tests/test_bluetooth_loopback.py` mais pour BLE.
    """
    transport_a = None
    transport_b = None

    async def send_a_vers_b(chunk):
        transport_b.feed(bytes(chunk))

    async def send_b_vers_a(chunk):
        transport_a.feed(bytes(chunk))

    transport_a = _BleTransport(loop_thread, send_a_vers_b)
    transport_b = _BleTransport(loop_thread, send_b_vers_a)

    from applications.secure_channel import client_handshake, serveur_handshake

    canaux = {}

    def cote_serveur():
        canaux["serveur"] = serveur_handshake(transport_a)

    t = threading.Thread(target=cote_serveur, daemon=True)
    t.start()
    canaux["client"] = client_handshake(transport_b)
    t.join(timeout=15.0)
    assert not t.is_alive(), "handshake serveur n'a pas termine"

    for msg in (b"hi", b"\x00\xff", b"y" * 500):
        canaux["client"].envoyer(msg)
        assert canaux["serveur"].recevoir() == msg
        canaux["serveur"].envoyer(b"echo:" + msg)
        assert canaux["client"].recevoir() == b"echo:" + msg

    assert canaux["client"].cle_aes == canaux["serveur"].cle_aes
    assert canaux["client"].cle_hmac == canaux["serveur"].cle_hmac
