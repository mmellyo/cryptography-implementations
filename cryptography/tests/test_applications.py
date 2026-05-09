"""TP6 - Tests des applications de communication securisee."""
import os
import socket
import threading

import pytest

pytest.importorskip("cryptography")
pytest.importorskip("sympy")

from applications.secure_channel import (
    AES_KEY_SIZE,
    HMAC_KEY_SIZE,
    SecureChannel,
    client_handshake,
    serveur_handshake,
)
from applications.tcp_secure import echo_serveur
from applications.udp_chat import (
    chiffrer_paquet,
    dechiffrer_paquet,
    serveur_chat,
)
from applications.voting import (
    chiffrer_vote,
    decompter,
    generer_election,
)


class TestSecureChannel:
    def _paire_sockets(self):
        a, b = socket.socketpair()
        return a, b

    def test_handshake_et_round_trip(self):
        a, b = self._paire_sockets()
        try:
            canaux = {}

            def cote_serveur():
                canaux["serveur"] = serveur_handshake(a)

            t = threading.Thread(target=cote_serveur, daemon=True)
            t.start()
            canaux["client"] = client_handshake(b)
            t.join(timeout=5.0)

            canaux["client"].envoyer(b"hello")
            assert canaux["serveur"].recevoir() == b"hello"

            canaux["serveur"].envoyer(b"reponse")
            assert canaux["client"].recevoir() == b"reponse"
        finally:
            a.close()
            b.close()

    def test_keys_share_avec_handshake(self):
        a, b = self._paire_sockets()
        try:
            results = {}

            def cote_serveur():
                results["s"] = serveur_handshake(a)

            t = threading.Thread(target=cote_serveur, daemon=True)
            t.start()
            results["c"] = client_handshake(b)
            t.join(timeout=5.0)

            assert results["s"].cle_aes == results["c"].cle_aes
            assert results["s"].cle_hmac == results["c"].cle_hmac
            assert len(results["s"].cle_aes) == AES_KEY_SIZE
            assert len(results["s"].cle_hmac) == HMAC_KEY_SIZE
        finally:
            a.close()
            b.close()

    def test_hmac_tampering_detecte(self):
        a, b = self._paire_sockets()
        try:
            cle_aes = os.urandom(AES_KEY_SIZE)
            cle_hmac = os.urandom(HMAC_KEY_SIZE)
            mauvaise_hmac = bytes(c ^ 1 for c in cle_hmac)
            envoyeur = SecureChannel(a, cle_aes, mauvaise_hmac)
            recevoir = SecureChannel(b, cle_aes, cle_hmac)
            envoyeur.envoyer(b"piege")
            with pytest.raises(ValueError, match="HMAC"):
                recevoir.recevoir()
        finally:
            a.close()
            b.close()

    def test_rejette_cles_de_taille_invalide(self):
        a, b = self._paire_sockets()
        try:
            with pytest.raises(ValueError):
                SecureChannel(a, b"trop court", os.urandom(HMAC_KEY_SIZE))
            with pytest.raises(ValueError):
                SecureChannel(a, os.urandom(AES_KEY_SIZE), b"court")
        finally:
            a.close()
            b.close()


class TestTCPSecure:
    def test_echo_serveur_round_trip(self):
        port, stop, thread = echo_serveur()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(("127.0.0.1", port))
            try:
                canal = client_handshake(sock)
                for msg in (b"hello", b"world", b"\x00\xff binaire"):
                    canal.envoyer(msg)
                    assert canal.recevoir() == b"echo: " + msg
            finally:
                sock.close()
        finally:
            stop.set()
            thread.join(timeout=2.0)


class TestUDPChat:
    def test_round_trip_envelope(self):
        cle_aes = os.urandom(AES_KEY_SIZE)
        cle_hmac = os.urandom(HMAC_KEY_SIZE)
        msg = b"hello via UDP"
        paquet = chiffrer_paquet(msg, cle_aes, cle_hmac)
        assert dechiffrer_paquet(paquet, cle_aes, cle_hmac) == msg

    def test_paquet_tampered_rejete(self):
        cle_aes = os.urandom(AES_KEY_SIZE)
        cle_hmac = os.urandom(HMAC_KEY_SIZE)
        paquet = bytearray(chiffrer_paquet(b"piege", cle_aes, cle_hmac))
        paquet[20] ^= 0x01
        with pytest.raises(ValueError, match="HMAC"):
            dechiffrer_paquet(bytes(paquet), cle_aes, cle_hmac)

    def test_mauvaise_cle_hmac_rejete(self):
        cle_aes = os.urandom(AES_KEY_SIZE)
        cle_hmac = os.urandom(HMAC_KEY_SIZE)
        paquet = chiffrer_paquet(b"x", cle_aes, cle_hmac)
        autre_hmac = os.urandom(HMAC_KEY_SIZE)
        with pytest.raises(ValueError, match="HMAC"):
            dechiffrer_paquet(paquet, cle_aes, autre_hmac)

    def test_paquet_trop_court_rejete(self):
        with pytest.raises(ValueError):
            dechiffrer_paquet(b"\x00" * 10, os.urandom(AES_KEY_SIZE), os.urandom(HMAC_KEY_SIZE))

    def test_serveur_udp_echo(self):
        cle_aes = os.urandom(AES_KEY_SIZE)
        cle_hmac = os.urandom(HMAC_KEY_SIZE)
        port, stop, thread = serveur_chat(0, cle_aes, cle_hmac)
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client.settimeout(2.0)
            client.sendto(chiffrer_paquet(b"ping", cle_aes, cle_hmac), ("127.0.0.1", port))
            data, _ = client.recvfrom(65536)
            assert dechiffrer_paquet(data, cle_aes, cle_hmac) == b"echo: ping"
            client.close()
        finally:
            stop.set()
            thread.join(timeout=2.0)


class TestVoting:
    @pytest.fixture(scope="class")
    def election(self):
        return generer_election(64)

    def test_decompte_correct(self, election):
        p, g, y, x = election
        votes = [1, 0, 1, 1, 0, 1, 0, 0, 1, 1]
        chiffres = [chiffrer_vote(p, g, y, v) for v in votes]
        total = decompter(p, g, x, chiffres, max_votants=len(votes))
        assert total == sum(votes)

    def test_vote_invalide_rejete(self, election):
        p, g, y, _ = election
        with pytest.raises(ValueError):
            chiffrer_vote(p, g, y, 2)
        with pytest.raises(ValueError):
            chiffrer_vote(p, g, y, -1)

    def test_non_determinisme_anonymat(self, election):
        p, g, y, _ = election
        e1 = chiffrer_vote(p, g, y, 0)
        e2 = chiffrer_vote(p, g, y, 0)
        e3 = chiffrer_vote(p, g, y, 1)
        assert e1 != e2  # deux E(0) sont differents
        assert e1 != e3  # E(0) != E(1)

    def test_total_borne_depasse_rejete(self, election):
        p, g, y, x = election
        chiffres = [chiffrer_vote(p, g, y, 1) for _ in range(5)]
        with pytest.raises(ValueError):
            decompter(p, g, x, chiffres, max_votants=2)
