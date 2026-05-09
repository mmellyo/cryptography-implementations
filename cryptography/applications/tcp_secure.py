"""TCP/IP secure communication using the SecureChannel protocol."""
import socket
import threading
from contextlib import contextmanager

from applications.secure_channel import client_handshake, serveur_handshake


@contextmanager
def serveur(host: str = "127.0.0.1", port: int = 0):
    """Yields (socket_serveur, port) ; le caller doit appeler accept_chiffre()."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(1)
    try:
        yield sock, sock.getsockname()[1]
    finally:
        sock.close()


def accepter_session(sock_serveur):
    """Accepte une connexion entrante et execute le handshake serveur."""
    conn, _ = sock_serveur.accept()
    return serveur_handshake(conn), conn


def connexion_client(host: str, port: int):
    """Etablit une connexion TCP et execute le handshake client."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    return client_handshake(sock), sock


def echo_serveur(host: str = "127.0.0.1", port: int = 0):
    """Demarre un serveur d'echo securise dans un thread, renvoie (port, stop_event)."""
    stop = threading.Event()

    def boucle():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(1)
        sock.settimeout(0.5)
        port_attribue.append(sock.getsockname()[1])
        ready.set()
        try:
            while not stop.is_set():
                try:
                    conn, _ = sock.accept()
                except socket.timeout:
                    continue
                with conn:
                    try:
                        canal = serveur_handshake(conn)
                        while True:
                            msg = canal.recevoir()
                            canal.envoyer(b"echo: " + msg)
                    except (ConnectionError, ValueError, OSError):
                        pass
        finally:
            sock.close()

    port_attribue: list = []
    ready = threading.Event()
    thread = threading.Thread(target=boucle, daemon=True)
    thread.start()
    ready.wait(timeout=2.0)
    return port_attribue[0], stop, thread


def demo():
    print("\n" + "=" * 50)
    print("  TCP secure communication")
    print("=" * 50)

    port, stop, thread = echo_serveur()
    print(f"\n  Serveur d'echo demarre sur 127.0.0.1:{port}")
    try:
        canal, sock = connexion_client("127.0.0.1", port)
        with sock:
            print("  Handshake RSA-OAEP: OK")
            for msg in (b"Hello secure world", b"Deuxieme message", b"\x00\x01\x02 binaire"):
                canal.envoyer(msg)
                reponse = canal.recevoir()
                print(f"    -> {msg!r} | <- {reponse!r}")
        print("\n  Test de tampering :")
        from applications.secure_channel import SecureChannel
        canal2, sock2 = connexion_client("127.0.0.1", port)
        with sock2:
            mauvais = SecureChannel(sock2, canal2.cle_aes, b"\x00" * 32)
            mauvais.envoyer(b"frame falsifiee")
            try:
                _ = canal2.recevoir()
                print("    NON DETECTE")
            except (ValueError, ConnectionError) as e:
                print(f"    HMAC tampering rejete cote serveur ({type(e).__name__})")
    finally:
        stop.set()
        thread.join(timeout=2.0)


if __name__ == "__main__":
    demo()
