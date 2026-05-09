"""Bluetooth RFCOMM secure communication.

Le protocole reutilise SecureChannel (RSA-OAEP + AES-CTR + HMAC-SHA256). La
couche transport utilise les sockets Bluetooth natifs de Python (AF_BLUETOOTH +
BTPROTO_RFCOMM), disponibles sous Windows depuis Python 3.9+. Aucune
dependance tierce (pybluez) n'est necessaire.

Le fonctionnement est identique a TCP (exercice 6.1) : seul le type de
socket change. Le meme SecureChannel est reutilise tel quel.
"""
import socket
import threading

from applications.secure_channel import client_handshake, serveur_handshake


def disponible() -> bool:
    """Verifie si le systeme supporte les sockets Bluetooth RFCOMM."""
    return hasattr(socket, "AF_BLUETOOTH") and hasattr(socket, "BTPROTO_RFCOMM")


def _adresse_locale() -> str:
    """Retourne l'adresse MAC de l'adaptateur Bluetooth local.

    Sous Windows, on peut binder sur la chaine vide pour laisser le
    systeme choisir l'adaptateur par defaut.
    """
    try:
        import subprocess
        result = subprocess.run(
            ["powershell", "-Command",
             "Get-NetAdapter -Name '*Bluetooth*' | Select-Object -ExpandProperty MacAddress"],
            capture_output=True, text=True, timeout=5,
        )
        mac = result.stdout.strip().replace("-", ":")
        if mac:
            return mac
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------------------
# Serveur RFCOMM
# ---------------------------------------------------------------------------

def serveur_rfcomm(host: str = "", port: int = 1):
    """Cree un socket RFCOMM en ecoute. Retourne (sock, port_effectif)."""
    if not disponible():
        raise NotImplementedError("AF_BLUETOOTH non disponible sur ce systeme.")
    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
    sock.bind((host, port))
    sock.listen(1)
    return sock


def accepter(sock):
    """Accepte une connexion entrante et execute le handshake serveur."""
    conn, addr = sock.accept()
    print(f"  Connexion Bluetooth recue de {addr}")
    canal = serveur_handshake(conn)
    return canal, conn


# ---------------------------------------------------------------------------
# Client RFCOMM
# ---------------------------------------------------------------------------

def client_rfcomm(adresse_mac: str, port: int = 1):
    """Etablit une connexion RFCOMM vers adresse_mac et execute le handshake client."""
    if not disponible():
        raise NotImplementedError("AF_BLUETOOTH non disponible sur ce systeme.")
    sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
    sock.connect((adresse_mac, port))
    canal = client_handshake(sock)
    return canal, sock


# ---------------------------------------------------------------------------
# Echo serveur (threaded) pour la demo
# ---------------------------------------------------------------------------

def echo_serveur_bt(host: str = "", port: int = 1):
    """Demarre un serveur d'echo securise Bluetooth dans un thread."""
    stop = threading.Event()

    def boucle():
        sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
        sock.bind((host, port))
        sock.listen(1)
        sock.settimeout(1.0)
        ready.set()
        try:
            while not stop.is_set():
                try:
                    conn, addr = sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    canal = serveur_handshake(conn)
                    while True:
                        msg = canal.recevoir()
                        canal.envoyer(b"echo: " + msg)
                except (ConnectionError, ValueError, OSError):
                    pass
                finally:
                    conn.close()
        finally:
            sock.close()

    ready = threading.Event()
    thread = threading.Thread(target=boucle, daemon=True)
    thread.start()
    ready.wait(timeout=3.0)
    return stop, thread


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def demo():
    print("\n" + "=" * 50)
    print("  Bluetooth (RFCOMM) secure communication")
    print("=" * 50)

    if not disponible():
        print("\n  AF_BLUETOOTH non disponible sur ce systeme.")
        print("  Python 3.9+ sous Windows est requis.")
        return

    print("\n  Support Bluetooth natif (AF_BLUETOOTH + BTPROTO_RFCOMM) : OK")

    mac = _adresse_locale()
    if mac:
        print(f"  Adresse MAC locale : {mac}")
    else:
        print("  Adresse MAC locale : non detectee")

    # --- Comparaison TCP vs Bluetooth ---
    print("\n  Comparaison des transports :")
    print("  ┌─────────────┬────────────────────────────────────┐")
    print("  │ TCP/IP      │ socket.AF_INET, SOCK_STREAM       │")
    print("  │ Bluetooth   │ socket.AF_BLUETOOTH, BTPROTO_RFCOMM│")
    print("  │ Protocole   │ SecureChannel identique            │")
    print("  │ Chiffrement │ RSA-OAEP + AES-CTR + HMAC-SHA256  │")
    print("  └─────────────┴────────────────────────────────────┘")

    # --- Demo fonctionnelle : loopback Bluetooth ---
    print("\n  Test loopback Bluetooth (serveur + client sur le meme adaptateur) :")
    try:
        # Creer le serveur
        srv_sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
        srv_sock.bind(("", 4))  # canal RFCOMM 4
        srv_sock.listen(1)
        srv_sock.settimeout(5.0)
        print("    Serveur RFCOMM en ecoute sur canal 4...")

        # Le client se connecte dans un thread
        resultats = {}

        def client_thread():
            try:
                cli_sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
                # Se connecter a l'adresse locale
                addr = mac.replace("-", ":") if mac else ""
                if not addr:
                    # Essai alternatif : recuperer l'adresse du serveur
                    addr = srv_sock.getsockname()[0]
                cli_sock.connect((addr, 4))
                canal_cli = client_handshake(cli_sock)
                resultats["canal_cli"] = canal_cli
                resultats["sock_cli"] = cli_sock
                resultats["handshake"] = True
            except Exception as e:
                resultats["erreur_client"] = f"{type(e).__name__}: {e}"

        t = threading.Thread(target=client_thread, daemon=True)
        t.start()

        # Attendre la connexion cote serveur
        try:
            conn, addr = srv_sock.accept()
            print(f"    Connexion acceptee de {addr}")
            canal_srv = serveur_handshake(conn)
            print("    Handshake RSA-OAEP : OK")
        except socket.timeout:
            print("    [TIMEOUT] Pas de connexion entrante.")
            print("    Note : le loopback Bluetooth n'est pas supporte sur tous")
            print("    les adaptateurs. Cela necessite normalement 2 appareils.")
            srv_sock.close()
            # Montrer que le code fonctionne avec un fallback TCP
            _demo_fallback_tcp()
            return

        t.join(timeout=5.0)

        if "erreur_client" in resultats:
            print(f"    [ERREUR CLIENT] {resultats['erreur_client']}")
            conn.close()
            srv_sock.close()
            _demo_fallback_tcp()
            return

        canal_cli = resultats["canal_cli"]
        sock_cli = resultats["sock_cli"]

        # Echange de messages chiffres
        messages = [b"Hello Bluetooth!", b"Message securise via RFCOMM", b"\x00\x01\x02 binaire"]
        for msg in messages:
            canal_cli.envoyer(msg)
            recu = canal_srv.recevoir()
            canal_srv.envoyer(b"echo: " + recu)
            reponse = canal_cli.recevoir()
            print(f"    -> {msg!r} | <- {reponse!r}")

        # Test de tampering
        print("\n    Test de tampering :")
        from applications.secure_channel import SecureChannel
        mauvais = SecureChannel(sock_cli, canal_cli.cle_aes, b"\x00" * 32)
        mauvais.envoyer(b"frame falsifiee")
        try:
            _ = canal_srv.recevoir()
            print("      NON DETECTE")
        except ValueError as e:
            print(f"      HMAC tampering rejete : {e}")

        conn.close()
        sock_cli.close()
        srv_sock.close()
        print("\n    Session Bluetooth fermee.")

    except OSError as e:
        print(f"    [ERREUR] {type(e).__name__}: {e}")
        print("    Le loopback Bluetooth n'est pas supporte par cet adaptateur.")
        _demo_fallback_tcp()


def _demo_fallback_tcp():
    """Quand le loopback BT ne marche pas, montre que le code est fonctionnel via TCP."""
    print("\n  Demonstration via TCP (meme protocole SecureChannel) :")
    print("  Le code Bluetooth est IDENTIQUE — seul le type de socket change :")
    print("    TCP  : socket.socket(AF_INET,      SOCK_STREAM)")
    print("    BT   : socket.socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM)")
    print("\n  Preuve via TCP loopback :")

    import socket as _s
    srv = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
    srv.setsockopt(_s.SOL_SOCKET, _s.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    srv.settimeout(3.0)

    resultats = {}

    def cli():
        try:
            cs = _s.socket(_s.AF_INET, _s.SOCK_STREAM)
            cs.connect(("127.0.0.1", port))
            resultats["canal"] = client_handshake(cs)
            resultats["sock"] = cs
        except Exception as e:
            resultats["err"] = str(e)

    t = threading.Thread(target=cli, daemon=True)
    t.start()
    conn, _ = srv.accept()
    canal_s = serveur_handshake(conn)
    t.join(timeout=3.0)
    canal_c = resultats["canal"]

    for msg in (b"Hello via SecureChannel", b"Fonctionne sur TCP et BT"):
        canal_c.envoyer(msg)
        recu = canal_s.recevoir()
        print(f"    -> {msg!r} | <- {recu!r}")

    conn.close()
    resultats["sock"].close()
    srv.close()
    print("\n  Le meme SecureChannel fonctionne sur les deux transports.")
    print("  Pour un test BT reel : 2 machines avec Bluetooth appairees.")


if __name__ == "__main__":
    demo()
