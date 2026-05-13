"""Demo BLE - cote SERVEUR (peripheral)."""

from applications.ble_secure import accepter, serveur_ble


def main():
    print("[serveur] Demarrage du peripheral BLE 'SecureChannelBLE'...")
    print("[serveur] En attente d'un central (lance ble_client.py sur le Mac)...")
    transport = serveur_ble("SecureChannelBLE")
    print("[serveur] Central connecte ! Handshake en cours...")
    canal, _ = accepter(transport)
    print("[serveur] Handshake termine. Boucle d'echo demarree.\n")

    try:
        while True:
            msg = canal.recevoir()
            print(f"[serveur] Recu  : {msg!r}")
            reponse = b"echo from Linux: " + msg
            canal.envoyer(reponse)
            print(f"[serveur] Envoye : {reponse!r}\n")
    except (ConnectionError, KeyboardInterrupt):
        print("[serveur] Fin.")


if __name__ == "__main__":
    main()
