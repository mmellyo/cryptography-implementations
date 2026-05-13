"""Demo BLE - cote CLIENT (central)."""

import sys
import time

from applications.ble_secure import client_ble


def main():
    print("[client] Scan BLE pour 'SecureChannelBLE' (30s max)...")
    try:
        canal, _ = client_ble("SecureChannelBLE", timeout_scan=30.0)
    except ConnectionError as e:
        print(f"[client] ERREUR : {e}")
        print("[client]   - Verifier que ble_serveur.py tourne sur Tensai.")
        print("[client]   - Verifier que Bluetooth est actif sur le Mac (Reglages).")
        print("[client]   - Distance < 10m entre les deux machines.")
        sys.exit(1)

    print("[client] Connecte + handshake termine. Envoi de 3 messages...\n")
    for i, msg in enumerate([b"hello", b"world", b"final"], start=1):
        canal.envoyer(msg)
        print(f"[client] Envoye  : {msg!r}")
        reponse = canal.recevoir()
        print(f"[client] Recu    : {reponse!r}")
        time.sleep(0.5)

    print("\n[client] Echange OK. Fermeture.")


if __name__ == "__main__":
    main()
