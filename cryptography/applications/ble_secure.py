"""Bluetooth Low Energy secure communication.

Alternative cross-plateforme a RFCOMM. Le protocole SecureChannel
(RSA-OAEP + AES-CTR + HMAC-SHA256) est inchange ; seul le transport
differe. Topologie :

  - Peripheral (Linux) : `bless` expose un service GATT advertise via BlueZ.
  - Central (macOS)    : `bleak` scanne, se connecte, souscrit aux notify.

Le service GATT comporte deux caracteristiques :
  - RX (write) : Central -> Peripheral
  - TX (notify): Peripheral -> Central

bleak et bless sont async-only. Une couche d'adaptation `_BleTransport`
ponte l'API synchrone .send()/.recv() attendue par SecureChannel et la
boucle asyncio qui tourne dans un thread dedie. La fragmentation
(MTU BLE = 23 par defaut, jusqu'a ~512 apres negociation) est gerÃ©e
automatiquement : SecureChannel emet ses trames, _BleTransport les
decoupe en chunks de DEFAULT_CHUNK_SIZE octets.

Limitations :
  - Pas de pairing/bonding (educational only).
  - Bonding system varies par OS : sur Linux il faut souvent que le
    peripherique soit deja appaire pour eviter les prompts BlueZ.
  - bless ne notifie pas la souscription du central -> le central
    envoie un octet "hello" apres souscription pour declencher la suite.
"""
import asyncio
import threading

from applications.secure_channel import client_handshake, serveur_handshake

SERVICE_UUID = "00112233-4455-6677-8899-aabbccddeeff"
RX_CHAR_UUID = "00112233-4455-6677-8899-aabbccddee01"
TX_CHAR_UUID = "00112233-4455-6677-8899-aabbccddee02"

DEFAULT_CHUNK_SIZE = 180
# Multi-byte marker so it cannot be confused with real protocol bytes
# (SecureChannel framing starts with a 4-byte length prefix whose first
# bytes are often 0x00 for typical sizes). The central sends this with
# ack-required so it is strictly ordered before any handshake data.
_HELLO_MARKER = b"BLEHELLO_v1\x00"


def disponible_central() -> bool:
    try:
        import bleak  # noqa: F401
        return True
    except ImportError:
        return False


def disponible_peripheral() -> bool:
    try:
        import bless  # noqa: F401
        return True
    except ImportError:
        return False


def disponible() -> bool:
    return disponible_central() or disponible_peripheral()


class _BleTransport:
    """Bridge sync SecureChannel API <-> async BLE I/O on worker thread.

    .recv(n) bloque jusqu'a ce qu'au moins 1 octet soit disponible puis
    retourne jusqu'a n octets (semantique socket : SecureChannel utilise
    _recv_exact donc les lectures partielles sont OK).

    .send(data) fragmente en chunks et soumet l'envoi a la boucle asyncio
    via run_coroutine_threadsafe.
    """

    def __init__(self, loop, send_coro_factory):
        self._loop = loop
        self._send_coro_factory = send_coro_factory
        self._rx_buf = bytearray()
        self._rx_event = threading.Event()
        self._lock = threading.Lock()
        self._closed = False

    def feed(self, data: bytes) -> None:
        if not data:
            return
        with self._lock:
            self._rx_buf.extend(data)
            self._rx_event.set()

    def recv(self, n: int) -> bytes:
        while True:
            with self._lock:
                if self._rx_buf:
                    out = bytes(self._rx_buf[:n])
                    del self._rx_buf[: len(out)]
                    if not self._rx_buf:
                        self._rx_event.clear()
                    return out
                if self._closed:
                    raise ConnectionError("BLE transport closed")
            self._rx_event.wait(timeout=1.0)

    def send(self, data: bytes) -> int:
        if self._closed:
            raise ConnectionError("BLE transport closed")
        future = asyncio.run_coroutine_threadsafe(
            self._send_chunks(data), self._loop
        )
        future.result(timeout=30.0)
        return len(data)

    def sendall(self, data: bytes) -> None:
        self.send(data)

    async def _send_chunks(self, data: bytes) -> None:
        for i in range(0, len(data), DEFAULT_CHUNK_SIZE):
            await self._send_coro_factory(data[i : i + DEFAULT_CHUNK_SIZE])

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._rx_event.set()


# ---------------------------------------------------------------------------
# Peripheral side (Linux, bless)
# ---------------------------------------------------------------------------


class _PeripheralController:
    """bless GATT server on a private asyncio loop in a worker thread."""

    def __init__(self, nom: str = "SecureChannelBLE"):
        self.nom = nom
        self._loop = None
        self._thread = None
        self._transport: _BleTransport | None = None
        self._ready = threading.Event()
        self._hello_received = threading.Event()
        self._error: Exception | None = None

    def demarrer(self, timeout_hello: float = 300.0) -> _BleTransport:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=30.0)
        if self._error is not None:
            raise self._error
        if not self._hello_received.wait(timeout=timeout_hello):
            raise TimeoutError(
                "Aucun central n'a ecrit l'octet hello avant timeout"
            )
        if self._transport is None:
            raise RuntimeError("BLE peripheral non initialise")
        return self._transport

    def _run(self) -> None:
        try:
            from bless import (
                BlessServer,
                GATTAttributePermissions,
                GATTCharacteristicProperties,
            )
        except ImportError as e:
            err = ImportError(
                "bless non installe. Installer via 'pip install bless'."
            )
            err.__cause__ = e
            self._error = err
            self._ready.set()
            return

        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        try:
            self._loop.run_until_complete(self._setup_and_run(
                BlessServer, GATTCharacteristicProperties, GATTAttributePermissions
            ))
        except Exception as e:
            self._error = e
            self._ready.set()

    async def _setup_and_run(
        self, BlessServer, GATTCharacteristicProperties, GATTAttributePermissions
    ) -> None:
        srv = BlessServer(name=self.nom, loop=self._loop)

        def read_cb(characteristic, **kwargs):
            return characteristic.value or b""

        def write_cb(characteristic, value, **kwargs):
            data = bytes(value)
            if not self._hello_received.is_set():
                # First write from central MUST be the hello marker. Anything
                # else is discarded (stale write from a previous session) until
                # we see the marker. The marker itself is never fed to the
                # transport; only data after it counts as protocol bytes.
                idx = data.find(_HELLO_MARKER)
                if idx < 0:
                    return
                self._hello_received.set()
                data = data[idx + len(_HELLO_MARKER):]
            if self._transport is not None and data:
                self._transport.feed(data)

        srv.read_request_func = read_cb
        srv.write_request_func = write_cb

        await srv.add_new_service(SERVICE_UUID)
        await srv.add_new_characteristic(
            SERVICE_UUID,
            RX_CHAR_UUID,
            GATTCharacteristicProperties.write
            | GATTCharacteristicProperties.write_without_response,
            None,
            GATTAttributePermissions.writeable,
        )
        await srv.add_new_characteristic(
            SERVICE_UUID,
            TX_CHAR_UUID,
            GATTCharacteristicProperties.notify | GATTCharacteristicProperties.read,
            None,
            GATTAttributePermissions.readable,
        )
        await srv.start()

        async def notify(chunk: bytes) -> None:
            tx_char = srv.get_characteristic(TX_CHAR_UUID)
            tx_char.value = bytearray(chunk)
            srv.update_value(SERVICE_UUID, TX_CHAR_UUID)
            # Yield to BlueZ so the notification ATT PDU is actually flushed
            # before the next chunk overwrites tx_char.value. Without this,
            # rapid successive notifications can coalesce and drop frames.
            await asyncio.sleep(0.02)

        self._transport = _BleTransport(self._loop, notify)
        self._ready.set()

        # Keep the loop alive; bless server runs in background tasks.
        while not self._transport._closed:
            await asyncio.sleep(0.5)
        await srv.stop()


def serveur_ble(nom: str = "SecureChannelBLE") -> _BleTransport:
    """Demarre le peripheral BLE, attend l'octet hello du central, retourne
    le transport pret a etre passe a `accepter()` ou serveur_handshake()."""
    ctrl = _PeripheralController(nom)
    return ctrl.demarrer()


def accepter(transport: _BleTransport):
    """Lance le handshake serveur sur un transport BLE deja connecte."""
    return serveur_handshake(transport), transport


# ---------------------------------------------------------------------------
# Central side (macOS, bleak)
# ---------------------------------------------------------------------------


class _CentralController:
    """bleak central on a private asyncio loop in a worker thread."""

    def __init__(self, nom_appareil: str = "SecureChannelBLE", timeout_scan: float = 30.0):
        self.nom_appareil = nom_appareil
        self.timeout_scan = timeout_scan
        self._loop = None
        self._thread = None
        self._client = None
        self._transport: _BleTransport | None = None
        self._ready = threading.Event()
        self._error: Exception | None = None

    def connecter(self) -> _BleTransport:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=self.timeout_scan + 30.0)
        if self._error is not None:
            raise self._error
        if self._transport is None:
            raise RuntimeError("BLE central non initialise")
        return self._transport

    def _run(self) -> None:
        try:
            from bleak import BleakClient, BleakScanner
        except ImportError as e:
            err = ImportError(
                "bleak non installe. Installer via 'pip install bleak'."
            )
            err.__cause__ = e
            self._error = err
            self._ready.set()
            return

        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)

        try:
            self._loop.run_until_complete(self._setup(BleakClient, BleakScanner))
        except Exception as e:
            self._error = e
            self._ready.set()

    async def _setup(self, BleakClient, BleakScanner) -> None:
        device = await BleakScanner.find_device_by_name(
            self.nom_appareil, timeout=self.timeout_scan
        )
        if device is None:
            raise ConnectionError(
                f"Peripheral '{self.nom_appareil}' introuvable apres "
                f"{self.timeout_scan}s de scan."
            )
        client = BleakClient(device)
        await client.connect()
        self._client = client

        # Resolve characteristic objects to disambiguate any duplicate UUIDs
        # (BlueZ peripheral leaks may register the same service twice).
        services = client.services
        target_service = None
        for svc in services:
            if svc.uuid.lower() == SERVICE_UUID.lower():
                target_service = svc
                break
        if target_service is None:
            raise ConnectionError(
                f"Service {SERVICE_UUID} introuvable sur le peripheral."
            )

        rx_char = None
        tx_char = None
        for ch in target_service.characteristics:
            if ch.uuid.lower() == RX_CHAR_UUID.lower():
                rx_char = ch
            elif ch.uuid.lower() == TX_CHAR_UUID.lower():
                tx_char = ch
        if rx_char is None or tx_char is None:
            raise ConnectionError(
                "Caracteristiques RX/TX introuvables dans le service."
            )

        async def write_chunk(chunk: bytes) -> None:
            # response=True: each chunk is ack'd by the peripheral before the
            # next is sent. Guarantees in-order delivery and no drops, which
            # is critical because SecureChannel frames are length-prefixed
            # and any reordering corrupts the framing.
            await client.write_gatt_char(rx_char, chunk, response=True)

        transport = _BleTransport(self._loop, write_chunk)

        def notify_cb(_char, data):
            transport.feed(bytes(data))

        await client.start_notify(tx_char, notify_cb)
        # Send hello marker (with response, for strict ordering before any
        # subsequent chunked handshake writes that use write-without-response).
        await client.write_gatt_char(rx_char, _HELLO_MARKER, response=True)

        self._transport = transport
        self._ready.set()

        while client.is_connected and not transport._closed:
            await asyncio.sleep(0.5)
        if client.is_connected:
            await client.disconnect()


def client_ble(nom: str = "SecureChannelBLE", timeout_scan: float = 30.0):
    """Scanne, se connecte au peripheral, lance le handshake client.

    Retourne (SecureChannel, transport).
    """
    ctrl = _CentralController(nom, timeout_scan)
    transport = ctrl.connecter()
    return client_handshake(transport), transport


# ---------------------------------------------------------------------------
# Demo / CLI
# ---------------------------------------------------------------------------


def demo():
    print("\n" + "=" * 50)
    print("  Bluetooth Low Energy (BLE) secure communication")
    print("=" * 50)
    if not disponible_central():
        print("\n  bleak non installe (role central) : pip install bleak")
    if not disponible_peripheral():
        print("  bless non installe (role peripheral) : pip install bless")
    print(f"\n  Service UUID : {SERVICE_UUID}")
    print(f"  RX (write)   : {RX_CHAR_UUID}")
    print(f"  TX (notify)  : {TX_CHAR_UUID}")
    print("\n  Cote peripheral (Linux) :")
    print("    from applications.ble_secure import serveur_ble, accepter")
    print("    transport = serveur_ble()")
    print("    canal, _ = accepter(transport)")
    print("    canal.envoyer(b'hello'); print(canal.recevoir())")
    print("\n  Cote central (macOS) :")
    print("    from applications.ble_secure import client_ble")
    print("    canal, _ = client_ble('SecureChannelBLE')")
    print("    print(canal.recevoir()); canal.envoyer(b'world')")


if __name__ == "__main__":
    demo()
