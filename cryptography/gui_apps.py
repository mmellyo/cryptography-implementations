"""Custom GUI panels for the secure-communication application demos.

TcpChatPanel and UdpChatPanel run a real bidirectional encrypted chat with
both endpoints (client and server) in-process: each side has its own message
column, you type from either side, and messages flow through the actual
SecureChannel / AES-CTR-HMAC framing.
"""
import os
import socket
import threading

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QComboBox,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)


# ---------------------------------------------------------------------------
# Reusable chat column (header + bubble area + input row)
# ---------------------------------------------------------------------------

class _ChatColonne(QWidget):
    """One side of a chat: header, scrollable bubble area, input row."""

    def __init__(self, titre: str, accent: str):
        super().__init__()
        self.accent = accent
        self.setStyleSheet(
            "QWidget { background-color: transparent; }"
        )

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(8)

        # Header bar with colored dot + title
        header = QWidget()
        header.setObjectName("chatHeader")
        header.setStyleSheet(
            "#chatHeader {"
            "  background-color: #e5f4e3;"
            "  border: 1px solid #d6dde6;"
            "  border-bottom: none;"
            "  border-top-left-radius: 8px;"
            "  border-top-right-radius: 8px;"
            "}"
        )
        h = QHBoxLayout(header)
        h.setContentsMargins(14, 10, 14, 10)
        dot = QLabel()
        dot.setFixedSize(10, 10)
        dot.setStyleSheet(f"background-color: {accent}; border-radius: 5px;")
        h.addWidget(dot)
        h.addSpacing(8)
        titre_w = QLabel(titre)
        titre_w.setStyleSheet("font-weight: 600; color: #003f91; font-size: 13px; background: transparent;")
        h.addWidget(titre_w)
        h.addStretch(1)
        self._lbl_meta = QLabel("")
        self._lbl_meta.setStyleSheet("color: #5e6b80; font-size: 11px; background: transparent;")
        h.addWidget(self._lbl_meta)
        outer.addWidget(header)

        # Scrollable bubble area
        self._bubbles = QWidget()
        self._bubbles.setObjectName("chatBubbles")
        self._bubbles.setStyleSheet("#chatBubbles { background-color: #ffffff; }")
        self._bubbles_layout = QVBoxLayout(self._bubbles)
        self._bubbles_layout.setContentsMargins(12, 12, 12, 12)
        self._bubbles_layout.setSpacing(6)
        self._bubbles_layout.addStretch(1)

        self._scroll = QScrollArea()
        self._scroll.setWidget(self._bubbles)
        self._scroll.setWidgetResizable(True)
        self._scroll.setStyleSheet(
            "QScrollArea {"
            "  background-color: white;"
            "  border: 1px solid #e2e8f0;"
            "  border-top: none;"
            "  border-bottom-left-radius: 8px;"
            "  border-bottom-right-radius: 8px;"
            "}"
        )
        outer.addWidget(self._scroll, 1)

        # Input row
        input_row = QHBoxLayout()
        input_row.setSpacing(6)
        self._input = QLineEdit()
        self._input.setPlaceholderText("Tapez un message...")
        self._input.setEnabled(False)
        input_row.addWidget(self._input, 1)
        self._send = QPushButton("Envoyer")
        self._send.setProperty("primary", True)
        self._send.setMinimumWidth(96)
        # Force the primary style explicitly so it stays visible regardless of
        # how the global QPushButton cascade evolves.
        self._send.setStyleSheet(
            "QPushButton {"
            "  background-color: #003f91; color: #ffffff;"
            "  border: 1px solid #003f91; border-radius: 6px;"
            "  padding: 8px 18px; font-weight: 600;"
            "}"
            "QPushButton:hover { background-color: #5da9e9; border-color: #5da9e9; }"
            "QPushButton:pressed { background-color: #002a66; }"
            "QPushButton:disabled { background-color: #b8c8e3; color: #ffffff;"
            " border-color: #b8c8e3; }"
        )
        self._send.setEnabled(False)
        input_row.addWidget(self._send)
        outer.addLayout(input_row)

    # -- Public API --------------------------------------------------------

    def connecter_envoi(self, callback):
        self._input.returnPressed.connect(callback)
        self._send.clicked.connect(callback)

    def texte_input(self) -> str:
        return self._input.text()

    def vider_input(self):
        self._input.clear()

    def activer(self, oui: bool):
        self._input.setEnabled(oui)
        self._send.setEnabled(oui)
        if oui:
            self._input.setFocus()

    def set_meta(self, texte: str):
        self._lbl_meta.setText(texte)

    def vider(self):
        # Remove all bubbles, keep trailing stretch.
        while self._bubbles_layout.count() > 1:
            item = self._bubbles_layout.takeAt(0)
            self._supprimer_item(item)

    def ajouter_message(self, texte: str, sortant: bool):
        bulle = QLabel(texte)
        bulle.setWordWrap(True)
        bulle.setMaximumWidth(420)
        bulle.setMinimumWidth(60)
        bulle.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        if sortant:
            bulle.setStyleSheet(
                f"background-color: {self.accent}; color: white; "
                "padding: 8px 14px; border-radius: 12px; font-size: 13px;"
                " min-height: 18px;"
            )
        else:
            bulle.setStyleSheet(
                "background-color: #e5f4e3; color: #0f1e3a; "
                "padding: 8px 14px; border-radius: 12px; font-size: 13px;"
                " min-height: 18px;"
            )
        ligne = QHBoxLayout()
        ligne.setContentsMargins(0, 0, 0, 0)
        if sortant:
            ligne.addStretch(1)
            ligne.addWidget(bulle)
        else:
            ligne.addWidget(bulle)
            ligne.addStretch(1)
        self._bubbles_layout.insertLayout(self._bubbles_layout.count() - 1, ligne)
        self._defiler()

    def ajouter_systeme(self, texte: str):
        bulle = QLabel(texte)
        bulle.setStyleSheet(
            "color: #5da9e9; font-style: italic; font-size: 11px; padding: 2px;"
        )
        bulle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        bulle.setWordWrap(True)
        self._bubbles_layout.insertWidget(self._bubbles_layout.count() - 1, bulle)
        self._defiler()

    # -- Internal ----------------------------------------------------------

    def _defiler(self):
        QTimer.singleShot(
            0,
            lambda: self._scroll.verticalScrollBar().setValue(
                self._scroll.verticalScrollBar().maximum()
            ),
        )

    def _supprimer_item(self, item):
        if item is None:
            return
        w = item.widget()
        if w is not None:
            w.deleteLater()
            return
        layout = item.layout()
        if layout is not None:
            while layout.count():
                self._supprimer_item(layout.takeAt(0))


# ---------------------------------------------------------------------------
# TCP chat: full SecureChannel handshake on a local loopback session
# ---------------------------------------------------------------------------

class TcpChatPanel(QWidget):
    """Local TCP secure session with both endpoints visible side by side."""

    description = (
        "Session TCP locale 'client <-> serveur' avec handshake RSA-OAEP, "
        "chiffrement AES + HMAC-SHA256. Les deux extremites tournent dans "
        "le meme processus : tapez depuis le cote client OU le cote serveur, "
        "les messages traversent reellement le canal chiffre."
    )

    sig_recu_client = Signal(str)
    sig_recu_serveur = Signal(str)
    sig_etat = Signal(str)
    sig_pret = Signal()
    sig_arrete = Signal()
    sig_journal = Signal(str)

    def __init__(self):
        super().__init__()
        self._stop = threading.Event()
        self._listen_sock = None
        self._sock_client = None
        self._sock_serveur = None
        self._canal_client = None
        self._canal_serveur = None
        self._port = None

        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        info = QLabel(self.description)
        info.setProperty("role", "subtitle")
        info.setWordWrap(True)
        layout.addWidget(info)

        # Control bar
        ctl = QHBoxLayout()
        ctl.setSpacing(8)
        self._b_start = QPushButton("Demarrer la session")
        self._b_start.setProperty("primary", True)
        self._b_start.clicked.connect(self._demarrer)
        ctl.addWidget(self._b_start)
        self._b_stop = QPushButton("Arreter")
        self._b_stop.setProperty("danger", True)
        self._b_stop.clicked.connect(self._arreter)
        self._b_stop.setEnabled(False)
        ctl.addWidget(self._b_stop)
        ctl.addStretch(1)
        self._lbl_etat = QLabel("Inactif")
        self._lbl_etat.setProperty("role", "subtitle")
        ctl.addWidget(self._lbl_etat)
        layout.addLayout(ctl)

        # Two-column chat
        cols = QHBoxLayout()
        cols.setSpacing(14)
        self._col_client = _ChatColonne("Client", accent="#003f91")
        self._col_serveur = _ChatColonne("Serveur", accent="#5da9e9")
        self._col_client.connecter_envoi(self._envoyer_client)
        self._col_serveur.connecter_envoi(self._envoyer_serveur)
        cols.addWidget(self._col_client, 1)
        cols.addWidget(self._col_serveur, 1)
        layout.addLayout(cols, 1)

        # Wire signals
        self.sig_recu_client.connect(
            lambda t: self._col_client.ajouter_message(t, sortant=False)
        )
        self.sig_recu_serveur.connect(
            lambda t: self._col_serveur.ajouter_message(t, sortant=False)
        )
        self.sig_etat.connect(self._lbl_etat.setText)
        self.sig_pret.connect(self._sur_pret)
        self.sig_arrete.connect(self._sur_arrete)
        self.sig_journal.connect(self._sur_journal)

    # -- Lifecycle ---------------------------------------------------------

    def _demarrer(self):
        self._stop = threading.Event()
        self._b_start.setEnabled(False)
        self._b_stop.setEnabled(True)
        self._col_client.vider()
        self._col_serveur.vider()
        self.sig_etat.emit("Initialisation...")
        threading.Thread(target=self._initialiser, daemon=True).start()

    def _initialiser(self):
        try:
            from applications.secure_channel import (
                client_handshake,
                serveur_handshake,
            )
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", 0))
            sock.listen(1)
            sock.settimeout(3.0)
            self._listen_sock = sock
            self._port = sock.getsockname()[1]
            self.sig_journal.emit(f"Serveur ecoute sur 127.0.0.1:{self._port}")

            client_done = threading.Event()

            def connect_client():
                try:
                    sc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sc.connect(("127.0.0.1", self._port))
                    self._sock_client = sc
                    self._canal_client = client_handshake(sc)
                    self.sig_journal.emit("Handshake client : OK")
                except Exception as e:
                    self.sig_journal.emit(f"[client] {type(e).__name__}: {e}")
                finally:
                    client_done.set()

            threading.Thread(target=connect_client, daemon=True).start()

            try:
                conn, _ = sock.accept()
            except socket.timeout:
                self.sig_journal.emit("Timeout accept (pas de connexion entrante)")
                self.sig_etat.emit("Echec")
                self.sig_arrete.emit()
                return

            self._sock_serveur = conn
            self._canal_serveur = serveur_handshake(conn)
            self.sig_journal.emit("Handshake serveur : OK")

            client_done.wait(timeout=5.0)
            if self._canal_client is None:
                self.sig_etat.emit("Echec : handshake client incomplet")
                self.sig_arrete.emit()
                return

            threading.Thread(target=self._lire, args=("client",), daemon=True).start()
            threading.Thread(target=self._lire, args=("serveur",), daemon=True).start()

            self._col_client.set_meta(f"127.0.0.1:{self._port}")
            self._col_serveur.set_meta(f"127.0.0.1:{self._port}")
            self.sig_etat.emit(f"Connecte - 127.0.0.1:{self._port}")
            self.sig_pret.emit()
        except Exception as e:
            self.sig_journal.emit(f"[init] {type(e).__name__}: {e}")
            self.sig_etat.emit("Erreur")
            self.sig_arrete.emit()

    def _lire(self, kind):
        canal = self._canal_client if kind == "client" else self._canal_serveur
        while not self._stop.is_set() and canal is not None:
            try:
                data = canal.recevoir()
            except (ConnectionError, ValueError, OSError):
                return
            except Exception as e:
                self.sig_journal.emit(f"[reader-{kind}] {type(e).__name__}: {e}")
                return
            texte = data.decode("utf-8", errors="replace")
            if kind == "client":
                self.sig_recu_client.emit(texte)
            else:
                self.sig_recu_serveur.emit(texte)

    def _envoyer_client(self):
        if self._canal_client is None:
            return
        texte = self._col_client.texte_input()
        if not texte:
            return
        try:
            self._canal_client.envoyer(texte.encode("utf-8"))
            self._col_client.ajouter_message(texte, sortant=True)
            self._col_client.vider_input()
        except Exception as e:
            self.sig_journal.emit(f"[client-send] {type(e).__name__}: {e}")

    def _envoyer_serveur(self):
        if self._canal_serveur is None:
            return
        texte = self._col_serveur.texte_input()
        if not texte:
            return
        try:
            self._canal_serveur.envoyer(texte.encode("utf-8"))
            self._col_serveur.ajouter_message(texte, sortant=True)
            self._col_serveur.vider_input()
        except Exception as e:
            self.sig_journal.emit(f"[serveur-send] {type(e).__name__}: {e}")

    def _arreter(self):
        self._stop.set()
        for s in (self._sock_client, self._sock_serveur, self._listen_sock):
            try:
                if s is not None:
                    s.close()
            except Exception:
                pass
        self._sock_client = None
        self._sock_serveur = None
        self._listen_sock = None
        self._canal_client = None
        self._canal_serveur = None
        self._port = None
        self.sig_arrete.emit()

    # -- UI thread reactions ----------------------------------------------

    def _sur_pret(self):
        self._col_client.activer(True)
        self._col_serveur.activer(True)

    def _sur_arrete(self):
        self._col_client.activer(False)
        self._col_serveur.activer(False)
        self._b_start.setEnabled(True)
        self._b_stop.setEnabled(False)
        self._lbl_etat.setText("Inactif")
        self._col_client.set_meta("")
        self._col_serveur.set_meta("")

    def _sur_journal(self, msg):
        self._col_client.ajouter_systeme(msg)
        self._col_serveur.ajouter_systeme(msg)


# ---------------------------------------------------------------------------
# Bluetooth secure chat: same SecureChannel protocol as TCP, but transported
# over BLE GATT (bleak central + bless peripheral). The Serveur column runs
# the peripheral role (advertises the service) ; the Client column runs the
# central role (scans and connects by advertised name). Cross-platform :
# Linux <-> macOS works because BLE is supported natively on both.
# ---------------------------------------------------------------------------

class BluetoothChatPanel(QWidget):
    """Bluetooth secure chat with Serveur and Client columns side-by-side.

    Each column is fully independent : own connection, own SecureChannel,
    own chat. Typically you run one side here and the other on a remote
    paired device (Mac native or another Linux box)."""

    description = (
        "Session Bluetooth (RFCOMM) avec handshake RSA-OAEP + chiffrement "
        "AES-CTR + HMAC-SHA256. Necessite Bluetooth et une carte BLE."
    )

    sig_recu_serveur = Signal(str)
    sig_recu_client = Signal(str)
    sig_etat_serveur = Signal(str)
    sig_etat_client = Signal(str)
    sig_journal_serveur = Signal(str)
    sig_journal_client = Signal(str)
    sig_pret_serveur = Signal()
    sig_pret_client = Signal()
    sig_arrete_serveur = Signal()
    sig_arrete_client = Signal()

    def __init__(self):
        super().__init__()
        self._stop_serveur = threading.Event()
        self._stop_client = threading.Event()
        self._transport_serveur = None
        self._transport_client = None
        self._canal_serveur = None
        self._canal_client = None

        layout = QVBoxLayout(self)
        layout.setSpacing(12)

        info = QLabel(self.description)
        info.setProperty("role", "subtitle")
        info.setWordWrap(True)
        layout.addWidget(info)

        from applications import ble_secure as ble_mod
        self._ble_mod = ble_mod
        self._central_ok = ble_mod.disponible_central()
        self._peripheral_ok = ble_mod.disponible_peripheral()

        if not (self._central_ok and self._peripheral_ok):
            manquant = []
            if not self._central_ok:
                manquant.append("bleak (client)")
            if not self._peripheral_ok:
                manquant.append("bless (serveur)")
            warning = QLabel(
                "Dependances Bluetooth manquantes : "
                + ", ".join(manquant)
                + ". Installer : 'pip install bleak bless'. Une carte "
                "Bluetooth est requise sur les deux machines."
            )
            warning.setWordWrap(True)
            warning.setStyleSheet(
                "background-color: #fee2e2; color: #991b1b; padding: 12px;"
                " border-radius: 6px; font-weight: 600;"
            )
            layout.addWidget(warning)

        # Shared service name (used both as advertise name + scan filter)
        params = QHBoxLayout()
        params.setSpacing(8)
        params.addWidget(QLabel("Nom du service :"))
        self._nom = QLineEdit("SecureChannelBLE")
        self._nom.setMinimumWidth(220)
        params.addWidget(self._nom)
        params.addStretch(1)
        layout.addLayout(params)

        cols = QHBoxLayout()
        cols.setSpacing(14)

        # ----- Serveur (peripheral) -----
        serveur_box = QVBoxLayout()
        serveur_ctl = QHBoxLayout()
        self._b_start_s = QPushButton("Demarrer le serveur")
        self._b_start_s.setProperty("primary", True)
        self._b_start_s.clicked.connect(self._demarrer_serveur)
        serveur_ctl.addWidget(self._b_start_s)
        self._b_stop_s = QPushButton("Arreter")
        self._b_stop_s.setProperty("danger", True)
        self._b_stop_s.setEnabled(False)
        self._b_stop_s.clicked.connect(self._arreter_serveur)
        serveur_ctl.addWidget(self._b_stop_s)
        serveur_ctl.addStretch(1)
        self._lbl_etat_s = QLabel("Inactif")
        self._lbl_etat_s.setProperty("role", "subtitle")
        serveur_ctl.addWidget(self._lbl_etat_s)
        serveur_box.addLayout(serveur_ctl)
        self._col_serveur = _ChatColonne("Serveur", accent="#003f91")
        self._col_serveur.connecter_envoi(self._envoyer_serveur)
        self._col_serveur.activer(False)
        serveur_box.addWidget(self._col_serveur, 1)
        serveur_widget = QWidget()
        serveur_widget.setLayout(serveur_box)
        cols.addWidget(serveur_widget, 1)

        # ----- Client (central) -----
        client_box = QVBoxLayout()
        client_ctl = QHBoxLayout()
        self._b_start_c = QPushButton("Connecter le client")
        self._b_start_c.setProperty("primary", True)
        self._b_start_c.clicked.connect(self._demarrer_client)
        client_ctl.addWidget(self._b_start_c)
        self._b_stop_c = QPushButton("Arreter")
        self._b_stop_c.setProperty("danger", True)
        self._b_stop_c.setEnabled(False)
        self._b_stop_c.clicked.connect(self._arreter_client)
        client_ctl.addWidget(self._b_stop_c)
        client_ctl.addStretch(1)
        self._lbl_etat_c = QLabel("Inactif")
        self._lbl_etat_c.setProperty("role", "subtitle")
        client_ctl.addWidget(self._lbl_etat_c)
        client_box.addLayout(client_ctl)
        self._col_client = _ChatColonne("Client", accent="#5da9e9")
        self._col_client.connecter_envoi(self._envoyer_client)
        self._col_client.activer(False)
        client_box.addWidget(self._col_client, 1)
        client_widget = QWidget()
        client_widget.setLayout(client_box)
        cols.addWidget(client_widget, 1)

        layout.addLayout(cols, 1)

        if not self._peripheral_ok:
            self._b_start_s.setEnabled(False)
        if not self._central_ok:
            self._b_start_c.setEnabled(False)

        # Wire signals to UI thread
        self.sig_recu_serveur.connect(
            lambda t: self._col_serveur.ajouter_message(t, sortant=False)
        )
        self.sig_recu_client.connect(
            lambda t: self._col_client.ajouter_message(t, sortant=False)
        )
        self.sig_etat_serveur.connect(self._lbl_etat_s.setText)
        self.sig_etat_client.connect(self._lbl_etat_c.setText)
        self.sig_journal_serveur.connect(self._col_serveur.ajouter_systeme)
        self.sig_journal_client.connect(self._col_client.ajouter_systeme)
        self.sig_pret_serveur.connect(lambda: self._col_serveur.activer(True))
        self.sig_pret_client.connect(lambda: self._col_client.activer(True))
        self.sig_arrete_serveur.connect(self._sur_arrete_serveur)
        self.sig_arrete_client.connect(self._sur_arrete_client)

    # -- Serveur (peripheral) -------------------------------------------------

    def _demarrer_serveur(self):
        if not self._peripheral_ok:
            return
        self._stop_serveur = threading.Event()
        self._b_start_s.setEnabled(False)
        self._b_stop_s.setEnabled(True)
        self._col_serveur.vider()
        self.sig_etat_serveur.emit("Advertise + attente central...")
        threading.Thread(target=self._run_server, daemon=True).start()

    def _run_server(self):
        try:
            nom = self._nom.text().strip() or "SecureChannelBLE"
            self.sig_journal_serveur.emit(
                f"Advertise GATT 'SecureChannelBLE' (nom={nom})"
            )
            transport = self._ble_mod.serveur_ble(nom)
            self._transport_serveur = transport
            self.sig_journal_serveur.emit("Central connecte. Handshake en cours...")
            canal, _ = self._ble_mod.accepter(transport)
            self._canal_serveur = canal
            self.sig_journal_serveur.emit("Handshake OK.")
            self.sig_etat_serveur.emit("Connecte")
            self.sig_pret_serveur.emit()
            self._lire_serveur()
        except Exception as e:
            self.sig_journal_serveur.emit(f"[peripheral] {type(e).__name__}: {e}")
            self.sig_etat_serveur.emit("Erreur")
            self.sig_arrete_serveur.emit()

    def _lire_serveur(self):
        while not self._stop_serveur.is_set() and self._canal_serveur is not None:
            try:
                data = self._canal_serveur.recevoir()
            except (ConnectionError, ValueError, OSError):
                return
            except Exception as e:
                self.sig_journal_serveur.emit(f"[reader] {type(e).__name__}: {e}")
                return
            self.sig_recu_serveur.emit(data.decode("utf-8", errors="replace"))

    def _envoyer_serveur(self):
        if self._canal_serveur is None:
            return
        texte = self._col_serveur.texte_input()
        if not texte:
            return
        try:
            self._canal_serveur.envoyer(texte.encode("utf-8"))
            self._col_serveur.ajouter_message(texte, sortant=True)
            self._col_serveur.vider_input()
        except Exception as e:
            self.sig_journal_serveur.emit(f"[send] {type(e).__name__}: {e}")

    def _arreter_serveur(self):
        self._stop_serveur.set()
        try:
            if self._transport_serveur is not None:
                self._transport_serveur.close()
        except Exception:
            pass
        self._transport_serveur = None
        self._canal_serveur = None
        self.sig_arrete_serveur.emit()

    def _sur_arrete_serveur(self):
        self._col_serveur.activer(False)
        self._b_start_s.setEnabled(self._peripheral_ok)
        self._b_stop_s.setEnabled(False)
        self._lbl_etat_s.setText("Inactif")

    # -- Client (central) -----------------------------------------------------

    def _demarrer_client(self):
        if not self._central_ok:
            return
        self._stop_client = threading.Event()
        self._b_start_c.setEnabled(False)
        self._b_stop_c.setEnabled(True)
        self._col_client.vider()
        nom = self._nom.text().strip() or "SecureChannelBLE"
        self.sig_etat_client.emit(f"Scan BLE pour '{nom}'...")
        threading.Thread(target=self._run_client, args=(nom,), daemon=True).start()

    def _run_client(self, nom: str):
        try:
            canal, transport = self._ble_mod.client_ble(nom, timeout_scan=30.0)
            self._transport_client = transport
            self._canal_client = canal
            self.sig_journal_client.emit(f"Connecte a '{nom}' + handshake OK")
            self.sig_etat_client.emit("Connecte")
            self.sig_pret_client.emit()
            self._lire_client()
        except Exception as e:
            self.sig_journal_client.emit(f"[central] {type(e).__name__}: {e}")
            self.sig_etat_client.emit("Erreur")
            self.sig_arrete_client.emit()

    def _lire_client(self):
        while not self._stop_client.is_set() and self._canal_client is not None:
            try:
                data = self._canal_client.recevoir()
            except (ConnectionError, ValueError, OSError):
                return
            except Exception as e:
                self.sig_journal_client.emit(f"[reader] {type(e).__name__}: {e}")
                return
            self.sig_recu_client.emit(data.decode("utf-8", errors="replace"))

    def _envoyer_client(self):
        if self._canal_client is None:
            return
        texte = self._col_client.texte_input()
        if not texte:
            return
        try:
            self._canal_client.envoyer(texte.encode("utf-8"))
            self._col_client.ajouter_message(texte, sortant=True)
            self._col_client.vider_input()
        except Exception as e:
            self.sig_journal_client.emit(f"[send] {type(e).__name__}: {e}")

    def _arreter_client(self):
        self._stop_client.set()
        try:
            if self._transport_client is not None:
                self._transport_client.close()
        except Exception:
            pass
        self._transport_client = None
        self._canal_client = None
        self.sig_arrete_client.emit()

    def _sur_arrete_client(self):
        self._col_client.activer(False)
        self._b_start_c.setEnabled(self._central_ok)
        self._b_stop_c.setEnabled(False)
        self._lbl_etat_c.setText("Inactif")


# ---------------------------------------------------------------------------
# UDP chat: stateless AES-CTR + HMAC-SHA256 packets, two endpoints in-process
# ---------------------------------------------------------------------------

class UdpChatPanel(QWidget):
    """Local UDP secure session with both endpoints visible side by side."""

    description = (
        "Session UDP locale 'client <-> serveur' avec AES-CTR + HMAC-SHA256 "
        "par paquet. Cles symetriques generees a la connexion. Tapez depuis "
        "n'importe quel cote, les paquets traversent vraiment le reseau "
        "loopback."
    )

    sig_recu_client = Signal(str)
    sig_recu_serveur = Signal(str)
    sig_etat = Signal(str)
    sig_pret = Signal()
    sig_arrete = Signal()
    sig_journal = Signal(str)

    def __init__(self):
        super().__init__()
        self._stop = threading.Event()
        self._sock_client = None
        self._sock_serveur = None
        self._addr_client = None
        self._addr_serveur = None
        self._cle_aes = None
        self._cle_hmac = None

        layout = QVBoxLayout(self)
        layout.setSpacing(14)

        info = QLabel(self.description)
        info.setProperty("role", "subtitle")
        info.setWordWrap(True)
        layout.addWidget(info)

        ctl = QHBoxLayout()
        ctl.setSpacing(8)
        self._b_start = QPushButton("Demarrer la session")
        self._b_start.setProperty("primary", True)
        self._b_start.clicked.connect(self._demarrer)
        ctl.addWidget(self._b_start)
        self._b_stop = QPushButton("Arreter")
        self._b_stop.setProperty("danger", True)
        self._b_stop.clicked.connect(self._arreter)
        self._b_stop.setEnabled(False)
        ctl.addWidget(self._b_stop)
        ctl.addStretch(1)
        self._lbl_etat = QLabel("Inactif")
        self._lbl_etat.setProperty("role", "subtitle")
        ctl.addWidget(self._lbl_etat)
        layout.addLayout(ctl)

        cols = QHBoxLayout()
        cols.setSpacing(14)
        self._col_client = _ChatColonne("Client", accent="#003f91")
        self._col_serveur = _ChatColonne("Serveur", accent="#5da9e9")
        self._col_client.connecter_envoi(self._envoyer_client)
        self._col_serveur.connecter_envoi(self._envoyer_serveur)
        cols.addWidget(self._col_client, 1)
        cols.addWidget(self._col_serveur, 1)
        layout.addLayout(cols, 1)

        self.sig_recu_client.connect(
            lambda t: self._col_client.ajouter_message(t, sortant=False)
        )
        self.sig_recu_serveur.connect(
            lambda t: self._col_serveur.ajouter_message(t, sortant=False)
        )
        self.sig_etat.connect(self._lbl_etat.setText)
        self.sig_pret.connect(self._sur_pret)
        self.sig_arrete.connect(self._sur_arrete)
        self.sig_journal.connect(self._sur_journal)

    def _demarrer(self):
        self._stop = threading.Event()
        self._b_start.setEnabled(False)
        self._b_stop.setEnabled(True)
        self._col_client.vider()
        self._col_serveur.vider()
        self.sig_etat.emit("Initialisation...")
        threading.Thread(target=self._initialiser, daemon=True).start()

    def _initialiser(self):
        try:
            from applications.udp_chat import AES_KEY_SIZE, HMAC_KEY_SIZE
            self._cle_aes = os.urandom(AES_KEY_SIZE)
            self._cle_hmac = os.urandom(HMAC_KEY_SIZE)

            sock_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock_s.bind(("127.0.0.1", 0))
            sock_s.settimeout(0.5)
            self._sock_serveur = sock_s
            self._addr_serveur = sock_s.getsockname()

            sock_c = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock_c.bind(("127.0.0.1", 0))
            sock_c.settimeout(0.5)
            self._sock_client = sock_c
            self._addr_client = sock_c.getsockname()

            self.sig_journal.emit(
                f"Client {self._addr_client[1]} <-> Serveur {self._addr_serveur[1]}"
            )
            self.sig_journal.emit(f"Cle AES (hex)  : {self._cle_aes.hex()[:24]}...")
            self.sig_journal.emit(f"Cle HMAC (hex) : {self._cle_hmac.hex()[:24]}...")

            threading.Thread(target=self._lire, args=("client",), daemon=True).start()
            threading.Thread(target=self._lire, args=("serveur",), daemon=True).start()

            self._col_client.set_meta(f"127.0.0.1:{self._addr_client[1]}")
            self._col_serveur.set_meta(f"127.0.0.1:{self._addr_serveur[1]}")
            self.sig_etat.emit("Connecte (UDP)")
            self.sig_pret.emit()
        except Exception as e:
            self.sig_journal.emit(f"[init] {type(e).__name__}: {e}")
            self.sig_etat.emit("Erreur")
            self.sig_arrete.emit()

    def _lire(self, kind):
        from applications.udp_chat import dechiffrer_paquet
        sock = self._sock_client if kind == "client" else self._sock_serveur
        while not self._stop.is_set() and sock is not None:
            try:
                data, _ = sock.recvfrom(65536)
            except socket.timeout:
                continue
            except (ConnectionError, OSError):
                return
            try:
                clair = dechiffrer_paquet(data, self._cle_aes, self._cle_hmac)
            except ValueError as e:
                self.sig_journal.emit(f"[{kind}] paquet rejete : {e}")
                continue
            texte = clair.decode("utf-8", errors="replace")
            if kind == "client":
                self.sig_recu_client.emit(texte)
            else:
                self.sig_recu_serveur.emit(texte)

    def _envoyer_client(self):
        from applications.udp_chat import chiffrer_paquet
        if self._sock_client is None or self._addr_serveur is None:
            return
        texte = self._col_client.texte_input()
        if not texte:
            return
        try:
            paquet = chiffrer_paquet(
                texte.encode("utf-8"), self._cle_aes, self._cle_hmac
            )
            self._sock_client.sendto(paquet, self._addr_serveur)
            self._col_client.ajouter_message(texte, sortant=True)
            self._col_client.vider_input()
        except Exception as e:
            self.sig_journal.emit(f"[client-send] {type(e).__name__}: {e}")

    def _envoyer_serveur(self):
        from applications.udp_chat import chiffrer_paquet
        if self._sock_serveur is None or self._addr_client is None:
            return
        texte = self._col_serveur.texte_input()
        if not texte:
            return
        try:
            paquet = chiffrer_paquet(
                texte.encode("utf-8"), self._cle_aes, self._cle_hmac
            )
            self._sock_serveur.sendto(paquet, self._addr_client)
            self._col_serveur.ajouter_message(texte, sortant=True)
            self._col_serveur.vider_input()
        except Exception as e:
            self.sig_journal.emit(f"[serveur-send] {type(e).__name__}: {e}")

    def _arreter(self):
        self._stop.set()
        for s in (self._sock_client, self._sock_serveur):
            try:
                if s is not None:
                    s.close()
            except Exception:
                pass
        self._sock_client = None
        self._sock_serveur = None
        self._addr_client = None
        self._addr_serveur = None
        self._cle_aes = None
        self._cle_hmac = None
        self.sig_arrete.emit()

    def _sur_pret(self):
        self._col_client.activer(True)
        self._col_serveur.activer(True)

    def _sur_arrete(self):
        self._col_client.activer(False)
        self._col_serveur.activer(False)
        self._b_start.setEnabled(True)
        self._b_stop.setEnabled(False)
        self._lbl_etat.setText("Inactif")
        self._col_client.set_meta("")
        self._col_serveur.set_meta("")

    def _sur_journal(self, msg):
        self._col_client.ajouter_systeme(msg)
        self._col_serveur.ajouter_systeme(msg)


# ---------------------------------------------------------------------------
# Voting panel (unchanged structure, kept for completeness)
# ---------------------------------------------------------------------------

def _mono(w):
    w.setFont(QFont("Menlo", 11))
    return w


class VotingPanel(QWidget):
    description = (
        "Vote homomorphique ElGamal : chaque bulletin (0 ou 1) est chiffre "
        "individuellement, les ciphertexts sont multiplies pour obtenir le "
        "chiffre du total, puis seule l'autorite (cle privee x) peut "
        "dechiffrer le total."
    )

    def __init__(self):
        super().__init__()
        self._election = None
        self._chiffres = []
        self._votes_clair = []

        layout = QVBoxLayout(self)
        info = QLabel(self.description)
        info.setProperty("role", "subtitle")
        info.setWordWrap(True)
        layout.addWidget(info)

        form = QFormLayout()
        self._bits = QSpinBox()
        self._bits.setRange(64, 256)
        self._bits.setValue(96)
        form.addRow("Taille p (bits)", self._bits)
        layout.addLayout(form)

        boutons = QHBoxLayout()
        b_init = QPushButton("Initialiser election")
        b_init.setProperty("primary", True)
        b_init.clicked.connect(self._initialiser)
        boutons.addWidget(b_init)
        b_reset = QPushButton("Reinitialiser bulletins")
        b_reset.clicked.connect(self._reset_bulletins)
        boutons.addWidget(b_reset)
        boutons.addStretch(1)
        layout.addLayout(boutons)

        self._statut = QLabel("Election non initialisee.")
        self._statut.setProperty("role", "subtitle")
        layout.addWidget(self._statut)

        ligne = QHBoxLayout()
        ligne.addWidget(QLabel("Vote :"))
        self._vote = QComboBox()
        self._vote.addItems(["0 (NON)", "1 (OUI)"])
        ligne.addWidget(self._vote)
        b_voter = QPushButton("Ajouter bulletin")
        b_voter.clicked.connect(self._voter)
        ligne.addWidget(b_voter)
        ligne.addStretch(1)
        layout.addLayout(ligne)

        self._sortie = _mono(QPlainTextEdit())
        self._sortie.setReadOnly(True)
        layout.addWidget(self._sortie, 1)

        b_compter = QPushButton("Compter les bulletins")
        b_compter.setProperty("primary", True)
        b_compter.clicked.connect(self._compter)
        layout.addWidget(b_compter)

    def _initialiser(self):
        try:
            from applications.voting import generer_election
            self._election = generer_election(self._bits.value())
            p, g, y, x = self._election
            self._chiffres = []
            self._votes_clair = []
            self._statut.setText(
                f"Election initialisee. p ({p.bit_length()} bits), g={g}."
            )
            self._sortie.clear()
            self._sortie.appendPlainText(f"p (hex)        : {hex(p)[:60]}...")
            self._sortie.appendPlainText(f"g              : {g}")
            self._sortie.appendPlainText(f"y publique     : {hex(y)[:60]}...")
            self._sortie.appendPlainText(f"x privee (hex) : {hex(x)[:60]}...")
            self._sortie.appendPlainText("")
        except Exception as e:
            self._sortie.appendPlainText(f"[ERREUR] {type(e).__name__}: {e}")

    def _reset_bulletins(self):
        self._chiffres = []
        self._votes_clair = []
        self._sortie.appendPlainText("[bulletins reinitialises]")

    def _voter(self):
        if self._election is None:
            self._sortie.appendPlainText("[election non initialisee]")
            return
        try:
            from applications.voting import chiffrer_vote
            p, g, y, _x = self._election
            v = 1 if self._vote.currentIndex() == 1 else 0
            c1, c2 = chiffrer_vote(p, g, y, v)
            self._chiffres.append((c1, c2))
            self._votes_clair.append(v)
            self._sortie.appendPlainText(
                f"Bulletin #{len(self._chiffres)} (vote={v}) -> "
                f"c1 {hex(c1)[:20]}... | c2 {hex(c2)[:20]}..."
            )
        except Exception as e:
            self._sortie.appendPlainText(f"[ERREUR] {type(e).__name__}: {e}")

    def _compter(self):
        if self._election is None or not self._chiffres:
            self._sortie.appendPlainText("[aucun bulletin]")
            return
        try:
            from applications.voting import decompter
            p, g, _y, x = self._election
            total = decompter(
                p, g, x, self._chiffres, max_votants=len(self._chiffres)
            )
            self._sortie.appendPlainText("")
            self._sortie.appendPlainText(
                f"Total OUI : {total} / {len(self._chiffres)} bulletins"
            )
            self._sortie.appendPlainText(
                f"Match clair (verif) : {total == sum(self._votes_clair)}"
            )
        except Exception as e:
            self._sortie.appendPlainText(f"[ERREUR] {type(e).__name__}: {e}")
