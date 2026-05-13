"""PySide6 panels: side-by-side encrypt/decrypt with format toggles,
Generate buttons, and per-algorithm configuration."""
import secrets
import threading
import traceback

from PySide6.QtCore import QObject, Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QVBoxLayout,
    QWidget,
)


class _AsyncBridge(QObject):
    """Emit-only QObject used to marshal results back to the UI thread."""

    done = Signal(object)
    failed = Signal(str)


def run_async(parent: QWidget, fn, on_done, on_failed=None):
    """Run fn() on a Python daemon thread. on_done/on_failed are invoked
    on the UI thread via queued Qt signals."""
    bridge = _AsyncBridge()
    # Cross-thread signal/slot : Qt auto-detects and uses QueuedConnection.
    bridge.done.connect(on_done)
    if on_failed is not None:
        bridge.failed.connect(on_failed)

    def _worker():
        try:
            result = fn()
            bridge.done.emit(result)
        except Exception as e:
            msg = f"{type(e).__name__}: {e}\n\n{traceback.format_exc()}"
            if on_failed is not None:
                bridge.failed.emit(msg)

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    # Keep the bridge alive by anchoring it on the parent (otherwise GC kills
    # the QObject before the signal is delivered).
    if not hasattr(parent, "_async_bridges"):
        parent._async_bridges = []  # type: ignore[attr-defined]
    parent._async_bridges.append(bridge)  # type: ignore[attr-defined]
    return t

from gui_widgets import (
    FormatField,
    LabeledDropdown,
    OutputArea,
    PRIMARY_BUTTON_STYLE,
    SECONDARY_BUTTON_STYLE,
    SectionFrame,
)


# Per-mode parameters for AES.
_AES_MODES: dict[str, dict] = {
    "ECB": {"iv": 0, "padding": True},
    "CBC": {"iv": 16, "padding": True},
    "CFB": {"iv": 16, "padding": False},
    "OFB": {"iv": 16, "padding": False},
    "CTR": {"iv": 8, "padding": False},   # pycryptodome default counter size
    "GCM": {"iv": 12, "padding": False, "authenticated": True},
}


def _aes_encrypt(mode: str, msg: bytes, cle: bytes, iv: bytes, padding: str) -> bytes:
    from symmetric.block import aes
    if mode == "ECB":
        return aes.chiffrer_ecb(msg, cle, padding)
    if mode == "CBC":
        return aes.chiffrer_cbc(msg, cle, iv, padding)
    if mode == "CFB":
        return aes.chiffrer_cfb(msg, cle, iv)
    if mode == "OFB":
        return aes.chiffrer_ofb(msg, cle, iv)
    if mode == "CTR":
        return aes.chiffrer_ctr(msg, cle, iv)
    if mode == "GCM":
        return aes.chiffrer_gcm(msg, cle, iv)
    raise ValueError(f"Mode AES inconnu : {mode}")


def _aes_decrypt(mode: str, blob: bytes, cle: bytes, iv: bytes, padding: str) -> bytes:
    from symmetric.block import aes
    if mode == "ECB":
        return aes.dechiffrer_ecb(blob, cle, padding)
    if mode == "CBC":
        return aes.dechiffrer_cbc(blob, cle, iv, padding)
    if mode == "CFB":
        return aes.dechiffrer_cfb(blob, cle, iv)
    if mode == "OFB":
        return aes.dechiffrer_ofb(blob, cle, iv)
    if mode == "CTR":
        return aes.dechiffrer_ctr(blob, cle, iv)
    if mode == "GCM":
        return aes.dechiffrer_gcm(blob, cle)  # nonce embedded
    raise ValueError(f"Mode AES inconnu : {mode}")


def _des_encrypt(mode: str, msg: bytes, cle: bytes, iv: bytes, padding: str) -> bytes:
    from symmetric.block import des
    if len(cle) == 8:
        return des.chiffrer_cbc(msg, cle, iv)
    return des.chiffrer_3des_cbc(msg, cle, iv)


def _des_decrypt(mode: str, blob: bytes, cle: bytes, iv: bytes, padding: str) -> bytes:
    from symmetric.block import des
    if len(cle) == 8:
        return des.dechiffrer_cbc(blob, cle, iv)
    return des.dechiffrer_3des_cbc(blob, cle, iv)


def _rc4_encrypt(mode: str, msg: bytes, cle: bytes, iv: bytes, padding: str) -> bytes:
    from symmetric.stream import rc4
    return rc4.chiffrer(cle, msg)


# Static config: which modes / key sizes / IV per algo.
_SYM_CONFIGS = {
    "AES": {
        "modes": list(_AES_MODES.keys()),
        "default_mode": "CBC",
        "key_sizes": [16, 24, 32],  # 128, 192, 256 bits
        "default_key_size": 16,
        "iv_size_fn": lambda mode: _AES_MODES[mode]["iv"],
        "padding_fn": lambda mode: _AES_MODES[mode]["padding"],
        "encrypt": _aes_encrypt,
        "decrypt": _aes_decrypt,
    },
    "DES": {
        "modes": ["CBC"],
        "default_mode": "CBC",
        "key_sizes": [8],
        "default_key_size": 8,
        "iv_size_fn": lambda mode: 8,
        "padding_fn": lambda mode: True,
        "encrypt": _des_encrypt,
        "decrypt": _des_decrypt,
    },
    "3DES": {
        "modes": ["CBC"],
        "default_mode": "CBC",
        "key_sizes": [16, 24],
        "default_key_size": 24,
        "iv_size_fn": lambda mode: 8,
        "padding_fn": lambda mode: True,
        "encrypt": _des_encrypt,
        "decrypt": _des_decrypt,
    },
    "RC4": {
        "modes": ["Stream"],
        "default_mode": "Stream",
        "key_sizes": [5, 16, 32],
        "default_key_size": 16,
        "iv_size_fn": lambda mode: 0,
        "padding_fn": lambda mode: False,
        "encrypt": _rc4_encrypt,
        "decrypt": _rc4_encrypt,  # stream cipher : encrypt == decrypt
    },
}


class SymmetricCipherPanel(QWidget):
    """Side-by-side encrypt/decrypt for AES, DES, 3DES, RC4."""

    def __init__(self, algo: str, parent=None):
        super().__init__(parent)
        if algo not in _SYM_CONFIGS:
            raise ValueError(f"Algorithme symetrique inconnu : {algo}")
        self.algo = algo
        self.cfg = _SYM_CONFIGS[algo]
        self._build()
        self._on_mode_changed(self.cfg["default_mode"])

    # ----- UI construction -----
    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(8)

        title = QLabel(f"{self.algo} - Chiffrement / dechiffrement")
        title.setStyleSheet("font-size: 18px; font-weight: 700; color: #003f91;")
        root.addWidget(title)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._build_encrypt_side())
        splitter.addWidget(self._build_decrypt_side())
        splitter.setSizes([1, 1])
        root.addWidget(splitter, stretch=1)

        # Shared bottom row : algo settings
        bottom = QHBoxLayout()
        bottom.setSpacing(12)

        self.mode_dd = LabeledDropdown(
            "Mode", self.cfg["modes"], default=self.cfg["default_mode"]
        )
        self.mode_dd.changed.connect(self._on_mode_changed)
        bottom.addWidget(self.mode_dd)

        self.key_size_dd = LabeledDropdown(
            "Taille cle (octets)",
            [str(k) for k in self.cfg["key_sizes"]],
            default=str(self.cfg["default_key_size"]),
        )
        self.key_size_dd.changed.connect(self._on_key_size_changed)
        bottom.addWidget(self.key_size_dd)

        self.padding_dd = LabeledDropdown(
            "Padding", ["PKCS7", "Zero", "None"], default="PKCS7"
        )
        bottom.addWidget(self.padding_dd)
        bottom.addStretch(1)

        root.addLayout(bottom)

    def _build_encrypt_side(self) -> QWidget:
        side = SectionFrame("Chiffrement")
        self.msg_in = FormatField(
            "Message en clair", default_text="Hello AES", default_format="Plain", multiline=True,
        )
        side.body.addWidget(self.msg_in)

        self.key_in = FormatField(
            "Cle secrete", default_text="", default_format="Hex",
            generate_size=self.cfg["default_key_size"],
        )
        # Pre-populate with a fresh key
        self.key_in.set_bytes(secrets.token_bytes(self.cfg["default_key_size"]))
        side.body.addWidget(self.key_in)

        self.iv_in = FormatField(
            "IV / Nonce", default_text="", default_format="Hex",
            generate_size=16,
        )
        self.iv_in.set_bytes(secrets.token_bytes(16))
        side.body.addWidget(self.iv_in)

        btn_encrypt = QPushButton("Chiffrer ->")
        btn_encrypt.setStyleSheet(PRIMARY_BUTTON_STYLE)
        btn_encrypt.clicked.connect(self._on_encrypt)
        side.body.addWidget(btn_encrypt)

        self.cipher_out = OutputArea("Chiffre", default_format="Hex")
        side.body.addWidget(self.cipher_out)

        side.body.addStretch(1)
        return side

    def _build_decrypt_side(self) -> QWidget:
        side = SectionFrame("Dechiffrement")
        self.cipher_in = FormatField(
            "Chiffre", default_text="", default_format="Hex", multiline=True,
        )
        side.body.addWidget(self.cipher_in)

        self.key_dec = FormatField(
            "Cle (meme que ci-contre)", default_text="", default_format="Hex",
            generate_size=None,
        )
        side.body.addWidget(self.key_dec)

        self.iv_dec = FormatField(
            "IV / Nonce (meme que ci-contre)", default_text="", default_format="Hex",
            generate_size=None,
        )
        side.body.addWidget(self.iv_dec)

        btn_decrypt = QPushButton("<- Dechiffrer")
        btn_decrypt.setStyleSheet(PRIMARY_BUTTON_STYLE)
        btn_decrypt.clicked.connect(self._on_decrypt)
        side.body.addWidget(btn_decrypt)

        btn_copy_from_encrypt = QPushButton("<= Copier chiffre + cle + IV depuis le panneau gauche")
        btn_copy_from_encrypt.clicked.connect(self._copy_from_encrypt_side)
        side.body.addWidget(btn_copy_from_encrypt)

        self.plain_out = OutputArea("Message dechiffre", default_format="Plain")
        side.body.addWidget(self.plain_out)

        side.body.addStretch(1)
        return side

    # ----- Reactions -----
    def _on_mode_changed(self, mode: str):
        iv_size = self.cfg["iv_size_fn"](mode)
        has_padding = self.cfg["padding_fn"](mode)
        # Toggle visibility / generate target size
        self.iv_in.setVisible(iv_size > 0)
        self.iv_dec.setVisible(iv_size > 0)
        if iv_size > 0:
            self.iv_in._gen_size = iv_size  # pylint: disable=protected-access
            # If current IV is wrong size, regenerate
            try:
                if len(self.iv_in.to_bytes()) != iv_size:
                    self.iv_in.set_bytes(secrets.token_bytes(iv_size))
            except Exception:
                self.iv_in.set_bytes(secrets.token_bytes(iv_size))
        self.padding_dd.setVisible(has_padding)

    def _on_key_size_changed(self, size_str: str):
        size = int(size_str)
        self.key_in._gen_size = size  # pylint: disable=protected-access
        # If key is wrong size, regenerate
        try:
            if len(self.key_in.to_bytes()) != size:
                self.key_in.set_bytes(secrets.token_bytes(size))
        except Exception:
            self.key_in.set_bytes(secrets.token_bytes(size))

    def _copy_from_encrypt_side(self):
        try:
            self.cipher_in.set_bytes(self.cipher_out.to_bytes())
            self.key_dec.set_bytes(self.key_in.to_bytes())
            self.iv_dec.set_bytes(self.iv_in.to_bytes())
        except Exception as e:
            self._error("Copie", str(e))

    def _on_encrypt(self):
        try:
            mode = self.mode_dd.value()
            msg = self.msg_in.to_bytes()
            cle = self.key_in.to_bytes()
            iv_size = self.cfg["iv_size_fn"](mode)
            iv = self.iv_in.to_bytes() if iv_size > 0 else b""
            padding = self.padding_dd.value() if self.cfg["padding_fn"](mode) else "PKCS7"

            expected_key = int(self.key_size_dd.value())
            if len(cle) != expected_key:
                raise ValueError(f"Cle doit faire {expected_key} octets (recue {len(cle)})")
            if iv_size and len(iv) != iv_size:
                raise ValueError(f"IV/Nonce doit faire {iv_size} octets (recu {len(iv)})")

            chiffre = self.cfg["encrypt"](mode, msg, cle, iv, padding)
            self.cipher_out.set_bytes(chiffre)
        except Exception as e:
            self._error("Erreur chiffrement", f"{e}\n\n{traceback.format_exc()}")

    def _on_decrypt(self):
        try:
            mode = self.mode_dd.value()
            blob = self.cipher_in.to_bytes()
            cle = self.key_dec.to_bytes()
            iv_size = self.cfg["iv_size_fn"](mode)
            iv = self.iv_dec.to_bytes() if iv_size > 0 else b""
            padding = self.padding_dd.value() if self.cfg["padding_fn"](mode) else "PKCS7"

            clair = self.cfg["decrypt"](mode, blob, cle, iv, padding)
            self.plain_out.set_bytes(clair)
        except Exception as e:
            self._error("Erreur dechiffrement", f"{e}\n\n{traceback.format_exc()}")

    def _error(self, title: str, msg: str):
        box = QMessageBox(self)
        box.setWindowTitle(title)
        box.setText(msg)
        box.setIcon(QMessageBox.Icon.Warning)
        box.exec()


# ============================================================================
#  ClassicalPanel : Caesar / Vigenere / OTP / Hill
# ============================================================================

class ClassicalPanel(QWidget):
    """Side-by-side encrypt/decrypt for classical ciphers."""

    def __init__(self, algo: str, parent=None):
        super().__init__(parent)
        assert algo in ("Caesar", "Vigenere", "OTP", "Hill")
        self.algo = algo
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(8)

        title = QLabel(f"{self.algo} - Chiffrement classique")
        title.setStyleSheet("font-size: 18px; font-weight: 700; color: #003f91;")
        root.addWidget(title)

        # Key controls (algo-specific)
        key_section = SectionFrame("Cle")
        if self.algo == "Caesar":
            from PySide6.QtWidgets import QSpinBox
            row = QHBoxLayout()
            row.addWidget(QLabel("Decalage (0-25) :"))
            self.caesar_key = QSpinBox()
            self.caesar_key.setRange(0, 25)
            self.caesar_key.setValue(7)
            row.addWidget(self.caesar_key)
            row.addStretch(1)
            key_section.body.addLayout(row)
        elif self.algo == "Vigenere":
            from PySide6.QtWidgets import QLineEdit
            row = QHBoxLayout()
            row.addWidget(QLabel("Cle (lettres) :"))
            self.vigenere_key = QLineEdit("CRYPTO")
            row.addWidget(self.vigenere_key, stretch=1)
            key_section.body.addLayout(row)
        elif self.algo == "OTP":
            self.otp_key = FormatField(
                "Cle (meme longueur que le message, idealement aleatoire)",
                default_text="", default_format="Hex", generate_size=16,
            )
            import secrets
            self.otp_key.set_bytes(secrets.token_bytes(16))
            key_section.body.addWidget(self.otp_key)
        else:  # Hill
            from PySide6.QtWidgets import QSpinBox, QLineEdit
            row1 = QHBoxLayout()
            row1.addWidget(QLabel("Taille de la matrice (n x n) :"))
            self.hill_n = QSpinBox()
            self.hill_n.setRange(2, 3)
            self.hill_n.setValue(2)
            row1.addWidget(self.hill_n)
            row1.addStretch(1)
            key_section.body.addLayout(row1)

            row2 = QHBoxLayout()
            row2.addWidget(QLabel("Matrice (lignes separees par ';', valeurs par ',') :"))
            self.hill_matrix = QLineEdit("3,3;2,5")
            row2.addWidget(self.hill_matrix, stretch=1)
            key_section.body.addLayout(row2)

            btn_gen = QPushButton("Generer une matrice valide aleatoire")
            btn_gen.clicked.connect(self._gen_hill_matrix)
            key_section.body.addWidget(btn_gen)

        root.addWidget(key_section)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._build_encrypt_side())
        splitter.addWidget(self._build_decrypt_side())
        splitter.setSizes([1, 1])
        root.addWidget(splitter, stretch=1)

    def _build_encrypt_side(self) -> QWidget:
        side = SectionFrame("Chiffrement")
        default_text = (
            "Hello secret world" if self.algo != "OTP"
            else "Secret"
        )
        self.msg_in = FormatField(
            "Message en clair", default_text=default_text, default_format="Plain", multiline=True,
        )
        side.body.addWidget(self.msg_in)
        btn = QPushButton("Chiffrer ->")
        btn.setStyleSheet(PRIMARY_BUTTON_STYLE)
        btn.clicked.connect(self._on_encrypt)
        side.body.addWidget(btn)

        out_format = "Plain" if self.algo in ("Caesar", "Vigenere", "Hill") else "Hex"
        self.cipher_out = OutputArea("Chiffre", default_format=out_format)
        side.body.addWidget(self.cipher_out)
        side.body.addStretch(1)
        return side

    def _build_decrypt_side(self) -> QWidget:
        side = SectionFrame("Dechiffrement")
        in_format = "Plain" if self.algo in ("Caesar", "Vigenere", "Hill") else "Hex"
        self.cipher_in = FormatField(
            "Chiffre", default_text="", default_format=in_format, multiline=True,
        )
        side.body.addWidget(self.cipher_in)

        btn_copy = QPushButton("<= Copier chiffre depuis le panneau gauche")
        btn_copy.clicked.connect(lambda: self.cipher_in.set_bytes(self.cipher_out.to_bytes()))
        side.body.addWidget(btn_copy)

        btn = QPushButton("<- Dechiffrer")
        btn.setStyleSheet(PRIMARY_BUTTON_STYLE)
        btn.clicked.connect(self._on_decrypt)
        side.body.addWidget(btn)

        self.plain_out = OutputArea("Message dechiffre", default_format="Plain")
        side.body.addWidget(self.plain_out)
        side.body.addStretch(1)
        return side

    def _parse_hill_matrix(self):
        text = self.hill_matrix.text().strip()
        rows = [r.strip() for r in text.split(";") if r.strip()]
        mat = []
        for r in rows:
            mat.append([int(x.strip()) for x in r.split(",")])
        n = int(self.hill_n.value())
        if len(mat) != n or any(len(row) != n for row in mat):
            raise ValueError(f"Matrice doit etre {n}x{n}")
        return mat, n

    def _gen_hill_matrix(self):
        from classical import hill
        import secrets
        n = int(self.hill_n.value())
        for _ in range(100):
            mat = [[secrets.randbelow(26) for _ in range(n)] for _ in range(n)]
            if hill.matrice_valide(mat, n):
                self.hill_matrix.setText(";".join(",".join(str(v) for v in row) for row in mat))
                return
        self._error("Hill", "Impossible de generer une matrice inversible apres 100 essais.")

    def _on_encrypt(self):
        try:
            if self.algo == "Caesar":
                from classical import caesar
                text = self.msg_in.text()
                k = int(self.caesar_key.value())
                chiffre = caesar.chiffrer(text, k)
                self.cipher_out.set_bytes(chiffre.encode("utf-8"))
            elif self.algo == "Vigenere":
                from classical import vigenere
                text = self.msg_in.text()
                key = self.vigenere_key.text()
                chiffre = vigenere.chiffrer(text, key)
                self.cipher_out.set_bytes(chiffre.encode("utf-8"))
            elif self.algo == "OTP":
                from classical import otp
                msg = self.msg_in.to_bytes()
                key = self.otp_key.to_bytes()
                if len(key) < len(msg):
                    raise ValueError(f"OTP : cle ({len(key)} o) doit etre >= message ({len(msg)} o)")
                chiffre = otp.chiffrer(msg, key[:len(msg)])
                self.cipher_out.set_bytes(chiffre)
            elif self.algo == "Hill":
                from classical import hill
                mat, n = self._parse_hill_matrix()
                text = self.msg_in.text()
                chiffre = hill.chiffrer(text, mat, n)
                self.cipher_out.set_bytes(chiffre.encode("utf-8"))
        except Exception as e:
            self._error("Erreur chiffrement", str(e))

    def _on_decrypt(self):
        try:
            if self.algo == "Caesar":
                from classical import caesar
                blob = self.cipher_in.to_bytes()
                text = blob.decode("utf-8", errors="replace")
                k = int(self.caesar_key.value())
                clair = caesar.dechiffrer(text, k)
                self.plain_out.set_text(clair)
            elif self.algo == "Vigenere":
                from classical import vigenere
                blob = self.cipher_in.to_bytes()
                text = blob.decode("utf-8", errors="replace")
                key = self.vigenere_key.text()
                clair = vigenere.dechiffrer(text, key)
                self.plain_out.set_text(clair)
            elif self.algo == "OTP":
                from classical import otp
                blob = self.cipher_in.to_bytes()
                key = self.otp_key.to_bytes()
                if len(key) < len(blob):
                    raise ValueError(f"OTP : cle ({len(key)} o) doit etre >= chiffre ({len(blob)} o)")
                clair = otp.dechiffrer(blob, key[:len(blob)])
                self.plain_out.set_bytes(clair)
            elif self.algo == "Hill":
                from classical import hill
                mat, n = self._parse_hill_matrix()
                blob = self.cipher_in.to_bytes()
                text = blob.decode("utf-8", errors="replace")
                clair = hill.dechiffrer(text, mat, n)
                self.plain_out.set_text(clair)
        except Exception as e:
            self._error("Erreur dechiffrement", str(e))

    def _error(self, title: str, msg: str):
        box = QMessageBox(self)
        box.setWindowTitle(title)
        box.setText(msg)
        box.setIcon(QMessageBox.Icon.Warning)
        box.exec()


# ============================================================================
#  HashPanel : MD5 / SHA-256 / SHA-512
# ============================================================================

class HashPanel(QWidget):
    """Hash a message with selectable algorithm."""

    HASH_ALGOS = ("MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-512")

    def __init__(self, default_algo: str = "SHA-256", parent=None):
        super().__init__(parent)
        self.default_algo = default_algo
        self._build()
        self._on_compute()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(8)

        title = QLabel("Fonctions de hachage")
        title.setStyleSheet("font-size: 18px; font-weight: 700; color: #003f91;")
        root.addWidget(title)

        section = SectionFrame("Calculer un hash")
        self.msg_in = FormatField(
            "Message", default_text="Hello world", default_format="Plain", multiline=True,
        )
        section.body.addWidget(self.msg_in)

        ctrls = QHBoxLayout()
        self.algo_dd = LabeledDropdown(
            "Algorithme", list(self.HASH_ALGOS), default=self.default_algo
        )
        self.algo_dd.changed.connect(lambda *_: self._on_compute())
        ctrls.addWidget(self.algo_dd)

        btn = QPushButton("Calculer")
        btn.setStyleSheet(PRIMARY_BUTTON_STYLE)
        btn.clicked.connect(self._on_compute)
        ctrls.addWidget(btn)
        ctrls.addStretch(1)
        section.body.addLayout(ctrls)

        self.digest_out = OutputArea("Hash", default_format="Hex")
        section.body.addWidget(self.digest_out)

        info = QLabel(
            "Note : MD5 et SHA-1 sont cryptographiquement casses (collisions"
            " connues). A utiliser uniquement pour comparaison / pedagogie."
        )
        info.setWordWrap(True)
        info.setStyleSheet("color: #92400e; font-size: 11px;")
        section.body.addWidget(info)
        section.body.addStretch(1)

        root.addWidget(section)
        root.addStretch(1)

    def _on_compute(self):
        try:
            import hashlib
            mapping = {
                "MD5": hashlib.md5, "SHA-1": hashlib.sha1,
                "SHA-256": hashlib.sha256, "SHA-384": hashlib.sha384,
                "SHA-512": hashlib.sha512,
                "SHA3-256": hashlib.sha3_256, "SHA3-512": hashlib.sha3_512,
            }
            algo = self.algo_dd.value()
            data = self.msg_in.to_bytes()
            digest = mapping[algo](data).digest()
            self.digest_out.set_bytes(digest)
        except Exception as e:
            self._error("Erreur hash", str(e))

    def _error(self, title: str, msg: str):
        box = QMessageBox(self)
        box.setWindowTitle(title)
        box.setText(msg)
        box.setIcon(QMessageBox.Icon.Warning)
        box.exec()


# ============================================================================
#  HMACPanel : keyed-hash message authentication code
# ============================================================================

class HMACPanel(QWidget):
    """Compute HMAC of a message with a key."""

    HASH_ALGOS = ("MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512")

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build()
        self._on_compute()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(8)

        title = QLabel("HMAC - Hash authentifie par cle")
        title.setStyleSheet("font-size: 18px; font-weight: 700; color: #003f91;")
        root.addWidget(title)

        section = SectionFrame("Calculer un HMAC")
        self.msg_in = FormatField(
            "Message", default_text="Document confidentiel", default_format="Plain", multiline=True,
        )
        section.body.addWidget(self.msg_in)

        self.key_in = FormatField(
            "Cle secrete", default_text="", default_format="Hex", generate_size=32,
        )
        import secrets
        self.key_in.set_bytes(secrets.token_bytes(32))
        section.body.addWidget(self.key_in)

        ctrls = QHBoxLayout()
        self.algo_dd = LabeledDropdown(
            "Hash sous-jacent", list(self.HASH_ALGOS), default="SHA-256"
        )
        self.algo_dd.changed.connect(lambda *_: self._on_compute())
        ctrls.addWidget(self.algo_dd)

        btn = QPushButton("Calculer")
        btn.setStyleSheet(PRIMARY_BUTTON_STYLE)
        btn.clicked.connect(self._on_compute)
        ctrls.addWidget(btn)
        ctrls.addStretch(1)
        section.body.addLayout(ctrls)

        self.tag_out = OutputArea("HMAC (tag)", default_format="Hex")
        section.body.addWidget(self.tag_out)
        section.body.addStretch(1)

        root.addWidget(section)
        root.addStretch(1)

    def _on_compute(self):
        try:
            import hmac
            algo = self.algo_dd.value().lower().replace("-", "")
            msg = self.msg_in.to_bytes()
            key = self.key_in.to_bytes()
            tag = hmac.new(key, msg, algo).digest()
            self.tag_out.set_bytes(tag)
        except Exception as e:
            self._error("Erreur HMAC", str(e))

    def _error(self, title: str, msg: str):
        box = QMessageBox(self)
        box.setWindowTitle(title)
        box.setText(msg)
        box.setIcon(QMessageBox.Icon.Warning)
        box.exec()


# ============================================================================
#  KeyExchangePanel : Diffie-Hellman (and ECDH)
# ============================================================================

class KeyExchangePanel(QWidget):
    """Simulates Alice and Bob agreeing on a shared secret without ever
    exchanging it directly."""

    def __init__(self, algo: str = "DH", parent=None):
        super().__init__(parent)
        assert algo in ("DH", "ECDH")
        self.algo = algo
        self._build()

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(8)

        title = QLabel(f"{self.algo} - Echange de cles")
        title.setStyleSheet("font-size: 18px; font-weight: 700; color: #003f91;")
        root.addWidget(title)

        info = QLabel(
            "Alice et Bob negocient un secret partage en n'echangeant que des"
            " valeurs publiques. Cliquer 'Executer' pour rejouer le scenario."
        )
        info.setWordWrap(True)
        root.addWidget(info)

        # Settings
        ctrls = QHBoxLayout()
        if self.algo == "DH":
            self.bits_dd = LabeledDropdown(
                "Taille p (bits)", ["512", "1024", "2048"], default="512"
            )
            ctrls.addWidget(self.bits_dd)
        else:
            self.curve_dd = LabeledDropdown(
                "Courbe", ["P-256", "P-384", "P-521"], default="P-256"
            )
            ctrls.addWidget(self.curve_dd)
        btn = QPushButton("Executer l'echange")
        btn.setStyleSheet(PRIMARY_BUTTON_STYLE)
        btn.clicked.connect(self._run_exchange)
        ctrls.addWidget(btn)
        ctrls.addStretch(1)
        root.addLayout(ctrls)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.alice = self._build_party("Alice")
        self.bob = self._build_party("Bob")
        splitter.addWidget(self.alice["frame"])
        splitter.addWidget(self.bob["frame"])
        splitter.setSizes([1, 1])
        root.addWidget(splitter, stretch=1)

        # Bottom : match indicator
        self.match_label = QLabel("Secret partage : ---")
        self.match_label.setStyleSheet(
            "font-size: 14px; font-weight: 600; padding: 8px;"
            " background: #f1f5f9; border-radius: 4px;"
        )
        root.addWidget(self.match_label)

    def _build_party(self, name: str) -> dict:
        frame = SectionFrame(name)
        widgets = {"frame": frame}
        for label, key in [
            ("Cle privee (secrete)", "priv"),
            ("Cle publique (envoyee)", "pub"),
            ("Secret partage calcule", "shared"),
        ]:
            row = QHBoxLayout()
            lbl = QLabel(label + " :")
            lbl.setMinimumWidth(180)
            row.addWidget(lbl)
            edit = QPlainTextEdit()
            edit.setReadOnly(True)
            edit.setMaximumHeight(60)
            edit.setStyleSheet("font-family: monospace; font-size: 11px;")
            row.addWidget(edit, stretch=1)
            frame.body.addLayout(row)
            widgets[key] = edit
        return widgets

    def _run_exchange(self):
        try:
            def short(n):
                h = hex(n) if isinstance(n, int) else str(n)
                return h if len(h) <= 80 else h[:80] + "..."

            if self.algo == "DH":
                from asymmetric import diffie_hellman as dh
                bits = int(self.bits_dd.value())
                p, g = dh.generer_p_g(bits)
                a, b, A, B, Ka, Kb = dh.echange(p, g)
                self.alice["priv"].setPlainText(f"a = {short(a)}")
                self.alice["pub"].setPlainText(f"A = g^a mod p = {short(A)}")
                self.alice["shared"].setPlainText(f"Ka = B^a mod p = {short(Ka)}")
                self.bob["priv"].setPlainText(f"b = {short(b)}")
                self.bob["pub"].setPlainText(f"B = g^b mod p = {short(B)}")
                self.bob["shared"].setPlainText(f"Kb = A^b mod p = {short(Kb)}")
                ok = (Ka == Kb)
            else:
                from cryptography.hazmat.primitives.asymmetric import ec
                curves = {"P-256": ec.SECP256R1(), "P-384": ec.SECP384R1(),
                          "P-521": ec.SECP521R1()}
                curve = curves[self.curve_dd.value()]
                sk_a = ec.generate_private_key(curve)
                sk_b = ec.generate_private_key(curve)
                pk_a = sk_a.public_key()
                pk_b = sk_b.public_key()
                shared_a = sk_a.exchange(ec.ECDH(), pk_b)
                shared_b = sk_b.exchange(ec.ECDH(), pk_a)

                da = sk_a.private_numbers().private_value
                db = sk_b.private_numbers().private_value
                pa = pk_a.public_numbers()
                pb = pk_b.public_numbers()
                self.alice["priv"].setPlainText(f"d_A = {short(da)}")
                self.alice["pub"].setPlainText(
                    f"P_A = d_A * G\n  x = {short(pa.x)}\n  y = {short(pa.y)}"
                )
                self.alice["shared"].setPlainText(f"hex = {shared_a.hex()[:80]}...")
                self.bob["priv"].setPlainText(f"d_B = {short(db)}")
                self.bob["pub"].setPlainText(
                    f"P_B = d_B * G\n  x = {short(pb.x)}\n  y = {short(pb.y)}"
                )
                self.bob["shared"].setPlainText(f"hex = {shared_b.hex()[:80]}...")
                ok = (shared_a == shared_b)

            if ok:
                self.match_label.setText("Secret partage : MATCH (Alice et Bob ont la meme cle)")
                self.match_label.setStyleSheet(
                    "font-size: 14px; font-weight: 600; padding: 8px;"
                    " background: #d1fae5; color: #065f46; border-radius: 4px;"
                )
            else:
                self.match_label.setText("Secret partage : MISMATCH (probleme)")
                self.match_label.setStyleSheet(
                    "font-size: 14px; font-weight: 600; padding: 8px;"
                    " background: #fee2e2; color: #991b1b; border-radius: 4px;"
                )
        except Exception as e:
            self._error("Erreur echange", str(e))

    def _error(self, title: str, msg: str):
        box = QMessageBox(self)
        box.setWindowTitle(title)
        box.setText(msg)
        box.setIcon(QMessageBox.Icon.Warning)
        box.exec()


# ============================================================================
#  SignaturePanel : RSA / DSA / ECDSA / ElGamal signatures
# ============================================================================

class SignaturePanel(QWidget):
    """Side-by-side sign / verify panel for signature schemes."""

    def __init__(self, algo: str, parent=None):
        super().__init__(parent)
        # algo : 'RSA-PKCS1v15' | 'RSA-PSS' | 'DSA' | 'ECDSA-P256'
        #      | 'ECDSA-P384' | 'ECDSA-P521' | 'ElGamal'
        self.algo = algo
        self._priv = None
        self._pub = None
        self._build()
        # Lazy : keys generated on first click (ElGamal-sig is slow via sympy).
        self.keys_display.setPlainText(
            "Aucune cle generee. Cliquer 'Generer une nouvelle paire de cles'"
            " pour commencer."
        )

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(8)

        title = QLabel(f"{self.algo} - Signature numerique")
        title.setStyleSheet("font-size: 18px; font-weight: 700; color: #003f91;")
        root.addWidget(title)

        # Top : key generation
        top = SectionFrame("Cles de signature")
        btn = QPushButton("Generer une nouvelle paire de cles")
        btn.setStyleSheet(PRIMARY_BUTTON_STYLE)
        btn.clicked.connect(self._regen_keys)
        top.body.addWidget(btn)

        self.keys_display = QPlainTextEdit()
        self.keys_display.setReadOnly(True)
        self.keys_display.setMaximumHeight(140)
        self.keys_display.setStyleSheet("font-family: monospace; font-size: 12px;")
        top.body.addWidget(self.keys_display)
        root.addWidget(top)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._build_sign_side())
        splitter.addWidget(self._build_verify_side())
        splitter.setSizes([1, 1])
        root.addWidget(splitter, stretch=1)

    def _build_sign_side(self) -> QWidget:
        side = SectionFrame("Signer (avec cle privee)")
        self.msg_sign = FormatField(
            "Message a signer", default_text="Document confidentiel",
            default_format="Plain", multiline=True,
        )
        side.body.addWidget(self.msg_sign)
        btn = QPushButton("Signer ->")
        btn.setStyleSheet(PRIMARY_BUTTON_STYLE)
        btn.clicked.connect(self._on_sign)
        side.body.addWidget(btn)
        self.sig_out = OutputArea("Signature", default_format="Hex")
        side.body.addWidget(self.sig_out)
        side.body.addStretch(1)
        return side

    def _build_verify_side(self) -> QWidget:
        side = SectionFrame("Verifier (avec cle publique)")
        self.msg_verify = FormatField(
            "Message recu", default_text="Document confidentiel",
            default_format="Plain", multiline=True,
        )
        side.body.addWidget(self.msg_verify)
        self.sig_in = FormatField(
            "Signature", default_text="", default_format="Hex", multiline=True,
        )
        side.body.addWidget(self.sig_in)

        btn_copy = QPushButton("<= Copier message + signature du panneau gauche")
        btn_copy.clicked.connect(self._copy_from_left)
        side.body.addWidget(btn_copy)

        btn = QPushButton("<- Verifier")
        btn.setStyleSheet(PRIMARY_BUTTON_STYLE)
        btn.clicked.connect(self._on_verify)
        side.body.addWidget(btn)

        self.verify_label = QLabel("Resultat : ---")
        self.verify_label.setStyleSheet(
            "font-size: 14px; font-weight: 600; padding: 8px;"
            " background: #f1f5f9; border-radius: 4px;"
        )
        side.body.addWidget(self.verify_label)
        side.body.addStretch(1)
        return side

    def _copy_from_left(self):
        try:
            self.msg_verify.set_bytes(self.msg_sign.to_bytes())
            self.sig_in.set_bytes(self.sig_out.to_bytes())
        except Exception as e:
            self._error("Copie", str(e))

    def _regen_keys(self):
        algo = self.algo
        self.keys_display.setPlainText(
            f"Generation de cles {algo} en cours...\n"
            f"(ElGamal-sig peut prendre 30 a 90 secondes via sympy)"
        )

        def work():
            if algo.startswith("RSA"):
                from signatures import rsa_signature
                priv, pub = rsa_signature.generer_cles(2048)
                return ("RSA", priv, pub)
            elif algo == "DSA":
                from cryptography.hazmat.primitives.asymmetric import dsa
                priv = dsa.generate_private_key(key_size=2048)
                return ("DSA", priv, priv.public_key())
            elif algo.startswith("ECDSA"):
                from cryptography.hazmat.primitives.asymmetric import ec
                curves = {"ECDSA-P256": ec.SECP256R1(), "ECDSA-P384": ec.SECP384R1(),
                          "ECDSA-P521": ec.SECP521R1()}
                priv = ec.generate_private_key(curves[algo])
                return ("ECDSA", priv, priv.public_key())
            else:  # ElGamal
                from signatures import elgamal_sig
                p, g, x, y = elgamal_sig.gen_cles(512)
                return ("ElGamal", (p, g, x), (p, g, y))

        def on_done(result):
            kind, priv, pub = result
            self._priv, self._pub = priv, pub

            def short(n):
                h = hex(n) if isinstance(n, int) else str(n)
                return h if len(h) <= 100 else h[:100] + "..."

            if kind == "RSA":
                pub_nums = pub.public_numbers()
                priv_nums = priv.private_numbers()
                self.keys_display.setPlainText(
                    f"=== Cle publique RSA (n, e) ===\n"
                    f"n : {short(pub_nums.n)}\n"
                    f"e : {pub_nums.e}\n"
                    f"\n=== Cle privee (d) ===\n"
                    f"d : {short(priv_nums.d)}"
                )
            elif kind == "DSA":
                params = pub.parameters().parameter_numbers()
                pub_nums = pub.public_numbers()
                priv_nums = priv.private_numbers()
                self.keys_display.setPlainText(
                    f"=== Parametres DSA (p, q, g) ===\n"
                    f"p : {short(params.p)}\n"
                    f"q : {short(params.q)}\n"
                    f"g : {short(params.g)}\n"
                    f"\n=== Cle publique y = g^x mod p ===\n"
                    f"y : {short(pub_nums.y)}\n"
                    f"\n=== Cle privee x ===\n"
                    f"x : {short(priv_nums.x)}"
                )
            elif kind == "ECDSA":
                pub_nums = pub.public_numbers()
                priv_nums = priv.private_numbers()
                self.keys_display.setPlainText(
                    f"=== Cle publique (point sur {algo}) ===\n"
                    f"x : {short(pub_nums.x)}\n"
                    f"y : {short(pub_nums.y)}\n"
                    f"\n=== Cle privee (scalaire d) ===\n"
                    f"d : {short(priv_nums.private_value)}"
                )
            else:  # ElGamal
                p, g, x = priv
                _, _, y = pub
                self.keys_display.setPlainText(
                    f"=== Cle publique (p, g, y) ===\n"
                    f"p : {short(p)}\n"
                    f"g : {g}\n"
                    f"y : {short(y)}\n"
                    f"\n=== Cle privee (x) ===\n"
                    f"x : {short(x)}"
                )

        def on_failed(msg):
            self.keys_display.setPlainText(f"Erreur generation cles :\n{msg}")

        self._keygen_thread = run_async(self, work, on_done, on_failed)

    def _on_sign(self):
        try:
            if self._priv is None:
                raise ValueError("Generer d'abord une paire de cles (bouton en haut)")
            msg = self.msg_sign.to_bytes()
            if self.algo == "RSA-PKCS1v15":
                from signatures import rsa_signature
                sig = rsa_signature.signer_pkcs1v15(self._priv, msg)
            elif self.algo == "RSA-PSS":
                from signatures import rsa_signature
                sig = rsa_signature.signer_pss(self._priv, msg)
            elif self.algo == "DSA":
                from cryptography.hazmat.primitives import hashes
                sig = self._priv.sign(msg, hashes.SHA256())
            elif self.algo.startswith("ECDSA"):
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import ec
                sig = self._priv.sign(msg, ec.ECDSA(hashes.SHA256()))
            elif self.algo == "ElGamal":
                from signatures import elgamal_sig
                p, g, x = self._priv
                r, s = elgamal_sig.signer(p, g, x, msg)
                sig = f"{hex(r)}:{hex(s)}".encode("ascii")
            else:
                raise ValueError(f"Algo inconnu : {self.algo}")
            self.sig_out.set_bytes(sig)
        except Exception as e:
            self._error("Erreur signature", str(e))

    def _on_verify(self):
        try:
            if self._pub is None:
                raise ValueError("Generer d'abord une paire de cles (bouton en haut)")
            msg = self.msg_verify.to_bytes()
            sig = self.sig_in.to_bytes()
            ok = False
            if self.algo == "RSA-PKCS1v15":
                from signatures import rsa_signature
                ok = rsa_signature.verifier_pkcs1v15(self._pub, msg, sig)
            elif self.algo == "RSA-PSS":
                from signatures import rsa_signature
                ok = rsa_signature.verifier_pss(self._pub, msg, sig)
            elif self.algo == "DSA":
                from cryptography.exceptions import InvalidSignature
                from cryptography.hazmat.primitives import hashes
                try:
                    self._pub.verify(sig, msg, hashes.SHA256())
                    ok = True
                except InvalidSignature:
                    ok = False
            elif self.algo.startswith("ECDSA"):
                from cryptography.exceptions import InvalidSignature
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import ec
                try:
                    self._pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
                    ok = True
                except InvalidSignature:
                    ok = False
            elif self.algo == "ElGamal":
                from signatures import elgamal_sig
                p, g, y = self._pub
                text = sig.decode("ascii", errors="replace")
                rs, ss = text.split(":")
                r = int(rs, 16)
                s = int(ss, 16)
                ok = elgamal_sig.verifier(p, g, y, msg, r, s)
            else:
                raise ValueError(f"Algo inconnu : {self.algo}")

            if ok:
                self.verify_label.setText("Resultat : VALIDE - signature legitime")
                self.verify_label.setStyleSheet(
                    "font-size: 14px; font-weight: 600; padding: 8px;"
                    " background: #d1fae5; color: #065f46; border-radius: 4px;"
                )
            else:
                self.verify_label.setText("Resultat : INVALIDE - message ou signature manipule")
                self.verify_label.setStyleSheet(
                    "font-size: 14px; font-weight: 600; padding: 8px;"
                    " background: #fee2e2; color: #991b1b; border-radius: 4px;"
                )
        except Exception as e:
            self._error("Erreur verification", str(e))

    def _error(self, title: str, msg: str):
        box = QMessageBox(self)
        box.setWindowTitle(title)
        box.setText(msg)
        box.setIcon(QMessageBox.Icon.Warning)
        box.exec()


# ============================================================================
#  AsymmetricEncryptPanel : RSA / ElGamal
# ============================================================================

class AsymmetricEncryptPanel(QWidget):
    """Side-by-side encrypt/decrypt for asymmetric algos (RSA, ElGamal).

    Generates a key pair on demand, displays public + private components,
    encrypts on the left, decrypts on the right.
    """

    def __init__(self, algo: str, parent=None):
        super().__init__(parent)
        assert algo in ("RSA", "ElGamal")
        self.algo = algo
        self._priv = None
        self._pub = None
        self._build()
        # Lazy : keys are generated on first click, not at init (ElGamal/sympy
        # is too slow to block the GUI startup).
        self.keys_display.setPlainText(
            "Aucune cle generee. Cliquer 'Generer une nouvelle paire de cles'"
            " pour commencer."
        )

    def _build(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(8)

        title = QLabel(f"{self.algo} - Chiffrement asymetrique")
        title.setStyleSheet("font-size: 18px; font-weight: 700; color: #003f91;")
        root.addWidget(title)

        # Top : key generation
        top = SectionFrame("Cles (generer ou editer manuellement)")
        ctrls = QHBoxLayout()
        sizes = ["1024", "2048", "3072", "4096"] if self.algo == "RSA" else ["512", "1024", "2048"]
        default = "2048" if self.algo == "RSA" else "512"
        self.bits_dd = LabeledDropdown("Taille (bits)", sizes, default=default)
        ctrls.addWidget(self.bits_dd)
        btn = QPushButton("Generer une nouvelle paire de cles")
        btn.setStyleSheet(PRIMARY_BUTTON_STYLE)
        btn.clicked.connect(self._regen_keys)
        ctrls.addWidget(btn)

        from PySide6.QtWidgets import QCheckBox
        self.manual_chk = QCheckBox("Editer manuellement (non securise)")
        self.manual_chk.toggled.connect(self._toggle_manual)
        ctrls.addWidget(self.manual_chk)

        self.apply_btn = QPushButton("Appliquer la cle saisie")
        self.apply_btn.setVisible(False)
        self.apply_btn.clicked.connect(self._apply_manual_keys)
        ctrls.addWidget(self.apply_btn)

        ctrls.addStretch(1)
        top.body.addLayout(ctrls)

        self.keys_display = QPlainTextEdit()
        self.keys_display.setReadOnly(True)
        self.keys_display.setMaximumHeight(200)
        self.keys_display.setStyleSheet("font-family: monospace; font-size: 12px;")
        top.body.addWidget(self.keys_display)

        hint = QLabel(
            "Format manuel : une cle par ligne 'nom = valeur' (decimal ou hex avec 0x)." +
            (" Necessaires : n, e, d (pour dechiffrer). p, q optionnels."
             if self.algo == "RSA"
             else " Necessaires : p, g, x (privee) ou p, g, y (publique).")
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: #64748b; font-size: 11px;")
        top.body.addWidget(hint)

        root.addWidget(top)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.addWidget(self._build_encrypt_side())
        splitter.addWidget(self._build_decrypt_side())
        splitter.setSizes([1, 1])
        root.addWidget(splitter, stretch=1)

    def _toggle_manual(self, checked: bool):
        self.keys_display.setReadOnly(not checked)
        self.apply_btn.setVisible(checked)
        if checked and (self._pub is None or "Aucune cle" in self.keys_display.toPlainText()):
            # Pre-fill with a template
            if self.algo == "RSA":
                self.keys_display.setPlainText(
                    "n = 0x...\n"
                    "e = 65537\n"
                    "d = 0x...\n"
                    "p = 0x...    # optionnel mais ameliore les perfs\n"
                    "q = 0x...    # optionnel"
                )
            else:
                self.keys_display.setPlainText(
                    "p = 0x...\n"
                    "g = 2\n"
                    "x = 0x...    # cle privee\n"
                    "y = 0x...    # cle publique (= g^x mod p, sera recalcule si absent)"
                )

    def _parse_keys_text(self) -> dict:
        out = {}
        for raw in self.keys_display.toPlainText().splitlines():
            line = raw.split("#")[0].strip()
            if not line or "=" not in line:
                continue
            name, val = [s.strip() for s in line.split("=", 1)]
            name = name.lower()
            val = val.strip()
            if not val or val.startswith("0x..."):
                continue
            base = 16 if val.lower().startswith("0x") else 10
            try:
                out[name] = int(val, base)
            except ValueError as e:
                raise ValueError(f"Impossible de parser '{name}' = '{val}' : {e}")
        return out

    def _apply_manual_keys(self):
        try:
            kv = self._parse_keys_text()
            if self.algo == "RSA":
                if not all(k in kv for k in ("n", "e", "d")):
                    raise ValueError("RSA : n, e et d sont obligatoires")
                from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa
                n, e, d = kv["n"], kv["e"], kv["d"]
                p = kv.get("p")
                q = kv.get("q")
                if p is None or q is None:
                    # Without p, q we can't build a private key via the standard
                    # API. Use a minimal stand-in : derive p, q via factorisation
                    # is too slow, so instead require them.
                    raise ValueError(
                        "RSA : p et q sont aussi requis pour reconstruire la cle privee"
                        " (la lib cryptography ne permet pas d'importer juste (n,e,d))."
                        " Tu peux les obtenir en generant une cle avec 'Generer' puis"
                        " en copiant les valeurs affichees."
                    )
                # Derive remaining CRT values
                dmp1 = d % (p - 1)
                dmq1 = d % (q - 1)
                iqmp = pow(q, -1, p)
                pub_nums = crypto_rsa.RSAPublicNumbers(e=e, n=n)
                priv_nums = crypto_rsa.RSAPrivateNumbers(
                    p=p, q=q, d=d, dmp1=dmp1, dmq1=dmq1, iqmp=iqmp,
                    public_numbers=pub_nums,
                )
                self._priv = priv_nums.private_key()
                self._pub = pub_nums.public_key()
            else:  # ElGamal
                if "p" not in kv or "g" not in kv:
                    raise ValueError("ElGamal : p et g sont obligatoires")
                p, g = kv["p"], kv["g"]
                x = kv.get("x")
                y = kv.get("y")
                if x is None and y is None:
                    raise ValueError("ElGamal : x (privee) ou y (publique) requis")
                if y is None and x is not None:
                    y = pow(g, x, p)
                self._priv = (p, g, x) if x is not None else None
                self._pub = (p, g, y)

            self.keys_display.setPlainText(
                self.keys_display.toPlainText().rstrip()
                + "\n\n# Cles importees avec succes."
            )
        except Exception as e:
            self._error("Import cles", str(e))

    def _build_encrypt_side(self) -> QWidget:
        side = SectionFrame("Chiffrement (avec cle publique)")
        self.msg_in = FormatField(
            "Message en clair",
            default_text=("Hello RSA" if self.algo == "RSA" else "12345"),
            default_format=("Plain" if self.algo == "RSA" else "Plain"),
            multiline=(self.algo == "RSA"),
        )
        side.body.addWidget(self.msg_in)

        btn = QPushButton("Chiffrer ->")
        btn.setStyleSheet(PRIMARY_BUTTON_STYLE)
        btn.clicked.connect(self._on_encrypt)
        side.body.addWidget(btn)

        self.cipher_out = OutputArea("Chiffre", default_format="Hex")
        side.body.addWidget(self.cipher_out)
        side.body.addStretch(1)
        return side

    def _build_decrypt_side(self) -> QWidget:
        side = SectionFrame("Dechiffrement (avec cle privee)")
        self.cipher_in = FormatField(
            "Chiffre",
            default_text="",
            default_format="Hex",
            multiline=True,
        )
        side.body.addWidget(self.cipher_in)

        btn_copy = QPushButton("<= Copier chiffre depuis le panneau gauche")
        btn_copy.clicked.connect(self._copy_cipher)
        side.body.addWidget(btn_copy)

        btn = QPushButton("<- Dechiffrer")
        btn.setStyleSheet(PRIMARY_BUTTON_STYLE)
        btn.clicked.connect(self._on_decrypt)
        side.body.addWidget(btn)

        self.plain_out = OutputArea("Message dechiffre", default_format="Plain")
        side.body.addWidget(self.plain_out)
        side.body.addStretch(1)
        return side

    # ----- Crypto -----
    def _regen_keys(self):
        bits = int(self.bits_dd.value())
        algo = self.algo
        self.keys_display.setPlainText(
            f"Generation de cles {algo} {bits} bits en cours...\n"
            f"(ElGamal en 2048 bits peut prendre 30 a 90 secondes via sympy)"
        )

        def work():
            if algo == "RSA":
                from asymmetric import rsa as rsa_mod
                priv, pub = rsa_mod.generer_cles(bits)
                return ("RSA", priv, pub)
            else:
                from asymmetric import elgamal
                p, g, x, y = elgamal.generer_cles(bits)
                return ("ElGamal", (p, g, x), (p, g, y))

        def on_done(result):
            kind, priv, pub = result
            self._priv, self._pub = priv, pub

            def short(n):
                h = hex(n) if isinstance(n, int) else str(n)
                return h if len(h) <= 100 else h[:100] + "..."

            if kind == "RSA":
                pub_nums = pub.public_numbers()
                priv_nums = priv.private_numbers()
                self.keys_display.setPlainText(
                    f"=== Cle publique (n, e) ===\n"
                    f"n  : {short(pub_nums.n)}\n"
                    f"e  : {pub_nums.e}\n"
                    f"\n=== Cle privee (d, p, q) ===\n"
                    f"d  : {short(priv_nums.d)}\n"
                    f"p  : {short(priv_nums.p)}\n"
                    f"q  : {short(priv_nums.q)}"
                )
            else:
                p, g, x = priv
                _, _, y = pub
                self.keys_display.setPlainText(
                    f"=== Cle publique (p, g, y) ===\n"
                    f"p  : {short(p)}\n"
                    f"g  : {g}\n"
                    f"y  : {short(y)}  (= g^x mod p)\n"
                    f"\n=== Cle privee (x) ===\n"
                    f"x  : {short(x)}"
                )

        def on_failed(msg):
            self.keys_display.setPlainText(f"Erreur generation cles :\n{msg}")

        self._keygen_thread = run_async(self, work, on_done, on_failed)

    def _copy_cipher(self):
        try:
            self.cipher_in.set_bytes(self.cipher_out.to_bytes())
        except Exception as e:
            self._error("Copie", str(e))

    def _on_encrypt(self):
        try:
            if self._pub is None:
                raise ValueError("Generer d'abord une paire de cles (bouton en haut)")
            if self.algo == "RSA":
                from asymmetric import rsa as rsa_mod
                msg = self.msg_in.to_bytes()
                c = rsa_mod.chiffrer(self._pub, msg)
                self.cipher_out.set_bytes(c)
            else:
                from asymmetric import elgamal
                p, g, y = self._pub
                txt = self.msg_in.text()
                try:
                    M = int(txt)
                except ValueError:
                    raise ValueError("ElGamal : le message doit etre un entier 0 < M < p")
                if not (0 < M < p):
                    raise ValueError(f"ElGamal : M doit verifier 0 < M < p (p a ~{p.bit_length()} bits)")
                c1, c2 = elgamal.chiffrer(p, g, y, M)
                blob = f"{hex(c1)}:{hex(c2)}".encode("ascii")
                self.cipher_out.set_bytes(blob)
        except Exception as e:
            self._error("Erreur chiffrement", str(e))

    def _on_decrypt(self):
        try:
            if self._priv is None:
                raise ValueError("Generer d'abord une paire de cles (bouton en haut)")
            if self.algo == "RSA":
                from asymmetric import rsa as rsa_mod
                blob = self.cipher_in.to_bytes()
                m = rsa_mod.dechiffrer(self._priv, blob)
                self.plain_out.set_bytes(m)
            else:
                from asymmetric import elgamal
                p, g, x = self._priv
                blob = self.cipher_in.to_bytes().decode("ascii", errors="replace")
                c1s, c2s = blob.split(":")
                c1 = int(c1s, 16)
                c2 = int(c2s, 16)
                M = elgamal.dechiffrer(p, x, c1, c2)
                self.plain_out.set_text(str(M))
        except Exception as e:
            self._error("Erreur dechiffrement", str(e))

    def _error(self, title: str, msg: str):
        box = QMessageBox(self)
        box.setWindowTitle(title)
        box.setText(msg)
        box.setIcon(QMessageBox.Icon.Warning)
        box.exec()
