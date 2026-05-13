"""Reusable PySide6 widgets for algorithm panels.

Provides:
- FormatToggle: radio-like selector for Plain / Hex / Base64
- FormatField: text input + format selector + optional Generate button
- LabeledDropdown: label + QComboBox
- SectionFrame: titled card grouping related fields
- encode_to_bytes / decode_from_bytes : conversions between str representations
"""
import base64
import os

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListView,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


# Stylesheet applied directly to each QComboBox popup view. The global QSS
# (QComboBox QAbstractItemView) does not always reach the popup on macOS with
# Fusion style, which caused the popup to render as a tall French Blue strip.
_COMBO_POPUP_STYLE = (
    "QListView {"
    "  background-color: #ffffff;"
    "  color: #0f1e3a;"
    "  border: 1px solid #c4cdd9;"
    "  border-radius: 6px;"
    "  padding: 4px;"
    "  outline: none;"
    "}"
    "QListView::item {"
    "  background-color: #ffffff;"
    "  color: #0f1e3a;"
    "  padding: 6px 12px;"
    "  min-height: 22px;"
    "  border: none;"
    "}"
    "QListView::item:hover {"
    "  background-color: #e5f4e3;"
    "  color: #003f91;"
    "}"
    "QListView::item:selected {"
    "  background-color: #003f91;"
    "  color: #ffffff;"
    "}"
)


# Pill-style toggle: each option is a small checkable button.
PRIMARY_BUTTON_STYLE = (
    "QPushButton {"
    "  background-color: #003f91;"
    "  color: #ffffff;"
    "  border: 1px solid #003f91;"
    "  border-radius: 8px;"
    "  padding: 12px 20px;"
    "  font-weight: 700;"
    "  font-size: 14px;"
    "}"
    "QPushButton:hover { background-color: #002a66; border-color: #002a66; }"
    "QPushButton:pressed { background-color: #001f4d; }"
    "QPushButton:disabled { background-color: #94a3b8; border-color: #94a3b8; }"
    "QPushButton:focus { outline: none; }"
)


SECONDARY_BUTTON_STYLE = (
    "QPushButton {"
    "  background-color: #ffffff;"
    "  color: #003f91;"
    "  border: 1px solid #c4cdd9;"
    "  border-radius: 6px;"
    "  padding: 7px 14px;"
    "  font-weight: 600;"
    "}"
    "QPushButton:hover { border-color: #5da9e9; }"
    "QPushButton:focus { outline: none; }"
)


_PILL_STYLE = (
    "QPushButton {"
    "  background-color: #ffffff;"
    "  color: #0f1e3a;"
    "  border: 1px solid #c4cdd9;"
    "  border-radius: 6px;"
    "  padding: 6px 14px;"
    "  font-weight: 600;"
    "}"
    "QPushButton:hover { border-color: #5da9e9; }"
    "QPushButton:checked {"
    "  background-color: #003f91;"
    "  color: #ffffff;"
    "  border-color: #003f91;"
    "}"
    "QPushButton:focus { outline: none; }"
)


class PillToggle(QWidget):
    """Group of mutually-exclusive pill buttons (replaces radios)."""

    changed = Signal(str)

    def __init__(self, options: list[str], default: str | None = None, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        self._group = QButtonGroup(self)
        self._group.setExclusive(True)
        self._buttons: dict[str, QPushButton] = {}
        for opt in options:
            btn = QPushButton(opt)
            btn.setCheckable(True)
            btn.setStyleSheet(_PILL_STYLE)
            btn.setCursor(self.cursor())
            self._group.addButton(btn)
            self._buttons[opt] = btn
            btn.toggled.connect(self._on_toggle)
            layout.addWidget(btn)
        layout.addStretch(1)

        if default is not None and default in self._buttons:
            self._buttons[default].setChecked(True)
        elif options:
            self._buttons[options[0]].setChecked(True)

    def _on_toggle(self, checked: bool):
        if checked:
            self.changed.emit(self.value())

    def value(self) -> str:
        for opt, btn in self._buttons.items():
            if btn.isChecked():
                return opt
        return next(iter(self._buttons))

    def set_value(self, opt: str):
        if opt in self._buttons:
            self._buttons[opt].setChecked(True)

    def set_options(self, options: list[str], keep: bool = True):
        current = self.value() if keep else None
        # Remove existing
        for btn in list(self._buttons.values()):
            self._group.removeButton(btn)
            btn.setParent(None)
            btn.deleteLater()
        self._buttons.clear()
        layout = self.layout()
        # Recreate
        for opt in options:
            btn = QPushButton(opt)
            btn.setCheckable(True)
            btn.setStyleSheet(_PILL_STYLE)
            self._group.addButton(btn)
            self._buttons[opt] = btn
            btn.toggled.connect(self._on_toggle)
            layout.insertWidget(layout.count() - 1, btn)
        if current and current in self._buttons:
            self._buttons[current].setChecked(True)
        elif options:
            self._buttons[options[0]].setChecked(True)


FORMATS = ("Plain", "Hex", "Base64")


def encode_to_bytes(text: str, fmt: str) -> bytes:
    """Convert a user-entered string into raw bytes per the chosen format."""
    if fmt == "Plain":
        return text.encode("utf-8")
    if fmt == "Hex":
        return bytes.fromhex(text.replace(" ", "").replace(":", ""))
    if fmt == "Base64":
        return base64.b64decode(text)
    raise ValueError(f"Format inconnu : {fmt}")


def decode_from_bytes(data: bytes, fmt: str) -> str:
    """Convert raw bytes into a printable string per the chosen format."""
    if fmt == "Plain":
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("utf-8", errors="replace")
    if fmt == "Hex":
        return data.hex()
    if fmt == "Base64":
        return base64.b64encode(data).decode("ascii")
    raise ValueError(f"Format inconnu : {fmt}")


class FormatToggle(PillToggle):
    """Pill toggle for the three formats : Plain | Hex | Base64."""

    def __init__(self, default: str = "Plain", parent=None):
        super().__init__(list(FORMATS), default=default, parent=parent)


class FormatField(QWidget):
    """Labeled text field + format toggle + optional Generate button.

    The 'value' is exposed as raw bytes via to_bytes(); the textual
    representation depends on the active format.
    """

    def __init__(
        self,
        label: str,
        default_text: str = "",
        default_format: str = "Hex",
        generate_size: int | None = None,
        multiline: bool = False,
        parent=None,
    ):
        super().__init__(parent)
        self._gen_size = generate_size

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(2)

        header = QHBoxLayout()
        header.setSpacing(8)
        header.addWidget(QLabel(label))
        header.addStretch(1)
        if generate_size is not None:
            self._btn_gen = QPushButton("Generate")
            self._btn_gen.setMaximumWidth(90)
            self._btn_gen.clicked.connect(self._on_generate)
            header.addWidget(self._btn_gen)
        outer.addLayout(header)

        if multiline:
            self._edit: QLineEdit | QPlainTextEdit = QPlainTextEdit()
            self._edit.setPlainText(default_text)
            self._edit.setMaximumHeight(120)
        else:
            self._edit = QLineEdit(default_text)
        outer.addWidget(self._edit)

        format_row = QHBoxLayout()
        format_row.setSpacing(6)
        format_row.addWidget(QLabel("Format :"))
        self._toggle = FormatToggle(default=default_format)
        self._toggle.changed.connect(self._on_format_changed)
        format_row.addWidget(self._toggle)
        outer.addLayout(format_row)

        self._format = default_format

    def _on_generate(self):
        if self._gen_size is None:
            return
        raw = os.urandom(self._gen_size)
        self.set_bytes(raw)

    def _on_format_changed(self, new_fmt: str):
        # Convert current display from old format to new format
        current_text = self.text()
        try:
            data = encode_to_bytes(current_text, self._format)
            new_text = decode_from_bytes(data, new_fmt)
            self.set_text(new_text)
        except Exception:
            # Invalid input under old format : just update format selector
            pass
        self._format = new_fmt

    def text(self) -> str:
        if isinstance(self._edit, QPlainTextEdit):
            return self._edit.toPlainText()
        return self._edit.text()

    def set_text(self, text: str):
        if isinstance(self._edit, QPlainTextEdit):
            self._edit.setPlainText(text)
        else:
            self._edit.setText(text)

    def to_bytes(self) -> bytes:
        return encode_to_bytes(self.text(), self._format)

    def set_bytes(self, data: bytes):
        self.set_text(decode_from_bytes(data, self._format))

    def format(self) -> str:
        return self._format


class LabeledDropdown(QWidget):
    """Label + QComboBox horizontally aligned."""

    changed = Signal(str)

    def __init__(self, label: str, options: list[str], default: str | None = None, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        layout.addWidget(QLabel(label))
        self._combo = QComboBox()
        self._combo.addItems(options)
        if default is not None and default in options:
            self._combo.setCurrentText(default)
        self._combo.currentTextChanged.connect(self.changed.emit)
        # Force a QListView popup and style it directly so the dropdown
        # renders as a clean white card on macOS / Fusion, instead of a
        # tall blue strip painted with the selection color.
        self._combo.setView(QListView())
        self._combo.view().setStyleSheet(_COMBO_POPUP_STYLE)
        self._combo.setMaxVisibleItems(8)
        self._combo.setMinimumWidth(140)
        self._combo.setMinimumHeight(28)
        layout.addWidget(self._combo, stretch=1)

    def value(self) -> str:
        return self._combo.currentText()

    def set_value(self, v: str):
        self._combo.setCurrentText(v)

    def set_options(self, options: list[str], keep: bool = True):
        current = self._combo.currentText() if keep else None
        self._combo.blockSignals(True)
        self._combo.clear()
        self._combo.addItems(options)
        if current and current in options:
            self._combo.setCurrentText(current)
        self._combo.blockSignals(False)


class SectionFrame(QFrame):
    """Titled card with vertical layout (use .body to add child widgets)."""

    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setObjectName("SectionFrame")
        self.setStyleSheet(
            "#SectionFrame { background: #f8fafc; border: 1px solid #d6dde6;"
            " border-radius: 6px; padding: 8px; }"
        )
        outer = QVBoxLayout(self)
        outer.setContentsMargins(10, 10, 10, 10)
        outer.setSpacing(8)
        title_lbl = QLabel(title)
        title_lbl.setStyleSheet("font-weight: 600; color: #003f91;")
        outer.addWidget(title_lbl)
        self.body = QVBoxLayout()
        self.body.setSpacing(10)
        outer.addLayout(self.body)


class OutputArea(QWidget):
    """Read-only output text area with format toggle and Copy button."""

    def __init__(self, label: str, default_format: str = "Hex", parent=None):
        super().__init__(parent)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(2)
        header = QHBoxLayout()
        header.addWidget(QLabel(label))
        header.addStretch(1)
        self._copy = QPushButton("Copy")
        self._copy.setMaximumWidth(70)
        self._copy.clicked.connect(self._on_copy)
        header.addWidget(self._copy)
        outer.addLayout(header)

        self._edit = QPlainTextEdit()
        self._edit.setReadOnly(True)
        self._edit.setMaximumHeight(160)
        outer.addWidget(self._edit)

        format_row = QHBoxLayout()
        format_row.setSpacing(6)
        format_row.addWidget(QLabel("Format :"))
        self._toggle = FormatToggle(default=default_format)
        self._toggle.changed.connect(self._on_format_changed)
        format_row.addWidget(self._toggle)
        outer.addLayout(format_row)

        self._raw: bytes | None = None
        self._format = default_format

    def _on_copy(self):
        from PySide6.QtGui import QGuiApplication
        QGuiApplication.clipboard().setText(self._edit.toPlainText())

    def _on_format_changed(self, fmt: str):
        self._format = fmt
        if self._raw is not None:
            self._edit.setPlainText(decode_from_bytes(self._raw, fmt))

    def set_bytes(self, data: bytes):
        self._raw = data
        self._edit.setPlainText(decode_from_bytes(data, self._format))

    def set_text(self, text: str):
        self._raw = text.encode("utf-8", errors="replace")
        self._edit.setPlainText(text)

    def to_bytes(self) -> bytes:
        return self._raw or b""

    def text(self) -> str:
        return self._edit.toPlainText()

    def format(self) -> str:
        return self._format
