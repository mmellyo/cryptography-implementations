"""Desktop GUI for the cryptography demos (PySide6).

Two views per module:
- 'Scenario' tab : runs the module's hard-coded demo() and displays stdout.
- 'Tester avec mes valeurs' tab : interactive form (or custom widget for the
  application demos) that lets the user supply their own inputs.
"""
import importlib
import io
import sys
from contextlib import redirect_stdout

from PySide6.QtCore import QObject, QThread, Qt, Signal
from PySide6.QtGui import QAction, QFont
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QSplitter,
    QStackedWidget,
    QStatusBar,
    QTabWidget,
    QToolBar,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gui_apps import TcpChatPanel, UdpChatPanel, VotingPanel
from gui_specs import (
    BYTES_HEX,
    BYTES_UTF8,
    CHOICE,
    INT,
    MULTILINE,
    SPECS,
    TEXT,
    Champ,
    Spec,
)
from main import MODULES, THEME_ORDER, THEMES

PANELS_PERSO = {
    "applications.tcp_secure": TcpChatPanel,
    "applications.udp_chat": UdpChatPanel,
    "applications.voting": VotingPanel,
}


STYLESHEET = """
/*
 * Palette
 *   Honeydew     #e5f4e3   soft tinted surface, received bubble
 *   Cool Sky     #5da9e9   hover/focus, secondary accent
 *   French Blue  #003f91   primary, brand, active states
 *   White        #ffffff   main canvas
 */

* {
    font-family: "Helvetica Neue", "Inter", "Segoe UI", Arial, sans-serif;
    font-size: 13px;
}

QMainWindow, QWidget {
    background-color: #ffffff;
    color: #0f172a;
}

QSplitter::handle {
    background-color: #d6dde6;
    width: 1px;
}
QSplitter::handle:hover { background-color: #5da9e9; }

/* Toolbar */
QToolBar {
    background-color: #ffffff;
    border: none;
    border-bottom: 1px solid #d6dde6;
    spacing: 4px;
    padding: 10px 16px;
}
QToolBar QToolButton {
    background-color: transparent;
    color: #1e3a6b;
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 6px 12px;
    font-weight: 500;
}
QToolBar QToolButton:hover {
    background-color: #e5f4e3;
    color: #003f91;
}
QToolBar QToolButton:pressed { background-color: #d3ead0; }
QToolBar QToolButton:disabled {
    background-color: transparent;
    color: #b8c2d1;
}

/* Status bar */
QStatusBar {
    background-color: #ffffff;
    color: #5e6b80;
    border-top: 1px solid #d6dde6;
    padding: 0 14px;
    min-height: 28px;
}
QStatusBar::item { border: none; }
QStatusBar QLabel { color: #5e6b80; }

/* Sidebar tree */
QTreeWidget {
    background-color: #ffffff;
    color: #1e3a6b;
    border: none;
    border-right: 1px solid #d6dde6;
    padding: 8px 0;
    outline: none;
    show-decoration-selected: 1;
}
QTreeWidget::item {
    padding: 6px 10px;
    color: #1e3a6b;
    border: none;
}
QTreeWidget::item:hover:!selected {
    background-color: #e5f4e3;
    color: #003f91;
}
QTreeWidget::item:selected,
QTreeWidget::item:selected:active {
    background-color: #003f91;
    color: #ffffff;
    font-weight: 600;
}
QTreeWidget::branch {
    background-color: #ffffff;
}
QTreeWidget::branch:hover { background-color: #e5f4e3; }
QTreeWidget::branch:selected,
QTreeWidget::branch:selected:active {
    background-color: #003f91;
}

/* Tabs */
QTabWidget {
    background-color: #ffffff;
}
QTabWidget::pane {
    background-color: #ffffff;
    border: none;
    border-top: 1px solid #d6dde6;
    top: -1px;
}
QTabWidget::tab-bar {
    background-color: #ffffff;
    left: 0;
}
QTabBar {
    background-color: #ffffff;
    qproperty-drawBase: 0;
}
QTabBar::tab {
    background-color: #ffffff;
    color: #5e6b80;
    padding: 12px 24px;
    border: none;
    border-bottom: 2px solid transparent;
    font-weight: 500;
    margin: 0;
}
QTabBar::tab:hover {
    color: #003f91;
    background-color: #f3faf2;
}
QTabBar::tab:selected {
    color: #003f91;
    border-bottom: 2px solid #003f91;
    background-color: #ffffff;
    font-weight: 600;
}

/* Text areas */
QPlainTextEdit {
    background-color: #f3faf2;
    color: #0f1e3a;
    border: 1px solid #d6dde6;
    border-radius: 8px;
    padding: 14px;
    selection-background-color: #5da9e9;
    selection-color: #ffffff;
}
QPlainTextEdit:focus { border-color: #5da9e9; }
QPlainTextEdit:read-only { background-color: #f3faf2; }

/* Inputs */
QLineEdit, QSpinBox, QComboBox {
    background-color: #ffffff;
    color: #0f1e3a;
    border: 1px solid #c4cdd9;
    border-radius: 6px;
    padding: 8px 12px;
    selection-background-color: #5da9e9;
    selection-color: #ffffff;
}
QLineEdit:hover, QSpinBox:hover, QComboBox:hover { border-color: #5da9e9; }
QLineEdit:focus, QSpinBox:focus, QComboBox:focus {
    border: 2px solid #5da9e9;
    padding: 7px 11px;
}

QComboBox::drop-down { border: none; width: 24px; }
QComboBox::down-arrow {
    width: 10px; height: 10px;
}
QComboBox QAbstractItemView {
    background-color: #ffffff;
    color: #0f1e3a;
    border: 1px solid #c4cdd9;
    border-radius: 6px;
    selection-background-color: #003f91;
    selection-color: #ffffff;
    padding: 4px;
    outline: none;
}
QSpinBox::up-button, QSpinBox::down-button {
    width: 20px;
    background-color: #e5f4e3;
    border: none;
}
QSpinBox::up-button:hover, QSpinBox::down-button:hover { background-color: #d3ead0; }
QSpinBox::up-button { border-top-right-radius: 6px; }
QSpinBox::down-button { border-bottom-right-radius: 6px; }

/* Buttons */
QPushButton {
    background-color: #ffffff;
    color: #1e3a6b;
    border: 1px solid #c4cdd9;
    border-radius: 6px;
    padding: 8px 18px;
    font-weight: 500;
}
QPushButton:hover {
    background-color: #e5f4e3;
    border-color: #5da9e9;
    color: #003f91;
}
QPushButton:pressed {
    background-color: #d3ead0;
    border-color: #003f91;
}
QPushButton:disabled {
    background-color: #f3faf2;
    color: #b8c2d1;
    border-color: #d6dde6;
}
QPushButton[primary="true"] {
    background-color: #003f91;
    color: #ffffff;
    border: 1px solid #003f91;
    font-weight: 600;
    padding: 9px 22px;
}
QPushButton[primary="true"]:hover {
    background-color: #5da9e9;
    border-color: #5da9e9;
}
QPushButton[primary="true"]:pressed {
    background-color: #002a66;
    border-color: #002a66;
}
QPushButton[primary="true"]:disabled {
    background-color: #b8c8e3;
    color: #ffffff;
    border-color: #b8c8e3;
}

QPushButton[danger="true"] {
    background-color: #ffffff;
    color: #003f91;
    border: 1px solid #003f91;
}
QPushButton[danger="true"]:hover {
    background-color: #003f91;
    color: #ffffff;
}

/* Labels */
QLabel { color: #0f1e3a; }
QLabel[role="title"] {
    color: #003f91;
    font-size: 20px;
    font-weight: 700;
}
QLabel[role="subtitle"] {
    color: #5e6b80;
    font-size: 13px;
}
QLabel[role="hint"] {
    color: #8a96a8;
    font-size: 11px;
}
QLabel[role="card-label"] {
    color: #003f91;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.6px;
}
QLabel[role="status-active"] {
    color: #003f91;
    font-weight: 600;
}
QLabel[role="status-idle"] {
    color: #8a96a8;
    font-weight: 500;
}

/* Dividers */
QFrame[role="divider"] {
    background-color: #d6dde6;
    max-height: 1px;
    border: none;
}

/* Progress bar in status */
QProgressBar {
    background-color: #e5f4e3;
    border: none;
    border-radius: 2px;
    max-height: 3px;
}
QProgressBar::chunk {
    background-color: #003f91;
    border-radius: 2px;
}

/* Scrollbars */
QScrollBar:vertical {
    background-color: transparent;
    width: 10px;
    margin: 2px;
    border: none;
}
QScrollBar::handle:vertical {
    background-color: #c4cdd9;
    border-radius: 4px;
    min-height: 24px;
}
QScrollBar::handle:vertical:hover { background-color: #5da9e9; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0; background: none;
}

QScrollBar:horizontal {
    background-color: transparent;
    height: 10px;
    margin: 2px;
    border: none;
}
QScrollBar::handle:horizontal {
    background-color: #c4cdd9;
    border-radius: 4px;
    min-width: 24px;
}
QScrollBar::handle:horizontal:hover { background-color: #5da9e9; }
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0; background: none;
}

QToolTip {
    background-color: #003f91;
    color: #ffffff;
    border: none;
    border-radius: 4px;
    padding: 5px 9px;
}
"""


def _divider() -> QFrame:
    f = QFrame()
    f.setProperty("role", "divider")
    f.setFrameShape(QFrame.Shape.HLine)
    return f


def _set_role(widget, role):
    widget.setProperty("role", role)
    return widget


class DemoWorker(QObject):
    sortie = Signal(str)
    erreur = Signal(str)
    fini = Signal()

    def __init__(self, chemin: str) -> None:
        super().__init__()
        self.chemin = chemin

    def run(self) -> None:
        try:
            module = importlib.import_module(self.chemin)
            if not hasattr(module, "demo"):
                self.sortie.emit(f"{self.chemin} : pas de fonction demo()")
                return
            buf = io.StringIO()
            with redirect_stdout(buf):
                module.demo()
            self.sortie.emit(buf.getvalue())
        except Exception as e:
            self.erreur.emit(f"{type(e).__name__}: {e}")
        finally:
            self.fini.emit()


class FormPanel(QWidget):
    """Generic input form built from a Spec: title, fields, primary Run, output."""

    def __init__(self, spec: Spec, label: str):
        super().__init__()
        self._spec = spec
        self._widgets: dict = {}

        outer = QVBoxLayout(self)
        outer.setContentsMargins(28, 24, 28, 24)
        outer.setSpacing(12)

        titre = QLabel(label)
        _set_role(titre, "title")
        outer.addWidget(titre)

        sous = QLabel("Renseignez les valeurs ci-dessous puis lancez le calcul.")
        _set_role(sous, "subtitle")
        outer.addWidget(sous)

        outer.addWidget(_divider())

        section = QLabel("Parametres")
        _set_role(section, "card-label")
        outer.addWidget(section)

        form = QFormLayout()
        form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft)
        form.setSpacing(10)
        form.setContentsMargins(0, 4, 0, 4)
        for champ in spec.champs:
            w = self._creer_widget(champ)
            self._widgets[champ.cle] = w
            label_w = QLabel(champ.label)
            if champ.note:
                label_w.setText(f"{champ.label}\n{champ.note}")
            form.addRow(label_w, w)
        outer.addLayout(form)

        ligne = QHBoxLayout()
        ligne.setSpacing(8)
        bouton = QPushButton("Lancer avec ces valeurs")
        bouton.setProperty("primary", True)
        bouton.clicked.connect(self._lancer)
        ligne.addWidget(bouton)
        ligne.addStretch(1)
        outer.addLayout(ligne)

        outer.addSpacing(4)
        section_out = QLabel("Resultat")
        _set_role(section_out, "card-label")
        outer.addWidget(section_out)

        self._sortie = QPlainTextEdit()
        self._sortie.setReadOnly(True)
        self._sortie.setFont(QFont("Menlo", 12))
        self._sortie.setPlaceholderText("Le resultat sera affiche ici.")
        outer.addWidget(self._sortie, 1)

    def _creer_widget(self, champ: Champ) -> QWidget:
        t = champ.type
        if t == TEXT:
            w = QLineEdit()
            w.setText(str(champ.defaut))
            return w
        if t in (MULTILINE, BYTES_UTF8):
            w = QPlainTextEdit()
            w.setPlainText(str(champ.defaut))
            w.setMaximumHeight(110)
            return w
        if t == INT:
            w = QSpinBox()
            w.setRange(int(champ.minimum), int(champ.maximum))
            w.setValue(int(champ.defaut) if champ.defaut != "" else 0)
            return w
        if t == BYTES_HEX:
            w = QLineEdit()
            w.setText(str(champ.defaut))
            w.setFont(QFont("Menlo", 12))
            return w
        if t == CHOICE:
            w = QComboBox()
            w.addItems(list(champ.options))
            if champ.defaut in champ.options:
                w.setCurrentText(str(champ.defaut))
            return w
        raise ValueError(f"Type de champ inconnu : {t}")

    def _lire_valeur(self, champ: Champ):
        w = self._widgets[champ.cle]
        t = champ.type
        if t == TEXT:
            return w.text()
        if t == MULTILINE:
            return w.toPlainText()
        if t == BYTES_UTF8:
            return w.toPlainText().encode("utf-8")
        if t == INT:
            return w.value()
        if t == BYTES_HEX:
            txt = w.text().strip().replace(" ", "")
            if not txt:
                return b""
            return bytes.fromhex(txt)
        if t == CHOICE:
            return w.currentText()
        raise ValueError(f"Type de champ inconnu : {t}")

    def _lancer(self):
        try:
            valeurs = {c.cle: self._lire_valeur(c) for c in self._spec.champs}
        except ValueError as e:
            self._sortie.setPlainText(f"[ERREUR ENTREE] {e}")
            return
        try:
            res = self._spec.runner(valeurs)
        except Exception as e:
            res = f"[ERREUR EXECUTION] {type(e).__name__}: {e}"
        self._sortie.setPlainText(res)


class CryptoFenetre(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Cryptography Implementations")
        self.resize(1320, 840)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setHandleWidth(1)

        # ----- Left sidebar -----
        sidebar = QWidget()
        sidebar.setMinimumWidth(280)
        sidebar.setMaximumWidth(380)
        sidebar_layout = QVBoxLayout(sidebar)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)
        sidebar_layout.setSpacing(0)

        marque = QWidget()
        marque.setObjectName("marque")
        marque_layout = QVBoxLayout(marque)
        marque_layout.setContentsMargins(22, 20, 20, 16)
        marque_layout.setSpacing(2)
        # Scope via #marque so descendants (the labels) don't inherit the border.
        marque.setStyleSheet(
            "#marque {"
            "  background-color: #003f91;"
            "  border-bottom: 1px solid #002a66;"
            "}"
        )
        titre_marque = QLabel("Cryptography")
        titre_marque.setStyleSheet(
            "color: #ffffff; font-size: 17px; font-weight: 700;"
            " background: transparent; border: none;"
        )
        sous_marque = QLabel("IMPLEMENTATIONS")
        sous_marque.setStyleSheet(
            "color: #5da9e9; font-size: 10px; font-weight: 700;"
            " letter-spacing: 1.6px; background: transparent; border: none;"
        )
        marque_layout.addWidget(titre_marque)
        marque_layout.addWidget(sous_marque)
        sidebar_layout.addWidget(marque)

        self.arbre = QTreeWidget()
        self.arbre.setHeaderHidden(True)
        self.arbre.setIndentation(14)
        for theme in THEME_ORDER:
            theme_item = QTreeWidgetItem([THEMES[theme]])
            f = theme_item.font(0)
            f.setBold(True)
            f.setPointSize(11)
            theme_item.setFont(0, f)
            theme_item.setFlags(theme_item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            for (t, _slug), (chemin, label) in MODULES.items():
                if t == theme:
                    feuille = QTreeWidgetItem([label])
                    feuille.setData(0, Qt.ItemDataRole.UserRole, chemin)
                    theme_item.addChild(feuille)
            self.arbre.addTopLevelItem(theme_item)
            theme_item.setExpanded(True)
        self.arbre.itemDoubleClicked.connect(self._sur_double_clic)
        self.arbre.currentItemChanged.connect(self._sur_changement_selection)
        sidebar_layout.addWidget(self.arbre, 1)
        splitter.addWidget(sidebar)

        # ----- Right side: tabs -----
        self.tabs = QTabWidget()
        self.tabs.setDocumentMode(True)
        self.tabs.setTabPosition(QTabWidget.TabPosition.North)

        # Scenario tab
        scenar_widget = QWidget()
        scenar_layout = QVBoxLayout(scenar_widget)
        scenar_layout.setContentsMargins(28, 24, 28, 24)
        scenar_layout.setSpacing(12)

        titre_sc = QLabel("Sortie du scenario")
        _set_role(titre_sc, "title")
        scenar_layout.addWidget(titre_sc)

        sous_sc = QLabel(
            "Lancez le scenario pre-defini d'un module pour voir la sortie complete "
            "(Ctrl+R ou double-clic dans la barre laterale)."
        )
        _set_role(sous_sc, "subtitle")
        sous_sc.setWordWrap(True)
        scenar_layout.addWidget(sous_sc)

        scenar_layout.addWidget(_divider())

        self.sortie = QPlainTextEdit()
        self.sortie.setReadOnly(True)
        self.sortie.setFont(QFont("Menlo", 12))
        self.sortie.setPlaceholderText("Selectionnez un module et lancez le scenario.")
        scenar_layout.addWidget(self.sortie, 1)

        self.tabs.addTab(scenar_widget, "Scenario")

        # Custom-values tab : QStackedWidget
        self.custom_stack = QStackedWidget()
        self._index_par_chemin: dict = {}
        defaut_widget = QWidget()
        dl = QVBoxLayout(defaut_widget)
        dl.setContentsMargins(28, 60, 28, 28)
        dl.setSpacing(8)
        dl_titre = QLabel("Selectionnez un module")
        _set_role(dl_titre, "title")
        dl_titre.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dl.addWidget(dl_titre)
        dl_sous = QLabel(
            "Choisissez un algorithme dans la barre laterale pour le tester avec "
            "vos propres valeurs."
        )
        _set_role(dl_sous, "subtitle")
        dl_sous.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dl_sous.setWordWrap(True)
        dl.addWidget(dl_sous)
        dl.addStretch(1)
        self.custom_stack.addWidget(defaut_widget)
        for _cle, (chemin, label) in MODULES.items():
            panel = self._creer_panel_perso(chemin, label)
            idx = self.custom_stack.addWidget(panel)
            self._index_par_chemin[chemin] = idx
        self.tabs.addTab(self.custom_stack, "Tester avec mes valeurs")

        splitter.addWidget(self.tabs)
        splitter.setSizes([300, 1020])
        splitter.setCollapsible(0, False)
        splitter.setCollapsible(1, False)
        self.setCentralWidget(splitter)

        # ----- Toolbar -----
        toolbar = QToolBar("Actions")
        toolbar.setMovable(False)
        toolbar.setIconSize(toolbar.iconSize())

        self._action_run = QAction("Lancer scenario", self)
        self._action_run.setShortcut("Ctrl+R")
        self._action_run.triggered.connect(self._lancer_selectionne)
        toolbar.addAction(self._action_run)

        toolbar.addSeparator()

        self._action_clear = QAction("Effacer", self)
        self._action_clear.setShortcut("Ctrl+L")
        self._action_clear.triggered.connect(self.sortie.clear)
        toolbar.addAction(self._action_clear)
        self.addToolBar(toolbar)

        # ----- Status bar -----
        self.setStatusBar(QStatusBar())
        self._statut_indicateur = QLabel(" Pret")
        _set_role(self._statut_indicateur, "status-idle")
        self.statusBar().addWidget(self._statut_indicateur)

        self._progress = QProgressBar()
        self._progress.setRange(0, 0)  # indeterminate
        self._progress.setMaximumWidth(180)
        self._progress.hide()
        self.statusBar().addPermanentWidget(self._progress)

        self._statut_module = QLabel("")
        _set_role(self._statut_module, "subtitle")
        self.statusBar().addPermanentWidget(self._statut_module)

        self._thread: QThread | None = None
        self._worker: DemoWorker | None = None
        self._chemin_actif: str | None = None

    # ----- Panel creation -----
    def _creer_panel_perso(self, chemin: str, label: str) -> QWidget:
        if chemin in PANELS_PERSO:
            return self._envelopper_panel(PANELS_PERSO[chemin](), label)
        if chemin in SPECS:
            return FormPanel(SPECS[chemin], label)
        return self._panel_indisponible(label)

    def _envelopper_panel(self, panel: QWidget, label: str) -> QWidget:
        """Ajoute un titre standard au-dessus d'un panel custom."""
        contenant = QWidget()
        layout = QVBoxLayout(contenant)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(12)
        titre = QLabel(label)
        _set_role(titre, "title")
        layout.addWidget(titre)
        sous = QLabel("Mode interactif. Demarrez le serveur, puis envoyez des messages.")
        _set_role(sous, "subtitle")
        layout.addWidget(sous)
        layout.addWidget(_divider())
        layout.addWidget(panel, 1)
        return contenant

    def _panel_indisponible(self, label: str) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(28, 60, 28, 28)
        layout.setSpacing(8)
        titre = QLabel(label)
        _set_role(titre, "title")
        titre.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(titre)
        msg = QLabel(
            "Pas de saisie personnalisee pour ce module.\n"
            "Lancez le scenario pre-defini via la barre d'outils (Ctrl+R)."
        )
        _set_role(msg, "subtitle")
        msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
        msg.setWordWrap(True)
        layout.addWidget(msg)
        layout.addStretch(1)
        return w

    # ----- Tree interactions -----
    def _sur_changement_selection(self, item, _prev):
        if item is None:
            return
        chemin = item.data(0, Qt.ItemDataRole.UserRole)
        if chemin and chemin in self._index_par_chemin:
            self.custom_stack.setCurrentIndex(self._index_par_chemin[chemin])
        else:
            self.custom_stack.setCurrentIndex(0)

    def _sur_double_clic(self, item: QTreeWidgetItem, _col: int) -> None:
        chemin = item.data(0, Qt.ItemDataRole.UserRole)
        if chemin:
            self._lancer(chemin)

    def _lancer_selectionne(self) -> None:
        item = self.arbre.currentItem()
        if item is None:
            return
        chemin = item.data(0, Qt.ItemDataRole.UserRole)
        if chemin:
            self._lancer(chemin)

    # ----- Run state -----
    def _est_occupe(self) -> bool:
        if self._thread is None:
            return False
        try:
            return self._thread.isRunning()
        except RuntimeError:
            self._thread = None
            self._worker = None
            return False

    def _maj_etat(self, en_cours: bool, chemin: str = "") -> None:
        self._action_run.setEnabled(not en_cours)
        if en_cours:
            self._statut_indicateur.setText(" En cours")
            _set_role(self._statut_indicateur, "status-active")
            self._statut_indicateur.style().polish(self._statut_indicateur)
            self._statut_module.setText(f"  {chemin}")
            self._progress.show()
        else:
            self._statut_indicateur.setText(" Pret")
            _set_role(self._statut_indicateur, "status-idle")
            self._statut_indicateur.style().polish(self._statut_indicateur)
            self._statut_module.setText("")
            self._progress.hide()

    def _lancer(self, chemin: str) -> None:
        if self._est_occupe():
            self.statusBar().showMessage("Occupe : attendez la fin du run.", 2500)
            return
        self.tabs.setCurrentIndex(0)
        self.sortie.appendPlainText(f"\n=== {chemin} ===")
        self._chemin_actif = chemin
        self._maj_etat(True, chemin)

        self._worker = DemoWorker(chemin)
        self._thread = QThread()
        worker = self._worker
        thread = self._thread
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.sortie.connect(self.sortie.appendPlainText)
        worker.erreur.connect(
            lambda msg: self.sortie.appendPlainText(f"\n[ERREUR] {msg}")
        )
        worker.fini.connect(thread.quit)
        thread.finished.connect(lambda: self._sur_thread_fini(thread, worker))
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.start()

    def _sur_thread_fini(self, thread, worker) -> None:
        if self._thread is thread:
            self._thread = None
        if self._worker is worker:
            self._worker = None
        self._chemin_actif = None
        self._maj_etat(False)


def main() -> None:
    app = QApplication(sys.argv)
    # Force Fusion: macOS native style ignores parts of QSS (e.g. QTabBar bg)
    # which causes dark strips behind the tabs in dark-mode systems.
    app.setStyle("Fusion")
    app.setStyleSheet(STYLESHEET)
    fenetre = CryptoFenetre()
    fenetre.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
