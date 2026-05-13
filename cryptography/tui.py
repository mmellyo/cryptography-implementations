"""Terminal UI for the cryptography demos (Textual).

Mirrors the desktop GUI layout:
- Brand block at the top, sidebar tree of modules on the left.
- Right pane with two tabs : 'Tester avec mes valeurs' (default) and 'Scenario'.
- Status bar at the bottom shows current activity ('Pret' / 'En cours...').
"""
import asyncio
import importlib
import io
from contextlib import redirect_stdout

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import (
    Button,
    Footer,
    Input,
    Label,
    RichLog,
    Select,
    Static,
    TabbedContent,
    TabPane,
    TextArea,
    Tree,
)

from gui_specs import (
    BYTES_HEX,
    BYTES_UTF8,
    CHOICE,
    INT,
    MULTILINE,
    SPECS,
    TEXT,
)
from main import MODULES, THEME_ORDER, THEMES


def _executer_demo(chemin: str) -> str:
    module = importlib.import_module(chemin)
    if not hasattr(module, "demo"):
        return f"{chemin} : pas de fonction demo()"
    buf = io.StringIO()
    with redirect_stdout(buf):
        module.demo()
    return buf.getvalue()


def _label_pour(chemin: str) -> str:
    for _cle, (c, label) in MODULES.items():
        if c == chemin:
            return label
    return chemin


class FormulairePerso(VerticalScroll):
    """Form rebuilt for each selected module's Spec."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._spec = None
        self._inputs: dict = {}

    def compose(self) -> ComposeResult:
        yield Static("Selectionnez un module", classes="form-titre center")
        yield Static(
            "Choisissez un algorithme dans la barre laterale pour le tester avec "
            "vos propres valeurs.",
            classes="form-soustitre center",
        )

    async def afficher_module(self, chemin: str, label: str) -> None:
        await self.remove_children()
        self._spec = SPECS.get(chemin)
        self._inputs = {}
        await self.mount(Static(label, classes="form-titre"))
        if self._spec is None:
            await self.mount(
                Static(
                    "Pas de saisie personnalisee pour ce module.\n"
                    "Lancez le scenario pre-defini (Ctrl+R ou Enter).",
                    classes="form-soustitre",
                )
            )
            return
        await self.mount(
            Static(
                "Renseignez les valeurs ci-dessous puis lancez le calcul.",
                classes="form-soustitre",
            )
        )
        await self.mount(Static("", classes="divider"))
        await self.mount(Static("PARAMETRES", classes="section-label"))
        for champ in self._spec.champs:
            label_text = champ.label
            if champ.note:
                label_text = f"{champ.label} - {champ.note}"
            await self.mount(Label(label_text, classes="form-label"))
            widget = self._creer_widget(champ)
            self._inputs[champ.cle] = widget
            await self.mount(widget)
        await self.mount(
            Button(
                "Lancer avec ces valeurs",
                id="lancer-perso",
                variant="primary",
            )
        )
        await self.mount(Static("RESULTAT", classes="section-label"))
        await self.mount(Static("", id="resultat-perso", classes="form-resultat"))

    def _creer_widget(self, champ):
        if champ.type == TEXT:
            return Input(value=str(champ.defaut), placeholder=champ.label)
        if champ.type in (MULTILINE, BYTES_UTF8):
            ta = TextArea(text=str(champ.defaut))
            ta.styles.height = 6
            return ta
        if champ.type == INT:
            return Input(
                value=str(champ.defaut) if champ.defaut != "" else "0",
                type="integer",
            )
        if champ.type == BYTES_HEX:
            return Input(value=str(champ.defaut), placeholder="hex")
        if champ.type == CHOICE:
            options = [(opt, opt) for opt in champ.options]
            valeur = (
                champ.defaut
                if champ.defaut in champ.options
                else (champ.options[0] if champ.options else None)
            )
            return Select(options=options, value=valeur, allow_blank=False)
        return Static(f"<type inconnu: {champ.type}>")

    def _lire_valeurs(self) -> dict:
        out: dict = {}
        for champ in self._spec.champs:
            w = self._inputs[champ.cle]
            if champ.type == TEXT:
                out[champ.cle] = w.value
            elif champ.type == MULTILINE:
                out[champ.cle] = w.text
            elif champ.type == BYTES_UTF8:
                out[champ.cle] = w.text.encode("utf-8")
            elif champ.type == INT:
                try:
                    out[champ.cle] = int(w.value or "0")
                except ValueError:
                    out[champ.cle] = 0
            elif champ.type == BYTES_HEX:
                txt = (w.value or "").strip().replace(" ", "")
                if not txt:
                    out[champ.cle] = b""
                else:
                    try:
                        out[champ.cle] = bytes.fromhex(txt)
                    except ValueError as e:
                        raise ValueError(f"{champ.label}: hex invalide ({e})")
            elif champ.type == CHOICE:
                out[champ.cle] = w.value
        return out

    def lancer(self) -> None:
        if self._spec is None:
            return
        try:
            result = self.query_one("#resultat-perso", Static)
        except Exception:
            return
        try:
            valeurs = self._lire_valeurs()
        except ValueError as e:
            result.update(f"[red][ERREUR ENTREE] {e}[/red]")
            return
        try:
            res = self._spec.runner(valeurs)
        except Exception as e:
            res = f"[red][ERREUR EXECUTION] {type(e).__name__}: {e}[/red]"
        result.update(res)


class CryptoTUI(App):
    # Palette : Honeydew #e5f4e3, Cool Sky #5da9e9, French Blue #003f91
    CSS = """
    Screen {
        layout: vertical;
        background: #ffffff;
        color: #0f1e3a;
    }
    #brand-bar {
        background: #003f91;
        color: #ffffff;
        height: 3;
        padding: 1 2;
    }
    #brand-title {
        color: #ffffff;
        text-style: bold;
        width: 40;
        content-align: left middle;
    }
    #brand-actions {
        color: #ffffff;
        content-align: right middle;
    }
    Footer {
        background: #003f91;
        color: #ffffff;
    }
    Footer > .footer--key {
        background: #5da9e9;
        color: #ffffff;
    }
    #corps { height: 1fr; }
    #panneau-droit { width: 1fr; }
    Tree {
        width: 38;
        border: none;
        background: #ffffff;
        color: #1e3a6b;
        padding: 1 1;
    }
    Tree > .tree--cursor {
        background: #003f91;
        color: #ffffff;
        text-style: bold;
    }
    Tree > .tree--guides {
        color: #c4cdd9;
    }
    Tree > .tree--label {
        color: #1e3a6b;
    }
    Tree:focus > .tree--cursor {
        background: #003f91;
        color: #ffffff;
    }
    #etat {
        background: #ffffff;
        color: #5e6b80;
        padding: 0 2;
        height: 1;
        border-top: solid #d6dde6;
    }
    #etat.actif {
        color: #003f91;
        text-style: bold;
    }
    TabbedContent {
        height: 1fr;
    }
    TabPane {
        padding: 0 0;
    }
    Tabs {
        background: #ffffff;
    }
    RichLog {
        border: round #d6dde6;
        background: #f3faf2;
        color: #0f1e3a;
        padding: 1 2;
    }
    #scenario-wrap {
        padding: 1 3;
    }
    FormulairePerso {
        background: #ffffff;
        padding: 1 3;
    }
    .form-titre {
        color: #003f91;
        text-style: bold;
        padding: 0 0 1 0;
    }
    .form-soustitre {
        color: #5e6b80;
        padding: 0 0 1 0;
    }
    .form-label {
        color: #1e3a6b;
        text-style: bold;
        padding: 1 0 0 0;
    }
    .section-label {
        color: #003f91;
        text-style: bold;
        padding: 1 0 0 0;
    }
    .divider {
        background: #d6dde6;
        height: 1;
        margin: 1 0;
    }
    .center {
        content-align: center middle;
        text-align: center;
    }
    .form-resultat {
        background: #f3faf2;
        color: #0f1e3a;
        border: round #d6dde6;
        padding: 1 2;
        margin-top: 1;
        height: auto;
    }
    Input {
        background: #ffffff;
        color: #0f1e3a;
        border: tall #c4cdd9;
    }
    Input:focus {
        border: tall #5da9e9;
    }
    TextArea {
        background: #ffffff;
        color: #0f1e3a;
        border: tall #c4cdd9;
    }
    TextArea:focus {
        border: tall #5da9e9;
    }
    Select {
        background: #ffffff;
        border: tall #c4cdd9;
    }
    Select:focus > SelectCurrent {
        border: tall #5da9e9;
    }
    Button {
        background: #ffffff;
        color: #1e3a6b;
        border: tall #c4cdd9;
    }
    Button:hover {
        background: #e5f4e3;
        border: tall #5da9e9;
        color: #003f91;
    }
    Button.-primary {
        background: #003f91;
        color: #ffffff;
        border: tall #003f91;
    }
    Button.-primary:hover {
        background: #5da9e9;
        border: tall #5da9e9;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quitter"),
        Binding("ctrl+r", "run_courant", "Lancer scenario"),
        Binding("ctrl+l", "clear_log", "Effacer"),
        Binding("r", "run_courant", "Lancer", show=False),
        Binding("c", "clear_log", "Effacer", show=False),
        Binding("s", "tab_scenario", "Scenario"),
        Binding("i", "tab_perso", "Mes valeurs"),
    ]

    def compose(self) -> ComposeResult:
        with Horizontal(id="brand-bar"):
            yield Static("Cryptography", id="brand-title")
            yield Static(
                "Ctrl+R Lancer scenario   Ctrl+L Effacer", id="brand-actions"
            )
        with Horizontal(id="corps"):
            tree: Tree[str | None] = Tree("Modules", id="modules")
            tree.show_root = False
            for theme in THEME_ORDER:
                noeud = tree.root.add(THEMES[theme], expand=True)
                for (t, _slug), (chemin, label) in MODULES.items():
                    if t == theme:
                        noeud.add_leaf(label, data=chemin)
            yield tree
            with Vertical(id="panneau-droit"):
                with TabbedContent(id="onglets", initial="tab-perso"):
                    with TabPane("Tester avec mes valeurs", id="tab-perso"):
                        yield FormulairePerso(id="formulaire")
                    with TabPane("Scenario", id="tab-scenario"):
                        with Vertical(id="scenario-wrap"):
                            yield Static(
                                "Sortie du scenario",
                                classes="form-titre",
                            )
                            yield Static(
                                "Lancez le scenario pre-defini d'un module pour "
                                "voir la sortie complete (Ctrl+R ou Enter dans "
                                "la barre laterale).",
                                classes="form-soustitre",
                            )
                            yield Static("", classes="divider")
                            yield RichLog(
                                highlight=True,
                                markup=True,
                                wrap=False,
                                max_lines=20000,
                                id="sortie",
                            )
                yield Static(" Pret", id="etat")
        yield Footer()

    def on_mount(self) -> None:
        self.query_one(Tree).focus()

    async def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        if event.node.data:
            chemin = event.node.data
            label = _label_pour(chemin)
            try:
                form = self.query_one(FormulairePerso)
                await form.afficher_module(chemin, label)
            except Exception as e:
                self._set_etat(f" Erreur form: {e}", actif=False)
            self._lancer(chemin)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "lancer-perso":
            self.query_one(FormulairePerso).lancer()

    def action_run_courant(self) -> None:
        tree = self.query_one(Tree)
        if tree.cursor_node and tree.cursor_node.data:
            self._lancer(tree.cursor_node.data)

    def action_clear_log(self) -> None:
        self.query_one("#sortie", RichLog).clear()
        self._set_etat(" Sortie effacee", actif=False)

    def action_tab_scenario(self) -> None:
        self.query_one(TabbedContent).active = "tab-scenario"

    def action_tab_perso(self) -> None:
        self.query_one(TabbedContent).active = "tab-perso"

    def _set_etat(self, texte: str, actif: bool) -> None:
        etat = self.query_one("#etat", Static)
        etat.update(texte)
        if actif:
            etat.add_class("actif")
        else:
            etat.remove_class("actif")

    def _lancer(self, chemin: str) -> None:
        sortie = self.query_one("#sortie", RichLog)
        self.query_one(TabbedContent).active = "tab-scenario"
        self._set_etat(f" En cours : {chemin}", actif=True)
        sortie.write(f"[bold #003f91]=== {chemin} ===[/bold #003f91]")
        self.run_worker(self._executer_async(chemin), exclusive=False, group="demo")

    async def _executer_async(self, chemin: str) -> None:
        sortie = self.query_one("#sortie", RichLog)
        loop = asyncio.get_running_loop()
        try:
            buf = await loop.run_in_executor(None, _executer_demo, chemin)
        except Exception as e:
            sortie.write(f"[red][ERREUR] {type(e).__name__}: {e}[/red]")
            self._set_etat(f" Erreur dans {chemin}", actif=False)
            return
        for line in buf.splitlines() or [""]:
            sortie.write(line)
        sortie.write("")
        self._set_etat(" Pret", actif=False)


def main() -> None:
    CryptoTUI().run()


if __name__ == "__main__":
    main()
