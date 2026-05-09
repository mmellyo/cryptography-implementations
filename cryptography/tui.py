"""Terminal UI for the cryptography demos (Textual).

Two tabs per module:
- 'Scenario' : runs the module's hard-coded demo() and streams stdout.
- 'Tester avec mes valeurs' : interactive form built from gui_specs.SPECS,
  same runners as the GUI so behaviour is identical.
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
    Header,
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
        yield Static(
            "Selectionnez un module dans la barre laterale.",
            id="form-vide",
            classes="form-soustitre",
        )

    async def afficher_module(self, chemin: str, label: str) -> None:
        await self.remove_children()
        self._spec = SPECS.get(chemin)
        self._inputs = {}
        if self._spec is None:
            await self.mount(
                Static(label, classes="form-titre"),
                Static(
                    "Pas de saisie personnalisee pour ce module.\n"
                    "Appuyez sur 'r' pour lancer le scenario pre-defini.",
                    classes="form-soustitre",
                ),
            )
            return
        await self.mount(Static(label, classes="form-titre"))
        await self.mount(
            Static(
                "Renseignez les valeurs ci-dessous puis appuyez sur 'Lancer'.",
                classes="form-soustitre",
            )
        )
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
    Header {
        background: #003f91;
        color: #ffffff;
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
        width: 40;
        border: round #003f91;
        background: #ffffff;
        color: #003f91;
        padding: 0 1;
    }
    Tree > .tree--cursor {
        background: #003f91;
        color: #ffffff;
        text-style: bold;
    }
    Tree > .tree--guides {
        color: #5da9e9;
    }
    Tree > .tree--label {
        color: #003f91;
    }
    Tree:focus > .tree--cursor {
        background: #003f91;
        color: #ffffff;
    }
    #etat {
        background: #003f91;
        color: #ffffff;
        padding: 0 1;
        height: 1;
        text-style: bold;
    }
    TabbedContent {
        height: 1fr;
    }
    TabPane {
        padding: 0 1;
    }
    Tabs {
        background: #ffffff;
    }
    RichLog {
        border: round #5da9e9;
        background: #ffffff;
        color: #0f1e3a;
        padding: 0 1;
    }
    FormulairePerso {
        background: #ffffff;
        padding: 1 2;
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
        color: #003f91;
        text-style: bold;
        padding: 1 0 0 0;
    }
    .form-resultat {
        background: #f3faf2;
        color: #0f1e3a;
        border: round #5da9e9;
        padding: 1;
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
        color: #003f91;
        border: tall #c4cdd9;
    }
    Button:hover {
        background: #e5f4e3;
        border: tall #5da9e9;
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
        Binding("r", "run_courant", "Lancer"),
        Binding("c", "clear_log", "Effacer"),
        Binding("s", "tab_scenario", "Scenario"),
        Binding("i", "tab_perso", "Mes valeurs"),
    ]

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
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
                yield Static(
                    "Selectionne un module + Enter (ou r) pour le scenario, "
                    "i pour 'Mes valeurs'.",
                    id="etat",
                )
                with TabbedContent(id="onglets", initial="tab-scenario"):
                    with TabPane("Scenario", id="tab-scenario"):
                        yield RichLog(
                            highlight=True,
                            markup=True,
                            wrap=False,
                            max_lines=20000,
                            id="sortie",
                        )
                    with TabPane("Tester avec mes valeurs", id="tab-perso"):
                        yield FormulairePerso(id="formulaire")
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
                self.query_one("#etat", Static).update(f"Erreur form: {e}")
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
        self.query_one("#etat", Static).update("Sortie effacee.")

    def action_tab_scenario(self) -> None:
        self.query_one(TabbedContent).active = "tab-scenario"

    def action_tab_perso(self) -> None:
        self.query_one(TabbedContent).active = "tab-perso"

    def _lancer(self, chemin: str) -> None:
        sortie = self.query_one("#sortie", RichLog)
        etat = self.query_one("#etat", Static)
        etat.update(f"Execution : {chemin}")
        sortie.write(f"[bold #003f91]>>> {chemin}[/bold #003f91]")
        self.run_worker(self._executer_async(chemin), exclusive=False, group="demo")

    async def _executer_async(self, chemin: str) -> None:
        sortie = self.query_one("#sortie", RichLog)
        etat = self.query_one("#etat", Static)
        loop = asyncio.get_running_loop()
        try:
            buf = await loop.run_in_executor(None, _executer_demo, chemin)
        except Exception as e:
            sortie.write(f"[red]Erreur : {type(e).__name__}: {e}[/red]")
            etat.update(f"Erreur dans {chemin}")
            return
        for line in buf.splitlines() or [""]:
            sortie.write(line)
        sortie.write("")
        etat.update(f"Termine : {chemin}")


def main() -> None:
    CryptoTUI().run()


if __name__ == "__main__":
    main()
