"""Root-owned native fonts, restrained surfaces, and progressive disclosure."""

from dataclasses import dataclass
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk


SURFACE = '#ffffff'
SOFT = '#f3f6fa'
TEXT = '#192638'
MUTED = '#506078'
BORDER = '#cbd5e1'
ACCENT = '#2455a5'


@dataclass(frozen=True)
class Appearance:
    body: tkfont.Font
    heading: tkfont.Font
    title: tkfont.Font
    small: tkfont.Font
    mono: tkfont.Font


def _font(root, source, line_height, *, bold=False):
    family = tkfont.nametofont(source, root=root).actual('family')
    font = tkfont.Font(root, family=family, size=-14, weight='bold' if bold else 'normal')
    # Desktop font settings can scale negative pixel sizes too. Measure once.
    font.configure(size=-max(1, round(14 * line_height / font.metrics('linespace'))))
    return font


def install(widget) -> Appearance:
    """Share fonts for the lifetime of this Tk interpreter, including peer windows."""
    root = widget._root()
    if hasattr(root, '_sparc_appearance'):
        return root._sparc_appearance
    appearance = Appearance(
        _font(root, 'TkDefaultFont', 22), _font(root, 'TkDefaultFont', 26, bold=True),
        _font(root, 'TkDefaultFont', 32, bold=True), _font(root, 'TkDefaultFont', 19),
        _font(root, 'TkFixedFont', 21),
    )
    root._sparc_appearance = appearance
    style = ttk.Style(root)
    if 'clam' in style.theme_names():
        style.theme_use('clam')
    style.configure('.', font=appearance.body, foreground=TEXT, background=SURFACE)
    style.configure('TFrame', background=SURFACE)
    style.configure('TLabel', background=SURFACE, foreground=TEXT)
    style.configure('Heading.TLabel', font=appearance.heading)
    style.configure('Title.TLabel', font=appearance.title)
    style.configure('Muted.TLabel', font=appearance.small, foreground=MUTED)
    style.configure('Error.TLabel', foreground='#a12626')
    style.configure('TButton', padding=(12, 7), background=SURFACE, bordercolor=BORDER,
                    focusthickness=2, focuscolor=ACCENT)
    style.map('TButton', background=[('active', SOFT)], foreground=[('disabled', MUTED)])
    style.configure('Primary.TButton', background=ACCENT, foreground=SURFACE, bordercolor=ACCENT)
    style.map('Primary.TButton', background=[('disabled', SOFT), ('active', '#193e7b')],
              foreground=[('disabled', MUTED), ('!disabled', SURFACE)])
    style.configure('TEntry', fieldbackground=SURFACE, padding=6, bordercolor=BORDER)
    style.configure('TCombobox', padding=5, bordercolor=BORDER, arrowsize=16)
    style.map('TCombobox', fieldbackground=[('readonly', SURFACE)])
    style.configure('TLabelframe', background=SURFACE, bordercolor=BORDER)
    style.configure('TLabelframe.Label', font=appearance.heading, foreground=TEXT, background=SURFACE)
    style.configure('TNotebook', background=SOFT, borderwidth=0, tabmargins=(12, 4, 12, 0))
    style.configure('TNotebook.Tab', padding=(14, 9), background=SOFT, foreground=MUTED)
    style.map('TNotebook.Tab', background=[('selected', SURFACE)], foreground=[('selected', ACCENT)])
    style.configure('TPanedwindow', background=BORDER)
    style.configure('Treeview', font=appearance.body, rowheight=appearance.body.metrics('linespace') + 10,
                    fieldbackground=SURFACE, background=SURFACE)
    style.configure('Treeview.Heading', font=appearance.body, padding=(8, 6), background=SOFT)
    style.map('Treeview', background=[('selected', ACCENT)], foreground=[('selected', SURFACE)])
    for kind in ('Text', 'Listbox', 'Entry', 'Spinbox', 'Menu'):
        root.option_add(f'*{kind}.font', appearance.body)
    return appearance


def text_options(appearance: Appearance, *, technical=False) -> dict:
    return dict(font=appearance.mono if technical else appearance.body, background=SURFACE,
                foreground=TEXT, insertbackground=TEXT, selectbackground=ACCENT,
                selectforeground=SURFACE, borderwidth=0, highlightthickness=1,
                highlightbackground=BORDER, highlightcolor=ACCENT, padx=12, pady=10)


class Disclosure(ttk.Frame):
    """A keyboard-operable labelled detail region, closed until requested."""

    def __init__(self, parent, text):
        super().__init__(parent)
        self.columnconfigure(0, weight=1)
        self.expanded = tk.BooleanVar(master=self, value=False)
        self.toggle = ttk.Checkbutton(self, text=text, variable=self.expanded, command=self.refresh)
        self.toggle.grid(row=0, column=0, sticky='w')
        self.body = ttk.Frame(self, padding=(0, 10, 0, 0))
        self.body.columnconfigure(0, weight=1)

    def refresh(self):
        if self.expanded.get():
            self.body.grid(row=1, column=0, sticky='ew')
        else:
            self.body.grid_remove()
