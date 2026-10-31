"""Root-owned dark desktop colors, measured type and progressive disclosure."""

from dataclasses import dataclass
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk


SURFACE = '#171c25'
SOFT = '#11161e'
RAISED = '#242d3a'
FIELD = '#10151d'
TEXT = '#e5eaf2'
MUTED = '#a5b1c2'
BORDER = '#43516a'
ACCENT = '#8cb7ff'
PRIMARY = '#3567bd'
ON_PRIMARY = '#ffffff'
SELECTION = '#294d7d'
ERROR = '#ff9d9d'


def chart_color(color: str) -> str:
    """Adapt drawing colors for the dark screen; exported SVG stays unchanged."""
    return {
        '#202124': TEXT, '#d1d5db': BORDER,
        '#1d4ed8': '#8cb7ff', '#b45309': '#f5bb72',
        '#0f766e': '#6fd3c0', '#a21caf': '#dba0eb',
        '#be123c': '#ff9db2', '#475569': '#b8c7dc',
    }.get(color, color)


@dataclass(frozen=True)
class Appearance:
    body: tkfont.Font
    heading: tkfont.Font
    title: tkfont.Font
    small: tkfont.Font
    mono: tkfont.Font
    navigation: tkfont.Font


def _font(root, source, line_height, *, bold=False, candidates=()):
    available = {name.casefold(): name for name in tkfont.families(root)}
    family = next((available[name.casefold()] for name in candidates if name.casefold() in available),
                  tkfont.nametofont(source, root=root).actual('family'))
    font = tkfont.Font(root, family=family, size=-14, weight='bold' if bold else 'normal')
    # Desktop font settings can scale negative pixel sizes too. Measure once.
    font.configure(size=-max(1, round(14 * line_height / font.metrics('linespace'))))
    while font.metrics('linespace') < line_height:
        font.configure(size=font.cget('size') - 1)
    return font


def install(widget) -> Appearance:
    """Share fonts for the lifetime of this Tk interpreter, including peer windows."""
    root = widget._root()
    if hasattr(root, '_sparc_appearance'):
        return root._sparc_appearance
    sans = ('Inter', 'Fira Sans', 'SF Pro Text', 'Segoe UI', 'Noto Sans')
    mono = ('Fira Mono', 'SF Mono', 'Cascadia Mono', 'Noto Sans Mono')
    appearance = Appearance(
        _font(root, 'TkDefaultFont', 30, candidates=sans),
        _font(root, 'TkDefaultFont', 36, bold=True, candidates=sans),
        _font(root, 'TkDefaultFont', 44, bold=True, candidates=sans),
        _font(root, 'TkDefaultFont', 24, candidates=sans),
        _font(root, 'TkFixedFont', 28, candidates=mono),
        _font(root, 'TkDefaultFont', 27, candidates=sans),
    )
    root._sparc_appearance = appearance
    style = ttk.Style(root)
    if 'clam' in style.theme_names():
        style.theme_use('clam')
    root.configure(background=SOFT)
    style.configure('.', font=appearance.body, foreground=TEXT, background=SURFACE,
                    bordercolor=BORDER, lightcolor=SURFACE, darkcolor=SURFACE)
    style.configure('TFrame', background=SURFACE)
    style.configure('TLabel', background=SURFACE, foreground=TEXT)
    style.configure('Heading.TLabel', font=appearance.heading)
    style.configure('Title.TLabel', font=appearance.title)
    style.configure('Muted.TLabel', font=appearance.small, foreground=MUTED)
    style.configure('Error.TLabel', foreground=ERROR)
    style.configure('TButton', padding=(12, 6), background=RAISED, bordercolor=BORDER,
                    lightcolor=RAISED, darkcolor=RAISED, relief='flat',
                    focusthickness=2, focuscolor=ACCENT)
    style.map('TButton', background=[('disabled', RAISED), ('pressed', SOFT), ('active', '#303e51')],
              foreground=[('disabled', MUTED), ('!disabled', TEXT)], bordercolor=[('focus', ACCENT)])
    style.configure('Primary.TButton', background=PRIMARY, foreground=ON_PRIMARY, bordercolor=PRIMARY)
    style.map('Primary.TButton', background=[('disabled', RAISED), ('active', '#4276d2')],
              foreground=[('disabled', MUTED), ('!disabled', ON_PRIMARY)])
    for kind in ('TEntry', 'TSpinbox', 'TCombobox'):
        style.configure(kind, foreground=TEXT, fieldbackground=FIELD, background=RAISED,
                        insertcolor=TEXT, padding=5, bordercolor=BORDER,
                        lightcolor=BORDER, darkcolor=BORDER, arrowcolor=MUTED, arrowsize=16)
        style.map(kind, fieldbackground=[('disabled', RAISED), ('readonly', FIELD)],
                  background=[('disabled', RAISED), ('readonly', FIELD)],
                  foreground=[('disabled', MUTED), ('!disabled', TEXT)],
                  bordercolor=[('focus', ACCENT)], lightcolor=[('focus', ACCENT)], darkcolor=[('focus', ACCENT)],
                  selectbackground=[('!disabled', SELECTION)], selectforeground=[('!disabled', TEXT)])
    for kind in ('TCheckbutton', 'TRadiobutton'):
        style.configure(kind, background=SURFACE, foreground=TEXT, indicatorbackground=FIELD,
                        indicatorforeground=TEXT, bordercolor=BORDER, padding=(0, 5))
        style.map(kind, background=[('active', SURFACE)], foreground=[('disabled', MUTED)],
                  indicatorbackground=[('selected', PRIMARY), ('!selected', FIELD)])
    for kind in ('Vertical.TScrollbar', 'Horizontal.TScrollbar'):
        style.configure(kind, troughcolor=SOFT, background=BORDER, bordercolor=SOFT,
                        lightcolor=BORDER, darkcolor=BORDER, arrowcolor=TEXT, arrowsize=18)
        style.map(kind, background=[('active', MUTED), ('pressed', ACCENT)])
    style.configure('TProgressbar', troughcolor=FIELD, background=ACCENT, bordercolor=BORDER)
    style.configure('TSeparator', background=BORDER)
    style.configure('TLabelframe', background=SURFACE, bordercolor=BORDER,
                    lightcolor=BORDER, darkcolor=BORDER)
    style.configure('TLabelframe.Label', font=appearance.heading, foreground=TEXT, background=SURFACE)
    style.configure('TNotebook', background=SOFT, borderwidth=0, tabmargins=(12, 4, 12, 0),
                    bordercolor=BORDER, lightcolor=SURFACE, darkcolor=SURFACE)
    style.configure('TNotebook.Tab', font=appearance.navigation, padding=(8, 10), background=SOFT,
                    foreground=MUTED, bordercolor=SOFT, lightcolor=SOFT, darkcolor=SOFT)
    style.map('TNotebook.Tab', background=[('selected', SURFACE)], foreground=[('selected', ACCENT)],
              lightcolor=[('selected', SURFACE), ('!selected', SOFT)],
              padding=[('selected', (8, 10)), ('!selected', (8, 10))])
    style.configure('Chrome.TFrame', background=SOFT)
    style.configure('Chrome.TLabel', background=SOFT, foreground=MUTED, font=appearance.small)
    style.configure('Chrome.TButton', background=SOFT, borderwidth=0, padding=(0, 0),
                    font=appearance.navigation, focuscolor=ACCENT)
    style.map('Chrome.TButton', background=[('active', RAISED), ('!active', SOFT)])
    style.map('Close.Chrome.TButton', background=[('active', '#a83245'), ('!active', SOFT)])
    style.configure('TPanedwindow', background=BORDER)
    style.configure('Treeview', font=appearance.body, rowheight=appearance.body.metrics('linespace') + 8,
                    fieldbackground=SURFACE, background=SURFACE)
    style.configure('Treeview.Heading', font=appearance.body, padding=(8, 6), background=SOFT,
                    bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER)
    style.map('Treeview', background=[('selected', SELECTION)], foreground=[('selected', TEXT)])
    for kind in ('Text', 'Listbox', 'Entry', 'Spinbox', 'Menu', 'TEntry', 'TSpinbox', 'TCombobox'):
        root.option_add(f'*{kind}.font', appearance.body)
    for kind in ('Text', 'Listbox', 'Entry', 'Spinbox', 'Menu'):
        for option, value in (('background', FIELD), ('foreground', TEXT),
                              ('selectBackground', SELECTION), ('selectForeground', TEXT),
                              ('insertBackground', TEXT), ('activeBackground', RAISED),
                              ('activeForeground', TEXT), ('disabledForeground', MUTED)):
            root.option_add(f'*{kind}.{option}', value)
    root.option_add('*Toplevel.background', SOFT)
    return appearance


def text_options(appearance: Appearance, *, technical=False) -> dict:
    return dict(font=appearance.mono if technical else appearance.body, background=FIELD,
                foreground=TEXT, insertbackground=TEXT, selectbackground=SELECTION,
                selectforeground=TEXT, inactiveselectbackground=SELECTION, borderwidth=0, highlightthickness=1,
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
