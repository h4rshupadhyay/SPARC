"""Application-owned window chrome, tested against real Tk widgets."""

from types import SimpleNamespace
import re
import shutil
import subprocess
import time
import tkinter as tk
from tkinter import ttk

import pytest

from sparc.gui.window_chrome import WindowChrome


@pytest.fixture
def window():
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        pytest.skip(f"Tk display unavailable: {exc}")
    root.withdraw()
    root.geometry("800x640+150+150")
    root.minsize(800, 640)
    yield root
    try:
        root.destroy()
    except tk.TclError:
        pass


def pump(window, predicate=lambda: True):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        window.update()
        if predicate():
            return
        time.sleep(.01)
    assert predicate()


def shell(window):
    notebook = ttk.Notebook(window)
    notebook.pack(fill="both", expand=True)
    chrome = WindowChrome(window, notebook=notebook)
    for title in ("Connection", "Chat", "Audit", "Analysis", "Traffic Analysis"):
        notebook.add(ttk.Frame(notebook), text=title)
    window.deiconify()
    pump(window)
    return notebook, chrome


def test_navigation_and_controls_fit_compact_window_without_extra_row(window):
    notebook, chrome = shell(window)
    assert (window.winfo_width(), window.winfo_height()) == (800, 640)
    assert notebook.winfo_y() == 0
    assert chrome.brand.winfo_y() < 10
    assert chrome.controls.winfo_x() > chrome.brand.winfo_x() + chrome.brand.winfo_width()
    # Every tab remains selectable in the space between brand and controls.
    for index in range(5):
        positions = [x for x in range(chrome.brand.winfo_width() + 14,
                                     chrome.controls.winfo_x())
                     if notebook.identify(x, 20) == 'label'
                     and notebook.index(f'@{x},20') == index]
        assert positions, index
        x = positions[len(positions) // 2]
        notebook.event_generate('<ButtonPress-1>', x=x, y=20)
        notebook.event_generate('<ButtonRelease-1>', x=x, y=20)
        pump(window)
        assert notebook.index('current') == index
    assert chrome.controls.winfo_x() + chrome.controls.winfo_width() <= 800


def test_close_uses_current_protocol_and_cleans_up_owned_callbacks(window):
    _, chrome = shell(window)
    calls = []
    window.protocol('WM_DELETE_WINDOW', lambda: calls.append('original'))
    window.protocol('WM_DELETE_WINDOW', lambda: calls.append('replacement'))
    chrome.close_button.invoke()
    assert calls == ['replacement']
    window.destroy()
    assert window.tk.splitlist(window.tk.call('after', 'info')) == ()


def test_drag_moves_window_and_resize_respects_minimum(window):
    _, chrome = shell(window)
    before = window.winfo_x(), window.winfo_y()
    chrome._start_drag(SimpleNamespace(x_root=200, y_root=200))
    chrome._drag(SimpleNamespace(x_root=240, y_root=230))
    pump(window)
    assert (window.winfo_x(), window.winfo_y()) == (before[0] + 40, before[1] + 30)
    window.geometry('1000x800')
    pump(window)
    right = window.winfo_x() + window.winfo_width()
    bottom = window.winfo_y() + window.winfo_height()
    chrome._start_resize(SimpleNamespace(x_root=200, y_root=200), 'nw')
    chrome._resize(SimpleNamespace(x_root=800, y_root=800))
    pump(window)
    assert (window.winfo_width(), window.winfo_height()) == (800, 640)
    assert window.winfo_x() + 800 == right
    assert window.winfo_y() + 640 == bottom


def test_maximize_restore_and_minimize_remain_managed(window):
    window.title(f'SPARC native chrome test {id(window)}')
    _, chrome = shell(window)
    if window.tk.call('tk', 'windowingsystem') != 'x11':
        pytest.skip('native state assertion requires the X11 desktop')
    if not shutil.which('xprop'):
        pytest.skip('xprop required to observe window-manager state')
    def properties(xid, *names):
        return subprocess.run(['xprop', '-id', xid, *names], capture_output=True,
                              text=True, check=True).stdout
    clients = subprocess.run(['xprop', '-root', '_NET_CLIENT_LIST'], capture_output=True,
                             text=True, check=True).stdout
    wrapper = next((xid for xid in re.findall(r'0x[0-9a-f]+', clients)
                    if window.title() in properties(xid, 'WM_NAME')), None)
    if wrapper is None:
        pytest.skip('native state assertion requires a desktop window manager')
    assert '0x2, 0x0, 0x0, 0x0, 0x0' in properties(wrapper, '_MOTIF_WM_HINTS')
    extents = properties(wrapper, '_NET_FRAME_EXTENTS')
    assert '= 0, 0, 0, 0' in extents or 'not found' in extents
    chrome.maximize_button.invoke()
    pump(window, lambda: bool(window.attributes('-zoomed')))
    chrome.maximize_button.invoke()
    pump(window, lambda: not window.attributes('-zoomed'))
    chrome.minimize_button.invoke()
    # On this GNOME/Tk combination wm state remains "normal" even for a plain
    # decorated Tk window. Observe the actual WM state rather than its cache.
    pump(window, lambda: 'Iconic' in properties(wrapper, 'WM_STATE'))
    window.withdraw()
    window.deiconify()
    pump(window, lambda: 'Normal' in properties(wrapper, 'WM_STATE'))
    assert not window.overrideredirect()


def test_dialog_header_exposes_close_without_resize_or_maximize(window):
    dialog = tk.Toplevel(window)
    dialog.resizable(False, False)
    chrome = WindowChrome(dialog)
    ttk.Frame(dialog, width=480, height=200).grid(row=1, column=0)
    calls = []
    dialog.protocol('WM_DELETE_WINDOW', lambda: calls.append('cancel'))
    pump(dialog)
    assert chrome.minimize_button is None
    assert chrome.maximize_button is None
    chrome.close_button.invoke()
    assert calls == ['cancel']
    dialog.destroy()


def test_drag_over_tabs_preserves_navigation_and_window_position(window):
    notebook, chrome = shell(window)
    before = window.geometry()
    chrome._start_drag(SimpleNamespace(widget=notebook, x=120, y=20, x_root=200, y_root=200))
    chrome._drag(SimpleNamespace(x_root=250, y_root=250))
    pump(window)
    assert window.geometry() == before


def test_drag_to_negative_coordinate_uses_absolute_position(window):
    _, chrome = shell(window)
    window.withdraw()
    chrome._start_drag(SimpleNamespace(x_root=200, y_root=200))
    chrome._drag(SimpleNamespace(x_root=20, y_root=200))
    window.update_idletasks()
    assert window.winfo_x() == -30


def test_integrated_chat_expands_after_window_resize(window):
    import queue
    from sparc.gui.app import SparcApp
    from sparc.gui.chat import ChatTab

    service = SimpleNamespace(events=queue.Queue(), close=lambda: None)
    app = SparcApp(window, service)
    tab = ChatTab(app.notebook, service)
    app.add_tab('Chat', tab)
    window.deiconify()
    pump(window)
    window.geometry('1200x1000')
    pump(window, lambda: tab._input.winfo_width() > 1100)
    assert tab._body.winfo_width() > 1100
    assert tab._body.winfo_height() > 500
    app.chrome.close_button.invoke()
    assert app._closed


def test_missing_native_adapter_keeps_frameless_close_and_cleanup(window, monkeypatch):
    monkeypatch.setattr('sparc.gui.window_chrome.hide_decorations', lambda _: False)
    _, chrome = shell(window)
    assert window.overrideredirect()
    calls = []

    def close():
        calls.append('close')
        window.destroy()

    window.protocol('WM_DELETE_WINDOW', close)
    chrome.close_button.invoke()
    assert calls == ['close']
    assert window.tk.splitlist(window.tk.call('after', 'info')) == ()
