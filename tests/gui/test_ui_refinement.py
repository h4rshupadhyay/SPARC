"""Native navigation and disclosure preserve SPARC's message/security evidence."""
import tkinter as tk
from tkinter import ttk

import pytest

from test_chat_view import _make_tab, _message, _inspection


@pytest.mark.gui
def test_chat_arrives_with_guidance_and_inspector_is_optional():
    root, tab, _ = _make_tab()
    try:
        root.deiconify(); root.geometry('800x640')
        tab.widget.master.pack_configure(fill='both', expand=True)
        root.update()
        assert 'No messages yet' in tab._history.get('1.0', 'end')
        assert not tab._inspector.winfo_ismapped()
        assert tab._input.winfo_ismapped()
        assert tab._images._attach_button.master is tab._send_button.master
        assert tab._images._attach_button.grid_info()['row'] == tab._send_button.grid_info()['row']
    finally:
        tab.close(); root.destroy()


@pytest.mark.gui
def test_selecting_message_reveals_security_without_changing_draft_or_receipt():
    root, tab, _ = _make_tab()
    try:
        root.deiconify(); root.geometry('1000x760')
        tab.widget.master.pack_configure(fill='both', expand=True)
        draft = 'Draft नमस्ते\nsecond line'
        tab._input.insert('1.0', draft)
        tab.handle_event(_message('1'*32, 'Received plaintext', _inspection()))
        root.update()
        assert not tab._inspector.winfo_ismapped()
        tab._history.select(0); root.update()
        assert tab._inspector.winfo_ismapped()
        evidence = tab._inspector.get('1.0', 'end')
        assert 'Received plaintext' in evidence and 'Ciphertext (base64)' in evidence
        assert 'Signature verification: 5.5 µs' in evidence
        tab._inspect_button.invoke(); root.update()
        assert not tab._inspector.winfo_ismapped()
        assert tab._input.get('1.0', 'end-1c') == draft
        assert tab._entries[0]['status'] == 'verified'
    finally:
        tab.close(); root.destroy()


@pytest.mark.gui
def test_appearance_fonts_survive_another_peer_window_closing():
    from sparc.gui.appearance import install
    root = tk.Tk(); root.withdraw()
    try:
        first = install(root)
        peer = tk.Toplevel(root)
        second = install(peer)
        assert first is second
        label = ttk.Label(root, text='Connection and verification status')
        before = first.body.measure(label.cget('text'))
        peer.destroy(); root.update()
        assert first.body.measure(label.cget('text')) == before
        assert first.body.name in root.tk.call('font', 'names')
    finally:
        root.destroy()

