"""Connection and audit status lead their native views."""
import tkinter as tk
from tkinter import ttk
import pytest


@pytest.mark.gui
def test_connection_leads_with_peer_controls_before_interface_inventory():
    from test_connection_view import _make_tab as make_connection
    root, tab = make_connection()
    try:
        root.deiconify(); root.geometry('800x640')
        tab.widget.master.pack_configure(fill='both', expand=True)
        root.update()
        connect = next(w for w in tab._content.winfo_children() if isinstance(w, ttk.LabelFrame) and w.cget('text') == 'Peer')
        assert connect.winfo_rooty() < tab._ip_rows.winfo_rooty()
    finally:
        tab.close(); root.destroy()


@pytest.mark.gui
def test_audit_head_disclosure_does_not_claim_a_verified_chain():
    from test_audit_view import _make_tab as make_audit, _pump, _button
    root, tab, _ = make_audit()
    try:
        root.deiconify(); root.geometry('800x640')
        tab.widget.master.pack_configure(fill='both', expand=True)
        _pump(root, lambda: tab._head is not None)
        assert tab._verification_text.get() == 'Not verified'
        assert not tab._head_label.winfo_ismapped()
        assert 'Verify' in tab._details.get('1.0', 'end')
        tab._raw_details.toggle.invoke(); root.update()
        assert tab._head_label.winfo_ismapped()
        assert 'b'*64 in tab._head_text.get()
        _button(tab, 'verify available chain').invoke()
        _pump(root, lambda: 'Verified' in tab._verification_text.get())
        before = tab._verification_text.get()
        _button(tab, 'refresh head').invoke()
        _pump(root, lambda: not tab._busy)
        assert tab._verification_text.get() == before
    finally:
        tab.close(); root.destroy()
