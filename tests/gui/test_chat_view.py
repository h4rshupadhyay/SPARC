"""C7c chat history and public security-inspector behavior."""

from __future__ import annotations

import base64
import queue
import threading
import time
import tkinter as tk
from tkinter import TclError, ttk

import pytest

from sparc.gui.chat import ChatTab
from sparc.models import DeliveryReceipt, Inspection, ServiceEvent, Timings


def _root_or_skip():
    try:
        root = tk.Tk()
    except TclError as exc:
        pytest.skip(f"Tk display unavailable: {exc}")
    root.withdraw()
    notebook = ttk.Notebook(root)
    notebook.pack()
    return root, notebook


class FakeService:
    def __init__(self):
        self.events = queue.Queue()
        self.calls = []
        self.send_entered = threading.Event()
        self.release_send = threading.Event()
        self.send_returned = threading.Event()
        self.block_send = False
        self.result_id = "f" * 32

    def send_text(self, text):
        self.calls.append(("send_text", text, threading.get_ident()))
        self.send_entered.set()
        if self.block_send:
            assert self.release_send.wait(2), "test did not release the fake send"
        self.send_returned.set()
        return self.result_id


def _make_tab(service=None):
    root, notebook = _root_or_skip()
    service = service or FakeService()
    tab = ChatTab(notebook, service)
    notebook.add(tab.widget, text="Chat")
    root.update()
    return root, tab, service


def _walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from _walk(child)


def _visible(widget):
    values = []
    for child in _walk(widget):
        try:
            label = child.cget("text")
        except tk.TclError:
            label = ""
        if label:
            values.append(str(label))
        if isinstance(child, tk.Text):
            values.append(child.get("1.0", tk.END))
        elif isinstance(child, tk.Listbox):
            values.extend(str(child.get(index)) for index in range(child.size()))
        elif isinstance(child, ttk.Treeview):
            for item in child.get_children(""):
                values.extend(str(value) for value in child.item(item, "values"))
        elif isinstance(child, ttk.Entry):
            values.append(child.get())
    return "\n".join(values)


def _send_button(tab):
    return next(
        child for child in _walk(tab.widget)
        if isinstance(child, ttk.Button) and str(child.cget("text")).strip().lower() == "send"
    )


def _input_text(tab):
    candidates = [child for child in _walk(tab.widget) if isinstance(child, tk.Text)]
    assert candidates, "chat input must be multiline"
    return candidates[-1]


def _pump(root, predicate, timeout=1.5):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        root.update()
        time.sleep(0.005)
    root.update()


def _inspection(message_id="1" * 32):
    return Inspection(
        message_id=message_id,
        sequence=7,
        sha256="a" * 64,
        computed_sha256="a" * 64,
        signature=b"\x11" * 64,
        ciphertext=b"\x01\x02\x03",
        nonce=b"\x04" * 12,
        tag=b"\x05" * 16,
        plaintext_bytes=7,
        timings=Timings(hash_ns=1500, sign_ns=2500, encrypt_ns=3500,
                        decrypt_ns=4500, verify_ns=5500),
    )


def _message(message_id, text, inspection=None, direction=0, origin="incoming"):
    return ServiceEvent("message", {
        "message_id": message_id,
        "text": text,
        "inspection": inspection,
        "direction": direction,
        "sequence": 7,
        "origin": origin,
    })


def test_send_disabled_until_connected():
    root, tab, _service = _make_tab()
    button = _send_button(tab)
    assert "disabled" in button.state()
    tab.handle_event(ServiceEvent("state", {"state": "awaiting approval", "reason": "pairing_required"}))
    assert "disabled" in button.state()
    tab.handle_event(ServiceEvent("state", {"state": "connected", "reason": "session_established"}))
    assert "disabled" not in button.state()
    tab.close()
    root.destroy()


def test_unicode_and_line_breaks_preserved_and_send_runs_off_tk_thread():
    service = FakeService()
    service.block_send = True
    root, tab, _ = _make_tab(service)
    tab.handle_event(ServiceEvent("state", {"state": "connected", "reason": "session_established"}))
    input_box = _input_text(tab)
    expected = "नमस्ते, café 🌱\nsecond line\n"
    input_box.insert("1.0", expected)
    _send_button(tab).invoke()
    assert service.send_entered.wait(1)

    # The user can edit the widget while the worker remains in the service call.
    input_box.delete("1.0", tk.END)
    input_box.insert("1.0", "later edit")
    service.release_send.set()
    assert service.send_returned.wait(1)
    _pump(root, lambda: "pending" in _visible(tab.widget).lower())
    assert service.calls[0][1] == expected
    assert service.calls[0][2] != threading.get_ident()
    assert "नमस्ते, café 🌱\nsecond line" in _visible(tab.widget)
    tab.close()
    root.destroy()


def test_history_evicts_after_500_with_notice():
    root, tab, _service = _make_tab()
    tab.handle_event(ServiceEvent("state", {"state": "connected", "reason": "session_established"}))
    for index in range(501):
        tab.handle_event(_message(f"{index:032x}", f"history-entry-{index:03d}"))
    visible = _visible(tab.widget)
    assert "history-entry-000" not in visible
    assert "history-entry-001" in visible
    assert "history-entry-500" in visible
    assert any(word in visible.lower() for word in ("older messages removed", "oldest messages removed", "history limit"))

    # Count the visible history collection rather than details for the selected row.
    counts = []
    for child in _walk(tab.widget):
        if isinstance(child, tk.Listbox):
            counts.append(child.size())
        elif isinstance(child, ttk.Treeview):
            counts.append(len(child.get_children("")))
        elif isinstance(child, tk.Text):
            lines = child.get("1.0", tk.END).splitlines()
            count = sum("history-entry-" in line for line in lines)
            if count:
                counts.append(count)
    assert 500 in counts
    tab.close()
    root.destroy()


def test_inspector_shows_hash_match_signature_ciphertext_and_microseconds():
    root, tab, _service = _make_tab()
    text = "verified 🌱"
    tab.handle_event(ServiceEvent("message", {
        "message_id": "1" * 32,
        "text": text,
        "inspection": _inspection(),
        "direction": 1,
        "sequence": 7,
    }))
    visible = _visible(tab.widget)
    assert text in visible
    assert "a" * 64 in visible
    assert "Sender SHA-256" in visible
    assert "Receiver SHA-256" in visible
    assert base64.b64encode(b"\x01\x02\x03").decode("ascii") in visible
    assert base64.b64encode(b"\x11" * 64).decode("ascii") in visible
    assert base64.b64encode(b"\x04" * 12).decode("ascii") in visible
    assert base64.b64encode(b"\x05" * 16).decode("ascii") in visible
    assert "match" in visible.lower()
    assert "7" in visible
    assert "µs" in visible.lower() or "us" in visible.lower()
    assert "private key" not in visible.lower()
    assert "session key" not in visible.lower()
    assert "private_key" not in visible.lower()
    assert "session_key" not in visible.lower()
    tab.close()
    root.destroy()


def test_pending_verified_unconfirmed_and_event_before_send_result():
    service = FakeService()
    service.block_send = True
    service.result_id = "2" * 32
    root, tab, _ = _make_tab(service)
    tab.handle_event(ServiceEvent("state", {"state": "connected", "reason": "session_established"}))
    original = "message whose writer callback wins the race"
    input_box = _input_text(tab)
    input_box.insert("1.0", original)
    _send_button(tab).invoke()
    assert service.send_entered.wait(1)

    # An incoming message can share text and even an ID with an active local
    # send. Origin, not text matching or wire direction, keeps it separate.
    tab.handle_event(_message(service.result_id, original, direction=0, origin="incoming"))
    tab.handle_event(_message(
        service.result_id, original, _inspection(service.result_id),
        direction=0, origin="outgoing",
    ))
    assert "pending" in _visible(tab.widget).lower()
    assert original in _visible(tab.widget)
    assert "incoming" in _visible(tab.widget).lower()
    service.release_send.set()
    assert service.send_returned.wait(1)
    # Wait for Tk to consume the worker result before attempting another send.
    _pump(root, lambda: "disabled" not in _send_button(tab).state())
    assert "disabled" not in _send_button(tab).state()
    _pump(root, lambda: "outgoing" in _visible(tab.widget).lower())
    _pump(root, lambda: "pending" in _visible(tab.widget).lower())
    receipt = DeliveryReceipt(service.result_id, 10, 20, len(original.encode()), len(original), 100)
    tab.handle_event(ServiceEvent("delivery", {"message_id": service.result_id, "receipt": receipt}))
    assert "verified" in _visible(tab.widget).lower()

    pending_id = "3" * 32
    second_text = "will remain unconfirmed"
    service.result_id = pending_id
    service.send_entered.clear()
    service.send_returned.clear()
    input_box.delete("1.0", tk.END)
    input_box.insert("1.0", second_text)
    _send_button(tab).invoke()
    assert service.send_entered.wait(1)
    tab.handle_event(_message(
        pending_id, second_text, _inspection(pending_id), direction=1, origin="outgoing"
    ))
    assert service.send_returned.wait(1)
    _pump(root, lambda: "outgoing" in _visible(tab.widget).lower()
          and second_text in _visible(tab.widget))
    tab.handle_event(ServiceEvent("state", {"state": "error", "reason": "tcp_loss"}))
    visible = _visible(tab.widget).lower()
    assert "unconfirmed" in visible
    assert "outgoing" in visible
    history_rows = next(
        child for child in _walk(tab.widget) if isinstance(child, tk.Listbox)
    )
    assert sum(original.lower() in history_rows.get(index).lower()
               for index in range(history_rows.size())) == 2
    tab.close()
    root.destroy()


def test_early_deliveries_are_bounded_and_cleared_on_reconciliation_and_disconnect():
    root, tab, _service = _make_tab()
    tab._active_send = {
        "origin": "outgoing", "message_id": None, "key": None,
        "text": "active", "inspection": None, "direction": None,
        "sequence": None, "status": "pending",
    }
    for index in range(150):
        tab.handle_event(ServiceEvent("delivery", {"message_id": f"{index:032x}"}))
    assert len(tab._early_deliveries) <= 100

    returned_id = "e" * 32
    stale_id = "d" * 32
    tab.handle_event(ServiceEvent("delivery", {"message_id": stale_id}))
    tab.handle_event(ServiceEvent("delivery", {"message_id": returned_id}))
    tab._job_result("result", ("active", returned_id))
    assert len(tab._early_deliveries) == 0

    # A stale receipt for a different ID must not verify a later send.
    tab._active_send = {
        "origin": "outgoing", "message_id": None, "key": None,
        "text": "later send", "inspection": None, "direction": None,
        "sequence": None, "status": "pending",
    }
    tab._job_result("result", ("later send", stale_id))
    assert tab._by_key[("outgoing", stale_id)]["status"] == "pending"

    tab._active_send = {
        "origin": "outgoing", "message_id": None, "key": None,
        "text": "active again", "inspection": None, "direction": None,
        "sequence": None, "status": "pending",
    }
    tab.handle_event(ServiceEvent("delivery", {"message_id": "d" * 32}))
    tab.handle_event(ServiceEvent("state", {"state": "disconnected"}))
    assert len(tab._early_deliveries) == 0

    tab._active_send = {
        "origin": "outgoing", "message_id": None, "key": None,
        "text": "failing send", "inspection": None, "direction": None,
        "sequence": None, "status": "pending",
    }
    tab.handle_event(ServiceEvent("delivery", {"message_id": "c" * 32}))
    tab._job_result("error", RuntimeError("send failed"))
    assert len(tab._early_deliveries) == 0
    tab.close()
    root.destroy()


def test_delivery_before_send_result_verifies_matching_message():
    root, tab, _service = _make_tab()
    message_id = "f" * 32
    tab._active_send = {
        "origin": "outgoing", "message_id": None, "key": None,
        "text": "active", "inspection": None, "direction": None,
        "sequence": None, "status": "pending",
    }
    tab.handle_event(ServiceEvent("delivery", {"message_id": message_id}))
    tab._job_result("result", ("active", message_id))
    assert tab._by_key[("outgoing", message_id)]["status"] == "verified"
    assert tab._early_deliveries == set()
    tab.close()
    root.destroy()


def test_chat_close_releases_in_memory_plaintext_and_pending_delivery_state():
    root, tab, _service = _make_tab()
    secret_text = "ephemeral chat text 🌱"
    tab.handle_event(_message("a" * 32, secret_text))
    tab._early_deliveries.add("b" * 32)
    assert secret_text in _visible(tab.widget)

    tab.close()

    assert tab._entries == []
    assert tab._by_key == {}
    assert tab._early_deliveries == set()
    assert secret_text not in _visible(tab.widget)
    root.destroy()


def test_history_identity_includes_origin_and_message_id():
    root, tab, _service = _make_tab()
    message_id = "4" * 32
    text = "same text and message id"
    tab.handle_event(_message(message_id, text, origin="incoming"))
    tab.handle_event(_message(message_id, text, origin="outgoing"))
    visible = _visible(tab.widget).lower()
    assert visible.count(text) >= 2
    assert "incoming" in visible
    assert "outgoing" in visible
    for index in range(500):
        tab.handle_event(_message(f"{index + 100:032x}", f"replacement-{index}"))
    visible = _visible(tab.widget).lower()
    assert text not in visible
    assert "replacement-499" in visible
    counts = []
    for child in _walk(tab.widget):
        if isinstance(child, tk.Listbox):
            counts.append(child.size())
        elif isinstance(child, ttk.Treeview):
            counts.append(len(child.get_children("")))
        elif isinstance(child, tk.Text):
            count = sum("replacement-" in line for line in child.get("1.0", tk.END).splitlines())
            if count:
                counts.append(count)
    assert 500 in counts
    tab.close()
    root.destroy()


def test_chat_inspector_scrollbar_reaches_security_details():
    root, tab, _service = _make_tab()
    tab.widget.master.pack_configure(fill="both", expand=True)
    root.geometry("800x600")
    root.deiconify()
    root.update()
    detail = Inspection(
        message_id="6" * 32,
        sequence=7,
        sha256="a" * 64,
        computed_sha256="a" * 64,
        signature=b"\x11" * 64,
        ciphertext=b"c" * 2048,
        nonce=b"\x04" * 12,
        tag=b"\x05" * 16,
        plaintext_bytes=7,
        timings=Timings(hash_ns=1500, sign_ns=2500, encrypt_ns=3500,
                        decrypt_ns=4500, verify_ns=5500),
    )
    tab.handle_event(ServiceEvent("message", {
        "message_id": detail.message_id,
        "text": "security details",
        "inspection": detail,
        "direction": 1,
        "sequence": None,
        "origin": "incoming",
    }))
    root.update()
    inspector = tab._inspector
    scrollbars = [child for child in _walk(tab.widget)
                  if isinstance(child, (ttk.Scrollbar, tk.Scrollbar))
                  and str(child.cget("orient")).lower() == "vertical"
                  and child.master is inspector.master
                  and "yview" in str(child.cget("command"))]
    assert scrollbars and any(scrollbar.winfo_ismapped() for scrollbar in scrollbars)

    inspector.yview_moveto(0.0)
    top = inspector.yview()
    inspector.yview_moveto(1.0)
    root.update()
    bottom = inspector.yview()
    assert bottom[1] >= 0.99
    assert bottom[0] > top[0]
    last_visible = inspector.index(f"@0,{max(0, inspector.winfo_height() - 3)}")
    viewport = inspector.get(inspector.index("@0,0"), last_visible)
    assert "verify" in viewport.lower()
    assert "µs" in viewport.lower() or "us" in viewport.lower()
    tab.close()
    root.destroy()


def test_outgoing_inspector_uses_public_inspection_sequence():
    root, tab, _service = _make_tab()
    message_id = "7" * 32
    tab.handle_event(ServiceEvent("message", {
        "message_id": message_id,
        "text": "outgoing with inspected sequence",
        "inspection": _inspection(message_id),
        "direction": 1,
        "origin": "outgoing",
    }))
    visible = _visible(tab.widget)
    assert "Sequence: 7" in visible
    assert "Sequence: None" not in visible
    tab.close()
    root.destroy()


def test_delivery_before_send_result_is_not_downgraded_by_late_result():
    service = FakeService()
    service.block_send = True
    service.result_id = "5" * 32
    root, tab, _ = _make_tab(service)
    tab.handle_event(ServiceEvent("state", {"state": "connected", "reason": "session_established"}))
    text = "receipt arrives before local send returns"
    _input_text(tab).insert("1.0", text)
    _send_button(tab).invoke()
    assert service.send_entered.wait(1)
    tab.handle_event(_message(
        service.result_id, text, _inspection(service.result_id),
        direction=1, origin="outgoing",
    ))
    receipt = DeliveryReceipt(service.result_id, 10, 20, len(text.encode()), len(text), 100)
    tab.handle_event(ServiceEvent("delivery", {
        "message_id": service.result_id, "receipt": receipt,
    }))
    assert "verified" in _visible(tab.widget).lower()

    service.release_send.set()
    assert service.send_returned.wait(1)
    deadline = time.monotonic() + 0.25
    while time.monotonic() < deadline:
        root.update()
        time.sleep(0.005)
    assert "verified" in _visible(tab.widget).lower()
    assert "pending" not in _visible(tab.widget).lower()
    tab.close()
    root.destroy()


def test_benchmark_progress_does_not_create_chat_entry():
    root, tab, _service = _make_tab()
    tab.handle_event(ServiceEvent("benchmark_progress", {
        "run_id": "9" * 32, "records": 1, "bytes": 64, "message_id": "8" * 32,
    }))
    visible = _visible(tab.widget)
    assert "9" * 32 not in visible
    assert "benchmark" not in visible.lower()
    tab.close()
    root.destroy()
