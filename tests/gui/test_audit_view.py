"""C7d audit view tests using real Tk widgets and public service wrappers."""

from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import TclError, ttk

import pytest

from sparc.audit_format import AuditReport
from sparc.gui.audit_view import AuditTab
from sparc.models import ServiceEvent, SparcError


def _root_or_skip():
    try:
        root = tk.Tk()
    except TclError as exc:
        pytest.skip(f"Tk display unavailable: {exc}")
    root.withdraw()
    notebook = ttk.Notebook(root)
    notebook.pack()
    return root, notebook


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
        elif isinstance(child, ttk.Entry):
            values.append(child.get())
    return "\n".join(values)


def _pump(root, predicate, timeout=1.5):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        root.update()
        time.sleep(0.005)
    root.update()


def _button(tab, *terms):
    return next(
        child for child in _walk(tab.widget)
        if isinstance(child, ttk.Button)
        and all(term in str(child.cget("text")).lower() for term in terms)
    )


def _report(*, valid=True, elapsed_ns=1_000_000_000):
    return AuditReport(
        valid=valid,
        verified_records=25,
        first_failed_record=None if valid else 3,
        reason=("available chain only; deletion of the log tail cannot be disproved"
                if valid else "audit_signature_failed: record signature is invalid"),
        checkpoint_checked=False,
        elapsed_ns=elapsed_ns,
    )


@pytest.mark.gui
def test_long_audit_report_has_a_visible_working_scrollbar():
    root, notebook = _root_or_skip()
    tab = AuditTab(notebook, FakeService())
    notebook.add(tab.widget, text="Audit")
    notebook.pack_configure(fill="both", expand=True)
    try:
        root.geometry("800x640")
        root.deiconify()
        root.update()
        bars = [child for child in _walk(tab.widget) if isinstance(child, ttk.Scrollbar)]
        assert bars and bars[0].winfo_ismapped()
        tab._details.configure(state="normal")
        tab._details.insert("end", "\n".join(f"Report line {i}" for i in range(200)))
        tab._details.configure(state="disabled")
        root.update()
        before = tab._details.yview()[0]
        bar = bars[0]
        bar.event_generate("<ButtonPress-1>", x=bar.winfo_width() // 2, y=bar.winfo_height() - 30)
        bar.event_generate("<ButtonRelease-1>", x=bar.winfo_width() // 2, y=bar.winfo_height() - 30)
        root.update()
        assert tab._details.yview()[0] > before
    finally:
        tab.close()
        root.destroy()


class FakeService:
    def __init__(self, report=None):
        self.events = queue.Queue()
        self.report = report or _report()
        self.head = {
            "log_id": "a" * 32,
            "last_record_number": 27,
            "last_record_hash": "b" * 64,
            "identity_fingerprint": "c" * 64,
        }
        self.calls = []
        self.entered = threading.Event()
        self.finished = threading.Event()
        self.block_until_cancel = False
        self.late_report = self.report

    def audit_head(self, *, cancel=None):
        self.calls.append(("head", threading.get_ident(), cancel))
        if cancel is not None and cancel.is_set():
            raise SparcError("operation_cancelled", "canceled")
        return dict(self.head)

    def verify_audit(self, checkpoint=None, *, cancel=None):
        self.calls.append(("verify", threading.get_ident(), checkpoint, cancel))
        self.entered.set()
        try:
            if self.block_until_cancel:
                assert cancel is not None
                while not cancel.wait(0.01):
                    pass
                return self.late_report
            return self.report
        finally:
            self.finished.set()

    def export_audit_checkpoint(self, path, *, cancel=None):
        self.calls.append(("export", threading.get_ident(), path, cancel))
        self.entered.set()
        self.finished.set()


def _make_tab(service=None):
    root, notebook = _root_or_skip()
    service = service or FakeService()
    tab = AuditTab(notebook, service)
    notebook.add(tab.widget, text="Audit")
    root.update()
    return root, tab, service


def test_audit_view_reports_failure_and_available_chain_status(monkeypatch):
    service = FakeService(_report(valid=False))
    root, tab, _ = _make_tab(service)
    _pump(root, lambda: any(call[0] == "head" for call in service.calls))
    head_call = next(call for call in service.calls if call[0] == "head")
    assert head_call[1] != threading.get_ident()
    _pump(root, lambda: "disabled" not in _button(tab, "verify").state())
    _button(tab, "verify").invoke()
    _pump(root, lambda: any(call[0] == "verify" for call in service.calls))
    _pump(root, lambda: "audit_signature_failed" in _visible(tab.widget))
    visible = _visible(tab.widget).lower()
    verify_call = next(call for call in service.calls if call[0] == "verify")
    assert verify_call[2] is None
    assert "available chain only" in visible
    assert "first failed record" in visible
    assert "3" in visible
    assert "audit_signature_failed" in visible
    assert "27" in visible
    assert "b" * 64 in visible
    assert "independently retained" not in visible

    # Explicit selection must pass the chosen path as the checkpoint argument.
    from tkinter import filedialog

    selected = "/tmp/operator-selected-checkpoint.json"
    service.report = AuditReport(
        valid=True, verified_records=25, first_failed_record=None,
        reason="checkpoint verified against the audit chain prefix",
        checkpoint_checked=True, elapsed_ns=1_000_000_000,
    )
    monkeypatch.setattr(filedialog, "askopenfilename", lambda **_kwargs: selected)
    buttons = [child for child in _walk(tab.widget) if isinstance(child, ttk.Button)]
    direct_action = next((child for child in buttons
                          if "verify" in str(child.cget("text")).lower()
                          and "checkpoint" in str(child.cget("text")).lower()), None)
    if direct_action is not None:
        direct_action.invoke()
    else:
        choose_action = next(child for child in buttons
                             if "checkpoint" in str(child.cget("text")).lower()
                             and any(word in str(child.cget("text")).lower()
                                     for word in ("choose", "select", "browse")))
        choose_action.invoke()
        _button(tab, "verify").invoke()
    _pump(root, lambda: len([call for call in service.calls if call[0] == "verify"]) > 1)
    calls = [call for call in service.calls if call[0] == "verify"]
    assert calls[-1][2] == Path(selected)
    _pump(root, lambda: "selected checkpoint matched the verified prefix"
          in _visible(tab.widget).lower())
    visible = _visible(tab.widget).lower()
    assert "selected checkpoint matched the verified prefix" in visible
    assert "verified records: 25" in visible
    assert "independently retained" not in visible
    tab.close()
    root.destroy()


def test_checkpoint_export_runs_off_tk_thread_with_selected_path(monkeypatch):
    from tkinter import filedialog

    service = FakeService()
    root, tab, _ = _make_tab(service)
    selected = "/tmp/exported-audit-checkpoint.json"
    monkeypatch.setattr(filedialog, "asksaveasfilename", lambda **_kwargs: selected)
    export_button = _button(tab, "export")
    _pump(root, lambda: "disabled" not in export_button.state())
    export_button.invoke()
    _pump(root, lambda: any(call[0] == "export" for call in service.calls))
    export_call = next(call for call in service.calls if call[0] == "export")
    assert export_call[1] != threading.get_ident()
    assert export_call[2] == Path(selected)
    assert export_call[3] is not None
    tab.close()
    root.destroy()


def test_verify_runs_off_tk_thread_and_close_cancels_same_job_event():
    service = FakeService()
    service.block_until_cancel = True
    service.late_report = _report()
    root, tab, _ = _make_tab(service)
    _pump(root, lambda: "disabled" not in _button(tab, "verify").state())
    _button(tab, "verify").invoke()
    assert service.entered.wait(1)
    verify_call = next(call for call in service.calls if call[0] == "verify")
    assert verify_call[1] != threading.get_ident()
    same_cancel_event = verify_call[3]
    assert same_cancel_event is not None and not same_cancel_event.is_set()

    tab.close()
    assert same_cancel_event.is_set()
    assert service.finished.wait(1)
    before = _visible(tab.widget)
    root.update()
    assert _visible(tab.widget) == before
    root.destroy()


def test_audit_metrics_keep_rate_time_and_bytes_separate():
    service = FakeService(_report())
    root, tab, _ = _make_tab(service)
    _pump(root, lambda: "disabled" not in _button(tab, "verify").state())
    _button(tab, "verify").invoke()
    _pump(root, lambda: "25" in _visible(tab.widget) and "records/s" in _visible(tab.widget))
    tab.handle_event(ServiceEvent("operation_metrics", {
        "operation": "audit", "elapsed_ns": 1_500_000, "encoded_bytes": 777,
        "success": True, "context": {},
    }))
    visible = _visible(tab.widget).lower()
    assert "25" in visible and "records/s" in visible
    assert "1500" in visible and ("µs" in visible or "us" in visible)
    assert "777" in visible and "bytes" in visible

    tab.handle_event(ServiceEvent("operation_metrics", {
        "operation": "send", "elapsed_ns": 99_000_000, "encoded_bytes": 999,
        "success": True, "context": {},
    }))
    visible = _visible(tab.widget).lower()
    assert "1500" in visible and "777" in visible
    tab.close()
    root.destroy()


def test_zero_verify_duration_and_missing_append_bytes_are_not_fabricated():
    service = FakeService(_report(elapsed_ns=0))
    root, tab, _ = _make_tab(service)
    _pump(root, lambda: "disabled" not in _button(tab, "verify").state())
    _button(tab, "verify").invoke()
    _pump(root, lambda: "available chain only" in _visible(tab.widget).lower())
    tab.handle_event(ServiceEvent("operation_metrics", {
        "operation": "audit", "elapsed_ns": 1_500_000,
        "success": True, "context": {},
    }))
    visible = _visible(tab.widget).lower()
    assert "1500" in visible
    assert "bytes/event: unavailable" in visible
    assert "bytes/event: 0" not in visible
    assert "verification throughput: unavailable" in visible
    assert "records/s" not in visible
    tab.close()
    root.destroy()


def test_audit_actions_and_head_fit_minimum_window():
    service = FakeService()
    root, tab, _ = _make_tab(service)
    tab.widget.master.pack_configure(fill="both", expand=True)
    root.tk.call("tk", "scaling", 1.8)
    root.geometry("800x640")
    root.deiconify()
    _pump(root, lambda: tab._head is not None)
    root.update()

    actions = [
        _button(tab, "verify available chain"),
        _button(tab, "verify selected checkpoint"),
        _button(tab, "export checkpoint"),
        _button(tab, "refresh head"),
    ]
    for button in actions:
        button.focus_force()
        root.update()
        left = button.winfo_rootx() - root.winfo_rootx()
        top = button.winfo_rooty() - root.winfo_rooty()
        assert button.winfo_ismapped()
        assert 0 <= left and left + button.winfo_width() <= root.winfo_width()
        assert 0 <= top and top + button.winfo_height() <= root.winfo_height()

    head_label = next(
        child for child in _walk(tab.widget)
        if isinstance(child, ttk.Label)
        and child.cget("textvariable") == str(tab._head_text)
    )
    assert head_label.winfo_width() <= root.winfo_width()
    assert head_label.winfo_height() > 20
    assert "b" * 64 in tab._head_text.get()
    tab.close()
    root.destroy()


def test_completed_report_preserves_captured_prefix_scope_after_head_refresh():
    service = FakeService(AuditReport(
        valid=True, verified_records=6, first_failed_record=None,
        reason="available chain only", checkpoint_checked=False, elapsed_ns=1_000_000_000,
    ))
    service.head["last_record_number"] = 7
    root, tab, _ = _make_tab(service)
    _pump(root, lambda: "disabled" not in _button(tab, "verify available chain").state())
    _button(tab, "verify available chain").invoke()
    _pump(root, lambda: "verified records: 6" in _visible(tab.widget).lower())
    report_before_refresh = _visible(tab.widget).lower()
    assert "committed prefix captured for this verification" in report_before_refresh
    assert "displayed writer head is a separate snapshot" in report_before_refresh

    _pump(root, lambda: "disabled" not in _button(tab, "refresh head").state())
    _button(tab, "refresh head").invoke()
    _pump(root, lambda: "record 7" in tab._head_text.get().lower())
    visible = _visible(tab.widget).lower()
    assert "verified records: 6" in visible
    assert "committed prefix captured for this verification" in visible
    assert "displayed writer head is a separate snapshot" in visible
    assert "verified records: 7" not in visible
    tab.close()
    root.destroy()
