"""A3c analysis tab behavior using real Tk widgets."""

from __future__ import annotations

import csv
import gc
import json
import threading
import time
import tkinter as tk
import tkinter.font as tkfont
from tkinter import TclError, ttk

import pytest

from sparc.analysis.models import LabResult
from sparc.models import Limits, ServiceEvent


def _analysis_view():
    from importlib import import_module

    try:
        view = import_module("sparc.gui.analysis_view")
    except ModuleNotFoundError as error:
        if error.name != "sparc.gui.analysis_view":
            raise
        pytest.fail("sparc.gui.analysis_view must be implemented")
    assert callable(getattr(view, "AnalysisTab", None)), "AnalysisTab must be implemented"
    return view


def _root_or_skip():
    try:
        root = tk.Tk()
    except TclError as exc:
        pytest.skip(f"Tk display unavailable: {exc}")
    root.withdraw()
    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True)
    return root, notebook


def _walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from _walk(child)


def _widget_value(widget):
    if isinstance(widget, tk.Text):
        return widget.get("1.0", tk.END).strip()
    if isinstance(widget, tk.Entry):
        return widget.get()
    if isinstance(widget, ttk.Entry):
        return widget.get()
    if isinstance(widget, ttk.Combobox):
        return widget.get()
    if isinstance(widget, ttk.Spinbox):
        return widget.get()
    if isinstance(widget, tk.Listbox):
        return "\n".join(str(widget.get(index)) for index in range(widget.size()))
    if isinstance(widget, ttk.Treeview):
        return "\n".join(
            " ".join(str(value) for value in widget.item(item, "values"))
            for item in widget.get_children("")
        )
    return ""


def _visible(widget):
    values = []
    for child in _walk(widget):
        try:
            label = child.cget("text")
            variable = child.cget("textvariable")
            if variable:
                label = child.getvar(variable)
        except (tk.TclError, TypeError):
            label = ""
        if label:
            values.append(str(label))
        value = _widget_value(child)
        if value:
            values.append(value)
    return "\n".join(values)


def _button(tab, *terms, exclude=()):
    return next(
        child for child in _walk(tab.widget)
        if isinstance(child, ttk.Button)
        and all(term in str(child.cget("text")).lower() for term in terms)
        and not any(term in str(child.cget("text")).lower() for term in exclude)
    )


def _pump(root, predicate, timeout=2.0):
    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        root.update()
        time.sleep(0.005)
    root.update()


class FakeService:
    def __init__(self, state="disconnected"):
        self.state = state
        self.limits = Limits()


def _make_tab(service=None):
    # Release prior destroyed Tk views on the main thread before allocating
    # hash-search containers can trigger cyclic collection in a worker.
    gc.collect()
    view = _analysis_view()
    root, notebook = _root_or_skip()
    tab = view.AnalysisTab(notebook, service or FakeService())
    notebook.add(tab.widget, text="Analysis")
    root.update()
    return root, tab


def _labeled_input(tab, term):
    for widget in _walk(tab.widget):
        if not isinstance(widget, (ttk.Entry, ttk.Spinbox, ttk.Combobox)):
            continue
        for sibling in widget.master.winfo_children():
            if isinstance(sibling, (ttk.Label, tk.Label)):
                text = sibling.cget("text")
                variable = sibling.cget("textvariable")
                if variable:
                    text = sibling.getvar(variable)
                if term in str(text).lower():
                    return widget
    raise AssertionError(f"no editable {term!r} control was found")


def _set_input(widget, value):
    if isinstance(widget, ttk.Combobox):
        widget.set(str(value))
        widget.event_generate("<<ComboboxSelected>>")
    else:
        widget.delete(0, tk.END)
        widget.insert(0, str(value))


@pytest.mark.gui
def test_analysis_close_cancels_job_and_ignores_late_result(monkeypatch):
    view = _analysis_view()
    root, tab = _make_tab()
    entered = threading.Event()
    release = threading.Event()
    cancel_events = []

    def late_sensitivity(*args, **kwargs):
        cancel = kwargs.get("cancel")
        if cancel is None and len(args) > 2:
            cancel = args[2]
        cancel_events.append(cancel)
        entered.set()
        assert release.wait(2)
        return LabResult(seed=42, cases=1, trials=[], summary={}, complete=False)

    monkeypatch.setattr(view, "run_sensitivity", late_sensitivity)
    _button(tab, "batch").invoke()
    assert entered.wait(1)
    assert cancel_events and cancel_events[0] is not None
    helper = threading.Thread(
        target=lambda: (cancel_events[0].wait(1), release.set()), daemon=True
    )
    helper.start()
    before = _visible(tab.widget)
    tab.close()
    helper.join(timeout=1)
    assert cancel_events[0].is_set()
    assert not helper.is_alive()

    callback_errors = []
    root.report_callback_exception = lambda *error: callback_errors.append(error)
    root.update()
    assert _visible(tab.widget) == before
    assert callback_errors == []
    root.destroy()


@pytest.mark.gui
def test_network_disabled_until_connected():
    root, tab = _make_tab(FakeService(state="disconnected"))
    network_button = _button(tab, "network")
    assert network_button.instate(["disabled"])

    tab.handle_event(ServiceEvent("state", {"state": "connected"}))
    root.update()
    assert not network_button.instate(["disabled"])

    tab.handle_event(ServiceEvent("state", {"state": "disconnected"}))
    root.update()
    assert network_button.instate(["disabled"])
    tab.close()
    root.destroy()


@pytest.mark.gui
def test_single_trial_displays_operands_formulas_and_observed_values():
    from sparc.analysis.sensitivity import sensitivity_trial

    root, tab = _make_tab()
    seed = _labeled_input(tab, "seed")
    case = _labeled_input(tab, "case")
    mode = _labeled_input(tab, "mode")
    bit = _labeled_input(tab, "bit")
    _set_input(seed, 42)
    _set_input(case, 0)

    _set_input(mode, "plaintext")
    root.update()
    _set_input(bit, 127)
    _button(tab, "trial", exclude=("batch",)).invoke()
    expected = sensitivity_trial(42, 0, "plaintext", 127)
    _pump(root, lambda: expected.baseline_ciphertext.hex() in _visible(tab.widget).lower())
    visible = _visible(tab.widget).lower()
    assert expected.key.hex() in visible
    assert expected.block.hex() in visible
    assert expected.modified_block.hex() in visible
    assert expected.baseline_ciphertext.hex() in visible
    assert expected.modified_ciphertext.hex() in visible
    assert "plaintext" in visible and "127" in visible
    assert "expected" in visible or "expectation" in visible
    assert "observed" in visible
    assert "50%" in visible
    assert "bit" in visible and "128" in visible
    assert "byte" in visible and "16" in visible
    assert "hex" in visible and "32" in visible

    _set_input(mode, "key")
    root.update()
    _set_input(bit, 255)
    _button(tab, "trial", exclude=("batch",)).invoke()
    key_trial = sensitivity_trial(42, 0, "key", 255)
    _pump(root, lambda: key_trial.modified_key.hex() in _visible(tab.widget).lower())
    visible = _visible(tab.widget).lower()
    assert key_trial.modified_key.hex() in visible
    assert "key" in visible and "255" in visible
    tab.close()
    root.destroy()


@pytest.mark.gui
def test_only_one_job_and_cancel_is_not_complete(monkeypatch):
    view = _analysis_view()
    root, tab = _make_tab()
    entered = threading.Event()
    calls = []

    def cancelable_sensitivity(*args, **kwargs):
        cancel = kwargs.get("cancel")
        if cancel is None and len(args) > 2:
            cancel = args[2]
        calls.append(cancel)
        entered.set()
        assert cancel is not None
        cancel.wait(2)
        return LabResult(seed=42, cases=1, trials=[], summary={}, complete=False)

    monkeypatch.setattr(view, "run_sensitivity", cancelable_sensitivity)
    batch = _button(tab, "batch")
    batch.invoke()
    assert entered.wait(1)
    batch.invoke()
    assert len(calls) == 1
    assert batch.instate(["disabled"])

    _button(tab, "cancel").invoke()
    _pump(root, lambda: any(word in _visible(tab.widget).lower() for word in ("canceled", "cancelled", "incomplete")))
    visible = _visible(tab.widget).lower()
    assert "complete: true" not in visible
    assert "incomplete" in visible or "canceled" in visible or "cancelled" in visible
    tab.close()
    root.destroy()


@pytest.mark.gui
def test_specimen_shows_valid_and_edited_rejection(monkeypatch):
    from sparc.analysis.specimen import make_specimen

    view = _analysis_view()
    specimen = make_specimen()
    monkeypatch.setattr(view, "make_timed_specimen", lambda: (*specimen, 2500))
    root, tab = _make_tab()

    specimen_buttons = [
        child for child in _walk(tab.widget)
        if isinstance(child, ttk.Button) and "specimen" in str(child.cget("text")).lower()
    ]
    create_button = next(
        (button for button in specimen_buttons if "verify" not in str(button.cget("text")).lower()),
        specimen_buttons[0],
    )
    create_button.invoke()
    _pump(root, lambda: "valid" in _visible(tab.widget).lower())
    visible = _visible(tab.widget).lower()
    assert "valid" in visible
    assert specimen[0].hex() in visible
    assert specimen[1].hex() in visible
    assert specimen[2].hex() in visible

    signature_hex = specimen[2].hex()
    editable = None
    for widget in _walk(tab.widget):
        value = _widget_value(widget).replace(" ", "").replace("\n", "").lower()
        if signature_hex in value and isinstance(widget, (tk.Text, tk.Entry, ttk.Entry)):
            editable = widget
            break
    assert editable is not None, "signature specimen should expose an editable signature field"
    edited = signature_hex[:-1] + ("0" if signature_hex[-1] != "0" else "1")
    if isinstance(editable, tk.Text):
        editable.delete("1.0", tk.END)
        editable.insert("1.0", edited)
    else:
        editable.delete(0, tk.END)
        editable.insert(0, edited)

    verify_button = next(
        (button for button in specimen_buttons
         if "verify" in str(button.cget("text")).lower()),
        create_button,
    )
    verify_button.invoke()
    _pump(root, lambda: "invalid" in _visible(tab.widget).lower() or "rejected" in _visible(tab.widget).lower())
    visible = _visible(tab.widget).lower()
    assert "invalid" in visible or "rejected" in visible
    tab.close()
    root.destroy()


@pytest.mark.gui
def test_signature_specimen_displays_signing_only_microseconds():
    root, tab = _make_tab()
    try:
        _button(tab, "generate", "specimen").invoke()
        _pump(root, lambda: not tab._busy)
        visible = _visible(tab.widget)
        assert "Signature generation" in visible
        assert "µs" in visible
        assert "excludes key generation" in visible.lower()
    finally:
        tab.close()
        root.destroy()


@pytest.mark.gui
def test_local_benchmark_labels_signature_generation_in_microseconds():
    from sparc.analysis.models import BenchmarkResult

    root, tab = _make_tab()
    try:
        tab._job_kind = "local"
        tab._job_result("result", BenchmarkResult(
            metadata={}, samples=[], summary=[{
                "operation": "sign", "payload_bytes": 64, "count": 2,
                "mean_ns": 2500, "p95_ns": 4000,
            }], complete=True,
        ))
        values = [tab._results.item(item, "values") for item in tab._results.get_children()]
        assert values[0][1] == "Signature generation (µs)"
        assert values[0][2] == "2.5"
        assert "p95 4 µs" in values[0][3]
    finally:
        tab.close()
        root.destroy()


@pytest.mark.gui
@pytest.mark.parametrize("mode", ["collision", "preimage", "second_preimage"])
def test_hash_search_gui_runs_and_exports_full_digest_searches(monkeypatch, tmp_path, mode):
    import hashlib

    root, tab = _make_tab()
    try:
        actions = [w for w in _walk(tab.widget)
                   if isinstance(w, ttk.Button) and w.cget("text") == "Run hash search"]
        assert actions, "Analysis must expose hashing security experiments"
        tab._hash_mode.set({
            "collision": "Collision resistance", "preimage": "Preimage resistance",
            "second_preimage": "Second-preimage resistance",
        }[mode])
        tab._hash_seed.set("7")
        tab._hash_attempts.set("4096")
        actions[0].invoke()
        _pump(root, lambda: not tab._busy)
        visible = _visible(tab.widget).lower()
        assert "no match within" in visible
        assert "full sha-256" in visible
        assert "shortened" not in visible
        assert "does not establish" in visible
        assert "attempts" in visible and "elapsed" in visible
        result = tab._last_result
        assert result.mode == mode
        assert result.digest_bits == 256
        assert result.attempts == 4096
        path = tmp_path / f"{mode}.csv"
        view = _analysis_view()
        monkeypatch.setattr(view.filedialog, "asksaveasfilename", lambda **kwargs: str(path))
        _button(tab, "save", "csv").invoke()
        _pump(root, lambda: path.exists() and not tab._busy)
        with path.open(newline="", encoding="utf-8") as stream:
            row = next(csv.DictReader(stream))
        assert row["scope"] == "full_sha256_bounded_search"
        assert row["digest_bits"] == "256"
        assert row["mode"] == mode
        assert row["outcome"] == "budget_exhausted"
        if mode == "second_preimage":
            assert hashlib.sha256(bytes.fromhex(row["input_a_hex"])).hexdigest() == row["target_digest"]
        elif mode == "preimage":
            assert len(row["target_digest"]) == 64
    finally:
        tab.close()
        root.destroy()


@pytest.mark.gui
def test_hash_search_gui_invalid_inputs_full_digest_and_cancel(monkeypatch):
    root, tab = _make_tab()
    try:
        actions = [w for w in _walk(tab.widget)
                   if isinstance(w, ttk.Button) and w.cget("text") == "Run hash search"]
        assert actions, "Analysis must expose hashing security experiments"
        run = actions[0]
        tab._hash_attempts.set("100001")
        run.invoke()
        assert not tab._busy
        assert "attempt" in tab._status.get().lower()
        tab._hash_attempts.set("10")
        run.invoke()
        _pump(root, lambda: not tab._busy)
        assert "no match within" in _visible(tab.widget).lower()
        assert "full sha-256" in _visible(tab.widget).lower()
        previous = tab._last_result
        entered = threading.Event()
        stopped = threading.Event()
        original = _analysis_view().run_hash_search

        def wait_for_cancel(*args, **kwargs):
            entered.set()
            try:
                assert kwargs["cancel"].wait(2)
                return original(*args, **kwargs)
            finally:
                stopped.set()

        monkeypatch.setattr(_analysis_view(), "run_hash_search", wait_for_cancel)
        run.invoke()
        assert entered.wait(1)
        assert run.instate(["disabled"])
        _button(tab, "cancel").invoke()
        assert stopped.wait(1)
        _pump(root, lambda: not tab._busy)
        assert "canceled" in tab._status.get().lower()
        assert tab._last_result.outcome == "canceled"
        assert not tab._last_result.complete
        assert tab._last_result is not previous
    finally:
        tab.close()
        root.destroy()


class AuditMetricService(FakeService):
    def __init__(self, report=None, error=None, *, wait_for_cancel=False, release=None):
        super().__init__(state="disconnected")
        self.report = report
        self.error = error
        self.wait_for_cancel = wait_for_cancel
        self.release = release
        self.calls = []
        self.entered = threading.Event()
        self.finished = threading.Event()

    def verify_audit(self, checkpoint=None, *, cancel=None):
        self.calls.append((checkpoint, cancel, threading.get_ident()))
        self.entered.set()
        try:
            if self.wait_for_cancel:
                assert cancel is not None
                cancel.wait(2)
                if self.release is not None:
                    assert self.release.wait(2)
            if self.error is not None:
                raise self.error
            return self.report
        finally:
            self.finished.set()


def _audit_metric_rows(tab):
    rows = []
    for widget in _walk(tab.widget):
        if not isinstance(widget, ttk.Treeview):
            continue
        for item in widget.get_children(""):
            values = tuple(str(value) for value in widget.item(item, "values"))
            if any("audit_verify" in value for value in values):
                rows.append(values)
    return rows


def _forbid_duration_clocks(monkeypatch, view):
    from importlib import import_module

    modules = [view]
    try:
        modules.append(import_module("sparc.analysis.operation_metrics"))
    except ModuleNotFoundError as error:
        if error.name != "sparc.analysis.operation_metrics":
            raise
    seen = set()

    def forbidden_clock():
        raise AssertionError("audit report duration must not use a new timer")

    for module in modules:
        clock = getattr(module, "time", None)
        if clock is None or id(clock) in seen or not hasattr(clock, "perf_counter_ns"):
            continue
        seen.add(id(clock))
        monkeypatch.setattr(clock, "perf_counter_ns", forbidden_clock)


@pytest.mark.gui
def test_audit_metric_uses_report_duration_once_and_exports_raw_context(monkeypatch, tmp_path):
    from tkinter import filedialog

    from sparc.audit_format import AuditReport

    view = _analysis_view()
    _forbid_duration_clocks(monkeypatch, view)
    report = AuditReport(
        valid=True,
        verified_records=7,
        first_failed_record=None,
        reason="ok",
        checkpoint_checked=False,
        elapsed_ns=2500,
    )
    service = AuditMetricService(report=report)
    root, tab = _make_tab(service)
    _button(tab, "verify audit metric").invoke()
    assert service.entered.wait(1)
    _pump(root, lambda: bool(_audit_metric_rows(tab)))

    assert len(service.calls) == 1
    checkpoint, cancel, worker_thread = service.calls[0]
    assert checkpoint is None
    assert cancel is not None
    assert worker_thread != threading.get_ident()
    visible = _visible(tab.widget).lower()
    assert "audit_verify" in visible
    assert "2500" in visible
    assert "verified_records" in visible and "7" in visible
    assert "captured_committed_prefix" in visible
    assert "encoded bytes: 0" not in visible

    destination = tmp_path / "audit-verification.csv"
    monkeypatch.setattr(filedialog, "asksaveasfilename", lambda **_kwargs: str(destination))
    _button(tab, "csv").invoke()
    _pump(root, destination.exists)
    with destination.open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    samples = [row for row in rows if row["row_type"] == "sample"]
    assert len(samples) == 1
    assert samples[0]["operation"] == "audit_verify"
    assert samples[0]["elapsed_ns"] == "2500"
    assert samples[0]["success"] == "true"
    assert samples[0]["encoded_bytes"] == ""
    assert json.loads(samples[0]["context_json"]) == {
        "verified_records": 7,
        "checkpoint_checked": False,
        "checkpoint_selected": False,
        "verification_scope": "captured_committed_prefix",
        "source": "analysis_audit_report",
    }
    metadata = json.loads(samples[0]["metadata_json"])
    from dataclasses import asdict

    assert metadata["test_type"] == "operation_metrics"
    assert metadata["evidence_mode"] == "retained_service_observations"
    assert metadata["sample_count"] == 1
    assert metadata["policy_limits"] == json.loads(json.dumps(asdict(service.limits)))
    tab.close()
    root.destroy()


@pytest.mark.gui
def test_rendered_tables_fit_native_text_without_widening_the_tab():
    root, tab = _make_tab()
    root.deiconify()
    root.geometry("800x640")
    root.update()
    font = tkfont.nametofont("TkDefaultFont")

    result_text = {
        "workload": "Synthetic specimen",
        "measurement": "Signature verification (µs)",
        "value": "61 / 128",
        "detail": "Observed 47.65625%",
    }
    for column, text in result_text.items():
        assert tab._results.column(column, "minwidth") >= font.measure(text) + 20

    metric_text = {
        "operation": "reconnect_recovery",
        "elapsed": "123456789012345",
        "success": "success",
        "encoded": "unavailable",
        "frame": "unavailable",
        "context": "{'verification_scope': 'captured_committed_prefix'}",
    }
    for column, text in metric_text.items():
        assert tab._metrics.column(column, "minwidth") >= font.measure(text) + 20
    assert root.winfo_width() == 800
    assert tab._results.winfo_width() <= 800
    assert tab._metrics.winfo_width() <= 800
    tab.close()
    root.destroy()


@pytest.mark.gui
def test_operation_metric_burst_coalesces_idle_render_and_close_cancels_it(monkeypatch):
    root, tab = _make_tab()
    renders = []
    render = tab._render_operation_metrics

    def render_spy():
        renders.append("render")
        render()

    monkeypatch.setattr(tab, "_render_operation_metrics", render_spy)
    for index in range(64):
        tab.handle_event(ServiceEvent("operation_metrics", {
            "operation": f"burst_{index}",
            "elapsed_ns": index + 1,
            "success": True,
            "context": {"sequence": index},
        }))
    assert len(tab._operation_metrics.result().samples) == 64
    assert renders == []
    root.update()
    assert renders == ["render"]
    visible = "\n".join(
        " ".join(str(value) for value in tab._metrics.item(row, "values"))
        for row in tab._metrics.get_children("")
    )
    assert "burst_63" in visible

    for index in range(64, 128):
        tab.handle_event(ServiceEvent("operation_metrics", {
            "operation": f"burst_{index}",
            "elapsed_ns": index + 1,
            "success": True,
            "context": {"sequence": index},
        }))
    assert len(tab._operation_metrics.result().samples) == 128
    tab.close()
    root.update()
    assert renders == ["render"]
    root.destroy()


@pytest.mark.gui
def test_invalid_audit_report_is_a_failed_duration_measurement():
    from sparc.audit_format import AuditReport

    report = AuditReport(
        valid=False,
        verified_records=3,
        first_failed_record=4,
        reason="audit_signature_failed",
        checkpoint_checked=False,
        elapsed_ns=6100,
    )
    root, tab = _make_tab(AuditMetricService(report=report))
    _button(tab, "verify audit metric").invoke()
    _pump(root, lambda: bool(_audit_metric_rows(tab)))

    visible = _visible(tab.widget).lower()
    assert "audit_verify" in visible
    assert "6100" in visible
    assert "false" in visible or "failed" in visible
    assert "verified_records" in visible and "3" in visible
    assert "complete: true" not in visible
    tab.close()
    root.destroy()


@pytest.mark.gui
def test_audit_metric_cancel_and_error_do_not_create_duration_rows():
    from sparc.models import SparcError

    release = threading.Event()
    service = AuditMetricService(wait_for_cancel=True, release=release)
    root, tab = _make_tab(service)
    _button(tab, "verify audit metric").invoke()
    assert service.entered.wait(1)
    cancel = service.calls[0][1]
    assert cancel is not None
    helper = threading.Thread(target=lambda: (cancel.wait(1), release.set()), daemon=True)
    helper.start()
    _button(tab, "cancel").invoke()
    helper.join(timeout=1)
    assert service.finished.wait(1)
    assert not _audit_metric_rows(tab)
    assert "canceled" in _visible(tab.widget).lower() or "cancelled" in _visible(tab.widget).lower()
    tab.close()
    root.destroy()

    error_service = AuditMetricService(error=SparcError("audit_failed", "verification unavailable"))
    root, tab = _make_tab(error_service)
    _button(tab, "verify audit metric").invoke()
    assert error_service.entered.wait(1)
    _pump(root, lambda: "analysis failed" in _visible(tab.widget).lower())
    assert not _audit_metric_rows(tab)
    tab.close()
    root.destroy()


@pytest.mark.gui
def test_audit_metric_close_ignores_late_report():
    from sparc.audit_format import AuditReport

    release = threading.Event()
    report = AuditReport(
        valid=True,
        verified_records=5,
        first_failed_record=None,
        reason="ok",
        checkpoint_checked=False,
        elapsed_ns=900,
    )
    service = AuditMetricService(report=report, wait_for_cancel=True, release=release)
    root, tab = _make_tab(service)
    _button(tab, "verify audit metric").invoke()
    assert service.entered.wait(1)
    cancel = service.calls[0][1]
    assert cancel is not None
    helper = threading.Thread(target=lambda: (cancel.wait(1), release.set()), daemon=True)
    helper.start()
    before = _visible(tab.widget)
    tab.close()
    helper.join(timeout=1)
    assert service.finished.wait(1)
    root.update()
    assert _visible(tab.widget) == before
    assert not _audit_metric_rows(tab)
    root.destroy()
