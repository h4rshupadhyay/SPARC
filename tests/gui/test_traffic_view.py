"""Native traffic-tab lifecycle and bounded, main-thread result rendering."""

import gc
import importlib
from pathlib import Path
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk
from decimal import Decimal

import pytest

from sparc.models import SparcError
from sparc.traffic.models import ConversionResult, TrafficReport

pytestmark = pytest.mark.gui


def _module():
    try:
        return importlib.import_module("sparc.gui.traffic_view")
    except ModuleNotFoundError as error:
        if error.name == "sparc.gui.traffic_view":
            pytest.fail("Traffic Analysis tab is not implemented", pytrace=False)
        raise


def _tab():
    module = _module()
    gc.collect()
    root = tk.Tk()
    root.geometry("800x640")
    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True)
    tab = module.TrafficTab(notebook)
    notebook.add(tab.widget, text="Traffic Analysis")
    root.update()
    return root, tab


def _pump(root, predicate, seconds=4):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        root.update()
        if predicate():
            return
        time.sleep(0.01)
    pytest.fail("traffic job did not settle within the test deadline")


def _report():
    conversion = ConversionResult(True, 2, 1000, 120, 4096, 2_000_000., {}, {})
    return TrafficReport({"source_sha256": "a" * 64, "truncated": {"directional_bytes": True}},
                         2, 180, Decimal("2"), Decimal("90"), {"TCP": 2}, [], [],
                         {"0-63": 0, "64-127": 2, "128-511": 0, "512-1023": 0, "1024-1518": 0, "1519+": 0}, 0, conversion)


def test_constructor_is_lazy_and_missing_tool_is_action_local(monkeypatch, tmp_path):
    monkeypatch.setitem(sys.modules, "pyshark", None)
    module = _module()
    def missing(*args, **kwargs):
        raise SparcError("tshark_missing", "private tool path marker")
    monkeypatch.setattr(module, "find_tshark", missing)
    root, tab = _tab()
    try:
        assert not tab._busy
        tab._select_source(tmp_path / "in.pcap")
        tab._start("analyze")
        _pump(root, lambda: not tab._busy)
        assert "TShark" in tab._status.get()
        assert "private" not in tab._status.get()
        assert root.winfo_exists()
    finally:
        tab.close(); root.destroy()


def test_results_render_on_main_thread_and_rates_have_distinct_labels(monkeypatch, tmp_path):
    module = _module()
    root, tab = _tab()
    worker_threads = []
    main = threading.get_ident()
    def analyze(*args):
        worker_threads.append(threading.get_ident())
        return _report()
    monkeypatch.setattr(module, "find_tshark", lambda path: Path("/tool"))
    monkeypatch.setattr(module, "analyze_capture", analyze)
    rendered = []
    original = tab._show_report
    def show(report):
        rendered.append(threading.get_ident())
        original(report)
    monkeypatch.setattr(tab, "_show_report", show)
    try:
        tab._select_source(tmp_path / "in.pcap")
        tab._start("analyze")
        _pump(root, lambda: not tab._busy)
        assert rendered == [main]
        assert worker_threads and worker_threads[0] != main
        assert tab._last_report.packet_count == 2
        rows = [tab._table.item(item) for item in tab._table.get_children("")]
        # User-visible definitions accompany measurements, including unavailable
        # application goodput and the retransmission caveat.
        text = " ".join(str(row) for row in rows)
        assert "Captured frame bytes/s" in text
        assert "Conversion packets/s" in text
        assert "Application plaintext goodput" in text
        assert "not measured" in text
        assert tab._job._queue.maxsize == 64
    finally:
        tab.close(); root.destroy()


def test_cancel_remains_busy_until_worker_settlement_and_keeps_previous_result(monkeypatch, tmp_path):
    module = _module()
    root, tab = _tab()
    entered, release = threading.Event(), threading.Event()
    monkeypatch.setattr(module, "find_tshark", lambda path: Path("/tool"))
    def blocking(*args):
        entered.set()
        release.wait(8)
        raise SparcError("capture_cleanup_failed", "private marker")
    monkeypatch.setattr(module, "analyze_capture", blocking)
    try:
        tab._select_source(tmp_path / "in.pcap")
        previous = _report()
        tab._last_report = previous
        tab._start("analyze")
        assert entered.wait(1)
        tab._cancel()
        assert tab._busy
        assert "waiting" in tab._status.get().lower()
        generation = tab._generation
        tab._start("analyze")
        tab._select_source(tmp_path / "other.pcap")
        assert tab._generation == generation
        release.set()
        _pump(root, lambda: not tab._busy)
        assert "cleanup" in tab._status.get().lower()
        assert tab._last_report is previous
        tab._select_source(tmp_path / "other.pcap")
        assert tab._last_report is None
    finally:
        release.set(); tab.close(); root.destroy()


def test_close_discards_late_success_and_is_idempotent(monkeypatch, tmp_path):
    module = _module()
    root, tab = _tab()
    entered, release = threading.Event(), threading.Event()
    monkeypatch.setattr(module, "find_tshark", lambda path: Path("/tool"))
    def blocking(*args):
        entered.set(); release.wait(8); return _report()
    monkeypatch.setattr(module, "analyze_capture", blocking)
    try:
        tab._select_source(tmp_path / "in.pcap")
        tab._start("analyze")
        assert entered.wait(1)
        tab.close(); tab.close()
        tab.widget.destroy()
        release.set()
        _pump(root, lambda: tab._done.is_set())
        assert tab._last_report is None
    finally:
        release.set(); tab.close(); root.destroy()


def test_export_error_preserves_report_and_filter_change_invalidates_it(monkeypatch, tmp_path):
    module = _module()
    root, tab = _tab()
    monkeypatch.setattr(module, "find_tshark", lambda path: Path("/tool"))
    def fail(*args):
        raise SparcError("traffic_publication_uncertain", "private marker")
    monkeypatch.setattr(module, "export_xml", fail)
    try:
        tab._select_source(tmp_path / "in.pcap")
        previous = _report()
        tab._last_report = previous
        tab._start("xml", tmp_path / "out.xml")
        _pump(root, lambda: not tab._busy)
        assert tab._last_report is previous
        assert "uncertain" in tab._status.get().lower()
        tab._filter.set("tcp")
        assert tab._last_report is None
    finally:
        tab.close(); root.destroy()


def test_traffic_registers_once_and_canceling_dialog_leaves_selection(monkeypatch, tmp_path):
    module = _module()
    root, tab = _tab()
    try:
        tab._select_source(tmp_path / "source.pcap")
        previous = _report()
        tab._last_report = previous
        generation = tab._generation
        monkeypatch.setattr(module.filedialog, "askopenfilename", lambda **kwargs: "")
        tab._open_capture()
        assert tab._generation == generation
        assert tab._last_report is previous
        class App:
            notebook = tab.widget.master
            def __init__(self):
                self.added = []
            def add_tab(self, title, view):
                self.added.append(view)
                self.notebook.add(view.widget, text=title)
        app = App()
        module.register_traffic(app)
        module.register_traffic(app)
        assert len(app.added) == 1
        app.added[0].close()
    finally:
        tab.close(); root.destroy()
