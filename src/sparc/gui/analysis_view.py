"""Synthetic analysis controls and bounded results for the SPARC GUI."""

from __future__ import annotations

import csv
import io
import math
import os
from dataclasses import asdict
from pathlib import Path
import tkinter as tk
import tkinter.font as tkfont
from tkinter import filedialog, ttk
from threading import Event

from ..analysis.benchmark import run_local_benchmarks
from ..analysis.export import export_benchmark, export_lab
from ..analysis.hashing import HASH_PROPERTIES, HASH_SOURCE, HashSearchResult, export_hash_search, run_hash_search
from ..analysis.models import BenchmarkResult, LabResult, ResourceResult, Trial
from ..analysis.operation_metrics import OperationMetrics
from ..analysis.network import run_network_benchmark
from ..analysis.resources import sample_resources
from ..analysis.sensitivity import run_sensitivity, sensitivity_trial
from ..analysis.specimen import make_timed_specimen, verify_specimen
from ..models import ServiceEvent
from ..storage import atomic_write
from .jobs import JobController
from .scrolling import CanvasScroller, scrollbar


_ALLOWED_SIZES = (64, 1024, 16384)
_RESULT_ROWS = 500
_RESOURCE_ROWS = 100
_HASH_MODES = {
    "Collision resistance": "collision",
    "Preimage resistance": "preimage",
    "Second-preimage resistance": "second_preimage",
}


def _parse_seed(value: str) -> int:
    """Parse a signed decimal seed in bounded chunks."""
    text = value.strip()
    sign = 1
    if text[:1] in ("+", "-"):
        if text[0] == "-":
            sign = -1
        text = text[1:]
    if not text or not text.isascii() or not text.isdecimal():
        raise ValueError("Seed must be a signed decimal integer")
    number = 0
    for offset in range(0, len(text), 9):
        chunk = text[offset : offset + 9]
        number = number * (10 ** len(chunk)) + int(chunk)
    return sign * number


class AnalysisTab:
    """Run bounded synthetic analysis and display public measurements."""

    def __init__(self, parent: ttk.Notebook, service) -> None:
        self.service = service
        self.widget = ttk.Frame(parent, padding=0)
        self._closed = False
        self._busy = False
        self._job_kind: str | None = None
        self._connection_state = getattr(service, "state", "stopped")
        self._last_result: object | None = None
        self._last_result_kind: str | None = None
        self._resource_stop: Event | None = None
        self._hash_cancel: Event | None = None
        self._operation_metrics = OperationMetrics()
        self._has_operation_metrics = False
        self._metrics_redraw_id = None
        self._status = tk.StringVar(master=self.widget, value="Ready for a synthetic analysis run")
        self._progress_text = tk.StringVar(master=self.widget, value="No job running")
        self._mode = tk.StringVar(master=self.widget, value="plaintext")
        self._evidence_mode = tk.StringVar(master=self.widget, value="unspecified")
        self._seed = tk.StringVar(master=self.widget, value="42")
        self._case_index = tk.StringVar(master=self.widget, value="0")
        self._bit_index = tk.StringVar(master=self.widget, value="0")
        self._batch_cases = tk.StringVar(master=self.widget, value="50")
        self._sizes = tk.StringVar(master=self.widget, value="64,1024,16384")
        self._warmups = tk.StringVar(master=self.widget, value="10")
        self._local_repetitions = tk.StringVar(master=self.widget, value="1000")
        self._network_repetitions = tk.StringVar(master=self.widget, value="100")
        self._resource_interval = tk.StringVar(master=self.widget, value="1.0")
        self._specimen_public = tk.StringVar(master=self.widget, value="")
        self._specimen_signed = tk.StringVar(master=self.widget, value="")
        self._specimen_signature = tk.StringVar(master=self.widget, value="")
        self._specimen_timing = tk.StringVar(master=self.widget, value="Signature generation: unavailable")
        self._hash_mode = tk.StringVar(master=self.widget, value="Collision resistance")
        self._hash_attempts = tk.StringVar(master=self.widget, value="100000")
        self._hash_seed = tk.StringVar(master=self.widget, value="42")
        self._job = JobController(parent.winfo_toplevel(), self._job_result)
        self._build()
        self._refresh_controls()

    def _build(self) -> None:
        frame = self.widget
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        frame.rowconfigure(1, weight=0)
        self._canvas = tk.Canvas(frame, highlightthickness=0, borderwidth=0)
        self._canvas.grid(row=0, column=0, sticky="nsew")
        page_scrollbar = scrollbar(frame, orient=tk.VERTICAL, command=self._canvas.yview)
        page_scrollbar.grid(row=0, column=1, sticky="ns")
        self._canvas.configure(yscrollcommand=page_scrollbar.set)
        self._content = ttk.Frame(self._canvas, padding=12)
        self._canvas_window = self._canvas.create_window((0, 0), window=self._content, anchor="nw")
        self._content.columnconfigure(0, weight=1)
        self._content.bind("<Configure>", self._content_resized, add="+")
        self._canvas.bind("<Configure>", self._canvas_resized, add="+")
        self._scroller = CanvasScroller(self._canvas)

        ttk.Label(self._content, text="Analysis laboratory", font=("TkDefaultFont", 13, "bold")).grid(
            row=0, column=0, sticky="w", pady=(2, 2)
        )
        ttk.Label(
            self._content,
            text="Synthetic trials and verified peer receipts. Live record keys are never used or exported.",
            wraplength=850,
        ).grid(row=1, column=0, sticky="ew", pady=(0, 10))

        sensitivity = ttk.LabelFrame(self._content, text="AES sensitivity", padding=8)
        sensitivity.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        sensitivity.columnconfigure(0, weight=1)
        fields = ttk.Frame(sensitivity)
        fields.grid(row=0, column=0, sticky="ew")
        for column in range(3):
            fields.columnconfigure(column, weight=1)
        self._field(fields, "Seed", self._seed, 0, width=18)
        self._field(fields, "Case", self._case_index, 1, kind="spin", low=0, high=49, width=8)
        self._field(
            fields, "Mode", self._mode, 2, kind="combo", values=("plaintext", "key"), width=13,
            on_change=self._mode_changed,
        )
        self._bit_spinbox = self._field(
            fields, "Bit index", self._bit_index, 3, kind="spin", low=0, high=127, width=8
        )
        self._bit_spinbox.master.grid_configure(row=1, column=0)
        self._field(fields, "Batch cases", self._batch_cases, 4, kind="spin", low=1, high=50, width=10)
        fields.winfo_children()[-1].grid_configure(row=1, column=1)
        actions = ttk.Frame(sensitivity)
        actions.grid(row=1, column=0, sticky="ew", pady=(7, 0))
        self._trial_button = ttk.Button(actions, text="Run single trial", command=self._run_trial)
        self._trial_button.grid(row=0, column=0, sticky="w", padx=(0, 6))
        self._batch_button = ttk.Button(actions, text="Run sensitivity batch", command=self._run_batch)
        self._batch_button.grid(row=0, column=1, sticky="w")

        performance = ttk.LabelFrame(self._content, text="Performance and resources", padding=8)
        performance.grid(row=3, column=0, sticky="ew", pady=(0, 8))
        performance.columnconfigure(0, weight=1)
        perf_top = ttk.Frame(performance)
        perf_top.grid(row=0, column=0, sticky="ew")
        perf_bottom = ttk.Frame(performance)
        perf_bottom.grid(row=1, column=0, sticky="ew", pady=(3, 0))
        for fields in (perf_top, perf_bottom):
            for column in range(2):
                fields.columnconfigure(column, weight=1)
        self._field(perf_top, "Payload sizes", self._sizes, 0, width=18)
        self._field(perf_top, "Warmups", self._warmups, 1, kind="spin", low=0, high=10, width=7)
        local_repetitions_widget = self._field(
            perf_top, "Local repetitions", self._local_repetitions,
            0, kind="spin", low=1, high=1000, width=9,
        )
        local_repetitions_widget.master.grid_configure(row=1, column=0)
        self._field(
            perf_bottom, "Network repetitions", self._network_repetitions,
            0, kind="spin", low=1, high=100, width=9,
        )
        self._field(
            perf_bottom, "Sample interval (s)", self._resource_interval,
            1, kind="spin", low=0.1, high=10, increment=0.1, width=8,
        )
        evidence_widget = self._field(
            perf_bottom, "Evidence mode", self._evidence_mode, 0, kind="combo",
            values=("unspecified", "paired_test", "loopback", "physical"), width=13,
        )
        evidence_widget.master.grid_configure(row=1, column=0)
        perf_actions = ttk.Frame(performance)
        perf_actions.grid(row=2, column=0, sticky="ew", pady=(7, 0))
        perf_actions.columnconfigure(0, weight=1)
        self._local_button = ttk.Button(
            perf_actions, text="Run local benchmark", command=self._run_local
        )
        self._local_button.grid(row=0, column=0, sticky="ew", pady=(0, 4))
        self._network_button = ttk.Button(
            perf_actions, text="Run network benchmark", command=self._run_network
        )
        self._network_button.grid(row=1, column=0, sticky="ew", pady=(0, 4))
        self._resource_button = ttk.Button(
            perf_actions, text="Sample process resources", command=self._run_resources
        )
        self._resource_button.grid(row=2, column=0, sticky="ew", pady=(0, 4))
        self._audit_metric_button = ttk.Button(
            perf_actions, text="Verify audit metric", command=self._run_audit_metric
        )
        self._audit_metric_button.grid(row=3, column=0, sticky="ew")

        specimen = ttk.LabelFrame(self._content, text="Synthetic signature specimen", padding=8)
        specimen.grid(row=4, column=0, sticky="ew", pady=(0, 8))
        specimen.columnconfigure(1, weight=1)
        ttk.Label(specimen, text="Public key (hex)").grid(row=0, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(specimen, textvariable=self._specimen_public).grid(row=0, column=1, sticky="ew")
        ttk.Label(specimen, text="Signed bytes (hex)").grid(row=1, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(specimen, textvariable=self._specimen_signed).grid(row=1, column=1, sticky="ew")
        ttk.Label(specimen, text="Signature (hex)").grid(row=2, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(specimen, textvariable=self._specimen_signature).grid(row=2, column=1, sticky="ew")
        specimen_actions = ttk.Frame(specimen)
        specimen_actions.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        self._make_specimen_button = ttk.Button(
            specimen_actions, text="Generate specimen", command=self._generate_specimen
        )
        self._make_specimen_button.grid(row=0, column=0, sticky="w", padx=(0, 6))
        self._verify_specimen_button = ttk.Button(
            specimen_actions, text="Verify specimen", command=self._verify_specimen
        )
        self._verify_specimen_button.grid(row=0, column=1, sticky="w")
        ttk.Label(specimen, textvariable=self._specimen_timing, wraplength=650).grid(
            row=4, column=0, columnspan=2, sticky="w", pady=(6, 0)
        )

        hashing = ttk.LabelFrame(self._content, text="Hashing security analysis", padding=8)
        hashing.grid(row=5, column=0, sticky="ew", pady=(0, 8))
        hashing.columnconfigure(0, weight=1)
        ttk.Label(
            hashing,
            text=("Synthetic searches compare full 256-bit SHA-256 digests. "
                  "No match within the attempt limit is a bounded observation, not proof of security."),
            wraplength=650,
        ).grid(row=0, column=0, sticky="ew")
        hash_fields = ttk.Frame(hashing)
        hash_fields.grid(row=1, column=0, sticky="ew", pady=(6, 0))
        hash_fields.columnconfigure((0, 1), weight=1)
        self._field(hash_fields, "Hash property", self._hash_mode, 0, kind="combo",
                    values=tuple(_HASH_MODES), width=28)
        digest_field = ttk.Frame(hash_fields, padding=(0, 0, 7, 0))
        digest_field.grid(row=0, column=1, sticky="ew")
        ttk.Label(digest_field, text="Digest bits").grid(row=0, column=0, sticky="w")
        ttk.Label(digest_field, text="256").grid(row=1, column=0, sticky="w")
        attempts_field = self._field(hash_fields, "Attempt limit", self._hash_attempts, 0,
                                     kind="spin", low=1, high=100000, width=12)
        attempts_field.master.grid_configure(row=1)
        seed_field = self._field(hash_fields, "Hash seed", self._hash_seed, 1, width=18)
        seed_field.master.grid_configure(row=1)
        self._hash_button = ttk.Button(hashing, text="Run hash search", command=self._run_hash)
        self._hash_button.grid(row=2, column=0, sticky="w", pady=(6, 0))

        result_area = ttk.LabelFrame(self._content, text="Run status and results", padding=8)
        result_area.grid(row=6, column=0, sticky="ew")
        result_area.columnconfigure(0, weight=1)
        result_area.rowconfigure(3, weight=1)
        result_actions = ttk.Frame(result_area)
        result_actions.grid(row=0, column=0, sticky="ew")
        self._save_metrics_button = ttk.Button(
            result_actions, text="Export metrics CSV…", command=self._save_metrics_csv
        )
        self._save_metrics_button.grid(row=0, column=0, sticky="w")
        self._save_metrics_button.state(["disabled"])
        self._save_button = ttk.Button(result_actions, text="Save CSV…", command=self._save_csv)
        self._save_button.grid(row=0, column=1, sticky="w", padx=(6, 0))
        self._save_button.state(["disabled"])
        default_font = tkfont.nametofont("TkDefaultFont")
        style = ttk.Style(self.widget)
        style.configure(
            "Analysis.Treeview",
            rowheight=default_font.metrics("linespace") + 8,
        )
        self._results = ttk.Treeview(
            result_area,
            columns=("workload", "measurement", "value", "detail"),
            show="headings",
            height=8,
            style="Analysis.Treeview",
        )
        result_examples = {
            "workload": "Synthetic specimen",
            "measurement": "Signature verification (µs)",
            "value": "61 / 128",
            "detail": "Observed 47.65625%",
        }
        for column, title, width in (
            ("workload", "Workload", 120),
            ("measurement", "Measurement", 125),
            ("value", "Value", 105),
            ("detail", "Detail", 310),
        ):
            self._results.heading(column, text=title)
            min_width = max(
                width,
                default_font.measure(title) + 24,
                default_font.measure(result_examples[column]) + 20,
            )
            self._results.column(
                column, width=min_width, minwidth=min_width,
                anchor="w", stretch=column == "detail",
            )
        self._results.grid(row=1, column=0, sticky="ew", pady=(5, 0))
        results_xscroll = scrollbar(result_area, orient=tk.HORIZONTAL, command=self._results.xview)
        results_xscroll.grid(row=2, column=0, sticky="ew")
        self._results.configure(xscrollcommand=results_xscroll.set)
        self._details = tk.Text(result_area, height=11, wrap=tk.WORD, state=tk.DISABLED)
        self._details.grid(row=3, column=0, sticky="ew", pady=(6, 0))
        metrics = ttk.LabelFrame(self._content, text="Core operation metrics", padding=8)
        metrics.grid(row=7, column=0, sticky="ew", pady=(8, 0))
        metrics.columnconfigure(0, weight=1)
        self._metrics = ttk.Treeview(
            metrics,
            columns=("operation", "elapsed", "success", "encoded", "frame", "context"),
            show="headings",
            height=6,
            style="Analysis.Treeview",
        )
        metric_examples = {
            "operation": "reconnect_recovery",
            "elapsed": "123456789012345",
            "success": "success",
            "encoded": "unavailable",
            "frame": "unavailable",
            "context": "{'verification_scope': 'captured_committed_prefix'}",
        }
        for column, title, width in (
            ("operation", "Operation", 115),
            ("elapsed", "Elapsed (ns)", 95),
            ("success", "Success", 70),
            ("encoded", "Encoded bytes", 90),
            ("frame", "Frame bytes", 90),
            ("context", "Public context", 280),
        ):
            self._metrics.heading(column, text=title)
            min_width = max(
                width,
                default_font.measure(title) + 24,
                default_font.measure(metric_examples[column]) + 20,
            )
            self._metrics.column(
                column, width=min_width, minwidth=min_width,
                anchor="w", stretch=column == "context",
            )
        self._metrics.grid(row=0, column=0, sticky="ew")
        metrics_xscroll = scrollbar(metrics, orient=tk.HORIZONTAL, command=self._metrics.xview)
        metrics_xscroll.grid(row=1, column=0, sticky="ew")
        self._metrics.configure(xscrollcommand=metrics_xscroll.set)
        self._content.bind("<Configure>", self._resize_wrapped_text, add="+")

        footer = ttk.Frame(frame, padding=(12, 5, 12, 7))
        footer.grid(row=1, column=0, columnspan=2, sticky="ew")
        footer.columnconfigure(0, weight=1)
        self._status_label = ttk.Label(footer, textvariable=self._status, wraplength=700)
        self._status_label.grid(
            row=0, column=0, columnspan=4, sticky="ew", pady=(0, 4)
        )
        ttk.Label(footer, textvariable=self._progress_text, width=23).grid(
            row=1, column=0, sticky="w", padx=(0, 7)
        )
        self._progress = ttk.Progressbar(footer, mode="determinate", maximum=1, value=0)
        self._progress.grid(row=1, column=1, sticky="ew")
        self._cancel_button = ttk.Button(footer, text="Cancel", command=self._cancel_job)
        self._cancel_button.grid(row=1, column=2, sticky="e", padx=(7, 0))
        self._cancel_button.state(["disabled"])
        self._finish_button = ttk.Button(
            footer, text="Finish sampling", command=self._finish_sampling
        )
        self._finish_button.grid(row=1, column=3, sticky="e", padx=(6, 0))
        self._finish_button.state(["disabled"])
        self._input_widgets = [
            child for child in _walk(self._content)
            if isinstance(child, (ttk.Entry, ttk.Spinbox, ttk.Combobox))
        ]
        self._scroller.bind_to(self._content)

    def _field(
        self, parent, label: str, variable: tk.StringVar, column: int, *,
        kind: str = "entry", width: int = 12, low=0, high=1, increment=1,
        values: tuple[str, ...] = (), on_change=None,
    ):
        wrapper = ttk.Frame(parent, padding=(0, 0, 7, 0))
        wrapper.grid(row=0, column=column, sticky="ew")
        ttk.Label(wrapper, text=label).grid(row=0, column=0, sticky="w")
        if kind == "spin":
            widget = ttk.Spinbox(
                wrapper, textvariable=variable, from_=low, to=high, increment=increment, width=width
            )
        elif kind == "combo":
            widget = ttk.Combobox(
                wrapper, textvariable=variable, values=values, state="readonly", width=width
            )
            if on_change is not None:
                widget.bind("<<ComboboxSelected>>", on_change, add="+")
        else:
            widget = ttk.Entry(wrapper, textvariable=variable, width=width)
        widget.grid(row=1, column=0, sticky="ew")
        wrapper.columnconfigure(0, weight=1)
        return widget

    def _content_resized(self, _event=None) -> None:
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))

    def _canvas_resized(self, event) -> None:
        self._canvas.itemconfigure(self._canvas_window, width=event.width)

    def _mousewheel(self, event):
        return self._scroller.scroll(event)

    def _resize_wrapped_text(self, event) -> None:
        width = max(240, event.width - 32)
        for child in _children(self._content):
            if isinstance(child, ttk.Label) and child.cget("wraplength"):
                child.configure(wraplength=width)

    def _mode_changed(self, _event=None) -> None:
        maximum = 127 if self._mode.get() == "plaintext" else 255
        self._bit_spinbox.configure(to=maximum)
        try:
            if int(self._bit_index.get()) > maximum:
                self._bit_index.set(str(maximum))
        except ValueError:
            self._bit_index.set("0")

    def _refresh_controls(self) -> None:
        enabled = not self._closed and not self._busy
        state = ["!disabled"] if enabled else ["disabled"]
        for button in (
            self._trial_button,
            self._batch_button,
            self._local_button,
            self._resource_button,
            self._audit_metric_button,
            self._make_specimen_button,
            self._verify_specimen_button,
            self._hash_button,
        ):
            button.state(state)
        for input_widget in self._input_widgets:
            input_widget.state(["!disabled"] if enabled else ["disabled"])
        network_enabled = enabled and self._connection_state == "connected"
        self._network_button.state(["!disabled"] if network_enabled else ["disabled"])
        self._cancel_button.state(["!disabled"] if self._busy and not self._closed else ["disabled"])
        finish_enabled = self._busy and self._job_kind == "resources" and not self._closed
        self._finish_button.state(["!disabled"] if finish_enabled else ["disabled"])
        self._save_button.state(
            ["!disabled"]
            if enabled and isinstance(self._last_result, (LabResult, BenchmarkResult, ResourceResult, HashSearchResult))
            else ["disabled"]
        )
        self._save_metrics_button.state(
            ["!disabled"]
            if enabled and self._has_operation_metrics
            else ["disabled"]
        )

    def _read_workload(self, repetitions_variable: tk.StringVar, max_repetitions: int):
        raw_sizes = [part.strip() for part in self._sizes.get().split(",")]
        sizes = tuple(int(part) for part in raw_sizes if part)
        if (
            not raw_sizes
            or len(sizes) != len(raw_sizes)
            or not 1 <= len(sizes) <= 3
            or len(set(sizes)) != len(sizes)
            or any(size not in _ALLOWED_SIZES for size in sizes)
        ):
            raise ValueError("Choose one to three distinct sizes: 64, 1024, or 16384 bytes")
        warmups = int(self._warmups.get())
        repetitions = int(repetitions_variable.get())
        if not 0 <= warmups <= 10:
            raise ValueError("Warmups must be between 0 and 10")
        if not 1 <= repetitions <= max_repetitions:
            raise ValueError(f"Repetitions must be between 1 and {max_repetitions}")
        return sizes, warmups, repetitions

    def _begin_job(self, kind: str, work, *, resource_stop: Event | None = None) -> None:
        if self._closed or self._busy:
            return
        self._busy = True
        self._job_kind = kind
        self._resource_stop = resource_stop
        self._status.set(self._starting_text(kind))
        self._progress_text.set("Starting…")
        self._progress.configure(maximum=1, value=0)
        self._refresh_controls()
        try:
            self._job.start(work)
        except RuntimeError as error:
            self._busy = False
            self._job_kind = None
            self._status.set(f"Could not start job: {error}")
            self._refresh_controls()

    @staticmethod
    def _starting_text(kind: str) -> str:
        return {
            "trial": "Running one synthetic AES trial…",
            "batch": "Running the sensitivity batch…",
            "local": "Running local cryptographic benchmarks…",
            "network": "Sending sequential benchmark messages and waiting for verified receipts…",
            "resources": "Sampling process resources…",
            "audit_verify": "Verifying the captured committed audit prefix…",
            "specimen_make": "Generating a synthetic signature specimen…",
            "specimen_verify": "Verifying the editable signature specimen…",
            "hash": "Searching synthetic hashes within the chosen attempt limit…",
            "export": "Saving the selected CSV result…",
            "metrics_export": "Saving retained operation metrics…",
        }.get(kind, "Running analysis…")

    def _report_progress(self, emit, completed: int, total: int) -> None:
        emit("progress", (completed, total))

    def _run_trial(self) -> None:
        try:
            seed = _parse_seed(self._seed.get())
            case_index = int(self._case_index.get())
            mode = self._mode.get()
            bit_index = int(self._bit_index.get())
        except ValueError as error:
            self._status.set(f"Check the trial inputs: {error}")
            return
        self._begin_job(
            "trial", lambda cancel, _emit: sensitivity_trial(seed, case_index, mode, bit_index)
        )

    def _run_batch(self) -> None:
        try:
            seed = _parse_seed(self._seed.get())
            cases = int(self._batch_cases.get())
            if not 1 <= cases <= 50:
                raise ValueError("Batch cases must be between 1 and 50")
        except ValueError as error:
            self._status.set(f"Check the batch inputs: {error}")
            return

        def work(cancel, emit):
            return run_sensitivity(
                seed=seed,
                cases=cases,
                cancel=cancel,
                progress=lambda completed, total: (
                    self._report_progress(emit, completed, total)
                    if completed % 128 == 0 or completed == total else None
                ),
            )

        self._begin_job("batch", work)

    def _run_local(self) -> None:
        try:
            sizes, warmups, repetitions = self._read_workload(self._local_repetitions, 1000)
        except ValueError as error:
            self._status.set(f"Check the local benchmark inputs: {error}")
            return

        def work(cancel, emit):
            total = len(sizes) * 6 * repetitions
            emit("progress", (0, total))
            result = run_local_benchmarks(sizes, warmups, repetitions, cancel)
            emit("progress", (total if result.complete else 0, total))
            return result

        self._begin_job("local", work)

    def _run_network(self) -> None:
        if self._connection_state != "connected":
            self._status.set("Connect to a peer before starting a network benchmark")
            return
        try:
            sizes, warmups, repetitions = self._read_workload(self._network_repetitions, 100)
        except ValueError as error:
            self._status.set(f"Check the network benchmark inputs: {error}")
            return
        evidence_mode = self._evidence_mode.get()

        def work(cancel, emit):
            total = len(sizes) * repetitions
            emit("progress", (0, total))
            result = run_network_benchmark(
                self.service,
                sizes=sizes,
                warmups=warmups,
                repetitions=repetitions,
                cancel=cancel,
                evidence_mode=evidence_mode,
            )
            emit("progress", (total if result.complete else 0, total))
            return result

        self._begin_job("network", work)

    def _run_resources(self) -> None:
        try:
            interval = float(self._resource_interval.get())
            if not math.isfinite(interval) or interval <= 0:
                raise ValueError("Sample interval must be finite and positive")
        except ValueError as error:
            self._status.set(f"Check the resource inputs: {error}")
            return
        stop = Event()

        def work(_cancel, emit):
            emit("progress", (0, 1))
            result = sample_resources(os.getpid(), stop, interval_s=interval)
            emit("progress", (1, 1))
            return result

        self._begin_job("resources", work, resource_stop=stop)

    def _run_audit_metric(self) -> None:
        def work(cancel, _emit):
            return self.service.verify_audit(checkpoint=None, cancel=cancel)

        self._begin_job("audit_verify", work)

    def _generate_specimen(self) -> None:
        def work(_cancel, _emit):
            public_key, signed_bytes, signature, sign_ns = make_timed_specimen()
            edited_bytes = bytes((signed_bytes[0] ^ 1,)) + signed_bytes[1:]
            edited_signature = bytes((signature[0] ^ 1,)) + signature[1:]
            return (
                public_key,
                signed_bytes,
                signature,
                verify_specimen(public_key, signed_bytes, signature),
                verify_specimen(public_key, edited_bytes, signature),
                verify_specimen(public_key, signed_bytes, edited_signature),
                sign_ns,
            )

        self._begin_job("specimen_make", work)

    def _run_hash(self) -> None:
        if self._closed or self._busy:
            return
        try:
            mode = _HASH_MODES.get(self._hash_mode.get())
            attempts = int(self._hash_attempts.get())
            seed = int(self._hash_seed.get())
            if mode not in HASH_PROPERTIES:
                raise ValueError("Choose a hash property")
            if not 1 <= attempts <= 100000:
                raise ValueError("Attempt limit must be between 1 and 100000")
            if not 0 <= seed < 2**64:
                raise ValueError("Hash seed must be from 0 to 2^64 - 1")
        except ValueError as error:
            self._status.set(f"Check the hashing inputs: {error}")
            return
        cancel = Event()
        self._hash_cancel = cancel

        def work(_cancel, emit):
            return run_hash_search(
                mode, max_attempts=attempts, seed=seed, cancel=cancel,
                on_progress=lambda completed, total: emit("progress", (completed, total)),
            )

        self._begin_job("hash", work)

    def _verify_specimen(self) -> None:
        try:
            public_key = bytes.fromhex(self._specimen_public.get().strip())
            signed_bytes = bytes.fromhex(self._specimen_signed.get().strip())
            signature = bytes.fromhex(self._specimen_signature.get().strip())
        except ValueError:
            self._status.set("Specimen rejected: fields must contain hexadecimal bytes")
            return
        self._begin_job(
            "specimen_verify",
            lambda _cancel, _emit: verify_specimen(public_key, signed_bytes, signature),
        )

    def _cancel_job(self) -> None:
        if self._closed or not self._busy:
            return
        if self._job_kind == "hash" and self._hash_cancel is not None:
            self._hash_cancel.set()
            self._status.set("Cancel requested; retaining partial hashing results…")
            return
        if self._job_kind == "resources" and self._resource_stop is not None:
            self._resource_stop.set()
        self._status.set("Canceled; this run is incomplete")
        self._progress_text.set("Canceled")
        self._busy = False
        self._job_kind = None
        self._refresh_controls()
        self._job.cancel()

    def _finish_sampling(self) -> None:
        if self._closed or not self._busy or self._job_kind != "resources":
            return
        if self._resource_stop is not None:
            self._resource_stop.set()
        self._status.set("Finishing resource sampling and keeping the collected window…")
        self._progress_text.set("Finishing sampler")

    def _job_result(self, kind: str, value: object) -> None:
        if self._closed:
            return
        operation = self._job_kind
        if kind == "progress":
            if isinstance(value, tuple) and len(value) == 2:
                completed, total = value
                if type(completed) is int and type(total) is int and total > 0:
                    self._progress.configure(maximum=total, value=min(completed, total))
                    self._progress_text.set(f"{completed:,} of {total:,}")
            return
        self._busy = False
        self._job_kind = None
        self._resource_stop = None
        self._hash_cancel = None
        self._refresh_controls()
        if kind == "error":
            self._status.set(f"Analysis failed: {value}")
            return
        if kind != "result":
            return
        if operation == "specimen_make" and isinstance(value, tuple) and len(value) == 7:
            (
                public_key, signed_bytes, signature,
                valid, edited_bytes_valid, edited_signature_valid,
                sign_ns,
            ) = value
            self._specimen_public.set(public_key.hex())
            self._specimen_signed.set(signed_bytes.hex())
            self._specimen_signature.set(signature.hex())
            self._specimen_timing.set(f"Signature generation: {sign_ns / 1000:g} µs (excludes key generation)")
            self._status.set("Synthetic signature specimen generated")
            self._clear_results()
            self._add_row("Synthetic specimen", "Signature generation (µs)", sign_ns / 1000,
                          "Ed25519 signing only; key generation and encoding excluded")
            self._details_text(
                "Synthetic public data, separate from live records.\n"
                f"Original specimen: {'valid' if valid else 'rejected'}.\n"
                f"Edited signed bytes: {'valid' if edited_bytes_valid else 'rejected'}.\n"
                f"Edited signature: {'valid' if edited_signature_valid else 'rejected'}."
            )
            return
        if operation == "specimen_verify" and isinstance(value, bool):
            self._status.set("Specimen signature is valid" if value else "Specimen signature rejected")
            self._details_text(
                "The public key, signed bytes, and signature match."
                if value else "The edited or malformed specimen did not verify."
            )
            return
        if operation in ("export", "metrics_export"):
            self._status.set(f"CSV saved: {value}")
            return
        if operation == "audit_verify":
            try:
                event = ServiceEvent("operation_metrics", {
                    "operation": "audit_verify",
                    "elapsed_ns": value.elapsed_ns,
                    "success": value.valid,
                    "context": {
                        "verified_records": value.verified_records,
                        "checkpoint_checked": value.checkpoint_checked,
                        "checkpoint_selected": False,
                        "verification_scope": "captured_committed_prefix",
                        "source": "analysis_audit_report",
                    },
                })
            except AttributeError:
                self._status.set("Audit verification returned an unsupported report")
                return
            self.handle_event(event)
            self._status.set(
                "Audit prefix verified" if value.valid
                else "Audit prefix verification failed; failed measurement retained"
            )
            self._progress_text.set("Verification report received")
            return

        self._last_result = value
        self._last_result_kind = operation
        self._refresh_controls()
        self._progress_text.set("Run finished")
        if isinstance(value, Trial):
            self._status.set("Single synthetic trial complete")
            self._render_trial(value)
        elif isinstance(value, LabResult):
            self._status.set(
                "Sensitivity batch complete" if value.complete else "Sensitivity batch incomplete"
            )
            self._render_lab(value)
        elif isinstance(value, BenchmarkResult):
            self._status.set(
                "Benchmark complete" if value.complete else "Benchmark incomplete"
            )
            self._render_benchmark(value)
        elif isinstance(value, ResourceResult):
            suffix = "; retained window was truncated" if value.window_truncated else ""
            self._status.set(f"Sampling stopped; collected {len(value.samples)} samples{suffix}")
            self._render_resources(value)
        elif isinstance(value, HashSearchResult):
            self._status.set({
                "match": "Hash search: match found",
                "budget_exhausted": "Hash search: no match within the search budget",
                "canceled": "Hash search canceled; partial results retained",
            }[value.outcome])
            self._render_hash(value)
        else:
            self._status.set("Analysis returned an unsupported result")
            self._last_result = None
            self._last_result_kind = None
            self._refresh_controls()

    def _clear_results(self) -> None:
        for row in self._results.get_children(""):
            self._results.delete(row)
        self._details_text("")

    def _details_text(self, value: str) -> None:
        self._details.configure(state=tk.NORMAL)
        self._details.delete("1.0", tk.END)
        if value:
            self._details.insert("1.0", value)
        self._details.configure(state=tk.DISABLED)

    def _add_row(self, workload: object, measurement: object, value: object, detail: object = "") -> None:
        self._results.insert(
            "", tk.END,
            values=(self._display(workload), self._display(measurement), self._display(value), self._display(detail)),
        )

    @staticmethod
    def _display(value: object) -> str:
        if value is None:
            return "unavailable"
        if isinstance(value, float):
            return f"{value:,.6g}"
        return str(value)

    def _render_trial(self, trial: Trial) -> None:
        self._clear_results()
        self._add_row("Ciphertext", "Bits changed", f"{(trial.difference.bit_percent * 128 / 100):g} / 128", f"Observed {trial.difference.bit_percent:g}%")
        self._add_row("Ciphertext", "Bytes changed", f"{(trial.difference.byte_percent * 16 / 100):g} / 16", f"Observed {trial.difference.byte_percent:g}%")
        self._add_row("Ciphertext", "Hex positions changed", f"{(trial.difference.hex_percent * 32 / 100):g} / 32", f"Observed {trial.difference.hex_percent:g}%")
        bit_operand = "plaintext block" if trial.mode == "plaintext" else "key"
        rows = [
            f"Mode: {trial.mode} · case {trial.case_index} · bit index {trial.bit_index}",
            "Ideal-model expectations: 50% of output bits, 99.609375% of output bytes, and 93.75% of lowercase hex positions change. These are expectations, not pass/fail thresholds.",
            "A plaintext-bit flip illustrates diffusion; a key-bit flip illustrates confusion.",
            "Formulas: changed bits / 128 × 100; changed bytes / 16 × 100; changed lowercase hex positions / 32 × 100.",
            f"Observed: bits {trial.difference.bit_percent:g}% · bytes {trial.difference.byte_percent:g}% · hex {trial.difference.hex_percent:g}%.",
            f"Original synthetic key: {trial.key.hex()}",
            f"Original synthetic block: {trial.block.hex()}",
            f"Modified {bit_operand}: key {trial.modified_key.hex()} · block {trial.modified_block.hex()}",
            f"Baseline ciphertext: {trial.baseline_ciphertext.hex()}",
            f"Modified ciphertext: {trial.modified_ciphertext.hex()}",
        ]
        self._details_text("\n".join(rows))

    def _render_lab(self, result: LabResult) -> None:
        self._clear_results()
        for mode in ("plaintext", "key"):
            for metric in ("bit_percent", "byte_percent", "hex_percent"):
                stats = result.summary[mode][metric]
                self._add_row(
                    mode, metric, stats["mean"],
                    f"n={stats['count']} · min {self._display(stats['min'])} · max {self._display(stats['max'])} · population SD {self._display(stats['population_std'])}",
                )
        self._details_text(
            f"Retained {len(result.trials)} synthetic trials across {result.cases} cases. "
            f"Complete: {result.complete}. Every key, block, and flip is synthetic."
        )

    def _render_benchmark(self, result: BenchmarkResult) -> None:
        self._clear_results()
        for summary in result.summary:
            operation = summary.get("operation")
            label = {"sign": "Signature generation", "verify": "Signature verification"}.get(operation)
            divisor = 1000 if label else 1
            unit = "µs" if label else "ns"
            mean = summary.get("mean_ns")
            p95 = summary.get("p95_ns")
            self._add_row(
                summary.get("payload_bytes"), f"{label} ({unit})" if label else operation,
                mean / divisor if mean is not None else None,
                f"n={summary.get('count')} · p95 {self._display(p95 / divisor if p95 is not None else None)} {unit} · "
                f"goodput {self._display(summary.get('goodput_bytes_s'))} B/s · "
                f"characters {self._display(summary.get('characters_s'))}/s",
            )
        for sample in result.samples[:_RESULT_ROWS]:
            operation = sample.get("operation")
            label = {"sign": "Signature generation", "verify": "Signature verification"}.get(operation)
            elapsed = sample.get("elapsed_ns")
            details = []
            for key in ("message_id", "characters", "frame_bytes", "error"):
                if sample.get(key) is not None:
                    details.append(f"{key}={sample[key]}")
            self._add_row(
                sample.get("payload_bytes"), f"{label} (µs)" if label else operation,
                elapsed / 1000 if label and elapsed is not None else elapsed,
                f"{'success' if sample.get('success') else 'failed'} · " + " · ".join(details),
            )
        omitted = max(0, len(result.samples) - _RESULT_ROWS)
        self._details_text(
            f"{len(result.samples)} measured samples; showing at most {_RESULT_ROWS}. "
            f"{omitted} rows omitted from this view. Complete: {result.complete}."
        )

    def _render_resources(self, result: ResourceResult) -> None:
        self._clear_results()
        for sample in result.samples[-_RESOURCE_ROWS:]:
            self._add_row(
                sample.monotonic_ns, "CPU percent", sample.cpu_percent,
                f"RSS {sample.rss_bytes:,} bytes",
            )
        self._add_row("retained window", "Peak observed RSS", result.peak_observed_rss_bytes, "bytes")
        self._details_text(
            f"Sampling interval: {result.interval_s:g} seconds. "
            f"Peak RSS is the maximum among {len(result.samples)} retained samples. "
            f"Window truncated: {result.window_truncated}."
        )

    def _render_hash(self, result: HashSearchResult) -> None:
        self._clear_results()
        title = result.mode.replace("_", " ").capitalize()
        self._add_row(title, "Candidate attempts", result.attempts,
                      f"Limit {result.max_attempts}; seed {result.seed}")
        self._add_row(title, "Elapsed (µs)", result.elapsed_ns / 1000,
                      "Search including progress callbacks; target preparation excluded")
        self._add_row(title, "Digest bits", result.digest_bits,
                      "Full SHA-256 bounded search")
        rows = [HASH_PROPERTIES[result.mode], result.interpretation,
                f"Outcome: {result.outcome}; complete: {result.complete}.",
                f"Target / matching digest: {result.target_digest or 'unavailable'}"]
        for label, value, digest in (
            ("Input A", result.input_a, result.input_a_sha256),
            ("Input B", result.input_b, result.input_b_sha256),
        ):
            if value is not None:
                rows.extend([f"{label} (synthetic hex): {value.hex()}",
                             f"{label} full SHA-256: {digest}"])
        rows.append(f"Definitions: {HASH_SOURCE}")
        self._details_text("\n".join(rows))

    def _save_csv(self) -> None:
        if self._closed or self._busy or self._last_result is None:
            return
        result = self._last_result
        if isinstance(result, LabResult):
            path_text = filedialog.askdirectory(
                parent=self.widget.winfo_toplevel(),
                title="Choose a folder for sensitivity CSV files",
                mustexist=False,
            )
        else:
            path_text = filedialog.asksaveasfilename(
                parent=self.widget.winfo_toplevel(),
                title="Save analysis CSV",
                defaultextension=".csv",
                filetypes=(("CSV files", "*.csv"), ("All files", "*")),
            )
        if not path_text:
            return
        path = Path(path_text)

        def work(_cancel, _emit):
            if isinstance(result, LabResult):
                return export_lab(result, path)
            if isinstance(result, BenchmarkResult):
                export_benchmark(result, path)
                return path
            if isinstance(result, ResourceResult):
                self._export_resources(result, path)
                return path
            if isinstance(result, HashSearchResult):
                export_hash_search(result, path)
                return path
            raise ValueError("This result type does not have a CSV export")

        self._begin_job("export", work)

    def _save_metrics_csv(self) -> None:
        if self._closed or self._busy:
            return
        result = self._operation_metrics.result()
        if not result.samples:
            return
        path_text = filedialog.asksaveasfilename(
            parent=self.widget.winfo_toplevel(),
            title="Export retained operation metrics",
            defaultextension=".csv",
            filetypes=(("CSV files", "*.csv"), ("All files", "*")),
        )
        if not path_text:
            return
        path = Path(path_text)
        metadata = dict(result.metadata)
        metadata["policy_limits"] = asdict(self.service.limits)
        result = BenchmarkResult(
            metadata=metadata,
            samples=result.samples,
            summary=result.summary,
            complete=result.complete,
        )

        def work(_cancel, _emit):
            export_benchmark(result, path)
            return path

        self._begin_job("metrics_export", work)

    @staticmethod
    def _export_resources(result: ResourceResult, path: Path) -> None:
        stream = io.StringIO(newline="")
        writer = csv.DictWriter(
            stream,
            fieldnames=(
                "sample_index", "monotonic_ns", "cpu_percent", "rss_bytes",
                "interval_s", "peak_observed_rss_bytes", "window_truncated",
            ),
            lineterminator="\n",
        )
        writer.writeheader()
        for index, sample in enumerate(result.samples):
            writer.writerow({
                "sample_index": index,
                "monotonic_ns": sample.monotonic_ns,
                "cpu_percent": sample.cpu_percent,
                "rss_bytes": sample.rss_bytes,
                "interval_s": result.interval_s,
                "peak_observed_rss_bytes": result.peak_observed_rss_bytes,
                "window_truncated": str(result.window_truncated).lower(),
            })
        atomic_write(path, stream.getvalue().encode("utf-8"), private=False, secure_parent=False)

    def handle_event(self, event) -> None:
        if self._closed:
            return
        if getattr(event, "kind", None) == "operation_metrics":
            self._operation_metrics.add(event)
            self._has_operation_metrics = True
            if self._metrics_redraw_id is None:
                self._metrics_redraw_id = self.widget.after_idle(self._flush_operation_metrics)
            self._refresh_controls()
            return
        if getattr(event, "kind", None) != "state":
            return
        data = getattr(event, "data", {})
        if not isinstance(data, dict):
            return
        state = data.get("state")
        if isinstance(state, str):
            self._connection_state = state
            self._refresh_controls()
            if state != "connected":
                self._status.set("Network benchmark is available when a peer is connected")

    def _flush_operation_metrics(self) -> None:
        self._metrics_redraw_id = None
        if self._closed:
            return
        self._render_operation_metrics()

    def _render_operation_metrics(self) -> None:
        if self._closed:
            return
        samples = self._operation_metrics.result().samples
        for row in self._metrics.get_children(""):
            self._metrics.delete(row)
        for sample in samples[-_RESULT_ROWS:]:
            self._metrics.insert("", tk.END, values=(
                sample.get("operation", ""),
                self._display(sample.get("elapsed_ns")),
                "success" if sample.get("success") else "failed",
                self._display(sample.get("encoded_bytes")),
                self._display(sample.get("frame_bytes")),
                repr(sample.get("context", {})),
            ))

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._metrics_redraw_id is not None:
            try:
                self.widget.after_cancel(self._metrics_redraw_id)
            except tk.TclError:
                pass
            self._metrics_redraw_id = None
        if self._resource_stop is not None:
            self._resource_stop.set()
        if self._hash_cancel is not None:
            self._hash_cancel.set()
        self._job.close()


def _children(widget):
    for child in widget.winfo_children():
        yield child


def _walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from _walk(child)


def register_analysis(app, service) -> AnalysisTab:
    """Construct and add the Analysis tab to an existing application shell."""
    tab = AnalysisTab(app.notebook, service)
    app.add_tab("Analysis", tab)
    return tab
