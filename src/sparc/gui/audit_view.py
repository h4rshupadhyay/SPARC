"""Main-thread audit report and checkpoint controls."""

from __future__ import annotations

from pathlib import Path
import tkinter as tk
from tkinter import filedialog, ttk

from ..audit_format import AuditReport
from .jobs import JobController
from .scrolling import scrollbar


class AuditTab:
    """Display a durable writer head and cancellable audit verification."""

    def __init__(self, parent: ttk.Notebook, service) -> None:
        self.service = service
        self.widget = ttk.Frame(parent, padding=10)
        self._closed = False
        self._busy = False
        self._job_kind: str | None = None
        self._job_checkpoint: Path | None = None
        self._head = None
        self._status = tk.StringVar(master=self.widget, value="Loading durable audit head")
        self._head_text = tk.StringVar(master=self.widget, value="Durable writer head unavailable")
        self._checkpoint_text = tk.StringVar(master=self.widget, value="No checkpoint selected")
        self._metrics_text = tk.StringVar(master=self.widget, value="Audit append metrics unavailable")
        self._error = tk.StringVar(master=self.widget, value="")
        self._job = JobController(self.widget, self._job_result)
        self._build()
        self._start_job("head")

    def _build(self) -> None:
        frame = self.widget
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(5, weight=1)
        ttk.Label(frame, textvariable=self._status).grid(row=0, column=0, sticky="w")
        self._head_label = ttk.Label(frame, textvariable=self._head_text, wraplength=850)
        self._head_label.grid(
            row=1, column=0, sticky="ew", pady=(4, 8)
        )

        controls = ttk.Frame(frame)
        controls.grid(row=2, column=0, sticky="ew")
        self._verify_button = ttk.Button(
            controls, text="Verify available chain", command=lambda: self._start_job("verify")
        )
        controls.columnconfigure((0, 1), weight=1, uniform="audit-actions")
        self._verify_button.grid(row=0, column=0, sticky="ew", padx=(0, 5), pady=(0, 4))
        self._selected_verify_button = ttk.Button(
            controls, text="Verify selected checkpoint", command=self._choose_checkpoint
        )
        self._selected_verify_button.grid(row=0, column=1, sticky="ew", padx=(5, 0), pady=(0, 4))
        self._export_button = ttk.Button(
            controls, text="Export checkpoint", command=self._choose_export_path
        )
        self._export_button.grid(row=1, column=0, sticky="ew", padx=(0, 5))
        self._refresh_button = ttk.Button(
            controls, text="Refresh head", command=lambda: self._start_job("head")
        )
        self._refresh_button.grid(row=1, column=1, sticky="ew", padx=(5, 0))

        self._checkpoint_label = ttk.Label(frame, textvariable=self._checkpoint_text, wraplength=850)
        self._checkpoint_label.grid(
            row=3, column=0, sticky="w", pady=(7, 0)
        )
        ttk.Label(frame, textvariable=self._metrics_text).grid(
            row=4, column=0, sticky="w", pady=(4, 0)
        )
        details = ttk.Frame(frame)
        details.grid(row=5, column=0, sticky="nsew", pady=(7, 0))
        details.columnconfigure(0, weight=1)
        details.rowconfigure(0, weight=1)
        self._details = tk.Text(details, height=15, wrap=tk.WORD, state=tk.DISABLED)
        self._details.grid(row=0, column=0, sticky="nsew")
        details_scroll = scrollbar(details, orient=tk.VERTICAL, command=self._details.yview)
        details_scroll.grid(row=0, column=1, sticky="ns")
        self._details.configure(yscrollcommand=details_scroll.set)
        self._error_label = ttk.Label(frame, textvariable=self._error, wraplength=850)
        self._error_label.grid(
            row=6, column=0, sticky="w", pady=(5, 0)
        )
        frame.bind("<Configure>", self._resize_wrapped_text, add="+")

    def _resize_wrapped_text(self, event) -> None:
        wrap = max(240, event.width - 24)
        for label in (self._head_label, self._checkpoint_label, self._error_label):
            label.configure(wraplength=wrap)

    def _choose_checkpoint(self) -> None:
        selected = filedialog.askopenfilename(
            parent=self.widget.winfo_toplevel(),
            title="Select an audit checkpoint",
            filetypes=(("Audit checkpoint", "*.json"), ("All files", "*")),
        )
        if selected:
            self._start_job("verify", Path(selected))

    def _choose_export_path(self) -> None:
        selected = filedialog.asksaveasfilename(
            parent=self.widget.winfo_toplevel(),
            title="Export audit checkpoint",
            defaultextension=".json",
            filetypes=(("Audit checkpoint", "*.json"), ("All files", "*")),
        )
        if selected:
            self._start_job("export", Path(selected))

    def _start_job(self, kind: str, checkpoint: Path | None = None) -> None:
        if self._closed or self._busy:
            return
        self._busy = True
        self._job_kind = kind
        self._job_checkpoint = checkpoint
        self._error.set("")
        self._status.set({
            "head": "Reading durable writer head…",
            "verify": "Verifying captured audit prefix…",
            "export": "Exporting audit checkpoint…",
        }[kind])
        self._set_controls_enabled(False)

        def work(cancel, _emit):
            if kind == "head":
                return self.service.audit_head(cancel=cancel)
            if kind == "verify":
                return self.service.verify_audit(checkpoint, cancel=cancel)
            self.service.export_audit_checkpoint(checkpoint, cancel=cancel)
            return None

        try:
            self._job.start(work)
        except RuntimeError as exc:
            self._busy = False
            self._job_kind = None
            self._status.set("Audit operation could not start")
            self._error.set(str(exc))
            self._set_controls_enabled(True)

    def _set_controls_enabled(self, enabled: bool) -> None:
        state = ["!disabled"] if enabled and not self._closed else ["disabled"]
        for button in (
            self._verify_button,
            self._selected_verify_button,
            self._export_button,
            self._refresh_button,
        ):
            button.state(state)

    def _job_result(self, kind: str, value: object) -> None:
        if self._closed:
            return
        operation = self._job_kind
        self._busy = False
        self._job_kind = None
        self._set_controls_enabled(True)
        if kind == "error":
            self._status.set("Audit operation failed")
            self._error.set(str(value))
            return
        if kind != "result":
            return
        if operation == "head" and isinstance(value, dict):
            self._head = dict(value)
            self._head_text.set(
                "Durable writer head (not a verification result): "
                f"record {value.get('last_record_number')} · "
                f"hash {value.get('last_record_hash')} · "
                f"log {value.get('log_id')}"
            )
            self._status.set("Durable writer head loaded")
        elif operation == "verify" and isinstance(value, AuditReport):
            self._show_report(value, self._job_checkpoint)
        elif operation == "export":
            self._status.set("Checkpoint exported")
            self._error.set("")

    def _show_report(self, report: AuditReport, checkpoint: Path | None) -> None:
        if checkpoint is None:
            checkpoint_status = "Available chain only; no checkpoint selected"
        elif report.valid and report.checkpoint_checked:
            checkpoint_status = "Selected checkpoint matched the verified prefix"
        else:
            checkpoint_status = "Selected checkpoint did not match the verified prefix"
        self._checkpoint_text.set(checkpoint_status)
        if report.elapsed_ns > 0:
            rate = report.verified_records / (report.elapsed_ns / 1_000_000_000)
            rate_text = f"{rate:g} records/s"
        else:
            rate_text = "unavailable"
        rows = [
            "Scope: committed prefix captured for this verification; the displayed writer head is a separate snapshot",
            f"Valid: {report.valid}",
            f"Verified records: {report.verified_records}",
            f"First failed record: {report.first_failed_record if report.first_failed_record is not None else 'none'}",
            f"Reason: {report.reason}",
            f"Verification throughput: {rate_text}",
        ]
        self._details.configure(state=tk.NORMAL)
        self._details.delete("1.0", tk.END)
        self._details.insert("1.0", "\n".join(rows))
        self._details.configure(state=tk.DISABLED)
        self._status.set("Verification complete" if report.valid else "Verification failed")

    def handle_event(self, event) -> None:
        if self._closed or getattr(event, "kind", None) != "operation_metrics":
            return
        data = getattr(event, "data", {})
        if not isinstance(data, dict) or data.get("operation") != "audit" or data.get("success") is not True:
            return
        elapsed_ns = data.get("elapsed_ns")
        if type(elapsed_ns) is not int or elapsed_ns < 0:
            return
        bytes_value = data.get("encoded_bytes")
        encoded = str(bytes_value) if type(bytes_value) is int and bytes_value >= 0 else "unavailable"
        self._metrics_text.set(
            f"Audit append: {elapsed_ns / 1000:g} µs · Encoded bytes/event: {encoded}"
        )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._job.close()
