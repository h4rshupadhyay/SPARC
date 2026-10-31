"""Main-thread offline traffic controls using the existing bounded job runner."""

from __future__ import annotations

from pathlib import Path
from threading import Event
import tkinter as tk
from tkinter import filedialog, ttk

from ..models import SparcError
from ..traffic.capture import find_tshark
from ..traffic.models import TrafficReport
from ..traffic.pdml import export_xml
from ..traffic.sqlite_index import analyze_capture, import_sqlite
from .appearance import install
from .jobs import JobController
from .plot_view import PlotView
from ..analysis.plots import Plot,Series


_ERRORS = {
    "tshark_missing": "Install TShark or choose its executable with Choose TShark.",
    "pyshark_missing": "Install the traffic Python extra: pip install '.[traffic]'.",
    "capture_source_unavailable": "Saved capture source is unavailable.",
    "capture_source_changed": "Saved capture changed during analysis; choose a stable saved capture.",
    "capture_parse_failed": "Could not decode the saved capture.",
    "capture_cancelled": "Traffic work canceled.",
    "capture_cleanup_failed": "Cleanup was not confirmed; decoder termination is uncertain.",
    "traffic_publication_uncertain": "Output publication durability is uncertain; the destination may contain the new artifact.",
    "traffic_output_alias": "Source and output must be different files.",
    "traffic_index_failed": "Could not build the traffic index.",
    "traffic_summary_failed": "Could not summarize the traffic index.",
    "traffic_xml_failed": "Could not export the capture as PDML.",
    "traffic_failed": "Traffic work failed; previous completed results remain available.",
}


class TrafficTab:
    """Own a single offline job and bounded results independent of secure chat."""

    def __init__(self, parent: ttk.Notebook, tshark_path: Path | None = None) -> None:
        self._appearance = install(parent)
        self.widget = ttk.Frame(parent, padding=(12, 8))
        self._root = parent.winfo_toplevel()
        self._closed = False
        self._busy = False
        self._canceling = False
        self._generation = 0
        self._source: Path | None = None
        self._tool_path = tshark_path
        self._last_report: TrafficReport | None = None
        self._done = Event()
        self._terminal = {}
        self._settle_id = None
        self._filter_snapshot = ""
        self._restoring_filter = False
        self._status = tk.StringVar(self.widget, "Open a saved capture to begin")
        self._source_text = tk.StringVar(self.widget, "No capture selected")
        self._tool_text = tk.StringVar(self.widget, str(tshark_path) if tshark_path else "TShark from PATH")
        self._filter = tk.StringVar(self.widget, "")
        self._job = JobController(self._root, self._on_job)
        self._build()
        self._filter_trace = self._filter.trace_add("write", self._filter_changed)
        self._refresh_controls()

    def _build(self) -> None:
        frame = self.widget
        style=ttk.Style(frame)
        style.configure('TrafficPath.TButton',padding=(12,3))
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(6, weight=1)
        ttk.Label(frame, text="Offline traffic", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        self._intro_label = ttk.Label(frame,
            text="Analyze a capture saved by Wireshark. The original capture is preserved.", style="Muted.TLabel")
        self._intro_label.grid(row=1, column=0, sticky="w", pady=(2, 10))
        paths = ttk.Frame(frame)
        paths.grid(row=2, column=0, sticky="ew")
        paths.columnconfigure(1, weight=1)
        self._open_button = ttk.Button(paths, text="Open Capture", command=self._open_capture,style='TrafficPath.TButton')
        self._open_button.grid(row=0, column=0, sticky="w", padx=(0, 10))
        ttk.Entry(paths, textvariable=self._source_text, state="readonly", width=1,
                  font=self._appearance.small).grid(row=0, column=1, sticky="ew")
        self._tool_button = ttk.Button(paths, text="Choose TShark", command=self._choose_tool,style='TrafficPath.TButton')
        self._tool_button.grid(row=1, column=0, sticky="w", padx=(0, 10), pady=(6, 0))
        ttk.Entry(paths, textvariable=self._tool_text, state="readonly", width=1,
                  font=self._appearance.small).grid(row=1, column=1, sticky="ew", pady=(6, 0))
        filters = ttk.Frame(frame)
        filters.grid(row=3, column=0, sticky="ew", pady=2)
        filters.columnconfigure(1, weight=1)
        ttk.Label(filters, text="Index display filter (optional)").grid(row=0, column=0, padx=(0, 10))
        self._filter_entry = ttk.Entry(filters, textvariable=self._filter)
        self._filter_entry.grid(row=0, column=1, sticky="ew")
        scope=ttk.Label(frame, text="XML export is always unfiltered. Retransmissions are dissector indications, not loss or attack proof.",
                  wraplength=720, style="Muted.TLabel")
        scope.grid(row=4,column=0,sticky='ew')
        actions = ttk.Frame(frame)
        actions.grid(row=5, column=0, sticky="ew", pady=3)
        self._analyze_button = ttk.Button(actions, text="Analyze", command=lambda: self._start("analyze"))
        self._sqlite_button = ttk.Button(actions, text="Export SQLite", command=lambda: self._start("sqlite"))
        self._xml_button = ttk.Button(actions, text="Export XML (unfiltered)", command=lambda: self._start("xml"))
        self._cancel_button = ttk.Button(actions, text="Cancel", command=self._cancel)
        for button in (self._analyze_button, self._sqlite_button, self._xml_button, self._cancel_button):
            button.pack(side="left", padx=(0, 8))
        style.configure('TrafficResults.TNotebook.Tab',font=self._appearance.small,padding=(10,3))
        style.map('TrafficResults.TNotebook.Tab',padding=[('selected',(10,3)),('!selected',(10,3))])
        self._results_tabs=ttk.Notebook(frame,style='TrafficResults.TNotebook')
        self._results_tabs.grid(row=6,column=0,sticky='nsew')
        table_frame = ttk.Frame(self._results_tabs)
        self._results_tabs.add(table_frame,text='Summary')
        self._rate_plot=PlotView(self._results_tabs)
        self._results_tabs.add(self._rate_plot,text='Capture rate')
        self._capture_controls=(paths,filters,scope,actions)
        self._results_tabs.bind('<<NotebookTabChanged>>',self._results_selected)
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        self._table = ttk.Treeview(table_frame, columns=("value",), show="tree headings", selectmode="browse")
        self._table.heading("#0", text="Measurement / group")
        self._table.heading("value", text="Value")
        self._table.column("#0", width=280, minwidth=200)
        self._table.column("value", width=430, minwidth=200)
        self._table.grid(row=0, column=0, sticky="nsew")
        yscroll = ttk.Scrollbar(table_frame, command=self._table.yview)
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll = ttk.Scrollbar(table_frame, orient="horizontal", command=self._table.xview)
        xscroll.grid(row=1, column=0, sticky="ew")
        self._table.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)
        ttk.Label(frame, textvariable=self._status, wraplength=720).grid(row=7, column=0, sticky="ew", pady=(6, 0))

    def _results_selected(self,_event=None):
        graph=self._results_tabs.select()==str(self._rate_plot)
        for control in self._capture_controls:
            control.grid_remove() if graph else control.grid()
        if graph or self._source is not None: self._intro_label.grid_remove()
        else: self._intro_label.grid()

    def _refresh_controls(self) -> None:
        if self._closed:
            return
        for button in (self._open_button, self._tool_button, self._filter_entry):
            button.configure(state="disabled" if self._busy else "normal")
        for button in (self._analyze_button, self._sqlite_button, self._xml_button):
            button.configure(state="normal" if self._source is not None and not self._busy else "disabled")
        self._cancel_button.configure(state="normal" if self._busy and not self._canceling else "disabled")

    def _invalidate(self) -> None:
        self._generation += 1
        self._last_report = None
        self._table.delete(*self._table.get_children())
        self._rate_plot.show_plots([],'Analyze a capture to see timestamped byte bins.')
        self._status.set("Selection changed; analyze to create a new result")

    def _select_source(self, source: Path) -> None:
        if self._closed or self._busy:
            return
        source = Path(source)
        if source != self._source:
            self._source = source
            self._source_text.set(str(source))
            self._intro_label.grid_remove()
            self._invalidate()
            self._refresh_controls()

    def _open_capture(self) -> None:
        if self._closed or self._busy:
            return
        selected = filedialog.askopenfilename(parent=self.widget, title="Open saved capture",
                                             filetypes=[("Capture files", "*.pcap *.pcapng"), ("All files", "*")])
        if selected:
            self._select_source(Path(selected))

    def _choose_tool(self) -> None:
        if self._closed or self._busy:
            return
        selected = filedialog.askopenfilename(parent=self.widget, title="Choose TShark executable")
        if selected:
            self._tool_path = Path(selected)
            self._tool_text.set(selected)
            self._invalidate()

    def _filter_changed(self, *_args) -> None:
        if self._closed or self._restoring_filter:
            return
        if self._busy:
            self._restoring_filter = True
            self._filter.set(self._filter_snapshot)
            self._restoring_filter = False
            return
        self._filter_snapshot = self._filter.get()
        self._invalidate()

    def _start(self, kind: str, destination: Path | None = None) -> None:
        if self._closed or self._busy or self._source is None:
            return
        if kind not in {"analyze", "sqlite", "xml"}:
            return
        if kind != "analyze" and destination is None:
            selected = filedialog.asksaveasfilename(parent=self.widget,
                title="Export SQLite index" if kind == "sqlite" else "Export unfiltered PDML",
                defaultextension=".sqlite" if kind == "sqlite" else ".xml")
            if not selected:
                return
            destination = Path(selected)
        source, tool = self._source, self._tool_path
        filter_text = self._filter.get()
        self._filter_snapshot = filter_text
        display_filter = filter_text if filter_text else None
        generation = self._generation
        done, terminal = Event(), {}
        self._done, self._terminal = done, terminal
        self._busy = True
        self._canceling = False
        suffix = "; previous completed result remains visible" if self._last_report is not None else ""
        self._status.set("Locating tools" + suffix)
        self._refresh_controls()

        def work(cancel, emit):
            # Only immutable snapshots and scalar terminal state cross threads.
            # No worker references to this tab, Tk variables, widgets or dialogs.
            try:
                executable = find_tshark(tool)
                emit("progress", (generation, "Validating unfiltered XML" if kind == "xml" else "Indexing saved capture"))
                if kind == "analyze":
                    value = analyze_capture(source, executable, cancel, display_filter)
                elif kind == "sqlite":
                    value = import_sqlite(source, destination, executable, cancel, display_filter)
                else:
                    value = export_xml(source, destination, executable, cancel)
                terminal["outcome"] = (None, None)
                return generation, source, filter_text, kind, value, None
            except BaseException as error:
                code = error.code if isinstance(error, SparcError) else "traffic_failed"
                code = code if code in _ERRORS else "traffic_failed"
                terminal["outcome"] = (code, _ERRORS[code])
                return generation, source, filter_text, kind, None, (code, _ERRORS[code])
            finally:
                done.set()

        try:
            self._job.start(work)
        except RuntimeError:
            self._busy = False
            self._status.set("The previous worker is still finishing; retry shortly")
            self._refresh_controls()

    def _on_job(self, event: str, payload: object) -> None:
        if self._closed or self._canceling:
            return
        if event == "progress":
            generation, text = payload
            if generation == self._generation:
                self._status.set(text + ("; previous completed result remains visible" if self._last_report else ""))
            return
        if event != "result":
            self._busy = False
            self._status.set(_ERRORS["traffic_failed"])
            self._refresh_controls()
            return
        generation, source, filter_text, kind, value, failure = payload
        if generation != self._generation or source != self._source or filter_text != self._filter.get():
            return
        self._busy = False
        if failure:
            self._status.set(failure[1])
        elif kind == "xml":
            self._show_conversion(value, "XML (unfiltered)")
            self._status.set("Unfiltered XML export complete; analyzed summary retained")
        else:
            self._last_report = value
            self._show_report(value)
            self._status.set("Analysis complete" if kind == "analyze" else "SQLite export complete")
        self._refresh_controls()

    def _cancel(self) -> None:
        if self._closed or not self._busy or self._canceling:
            return
        self._canceling = True
        self._generation += 1
        self._status.set("Canceling; waiting for cleanup")
        self._refresh_controls()
        self._job.cancel()
        self._settle_cancel()

    def _settle_cancel(self) -> None:
        self._settle_id = None
        if self._closed:
            return
        if not self._done.is_set():
            self._settle_id = self._root.after(100, self._settle_cancel)
            return
        code, message = self._terminal.get("outcome", (None, None))
        self._status.set(message if code in {"capture_cleanup_failed", "traffic_publication_uncertain"}
                         else "Traffic work canceled; previous completed result retained")
        self._busy = self._canceling = False
        self._refresh_controls()

    def _row(self, label, value, parent=""):
        return self._table.insert(parent, "end", text=label, values=("unavailable" if value is None else str(value),))

    def _show_conversion(self, result, title="Conversion") -> None:
        # Replace the previous conversion group to keep retries bounded.
        if self._table.exists("conversion"):
            self._table.delete("conversion")
        parent = self._table.insert("", "end", iid="conversion", text=title, open=True)
        for key, value in (("Conversion packets/s", result.packets_s), ("Elapsed ns", result.elapsed_ns),
                           ("Source file bytes", result.source_bytes), ("Output bytes", result.output_bytes),
                           ("Included packets", result.packet_count)):
            self._row(key, value, parent)
        self._row("Measurement scope", result.metadata.get("measurement_scope", "unspecified"), parent)
        self._row("Tool versions", result.versions, parent)

    def _show_report(self, report: TrafficReport) -> None:
        self._table.delete(*self._table.get_children())
        for label, value in (("Included packets", report.packet_count), ("Captured frame bytes", report.captured_bytes),
                             ("First-to-last interval (s)", report.duration_s), ("Captured frame bytes/s", report.captured_bytes_s),
                             ("Application plaintext goodput", "not measured here"),
                             ("Retransmission indications", report.retransmission_indications),
                             ("Conversion packets/s", report.conversion.packets_s)):
            self._row(label, value)
        for title, rows in (
            ("Protocols (top 100)", report.protocol_counts.items()),
            ("Captured-byte size bins", report.packet_size_distribution.items()),
            ("Directional endpoints (top 100)", ((f"{row.get('src')}:{row.get('src_port')} → {row.get('dst')}:{row.get('dst_port')}", row) for row in report.directional_bytes[:100])),
            ("TCP conversations (top 100)", ((f"Stream {row.get('tcp_stream')}", row) for row in report.tcp_conversations[:100])),
        ):
            parent = self._table.insert("", "end", text=title)
            for position, (label, value) in enumerate(rows):
                if position >= 100:
                    break
                self._row(label, value, parent)
        self._row("Truncated presentation", report.metadata.get("truncated", {}))
        self._row("Source SHA-256", report.metadata.get("source_sha256"))
        parent = self._table.insert("", "end", text="Definitions and provenance")
        for key, value in report.metadata.get("definitions", {}).items():
            self._row(key, value, parent)
        self._show_conversion(report.conversion)
        bins=report.metadata.get('capture_rate_bins',{})
        if bins.get('available'):
            width=float(bins['width_s'])
            points=tuple((float(offset)+width/2,float(value)) for offset,value in zip(bins['offsets_s'],bins['bytes_s']))
            end=width*len(points)
            plot=Plot('Captured traffic by time bin','Seconds from first epoch-aligned bin',
                'Captured bytes / nominal bin (B/s)',(Series('Captured frame bytes',points,'#1d4ed8',connected=False,bars=True),),
                True,ticks=tuple((end*i/4,f'{end*i/4:g}') for i in range(5)),x_scale='linear',
                notes=(bins['definition'],),context=(f"Source: {report.metadata.get('source_name','capture')} | SHA-256: {report.metadata.get('source_sha256','not reported')}",))
            self._rate_plot.show_plots([plot],f"Nominal width: {bins['width_s']} s; origin epoch: {bins['origin_timestamp']}. First/final bins may be partial. Not plaintext goodput.")
        else:
            self._rate_plot.show_plots([],bins.get('reason','Analyze a capture with a positive interval to see capture-rate bins.'))

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._generation += 1
        if self._settle_id is not None:
            self._root.after_cancel(self._settle_id)
            self._settle_id = None
        self._filter.trace_remove("write", self._filter_trace)
        self._job.close()
        self._rate_plot.close()


def register_traffic(app, tshark_path: Path | None = None) -> None:
    if getattr(app, "_traffic_tab", None) is not None:
        return
    tab = TrafficTab(app.notebook, tshark_path)
    app.add_tab("Traffic Analysis", tab)
    app._traffic_tab = tab
