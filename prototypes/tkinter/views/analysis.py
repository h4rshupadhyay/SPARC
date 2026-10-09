"""Small result tables with explicitly illustrative measurements."""

import customtkinter as ctk

import theme as t
from ui import button, label


class AnalysisView(ctk.CTkFrame):
    def __init__(self, parent, state, on_change):
        super().__init__(parent, fg_color="transparent")
        self.state, self.on_change = state, on_change
        self._compact = None
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)
        label(self, "Analysis", "heading").grid(row=0, column=0, **t.INTERNAL)
        label(self, "Explore how sample analysis results could be presented.", muted=True).grid(row=1, column=0, **t.INTERNAL)
        self.content = ctk.CTkScrollableFrame(self, fg_color="transparent", corner_radius=0)
        self.content.columnconfigure(0, weight=1)
        self.content.grid(row=2, column=0, **t.INTERNAL)
        label(self.content, "Sample run", "subheading").grid(row=0, column=0, **t.MAIN)
        label(self.content, "AES sensitivity · Encryption timing · Resources", muted=True, wraplength=500).grid(row=1, column=0, **t.INTERNAL)
        self.run_status = label(self.content, "")
        self.run_status.grid(row=2, column=0, **t.INTERNAL)
        self.results = ctk.CTkFrame(self.content, fg_color="transparent")
        self.results.columnconfigure((0, 1), weight=1, uniform="results")
        self.results.grid(row=3, column=0, **t.INTERNAL)
        self.values = {}
        self.groups = []
        for title, rows in [
            ("Cryptography", [("sensitivity", "AES sensitivity"), ("encrypt_ms", "Encryption timing")]),
            ("Resources", [("cpu_percent", "CPU use"), ("memory_mb", "Memory")]),
        ]:
            group = ctk.CTkFrame(self.results, fg_color="transparent")
            group.columnconfigure(0, weight=1)
            label(group, title, "subheading").grid(row=0, column=0, columnspan=2, **t.MAIN)
            for row, (key, name) in enumerate(rows, start=1):
                label(group, name, muted=True).grid(row=row, column=0, **t.INTERNAL)
                value = label(group, "—")
                value.grid(row=row, column=1, **t.INTERNAL)
                self.values[key] = value
            self.groups.append(group)
        self.note = label(self.content, "Illustrative values only. No benchmarks or resource measurements are run.", muted=True, wraplength=700)
        self.note.grid(row=4, column=0, **t.MAIN)
        self.run_button = button(self, "Simulate run", self.run, primary=True)
        self.run_button.grid(row=3, column=0, **t.INTERNAL)
        self.refresh()
        self.reflow(1180)

    def run(self):
        self.state.run_analysis()
        self.on_change()

    def refresh(self):
        result = self.state.analysis_result
        self.run_status.configure(text=f"Sample dataset {self.state.analysis_run} · 1,024-byte payload" if result else "No sample dataset loaded")
        units = {"sensitivity": "%", "encrypt_ms": " ms", "cpu_percent": "%", "memory_mb": " MB"}
        for key, value in self.values.items():
            value.configure(text=f"{result[key]:g}{units[key]}" if result else "—")

    def reflow(self, width):
        compact = width < 1000
        if compact != self._compact:
            self._compact = compact
            self.results.columnconfigure(1, weight=0 if compact else 1)
            for index, group in enumerate(self.groups):
                group.grid_forget()
                group.grid(row=index if compact else 0, column=0 if compact else index, **t.INTERNAL)
        self.note.configure(wraplength=max(300, width - 360))
