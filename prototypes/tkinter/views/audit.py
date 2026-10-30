"""Illustrative audit events, separate head and verification snapshots."""

import customtkinter as ctk

import theme as t
from ui import button, label


class AuditView(ctk.CTkFrame):
    def __init__(self, parent, state, on_change):
        super().__init__(parent, fg_color="transparent")
        self.state, self.on_change = state, on_change
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)
        label(self, "Audit", "heading").grid(row=0, column=0, **t.INTERNAL)
        label(self, "Sample events and a simulated verification result.", muted=True).grid(row=1, column=0, **t.INTERNAL)
        content = ctk.CTkScrollableFrame(self, fg_color="transparent", corner_radius=0)
        content.columnconfigure(0, weight=1)
        content.grid(row=2, column=0, **t.INTERNAL)
        label(content, "Recent events", "subheading").grid(row=0, column=0, **t.MAIN)
        for index, (time, event, detail) in enumerate([
            ("10:41", "Identity unlocked", "Sample local session"),
            ("10:42", "Peer connected", "Bob · 192.0.2.24:47655"),
            ("10:42", "Peer approved", "Sample fingerprint matched"),
            ("10:43", "Message received", "Sample sequence 0003"),
            ("10:44", "Delivery confirmed", "Sample sequence 0004"),
        ], start=1):
            row = ctk.CTkFrame(content, fg_color="transparent")
            row.columnconfigure(1, weight=1)
            row.grid(row=index, column=0, **t.INTERNAL)
            label(row, time, muted=True, width=60).grid(row=0, column=0, **t.INTERNAL)
            label(row, event).grid(row=0, column=1, **t.INTERNAL)
            label(row, detail, muted=True).grid(row=1, column=1, **t.INTERNAL)
        label(content, "Writer head · Sample snapshot", "subheading").grid(row=6, column=0, **t.MAIN)
        label(content, "Record 26 · Independent of the verification result", muted=True).grid(row=7, column=0, **t.INTERNAL)
        label(content, "Verification", "subheading").grid(row=8, column=0, **t.MAIN)
        self.result = label(content, "", wraplength=700)
        self.result.grid(row=9, column=0, **t.INTERNAL)
        self.verify_button = button(self, "Simulate verification", self.verify, primary=True)
        self.verify_button.grid(row=3, column=0, **t.INTERNAL)
        self.refresh()

    def verify(self):
        self.state.verify_audit()
        self.on_change()

    def refresh(self):
        self.result.configure(text=("Sample result: 24 records match the simulated prefix.\nNo checkpoint was selected. No real chain was verified."
                                    if self.state.audit_verified else "No simulation run yet.\nUse Simulate verification to display a sample result."))

    def reflow(self, width):
        self.result.configure(wraplength=max(300, width - 340))
