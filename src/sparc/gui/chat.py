"""In-memory chat history and public record inspector."""

from __future__ import annotations

import base64
import tkinter as tk
from tkinter import ttk

from .jobs import JobController


_HISTORY_LIMIT = 500
_EARLY_DELIVERY_LIMIT = 100


class ChatTab:
    """Display validated message events and inspect their public metadata."""

    def __init__(self, parent: ttk.Notebook, service) -> None:
        self.service = service
        self.widget = ttk.Frame(parent, padding=10)
        self._closed = False
        self._connected = False
        self._entries: list[dict] = []
        self._by_key: dict[tuple[str, str], dict] = {}
        self._early_deliveries: set[str] = set()
        self._active_send: dict | None = None
        self._notice = ""
        self._status = tk.StringVar(master=self.widget, value="Disconnected")
        self._detail = tk.StringVar(master=self.widget, value="Select a message to inspect its public security details")
        self._job = JobController(self.widget, self._job_result)
        self._build()

    def _build(self) -> None:
        frame = self.widget
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)
        ttk.Label(frame, textvariable=self._status).grid(row=0, column=0, sticky="w", pady=(0, 6))

        body = ttk.Panedwindow(frame, orient=tk.VERTICAL)
        body.grid(row=1, column=0, sticky="nsew")
        history_frame = ttk.Frame(body)
        history_frame.columnconfigure(0, weight=1)
        history_frame.rowconfigure(0, weight=1)
        self._history = tk.Listbox(history_frame, height=12, exportselection=False)
        scroll = ttk.Scrollbar(history_frame, orient=tk.VERTICAL, command=self._history.yview)
        self._history.configure(yscrollcommand=scroll.set)
        self._history.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        self._history.bind("<<ListboxSelect>>", self._selection_changed)
        self._notice_label = ttk.Label(history_frame, text="")
        self._notice_label.grid(row=1, column=0, columnspan=2, sticky="w")
        inspector_frame = ttk.Frame(body)
        inspector_frame.columnconfigure(0, weight=1)
        inspector_frame.rowconfigure(0, weight=1)
        self._inspector = tk.Text(inspector_frame, height=13, wrap=tk.WORD, state=tk.DISABLED)
        inspector_scroll = ttk.Scrollbar(
            inspector_frame, orient=tk.VERTICAL, command=self._inspector.yview
        )
        self._inspector.configure(yscrollcommand=inspector_scroll.set)
        self._inspector.grid(row=0, column=0, sticky="nsew")
        inspector_scroll.grid(row=0, column=1, sticky="ns")
        body.add(history_frame, weight=3)
        body.add(inspector_frame, weight=2)

        compose = ttk.Frame(frame)
        compose.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        compose.columnconfigure(0, weight=1)
        self._input = tk.Text(compose, height=4, wrap=tk.WORD)
        self._input.grid(row=0, column=0, sticky="ew")
        self._send_button = ttk.Button(compose, text="Send", command=self._send)
        self._send_button.grid(row=0, column=1, sticky="ns", padx=(8, 0))
        self._send_button.state(["disabled"])
        self._error = tk.StringVar(master=self.widget, value="")
        ttk.Label(frame, textvariable=self._error, wraplength=750).grid(row=3, column=0, sticky="w", pady=(5, 0))

    def handle_event(self, event) -> None:
        if self._closed:
            return
        kind = getattr(event, "kind", None)
        data = getattr(event, "data", {})
        if not isinstance(data, dict):
            return
        if kind == "state":
            connected = data.get("state") == "connected"
            self._connected = connected
            self._status.set("Connected" if connected else str(data.get("state", "Disconnected")))
            self._send_button.state(["!disabled"] if connected and self._active_send is None else ["disabled"])
            if not connected:
                self._early_deliveries.clear()
                for entry in self._entries:
                    if entry["origin"] == "outgoing" and entry["status"] == "pending":
                        entry["status"] = "unconfirmed"
                self._refresh_history()
            return
        if kind == "message":
            self._message(data)
        elif kind == "delivery":
            self._delivery(data)

    def _message(self, data: dict) -> None:
        message_id, text = data.get("message_id"), data.get("text")
        if not isinstance(message_id, str) or not isinstance(text, str):
            return
        origin = data.get("origin", "incoming")
        if origin not in {"incoming", "outgoing"}:
            return
        key = (origin, message_id)
        entry = self._by_key.get(key)
        if entry is None and origin == "outgoing" and self._active_send is not None:
            pending = self._active_send
            if pending["text"] == text and pending.get("key") is None:
                entry = pending
                entry["key"] = key
                entry["message_id"] = message_id
                self._by_key[key] = entry
        if entry is None:
            entry = {
                "origin": origin,
                "message_id": message_id,
                "key": key,
                "text": text,
                "inspection": None,
                "direction": data.get("direction"),
                "sequence": data.get("sequence"),
                "status": "verified" if origin == "incoming" else "pending",
            }
            self._append(entry)
        else:
            entry["message_id"] = message_id
            entry["key"] = key
            entry["text"] = text
            self._by_key[key] = entry
            if entry["origin"] == "incoming":
                entry["status"] = "verified"
        entry["inspection"] = data.get("inspection") or entry.get("inspection")
        entry["direction"] = data.get("direction", entry.get("direction"))
        entry["sequence"] = data.get("sequence", entry.get("sequence"))
        if origin == "outgoing" and message_id in self._early_deliveries:
            entry["status"] = "verified"
        self._refresh_history()

    def _delivery(self, data: dict) -> None:
        message_id = data.get("message_id")
        if not isinstance(message_id, str):
            return
        entry = self._by_key.get(("outgoing", message_id))
        if entry is not None:
            entry["status"] = "verified"
            self._refresh_history()
        elif self._active_send is not None:
            self._early_deliveries.add(message_id)
            while len(self._early_deliveries) > _EARLY_DELIVERY_LIMIT:
                self._early_deliveries.pop()

    def _append(self, entry: dict) -> None:
        self._entries.append(entry)
        if entry.get("key") is not None:
            self._by_key[entry["key"]] = entry
        if len(self._entries) > _HISTORY_LIMIT:
            removed = self._entries.pop(0)
            if removed.get("key") is not None and self._by_key.get(removed["key"]) is removed:
                self._by_key.pop(removed["key"], None)
            if removed is self._active_send:
                self._active_send = None
            self._notice = "Older messages removed (history limit: 500)"

    def _refresh_history(self) -> None:
        selected = self._history.curselection()
        selected_entry = self._entries[selected[0]] if selected and selected[0] < len(self._entries) else None
        self._history.delete(0, tk.END)
        self._notice_label.configure(text=self._notice)
        for entry in self._entries:
            label = f"{entry['origin'].title()} · {entry['status'].title()} · {entry['text'].replace(chr(10), ' ↵ ')}"
            self._history.insert(tk.END, label)
        if selected_entry is None and self._entries:
            selected_entry = self._entries[-1]
        if selected_entry in self._entries:
            index = self._entries.index(selected_entry)
            self._history.selection_set(index)
            self._show_inspection(selected_entry)

    def _selection_changed(self, _event=None) -> None:
        selection = self._history.curselection()
        index = selection[0] if selection else -1
        if 0 <= index < len(self._entries):
            self._show_inspection(self._entries[index])

    def _show_inspection(self, entry: dict) -> None:
        inspection = entry.get("inspection")
        sequence = entry.get("sequence")
        if sequence is None and inspection is not None:
            sequence = getattr(inspection, "sequence", None)
        rows = [
            f"Origin: {entry['origin']}",
            f"Status: {entry['status']}",
            f"Message ID: {entry.get('message_id') or 'pending'}",
            f"Direction: {entry.get('direction')}",
            f"Sequence: {sequence}",
            f"Text: {entry['text']}",
        ]
        if inspection is not None:
            computed = getattr(inspection, "computed_sha256", None)
            digest = getattr(inspection, "sha256", None)
            rows.extend([
                f"Sender SHA-256: {digest or 'unavailable'}",
                f"Receiver SHA-256: {computed or 'unavailable'}",
                f"Hash: {'match' if digest is not None and computed is not None and digest == computed else 'mismatch' if digest is not None and computed is not None else 'unavailable'}",
                f"Plaintext size: {getattr(inspection, 'plaintext_bytes', None)} bytes",
                f"Signature (base64): {self._b64(getattr(inspection, 'signature', None))}",
                f"Nonce (base64): {self._b64(getattr(inspection, 'nonce', None))}",
                f"Tag (base64): {self._b64(getattr(inspection, 'tag', None))}",
                f"Ciphertext (base64): {self._b64(getattr(inspection, 'ciphertext', None))}",
            ])
            timings = getattr(inspection, "timings", None)
            if timings is not None:
                rows.append("Timings:")
                for field in ("hash_ns", "sign_ns", "encrypt_ns", "decrypt_ns", "verify_ns"):
                    value = getattr(timings, field, None)
                    if value is not None:
                        rows.append(f"  {field.removesuffix('_ns')}: {value / 1000:g} µs")
        self._inspector.configure(state=tk.NORMAL)
        self._inspector.delete("1.0", tk.END)
        self._inspector.insert("1.0", "\n".join(rows))
        self._inspector.configure(state=tk.DISABLED)

    @staticmethod
    def _b64(value) -> str:
        return base64.b64encode(value).decode("ascii") if isinstance(value, bytes) else "unavailable"

    def _send(self) -> None:
        if self._closed or not self._connected or self._active_send is not None:
            return
        text = self._input.get("1.0", "end-1c")
        if not text:
            return
        self._input.delete("1.0", tk.END)
        self._error.set("")
        entry = {
            "origin": "outgoing", "message_id": None, "key": None, "text": text,
            "inspection": None, "direction": None, "sequence": None, "status": "pending",
        }
        self._active_send = entry
        self._append(entry)
        self._refresh_history()
        self._send_button.state(["disabled"])

        def work(cancel, emit):
            message_id = self.service.send_text(text)
            return (text, message_id)

        try:
            self._job.start(work)
        except RuntimeError as exc:
            self._active_send = None
            entry["status"] = "error"
            self._error.set(str(exc))
            self._send_button.state(["!disabled"] if self._connected else ["disabled"])
            self._refresh_history()

    def _job_result(self, kind: str, value: object) -> None:
        if self._closed:
            return
        if kind == "error":
            self._early_deliveries.clear()
            if self._active_send is not None:
                self._active_send["status"] = "error"
                self._active_send = None
            self._error.set(str(value))
            self._send_button.state(["!disabled"] if self._connected else ["disabled"])
            self._refresh_history()
            return
        if kind != "result" or not isinstance(value, tuple) or len(value) != 2:
            return
        text, message_id = value
        delivered_early = message_id in self._early_deliveries
        self._early_deliveries.clear()
        entry = self._active_send
        if entry is not None:
            key = ("outgoing", message_id)
            existing = self._by_key.get(key)
            if existing is not None and existing is not entry:
                # A same-ID outgoing event was rendered before this result.
                self._entries.remove(entry)
                entry = existing
            else:
                entry["message_id"] = message_id
                entry["key"] = key
                self._by_key[key] = entry
            entry["text"] = text
            if delivered_early:
                entry["status"] = "verified"
            self._active_send = None
        self._send_button.state(["!disabled"] if self._connected else ["disabled"])
        self._refresh_history()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._job.close()
        self._early_deliveries.clear()
        self._entries.clear()
        self._by_key.clear()
        self._active_send = None
        self._input.delete("1.0", tk.END)
        self._history.delete(0, tk.END)
        self._inspector.configure(state=tk.NORMAL)
        self._inspector.delete("1.0", tk.END)
        self._inspector.configure(state=tk.DISABLED)
