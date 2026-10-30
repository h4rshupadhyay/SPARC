"""In-memory chat history and public record inspector."""

from __future__ import annotations

import base64
from datetime import datetime
import tkinter as tk
from tkinter import ttk
from tkinter.font import nametofont

from .jobs import JobController
from .scrolling import scrollbar


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
        self._selected_entry: dict | None = None
        self._crypto_expanded = False
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
        self._history = tk.Listbox(history_frame, height=6, exportselection=False)
        scroll = scrollbar(history_frame, orient=tk.VERTICAL, command=self._history.yview)
        self._history.configure(yscrollcommand=scroll.set)
        self._history.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        self._history.bind("<<ListboxSelect>>", self._selection_changed)
        self._notice_label = ttk.Label(history_frame, text="")
        self._notice_label.grid(row=1, column=0, columnspan=2, sticky="w")
        inspector_frame = ttk.Frame(body)
        inspector_frame.columnconfigure(0, weight=1)
        inspector_frame.rowconfigure(1, weight=1)
        inspector_toolbar = ttk.Frame(inspector_frame)
        inspector_toolbar.grid(row=0, column=0, sticky="w", pady=(0, 6))
        self._crypto_toggle = ttk.Button(
            inspector_toolbar, text="Show cryptographic details", command=self._toggle_crypto,
        )
        self._crypto_toggle.grid(row=0, column=0, sticky="w")
        self._crypto_toggle.state(["disabled"])
        self._inspector = tk.Text(
            inspector_frame, height=13, wrap=tk.WORD, state=tk.DISABLED,
            font="TkFixedFont", padx=12, pady=10,
        )
        self._heading_font = nametofont("TkDefaultFont", root=frame).copy()
        self._heading_font.configure(weight="bold")
        self._inspector.tag_configure("heading", font=self._heading_font, spacing1=8, spacing3=4)
        self._inspector.tag_configure("message", font="TkDefaultFont", spacing3=8)
        inspector_scroll = scrollbar(
            inspector_frame, orient=tk.VERTICAL, command=self._inspector.yview
        )
        self._inspector.configure(yscrollcommand=inspector_scroll.set)
        self._inspector.grid(row=1, column=0, sticky="nsew")
        inspector_scroll.grid(row=1, column=1, sticky="ns")
        self._copy_button = ttk.Menubutton(inspector_toolbar, text="Copy value")
        self._copy_menu = tk.Menu(self._copy_button, tearoff=False)
        self._copy_button.configure(menu=self._copy_menu)
        for field, label in (
            ("sha256", "Sender SHA-256"), ("computed_sha256", "Receiver SHA-256"),
            ("signature", "Signature"), ("nonce", "Nonce"),
            ("tag", "Tag"), ("ciphertext", "Ciphertext"),
        ):
            self._copy_menu.add_command(
                label=label,
                command=lambda field=field: self._copy_public_value(field),
            )
        self._copy_button.grid(row=0, column=1, sticky="w", padx=(8, 0))
        self._copy_button.state(["disabled"])
        body.add(history_frame, weight=1)
        body.add(inspector_frame, weight=3)

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
        entry["timestamp"] = datetime.now().astimezone()
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
            timestamp = entry.get("timestamp")
            clock = f"{timestamp:%H:%M:%S} · " if timestamp is not None else ""
            label = f"{clock}{entry['origin'].title()} · {entry['status'].title()} · {entry['text'].replace(chr(10), ' ↵ ')}"
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
        self._selected_entry = entry
        inspection = entry.get("inspection")
        sequence = entry.get("sequence")
        if sequence is None and inspection is not None:
            sequence = getattr(inspection, "sequence", None)
        timestamp = entry.get("timestamp")
        if timestamp is not None:
            offset = timestamp.strftime("%z")
            timestamp_text = f"{timestamp:%Y-%m-%d %H:%M:%S %Z} (UTC{offset[:3]}:{offset[3:]})"
        else:
            timestamp_text = "unavailable"
        sections = [("MESSAGE DETAILS", [
            f"Message ID: {entry.get('message_id') or 'pending'}",
            f"Direction: {entry.get('direction') if entry.get('direction') is not None else 'pending'}",
            f"Sequence: {sequence if sequence is not None else 'pending'}",
        ])]
        if inspection is not None:
            size = getattr(inspection, "plaintext_bytes", None)
            size_text = f"{size} bytes" if size is not None else "unavailable"
            sections[0][1].append(f"Plaintext payload size: {size_text}")
        timings = getattr(inspection, "timings", None)
        if entry["origin"] == "outgoing":
            fields = (("sign_ns", "Signature generation"), ("hash_ns", "Hashing"),
                      ("encrypt_ns", "Encryption"))
            timing_heading = "LOCAL SENDER TIMINGS"
        else:
            fields = (("verify_ns", "Signature verification"), ("hash_ns", "Hash recomputation"),
                      ("decrypt_ns", "Decryption"))
            timing_heading = "LOCAL RECEIVER TIMINGS"
        timing_rows = []
        for field, label in fields:
            value = getattr(timings, field, None)
            measured = f"{value / 1000:g} µs" if value is not None else "unavailable"
            timing_rows.append(f"{label}: {measured}")
        sections.insert(0, (timing_heading, timing_rows))
        if inspection is not None:
            computed = getattr(inspection, "computed_sha256", None)
            digest = getattr(inspection, "sha256", None)
            missing = "not available locally" if entry["origin"] == "outgoing" else "unavailable"
            comparison = "match" if digest == computed else "mismatch"
            if digest is None or computed is None:
                comparison = missing
            sections.append(("HASH DETAILS", [
                f"Sender SHA-256: {self._hash_preview(digest) or missing}",
                f"Receiver SHA-256: {self._hash_preview(computed) or missing}",
                f"Hash comparison: {comparison}",
            ]))
            if self._crypto_expanded:
                sections.append(("CRYPTOGRAPHIC DETAILS", [
                    f"Sender SHA-256 (full): {digest or missing}",
                    f"Receiver SHA-256 (full): {computed or missing}",
                    f"Signature (base64): {self._b64(getattr(inspection, 'signature', None))}",
                    f"Nonce (base64): {self._b64(getattr(inspection, 'nonce', None))}",
                    f"Tag (base64): {self._b64(getattr(inspection, 'tag', None))}",
                    f"Ciphertext (base64): {self._b64(getattr(inspection, 'ciphertext', None))}",
                ]))
        self._crypto_toggle.state(["!disabled"] if inspection is not None else ["disabled"])
        self._crypto_toggle.configure(text=f"{'Hide' if self._crypto_expanded else 'Show'} cryptographic details")
        self._copy_button.state(["!disabled"] if inspection is not None else ["disabled"])
        for index, field in enumerate((
            "sha256", "computed_sha256", "signature", "nonce", "tag", "ciphertext",
        )):
            state = tk.NORMAL if getattr(inspection, field, None) is not None else tk.DISABLED
            self._copy_menu.entryconfigure(index, state=state)
        self._inspector.configure(state=tk.NORMAL)
        self._inspector.delete("1.0", tk.END)
        self._inspector.insert(tk.END, f"{entry['origin'].title()} · {entry['status'].title()}\n", "heading")
        self._inspector.insert(tk.END, entry["text"] + "\n", "message")
        self._inspector.insert(tk.END, f"Local timestamp: {timestamp_text}\n")
        for heading, rows in sections:
            self._inspector.insert(tk.END, f"{heading}\n", "heading")
            self._inspector.insert(tk.END, "\n".join(rows) + "\n")
        self._inspector.configure(state=tk.DISABLED)
        # Include the last wrapped ciphertext line in Tk's scroll extent.
        self._inspector.count("1.0", "end", "update", "ypixels")
        self._inspector.yview_moveto(0.0)

    @staticmethod
    def _hash_preview(value: str | None) -> str | None:
        return f"{value[:12]}…{value[-12:]}" if value and len(value) > 24 else value

    def _toggle_crypto(self) -> None:
        if not self._closed and self._selected_entry is not None:
            self._crypto_expanded = not self._crypto_expanded
            self._show_inspection(self._selected_entry)

    def _copy_public_value(self, field: str) -> None:
        if self._closed or self._selected_entry is None:
            return
        value = getattr(self._selected_entry.get("inspection"), field, None)
        if value is None:
            return
        text = self._b64(value) if isinstance(value, bytes) else str(value)
        self.widget.clipboard_clear()
        self.widget.clipboard_append(text)

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
        self._selected_entry = None
        self._crypto_toggle.state(["disabled"])
        self._copy_button.state(["disabled"])
        self._input.delete("1.0", tk.END)
        self._history.delete(0, tk.END)
        self._inspector.configure(state=tk.NORMAL)
        self._inspector.delete("1.0", tk.END)
        self._inspector.configure(state=tk.DISABLED)
