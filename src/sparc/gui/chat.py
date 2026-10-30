"""In-memory chat history and public record inspector."""

from __future__ import annotations

import base64
import tkinter as tk
from tkinter import ttk
from ..models import Endpoint

from .jobs import JobController
from .conversation import Conversation
from .image_chat import ImageChat
from .appearance import install, text_options, BORDER


_HISTORY_LIMIT = 500
_EARLY_DELIVERY_LIMIT = 100


class ChatTab:
    """Display validated message events and inspect their public metadata."""

    def __init__(self, parent: ttk.Notebook, service) -> None:
        self.service = service
        self._appearance = install(parent)
        self.widget = ttk.Frame(parent, padding=20)
        self._closed = False
        self._layout_id = None
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
        header = ttk.Frame(frame)
        header.grid(row=0, column=0, sticky='ew', pady=(0, 10))
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text='Chat', style='Title.TLabel').grid(row=0, column=0, sticky='w')
        ttk.Label(header, textvariable=self._status, style='Muted.TLabel').grid(row=1, column=0, sticky='w', pady=(4, 0))
        self._security_open = tk.BooleanVar(master=frame, value=False)
        self._inspect_button = ttk.Checkbutton(header, text='Security details', variable=self._security_open,
                                               command=self._toggle_inspector)
        self._inspect_button.grid(row=0, column=1, rowspan=2, sticky='e')

        body = self._body = tk.PanedWindow(frame, orient=tk.HORIZONTAL, background=BORDER,
                                           borderwidth=0, sashwidth=8, opaqueresize=True)
        body.grid(row=1, column=0, sticky="nsew")
        history_frame = ttk.Frame(body)
        history_frame.columnconfigure(0, weight=1)
        history_frame.rowconfigure(0, weight=1)
        self._history = Conversation(history_frame, self._selection_changed)
        scroll = ttk.Scrollbar(history_frame, orient=tk.VERTICAL, command=self._history.yview)
        self._history.configure(yscrollcommand=scroll.set)
        self._history.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        self._notice_label = ttk.Label(history_frame, text="")
        self._notice_label.grid(row=1, column=0, columnspan=2, sticky="w")
        self._notice_label.grid_remove()
        inspector_frame = self._inspector_frame = ttk.LabelFrame(body, text='Message security', padding=8)
        inspector_frame.columnconfigure(0, weight=1)
        inspector_frame.rowconfigure(0, weight=1)
        self._inspector = tk.Text(inspector_frame, height=8, width=38, wrap=tk.WORD,
                                  **text_options(self._appearance, technical=True))
        self._inspector.insert('1.0', 'Select a message to inspect its plaintext, ciphertext, digest, signature and local timings.')
        self._inspector.configure(state=tk.DISABLED)
        inspector_scroll = ttk.Scrollbar(
            inspector_frame, orient=tk.VERTICAL, command=self._inspector.yview
        )
        self._inspector.configure(yscrollcommand=inspector_scroll.set)
        self._inspector.grid(row=0, column=0, sticky="nsew")
        self._inspector.bind('<Configure>', self._sync_inspector_extent, add='+')
        inspector_scroll.grid(row=0, column=1, sticky="ns")
        body.add(history_frame, stretch='always', minsize=100)
        body.bind('<Configure>', self._schedule_layout, add='+')

        compose = ttk.Frame(frame)
        compose.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        compose.columnconfigure(0, weight=1)
        ttk.Label(compose, text='Message', style='Heading.TLabel').grid(row=0, column=0, sticky='w', pady=(0, 8))
        self._input = tk.Text(compose, height=3, wrap=tk.WORD, **text_options(self._appearance))
        self._input.grid(row=1, column=0, sticky="ew")
        self._input.bind('<Control-Return>', self._send_shortcut)
        actions = ttk.Frame(compose)
        actions.grid(row=2, column=0, sticky='ew', pady=(8, 0))
        actions.columnconfigure(1, weight=1)
        self._send_button = ttk.Button(actions, text="Send", command=self._send, style='Primary.TButton')
        self._send_button.grid(row=0, column=2, sticky='e')
        ttk.Label(actions, text='Ctrl+Enter to send', style='Muted.TLabel').grid(row=0, column=1, sticky='e', padx=12)
        self._send_button.state(["disabled"])
        self._images = ImageChat(self, compose, actions)
        self._error = tk.StringVar(master=self.widget, value="")
        ttk.Label(frame, textvariable=self._error, wraplength=750, style='Error.TLabel').grid(row=3, column=0, sticky="w", pady=(5, 0))

    def _send_shortcut(self, _event=None):
        self._send()
        return 'break'

    def _toggle_inspector(self):
        if self._security_open.get():
            if str(self._inspector_frame) not in tuple(map(str, self._body.panes())):
                self._body.add(self._inspector_frame, stretch='always', minsize=100)
            self._schedule_layout()
        elif str(self._inspector_frame) in tuple(map(str, self._body.panes())):
            self._body.forget(self._inspector_frame)

    def _layout_conversation(self, _event=None):
        self._layout_id = None
        if self._closed:
            return
        self._input.configure(height=2 if self.widget.winfo_height() < 700 else 3)
        if not self._security_open.get():
            return
        wide = self._body.winfo_width() >= 1100 or self._body.winfo_height() < 420
        orient = tk.HORIZONTAL if wide else tk.VERTICAL
        if str(self._body.cget('orient')) != orient:
            self._body.configure(orient=orient)
        extent = self._body.winfo_width() if wide else self._body.winfo_height()
        if extent > 100 and len(self._body.panes()) == 2:
            ratio = .58 if wide and extent >= 1100 else .40
            position = int(extent * ratio)
            self._body.sash_place(0, position if wide else 0, 0 if wide else position)

    def _schedule_layout(self, _event=None):
        if not self._closed and self._layout_id is None:
            self._layout_id = self._body.after_idle(self._layout_conversation)

    def _sync_inspector_extent(self, _event=None):
        if not self._closed:
            self._inspector.count('1.0', 'end', 'update', 'ypixels')

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
            if connected:
                peer = getattr(self.service, 'connected_peer', lambda: None)()
                if isinstance(peer, dict) and isinstance(peer.get('endpoint'), Endpoint):
                    endpoint = peer['endpoint']
                    self._status.set(f'Connected · {endpoint.ip}:{endpoint.port}')
            self._send_button.state(["!disabled"] if connected and self._active_send is None else ["disabled"])
            self._images.state()
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
        elif kind == "image_transfer":
            self._images.handle(data)

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
            removed = next((item for item in self._entries
                            if item.get('kind') != 'image' or item['status'] in
                            {'verified','rejected','canceled','failed','unconfirmed'}), self._entries[0])
            self._entries.remove(removed)
            if removed.get("key") is not None and self._by_key.get(removed["key"]) is removed:
                self._by_key.pop(removed["key"], None)
            if removed is self._active_send:
                self._active_send = None
            self._notice = "Older messages removed (history limit: 500)"

    def _refresh_history(self) -> None:
        self._notice_label.configure(text=self._notice)
        if self._notice:
            self._notice_label.grid()
        self._history.render(self._entries, self._images)
        selected = self._history.curselection()
        if selected and selected[0] < len(self._entries):
            self._show_inspection(self._entries[selected[0]])

    def _selection_changed(self, _event=None) -> None:
        selection = self._history.curselection()
        index = selection[0] if selection else -1
        if 0 <= index < len(self._entries):
            self._security_open.set(True)
            self._toggle_inspector()
            if self._entries[index].get('kind') == 'image':
                self._refresh_history()
            else:
                self._show_inspection(self._entries[index])

    def _show_inspection(self, entry: dict) -> None:
        inspection = entry.get("inspection")
        sequence = entry.get("sequence")
        if sequence is None and inspection is not None:
            sequence = getattr(inspection, "sequence", None)
        rows = [
            f"Origin: {entry['origin']}",
            f"Status: {entry['status']}",
        ]
        timings = getattr(inspection, "timings", None)
        if entry["origin"] == "outgoing":
            fields = (("sign_ns", "Signature generation"), ("hash_ns", "Hashing"),
                      ("encrypt_ns", "Encryption"))
            rows.append("Local sender timings:")
        else:
            fields = (("verify_ns", "Signature verification"), ("hash_ns", "Hash recomputation"),
                      ("decrypt_ns", "Decryption"))
            rows.append("Local receiver timings:")
        for field, label in fields:
            value = getattr(timings, field, None)
            measured = f"{value / 1000:g} µs" if value is not None else "unavailable"
            rows.append(f"  {label}: {measured}")
        if entry.get('kind') == 'image':
            rows.extend(self._images.inspection_rows(entry))
        rows.extend([
            f"Message ID: {entry.get('message_id') or 'pending'}",
            f"Direction: {entry.get('direction')}",
            f"Sequence: {sequence}",
            f"Text: {entry['text']}",
        ])
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
        if inspection is not None and getattr(inspection, 'ciphertext_length', 0) > len(inspection.ciphertext):
            rows.append(f"Ciphertext truncated: showing {len(inspection.ciphertext):,} of {inspection.ciphertext_length:,} bytes")
        self._inspector.configure(state=tk.NORMAL)
        self._inspector.delete("1.0", tk.END)
        self._inspector.insert("1.0", "\n".join(rows))
        self._inspector.configure(state=tk.DISABLED)
        # Include the last wrapped ciphertext line in Tk's scroll extent.
        if self._inspector.winfo_ismapped():
            self._inspector.count("1.0", "end", "update", "ypixels")
        self._inspector.yview_moveto(0.0)

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
        if self._layout_id is not None:
            self._body.after_cancel(self._layout_id)
            self._layout_id = None
        self._job.close()
        self._images.close()
        self._early_deliveries.clear()
        self._entries.clear()
        self._by_key.clear()
        self._active_send = None
        self._input.delete("1.0", tk.END)
        self._history.clear()
        self._inspector.configure(state=tk.NORMAL)
        self._inspector.delete("1.0", tk.END)
        self._inspector.configure(state=tk.DISABLED)
