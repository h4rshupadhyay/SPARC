"""In-memory chat history and public record inspector."""

from __future__ import annotations

import base64
from datetime import datetime
import tkinter as tk
from tkinter import ttk
from tkinter.font import nametofont

from .jobs import JobController
from .scrolling import scrollbar
from ..models import Endpoint

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
        header = ttk.Frame(frame)
        header.grid(row=0, column=0, sticky='ew', pady=(0, 6))
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text='Chat', style='Title.TLabel').grid(row=0, column=0, sticky='w')
        ttk.Label(header, textvariable=self._status, style='Muted.TLabel').grid(row=1, column=0, sticky='w', pady=(4, 0))
        self._security_open = tk.BooleanVar(master=frame, value=True)
        self._inspector_width = 380
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
        scroll = scrollbar(history_frame, orient=tk.VERTICAL, command=self._history.yview)
        self._history.configure(yscrollcommand=scroll.set)
        self._history.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        self._notice_label = ttk.Label(history_frame, text="")
        self._notice_label.grid(row=1, column=0, columnspan=2, sticky="w")
        self._notice_label.grid_remove()
        inspector_frame = self._inspector_frame = ttk.LabelFrame(body, text='Message security', padding=8)
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
            inspector_frame, height=13, width=40, wrap=tk.WORD, state=tk.DISABLED,
            **text_options(self._appearance, technical=True),
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
        self._inspector.bind('<Configure>', self._sync_inspector_extent, add='+')
        inspector_scroll.grid(row=1, column=1, sticky="ns")
        body.add(history_frame, stretch='always', minsize=280)
        body.add(inspector_frame, stretch='never', minsize=380, width=self._inspector_width)
        body.bind('<Configure>', self._schedule_layout, add='+')

        compose = ttk.Frame(frame)
        compose.grid(row=2, column=0, sticky="ew", pady=(6, 0))
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
        self._error = tk.StringVar(master=self.widget, value="")
        self._images = ImageChat(self, compose, actions)
        ttk.Label(frame, textvariable=self._error, wraplength=750, style='Error.TLabel').grid(row=3, column=0, sticky="w", pady=(5, 0))

    def _send_shortcut(self, _event=None):
        self._send()
        return 'break'

    def _toggle_inspector(self):
        if self._security_open.get():
            if str(self._inspector_frame) not in tuple(map(str, self._body.panes())):
                self._body.add(self._inspector_frame, stretch='never', minsize=380,
                               width=self._inspector_width)
            self._schedule_layout()
        elif str(self._inspector_frame) in tuple(map(str, self._body.panes())):
            self._inspector_width = self._inspector_frame.winfo_width()
            self._body.forget(self._inspector_frame)

    def _layout_conversation(self, _event=None):
        self._layout_id = None
        if self._closed:
            return
        self._input.configure(height=2 if self.widget.winfo_height() < 700 else 3)

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
        entry["timestamp"] = datetime.now().astimezone()
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
            if self._entries[index].get('kind') == 'image':
                self._refresh_history()
            else:
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
        if entry.get("kind") == "image":
            sections.append(("IMAGE TRANSFER DETAILS", self._images.inspection_rows(entry)))
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
                crypto_rows = [
                    f"Sender SHA-256 (full): {digest or missing}",
                    f"Receiver SHA-256 (full): {computed or missing}",
                    f"Signature (base64): {self._b64(getattr(inspection, 'signature', None))}",
                    f"Nonce (base64): {self._b64(getattr(inspection, 'nonce', None))}",
                    f"Tag (base64): {self._b64(getattr(inspection, 'tag', None))}",
                    f"Ciphertext (base64): {self._b64(getattr(inspection, 'ciphertext', None))}",
                ]
                ciphertext = getattr(inspection, "ciphertext", None)
                ciphertext_length = getattr(inspection, "ciphertext_length", 0)
                if isinstance(ciphertext, bytes) and ciphertext_length > len(ciphertext):
                    crypto_rows.append(
                        f"Ciphertext truncated: showing {len(ciphertext):,} of "
                        f"{ciphertext_length:,} bytes"
                    )
                sections.append(("CRYPTOGRAPHIC DETAILS", crypto_rows))
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
        if self._inspector.winfo_ismapped():
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
        if self._layout_id is not None:
            self._body.after_cancel(self._layout_id)
            self._layout_id = None
        self._job.close()
        self._images.close()
        self._early_deliveries.clear()
        self._entries.clear()
        self._by_key.clear()
        self._active_send = None
        self._selected_entry = None
        self._crypto_toggle.state(["disabled"])
        self._copy_button.state(["disabled"])
        self._input.delete("1.0", tk.END)
        self._history.clear()
        self._inspector.configure(state=tk.NORMAL)
        self._inspector.delete("1.0", tk.END)
        self._inspector.configure(state=tk.DISABLED)
