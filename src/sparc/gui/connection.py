"""Connection, listener, pairing, and remembered-peer controls."""

from __future__ import annotations

import ipaddress
import re
import socket
import tkinter as tk
from tkinter import ttk

import psutil

from ..models import Endpoint
from .jobs import JobController


_DEFAULT_PORT = 47655


class ConnectionTab:
    """Tk view that calls the peer service and renders its public events."""

    def __init__(self, parent: ttk.Notebook, service) -> None:
        self.service = service
        self.widget = ttk.Frame(parent, padding=10)
        self._closed = False
        self._focus_callback = None
        self._pending_pairing: tuple[str, str, str, str, int] | None = None
        self._interfaces = self._ipv4_interfaces()
        self._bind_ip = tk.StringVar(master=self.widget, value="0.0.0.0")
        self._bind_port = tk.StringVar(master=self.widget, value=str(_DEFAULT_PORT))
        self._configured_port_text = tk.StringVar(master=self.widget, value=str(_DEFAULT_PORT))
        self._listener_active = False
        self._active_port: int | None = None
        self._bind_port.trace_add("write", self._configured_port_changed)
        self._peer_ip = tk.StringVar(master=self.widget, value="")
        self._peer_port = tk.StringVar(master=self.widget, value=str(_DEFAULT_PORT))
        self._listener_text = tk.StringVar(
            master=self.widget, value=f"Not listening (configured port {_DEFAULT_PORT})"
        )
        self._state_text = tk.StringVar(master=self.widget, value="stopped")
        self._message_text = tk.StringVar(master=self.widget, value="")
        self._own_fingerprint = str(service.own_fingerprint)
        self._peer_fingerprint = tk.StringVar(master=self.widget, value="Not connected")
        self._peer_endpoint = tk.StringVar(master=self.widget, value="")
        self._pairing_text = tk.StringVar(master=self.widget, value="No approval request")
        self._trusted_records = ()
        self._job = JobController(self.widget, self._job_result)
        self._build()
        self._refresh_peers()

    @staticmethod
    def _ipv4_interfaces() -> list[tuple[str, str]]:
        rows = []
        try:
            interfaces = psutil.net_if_addrs()
        except Exception:
            interfaces = {}
        for name, addresses in interfaces.items():
            for address in addresses:
                if address.family == socket.AF_INET:
                    ip = str(address.address).split("%", 1)[0]
                    try:
                        ipaddress.IPv4Address(ip)
                    except ipaddress.AddressValueError:
                        continue
                    rows.append((str(name), ip))
        return rows

    def _build(self) -> None:
        frame = self.widget
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        self._canvas = tk.Canvas(frame, highlightthickness=0, borderwidth=0)
        self._canvas.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self._canvas.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self._canvas.configure(yscrollcommand=scroll.set)
        content = ttk.Frame(self._canvas, padding=10)
        self._content = content
        self._canvas_window = self._canvas.create_window((0, 0), window=content, anchor="nw")
        content.columnconfigure(0, weight=1)
        content.bind("<Configure>", self._content_resized, add="+")
        self._canvas.bind("<Configure>", self._canvas_resized, add="+")
        self._canvas.bind("<MouseWheel>", self._mousewheel, add="+")
        self._canvas.bind("<Button-4>", self._mousewheel, add="+")
        self._canvas.bind("<Button-5>", self._mousewheel, add="+")
        local = ttk.LabelFrame(content, text="Your device IP addresses", padding=8)
        local.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        local.columnconfigure(1, weight=1)
        ttk.Label(local, text=f"Hostname: {socket.gethostname()}").grid(
            row=0, column=0, columnspan=3, sticky="w"
        )
        if not self._interfaces:
            ttk.Label(local, text="No IPv4 addresses found").grid(row=1, column=0, sticky="w")
        for index, (name, ip) in enumerate(self._interfaces, start=1):
            ttk.Label(local, text=name).grid(row=index, column=0, sticky="w", padx=(0, 10))
            ttk.Label(local, text=ip).grid(row=index, column=1, sticky="w")
            ttk.Button(
                local, text="Copy endpoint",
                command=lambda address=ip: self._copy_endpoint(address),
            ).grid(row=index, column=2, sticky="e")
        all_row = len(self._interfaces) + 1
        ttk.Label(local, text="0.0.0.0").grid(row=all_row, column=0, sticky="w")
        ttk.Label(local, text="All IPv4 interfaces").grid(row=all_row, column=1, sticky="w")
        ttk.Label(local, text="Your listening TCP port:").grid(
            row=all_row + 1, column=0, sticky="w", pady=(5, 0)
        )
        ttk.Label(local, textvariable=self._configured_port_text).grid(
            row=all_row + 1, column=1, columnspan=2, sticky="w", pady=(5, 0)
        )

        listener = ttk.LabelFrame(content, text="Listener", padding=8)
        listener.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        listener.columnconfigure(1, weight=1)
        ttk.Label(listener, text="Bind IPv4").grid(row=0, column=0, sticky="w")
        ttk.Entry(listener, textvariable=self._bind_ip, width=18).grid(row=0, column=1, sticky="w")
        ttk.Label(listener, text="Port").grid(row=0, column=2, sticky="w", padx=(8, 0))
        ttk.Entry(listener, textvariable=self._bind_port, width=8).grid(row=0, column=3, sticky="w")
        ttk.Button(listener, text="Start listening", command=self._start_listener).grid(
            row=1, column=0, sticky="w", pady=(5, 0)
        )
        ttk.Button(listener, text="Stop listening", command=self._stop_listener).grid(
            row=1, column=1, sticky="w", padx=5, pady=(5, 0)
        )
        ttk.Label(listener, textvariable=self._listener_text).grid(
            row=2, column=0, columnspan=4, sticky="w", pady=(5, 0)
        )

        peer = ttk.LabelFrame(content, text="Peer", padding=8)
        peer.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        peer.columnconfigure(1, weight=1)
        ttk.Label(peer, text="Peer IPv4").grid(row=0, column=0, sticky="w")
        ttk.Entry(peer, textvariable=self._peer_ip, width=18).grid(row=0, column=1, sticky="w")
        ttk.Label(peer, text="Port").grid(row=0, column=2, sticky="w", padx=(8, 0))
        ttk.Entry(peer, textvariable=self._peer_port, width=8).grid(row=0, column=3, sticky="w")
        ttk.Button(peer, text="Connect", command=self._connect).grid(row=1, column=0, sticky="w", pady=(5, 0))
        ttk.Button(peer, text="Disconnect", command=self._disconnect).grid(row=1, column=1, sticky="w", padx=5, pady=(5, 0))
        ttk.Label(peer, text="Connection state:").grid(row=2, column=0, sticky="w", pady=(5, 0))
        ttk.Label(peer, textvariable=self._state_text).grid(row=2, column=1, columnspan=3, sticky="w", pady=(5, 0))
        ttk.Label(peer, text="Your full SHA-256 fingerprint").grid(
            row=3, column=0, columnspan=3, sticky="w", pady=(7, 0)
        )
        self._own_fp_label = ttk.Label(peer, text=self._own_fingerprint, wraplength=620)
        self._own_fp_label.grid(row=4, column=0, columnspan=4, sticky="w")
        ttk.Button(peer, text="Copy own fingerprint", command=lambda: self._copy(self._own_fingerprint)).grid(
            row=5, column=0, sticky="w"
        )
        ttk.Label(peer, text="Peer full SHA-256 fingerprint").grid(
            row=6, column=0, columnspan=3, sticky="w", pady=(7, 0)
        )
        self._peer_fp_label = ttk.Label(peer, textvariable=self._peer_fingerprint, wraplength=620)
        self._peer_fp_label.grid(row=7, column=0, columnspan=4, sticky="w")
        ttk.Button(peer, text="Copy peer fingerprint", command=self._copy_peer_fingerprint).grid(
            row=8, column=0, sticky="w"
        )
        ttk.Label(peer, textvariable=self._peer_endpoint).grid(
            row=9, column=0, columnspan=4, sticky="w", pady=(5, 0)
        )

        pairing = ttk.LabelFrame(content, text="Peer identity approval", padding=8)
        pairing.grid(row=3, column=0, sticky="ew", pady=(0, 8))
        pairing.columnconfigure((0, 1), weight=1)
        self._pairing_label = ttk.Label(pairing, textvariable=self._pairing_text, wraplength=700)
        self._pairing_label.grid(
            row=0, column=0, columnspan=3, sticky="w"
        )
        self._approve_button = ttk.Button(pairing, text="Approve", command=lambda: self._respond(True))
        self._approve_button.grid(row=1, column=0, sticky="ew", pady=(5, 0))
        self._reject_button = ttk.Button(pairing, text="Reject", command=lambda: self._respond(False))
        self._reject_button.grid(row=1, column=1, sticky="ew", padx=5, pady=(5, 0))
        self._approve_button.state(["disabled"])
        self._reject_button.state(["disabled"])

        remembered = ttk.LabelFrame(content, text="Remembered peers", padding=8)
        remembered.grid(row=4, column=0, sticky="nsew")
        remembered.columnconfigure(0, weight=1)
        self._peers = tk.Listbox(remembered, height=4, exportselection=False)
        self._peers.grid(row=0, column=0, sticky="nsew")
        ttk.Button(remembered, text="Forget peer", command=self._forget_selected).grid(
            row=1, column=0, sticky="w", pady=(5, 0)
        )
        ttk.Label(remembered, text="Forgetting never disconnects a peer; active sessions must be disconnected first.").grid(
            row=2, column=0, sticky="w", pady=(5, 0)
        )
        self._message_label = ttk.Label(content, textvariable=self._message_text, wraplength=750)
        self._message_label.grid(
            row=5, column=0, sticky="w", pady=(6, 0)
        )
        self._watch_focus(content)

    def _content_resized(self, _event=None) -> None:
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))
        width = max(240, self._canvas.winfo_width() - 30)
        for label in (self._own_fp_label, self._peer_fp_label, self._pairing_label, self._message_label):
            label.configure(wraplength=width)

    def _canvas_resized(self, event) -> None:
        self._canvas.itemconfigure(self._canvas_window, width=event.width)

    def _mousewheel(self, event):
        if getattr(event, "num", None) == 4:
            delta = -1
        elif getattr(event, "num", None) == 5:
            delta = 1
        else:
            delta = -1 if event.delta > 0 else 1
        self._canvas.yview_scroll(delta, "units")
        return "break"

    def _watch_focus(self, widget) -> None:
        widget.bind("<FocusIn>", self._focus_into_view, add="+")
        widget.bind("<MouseWheel>", self._mousewheel, add="+")
        widget.bind("<Button-4>", self._mousewheel, add="+")
        widget.bind("<Button-5>", self._mousewheel, add="+")
        for child in widget.winfo_children():
            self._watch_focus(child)

    def _focus_into_view(self, event) -> None:
        if self._closed:
            return
        if self._focus_callback is not None:
            try:
                self._canvas.after_cancel(self._focus_callback)
            except tk.TclError:
                pass
        self._focus_callback = self._canvas.after_idle(self._reveal_focused_widget)

    def _reveal_focused_widget(self) -> None:
        self._focus_callback = None
        if self._closed:
            return
        widget = self.widget.focus_get()
        if widget is not None and str(widget).startswith(str(self._content)):
            self._reveal_widget(widget)

    def _reveal_widget(self, widget) -> None:
        if self._closed or not widget.winfo_exists():
            return
        top = self._canvas.canvasy(0)
        height = self._canvas.winfo_height()
        item = self._canvas.bbox(self._canvas_window)
        if not item or height <= 1:
            return
        y1 = widget.winfo_rooty() - self._canvas.winfo_rooty() + top
        y2 = y1 + widget.winfo_height()
        if y1 < top:
            self._canvas.yview_moveto(max(0, y1 / max(1, item[3])))
        elif y2 > top + height:
            self._canvas.yview_moveto(max(0, (y2 - height) / max(1, item[3])))

    def _copy(self, value: str) -> None:
        self.widget.clipboard_clear()
        self.widget.clipboard_append(value)
        self._message_text.set("Copied to clipboard")

    def _copy_endpoint(self, address: str) -> None:
        port = self._active_port if self._listener_active else self._safe_port()
        if port is None:
            self._message_text.set("Enter a listening port from 1 to 65535 before copying an endpoint")
            return
        self._copy(f"{address}:{port}")

    def _configured_port_changed(self, *_args) -> None:
        if self._closed:
            return
        self._configured_port_text.set(self._bind_port.get())
        if not self._listener_active:
            self._listener_text.set(
                f"Not listening (configured port {self._bind_port.get()})"
            )

    def _copy_peer_fingerprint(self) -> None:
        value = self._peer_fingerprint.get()
        if len(value) == 64:
            self._copy(value)

    def _safe_port(self) -> int | None:
        try:
            port = int(self._bind_port.get())
        except (TypeError, ValueError):
            return None
        return port if 1 <= port <= 65535 else None

    @staticmethod
    def _parse_endpoint(ip: str, raw_port: str) -> Endpoint:
        if not isinstance(ip, str):
            raise ValueError("Enter a literal IPv4 address")
        try:
            address = ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError as exc:
            raise ValueError("Enter a literal IPv4 address") from exc
        if str(address) != ip:
            raise ValueError("Enter a canonical literal IPv4 address")
        try:
            port = int(raw_port)
        except (TypeError, ValueError) as exc:
            raise ValueError("Port must be an integer from 1 to 65535") from exc
        if not 1 <= port <= 65535:
            raise ValueError("Port must be from 1 to 65535")
        return Endpoint(ip, port)

    def _run(self, action: str, operation) -> None:
        if self._closed:
            return
        self._message_text.set(f"{action}…")

        def work(cancel, emit):
            return action, operation()

        try:
            self._job.start(work)
        except RuntimeError as exc:
            self._message_text.set(str(exc))

    def _start_listener(self) -> None:
        bind_ip, raw_port = self._bind_ip.get().strip(), self._bind_port.get().strip()
        try:
            endpoint = self._parse_endpoint(bind_ip, raw_port)
        except ValueError as exc:
            self._message_text.set(str(exc))
            return
        self._run("Starting listener", lambda: self.service.start_listener(endpoint.ip, endpoint.port))

    def _stop_listener(self) -> None:
        self._run("Stopping listener", self.service.stop_listener)

    def _connect(self) -> None:
        peer_ip, raw_port = self._peer_ip.get().strip(), self._peer_port.get().strip()
        try:
            endpoint = self._parse_endpoint(peer_ip, raw_port)
        except ValueError as exc:
            self._message_text.set(str(exc))
            return
        self._run("Connecting", lambda: self.service.connect(endpoint))

    def _disconnect(self) -> None:
        self._run("Disconnecting", self.service.disconnect)

    def _respond(self, approved: bool) -> None:
        request = self._pending_pairing
        if request is None:
            return
        request_id = request[0]
        self._pending_pairing = None
        self._set_pairing_controls(False)
        self._run(
            "Submitting approval" if approved else "Rejecting peer",
            lambda: self.service.respond_to_pairing(request_id, approved),
        )

    def _set_pairing_controls(self, enabled: bool) -> None:
        state = ["!disabled"] if enabled else ["disabled"]
        self._approve_button.state(state)
        self._reject_button.state(state)

    def _forget_selected(self) -> None:
        selection = self._peers.curselection()
        if not selection:
            self._message_text.set("Select a remembered peer to forget")
            return
        fingerprint = self._peer_fingerprints[selection[0]]
        self._run("Forgetting peer", lambda: self.service.forget_peer(fingerprint))

    def _refresh_peers(self) -> None:
        self._peer_fingerprints = []
        self._peers.delete(0, tk.END)
        try:
            peers = self.service.trusted_peers()
        except Exception as exc:
            self._message_text.set(str(exc))
            return
        for peer in peers:
            fingerprint = str(peer.get("fingerprint", ""))
            endpoint = peer.get("endpoint")
            address = f"{endpoint.ip}:{endpoint.port}" if isinstance(endpoint, Endpoint) else ""
            self._peer_fingerprints.append(fingerprint)
            self._peers.insert(tk.END, f"{peer.get('label') or 'Peer'} — {fingerprint} — {address}")

    def _job_result(self, kind: str, value: object) -> None:
        if self._closed:
            return
        if kind == "error":
            message = getattr(value, "message", str(value))
            self._message_text.set(message)
            return
        if kind != "result" or not isinstance(value, tuple) or len(value) != 2:
            return
        action, result = value
        self._message_text.set(f"{action} complete")
        if action.startswith("Starting listener") and isinstance(result, Endpoint):
            self._listener_active = True
            self._active_port = result.port
            self._listener_text.set(f"Listening on {result.ip}:{result.port}")
        elif action.startswith("Stopping listener"):
            self._listener_active = False
            self._active_port = None
            self._listener_text.set(f"Not listening (configured port {self._bind_port.get()})")
        elif action.startswith("Forgetting peer"):
            self._refresh_peers()

    def handle_event(self, event) -> None:
        if self._closed or not hasattr(event, "kind") or not isinstance(event.data, dict):
            return
        data = event.data
        if event.kind == "pairing_request":
            request_id = data.get("request_id")
            own = data.get("own_fingerprint")
            candidate = data.get("candidate_fingerprint")
            endpoint = data.get("endpoint")
            if (not isinstance(request_id, str) or not request_id
                    or not isinstance(own, str) or re.fullmatch(r"[0-9a-f]{64}", own) is None
                    or not isinstance(candidate, str) or re.fullmatch(r"[0-9a-f]{64}", candidate) is None
                    or not isinstance(endpoint, dict)
                    or not isinstance(endpoint.get("ip"), str)
                    or type(endpoint.get("port")) is not int):
                self._pending_pairing = None
                self._set_pairing_controls(False)
                self._pairing_text.set("Invalid approval request; approval is disabled")
                return
            try:
                validated_endpoint = self._parse_endpoint(
                    endpoint["ip"], str(endpoint["port"])
                )
            except ValueError:
                self._pending_pairing = None
                self._set_pairing_controls(False)
                self._pairing_text.set("Invalid approval endpoint; approval is disabled")
                return
            self._pending_pairing = (
                str(request_id), str(own), str(candidate),
                validated_endpoint.ip, validated_endpoint.port,
            )
            self._peer_fingerprint.set(candidate)
            self._pairing_text.set(
                f"Review both full fingerprints before approval.\n"
                f"Your fingerprint: {own}\nPeer fingerprint: {candidate}\n"
                f"Peer endpoint: {endpoint['ip']}:{endpoint['port']}"
            )
            self._set_pairing_controls(True)
            self._state_text.set("awaiting approval")
            return

        if event.kind == "state":
            state, reason = data.get("state"), data.get("reason")
            if isinstance(state, str):
                self._state_text.set(state)
            if state in {
                "listening", "stopped", "error", "connecting", "handshaking",
                "reconnecting", "disconnected",
            }:
                self._peer_fingerprint.set("Not connected")
                self._peer_endpoint.set("")
            if state != "awaiting approval":
                self._pending_pairing = None
                self._set_pairing_controls(False)
            if reason == "listener_started":
                self._listener_active = True
                endpoint = data.get("endpoint")
                if isinstance(endpoint, dict):
                    self._active_port = endpoint.get("port")
                    self._listener_text.set(
                        f"Listening on {endpoint.get('ip')}:{endpoint.get('port')}"
                    )
            elif reason == "listener_stopped":
                self._listener_active = False
                self._active_port = None
                self._listener_text.set(
                    f"Not listening (configured port {self._bind_port.get()})"
                )
            if reason in {"changed_identity", "identity_changed"}:
                self._pending_pairing = None
                self._set_pairing_controls(False)
                self._pairing_text.set(
                    "Blocked: remembered peer identity changed. Deliberately forget the old pin before pairing again."
                )
            elif state in {"connected", "listening"}:
                self._pending_pairing = None
                self._set_pairing_controls(False)
                if state == "connected":
                    peer = self.service.connected_peer()
                    if (isinstance(peer, dict)
                            and isinstance(peer.get("fingerprint"), str)
                            and len(peer["fingerprint"]) == 64
                            and isinstance(peer.get("endpoint"), Endpoint)):
                        self._peer_fingerprint.set(peer["fingerprint"])
                        endpoint = peer["endpoint"]
                        self._peer_endpoint.set(
                            f"Connected peer endpoint: {endpoint.ip}:{endpoint.port}"
                        )
                    else:
                        self._peer_fingerprint.set("Not connected")
                        self._peer_endpoint.set("")
            elif state in {"error", "stopped", "disconnected"}:
                if state == "error":
                    self._pending_pairing = None
                    self._set_pairing_controls(False)
                if reason == "changed_identity":
                    self._pairing_text.set("Blocked: peer identity changed; deliberate re-pairing is required")

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._focus_callback is not None:
            try:
                self._canvas.after_cancel(self._focus_callback)
            except tk.TclError:
                pass
            self._focus_callback = None
        self._pending_pairing = None
        self._job.close()
