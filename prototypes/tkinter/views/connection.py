"""Fictional connection controls; callbacks never open sockets."""

import customtkinter as ctk

import theme as t
from state import OWN_FINGERPRINT, PEER_FINGERPRINT
from ui import button, field, label, section


class ConnectionView(ctk.CTkFrame):
    def __init__(self, parent, state, on_change):
        super().__init__(parent, fg_color="transparent")
        self.state, self.on_change = state, on_change
        self._compact = None
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)
        label(self, "Connection", "heading").grid(row=0, column=0, **t.INTERNAL)
        label(self, "Manage a sample peer and your local listener.", muted=True).grid(row=1, column=0, **t.INTERNAL)
        self.content = ctk.CTkScrollableFrame(self, fg_color="transparent", corner_radius=0)
        self.content.grid(row=2, column=0, **t.INTERNAL)
        self.content.columnconfigure((0, 1), weight=1, uniform="tasks")

        peer = section(self.content, "Peer connection")
        fields = ctk.CTkFrame(peer, fg_color="transparent")
        fields.columnconfigure(0, weight=1)
        fields.grid(row=1, column=0, **t.INTERNAL)
        self.peer_ip = field(fields, "Peer IPv4", "192.0.2.24", 0)
        self.peer_port = field(fields, "Port", "47655", 0, 1, width=80)
        actions = ctk.CTkFrame(peer, fg_color="transparent")
        actions.columnconfigure((0, 1), weight=1)
        actions.grid(row=2, column=0, **t.INTERNAL)
        self.connect_button = button(actions, "Connect", self.connect, primary=True)
        self.connect_button.grid(row=0, column=0, **t.INTERNAL)
        self.disconnect_button = button(actions, "Disconnect", self.disconnect)
        self.disconnect_button.grid(row=0, column=1, **t.INTERNAL)
        self.connection_status = label(peer, "")
        self.connection_status.grid(row=3, column=0, **t.INTERNAL)
        self.error = label(peer, "", wraplength=350)
        self.error.configure(text_color=t.ERROR)
        self.error.grid(row=4, column=0, **t.INTERNAL)
        label(peer, "Your sample fingerprint", muted=True).grid(row=5, column=0, **t.INTERNAL)
        self.own_fp = label(peer, OWN_FINGERPRINT, wraplength=340)
        self.own_fp.grid(row=6, column=0, **t.INTERNAL)

        listener = section(self.content, "Local listener")
        label(listener, "Sample bind address", muted=True).grid(row=1, column=0, **t.INTERNAL)
        label(listener, "192.0.2.10:47655").grid(row=2, column=0, **t.INTERNAL)
        self.listener_status = label(listener, "", muted=True)
        self.listener_status.grid(row=3, column=0, **t.INTERNAL)
        self.listener_button = button(listener, "Start listening", self.toggle_listener)
        self.listener_button.grid(row=4, column=0, **t.INTERNAL)
        label(listener, "This control changes demo state only.", muted=True, wraplength=340).grid(row=5, column=0, **t.INTERNAL)

        pairing = section(self.content, "Identity approval")
        self.pairing_status = label(pairing, "", wraplength=340)
        self.pairing_status.grid(row=1, column=0, **t.INTERNAL)
        label(pairing, "Sample peer fingerprint", muted=True).grid(row=2, column=0, **t.INTERNAL)
        self.peer_fp = label(pairing, PEER_FINGERPRINT, wraplength=340)
        self.peer_fp.grid(row=3, column=0, **t.INTERNAL)
        pair_actions = ctk.CTkFrame(pairing, fg_color="transparent")
        pair_actions.columnconfigure((0, 1), weight=1)
        pair_actions.grid(row=4, column=0, **t.INTERNAL)
        self.approve_button = button(pair_actions, "Approve", lambda: self.respond(True))
        self.approve_button.grid(row=0, column=0, **t.INTERNAL)
        self.reject_button = button(pair_actions, "Reject", lambda: self.respond(False))
        self.reject_button.grid(row=0, column=1, **t.INTERNAL)

        remembered = section(self.content, "Remembered peers")
        label(remembered, "Bob").grid(row=1, column=0, **t.INTERNAL)
        label(remembered, "192.0.2.24:47655 · Sample peer", muted=True).grid(row=2, column=0, **t.INTERNAL)
        label(remembered, "Charlie").grid(row=3, column=0, **t.INTERNAL)
        label(remembered, "198.51.100.18:47655 · Sample peer", muted=True).grid(row=4, column=0, **t.INTERNAL)
        self.panels = [peer, listener, pairing, remembered]
        self.refresh()
        self.reflow(1180)

    def connect(self):
        try:
            self.state.connect(self.peer_ip.get(), self.peer_port.get())
        except ValueError as error:
            self.error.configure(text=str(error))
            return
        self.error.configure(text="")
        self.on_change()

    def disconnect(self):
        self.state.disconnect()
        self.on_change()

    def toggle_listener(self):
        self.state.set_listening(not self.state.listening)
        self.on_change()

    def respond(self, approve):
        self.state.respond_to_pairing(approve)
        self.on_change()

    def refresh(self):
        self.connection_status.configure(text=f"{'Connected to' if self.state.connected else 'Disconnected from'} Bob (demo)")
        self.disconnect_button.configure(state="normal" if self.state.connected else "disabled")
        self.listener_status.configure(text="Listening (demo)" if self.state.listening else "Not listening (demo)")
        self.listener_button.configure(text="Stop listening" if self.state.listening else "Start listening")
        self.pairing_status.configure(text={"pending": "Bob is requesting approval (sample).",
                                           "approved": "Sample request approved.", "rejected": "Sample request rejected."}[self.state.pairing])
        for item in (self.approve_button, self.reject_button):
            item.configure(state="normal" if self.state.pairing == "pending" else "disabled")

    def reflow(self, width):
        compact = width < 1000
        if compact != self._compact:
            self._compact = compact
            self.content.columnconfigure(1, weight=0 if compact else 1)
            for index, panel in enumerate(self.panels):
                panel.grid_forget()
                panel.grid(row=index if compact else index // 2, column=0 if compact else index % 2, **t.INTERNAL)
        wrap = max(230, (width - 310) if compact else (width - 340) // 2)
        for item in (self.own_fp, self.peer_fp, self.error, self.pairing_status):
            item.configure(wraplength=wrap)
