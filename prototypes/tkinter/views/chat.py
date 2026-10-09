"""Conversation and sample metadata with an always reachable composer."""

import customtkinter as ctk

import theme as t
from state import PEER_FINGERPRINT
from ui import button, label


class ChatView(ctk.CTkFrame):
    def __init__(self, parent, state, on_change):
        super().__init__(parent, fg_color="transparent")
        self.state, self.on_change = state, on_change
        self._render_key = None
        self._width = 1180
        self._compact = None
        self._labels = []
        self.selected_id = 3
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.columnconfigure(0, weight=1)
        header.grid(row=0, column=0, **t.INTERNAL)
        label(header, "Chat", "heading").grid(row=0, column=0, **t.INTERNAL)
        self.status = label(header, "Bob · Connected (demo)", muted=True)
        self.status.grid(row=1, column=0, **t.INTERNAL)

        self.body = ctk.CTkFrame(self, fg_color="transparent")
        self.body.columnconfigure(0, weight=1)
        self.body.rowconfigure(0, weight=1)
        self.body.grid(row=1, column=0, **t.INTERNAL)
        self.history = ctk.CTkScrollableFrame(self.body, fg_color="transparent", corner_radius=0)
        self.history.columnconfigure(0, weight=1)
        self.inspector = ctk.CTkFrame(self.body, width=260, fg_color=t.SURFACE, corner_radius=t.RADIUS)
        self.inspector.columnconfigure(0, weight=1)
        label(self.inspector, "Message details", "subheading").grid(row=0, column=0, **t.INTERNAL)
        self.selector = ctk.CTkOptionMenu(self.inspector, values=["Message 3"], command=self._select_option,
                                         font=t.font(), dropdown_font=t.font(), height=32,
                                         fg_color=t.HOVER, button_color=t.HOVER, button_hover_color=t.SELECTED,
                                         text_color=t.TEXT, dropdown_fg_color=t.SURFACE,
                                         dropdown_text_color=t.TEXT, dropdown_hover_color=t.HOVER)
        self.selector.grid(row=1, column=0, **t.INTERNAL)
        self.metadata = label(self.inspector, "", wraplength=230)
        self.metadata.grid(row=2, column=0, **t.INTERNAL)

        compose = ctk.CTkFrame(self, fg_color="transparent")
        compose.columnconfigure(0, weight=1)
        compose.grid(row=2, column=0, **t.INTERNAL)
        label(compose, "Message Bob", muted=True).grid(row=0, column=0, columnspan=2, **t.INTERNAL)
        self.composer = ctk.CTkTextbox(compose, height=70, font=t.font(), fg_color=t.SURFACE,
                                       text_color=t.TEXT, border_width=1, border_color=t.BORDER,
                                       corner_radius=t.RADIUS, wrap="word")
        self.composer.grid(row=1, column=0, **t.INTERNAL)
        self.composer.bind("<Control-Return>", self._keyboard_send)
        self.send_button = button(compose, "Send", self.send, primary=True, width=88)
        self.send_button.grid(row=1, column=1, **t.INTERNAL)
        label(compose, "Ctrl+Enter to send · Messages stay in this demo", muted=True).grid(
            row=2, column=0, columnspan=2, **t.INTERNAL)
        self.refresh()
        self.reflow(1180)

    def _keyboard_send(self, _event):
        self.send()
        return "break"

    def send(self):
        message = self.state.send(self.composer.get("1.0", "end-1c"))
        if message is not None:
            self.selected_id = message.id
            self.composer.delete("1.0", "end")
            self.on_change()
            self.history.update_idletasks()
            self.history._parent_canvas.yview_moveto(1)

    def _select_option(self, value):
        self.select(int(value.split()[1]))

    def select(self, message_id):
        self.selected_id = message_id
        self.selector.set(f"Message {message_id}")
        self._show_metadata()

    def _show_metadata(self):
        message = next((m for m in self.state.messages if m.id == self.selected_id), self.state.messages[-1])
        if self._compact:
            text = f"Message {message.id} · {message.direction.title()} · {message.status}\nSample fingerprint: {PEER_FINGERPRINT}"
        else:
            text = (f"Message {message.id}\n\n{message.direction.title()}\n{message.status}\n\n"
                    f"Sample sequence\n{message.id:04d}\n\nSample peer fingerprint\n{PEER_FINGERPRINT}\n\n"
                    "Illustrative metadata only.\nNo cryptography is performed.")
        self.metadata.configure(text=text)

    def refresh(self):
        self.status.configure(text="Bob · Connected (demo)" if self.state.connected else "Bob · Disconnected (demo)")
        self.send_button.configure(state="normal" if self.state.connected else "disabled")
        key = tuple((m.id, m.text) for m in self.state.messages)
        if key != self._render_key:
            self._render_key = key
            for child in self.history.winfo_children():
                child.destroy()
            self._labels = []
            for index, message in enumerate(self.state.messages):
                row = ctk.CTkFrame(self.history, fg_color="transparent")
                row.columnconfigure(0 if message.direction == "outgoing" else 1, weight=1)
                row.grid(row=index, column=0, **t.INTERNAL)
                bubble = ctk.CTkFrame(row, fg_color=t.OUTGOING if message.direction == "outgoing" else t.SURFACE,
                                      corner_radius=t.RADIUS)
                bubble.columnconfigure(0, weight=1)
                bubble.grid(row=0, column=1 if message.direction == "outgoing" else 0, **t.INTERNAL)
                heading = label(bubble, f"{'You' if message.direction == 'outgoing' else 'Bob'} · {message.timestamp}", muted=True)
                heading.grid(row=0, column=0, **t.INTERNAL)
                text = label(bubble, message.text, wraplength=330)
                text.grid(row=1, column=0, **t.INTERNAL)
                self._labels.append(text)
                for target in (bubble, heading, text):
                    target.bind("<Button-1>", lambda _e, mid=message.id: self.select(mid))
                label(bubble, message.status, muted=True).grid(row=2, column=0, **t.INTERNAL)
            self.selector.configure(values=[f"Message {m.id}" for m in self.state.messages])
            self.selector.set(f"Message {self.selected_id}")
        self._show_metadata()
        self._wrap_messages()

    def _wrap_messages(self):
        available = self._width - 280 - (0 if self._compact else 300)
        for text in self._labels:
            text.configure(wraplength=max(180, min(430, available - 80)))

    def reflow(self, width):
        self._width = width
        compact = width < 1000
        if compact != self._compact:
            self._compact = compact
            self.history.grid_forget()
            self.inspector.grid_forget()
            self.body.columnconfigure(1, weight=0, minsize=0 if compact else 260)
            self.history.grid(row=0, column=0, **t.INTERNAL)
            self.inspector.grid(row=1 if compact else 0, column=0 if compact else 1, **t.INTERNAL)
        self.metadata.configure(wraplength=max(240, width - 340) if compact else 230)
        self._show_metadata()
        self._wrap_messages()
