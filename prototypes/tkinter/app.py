"""Standalone visual prototype. Start here; no SPARC backend is imported."""

import sys
from tkinter import TclError

import customtkinter as ctk

import theme as t
from state import DemoState
from ui import button, label
from views.chat import ChatView
from views.connection import ConnectionView
from views.audit import AuditView
from views.analysis import AnalysisView


class PrototypeApp(ctk.CTk):
    def __init__(self, state=None):
        t.initialize()
        super().__init__()
        self.demo = state or DemoState()
        self.title("SPARC · Visual prototype")
        self.geometry("1180x780")
        self.minsize(760, 600)
        self.configure(fg_color=t.BACKGROUND)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)
        self._closed = False
        self.sidebar = ctk.CTkFrame(self, width=180, fg_color=t.SIDEBAR, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        self.sidebar.columnconfigure(0, weight=1)
        self.sidebar.rowconfigure(6, weight=1)
        label(self.sidebar, "SPARC", "subheading").grid(row=0, column=0, **t.MAIN)
        self.nav = {}
        for row, name in enumerate(("Connection", "Chat", "Audit", "Analysis"), start=1):
            item = button(self.sidebar, name, lambda n=name: self.show_view(n), width=140, anchor="w")
            item.grid(row=row, column=0, **t.INTERNAL)
            self.nav[name] = item
        self.demo_label = label(self.sidebar, "Demo · Mock data", muted=True)
        self.demo_label.grid(row=7, column=0, **t.INTERNAL)
        label(self.sidebar, "Appearance", muted=True).grid(row=8, column=0, **t.INTERNAL)
        self.appearance = ctk.CTkOptionMenu(self.sidebar, values=["System", "Light", "Dark"],
                                           command=self.set_appearance, font=t.font(), dropdown_font=t.font(),
                                           fg_color=t.HOVER, button_color=t.HOVER, button_hover_color=t.SELECTED,
                                           text_color=t.TEXT, dropdown_fg_color=t.SURFACE,
                                           dropdown_text_color=t.TEXT, dropdown_hover_color=t.HOVER, width=140)
        self.appearance.grid(row=9, column=0, **t.MAIN)
        self.appearance.set("System")
        self.main = ctk.CTkFrame(self, fg_color="transparent")
        self.main.columnconfigure(0, weight=1)
        self.main.rowconfigure(0, weight=1)
        self.main.grid(row=0, column=1, **t.MAIN)
        self.views = {name: view(self.main, self.demo, self.refresh_views) for name, view in (
            ("Connection", ConnectionView), ("Chat", ChatView), ("Audit", AuditView), ("Analysis", AnalysisView))}
        self.current_view = "Chat"
        self.show_view("Chat")
        self.bind("<Configure>", self._resize)
        self.protocol("WM_DELETE_WINDOW", self.close)

    def show_view(self, name):
        if name not in self.views:
            return
        for view in self.views.values():
            view.grid_remove()
        self.current_view = name
        self.views[name].grid(row=0, column=0, sticky="nsew")
        self.views[name].reflow(self.winfo_width())
        self.views[name].refresh()
        for destination, item in self.nav.items():
            item.configure(fg_color=t.SELECTED if destination == name else "transparent")

    def refresh_views(self):
        for view in self.views.values():
            view.refresh()

    def set_appearance(self, mode):
        ctk.set_appearance_mode(mode)
        self.appearance.set(mode)

    def _resize(self, event):
        if event.widget is self:
            for view in self.views.values():
                view.reflow(event.width)

    def close(self):
        if not self._closed:
            self._closed = True
            self.destroy()


if __name__ == "__main__":
    try:
        PrototypeApp().mainloop()
    except TclError as error:
        sys.exit(f"Cannot open the prototype window. Use a desktop session with Tcl/Tk support.\n{error}")
