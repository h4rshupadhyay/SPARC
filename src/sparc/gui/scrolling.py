"""Native Tk scrolling with platform-aware wheel movement and usable handles."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk


def scrollbar(parent, **kwargs) -> ttk.Scrollbar:
    """Keep the native theme; enlarge SPARC's Linux scroll handles for dragging."""
    if parent.tk.call("tk", "windowingsystem") == "x11":
        orientation = str(kwargs.get("orient", tk.VERTICAL)).title()
        name = f"Sparc.{orientation}.TScrollbar"
        size = max(20, parent.winfo_pixels("15p"))
        ttk.Style(parent).configure(name, width=size, arrowsize=size)
        kwargs.setdefault("style", name)
    return ttk.Scrollbar(parent, **kwargs)


class CanvasScroller:
    """Route page gestures while preserving embedded widgets' own scrolling."""

    def __init__(self, canvas: tk.Canvas) -> None:
        self.canvas = canvas
        self._windowing_system = canvas.tk.call("tk", "windowingsystem")
        self._remainder = 0.0
        # Canvas's default unit is a fraction of the viewport. Use a stable
        # line-sized step so trackpad deltas do not jump differently on resize.
        canvas.configure(yscrollincrement=max(1, canvas.winfo_pixels("15p")))
        self._bindtag = f"SparcScroll:{canvas}"
        self._bindings = {}
        for sequence in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self._bindings[sequence] = canvas.bind_class(self._bindtag, sequence, self.scroll)
        self.bind_to(canvas)
        canvas.bind("<Destroy>", self._destroyed, add="+")

    def _destroyed(self, event) -> None:
        if event.widget is not self.canvas:
            return
        # Class bindings are interpreter-owned, unlike widget bindings. Both
        # their scripts and Python callback commands must be removed explicitly.
        for sequence, command in self._bindings.items():
            self.canvas.unbind_class(self._bindtag, sequence)
            self.canvas.deletecommand(command)
        self._bindings.clear()

    def scroll(self, event):
        number = getattr(event, "num", None)
        if number in (4, 5):
            amount = -3 if number == 4 else 3
        else:
            delta = getattr(event, "delta", 0)
            if not delta:
                return None
            # Aqua deltas already count movement units; Windows/X11 wheel
            # deltas use 120 per notch. Do not reduce a gesture to its sign.
            amount = -delta if self._windowing_system == "aqua" else -delta / 120 * 3
        self._remainder += amount
        units = int(self._remainder)
        self._remainder -= units
        if units:
            self.canvas.yview_scroll(units, "units")
        return "break"

    def bind_to(self, widget) -> None:
        """Bind page surfaces and controls, leaving native scrollable inputs alone."""
        if isinstance(widget, (tk.Text, tk.Listbox, ttk.Treeview, ttk.Scrollbar,
                               ttk.Combobox, ttk.Spinbox, tk.Spinbox)):
            return
        tags = widget.bindtags()
        if self._bindtag not in tags:
            widget.bindtags((tags[0], self._bindtag, *tags[1:]))
        for child in widget.winfo_children():
            self.bind_to(child)
