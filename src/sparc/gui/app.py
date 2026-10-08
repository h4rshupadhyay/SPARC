"""Main-thread Tk shell for peer service events and tab lifecycle."""

from __future__ import annotations

import queue
import tkinter as tk
import tkinter.ttk as ttk
from pathlib import Path

from ..models import SparcError
from ..peer.service import PeerService
from ..storage import resolve_data_dir
from .audit_view import AuditTab
from .chat import ChatTab
from .connection import ConnectionTab


_POLL_MS = 100
_BATCH_SIZE = 64


def launch(data_dir: Path) -> None:
    """Create and run the three core GUI tabs for one SPARC data directory."""
    root = None
    service = None
    app = None
    try:
        try:
            root = tk.Tk()
        except tk.TclError as exc:
            raise SparcError(
                "gui_unavailable",
                "Tk could not open a window. Install the Python Tk package (python3-tk on "
                "Debian or Ubuntu), or install CPython for Windows with Tcl/Tk support.",
            ) from exc
        root.title("SPARC")
        root.geometry("960x760")
        root.minsize(800, 640)
        resolved_data_dir = resolve_data_dir(data_dir)
        service = PeerService(resolved_data_dir)
        app = SparcApp(root, service)
        app.add_tab("Connection", ConnectionTab(app.notebook, service))
        app.add_tab("Chat", ChatTab(app.notebook, service))
        app.add_tab("Audit", AuditTab(app.notebook, service))
        root.mainloop()
    except BaseException:
        if app is not None:
            try:
                app.close()
            except Exception:
                if service is not None:
                    try:
                        service.close()
                    except Exception:
                        pass
                if root is not None:
                    try:
                        root.destroy()
                    except Exception:
                        pass
        else:
            if service is not None:
                try:
                    service.close()
                except Exception:
                    pass
            if root is not None:
                try:
                    root.destroy()
                except Exception:
                    pass
        raise
    else:
        if app is not None:
            app.close()


class SparcApp:
    """Own the notebook, service event drain, tabs, and ordered shutdown."""

    def __init__(self, root, service) -> None:
        self.root = root
        self.service = service
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True)
        self._tabs = []
        self._closed = False
        self._after_id = self.root.after(_POLL_MS, self._poll_service)
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def add_tab(self, title: str, widget) -> None:
        """Add a tab object or frame; tab objects may expose ``widget``."""
        if self._closed:
            raise RuntimeError("application is closed")
        frame = getattr(widget, "widget", widget)
        self.notebook.add(frame, text=title)
        self._tabs.append(widget)

    def handle_event(self, event) -> None:
        """Forward a service event to each registered tab on the Tk thread."""
        if self._closed:
            return
        for tab in tuple(self._tabs):
            handler = getattr(tab, "handle_event", None)
            if handler is not None:
                handler(event)

    def _poll_service(self) -> None:
        self._after_id = None
        if self._closed:
            return
        # get_nowait must be attempted directly: the service can retain a
        # terminal state outside the ordinary queue's qsize accounting.
        for _ in range(_BATCH_SIZE):
            try:
                event = self.service.events.get_nowait()
            except queue.Empty:
                break
            self.handle_event(event)
        if not self._closed:
            self._after_id = self.root.after(_POLL_MS, self._poll_service)

    def close(self) -> None:
        """Close tabs, then service, then root; repeated calls are harmless."""
        if self._closed:
            return
        self._closed = True
        if self._after_id is not None:
            try:
                self.root.after_cancel(self._after_id)
            except Exception:
                pass
            self._after_id = None
        for tab in tuple(self._tabs):
            close = getattr(tab, "close", None)
            if close is not None:
                close()
        self._tabs.clear()
        self.service.close()
        self.root.destroy()
