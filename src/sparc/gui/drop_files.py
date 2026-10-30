"""Native local-file drops for an existing Tk interpreter."""
import tkinter as tk
from pathlib import Path


class ImageDropTarget:
    def __init__(self, widgets, on_image, on_error):
        self._widgets = []
        self._on_image = on_image
        self._on_error = on_error
        self._root = widgets[0]._root()
        self.available = False
        try:
            from tkinterdnd2 import DND_FILES, TkinterDnD

            try:
                self._root.tk.call('package', 'present', 'tkdnd')
            except tk.TclError:
                TkinterDnD.require(self._root)
            for widget in widgets:
                widget.drop_target_register(DND_FILES)
                binding = widget.dnd_bind('<<Drop>>', self.handle)
                self._widgets.append((widget, binding))
            self.available = True
        except (ImportError, RuntimeError, tk.TclError):
            self.close()

    def handle(self, event):
        try:
            paths = self._root.tk.splitlist(event.data)
            if len(paths) != 1:
                raise ValueError('Drop one image at a time.')
            if not self._on_image(Path(paths[0])):
                return 'refuse_drop'
        except (tk.TclError, ValueError) as error:
            self._on_error(str(error))
            return 'refuse_drop'
        return 'copy'

    def close(self):
        self.available = False
        for widget, binding in self._widgets:
            try:
                widget.drop_target_unregister()
                # tkdnd uses its own binding script, rather than Tk's normal
                # "if ... break" wrapper. Delete its exact owned command.
                widget.tk.call('bind', widget._w, '<<Drop>>', '')
                widget.deletecommand(binding)
            except tk.TclError:
                pass
        self._widgets.clear()
