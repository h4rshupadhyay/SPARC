"""Integrated navigation chrome with ordinary desktop window controls."""

import tkinter as tk
from tkinter import ttk

from . import appearance as colors
from .window_native import hide_decorations


class WindowChrome:
    """Own header widgets and bindings, without taking over close policy."""

    def __init__(self, window, *, notebook=None):
        self.window = window
        mapped = bool(window.winfo_ismapped())
        show_when_ready = not mapped and window.state() != 'withdrawn'
        if show_when_ready:
            window.withdraw()
        self.notebook = notebook
        self._bindings = []
        self._drag_origin = None
        self._resize_origin = None
        self._maximized = False
        self._restore_geometry = None
        self._fallback = False
        self._restore_after = None
        self._disposed = False
        self._system = window.tk.call('tk', 'windowingsystem')
        colors.install(window)
        self._build_header()
        self._bind_dragging()
        if notebook is not None:
            self._build_resize_handles()
        self._bind(window, '<Map>', self._on_map)
        self._bind(window, '<Destroy>', self._on_destroy)
        self._bind(window, '<Alt-F4>', lambda event: self.request_close())
        self._configure_decorations(mapped)
        if show_when_ready:
            window.deiconify()

    def _build_header(self):
        window = self.window
        if self.notebook is not None:
            ttk.Style(window).configure('Chrome.TNotebook', tabmargins=(88, 4, 132, 0))
            self.notebook.configure(style='Chrome.TNotebook')
            self.header = window
        else:
            self.header = ttk.Frame(window, style='Chrome.TFrame', height=44)
            self.header.grid(row=0, column=0, sticky='ew')
            window.columnconfigure(0, weight=1)
        self.brand = ttk.Label(self.header, text='SPARC', style='Chrome.TLabel', anchor='w')
        self.brand.place(x=14, y=4, width=72, height=36)
        self.controls = ttk.Frame(self.header, style='Chrome.TFrame')
        self.minimize_button = self.maximize_button = None
        if self.notebook is not None:
            self.controls.place(relx=1, x=-126, y=4, width=120, height=36)
            self.minimize_button = self._button('−', self.minimize, 0)
            self.maximize_button = self._button('□', self.toggle_maximize, 1)
        else:
            self.controls.place(relx=1, x=-46, y=4, width=40, height=36)
        self.close_button = self._button('×', self.request_close,
                                         2 if self.notebook is not None else 0, close=True)

    def _bind_dragging(self):
        surface = self.notebook if self.notebook is not None else self.header
        for target in (self.brand, surface):
            self._bind(target, '<ButtonPress-1>', self._start_drag)
            self._bind(target, '<B1-Motion>', self._drag)
            self._bind(target, '<ButtonRelease-1>', self._end_gesture)
            self._bind(target, '<Double-Button-1>', self._double_click)

    def _build_resize_handles(self):
        for edge, options, cursor in (
            ('n', dict(relwidth=1, height=4), 'top_side'),
            ('s', dict(rely=1, y=-4, relwidth=1, height=4), 'bottom_side'),
            ('w', dict(relheight=1, width=4), 'left_side'),
            ('e', dict(relx=1, x=-4, relheight=1, width=4), 'right_side'),
            ('nw', dict(width=9, height=9), 'top_left_corner'),
            ('ne', dict(relx=1, x=-9, width=9, height=9), 'top_right_corner'),
            ('sw', dict(rely=1, y=-9, width=9, height=9), 'bottom_left_corner'),
            ('se', dict(relx=1, rely=1, x=-9, y=-9, width=9, height=9), 'bottom_right_corner'),
        ):
            grip = tk.Frame(self.window, background=colors.SOFT, cursor=cursor,
                            borderwidth=0, highlightthickness=0)
            grip.place(**options)
            self._bind(grip, '<ButtonPress-1>', lambda event, edge=edge: self._start_resize(event, edge))
            self._bind(grip, '<B1-Motion>', self._resize)
            self._bind(grip, '<ButtonRelease-1>', self._end_gesture)

    def _configure_decorations(self, mapped):
        # Set hints before the first managed map. Besides avoiding a flash,
        # this prevents some WMs from retaining the old title-bar extents.
        if self._system != 'aqua' and not mapped:
            # Hidden Tk windows still need an idle geometry pass to create
            # and flush their native wrapper before X11/Win32 can address it.
            self.window.update_idletasks()
        self._fallback = not hide_decorations(self.window)
        if self._fallback:
            self.window.overrideredirect(True)

    def _bind(self, widget, sequence, callback):
        self._bindings.append((widget, sequence, widget.bind(sequence, callback, add='+')))

    def _button(self, text, command, column, *, close=False):
        button = ttk.Button(self.controls, text=text, command=command, takefocus=True,
                            style='Close.Chrome.TButton' if close else 'Chrome.TButton')
        button.place(x=column * 40, y=0, width=40, height=36)
        return button

    def _on_map(self, event):
        if event.widget is not self.window or not self._fallback:
            return
        if not self.window.overrideredirect() and self._restore_after is None:
            self._restore_after = self.window.after_idle(self._restore_override)

    def _restore_override(self):
        self._restore_after = None
        if not self._disposed:
            self.window.overrideredirect(True)

    def _is_drag_area(self, event):
        if getattr(event, 'widget', None) is self.notebook:
            element = self.notebook.identify(event.x, event.y)
            return event.y < 44 and element not in ('tab', 'label', 'focus')
        return getattr(event, 'widget', self.brand) in (self.brand, self.header)

    def _start_drag(self, event):
        self._drag_origin = None
        if not self._is_drag_area(event):
            return
        if self._is_maximized():
            return
        self._drag_origin = (event.x_root, event.y_root, self.window.winfo_x(), self.window.winfo_y())

    def _drag(self, event):
        if self._drag_origin:
            px, py, x, y = self._drag_origin
            # A leading '+' makes even negative coordinates absolute. Tk's
            # bare '-10' means an offset from the opposite screen edge.
            self.window.geometry(f'+{x + event.x_root - px}+{y + event.y_root - py}')

    def _end_gesture(self, event):
        self._drag_origin = self._resize_origin = None

    def _double_click(self, event):
        if self.notebook is not None and self._is_drag_area(event):
            self._drag_origin = None
            self.toggle_maximize()

    def _is_maximized(self):
        if self._fallback:
            return self._maximized
        try:
            if self._system == 'x11':
                return bool(self.window.attributes('-zoomed'))
            return self.window.state() == 'zoomed'
        except tk.TclError:
            return self._maximized

    def toggle_maximize(self):
        if not any(self.window.resizable()):
            return
        self._maximized = not self._is_maximized()
        if self._fallback:
            if self._maximized:
                self._restore_geometry = self.window.geometry()
                self.window.geometry(f'{self.window.winfo_screenwidth()}x{self.window.winfo_screenheight()}+0+0')
            elif self._restore_geometry:
                self.window.geometry(self._restore_geometry)
        elif self._system == 'x11':
            self.window.attributes('-zoomed', self._maximized)
        else:
            self.window.state('zoomed' if self._maximized else 'normal')
        self.maximize_button.configure(text='❐' if self._maximized else '□')

    def minimize(self):
        if self._fallback:
            self.window.overrideredirect(False)
        self.window.iconify()

    def request_close(self):
        command = self.window.protocol('WM_DELETE_WINDOW')
        if command:
            self.window.tk.eval(command)
        else:
            self.window.destroy()
        return 'break'

    def _start_resize(self, event, edge):
        if self._is_maximized() or not any(self.window.resizable()):
            return
        self._resize_origin = (edge, event.x_root, event.y_root, self.window.winfo_x(),
                               self.window.winfo_y(), self.window.winfo_width(), self.window.winfo_height())

    def _resize(self, event):
        if self._resize_origin is None:
            return
        edge, px, py, x, y, width, height = self._resize_origin
        dx, dy = event.x_root - px, event.y_root - py
        minimum_w, minimum_h = self.window.minsize()
        maximum_w, maximum_h = self.window.maxsize()
        horizontal, vertical = self.window.resizable()
        new_w, new_h = width, height
        if horizontal and ('w' in edge or 'e' in edge):
            new_w = min(maximum_w, max(minimum_w, width + (-dx if 'w' in edge else dx)))
        if vertical and ('n' in edge or 's' in edge):
            new_h = min(maximum_h, max(minimum_h, height + (-dy if 'n' in edge else dy)))
        new_x = x + width - new_w if 'w' in edge else x
        new_y = y + height - new_h if 'n' in edge else y
        self.window.geometry(f'{new_w}x{new_h}+{new_x}+{new_y}')

    def _on_destroy(self, event):
        if event.widget is self.window:
            self.dispose()

    def dispose(self):
        """Release only callbacks owned by this controller; safe during destroy."""
        if self._disposed:
            return
        self._disposed = True
        if self._restore_after is not None:
            self.window.after_cancel(self._restore_after)
            self._restore_after = None
        for widget, sequence, binding in self._bindings:
            try:
                widget.unbind(sequence, binding)
            except tk.TclError:
                pass
        self._bindings.clear()
