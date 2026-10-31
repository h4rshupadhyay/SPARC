"""Small optional native adapters; Tk owns the window and its lifetime."""

import ctypes
import ctypes.util
import tkinter as tk


class _MessageData(ctypes.Union):
    _fields_ = [('bytes', ctypes.c_char * 20), ('shorts', ctypes.c_short * 10),
                ('longs', ctypes.c_long * 5)]


class _ClientMessage(ctypes.Structure):
    _fields_ = [('type', ctypes.c_int), ('serial', ctypes.c_ulong),
                ('send_event', ctypes.c_int), ('display', ctypes.c_void_p),
                ('window', ctypes.c_ulong), ('message_type', ctypes.c_ulong),
                ('format', ctypes.c_int), ('data', _MessageData)]


class _XEvent(ctypes.Union):
    _fields_ = [('message', _ClientMessage), ('padding', ctypes.c_long * 24)]


def begin_move(window, x_root: int, y_root: int) -> bool:
    """Let an X11 window manager own dragging, including its snap preview.

    Return False when native moving is unavailable so the caller can retain
    manual movement. Never replace a modal dialog's existing Tk grab.
    """
    try:
        if (window.tk.call('tk', 'windowingsystem') == 'x11'
                and window.winfo_ismapped() and not window.overrideredirect()
                and window.grab_current() is None):
            return _x11_move(window, x_root, y_root, 8)
    except (OSError, AttributeError, tk.TclError):
        pass
    return False


def cancel_move(window) -> None:
    """End a pending WM move if Tk receives the release before the WM does."""
    try:
        if window.tk.call('tk', 'windowingsystem') == 'x11':
            _x11_move(window, 0, 0, 11)
    except (OSError, AttributeError, tk.TclError):
        pass


def _x11_move(window, x_root, y_root, direction):
    library = ctypes.util.find_library('X11')
    if not library:
        return False
    xlib = ctypes.CDLL(library)
    pointer, xid = ctypes.c_void_p, ctypes.c_ulong
    byte_pointer = ctypes.POINTER(ctypes.c_ubyte)
    xlib.XOpenDisplay.argtypes = [ctypes.c_char_p]
    xlib.XOpenDisplay.restype = pointer
    xlib.XCloseDisplay.argtypes = [pointer]
    xlib.XQueryTree.argtypes = [pointer, xid, ctypes.POINTER(xid), ctypes.POINTER(xid),
                               ctypes.POINTER(ctypes.POINTER(xid)), ctypes.POINTER(ctypes.c_uint)]
    xlib.XQueryTree.restype = ctypes.c_int
    xlib.XFree.argtypes = [pointer]
    xlib.XInternAtom.argtypes = [pointer, ctypes.c_char_p, ctypes.c_int]
    xlib.XInternAtom.restype = xid
    xlib.XGetWindowProperty.argtypes = [pointer, xid, xid, ctypes.c_long, ctypes.c_long,
                                      ctypes.c_int, xid, ctypes.POINTER(xid),
                                      ctypes.POINTER(ctypes.c_int), ctypes.POINTER(xid),
                                      ctypes.POINTER(xid), ctypes.POINTER(byte_pointer)]
    xlib.XGetWindowProperty.restype = ctypes.c_int
    xlib.XSendEvent.argtypes = [pointer, xid, ctypes.c_int, ctypes.c_long,
                               ctypes.POINTER(_XEvent)]
    xlib.XSendEvent.restype = ctypes.c_int
    xlib.XFlush.argtypes = [pointer]
    display = xlib.XOpenDisplay(window.winfo_screen().encode())
    if not display:
        return False
    try:
        root, parent = xid(), xid()
        children = ctypes.POINTER(xid)()
        count = ctypes.c_uint()
        queried = xlib.XQueryTree(display, window.winfo_id(), ctypes.byref(root),
                                 ctypes.byref(parent), ctypes.byref(children), ctypes.byref(count))
        if children:
            xlib.XFree(children)
        if not queried or parent.value in (0, root.value):
            return False
        atom = xlib.XInternAtom(display, b'_NET_WM_MOVERESIZE', 0)
        supported = xlib.XInternAtom(display, b'_NET_SUPPORTED', 0)
        actual_type, items, remaining = xid(), xid(), xid()
        actual_format = ctypes.c_int()
        data = byte_pointer()
        try:
            result = xlib.XGetWindowProperty(display, root, supported, 0, 1024, 0, 4,
                                             ctypes.byref(actual_type), ctypes.byref(actual_format),
                                             ctypes.byref(items), ctypes.byref(remaining), ctypes.byref(data))
            if (result != 0 or actual_type.value != 4 or actual_format.value != 32 or not data
                    or atom not in ctypes.cast(data, ctypes.POINTER(xid))[:items.value]):
                return False
        finally:
            if data:
                xlib.XFree(data)
        if direction == 8:
            # Tk's X connection owns the implicit ButtonPress grab. Release
            # through Tk, not this separate X connection, before notifying WM.
            try:
                window.grab_set_global()
            finally:
                window.grab_release()
            window.winfo_pointerxy()  # round-trip flushes Tk's ungrab first
        event = _XEvent()
        event.message.type = 33  # ClientMessage
        event.message.display = display
        event.message.window = parent.value  # Tk's managed outer wrapper
        event.message.message_type = atom
        event.message.format = 32
        event.message.data.longs[:] = (x_root, y_root, direction, 1, 1)
        sent = xlib.XSendEvent(display, root, 0, (1 << 20) | (1 << 19), ctypes.byref(event))
        xlib.XFlush(display)
        return bool(sent)
    finally:
        xlib.XCloseDisplay(display)


def hide_decorations(window) -> bool:
    """Keep WM management when the platform can hide only the decoration.

    X11 and Windows callers must flush idle geometry while hidden, or wait
    for Map, so Tk's outer native window exists. No subprocesses or hooks.
    """
    system = window.tk.call('tk', 'windowingsystem')
    try:
        if system == 'x11':
            return _x11(window)
        if system == 'win32':
            return _windows(window)
        if system == 'aqua':
            attributes = ('noTitleBar', 'resizable', 'collapseBox', 'fullZoom')
            if not any(window.resizable()):
                attributes = ('noTitleBar',)
            window.tk.call('::tk::unsupported::MacWindowStyle', 'style',
                           window._w, 'document', attributes)
            return True
    except (OSError, AttributeError, tk.TclError):
        pass
    return False


def _x11(window):
    library = ctypes.util.find_library('X11')
    if not library:
        return False
    xlib = ctypes.CDLL(library)
    pointer = ctypes.c_void_p
    xid = ctypes.c_ulong
    xlib.XOpenDisplay.argtypes = [ctypes.c_char_p]
    xlib.XOpenDisplay.restype = pointer
    xlib.XCloseDisplay.argtypes = [pointer]
    xlib.XQueryTree.argtypes = [pointer, xid, ctypes.POINTER(xid), ctypes.POINTER(xid),
                               ctypes.POINTER(ctypes.POINTER(xid)), ctypes.POINTER(ctypes.c_uint)]
    xlib.XQueryTree.restype = ctypes.c_int
    xlib.XFree.argtypes = [pointer]
    xlib.XInternAtom.argtypes = [pointer, ctypes.c_char_p, ctypes.c_int]
    xlib.XInternAtom.restype = xid
    xlib.XChangeProperty.argtypes = [pointer, xid, xid, xid, ctypes.c_int, ctypes.c_int,
                                    ctypes.POINTER(ctypes.c_ubyte), ctypes.c_int]
    xlib.XFlush.argtypes = [pointer]
    display = xlib.XOpenDisplay(window.winfo_screen().encode())
    if not display:
        return False
    try:
        root, parent = xid(), xid()
        children = ctypes.POINTER(xid)()
        count = ctypes.c_uint()
        client = window.winfo_id()
        queried = xlib.XQueryTree(display, client, ctypes.byref(root), ctypes.byref(parent),
                                 ctypes.byref(children), ctypes.byref(count))
        if children:
            xlib.XFree(children)
        if not queried or parent.value in (0, root.value):
            return False
        # Tk's window-manager wrapper is the immediate parent of winfo_id().
        # wm_frame() can instead be the WM's own decoration frame.
        atom = xlib.XInternAtom(display, b'_MOTIF_WM_HINTS', 0)
        hints = (ctypes.c_ulong * 5)(2, 0, 0, 0, 0)  # decorations flag, no decorations
        xlib.XChangeProperty(display, parent, atom, atom, 32, 0,
                             ctypes.cast(hints, ctypes.POINTER(ctypes.c_ubyte)), 5)
        xlib.XFlush(display)
        return True
    finally:
        xlib.XCloseDisplay(display)


def _windows(window):
    from ctypes import wintypes

    user = ctypes.WinDLL('user32', use_last_error=True)
    user.GetParent.argtypes = [wintypes.HWND]
    user.GetParent.restype = wintypes.HWND
    hwnd = user.GetParent(window.winfo_id())
    if not hwnd:
        return False
    get_style = user.GetWindowLongPtrW if ctypes.sizeof(ctypes.c_void_p) == 8 else user.GetWindowLongW
    set_style = user.SetWindowLongPtrW if ctypes.sizeof(ctypes.c_void_p) == 8 else user.SetWindowLongW
    get_style.argtypes = [wintypes.HWND, ctypes.c_int]
    get_style.restype = ctypes.c_ssize_t
    set_style.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_ssize_t]
    set_style.restype = ctypes.c_ssize_t
    user.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
                                  ctypes.c_int, ctypes.c_int, wintypes.UINT]
    style = get_style(hwnd, -16)
    if not style:
        return False
    ctypes.set_last_error(0)
    previous = set_style(hwnd, -16, style & ~0x00C00000)  # WS_CAPTION
    if not previous and ctypes.get_last_error():
        return False
    return bool(user.SetWindowPos(hwnd, None, 0, 0, 0, 0, 0x0037))
