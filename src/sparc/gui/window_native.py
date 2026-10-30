"""Small optional native adapters; Tk owns the window and its lifetime."""

import ctypes
import ctypes.util
import tkinter as tk


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
