"""Real-widget regression checks for legacy Tk scrolling and drag targets."""

import gc
import tkinter as tk
import weakref
from tkinter import ttk

import pytest

from sparc.gui.scrolling import CanvasScroller, scrollbar


@pytest.fixture
def page():
    try:
        root = tk.Tk()
    except tk.TclError as error:
        pytest.skip(f"Tk display unavailable: {error}")
    root.geometry("400x300")
    canvas = tk.Canvas(root, width=350, height=240)
    canvas.pack(fill="both", expand=True)
    content = ttk.Frame(canvas)
    canvas.create_window((0, 0), window=content, anchor="nw")
    scroller = CanvasScroller(canvas)
    root.update()
    canvas.configure(scrollregion=(0, 0, 400, 20000))
    try:
        yield root, canvas, content, scroller
    finally:
        root.destroy()


@pytest.mark.gui
def test_aqua_gesture_moves_in_proportion_to_delta(page):
    root, canvas, content, scroller = page
    # Replay Aqua event units on Linux; this is not a native macOS hardware check.
    scroller._windowing_system = "aqua"
    label = ttk.Label(content, text="Page label")
    label.pack()
    scroller.bind_to(content)
    root.update()
    canvas.yview_moveto(0.4)
    start = canvas.yview()[0]
    label.event_generate("<MouseWheel>", delta=-1)
    small = canvas.yview()[0] - start
    canvas.yview_moveto(0.4)
    label.event_generate("<MouseWheel>", delta=-8)
    large = canvas.yview()[0] - start
    assert small > 0 and large == pytest.approx(small * 8)
    label.event_generate("<MouseWheel>", delta=8)
    assert canvas.yview()[0] == pytest.approx(start)


@pytest.mark.gui
def test_small_wheel_deltas_accumulate_without_drift(page):
    _, canvas, _, scroller = page
    scroller._windowing_system = "win32"
    canvas.yview_moveto(0.4)
    start = canvas.yview()[0]
    for _ in range(4):
        canvas.event_generate("<MouseWheel>", delta=-10)
    down = canvas.yview()[0]
    assert down > start
    for _ in range(4):
        canvas.event_generate("<MouseWheel>", delta=10)
    assert canvas.yview()[0] == pytest.approx(start)
    before = canvas.yview()
    canvas.event_generate("<MouseWheel>", delta=0)
    assert canvas.yview() == before


@pytest.mark.gui
@pytest.mark.parametrize("kind", [tk.Listbox, tk.Text, ttk.Treeview])
def test_embedded_widget_scrolls_without_moving_the_page(page, kind):
    root, canvas, content, scroller = page
    widget = kind(content, height=3)
    widget.pack()
    for index in range(100):
        if kind is tk.Listbox:
            widget.insert("end", f"Line {index}")
        elif kind is tk.Text:
            widget.insert("end", f"Line {index}\n")
        else:
            widget.insert("", "end", text=f"Line {index}")
    scroller.bind_to(content)
    root.update()
    before = canvas.yview()
    delta = -3 if root.tk.call("tk", "windowingsystem") == "aqua" else -120
    widget.event_generate("<MouseWheel>", delta=delta)
    root.update()
    assert widget.yview()[0] > 0
    assert canvas.yview() == before


@pytest.mark.gui
def test_rebinding_dynamic_controls_does_not_multiply_movement(page):
    root, canvas, content, scroller = page
    for _ in range(3):
        for child in content.winfo_children():
            child.destroy()
        label = ttk.Label(content, text="Refreshed IP row")
        label.pack()
        scroller.bind_to(content)
        scroller.bind_to(content)
        root.update()
        canvas.yview_moveto(0.4)
        start = canvas.yview()[0]
        label.event_generate("<Button-5>")
        movement = canvas.yview()[0] - start
        canvas.yview_moveto(0.4)
        canvas.event_generate("<Button-5>")
        assert canvas.yview()[0] - start == pytest.approx(movement)


@pytest.mark.gui
def test_destroyed_page_releases_its_scroll_callbacks():
    try:
        root = tk.Tk()
    except tk.TclError as error:
        pytest.skip(f"Tk display unavailable: {error}")
    try:
        canvas = tk.Canvas(root)
        scroller = CanvasScroller(canvas)
        reference = weakref.ref(scroller)
        commands = tuple(scroller._bindings.values())
        canvas.destroy()
        assert all(not root.tk.call("info", "commands", command) for command in commands)
        del scroller, canvas
        gc.collect()
        assert reference() is None, "Destroyed pages must release their Tcl wheel callbacks"
    finally:
        root.destroy()


@pytest.mark.gui
@pytest.mark.parametrize("theme", ["clam", "alt", "default", "classic"])
@pytest.mark.parametrize("orientation", ["vertical", "horizontal"])
def test_linux_drag_target_across_native_themes(theme, orientation):
    try:
        root = tk.Tk()
    except tk.TclError as error:
        pytest.skip(f"Tk display unavailable: {error}")
    try:
        if root.tk.call("tk", "windowingsystem") != "x11":
            pytest.skip("Linux/X11 scrollbar geometry")
        style = ttk.Style(root)
        if theme not in style.theme_names():
            pytest.skip(f"Theme {theme} unavailable")
        style.theme_use(theme)
        root.tk.call("tk", "scaling", 1.8)
        bar = scrollbar(root, orient=orientation)
        bar.pack()
        root.update()
        thickness = bar.winfo_width() if orientation == "vertical" else bar.winfo_height()
        assert thickness >= 20
        assert style.theme_use() == theme
    finally:
        root.destroy()
