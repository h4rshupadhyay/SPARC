"""Dark desktop contrast, readable type and startup/chart coverage."""

import gc
import tkinter as tk
from tkinter import ttk

import pytest

pytestmark = pytest.mark.gui


def _luminance(widget, color):
    channels = [value / 65535 for value in widget.winfo_rgb(color)]
    channels = [value / 12.92 if value <= .04045 else ((value + .055) / 1.055) ** 2.4 for value in channels]
    return sum(value * factor for value, factor in zip(channels, (.2126, .7152, .0722)))


def _contrast(widget, first, second):
    a, b = sorted((_luminance(widget, first), _luminance(widget, second)))
    return (b + .05) / (a + .05)


def test_dark_fields_and_states_have_readable_larger_shared_type():
    from sparc.gui.appearance import install, text_options
    gc.collect()
    root = tk.Tk()
    try:
        appearance = install(root)
        options = text_options(appearance)
        style = ttk.Style(root)
        assert _luminance(root, options['background']) < .04
        assert _contrast(root, options['foreground'], options['background']) >= 7
        assert _contrast(root, options['selectforeground'], options['selectbackground']) >= 4.5
        assert _contrast(root, style.lookup('TButton', 'foreground', ('disabled',)),
                         style.lookup('TButton', 'background', ('disabled',))) >= 4.5
        assert _luminance(root, style.lookup('TCombobox', 'fieldbackground', ('readonly',))) < .06
        assert _luminance(root, style.lookup('TEntry', 'fieldbackground')) < .04
        assert _luminance(root, style.lookup('Vertical.TScrollbar', 'troughcolor')) < .06
        assert _luminance(root, style.lookup('TNotebook.Tab', 'lightcolor')) < .08
        assert appearance.body.metrics('linespace') >= 26
        assert appearance.small.metrics('linespace') >= 22
        assert appearance.title.metrics('linespace') > appearance.body.metrics('linespace')
        technical = text_options(appearance, technical=True)
        assert technical['font'].actual('family') != appearance.body.actual('family')
        peer = tk.Toplevel(root)
        assert install(peer) is appearance
        peer.destroy()
        assert appearance.body.name in root.tk.call('font', 'names')
    finally:
        root.destroy()


def test_native_chart_text_and_series_are_legible_on_dark_background():
    from sparc.gui.plot_view import PlotView
    from sparc.analysis.models import BenchmarkResult
    gc.collect()
    root = tk.Tk()
    root.geometry('900x700')
    view = PlotView(root)
    view.pack(fill='both', expand=True)
    try:
        view.show(BenchmarkResult({}, [], [dict(operation='encrypt', payload_bytes=64,
                    mean_ns=1000, p95_ns=2000, throughput_bytes_s=1048576)], True))
        root.update()
        background = view.canvas.cget('background')
        assert _luminance(root, background) < .04
        texts = [item for item in view.canvas.find_all() if view.canvas.type(item) == 'text']
        assert texts
        assert all(_contrast(root, view.canvas.itemcget(item, 'fill'), background) >= 4.5 for item in texts)
        series = [item for item in view.canvas.find_all() if view.canvas.type(item) in ('oval', 'rectangle')]
        assert series
        assert all(_contrast(root, view.canvas.itemcget(item, 'fill'), background) >= 3 for item in series)
    finally:
        view.close(); root.destroy()


def test_identity_dialog_uses_shared_dark_theme_before_app_creation(tmp_path):
    from sparc.gui.identity_unlock import unlock_identity_for_gui
    from sparc.models import SparcError
    gc.collect()
    root = tk.Tk()
    root.withdraw()
    observations = []
    def observe():
        dialogs = [child for child in root.winfo_children() if isinstance(child, tk.Toplevel)]
        if not dialogs:
            root.after(10, observe)
            return
        style = ttk.Style(root)
        observations.append(_luminance(root, style.lookup('TFrame', 'background')))
        dialog = dialogs[0]
        command = dialog.protocol('WM_DELETE_WINDOW')
        root.tk.call(command)
    try:
        root.after(20, observe)
        with pytest.raises(SparcError) as caught:
            unlock_identity_for_gui(root, tmp_path / 'identity')
        assert caught.value.code == 'identity_unlock_cancelled'
        assert observations and observations[0] < .04
    finally:
        root.destroy()


def test_compact_traffic_keeps_multiple_measurements_visible_with_long_paths(tmp_path):
    from sparc.gui.traffic_view import TrafficTab
    gc.collect()
    root = tk.Tk()
    root.geometry('800x640')
    notebook = ttk.Notebook(root)
    notebook.pack(fill='both', expand=True)
    tab = TrafficTab(notebook, tmp_path / ('long-tool-directory-' * 4) / 'tshark')
    notebook.add(tab.widget, text='Traffic Analysis')
    try:
        tab._select_source(tmp_path / ('long-capture-directory-' * 4) / 'source.pcap')
        rows = [tab._table.insert('', 'end', text=f'Measurement {n}', values=(n,)) for n in range(5)]
        root.update()
        rowheight = int(ttk.Style(root).lookup('Treeview', 'rowheight'))
        # Leave room for a heading and at least three whole data rows.
        assert tab._table.winfo_height() >= rowheight * 4
        third = tab._table.bbox(rows[2])
        assert third and third[1] + third[3] <= tab._table.winfo_height() - 2
        assert tab._xml_button.winfo_rootx() + tab._xml_button.winfo_width() <= root.winfo_rootx() + 800
    finally:
        tab.close(); root.destroy()
