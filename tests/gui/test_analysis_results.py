"""Results are visible on completion and each graph category keeps its own run."""
import tkinter as tk
from tkinter import ttk
import xml.etree.ElementTree as ET

import pytest

from sparc.analysis.models import BenchmarkResult
from sparc.analysis.sensitivity import run_sensitivity
from test_analysis_view import _make_tab, _walk


def _benchmark(network=False):
    return BenchmarkResult(dict(run_id='performance-run',warmups=2,repetitions=3),[],[
        dict(operation='network_round_trip' if network else 'encrypt',payload_bytes=64,
             count=3,mean_ns=1000,p95_ns=2000,throughput_bytes_s=1024,goodput_bytes_s=2048)
    ],True)


@pytest.mark.gui
def test_completed_benchmark_reveals_graphs_at_ordinary_window_size():
    root,tab=_make_tab()
    try:
        root.deiconify(); root.geometry('800x640'); root.update()
        tab._job_kind='local'; tab._job_result('result',_benchmark()); root.update()
        assert tab._workspace.tab(tab._workspace.select(),'text')=='Performance'
        report=tab._plots
        assert report.tabs.tab(report.tabs.select(),'text')=='Performance'
        graph=report.performance
        assert graph.canvas.winfo_ismapped()
        # A completed result must put actual chart marks in the first viewport.
        marks=[graph.canvas.bbox(item) for item in graph.canvas.find_all() if graph.canvas.type(item)=='oval']
        assert marks and min(box[1] for box in marks)<graph.canvas.winfo_height()
        assert graph.canvas.yview()[0]==0
        assert graph.canvas.winfo_width()<=800
        assert root.winfo_width()==800
        assert 'performance-run' in ' '.join(graph.plots[0].context)
    finally:
        tab.close(); root.destroy()


@pytest.mark.gui
def test_categories_retain_their_own_run_and_export_after_switching(monkeypatch,tmp_path):
    root,tab=_make_tab()
    try:
        tab._job_kind='local'; tab._job_result('result',_benchmark())
        tab._job_kind='batch'; tab._job_result('result',run_sensitivity(7,1)); root.update()
        report=tab._plots
        assert report.tabs.tab(report.tabs.select(),'text')=='Avalanche'
        assert 'Seed: 7' in ' '.join(report.avalanche.plots[0].context)
        assert 'performance-run' in ' '.join(report.performance.plots[0].context)
        destination=tmp_path/'performance.svg'
        monkeypatch.setattr('sparc.gui.plot_view.filedialog.asksaveasfilename',lambda **_:str(destination))
        report.tabs.select(report.performance)
        report.performance.export()
        assert 'performance-run' in ' '.join(ET.parse(destination).getroot().itertext())
        assert 'Seed: 7' not in destination.read_text()
        # CSV completion/error must not masquerade as a fresh graph result.
        tab._job_kind='export'; tab._job_result('result',str(tmp_path/'a.csv'))
        tab._job_kind='local'; tab._job_result('error','controlled failure')
        assert report.performance._result.metadata['run_id']=='performance-run'
        assert 'Analysis failed' in tab._status.get()
    finally:
        tab.close(); root.destroy()


@pytest.mark.gui
def test_network_graphs_hide_primitive_operation_filter_and_chart_selection_redraws():
    root,tab=_make_tab()
    try:
        root.deiconify(); root.geometry('1000x760')
        tab._job_kind='network'; tab._job_result('result',_benchmark(True)); root.update()
        graph=tab._plots.performance
        assert not graph._choice.winfo_ismapped()
        graph.chart.set('Network verified goodput')
        graph._chart_choice.event_generate('<<ComboboxSelected>>'); root.update()
        texts=[graph.canvas.itemcget(item,'text') for item in graph.canvas.find_all() if graph.canvas.type(item)=='text']
        assert 'Verified network goodput (MiB/s)' in texts
        assert 'Duration (µs)' not in texts
        # All exported panels remain available when only one is shown.
        assert len(graph.plots)==2
    finally:
        tab.close(); root.destroy()


@pytest.mark.gui
def test_graph_fills_at_least_eighty_percent_of_window_and_resizes_both_ways():
    root, tab = _make_tab()
    try:
        root.deiconify()
        tab._job_kind = 'local'
        tab._job_result('result', _benchmark())
        graph = tab._plots.performance
        for width, height in ((800, 640), (1440, 900), (2400, 1600), (800, 640)):
            root.geometry(f'{width}x{height}')
            root.update()
            axes = next(graph.canvas.coords(item) for item in graph.canvas.find_all()
                        if graph.canvas.type(item) == 'line'
                        and len(graph.canvas.coords(item)) == 6
                        and graph.canvas.coords(item)[0] == graph.canvas.coords(item)[2]
                        and graph.canvas.coords(item)[3] == graph.canvas.coords(item)[5])
            assert axes[4] - axes[0] >= root.winfo_width() * .8
            assert axes[4] <= graph.canvas.winfo_width()
            if graph.canvas.winfo_height() >= 500:
                assert axes[3] - axes[1] >= graph.canvas.winfo_height() * .7
            assert graph._result.metadata['run_id'] == 'performance-run'
    finally:
        tab.close(); root.destroy()


@pytest.mark.gui
def test_detail_metrics_table_and_report_have_a_draggable_resizable_divider():
    root, tab = _make_tab()
    try:
        root.deiconify(); root.geometry('1000x800')
        tab._job_kind = 'local'; tab._job_result('result', _benchmark())
        tab._plots.select(tab._plots.details)
        root.update()
        panes = [child for child in _walk(tab._plots.details) if isinstance(child, tk.PanedWindow)]
        assert panes, 'The metrics table and text report need a user-adjustable divider'
        pane = panes[0]
        table_height, report_height = tab._results.winfo_height(), tab._details.winfo_height()
        table_width = tab._results.winfo_width()
        rows = tab._results.get_children()
        x, y = pane.winfo_width() // 2, pane.sash_coord(0)[1]
        pane.event_generate('<ButtonPress-1>', x=x, y=y)
        pane.event_generate('<B1-Motion>', x=x, y=y-80, state=0x100)
        pane.event_generate('<ButtonRelease-1>', x=x, y=y-80)
        root.update()
        assert tab._results.winfo_height() <= table_height - 50
        assert tab._details.winfo_height() >= report_height + 50
        assert tab._results.get_children() == rows
        root.geometry('1400x1000'); root.update()
        assert tab._results.winfo_width() > table_width
        assert tab._details.winfo_width() > table_width
        divider = pane.sash_coord(0)[1]
        tab._job_kind = 'local'; tab._job_result('result', _benchmark())
        tab._plots.select(tab._plots.details); root.update()
        assert abs(pane.sash_coord(0)[1] - divider) <= 2
        pane.sash_place(0, 0, pane.winfo_height() - 110); root.update()
        root.geometry('800x640'); root.update()
        assert tab._details.winfo_height() >= 90
        assert tab._results.winfo_height() >= 80
    finally:
        tab.close(); root.destroy()


@pytest.mark.gui
def test_matrix_hover_tracks_the_actual_cells_after_large_and_small_resizes():
    from sparc.analysis.plots import Plot

    root, tab = _make_tab()
    try:
        root.deiconify()
        matrix = [[None] * 128 for _ in range(4)]
        matrix[3][120] = 63.5
        graph = tab._plots.avalanche
        graph.show_plots([Plot('Conditional matrix', 'Output bit', 'Input bit', (), True,
                              matrix=tuple(tuple(row) for row in matrix))], 'Synthetic test matrix')
        tab._plots.select(graph)
        for width, height in ((2400, 1600), (800, 640)):
            root.geometry(f'{width}x{height}'); root.update()
            cells = [item for item in graph.canvas.find_all() if graph.canvas.type(item) == 'rectangle']
            x0, y0, x1, y1 = graph.canvas.coords(cells[3 * 128 + 120])
            graph.status.set('Waiting for hover')
            graph.canvas.event_generate('<Motion>', x=int((x0+x1)/2), y=int((y0+y1)/2))
            root.update()
            assert graph.status.get() == 'Input bit 3 / output bit 120: 63.5% of observed cases changed'
    finally:
        tab.close(); root.destroy()
