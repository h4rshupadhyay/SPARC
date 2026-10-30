"""Results are visible on completion and each graph category keeps its own run."""
import tkinter as tk
from tkinter import ttk
import xml.etree.ElementTree as ET

import pytest

from sparc.analysis.models import BenchmarkResult
from sparc.analysis.sensitivity import run_sensitivity
from test_analysis_view import _make_tab


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
