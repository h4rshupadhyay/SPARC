"""Native Analysis graphs use measured results and clear stale displays."""
from pathlib import Path
import tkinter as tk
from test_analysis_view import _make_tab, _pump, _visible
from sparc.analysis.models import BenchmarkResult
def benchmark():
    return BenchmarkResult({},[],[
        dict(operation='encrypt',payload_bytes=64,mean_ns=1000,throughput_bytes_s=1048576),
        dict(operation='encrypt',payload_bytes=1024,mean_ns=3000,throughput_bytes_s=2097152),
    ],True)


def test_analysis_renders_filters_and_exports_real_benchmark_graphs(tmp_path,monkeypatch):
    root,tab=_make_tab()
    try:
        tab._job_kind='local'
        tab._job_result('result',benchmark())
        root.update()
        view=tab._plots
        assert len(view.plots)==2
        assert any('Mean duration' in str(view.canvas.itemcget(i,'text'))
                   for i in view.canvas.find_all() if view.canvas.type(i)=='text')
        view.operation.set('Sign/verify'); view.refresh()
        assert not view.plots
        view.operation.set('Encrypt/decrypt'); view.refresh()
        path=tmp_path/'graphs.svg'
        monkeypatch.setattr('sparc.gui.plot_view.filedialog.asksaveasfilename',lambda **kw:str(path))
        view.export()
        assert path.exists() and 'Local cryptographic throughput' in path.read_text()
        tab._job_kind='specimen_verify'; tab._job_result('result',True)
        assert not view.plots
    finally: tab.close(); root.destroy()


def test_graph_resize_is_coalesced_and_close_cancels_redraw():
    root,tab=_make_tab()
    try:
        tab._job_kind='local'; tab._job_result('result',benchmark())
        for i in range(25): tab._plots.schedule_draw()
        assert tab._plots._draw_id is not None
        tab.close()
        assert tab._plots._draw_id is None
        root.update()
    finally: tab.close(); root.destroy()
