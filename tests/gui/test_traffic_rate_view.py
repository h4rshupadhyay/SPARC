"""The capture-time graph stays separate from aggregate/verified goodput."""
from test_traffic_view import _tab, _report

def test_rate_view_displays_bounded_capture_bins_and_clears_on_source_change(tmp_path):
    root,tab=_tab()
    try:
        view=getattr(tab,'_rate_plot',None)
        assert view is not None,'capture-time graph is missing'
        report=_report()
        report.metadata['capture_rate_bins']={'available':True,'width_s':'1','origin_timestamp':'1',
            'offsets_s':['0','1','2'],'captured_bytes':[100,0,80], 'bytes_s':['100','0','80'],
            'definition':'Nominal bin width; final bin can be partial.'}
        tab._show_report(report); root.update()
        assert view.plots and view.plots[0].y_label=='Captured bytes / nominal bin (B/s)'
        assert sum(y for x,y in view.plots[0].series[0].points)==180
        root.geometry('800x640'); root.deiconify()
        tab._results_tabs.select(view); root.update()
        assert view.canvas.winfo_height()>=180
        tab._select_source(tmp_path/'other.pcap')
        assert not view.plots
    finally: tab.close(); root.destroy()
