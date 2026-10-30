"""The presentation uses actual jobs, custom inputs and the visible result."""
import json
from pathlib import Path

import pytest
from test_analysis_view import _make_tab, _pump, _visible
from sparc.analysis.models import BenchmarkResult
from sparc.analysis.specimen import SignatureResult

def settled(root, tab):
    _pump(root, lambda:not tab._busy, timeout=5)
    assert not tab._busy

def test_specimen_export_saves_the_visible_signature_instead_of_previous_benchmark(tmp_path, monkeypatch):
    root, tab = _make_tab()
    try:
        tab._job_kind='local'; tab._job_result('result',BenchmarkResult({},[],[],True))
        tab._make_specimen_button.invoke(); settled(root,tab)
        assert isinstance(tab._last_result,SignatureResult)
        path=tmp_path/'signature.json'
        monkeypatch.setattr('sparc.gui.analysis_view.filedialog.asksaveasfilename',lambda **_:str(path))
        tab._save_button.invoke(); settled(root,tab)
        saved=json.loads(path.read_text())
        assert saved['kind']=='signature'
        assert saved['data']['signature']==tab._specimen_signature.get()
    finally: tab.close(); root.destroy()

def test_specimen_verification_keeps_matching_generation_time_and_measures_verification():
    root,tab=_make_tab()
    try:
        tab._make_specimen_button.invoke(); settled(root,tab)
        prior=tab._last_result
        assert prior.signature.hex() in tab._details.get('1.0','end')
        tab._verify_specimen_button.invoke(); settled(root,tab)
        assert isinstance(tab._last_result,SignatureResult)
        assert tab._last_result.sign_ns==prior.sign_ns
        assert tab._last_result.verify_ns>=0 and tab._last_result.valid
        assert 'Signature verification' in _visible(tab.widget)
        old=tab._specimen_signature.get()
        tab._specimen_signature.set(('00' if old[:2]!='00' else '01')+old[2:])
        tab._verify_specimen_button.invoke(); settled(root,tab)
        assert not tab._last_result.valid and tab._last_result.sign_ns is None
    finally: tab.close(); root.destroy()

def test_custom_message_gui_shows_exact_input_outputs_and_saves_that_result(tmp_path, monkeypatch):
    root,tab=_make_tab()
    try:
        form=getattr(tab,'_message_lab',None)
        assert form is not None, 'custom message form is missing'
        form.text.insert('1.0','Custom message — 中文\nsecond line')
        form.button.invoke(); settled(root,tab)
        result=tab._last_result
        assert result.recovered_text=='Custom message — 中文\nsecond line'
        details=tab._details.get('1.0','end')
        assert result.digest in details and result.signature.hex() in details
        assert 'Hash: match' in details and 'Recovered text matches' in details
        root.geometry('800x640'); root.deiconify(); root.update()
        assert tab._details.winfo_height()>=90
        path=tmp_path/'message.json'
        monkeypatch.setattr('sparc.gui.analysis_view.filedialog.asksaveasfilename',lambda **_:str(path))
        tab._save_button.invoke(); settled(root,tab)
        assert json.loads(path.read_text())['data']['plaintext']==result.plaintext
    finally: tab.close(); root.destroy()

def test_custom_sensitivity_gui_uses_entered_block_and_reports_invalid_lengths():
    root,tab=_make_tab()
    try:
        source=getattr(tab,'_trial_source',None)
        assert source is not None, 'custom sensitivity controls are missing'
        source.set('Custom input')
        tab._custom_key.set('00'*32); tab._custom_block.set('0123456789abcdef')
        tab._block_encoding.set('UTF-8'); tab._trial_button.invoke(); settled(root,tab)
        assert tab._last_result.block==b'0123456789abcdef'
        assert tab._last_result.input_source=='custom'
        tab._custom_block.set('too short'); tab._trial_button.invoke(); settled(root,tab)
        assert '16 bytes' in tab._status.get() and not tab._busy
    finally: tab.close(); root.destroy()

def test_load_public_specimen_rechecks_signature_and_updates_current_export(tmp_path,monkeypatch):
    from sparc.analysis.artifacts import save_artifact
    from sparc.analysis.specimen import make_timed_specimen
    public,signed,sig,sign_ns=make_timed_specimen()
    path=tmp_path/'specimen.json'; save_artifact(SignatureResult(public,signed,sig,True,sign_ns),path)
    root,tab=_make_tab()
    try:
        button=getattr(tab,'_load_specimen_button',None)
        assert button is not None,'load specimen is missing'
        monkeypatch.setattr('sparc.gui.analysis_view.filedialog.askopenfilename',lambda **_:str(path))
        button.invoke(); settled(root,tab)
        assert tab._last_result.valid and tab._last_result.signature==sig
        assert tab._last_result.verify_ns>=0 and tab._specimen_signature.get()==sig.hex()
    finally: tab.close(); root.destroy()

def test_graph_legend_and_scope_remain_visible_at_compact_size():
    root,tab=_make_tab()
    try:
        root.geometry('800x640'); root.deiconify()
        result=BenchmarkResult({'repetitions':100,'sizes':[64,1024,16384]},[],[
            dict(operation=op,payload_bytes=size,count=100,mean_ns=2000,p95_ns=4000,throughput_bytes_s=100000)
            for op in ('encrypt','decrypt') for size in (64,1024,16384)],True)
        tab._job_kind='local'; tab._job_result('result',result); root.update()
        graph=tab._plots.performance
        legend=getattr(graph,'_legend_frame',None)
        assert legend is not None,'fixed graph legend is missing'
        assert legend.winfo_ismapped()
        assert graph._scope_label.winfo_ismapped()
        assert graph._scope_label.winfo_rooty()+graph._scope_label.winfo_height()<=tab.widget.winfo_rooty()+tab.widget.winfo_height()
        assert '100' in graph.scope.get()
    finally: tab.close(); root.destroy()

def test_primary_experiment_actions_are_reachable_without_form_scrolling():
    root,tab=_make_tab()
    try:
        root.geometry('800x640'); root.deiconify(); root.update()
        for name,button in (('Performance',tab._local_button),('Hash security',tab._hash_button),('Message lab',tab._message_lab.button)):
            tab._workspace.select(tab._experiments); tab._experiment_kind.set(name); tab._select_experiment(); root.update()
            assert button.winfo_ismapped()
            assert button.winfo_rooty()+button.winfo_height()<=tab._canvas.winfo_rooty()+tab._canvas.winfo_height()
    finally: tab.close(); root.destroy()

def test_custom_sensitivity_is_independent_of_unused_seed_fields():
    root,tab=_make_tab()
    try:
        tab._trial_source.set('Custom input'); tab._seed.set('unused seed'); tab._case_index.set('unused case')
        tab._custom_key.set('00'*32); tab._custom_block.set('0123456789abcdef')
        tab._trial_button.invoke(); settled(root,tab)
        assert getattr(tab._last_result,'input_source',None)=='custom'
    finally: tab.close(); root.destroy()

def test_gui_allows_more_local_sizes_but_retains_network_bounds():
    root,tab=_make_tab()
    try:
        tab._sizes.set('64,128,256,512,1024,2048,4096,8192,16384')
        tab._warmups.set('0'); tab._local_repetitions.set('1')
        tab._local_button.invoke(); settled(root,tab)
        assert tab._last_result is not None and len(tab._last_result.samples)==54
        with pytest.raises(ValueError): tab._read_workload(tab._network_repetitions,100)
    finally: tab.close(); root.destroy()
