"""One local Analysis navigation row and focused experiment configuration."""
import pytest
from tkinter import ttk
from test_analysis_view import _make_tab


@pytest.mark.gui
def test_analysis_has_direct_result_sections_in_one_local_notebook():
    root, tab = _make_tab()
    try:
        names = [tab._workspace.tab(item, 'text') for item in tab._workspace.tabs()]
        assert names == ['Experiments', 'Performance', 'Avalanche', 'Details', 'Operation metrics']
        assert tab._plots.performance.master is tab._workspace
        assert tab._plots.avalanche.master is tab._workspace
    finally:
        tab.close(); root.destroy()


@pytest.mark.gui
def test_experiment_selector_preserves_inputs_and_shows_only_relevant_form():
    root, tab = _make_tab()
    try:
        root.deiconify(); root.geometry('800x640')
        tab._warmups.set('2')
        tab._experiment_kind.set('Avalanche')
        tab._experiment_choice.event_generate('<<ComboboxSelected>>'); root.update()
        assert tab._experiment_frames['Avalanche'].winfo_ismapped()
        assert not tab._experiment_frames['Performance'].winfo_ismapped()
        tab._experiment_kind.set('Performance')
        tab._experiment_choice.event_generate('<<ComboboxSelected>>'); root.update()
        assert tab._warmups.get() == '2'
        assert tab._experiment_frames['Performance'].winfo_ismapped()
        assert not tab._experiment_frames['Avalanche'].winfo_ismapped()
    finally:
        tab.close(); root.destroy()
