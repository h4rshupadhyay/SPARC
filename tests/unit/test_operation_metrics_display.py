"""Operation metric rendering without a Tk display."""

from sparc.analysis.operation_metrics import OperationMetrics
from sparc.gui.analysis_view import AnalysisTab
from sparc.models import ServiceEvent


class MetricTable:
    """Collect widget writes while keeping the real renderer and collector."""

    def __init__(self):
        self.rows = {}

    def get_children(self, parent):
        return tuple(self.rows)

    def delete(self, row):
        del self.rows[row]

    def insert(self, parent, index, *, values):
        self.rows[len(self.rows)] = values


def _tab(events):
    tab = object.__new__(AnalysisTab)
    tab._closed = False
    tab._metrics = MetricTable()
    tab._operation_metrics = OperationMetrics()
    for data in events:
        tab._operation_metrics.add(ServiceEvent("operation_metrics", data))
    return tab


def test_missing_byte_counts_render_as_dashes_without_inventing_measurements():
    tab = _tab([
        {"operation": "handshake", "elapsed_ns": 8624355, "success": True},
        {"operation": "audit", "elapsed_ns": 1447208, "success": True,
         "encoded_bytes": 638, "context": {"event": "pairing_outcome"}},
        {"operation": "encrypt", "elapsed_ns": 20, "success": True,
         "encoded_bytes": 0, "frame_bytes": 96},
    ])

    tab._render_operation_metrics()
    rows = list(tab._metrics.rows.values())

    assert rows[0][3:5] == ("—", "—")
    assert rows[1][3:5] == ("638", "—")
    assert rows[2][3:5] == ("0", "96")
    assert rows[0][1] == "8624355"
    assert rows[1][-1] == "{'event': 'pairing_outcome'}"
    samples = tab._operation_metrics.result().samples
    assert samples[0]["encoded_bytes"] is None
    assert samples[1]["frame_bytes"] is None


def test_metrics_refresh_replaces_rows_and_displays_latest_500_samples():
    tab = _tab([
        {"operation": "audit", "elapsed_ns": index, "success": True,
         "encoded_bytes": index}
        for index in range(600)
    ])

    tab._render_operation_metrics()
    tab._render_operation_metrics()
    rows = list(tab._metrics.rows.values())

    assert len(rows) == 500
    assert rows[0][3] == "100"
    assert rows[-1][3] == "599"
    assert len(tab._operation_metrics.result().samples) == 600
