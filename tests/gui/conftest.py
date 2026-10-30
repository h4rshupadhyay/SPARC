"""Release destroyed Tk interpreter cycles on their creating thread."""
import gc

import pytest


@pytest.fixture(autouse=True)
def collect_destroyed_tk_views():
    yield
    # Native widgets/parents and bound callbacks form cycles. A later peer
    # worker must not become the thread that runs Tk's Python finalizers.
    gc.collect()
