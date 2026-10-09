"""F1e GUI identity unlock entrypoint contract."""

from __future__ import annotations

import importlib
import inspect

import pytest


def test_gui_unlock_entrypoint_is_available_without_importing_it_at_collection():
    try:
        module = importlib.import_module("sparc.gui.identity_unlock")
    except ModuleNotFoundError as error:
        if error.name == "sparc.gui.identity_unlock":
            pytest.fail("the responsive GUI identity unlock module must be implemented")
        raise
    entrypoint = getattr(module, "unlock_identity_for_gui", None)
    assert callable(entrypoint)
    assert list(inspect.signature(entrypoint).parameters) == ["root", "data_dir"]
