"""C7e default GUI launch and headless diagnostic integration contracts."""

from __future__ import annotations

import builtins
from pathlib import Path

from sparc.__main__ import main
from sparc.storage import resolve_data_dir


def test_default_launch_wires_three_core_tabs(tmp_path, monkeypatch):
    import sparc.gui.app as app_module
    import tkinter

    calls = []

    class FakeRoot:
        def title(self, value):
            calls.append(("title", value))

        def geometry(self, value):
            calls.append(("geometry", value))

        def minsize(self, *value):
            calls.append(("minsize", value))

        def protocol(self, name, callback):
            calls.append(("protocol", name, callback))

        def mainloop(self):
            calls.append(("mainloop",))

        def destroy(self):
            calls.append(("root.destroy",))

    class FakeService:
        def __init__(self, data_dir):
            calls.append(("service", Path(data_dir)))

        def close(self):
            calls.append(("service.close",))

    class FakeTab:
        def __init__(self, name):
            self.name = name
            self.widget = object()

        def close(self):
            calls.append((f"{self.name}.close",))

    class FakeApp:
        def __init__(self, root, service):
            self.root = root
            self.service = service
            self.notebook = object()
            self.names = []
            calls.append(("app",))

        def add_tab(self, name, tab):
            self.names.append(name)
            calls.append(("tab", name))

        def close(self):
            calls.append(("app.close",))

    monkeypatch.setattr(tkinter, "Tk", FakeRoot)
    monkeypatch.setattr(app_module, "PeerService", FakeService, raising=False)
    monkeypatch.setattr(app_module, "SparcApp", FakeApp, raising=False)
    monkeypatch.setattr(app_module, "ConnectionTab", lambda *_: FakeTab("Connection"), raising=False)
    monkeypatch.setattr(app_module, "ChatTab", lambda *_: FakeTab("Chat"), raising=False)
    monkeypatch.setattr(app_module, "AuditTab", lambda *_: FakeTab("Audit"), raising=False)

    result = main(["--data-dir", str(tmp_path)])

    names = [call[1] for call in calls if call[0] == "tab"]
    assert result == 0
    assert {"Connection", "Chat", "Audit"}.issubset(names)
    assert ("mainloop",) in calls
    assert ("service", resolve_data_dir(tmp_path)) in calls


def test_missing_tk_is_actionable_without_traceback(tmp_path, monkeypatch, capsys):
    import sparc.gui.app as app_module

    def no_tk(_data_dir):
        raise ModuleNotFoundError("No module named 'tkinter'", name="tkinter")

    monkeypatch.setattr(app_module, "launch", no_tk, raising=False)
    result = main(["--data-dir", str(tmp_path)])
    captured = capsys.readouterr()
    assert result != 0
    assert "tk" in captured.err.lower()
    assert any(word in captured.err.lower() for word in ("install", "python3-tk", "windows"))
    assert "traceback" not in captured.err.lower()


def test_check_remains_usable_without_tk_or_tshark(tmp_path, monkeypatch, capsys):
    real_import = builtins.__import__

    def reject_gui_and_tshark(name, *args, **kwargs):
        if name == "tkinter" or name.startswith(("tkinter.", "sparc.gui", "pyshark")):
            raise AssertionError(f"unexpected diagnostic import: {name}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", reject_gui_and_tshark)
    result = main(["--check", "--data-dir", str(tmp_path)])
    captured = capsys.readouterr()
    assert result == 0
    assert "SPARC:" in captured.out
    assert "Public fingerprint:" in captured.out


def test_launch_setup_failure_closes_service_and_root(tmp_path, monkeypatch):
    import sparc.gui.app as app_module
    import tkinter

    calls = []

    class FakeRoot:
        def title(self, _value):
            pass

        def geometry(self, _value):
            pass

        def minsize(self, *_value):
            pass

        def protocol(self, *_args):
            pass

        def destroy(self):
            calls.append("root.destroy")

    class FakeService:
        def __init__(self, _data_dir):
            pass

        def close(self):
            calls.append("service.close")

    class BrokenApp:
        def __init__(self, *_args):
            raise RuntimeError("injected app setup failure")

    monkeypatch.setattr(tkinter, "Tk", FakeRoot)
    monkeypatch.setattr(app_module, "PeerService", FakeService, raising=False)
    monkeypatch.setattr(app_module, "SparcApp", BrokenApp, raising=False)

    try:
        app_module.launch(resolve_data_dir(tmp_path))
    except RuntimeError as exc:
        assert "injected app setup failure" in str(exc)
    else:
        raise AssertionError("launch should propagate its setup failure")
    assert calls == ["service.close", "root.destroy"]
