"""C7e default GUI launch and headless diagnostic integration contracts."""

from __future__ import annotations

import builtins

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
        def close(self):
            calls.append(("service.close",))

        @classmethod
        def _from_unlocked_store(cls, handle):
            calls.append(("service", handle))
            return cls()

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
    handle = object()

    def unlock(_root, _data_dir):
        calls.append(("unlock_success",))
        return handle

    monkeypatch.setattr(app_module, "unlock_identity_for_gui", unlock, raising=False)
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
    assert calls.index(("unlock_success",)) < calls.index(("service", handle))
    assert calls.index(("service", handle)) < calls.index(("tab", "Connection"))
    assert sum(call[0] == "service" for call in calls) == 1


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
    data_dir = tmp_path / "diagnostic"
    real_import = builtins.__import__

    def reject_gui_and_tshark(name, *args, **kwargs):
        if name == "tkinter" or name.startswith(("tkinter.", "sparc.gui", "pyshark")):
            raise AssertionError(f"unexpected diagnostic import: {name}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", reject_gui_and_tshark)
    result = main(["--check", "--data-dir", str(data_dir)])
    captured = capsys.readouterr()
    assert result == 0
    assert "SPARC:" in captured.out
    assert "Public fingerprint:" in captured.out
    assert not data_dir.exists()


def test_gui_unlock_cancel_maps_to_interrupt_exit_without_traceback(
    tmp_path, monkeypatch, capsys
):
    import sparc.gui.app as app_module
    from sparc.models import SparcError

    def canceled(_data_dir):
        raise SparcError("identity_unlock_cancelled", "private cancellation detail")

    monkeypatch.setattr(app_module, "launch", canceled, raising=False)
    result = main(["--data-dir", str(tmp_path)])
    captured = capsys.readouterr()

    assert result == 130
    assert "SPARC launch canceled." in captured.err
    assert "Traceback" not in captured.err
    assert "private cancellation detail" not in captured.err


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
        def close(self):
            calls.append("service.close")

        @classmethod
        def _from_unlocked_store(cls, _handle):
            calls.append("service")
            return cls()

    class BrokenApp:
        def __init__(self, *_args):
            raise RuntimeError("injected app setup failure")

    monkeypatch.setattr(tkinter, "Tk", FakeRoot)
    monkeypatch.setattr(
        app_module,
        "unlock_identity_for_gui",
        lambda _root, _data_dir: (calls.append("unlock_success") or object()),
        raising=False,
    )
    monkeypatch.setattr(app_module, "PeerService", FakeService, raising=False)
    monkeypatch.setattr(app_module, "SparcApp", BrokenApp, raising=False)

    try:
        app_module.launch(resolve_data_dir(tmp_path))
    except RuntimeError as exc:
        assert "injected app setup failure" in str(exc)
    else:
        raise AssertionError("launch should propagate its setup failure")
    assert calls == ["unlock_success", "service", "service.close", "root.destroy"]


def test_canceled_unlock_never_constructs_service(tmp_path, monkeypatch):
    import sparc.gui.app as app_module
    import tkinter
    from sparc.models import SparcError

    calls = []

    class FakeRoot:
        def title(self, _value):
            pass

        def geometry(self, _value):
            pass

        def minsize(self, *_value):
            pass

        def destroy(self):
            calls.append("root.destroy")

    class FakeService:
        @classmethod
        def _from_unlocked_store(cls, _handle):
            calls.append("service")
            return cls()

    def canceled(_root, _data_dir):
        raise SparcError("identity_unlock_cancelled", "canceled by test")

    monkeypatch.setattr(tkinter, "Tk", FakeRoot)
    monkeypatch.setattr(app_module, "unlock_identity_for_gui", canceled, raising=False)
    monkeypatch.setattr(app_module, "PeerService", FakeService, raising=False)

    try:
        app_module.launch(resolve_data_dir(tmp_path))
    except SparcError as error:
        assert error.code == "identity_unlock_cancelled"
    else:
        raise AssertionError("canceled unlock must stop launch")
    assert calls == ["root.destroy"]
