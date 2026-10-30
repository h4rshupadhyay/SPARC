"""C7a GUI shell contracts; requires a working Tk display."""

from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
from tkinter import TclError

import pytest

from sparc.gui.app import SparcApp
from sparc.models import ServiceEvent


def _root_or_skip():
    try:
        root = tk.Tk()
    except TclError as exc:
        pytest.skip(f"Tk display unavailable: {exc}")
    root.withdraw()
    return root


class FakeService:
    def __init__(self):
        self.events = queue.Queue(maxsize=1)
        self.calls = []

    def close(self):
        self.calls.append("service.close")


class Tab:
    def __init__(self, root, calls):
        self.widget = tk.Frame(root)
        self.calls = calls

    def handle_event(self, event):
        self.calls.append(("event", threading.get_ident(), event))

    def close(self):
        self.calls.append(("tab.close", threading.get_ident()))
        self.widget.destroy()


def test_event_dispatch_stays_on_tk_thread():
    root = _root_or_skip()
    service = FakeService()
    calls = []
    app = SparcApp(root, service)
    tab = Tab(root, calls)
    app.add_tab("test", tab)
    event = ServiceEvent("progress", {"step": 1})
    service.events.put(event)

    deadline = time.monotonic() + 1.0
    while not calls and time.monotonic() < deadline:
        root.update()
        time.sleep(0.005)

    assert calls == [("event", threading.get_ident(), event)]
    app.close()


def test_close_ignores_late_worker_events():
    root = _root_or_skip()
    service = FakeService()
    calls = []
    app = SparcApp(root, service)
    tab = Tab(root, calls)
    app.add_tab("test", tab)
    original_destroy = root.destroy
    destroy_calls = []

    def counted_destroy():
        destroy_calls.append(threading.get_ident())
        original_destroy()

    root.destroy = counted_destroy
    app.close()
    app.close()  # idempotent

    service.events.put(ServiceEvent("late", {}))
    assert [call[0] for call in calls] == ["tab.close"]
    assert service.calls == ["service.close"]
    assert destroy_calls == [threading.get_ident()]
    assert root.tk.splitlist(root.tk.call("after", "info")) == ()


@pytest.mark.parametrize('failing_owner', ['tab', 'service'])
def test_close_releases_every_owner_when_one_close_raises(failing_owner):
    root = _root_or_skip()
    service = FakeService()
    app = SparcApp(root, service)
    calls = []

    class ClosingTab:
        def __init__(self, name):
            self.widget = tk.Frame(app.notebook)
            self.name = name

        def close(self):
            calls.append(self.name)
            if self.name == 'first' and failing_owner == 'tab':
                raise RuntimeError('tab close failed')

    def close_service():
        calls.append('service')
        if failing_owner == 'service':
            raise RuntimeError('service close failed')

    original_destroy = root.destroy

    def destroy():
        calls.append('root')
        original_destroy()

    service.close = close_service
    root.destroy = destroy
    app.add_tab('First', ClosingTab('first'))
    app.add_tab('Second', ClosingTab('second'))
    try:
        with pytest.raises(RuntimeError, match=f'{failing_owner} close failed'):
            app.close()
        assert calls == ['first', 'second', 'service', 'root']
        assert root.tk.splitlist(root.tk.call('after', 'info')) == ()
        app.close()
        assert calls == ['first', 'second', 'service', 'root']
    finally:
        try:
            original_destroy()
        except TclError:
            pass
