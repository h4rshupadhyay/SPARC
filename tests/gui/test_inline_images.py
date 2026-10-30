"""Inline receive/save and native file dropping without interrupting drafts."""
from pathlib import Path
from types import SimpleNamespace
import tkinter as tk

from test_chat_images import ImageService, button, picture, transfer
from test_chat_view import _make_tab, _pump, _visible
from test_chat_view import _message, _walk
from sparc.models import ServiceEvent


class RuntimeService(ImageService):
    def receive_image(self, tid):
        self.calls.append(('receive', tid))


def test_offer_receives_automatically_and_save_is_independent_of_connection(tmp_path, monkeypatch):
    service = RuntimeService()
    root, tab, _ = _make_tab(service)
    try:
        tab.handle_event(ServiceEvent('state', {'state': 'connected'}))
        tab._input.insert('1.0', 'keep this draft')
        monkeypatch.setattr('sparc.gui.image_chat.filedialog.asksaveasfilename',
                            lambda **_: str(tmp_path / 'saved.png'))
        tab.handle_event(transfer())
        _pump(root, lambda: ('receive', 'a' * 32) in service.calls)
        assert ('receive', 'a' * 32) in service.calls
        assert 'Accept and save' not in _visible(tab.widget)
        assert 'Reject' not in _visible(tab.widget)
        source = picture(tmp_path)
        tab.handle_event(transfer(status='verified', path=source))
        tab.handle_event(ServiceEvent('state', {'state': 'disconnected'}))
        button(tab, 'Save image').invoke()
        _pump(root, lambda: (tmp_path / 'saved.png').exists(), timeout=3)
        assert (tmp_path / 'saved.png').read_bytes() == source.read_bytes()
        assert tab._input.get('1.0', 'end-1c') == 'keep this draft'
    finally:
        tab.close(); root.destroy()


def test_text_messages_have_distinct_directional_bubbles():
    root, tab, _ = _make_tab(RuntimeService())
    try:
        root.geometry('1200x900'); root.deiconify()
        tab.widget.master.pack_configure(fill='both', expand=True)
        tab.handle_event(_message('1' * 32, 'Incoming message', origin='incoming'))
        tab.handle_event(_message('2' * 32, 'Outgoing message', origin='outgoing'))
        root.update()
        bubbles = [w for w in _walk(tab._history) if isinstance(w, tk.Canvas) and w.find_withtag('bubble')]
        assert len(bubbles) == 2
        incoming, outgoing = bubbles
        assert incoming.itemcget('bubble', 'fill') != outgoing.itemcget('bubble', 'fill')
        assert outgoing.bbox('bubble')[0] > incoming.bbox('bubble')[0]
        assert 'Incoming message' in tab._history.get('1.0', 'end')
        tab._history.select(0); root.update()
        tab.handle_event(_message('3' * 32, 'Latest message'))
        root.update()
        assert incoming.winfo_exists() and outgoing.winfo_exists()
    finally:
        tab.close(); root.destroy()


def test_drop_spaced_path_prepares_image_then_sends_preserving_text(tmp_path):
    service = RuntimeService()
    root, tab, _ = _make_tab(service)
    try:
        tab.handle_event(ServiceEvent('state', {'state': 'connected'}))
        source = picture(tmp_path).rename(tmp_path / 'image with spaces.png')
        tab._input.insert('1.0', 'draft stays')
        assert tab._images._drop.available
        event = SimpleNamespace(data=root.tk.call('list', str(source)))
        assert tab._images._drop.handle(event) == 'copy'
        _pump(root, lambda: tab._images._attachment == source, timeout=3)
        assert tab._images._attachment == source
        button(tab, 'Send image').invoke()
        _pump(root, lambda: ('send_image', source) in service.calls)
        assert ('send_image', source) in service.calls
        assert tab._input.get('1.0', 'end-1c') == 'draft stays'
        assert tab._images._drop.handle(SimpleNamespace(data=root.tk.call('list', str(source), str(source)))) == 'refuse_drop'
        assert 'one image' in tab._error.get().lower()
        _pump(root, lambda: tab._images._attachment is None)
        unsupported = tmp_path / 'document.txt'
        unsupported.write_text('This is not an image.')
        tab._images._drop.handle(SimpleNamespace(data=root.tk.call('list', str(unsupported))))
        _pump(root, lambda: 'Preparing' not in tab._error.get(), timeout=3)
        assert tab._error.get() and tab._images._attachment is None
        assert tab._input.get('1.0', 'end-1c') == 'draft stays'
        bindings = [binding for _, binding in tab._images._drop._widgets]
        tab.close()
        assert all(not root.tk.call('info', 'commands', binding) for binding in bindings)
    finally:
        tab.close(); root.destroy()
