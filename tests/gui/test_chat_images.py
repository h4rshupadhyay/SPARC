"""Images are ordinary chronological Chat attachments with inline controls."""
import hashlib
from pathlib import Path
import tkinter as tk
from tkinter import ttk

import pytest

from sparc.models import ServiceEvent
from test_chat_view import _make_tab, _visible, _walk, _pump, _message, FakeService


class ImageService(FakeService):
    def send_image(self,path): self.calls.append(('send_image',Path(path))); return 'a'*32
    def respond_to_image(self,tid,path): self.calls.append(('respond',tid,path))
    def cancel_image(self,tid): self.calls.append(('cancel',tid))


def button(tab,label):
    return next(w for w in _walk(tab.widget) if isinstance(w,ttk.Button) and w.cget('text')==label)


def picture(tmp_path):
    from PIL import Image
    p=tmp_path/'test.png'; Image.new('RGB',(40,30),'navy').save(p); return p


def transfer(tid='a'*32,origin='incoming',status='offered',path=None):
    return ServiceEvent('image_transfer',dict(transfer_id=tid,origin=origin,status=status,
        filename='test.png',size=101,sha256='b'*64,media_type='image/png',bytes_done=0,
        path=str(path) if path else None,peer_fingerprint='c'*64,inspection=None))


def test_attach_preview_and_send_stay_in_chat_and_preserve_text_draft(tmp_path,monkeypatch):
    service=ImageService(); root,tab,_=_make_tab(service)
    try:
        tab.handle_event(ServiceEvent('state',dict(state='connected')))
        tab._input.insert('1.0','draft text remains')
        path=picture(tmp_path)
        monkeypatch.setattr('sparc.gui.image_chat.filedialog.askopenfilename',lambda **kw:str(path))
        button(tab,'Attach image').invoke()
        _pump(root,lambda:'Original image' in _visible(tab.widget),timeout=3)
        assert tab._input.get('1.0','end-1c')=='draft text remains'
        assert 'Original image' in _visible(tab.widget)
        assert hashlib.sha256(path.read_bytes()).hexdigest() in _visible(tab.widget)
        button(tab,'Send image').invoke()
        _pump(root,lambda:any(c[0]=='send_image' for c in service.calls))
        assert tab._input.get('1.0','end-1c')=='draft text remains'
        assert 'disabled' not in tab._send_button.state()
    finally: tab.close(); root.destroy()


def test_incoming_offer_accepts_in_chat_and_only_verified_file_gets_preview(tmp_path,monkeypatch):
    service=ImageService(); root,tab,_=_make_tab(service)
    try:
        tab.handle_event(ServiceEvent('state',dict(state='connected')))
        path=picture(tmp_path)
        tab.handle_event(_message('1'*32,'before image'))
        tab.handle_event(transfer(path=path))
        tab.handle_event(_message('2'*32,'after image'))
        visible=_visible(tab.widget)
        assert visible.index('before image')<visible.index('test.png')<visible.index('after image')
        assert 'Recovered image' not in visible
        monkeypatch.setattr('sparc.gui.image_chat.filedialog.asksaveasfilename',lambda **kw:str(tmp_path/'saved.png'))
        button(tab,'Accept and save').invoke()
        _pump(root,lambda:any(c[0]=='respond' for c in service.calls))
        assert ('respond','a'*32,tmp_path/'saved.png') in service.calls
        tab.handle_event(transfer(status='verified',path=path))
        _pump(root,lambda:'Recovered image' in _visible(tab.widget),timeout=3)
        assert tab._images.thumbnail_count<=16
        assert 'b'*64 in tab._inspector.get('1.0','end') or 'test.png' in tab._history.get('1.0','end')
    finally: tab.close(); root.destroy()


def test_inline_reject_cancel_and_history_keyboard_selection():
    service=ImageService(); root,tab,_=_make_tab(service)
    try:
        tab.handle_event(ServiceEvent('state',dict(state='connected')))
        tab.handle_event(transfer())
        button(tab,'Reject').invoke()
        _pump(root,lambda:('respond','a'*32,None) in service.calls)
        tab.handle_event(transfer(tid='d'*32,origin='outgoing',status='transferring'))
        button(tab,'Cancel transfer').invoke()
        _pump(root,lambda:('cancel','d'*32) in service.calls)
        tab._history.select(0)
        assert tab._history.curselection()==(0,)
        assert 'a'*32 in tab._inspector.get('1.0','end')
    finally: tab.close(); root.destroy()


def test_image_summaries_are_bounded_and_close_clears_previews():
    root,tab,_=_make_tab(ImageService())
    try:
        for i in range(105): tab.handle_event(transfer(tid=f'{i:032x}',status='rejected'))
        assert sum(e.get('kind')=='image' for e in tab._entries)<=100
        tab.close()
        assert tab._images.thumbnail_count==0 and not tab._entries
        tab.handle_event(transfer(status='verified'))
        assert not tab._entries
    finally: tab.close(); root.destroy()


def test_history_refresh_does_not_accumulate_tcl_callbacks():
    root,tab,_=_make_tab(ImageService())
    try:
        before=len(tab._history._tclCommands or [])
        for i in range(30): tab.handle_event(_message(f'{i:032x}',f'line {i}'))
        assert len(tab._history._tclCommands or [])<=before+2
    finally: tab.close(); root.destroy()


def test_reading_old_history_preserves_scroll_position_on_new_message():
    root,tab,_=_make_tab(ImageService())
    try:
        root.geometry('800x640'); root.deiconify(); tab.widget.master.pack_configure(fill='both',expand=True)
        for i in range(80): tab.handle_event(_message(f'{i:032x}',f'line {i}'))
        root.update(); tab._history.yview_moveto(.2); root.update()
        before=tab._history.yview()[0]
        tab.handle_event(_message('f'*32,'latest message')); root.update()
        assert abs(tab._history.yview()[0]-before)<.02
    finally: tab.close(); root.destroy()
