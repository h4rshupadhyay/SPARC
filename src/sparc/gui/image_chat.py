"""Chat attachment composer, inline transfer actions, and bounded thumbnail jobs."""
from collections import OrderedDict
import hashlib
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import filedialog, ttk

from ..images import inspect_image, make_thumbnail
from ..protocol.files import CHUNK_BYTES
from .jobs import JobController

_TERMINAL={'verified','rejected','canceled','failed','unconfirmed'}


class ImageChat:
    def __init__(self,chat,compose,actions=None):
        self.chat=chat
        self._closed=False
        self._attachment=None
        self._attachment_photo=None
        self._thumbs=OrderedDict()
        self._requested=set()
        self._failed=set()
        self._requests=queue.Queue(16)
        self._results=queue.Queue(16)
        self._stop=threading.Event()
        self._job=JobController(chat.widget,self._job_result)
        self._attach_button=ttk.Button(actions if actions is not None else compose,text='Attach image',command=self.attach)
        self._attach_button.grid(row=0 if actions is not None else 1,column=0,sticky='w')
        self._attachment_frame=ttk.Frame(compose,padding=(0,6,0,0))
        self._attachment_frame.columnconfigure(1,weight=1)
        self._attachment_label=ttk.Label(self._attachment_frame)
        self._attachment_label.grid(row=0,column=0,rowspan=2,sticky='nw',padx=(0,8))
        self._attachment_details=ttk.Label(self._attachment_frame,wraplength=500)
        self._attachment_details.grid(row=0,column=1,sticky='nw')
        actions=ttk.Frame(self._attachment_frame)
        actions.grid(row=1,column=1,sticky='w',pady=(4,0))
        self._send_image=ttk.Button(actions,text='Send image',command=self.send)
        self._send_image.grid(row=0,column=0,padx=(0,6))
        ttk.Button(actions,text='Remove attachment',command=self.remove).grid(row=0,column=1)
        self._worker=threading.Thread(target=self._thumbnail_worker,name='sparc-preview',daemon=True)
        self._worker.start()
        self._after=chat.widget.after(50,self._poll)
        self.state()

    @property
    def thumbnail_count(self): return len(self._thumbs)

    def _photo(self,image, maximum=(320,180)):
        from PIL import ImageTk
        display = image.copy()
        display.thumbnail(maximum)
        return ImageTk.PhotoImage(display,master=self.chat.widget)

    def state(self):
        connected=self.chat._connected and not self._closed
        self._send_image.state(['!disabled'] if connected and self._attachment else ['disabled'])
        self._attach_button.state(['!disabled'] if not self._closed else ['disabled'])
        if not connected:
            for entry in self.chat._entries:
                if entry.get('kind')=='image' and entry['status'] not in _TERMINAL:
                    entry['status']='unconfirmed' if entry['origin']=='outgoing' else 'canceled'

    def attach(self):
        if self._closed: return
        path=filedialog.askopenfilename(parent=self.chat.widget.winfo_toplevel(),title='Attach an image',
            filetypes=(('Images','*.png *.jpg *.jpeg *.gif *.webp'),('All files','*')))
        if not path: return
        self.chat._error.set('Preparing image preview…')
        def work(cancel,emit):
            info=inspect_image(Path(path))
            thumb=make_thumbnail(Path(path))
            digest=hashlib.sha256()
            size=0
            with open(path,'rb') as source:
                while not cancel.is_set():
                    data=source.read(CHUNK_BYTES)
                    if not data: break
                    size+=len(data); digest.update(data)
            if cancel.is_set(): return None
            return ('attachment',Path(path),info,thumb,size,digest.hexdigest())
        self._start(work)

    def _start(self,work):
        try: self._job.start(work)
        except RuntimeError as exc: self.chat._error.set(str(exc))

    def _job_result(self,kind,value):
        if self._closed: return
        if kind=='error':
            self.chat._error.set(str(value)); return
        if kind!='result' or value is None: return
        if value[0]=='attachment':
            _,path,info,thumb,size,digest=value
            self._attachment=path
            self._attachment_photo=self._photo(thumb,(160,100))
            self._attachment_label.configure(image=self._attachment_photo)
            self._attachment_details.configure(text=f'Original image · {path.name}\n{info.format} · {info.width} × {info.height} · {size:,} bytes\nSHA-256: {digest}')
            self._attachment_frame.grid(row=3,column=0,sticky='ew')
            self.chat._error.set('')
            self.state()
        else:
            self.chat._error.set('')

    def remove(self):
        self._attachment=None
        self._attachment_label.configure(image='')
        self._attachment_photo=None
        self._attachment_frame.grid_remove()
        self.state()

    def send(self):
        if self._closed or not self.chat._connected or self._attachment is None: return
        path=self._attachment
        def work(cancel,emit):
            if not cancel.is_set(): self.chat.service.send_image(path)
            return ('sent',)
        self._start(work)
        self.remove()

    def handle(self,data):
        tid=data.get('transfer_id'); origin=data.get('origin')
        if not isinstance(tid,str) or origin not in {'incoming','outgoing'}: return
        key=(origin,'image:'+tid)
        entry=self.chat._by_key.get(key)
        if entry is None:
            entry=dict(kind='image',key=key,message_id=tid,text=data.get('filename','Image'),
                       inspection=None,direction=None,sequence=None)
            entry.update(data)
            self.chat._append(entry)
        else:
            inspection=data.get('inspection') or entry.get('inspection')
            entry.update(data); entry['inspection']=inspection
        images=[e for e in self.chat._entries if e.get('kind')=='image']
        while len(images)>100:
            oldest=next((e for e in images if e['status'] in _TERMINAL),None)
            if oldest is None: break
            self.chat._entries.remove(oldest); images.remove(oldest)
            self.chat._by_key.pop(oldest['key'],None)
        self.chat._refresh_history()

    def _action(self,entry,decision):
        if self._closed or not self.chat._connected: return
        tid=entry['transfer_id']
        destination=None
        if decision=='accept':
            filename=filedialog.asksaveasfilename(parent=self.chat.widget.winfo_toplevel(),
                       title='Accept image and save',initialfile=entry['filename'])
            if not filename: return
            destination=Path(filename)
        def work(cancel,emit):
            if cancel.is_set(): return None
            if decision=='cancel': self.chat.service.cancel_image(tid)
            else: self.chat.service.respond_to_image(tid,destination)
            return ('action',)
        self._start(work)

    def actions(self,entry):
        if not self.chat._connected: return []
        if entry['status']=='offered' and entry['origin']=='incoming':
            return [('Accept and save',lambda:self._action(entry,'accept')),
                    ('Reject',lambda:self._action(entry,'reject'))]
        if entry['status'] not in _TERMINAL:
            return [('Cancel transfer',lambda:self._action(entry,'cancel'))]
        return []

    def thumbnail(self,entry):
        path=entry.get('path')
        if not path: return None
        if path in self._thumbs:
            self._thumbs.move_to_end(path)
            return self._thumbs[path]
        if path not in self._requested and path not in self._failed:
            try:
                self._requests.put_nowait(path)
                self._requested.add(path)
            except queue.Full: pass
        return None

    def _thumbnail_worker(self):
        while not self._stop.is_set():
            try: path=self._requests.get(timeout=.1)
            except queue.Empty: continue
            try: result=make_thumbnail(Path(path))
            except Exception: result=None
            while not self._stop.is_set():
                try:
                    self._results.put((path,result),timeout=.05)
                    break
                except queue.Full: continue

    def _poll(self):
        self._after=None
        if self._closed: return
        changed=False
        for _ in range(16):
            try: path,result=self._results.get_nowait()
            except queue.Empty: break
            self._requested.discard(path)
            if result is None:
                self._failed.add(path)
                if len(self._failed)>100: self._failed.pop()
            else:
                self._thumbs[path]=self._photo(result)
                while len(self._thumbs)>16: self._thumbs.popitem(last=False)
            changed=True
        if changed: self.chat._refresh_history()
        self._after=self.chat.widget.after(50,self._poll)

    def inspection_rows(self,entry):
        rows=[f"Image transfer: {entry['transfer_id']}",f"Status: {entry['status']}",
              f"File: {entry['filename']}",f"Peer fingerprint: {entry.get('peer_fingerprint','unavailable')}",
              f"Whole-file SHA-256: {entry.get('sha256') or 'unavailable'}",
              f"Bytes stored/confirmed: {entry.get('bytes_done',0)} / {entry.get('size',0)}",
              'Ciphertext below is a bounded sample of the latest image chunk.']
        hash_ns=entry.get('hash_ns')
        if hash_ns: rows.append(f'File hashing including I/O: {hash_ns/1000:g} µs')
        elapsed=entry.get('elapsed_ns')
        if elapsed: rows.append(f'Local transfer duration: {elapsed/1e9:g} s')
        goodput=entry.get('goodput_bytes_s')
        if goodput is not None: rows.append(f'Verified file goodput: {goodput:g} B/s')
        return rows

    def close(self):
        if self._closed: return
        self._closed=True
        self._stop.set()
        if self._after is not None: self.chat.widget.after_cancel(self._after)
        self._job.close()
        self._worker.join(timeout=2)
        self._attachment_label.configure(image='')
        self._attachment_photo=None
        self._attachment=None
        self._thumbs.clear(); self._requested.clear(); self._failed.clear()
