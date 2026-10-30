"""Native mixed text/image conversation with keyboard selection and stable scroll."""
import tkinter as tk
from tkinter import ttk
from .appearance import install, text_options, SOFT, MUTED


class Conversation(tk.Text):
    def __init__(self,parent,on_select):
        appearance = install(parent)
        options = text_options(appearance)
        options['background'] = SOFT
        super().__init__(parent,height=12,wrap=tk.WORD,state=tk.DISABLED,
                         takefocus=True,cursor='arrow',**options)
        self._on_select=on_select
        self._entries=[]
        self._selected=None
        self._controls=[]
        self.tag_configure('heading',spacing1=16,spacing3=4,foreground=MUTED,font=appearance.small)
        self.tag_configure('body',spacing3=16)
        self.tag_configure('empty_title',font=appearance.heading,spacing1=32,spacing3=8)
        self.tag_configure('empty_help',foreground=MUTED,spacing3=12)
        self.bind('<Configure>', self._layout_messages, add='+')
        self.bind('<Button-1>',self._click)
        self.bind('<Up>',lambda e:self._step(-1))
        self.bind('<Down>',lambda e:self._step(1))
        self.bind('<Home>',lambda e:self.select(0))
        self.bind('<End>',lambda e:self.select(len(self._entries)-1))
        self.bind('<Button-4>',lambda e:self._wheel(-3))
        self.bind('<Button-5>',lambda e:self._wheel(3))
        self.bind('<MouseWheel>',lambda e:self._wheel(-int(e.delta/120) if abs(e.delta)>=120 else -e.delta))
        self.configure(state=tk.NORMAL)
        self._empty_state()
        self.configure(state=tk.DISABLED)

    def _empty_state(self):
        self.insert('end','No messages yet\n','empty_title')
        self.insert('end','Send a message or attach an image to start the conversation.\n'
                    'Select a message to inspect its security details.','empty_help')

    def _layout_messages(self, _event=None):
        margin=max(20,self.winfo_width()-820)
        self.tag_configure('incoming',lmargin1=20,lmargin2=20,rmargin=margin)
        self.tag_configure('outgoing',lmargin1=margin,lmargin2=margin,rmargin=20)

    def _click(self,event):
        self.focus_set()
        for tag in self.tag_names(f'@{event.x},{event.y}'):
            if tag.startswith('entry_'):
                self.select(int(tag[6:]),reveal=False)
                return 'break'

    def _wheel(self,amount):
        self.yview_scroll(amount,'units')
        return 'break'

    def _step(self,delta):
        self.select((self._selected or 0)+delta)
        return 'break'

    def curselection(self):
        return () if self._selected is None else (self._selected,)

    def select(self,index,*,reveal=True):
        if not self._entries:
            return 'break'
        self._selected=max(0,min(index,len(self._entries)-1))
        self.tag_remove('sel','1.0','end')
        ranges=self.tag_ranges(f'entry_{self._selected}')
        if ranges:
            self.tag_add('sel',*ranges[:2])
            if reveal:
                self.see(ranges[0])
        self._on_select()
        return 'break'

    def clear(self):
        self.configure(state=tk.NORMAL)
        self.delete('1.0','end')
        for widget in self._controls:
            widget.destroy()
        self._controls.clear()
        self._entries=[]
        self._selected=None
        self.configure(state=tk.DISABLED)

    def render(self,entries,images):
        selected=self._entries[self._selected] if self._selected is not None and self._selected<len(self._entries) else None
        focused=self.focus_get()
        focus_key=getattr(getattr(focused,'master',None),'_entry_key',None)
        focus_label=focused.cget('text') if focus_key is not None else None
        restored_focus=False
        top,bottom=self.yview()
        follow=bottom>=.99
        self.configure(state=tk.NORMAL)
        self.delete('1.0','end')
        for widget in self._controls:
            widget.destroy()
        self._controls.clear()
        for tag in self.tag_names():
            if tag.startswith('entry_'):
                self.tag_delete(tag)
        self._entries=list(entries)
        if not entries:
            self._empty_state()
        # Only the most recent sixteen images can own a decoded thumbnail.
        candidates=[e for e in entries if e.get('kind')=='image'][-16:]
        if selected is not None and selected.get('kind')=='image' and selected not in candidates:
            candidates=candidates[-15:]+[selected]
        previews={id(entry) for entry in candidates}
        for index,entry in enumerate(entries):
            tag=f'entry_{index}'
            start=self.index('end-1c')
            if entry.get('kind')=='image':
                self.insert('end',f"{entry['origin'].title()} image · {entry['status'].replace('_',' ').title()}\n",'heading')
                self.insert('end',f"{entry['filename']} · {entry.get('bytes_done',0):,} / {entry.get('size',0):,} bytes\n",'body')
                can_preview=entry.get('path') and (entry['origin']=='outgoing' or entry['status']=='verified')
                if can_preview and id(entry) in previews:
                    photo=images.thumbnail(entry)
                    if photo is not None:
                        self.insert('end','Original image\n' if entry['origin']=='outgoing' else 'Recovered image\n')
                        self.image_create('end',image=photo,padx=2,pady=4)
                        self.insert('end','\n')
                actions=images.actions(entry)
                if actions:
                    frame=ttk.Frame(self,padding=(0,2,0,8))
                    frame._entry_key=entry['key']
                    self._controls.append(frame)
                    for column,(label,command) in enumerate(actions):
                        button=ttk.Button(frame,text=label,command=command)
                        button.grid(row=0,column=column,padx=(0,6))
                        if focus_key==entry['key'] and focus_label==label:
                            button.focus_set()
                            restored_focus=True
                    self.window_create('end',window=frame,align='top')
                    self.insert('end','\n')
                if entry.get('reason'):
                    self.insert('end',entry['reason']+'\n','body')
            else:
                sender='You' if entry['origin']=='outgoing' else 'Peer'
                self.insert('end',f"{sender} · {entry['status'].title()}\n",'heading')
                self.insert('end',entry['text']+'\n','body')
            end=self.index('end-1c')
            self.tag_add(tag,start,end)
            self.tag_add(entry['origin'],start,end)
        self.configure(state=tk.DISABLED)
        if selected in self._entries:
            self._selected=self._entries.index(selected)
        else:
            self._selected=len(entries)-1 if entries else None
        if self._selected is not None:
            ranges=self.tag_ranges(f'entry_{self._selected}')
            if ranges: self.tag_add('sel',*ranges[:2])
        if focus_key is not None and not restored_focus:
            self.focus_set()
        if follow:
            self.yview_moveto(1.0)
        else:
            self.yview_moveto(top)
