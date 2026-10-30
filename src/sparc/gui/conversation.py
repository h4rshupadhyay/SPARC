"""Native mixed text/image conversation with keyboard selection and stable scroll."""
import tkinter as tk
from tkinter import ttk


class Conversation(tk.Text):
    def __init__(self,parent,on_select):
        style=ttk.Style(parent)
        background=style.lookup('TFrame','background') or '#ffffff'
        foreground=style.lookup('TLabel','foreground') or '#202124'
        super().__init__(parent,height=12,wrap=tk.WORD,state=tk.DISABLED,
                         font='TkDefaultFont',background=background,foreground=foreground,
                         borderwidth=0,highlightthickness=1,takefocus=True,padx=10,pady=8,
                         cursor='arrow')
        self._on_select=on_select
        self._entries=[]
        self._selected=None
        self._controls=[]
        self.tag_configure('heading',spacing1=8,spacing3=3)
        self.tag_configure('body',spacing3=8)
        self.bind('<Button-1>',self._click)
        self.bind('<Up>',lambda e:self._step(-1))
        self.bind('<Down>',lambda e:self._step(1))
        self.bind('<Home>',lambda e:self.select(0))
        self.bind('<End>',lambda e:self.select(len(self._entries)-1))
        self.bind('<Button-4>',lambda e:self._wheel(-3))
        self.bind('<Button-5>',lambda e:self._wheel(3))
        self.bind('<MouseWheel>',lambda e:self._wheel(-int(e.delta/120) if abs(e.delta)>=120 else -e.delta))

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
        # Only the most recent sixteen images can own a decoded thumbnail.
        previews={id(entry) for entry in [e for e in entries if e.get('kind')=='image'][-16:]}
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
                    self._controls.append(frame)
                    for column,(label,command) in enumerate(actions):
                        ttk.Button(frame,text=label,command=command).grid(row=0,column=column,padx=(0,6))
                    self.window_create('end',window=frame,align='top')
                    self.insert('end','\n')
                if entry.get('reason'):
                    self.insert('end',entry['reason']+'\n','body')
            else:
                self.insert('end',f"{entry['origin'].title()} · {entry['status'].title()} · {entry['text']}\n",'body')
            end=self.index('end-1c')
            self.tag_add(tag,start,end)
        self.configure(state=tk.DISABLED)
        if selected in self._entries:
            self._selected=self._entries.index(selected)
        else:
            self._selected=len(entries)-1 if entries else None
        if follow:
            self.yview_moveto(1.0)
        else:
            self.yview_moveto(top)
