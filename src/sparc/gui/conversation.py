"""Native mixed text/image conversation with keyboard selection and stable scroll."""
import tkinter as tk
from tkinter import ttk
import math
from .appearance import install, text_options, SOFT, MUTED, TEXT, ACCENT


class _Bubble(tk.Canvas):
    """A reusable message row; history retains selection and semantic text."""

    def __init__(self, history, key):
        super().__init__(history, background=SOFT, highlightthickness=0, borderwidth=0,
                         takefocus=False)
        self.key = key
        self._history = history
        self._appearance = install(history)
        self._signature = None
        self._actions = None
        self._action_labels = ()
        self._photo = None
        self._scaled_photo = None
        self._heading = tk.Label(self, borderwidth=0, padx=0, pady=0, anchor='w', justify='left')
        self._body = tk.Label(self, borderwidth=0, padx=0, pady=0, anchor='w', justify='left')
        self.bind('<Button-1>', self._select)
        for label in (self._heading, self._body):
            label.bind('<Button-1>', self._select)
            for event in ('<MouseWheel>', '<Button-4>', '<Button-5>'):
                label.bind(event, history._mousewheel)
        for event in ('<MouseWheel>', '<Button-4>', '<Button-5>'):
            self.bind(event, history._mousewheel)

    def _select(self, event=None):
        self._history.focus_set()
        self._history.select(self._history._keys.index(self.key), reveal=False)
        return 'break'

    def show(self, entry, images, selected, width, preview):
        photo = images.thumbnail(entry) if preview else None
        actions = images.actions(entry) if entry.get('kind') == 'image' else []
        labels = tuple(label for label, _ in actions)
        signature = (entry.copy(), selected, width, str(photo), labels)
        if signature == self._signature:
            return
        self._signature = signature
        self._photo = photo
        self._scaled_photo = None
        self.delete('all')
        outgoing = entry['origin'] == 'outgoing'
        color = '#28579b' if outgoing else '#293342'
        font, small = self._appearance.body, self._appearance.small
        sender = 'You' if outgoing else 'Peer'
        timestamp = entry.get('timestamp')
        clock = f"{timestamp:%H:%M:%S} · " if timestamp is not None else ""
        heading = f"{clock}{sender} · {entry['status'].replace('_', ' ').title()}"
        image = entry.get('kind') == 'image'
        body = entry['filename'] if image else entry['text']
        if image and entry['status'] != 'verified':
            body += f"\n{entry.get('bytes_done', 0):,} / {entry.get('size', 0):,} bytes"
        if entry.get('reason'):
            body += '\n' + entry['reason']
        limit = max(120, min(560, int(width * .82) - 24))
        content = min(limit, max(small.measure(heading),
                                *(font.measure(line) for line in body.split('\n')), 120))
        if photo is not None:
            maximum = max(80, width - 48)
            if photo.width() > maximum:
                factor = math.ceil(photo.width() / maximum)
                scaled = tk.PhotoImage(master=self)
                self.tk.call(str(scaled), 'copy', str(photo), '-subsample', factor, factor)
                self._scaled_photo = scaled
                photo = scaled
            content = max(content, photo.width())
        if labels:
            content = max(content, *(font.measure(label) + 28 for label in labels))
        bubble_width = min(width - 12, content + 28)
        left = max(6, width - bubble_width - 6) if outgoing else 6
        x, y = left + 14, 12
        self._heading.configure(text=heading, background=color, foreground='#c7dcff' if outgoing else MUTED,
                                font=small, wraplength=bubble_width - 28)
        self.create_window(x, y, window=self._heading, anchor='nw')
        y += self._heading.winfo_reqheight() + 6
        self._body.configure(text=body, background=color, foreground=TEXT, font=font,
                             wraplength=bubble_width - 28)
        self.create_window(x, y, window=self._body, anchor='nw')
        y += self._body.winfo_reqheight() + 10
        if photo is not None:
            self.create_image(x, y, image=photo, anchor='nw')
            y += photo.height() + 10
        if labels != self._action_labels:
            if self._actions is not None:
                self._actions.destroy()
            self._actions = None
            self._action_labels = labels
            if labels:
                self._actions = tk.Frame(self, background=color)
                self._actions._entry_key = entry['key']
                for column, (label, command) in enumerate(actions):
                    ttk.Button(self._actions, text=label, command=command).grid(row=0, column=column)
        if self._actions is not None:
            self.create_window(x, y, window=self._actions, anchor='nw')
            y += font.metrics('linespace') + 28
        bottom, right, radius = y + 2, left + bubble_width, 14
        points = (left + radius, 2, right - radius, 2, right, 2, right, radius,
                  right, bottom - radius, right, bottom, right - radius, bottom,
                  left + radius, bottom, left, bottom, left, bottom - radius, left, radius, left, 2)
        self.create_polygon(points, smooth=True, splinesteps=16, fill=color,
                            outline=ACCENT if selected else color, width=2, tags='bubble')
        self.tag_lower('bubble')
        self.configure(width=width, height=bottom + 4)


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
        self._bubbles = {}
        self._keys = []
        self._images = None
        self.tag_configure('semantic', elide=True)
        self._follow_end=True
        self._scroll_id=None
        self.tag_configure('heading',spacing1=16,spacing3=4,foreground=MUTED,font=appearance.small)
        self.tag_configure('body',spacing3=16)
        self.tag_configure('empty_title',font=appearance.heading,spacing1=32,spacing3=8)
        self.tag_configure('empty_help',foreground=MUTED,spacing3=12)
        self.tag_raise('sel')
        self.bind('<Configure>', self._layout_messages, add='+')
        self.bind('<Button-1>',self._click)
        self.bind('<Up>',lambda e:self._step(-1))
        self.bind('<Down>',lambda e:self._step(1))
        self.bind('<Home>',lambda e:self.select(0))
        self.bind('<End>',lambda e:self.select(len(self._entries)-1))
        for event in ('<MouseWheel>', '<Button-4>', '<Button-5>'):
            self.bind(event, self._mousewheel)
        self.configure(state=tk.NORMAL)
        self._empty_state()
        self.configure(state=tk.DISABLED)

    def _empty_state(self):
        self.insert('end','No messages yet\n','empty_title')
        self.insert('end','Send a message or attach an image to start the conversation.\n'
                    'Select a message to inspect its security details.','empty_help')

    def _layout_messages(self, _event=None):
        self._draw_bubbles()
        if self._follow_end and self._scroll_id is None:
            self._scroll_id=self.after_idle(self._follow_latest)

    def _follow_latest(self):
        self._scroll_id=None
        if self._follow_end:
            self.count('1.0','end','update','ypixels')
            self.yview_moveto(1.0)

    def yview(self,*args):
        result=super().yview(*args)
        if args:
            self._follow_end=super().yview()[1]>=.99
        return result

    def _click(self,event):
        self.focus_set()
        for tag in self.tag_names(f'@{event.x},{event.y}'):
            if tag.startswith('entry_'):
                self.select(int(tag[6:]),reveal=False)
                return 'break'

    def _wheel(self,amount):
        self.yview_scroll(amount,'units')
        self._follow_end=self.yview()[1]>=.99
        return 'break'

    def _mousewheel(self, event):
        if getattr(event, 'num', None) in (4, 5):
            return self._wheel(-3 if event.num == 4 else 3)
        return self._wheel(-int(event.delta / 120) if abs(event.delta) >= 120 else -event.delta)

    def _draw_bubbles(self):
        if self._images is None:
            return
        candidates = [entry for entry in self._entries if entry.get('kind') == 'image'][-16:]
        selected = self._entries[self._selected] if self._selected is not None else None
        if selected is not None and selected.get('kind') == 'image' and selected not in candidates:
            candidates = candidates[-15:] + [selected]
        previews = {id(entry) for entry in candidates}
        width = max(180, self.winfo_width() - 28)
        for index, (key, entry) in enumerate(zip(self._keys, self._entries)):
            preview = (id(entry) in previews and entry.get('path')
                       and (entry['origin'] == 'outgoing' or entry['status'] == 'verified'))
            self._bubbles[key].show(entry, self._images, index == self._selected, width, preview)

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
                self._follow_end=self.yview()[1]>=.99
        self._draw_bubbles()
        self._on_select()
        return 'break'

    def clear(self):
        if self._scroll_id is not None:
            self.after_cancel(self._scroll_id)
            self._scroll_id=None
        self.configure(state=tk.NORMAL)
        self.delete('1.0','end')
        for bubble in self._bubbles.values():
            bubble.destroy()
        self._bubbles.clear()
        self._keys.clear()
        self._images = None
        self._entries=[]
        self._selected=None
        self.configure(state=tk.DISABLED)

    def render(self,entries,images):
        selected=self._entries[self._selected] if self._selected is not None and self._selected<len(self._entries) else None
        top,bottom=self.yview()
        follow=bottom>=.99 if self.winfo_ismapped() else self._follow_end
        self._follow_end=follow
        self.configure(state=tk.NORMAL)
        # Text owns embedded windows and destroys them when their index is
        # deleted. Detach retained rows before rebuilding semantic indices.
        for window in self.window_names():
            self.window_configure(window, window='')
        self.delete('1.0','end')
        for tag in self.tag_names():
            if tag.startswith('entry_'):
                self.tag_delete(tag)
        self._entries=list(entries)
        self._images = images
        self._keys = [entry.get('key') or ('pending', id(entry)) for entry in entries]
        for key in set(self._bubbles) - set(self._keys):
            self._bubbles.pop(key).destroy()
        if not entries:
            self._empty_state()
        for index,entry in enumerate(entries):
            tag=f'entry_{index}'
            start=self.index('end-1c')
            if entry.get('kind') == 'image':
                timestamp = entry.get('timestamp')
                clock = f"{timestamp:%H:%M:%S} · " if timestamp is not None else ""
                text = (f"{clock}{entry['origin'].title()} image · {entry['status'].title()}\n"
                        f"{entry['filename']} · {entry.get('bytes_done', 0):,} / {entry.get('size', 0):,} bytes\n")
                if entry.get('path') and entry['status'] == 'verified':
                    text += 'Recovered image\n' if entry['origin'] == 'incoming' else 'Original image\n'
            else:
                sender = 'You' if entry['origin'] == 'outgoing' else 'Peer'
                timestamp = entry.get('timestamp')
                clock = f"{timestamp:%H:%M:%S} · " if timestamp is not None else ""
                text = f"{clock}{sender} · {entry['status'].title()}\n{entry['text']}\n"
            self.insert('end', text, 'semantic')
            key = self._keys[index]
            if key not in self._bubbles:
                self._bubbles[key] = _Bubble(self, key)
            self.window_create('end', window=self._bubbles[key], align='top', pady=6)
            self.insert('end', '\n')
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
        self._draw_bubbles()
        if self.winfo_ismapped():
            self.count('1.0','end','update','ypixels')
        if follow:
            self.yview_moveto(1.0)
        else:
            self.yview_moveto(top)
