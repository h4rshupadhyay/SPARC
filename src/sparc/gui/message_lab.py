"""Custom-message form; analysis jobs and result ownership stay with AnalysisTab."""
import tkinter as tk
from tkinter import ttk
from .appearance import text_options, install

class MessageLab:
    def __init__(self, parent, command):
        self.widget = ttk.LabelFrame(parent,text='Custom message · AES-256-GCM / SHA-256 / Ed25519',padding=10)
        self.widget.columnconfigure(0,weight=1)
        self.button = ttk.Button(self.widget,text='Analyze message',command=command)
        self.button.grid(row=0,column=0,sticky='w',pady=(0,8))
        ttk.Label(self.widget,text='Message (UTF-8, up to 16,384 bytes)').grid(row=1,column=0,sticky='w')
        self.text = tk.Text(self.widget,height=4,wrap='word',**text_options(install(parent)))
        self.text.grid(row=2,column=0,sticky='ew',pady=(4,8))
        self.key = tk.StringVar(master=self.widget)
        ttk.Label(self.widget,text='Optional AES-256 lab key · 64 hexadecimal digits').grid(row=3,column=0,sticky='w')
        ttk.Entry(self.widget,textvariable=self.key).grid(row=4,column=0,sticky='ew',pady=(4,6))
        ttk.Label(self.widget,text='Blank key: generate a fresh lab key. Private keys are never saved.\n'
                  'The result includes recovered text, digest, public signature and six operation timings.',
                  wraplength=650,style='Muted.TLabel').grid(row=5,column=0,sticky='ew')

    def read(self):
        end='end-1c' if self.text.compare('end-1c','<=','1.0+16385c') else '1.0+16385c'
        text=self.text.get('1.0',end)
        value=self.key.get().strip()
        key=bytes.fromhex(value) if value else None
        if key is not None and len(key)!=32:
            raise ValueError('AES-256 lab key must contain exactly 32 bytes (64 hex digits)')
        return text,key

    def state(self,enabled):
        self.button.state(['!disabled'] if enabled else ['disabled'])
        self.text.configure(state='normal' if enabled else 'disabled')
