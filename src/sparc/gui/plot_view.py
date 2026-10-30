"""Native chart view for the same vector marks exported to SVG."""
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, ttk

from ..analysis.models import BenchmarkResult, LabResult, Trial
from ..analysis.plots import benchmark_plots, sensitivity_plots, drawing, plots_svg
from ..storage import atomic_write

_CHOICES={'Encrypt/decrypt':('encrypt','decrypt'),'Hash':('hash','recompute_hash'),
          'Sign/verify':('sign','verify'),'All operations':('encrypt','decrypt','hash','recompute_hash','sign','verify')}


class PlotView(ttk.LabelFrame):
    def __init__(self,parent):
        super().__init__(parent,text='Graphs',padding=8)
        self.columnconfigure(0,weight=1)
        self.operation=tk.StringVar(master=self,value='Encrypt/decrypt')
        controls=ttk.Frame(self); controls.grid(row=0,column=0,sticky='ew')
        ttk.Label(controls,text='Operations').pack(side='left',padx=(0,6))
        self._choice=ttk.Combobox(controls,textvariable=self.operation,values=tuple(_CHOICES),state='readonly',width=20)
        self._choice.pack(side='left'); self._choice.bind('<<ComboboxSelected>>',lambda e:self.refresh())
        self._export=ttk.Button(controls,text='Export graphs SVG…',command=self.export)
        self._export.pack(side='right')
        self.canvas=tk.Canvas(self,height=60,background='white',highlightthickness=0)
        self.canvas.grid(row=1,column=0,sticky='ew',pady=(8,0))
        self.canvas.bind('<Configure>',lambda e:self.schedule_draw())
        self.status=tk.StringVar(master=self,value='Run a benchmark or sensitivity trial to see graphs.')
        ttk.Label(self,textvariable=self.status,wraplength=650).grid(row=2,column=0,sticky='w',pady=(4,0))
        self.plots=[]
        self._result=None
        self._draw_id=None
        self._closed=False
        self._export.state(['disabled'])

    def show(self,result):
        self._result=result if isinstance(result,(BenchmarkResult,LabResult,Trial)) else None
        self.refresh()

    def refresh(self):
        if self._closed: return
        if isinstance(self._result,BenchmarkResult):
            self.plots=benchmark_plots(self._result,_CHOICES[self.operation.get()])
            self._choice.configure(state='disabled' if any(r.get('operation')=='network_round_trip' for r in self._result.summary) else 'readonly')
        elif isinstance(self._result,(LabResult,Trial)):
            self.plots=sensitivity_plots(self._result)
            self._choice.configure(state='disabled')
        else:
            self.plots=[]; self._choice.configure(state='disabled')
        self._export.state(['!disabled'] if self.plots else ['disabled'])
        self.status.set('Measured results; missing values remain unavailable. SVG exports use these same data and units.'
                        if self.plots else 'No graphable measurements for the selected operations. Run a benchmark or sensitivity trial.')
        self.canvas.configure(height=360*len(self.plots) if self.plots else 60)
        self.draw()

    def schedule_draw(self):
        if not self._closed and self._draw_id is None:
            self._draw_id=self.after_idle(self.draw)

    def draw(self):
        if self._draw_id is not None:
            self.after_cancel(self._draw_id); self._draw_id=None
        if self._closed: return
        self.canvas.delete('all')
        width=max(380,self.canvas.winfo_width())
        for index,plot in enumerate(self.plots):
            offset=index*360
            for mark in drawing(plot,width,360):
                xy=tuple(value+(offset if i%2 else 0) for i,value in enumerate(mark.xy))
                if mark.kind=='text':
                    self.canvas.create_text(*xy,text=mark.text,fill=mark.color,anchor=mark.anchor,
                                            angle=mark.angle,font=('TkDefaultFont',10))
                elif mark.kind=='circle':
                    x,y=xy; self.canvas.create_oval(x-3,y-3,x+3,y+3,fill=mark.color,outline=mark.color)
                else:
                    kwargs=dict(fill=mark.color,width=1.5)
                    if mark.dashed: kwargs['dash']=(5,4)
                    self.canvas.create_line(*xy,**kwargs)

    def export(self):
        if not self.plots or self._closed: return
        selected=filedialog.asksaveasfilename(parent=self.winfo_toplevel(),title='Export analysis graphs',
                    defaultextension='.svg',filetypes=(('SVG graphs','*.svg'),))
        if not selected: return
        try:
            atomic_write(Path(selected),plots_svg(self.plots).encode('utf-8'),private=False,secure_parent=False)
        except Exception as exc:
            self.status.set(f'Graph export failed: {exc}')
        else:
            self.status.set(f'Graphs saved: {selected}')

    def close(self):
        if self._closed: return
        self._closed=True
        if self._draw_id is not None:
            self.after_cancel(self._draw_id); self._draw_id=None
        self._result=None; self.plots=[]
