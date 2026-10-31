"""Native results navigation and measured charts sharing the SVG drawing model."""

from pathlib import Path
import tkinter as tk
from tkinter import filedialog, ttk

from ..analysis.models import BenchmarkResult, LabResult, Trial
from ..analysis.plots import benchmark_plots, sensitivity_plots, drawing, plots_svg, plot_height
from ..storage import atomic_write
from .appearance import install, SURFACE, TEXT, BORDER, chart_color

_CHOICES = {
    'Encrypt/decrypt': ('encrypt', 'decrypt'),
    'Hash': ('hash', 'recompute_hash'),
    'Sign/verify': ('sign', 'verify'),
    'All operations': ('encrypt', 'decrypt', 'hash', 'recompute_hash', 'sign', 'verify'),
}


class PlotView(ttk.Frame):
    """One latest run; select a panel on screen and export every panel together."""

    def __init__(self, parent):
        # Leave the chart enough width even in the minimum 800 px window;
        # controls retain their normal inset independently of the canvas.
        super().__init__(parent, padding=(4, 12))
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)
        # Some desktop font configurations scale pixel fonts again. Calibrate
        # against measured metrics instead of assuming the requested size wins.
        self._chart_font = install(self).body
        self.operation = tk.StringVar(master=self, value='Encrypt/decrypt')
        self.chart = tk.StringVar(master=self)
        controls = ttk.Frame(self)
        controls.grid(row=0, column=0, columnspan=2, sticky='ew', padx=8, pady=(0, 8))
        controls.columnconfigure(1, weight=1)
        ttk.Label(controls, text='Chart', font=self._chart_font).grid(row=0, column=0, padx=(0, 8))
        self._chart_choice = ttk.Combobox(controls, textvariable=self.chart, state='disabled', width=28, font=self._chart_font)
        self._chart_choice.grid(row=0, column=1, sticky='ew')
        self._chart_choice.bind('<<ComboboxSelected>>', self._select_chart)
        self._export = ttk.Button(controls, text='Export graphs SVG…', command=self.export)
        self._export.grid(row=0, column=2, padx=(12, 0))
        self._operations = ttk.Frame(self)
        self._operations.grid(row=1, column=0, sticky='w', padx=8, pady=(0, 8))
        ttk.Label(self._operations, text='Operations', font=self._chart_font).pack(side='left', padx=(0, 8))
        self._choice = ttk.Combobox(self._operations, textvariable=self.operation,
                                    values=tuple(_CHOICES), state='readonly', width=20, font=self._chart_font)
        self._choice.pack(side='left')
        self._choice.bind('<<ComboboxSelected>>', lambda _event: self.refresh())
        self.conditional=tk.BooleanVar(master=self,value=False)
        self._conditional_controls=ttk.Frame(self)
        self._conditional_controls.grid(row=1,column=0,sticky='w',padx=8,pady=(0,8))
        ttk.Checkbutton(self._conditional_controls,text='Include input/output-bit conditional views',
            variable=self.conditional,command=self.refresh).pack(side='left')
        self.canvas = tk.Canvas(self, background=SURFACE, highlightbackground=BORDER,
                                highlightcolor=TEXT, highlightthickness=1, takefocus=True)
        self.canvas.grid(row=2, column=0, sticky='nsew')
        scrollbar = ttk.Scrollbar(self, orient='vertical', command=self.canvas.yview)
        scrollbar.grid(row=2, column=1, sticky='ns')
        self.canvas.configure(yscrollcommand=scrollbar.set)
        self.canvas.bind('<Configure>', lambda _event: self.schedule_draw())
        self.bind('<Configure>', lambda _event: self.schedule_draw())
        self.canvas.bind('<Motion>',self._matrix_hint)
        for event in ('<MouseWheel>', '<Button-4>', '<Button-5>'):
            self.canvas.bind(event, self._scroll)
        for key, direction in (('<Prior>', -1), ('<Next>', 1)):
            self.canvas.bind(key, lambda _event, d=direction: self.canvas.yview_scroll(d, 'pages'))
        self.status = tk.StringVar(master=self, value='Run an experiment to see measured graphs here.')
        self._status_label = ttk.Label(self, textvariable=self.status, wraplength=650, font=self._chart_font)
        self._legend_frame=ttk.Frame(self)
        self._legend_frame.grid(row=3,column=0,columnspan=2,sticky='ew',padx=8,pady=(6,0))
        self._legend_items=[]
        self.scope=tk.StringVar(master=self)
        self._scope_label=ttk.Label(self,textvariable=self.scope,wraplength=650,font=install(self).small)
        self._scope_label.grid(row=4,column=0,columnspan=2,sticky='ew',padx=8,pady=(4,0))
        self._status_label.grid(row=5, column=0, columnspan=2, sticky='ew', padx=8, pady=(4, 0))
        self.plots = []
        self._result = None
        self._external_plots = None
        self._external_scope = ''
        self._draw_id = None
        self._closed = False
        self._export.state(['disabled'])
        self._operations.grid_remove()
        self._conditional_controls.grid_remove()

    def _scroll(self, event):
        delta = -1 if getattr(event, 'num', None) == 4 or getattr(event, 'delta', 0) > 0 else 1
        self.canvas.yview_scroll(delta, 'units')
        return 'break'

    def show(self, result):
        self._external_plots=None
        self._result = result if isinstance(result, (BenchmarkResult, LabResult, Trial)) else None
        self.refresh()

    def show_plots(self,plots,scope):
        """Display already validated non-crypto observations, such as capture bins."""
        self._result=None
        self._external_plots=list(plots)
        self._external_scope=scope
        self.refresh()

    def refresh(self):
        if self._closed:
            return
        local = isinstance(self._result, BenchmarkResult) and not any(
            row.get('operation') == 'network_round_trip' for row in self._result.summary)
        if self._external_plots is not None:
            self.plots=self._external_plots
        elif isinstance(self._result, BenchmarkResult):
            self.plots = benchmark_plots(self._result, _CHOICES[self.operation.get()])
        elif isinstance(self._result, (LabResult, Trial)):
            self.plots = sensitivity_plots(self._result,conditional=self.conditional.get())
        else:
            self.plots = []
        if local:
            self._operations.grid()
        else:
            self._operations.grid_remove()
        if isinstance(self._result,LabResult) and self._result.trials:
            self._conditional_controls.grid()
        else:
            self._conditional_controls.grid_remove()
        titles = tuple(plot.title for plot in self.plots)
        self._chart_choice.configure(values=titles, state='readonly' if titles else 'disabled')
        if self.chart.get() not in titles:
            self.chart.set(titles[0] if titles else '')
        self._export.state(['!disabled'] if self.plots else ['disabled'])
        self.status.set('Measured observations. SVG includes full run details.'
                        if self.plots else 'No graphable measurements. Run an experiment or choose other operations.')
        self.canvas.yview_moveto(0)
        self.draw()

    def _select_chart(self, _event=None):
        self.canvas.yview_moveto(0)
        self.status.set('Measured observations. SVG includes full run details.')
        self.draw()

    def schedule_draw(self):
        if not self._closed and self._draw_id is None:
            self._draw_id = self.after_idle(self.draw)

    def _chart_size(self):
        return max(380, self.canvas.winfo_width()), max(50, self.canvas.winfo_height() - 126)

    def draw(self):
        if self._draw_id is not None:
            self.after_cancel(self._draw_id)
            self._draw_id = None
        if self._closed:
            return
        self.canvas.delete('all')
        width, chart_height = self._chart_size()
        self._status_label.configure(wraplength=max(240, self.winfo_width() - 32))
        self._scope_label.configure(wraplength=max(240,self.winfo_width()-32))
        selected = next((plot for plot in self.plots if plot.title == self.chart.get()), None)
        line_height = self._chart_font.metrics('linespace') + 4
        height = 126+chart_height if selected else 100
        self.canvas.configure(scrollregion=(0, 0, width, height))
        self._set_legend(selected)
        if selected is None:
            self.canvas.create_text(24, 36, text='Run an experiment to see its graphs.',
                                    anchor='w', fill=TEXT, font=self._chart_font)
            return
        for mark in drawing(selected, width, height, chart_height=chart_height,
                            measure=self._chart_font.measure, line_height=line_height,include_footer=False):
            color = chart_color(mark.color)
            xy = mark.xy
            if mark.kind == 'text':
                # Pixel fonts match the shared geometry and SVG at every Tk DPI.
                self.canvas.create_text(*xy, text=mark.text, fill=color, anchor=mark.anchor,
                                        angle=mark.angle, font=self._chart_font)
            elif mark.kind == 'circle':
                x, y = xy
                self.canvas.create_oval(x - 3, y - 3, x + 3, y + 3, fill=color, outline=color)
            elif mark.kind == 'rectangle':
                self.canvas.create_rectangle(*xy, fill=color, outline=color)
            else:
                kwargs = dict(fill=color, width=1.5)
                if mark.dashed:
                    kwargs['dash'] = (5, 4)
                self.canvas.create_line(*xy, **kwargs)

    def _set_legend(self,plot):
        items=[] if plot is None else [(series.label,series.color,series.dashed) for series in plot.series]
        signature=tuple(items)
        if signature!=getattr(self,'_legend_signature',None):
            for widget in self._legend_frame.winfo_children(): widget.destroy()
            self._legend_items=[]
            for label,color,dashed in items:
                frame=ttk.Frame(self._legend_frame)
                swatch=tk.Canvas(frame,width=22,height=14,highlightthickness=0,background=SURFACE)
                swatch.pack(side='left',padx=(0,4))
                swatch.create_line(1,7,21,7,fill=chart_color(color),width=2,dash=(4,3) if dashed else ())
                ttk.Label(frame,text=label,foreground=chart_color(color),font=install(self).small).pack(side='left')
                self._legend_items.append(frame)
            self._legend_signature=signature
        columns=2 if self.winfo_width()<1000 else 3
        for index,item in enumerate(self._legend_items):
            item.grid(row=index//columns,column=index%columns,sticky='w',padx=(0,12),pady=1)
        for index in range(3): self._legend_frame.columnconfigure(index,weight=1 if index<columns else 0)
        if plot is None:
            self.scope.set(self._external_scope if self._external_plots is not None else ''); return
        if self._external_plots is not None:
            self.scope.set(self._external_scope)
        elif plot.matrix:
            self.scope.set(plot.notes[-1]+'\nBlue 0% · neutral 50% · orange 100% · dark: unmeasured. Hover for values.')
        elif isinstance(self._result,BenchmarkResult):
            counts=sorted({r.get('count') for r in self._result.summary if type(r.get('count')) is int})
            repetitions=', '.join(str(count) for count in counts) or 'not reported'
            scope={'Encrypt/decrypt':'AES-256-GCM signed envelope', 'Hash':'SHA-256 original plaintext',
                'Sign/verify':'Ed25519 near-constant-length protocol context'}.get(self.operation.get(),
                'AES-256-GCM / SHA-256 / Ed25519')
            if any(r.get('operation')=='network_round_trip' for r in self._result.summary):
                scope='Verified application receipt interval · '+str(self._result.metadata.get('evidence_mode','unspecified evidence mode'))
            else: scope+=' · primitive calls; key creation, encoding and I/O excluded'
            if plot.y_label=='Operations/s': scope='Ed25519 near-constant-length protocol context · signing/verification only'
            self.scope.set(f'{scope}. n={repetitions} per operation/workload. '+
                ('Box: Q1–Q3; median line; whiskers: observed min–max.' if 'distribution' in plot.title else
                 'p95 is a percentile, not a confidence interval.' if plot.y_label=='Duration (µs)' else
                 'Rates use successful measured calls.'))
        else:
            counts=' · '.join(note for note in plot.notes if ': n=' in note)
            values=' · '.join(series.annotations[index] for series in plot.series for index in range(len(series.annotations)))
            scope='Pooled across input bits/cases; not a conditional avalanche test. ' if plot.title=='Output-bit change frequency' else ''
            self.scope.set(f'{values} · {counts}\n{scope}Isolated AES-256 block experiment; finite observations, not a security proof.')

    def _matrix_hint(self,event):
        plot=next((plot for plot in self.plots if plot.title==self.chart.get()),None)
        if plot is None or not plot.matrix: return
        width,height=self._chart_size()
        x=self.canvas.canvasx(event.x); y=self.canvas.canvasy(event.y)
        if 94<=x<width-32 and 64<=y<64+height:
            column=min(127,int((x-94)/(width-126)*128))
            row=min(len(plot.matrix)-1,int((y-64)/height*len(plot.matrix)))
            value=plot.matrix[row][column]
            self.status.set(f'Input bit {row} / output bit {column}: '+('not measured' if value is None else f'{value:g}% of observed cases changed'))

    def export(self):
        if not self.plots or self._closed:
            return
        selected = filedialog.asksaveasfilename(parent=self.winfo_toplevel(), title='Export analysis graphs',
                    defaultextension='.svg', filetypes=(('SVG graphs', '*.svg'),))
        if not selected:
            return
        try:
            atomic_write(Path(selected), plots_svg(self.plots).encode('utf-8'), private=False, secure_parent=False)
        except Exception as exc:
            self.status.set(f'Graph export failed: {exc}')
        else:
            self.status.set(f'Graphs saved: {selected}')

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self._draw_id is not None:
            self.after_cancel(self._draw_id)
            self._draw_id = None
        self._result = None
        self.plots = []


class ResultsView:
    """Retain the latest graph run independently from the latest detail report."""

    def __init__(self, parent):
        self.tabs = parent
        self.performance = PlotView(self.tabs)
        self.avalanche = PlotView(self.tabs)
        self.details = ttk.Frame(self.tabs, padding=12)
        self.metrics = ttk.Frame(self.tabs, padding=12)
        for title, widget in (('Performance', self.performance), ('Avalanche', self.avalanche),
                              ('Details', self.details), ('Operation metrics', self.metrics)):
            self.tabs.add(widget, text=title)
        for widget in (self.details, self.metrics):
            widget.columnconfigure(0, weight=1)
            widget.rowconfigure(0, weight=1)

    def show(self, result):
        if result is None:
            return
        if isinstance(result, BenchmarkResult):
            self.performance.show(result)
            self.select(self.performance)
        elif isinstance(result, (LabResult, Trial)):
            self.avalanche.show(result)
            self.select(self.avalanche)
        else:
            self.select(self.details)

    def select(self, widget):
        self.tabs.select(widget)

    def close(self):
        self.performance.close()
        self.avalanche.close()
