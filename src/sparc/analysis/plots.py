"""Measured plot data and a shared vector drawing for Tk and SVG exports."""
from dataclasses import dataclass
import math
from statistics import fmean
import textwrap
import xml.etree.ElementTree as ET

from .models import BenchmarkResult, LabResult, Trial

_COLORS=('#1d4ed8','#b45309','#0f766e','#a21caf','#be123c','#475569')
_LABELS={'encrypt':'Encryption','decrypt':'Decryption','hash':'Hash generation',
         'recompute_hash':'Hash recomputation','sign':'Signature generation','verify':'Signature verification',
         'network_round_trip':'Verified receipt'}


@dataclass(frozen=True)
class Series:
    label: str
    points: tuple[tuple[float,float|None],...]
    color: str
    dashed: bool=False
    connected: bool=True
    ranges: tuple[tuple[float,float,float],...]=()


@dataclass(frozen=True)
class Plot:
    title: str
    x_label: str
    y_label: str
    series: tuple[Series,...]
    complete: bool
    ticks: tuple[tuple[float,str],...]=()
    x_scale: str='category'
    y_limit: float | None=None
    notes: tuple[str,...]=()
    context: tuple[str,...]=()


@dataclass(frozen=True)
class Mark:
    kind: str
    xy: tuple[float,...]
    color: str='#202124'
    text: str=''
    anchor: str='w'
    dashed: bool=False
    angle: int=0


def _value(value,divisor):
    if type(value) not in (int,float) or not math.isfinite(value) or value<0:
        return None
    return value/divisor


def benchmark_plots(result: BenchmarkResult, operations=('encrypt','decrypt')) -> list[Plot]:
    rows=result.summary
    network=any(r.get('operation')=='network_round_trip' for r in rows)
    names=('network_round_trip',) if network else operations
    duration=[]; percentiles=[]; rate=[]; counts=[]
    for index,name in enumerate(names):
        matching=sorted((r for r in rows if r.get('operation')==name and
                         type(r.get('payload_bytes')) is int and r['payload_bytes']>0),
                        key=lambda r:r['payload_bytes'])
        if not matching: continue
        color=_COLORS[index%len(_COLORS)]
        label=_LABELS.get(name,name)
        duration.append(Series(label+' mean',tuple((r['payload_bytes'],_value(r.get('mean_ns'),1000)) for r in matching),color))
        percentiles.append(Series(label+' p95',tuple((r['payload_bytes'],_value(r.get('p95_ns'),1000)) for r in matching),color,True))
        counts.append(label+': '+', '.join(f"{r['payload_bytes']} B n={r.get('count','unavailable')}" for r in matching))
        field='goodput_bytes_s' if network else 'throughput_bytes_s'
        rate.append(Series(label,tuple((r['payload_bytes'],_value(r.get(field),1048576)) for r in matching),color))
    if not duration: return []
    context=benchmark_context(result)
    return [Plot('Network verified receipt duration' if network else 'Local cryptographic duration',
                 'Payload (bytes, logarithmic scale)','Duration (µs)',tuple(duration+percentiles),result.complete,
                 x_scale='log',notes=tuple(counts)+('p95: 95th sample percentile; not a confidence interval.',),context=context),
            Plot('Network verified goodput' if network else 'Local cryptographic throughput',
                 'Payload (bytes, logarithmic scale)','Verified network goodput (MiB/s)' if network else 'Local cryptographic throughput (MiB/s)',
                 tuple(rate),result.complete,x_scale='log',notes=tuple(counts)+(
                     'Goodput includes the measured verified-receipt interval.' if network else
                     'Throughput uses plaintext bytes / summed primitive time; signing uses a near-constant-length context.',),context=context)]


def benchmark_context(result: BenchmarkResult) -> tuple[str,...]:
    """Only public, explicitly selected provenance belongs in chart exports."""
    m=result.metadata
    return (
        f"Run: {m.get('run_id','unavailable')} | UTC: {m.get('utc','unavailable')}",
        f"Warmups: {m.get('warmups','unavailable')} | Repetitions: {m.get('repetitions','unavailable')} per operation/workload | Evidence: {m.get('evidence_mode','unavailable')}",
        f"Python: {m.get('python','unavailable')} | Platform: {m.get('platform','unavailable')}",
    )


def sensitivity_plots(result: LabResult | Trial) -> list[Plot]:
    metrics=(('bit_percent','Bit change',50),('byte_percent','Byte change (character-level proxy)',99.609375),
             ('hex_percent','Hex-character change',93.75))
    modes=('plaintext','key') if isinstance(result,LabResult) else (result.mode,)
    xs=tuple(range(len(modes)))
    batch=isinstance(result,LabResult)
    trials=result.trials if batch else [result]
    groups={mode:[t for t in trials if t.mode==mode] for mode in modes}
    complete=result.complete if batch else True
    context=(f'Seed: {result.seed} | Cases requested: {result.cases} | Retained trials: {len(trials)}',) if batch else (
        f'Single trial | Mode: {result.mode} | Case: {result.case_index} | Input bit: {result.bit_index}',)
    context+=('Synthetic isolated AES-256 block experiment; observations do not establish cryptographic security.',)
    plots=[]
    for metric,title,expected in metrics:
        values={mode:[getattr(t.difference,metric) for t in groups[mode]] for mode in modes}
        points=tuple((x,fmean(values[mode]) if values[mode] else None) for x,mode in zip(xs,modes))
        ranges=tuple((x,min(values[mode]),max(values[mode])) for x,mode in zip(xs,modes) if values[mode] and batch)
        series=[Series('Observed mean (range: min–max)' if batch else 'Observed trial',points,_COLORS[0],connected=False,ranges=ranges),
                Series(f'Model expectation ({expected}%)',tuple((x,expected) for x in xs),_COLORS[2],True)]
        if metric=='byte_percent':
            series.append(Series('Coursework target (100%)',tuple((x,100) for x in xs),_COLORS[1],True))
        ticks=tuple((x,'Plaintext bit (diffusion)' if mode=='plaintext' else 'Key bit (confusion)') for x,mode in zip(xs,modes))
        plots.append(Plot(title,'Flipped operand','Ciphertext positions changed (%)',tuple(series),
                          complete,ticks,y_limit=100,notes=tuple(f'{mode}: n={len(groups[mode])}' for mode in modes),context=context))
    if batch and trials:
        distribution=[]; frequencies=[]
        for index,mode in enumerate(modes):
            group=groups[mode]
            counts=[0]*20
            for trial in group:
                counts[min(19,int(trial.difference.bit_percent//5))]+=1
            distribution.append(Series(mode.title(),tuple((2.5+5*i,100*n/len(group) if group else None) for i,n in enumerate(counts)),_COLORS[index]))
            bits=[0]*128
            for trial in group:
                delta=bytes(a^b for a,b in zip(trial.baseline_ciphertext,trial.modified_ciphertext))
                for bit in range(128):
                    bits[bit]+=bool(delta[bit//8] & (0x80>>(bit%8)))
            frequencies.append(Series(mode.title(),tuple((bit,100*n/len(group) if group else None) for bit,n in enumerate(bits)),_COLORS[index]))
        counts=tuple(f'{mode}: n={len(groups[mode])}' for mode in modes)
        plots.append(Plot('Bit-change distribution','Output bits changed (%); 5-point bins','Trials in bin (%)',tuple(distribution),complete,
                          ticks=tuple((x,str(x)) for x in (0,25,50,75,100)),x_scale='linear',notes=counts+('Each mode is normalized independently; 100% is included in the last bin.',),context=context))
        frequencies.append(Series('Model expectation (50%)',((0,50),(127,50)),_COLORS[2],True))
        plots.append(Plot('Output-bit change frequency','Output bit index (MSB first)','Trials changing this bit (%)',tuple(frequencies),complete,
                          ticks=tuple((x,str(x)) for x in (0,32,64,96,127)),x_scale='linear',y_limit=100,
                          notes=counts+('Frequency across retained trials, not a pass/fail test.',),context=context))
    return plots


def _footer_lines(plot: Plot,width: int) -> list[str]:
    # Conservative estimate also leaves room for native font metrics.
    columns=max(24,(width-64)//9)
    return [part for line in (*plot.notes,*plot.context) for part in textwrap.wrap(line,columns)]


def plot_height(plot: Plot,width=900) -> int:
    return 400 + len(plot.series)*24 + len(_footer_lines(plot,width))*22


def drawing(plot: Plot,width=900,height=360) -> list[Mark]:
    """Layout once; both native and exported graphs consume these exact marks."""
    width=max(380,width); height=max(plot_height(plot,width),height)
    left,right,top,bottom=94,width-32,94,314
    xs=sorted({x for series in plot.series for x,y in series.points}|{x for x,label in plot.ticks})
    values=[y for series in plot.series for x,y in series.points if y is not None]
    values.extend(high for series in plot.series for x,low,high in series.ranges)
    upper=plot.y_limit if plot.y_limit is not None else max(values,default=1)*1.1 or 1
    xlow,xhigh=(min(xs),max(xs)) if xs else (0,1)
    def point(x,y):
        if len(xs)<2:
            px=(left+right)/2
        elif plot.x_scale=='log':
            px=left+(math.log2(x)-math.log2(xlow))/(math.log2(xhigh)-math.log2(xlow))*(right-left)
        elif plot.x_scale=='linear':
            px=left+(x-xlow)/(xhigh-xlow)*(right-left)
        else:
            px=left+xs.index(x)/(len(xs)-1)*(right-left)
        return (px,bottom-y/upper*(bottom-top))
    marks=[Mark('text',(left,20),text=plot.title),
           Mark('text',(right,20),text='Complete' if plot.complete else 'Incomplete',anchor='e'),
           Mark('text',((left+right)/2,bottom+48),text=plot.x_label,anchor='center'),
           Mark('text',(left,62),text=plot.y_label)]
    for i in range(5):
        value=upper*i/4
        y=point(xlow,value)[1]
        marks.extend([Mark('line',(left,y,right,y),'#d1d5db'),
                      Mark('text',(left-8,y),text=f'{value:.4g}',anchor='e')])
    marks.append(Mark('line',(left,top,left,bottom,right,bottom)))
    labels=dict(plot.ticks)
    for x in (labels if labels else xs):
        px=point(x,0)[0]
        marks.append(Mark('text',(px,bottom+16),text=labels.get(x,f'{x:g}'),anchor='w' if x==xlow else ('e' if x==xhigh else 'center')))
    unavailable=False
    for index,series in enumerate(plot.series):
        segment=[]
        def flush():
            if series.connected and len(segment)>=4:
                marks.append(Mark('polyline',tuple(segment),series.color,dashed=series.dashed))
            segment.clear()
        for x,y in series.points:
            if y is None:
                unavailable=True; flush(); continue
            px,py=point(x,y)
            segment.extend((px,py))
            marks.append(Mark('circle',(px,py),series.color))
        flush()
        for x,low,high in series.ranges:
            px,py=point(x,low); _,high_y=point(x,high)
            marks.extend([Mark('line',(px,py,px,high_y),series.color),
                          Mark('line',(px-5,py,px+5,py),series.color),
                          Mark('line',(px-5,high_y,px+5,high_y),series.color)])
        lx=32
        ly=392+index*24
        marks.extend([Mark('line',(lx,ly,lx+18,ly),series.color,dashed=series.dashed),
                      Mark('text',(lx+24,ly),series.color,text=series.label)])
    if unavailable:
        marks.append(Mark('text',(right,82),text='Unavailable measurements appear as gaps.',anchor='e'))
    footer_y=392+len(plot.series)*24
    for line in _footer_lines(plot,width):
        marks.append(Mark('text',(32,footer_y),text=line))
        footer_y+=22
    return marks


def _svg_element(plot,width,height):
    root=ET.Element('svg',xmlns='http://www.w3.org/2000/svg',width=str(width),height=str(height),
                    viewBox=f'0 0 {width} {height}',role='img')
    ET.SubElement(root,'title').text=plot.title
    ET.SubElement(root,'rect',width='100%',height='100%',fill='white')
    for mark in drawing(plot,width,height):
        xy=mark.xy
        if mark.kind=='text':
            node=ET.SubElement(root,'text',x=f'{xy[0]:.3f}',y=f'{xy[1]:.3f}',fill=mark.color,
                **{'font-family':'sans-serif','font-size':'14','dominant-baseline':'middle',
                   'text-anchor':{'w':'start','e':'end','center':'middle'}[mark.anchor]})
            if mark.angle: node.set('transform',f'rotate({-mark.angle} {xy[0]} {xy[1]})')
            node.text=mark.text
        elif mark.kind=='circle':
            ET.SubElement(root,'circle',cx=f'{xy[0]:.3f}',cy=f'{xy[1]:.3f}',r='3',fill=mark.color)
        else:
            attrs={'points':' '.join(f'{xy[i]:.3f},{xy[i+1]:.3f}' for i in range(0,len(xy),2)),
                   'fill':'none','stroke':mark.color,'stroke-width':'1.5'}
            if mark.kind=='polyline': attrs['class']='series'
            if mark.dashed: attrs['stroke-dasharray']='5 4'
            ET.SubElement(root,'polyline',attrs)
    return root


def plot_svg(plot: Plot,width=900,height=360) -> str:
    width=max(380,width); height=max(plot_height(plot,width),height)
    return ET.tostring(_svg_element(plot,width,height),encoding='unicode')


def plots_svg(plots: list[Plot],width=900,height=360) -> str:
    width=max(380,width)
    heights=[max(height,plot_height(plot,width)) for plot in plots]
    total=sum(heights)
    root=ET.Element('svg',xmlns='http://www.w3.org/2000/svg',width=str(width),height=str(total),
                    viewBox=f'0 0 {width} {total}')
    offset=0
    for plot,plot_h in zip(plots,heights):
        child=_svg_element(plot,width,plot_h); child.set('y',str(offset)); root.append(child)
        offset+=plot_h
    return ET.tostring(root,encoding='unicode')
