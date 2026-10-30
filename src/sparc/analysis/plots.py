"""Measured plot data and a shared vector drawing for Tk and SVG exports."""
from dataclasses import dataclass
import math
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


@dataclass(frozen=True)
class Plot:
    title: str
    x_label: str
    y_label: str
    series: tuple[Series,...]
    complete: bool
    ticks: tuple[tuple[float,str],...]=()


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
    duration=[]; rate=[]
    for index,name in enumerate(names):
        matching=sorted((r for r in rows if r.get('operation')==name and
                         type(r.get('payload_bytes')) is int and r['payload_bytes']>0),
                        key=lambda r:r['payload_bytes'])
        if not matching: continue
        color=_COLORS[index%len(_COLORS)]
        label=_LABELS.get(name,name)
        duration.append(Series(label,tuple((r['payload_bytes'],_value(r.get('mean_ns'),1000)) for r in matching),color))
        field='goodput_bytes_s' if network else 'throughput_bytes_s'
        rate.append(Series(label,tuple((r['payload_bytes'],_value(r.get(field),1048576)) for r in matching),color))
    if not duration: return []
    return [Plot('Network verified receipt duration' if network else 'Local cryptographic duration',
                 'Payload (bytes)','Mean duration (µs)',tuple(duration),result.complete),
            Plot('Network verified goodput' if network else 'Local cryptographic throughput',
                 'Payload (bytes)','Verified network goodput (MiB/s)' if network else 'Local cryptographic throughput (MiB/s)',
                 tuple(rate),result.complete)]


def sensitivity_plots(result: LabResult | Trial) -> list[Plot]:
    metrics=(('bit_percent','Bit change',50),('byte_percent','Byte change (character-level proxy)',99.609375),
             ('hex_percent','Hex-character change',93.75))
    modes=('plaintext','key') if isinstance(result,LabResult) else (result.mode,)
    xs=tuple(range(len(modes)))
    plots=[]
    for metric,title,expected in metrics:
        points=tuple((x,_value(result.summary[mode][metric]['mean'] if isinstance(result,LabResult)
                              else getattr(result.difference,metric),1)) for x,mode in zip(xs,modes))
        series=[Series('Observed average' if isinstance(result,LabResult) else 'Observed trial',points,_COLORS[0]),
                Series(f'Model expectation ({expected}%)',tuple((x,expected) for x in xs),_COLORS[2],True)]
        if metric=='byte_percent':
            series.append(Series('Coursework target (100%)',tuple((x,100) for x in xs),_COLORS[1],True))
        ticks=tuple((x,'Plaintext bit (diffusion)' if mode=='plaintext' else 'Key bit (confusion)') for x,mode in zip(xs,modes))
        plots.append(Plot(title,'Flipped operand','Ciphertext positions changed (%)',tuple(series),
                          result.complete if isinstance(result,LabResult) else True,ticks))
    return plots


def drawing(plot: Plot,width=900,height=360) -> list[Mark]:
    """Layout once; both native and exported graphs consume these exact marks."""
    width=max(380,width); height=max(300,height)
    left,right,top,bottom=88,width-28,64,height-106
    xs=sorted({x for series in plot.series for x,y in series.points})
    values=[y for series in plot.series for x,y in series.points if y is not None]
    upper=max(values,default=1)*1.1 or 1
    # Numeric workload spacing keeps the axis honest; a single value is centered.
    xlow,xhigh=(min(xs),max(xs)) if xs else (0,1)
    def point(x,y):
        px=(left+right)/2 if xhigh==xlow else left+(x-xlow)/(xhigh-xlow)*(right-left)
        return (px,bottom-y/upper*(bottom-top))
    marks=[Mark('text',(left,20),text=plot.title),
           Mark('text',(right,20),text='Complete' if plot.complete else 'Incomplete',anchor='e'),
           Mark('text',((left+right)/2,height-70),text=plot.x_label,anchor='center'),
           Mark('text',(19,(top+bottom)/2),text=plot.y_label,anchor='center',angle=90)]
    for i in range(5):
        value=upper*i/4
        y=point(xlow,value)[1]
        marks.extend([Mark('line',(left,y,right,y),'#d1d5db'),
                      Mark('text',(left-8,y),text=f'{value:.4g}',anchor='e')])
    marks.append(Mark('line',(left,top,left,bottom,right,bottom)))
    labels=dict(plot.ticks)
    for x in xs:
        px=point(x,0)[0]
        marks.append(Mark('text',(px,bottom+16),text=labels.get(x,f'{x:g}'),anchor='center'))
    unavailable=False
    for index,series in enumerate(plot.series):
        segment=[]
        def flush():
            if len(segment)>=4:
                marks.append(Mark('polyline',tuple(segment),series.color,dashed=series.dashed))
            segment.clear()
        for x,y in series.points:
            if y is None:
                unavailable=True; flush(); continue
            px,py=point(x,y)
            segment.extend((px,py))
            marks.append(Mark('circle',(px,py),series.color))
        flush()
        lx=left+(index%3)*(right-left)/3
        ly=height-44+(index//3)*18
        marks.extend([Mark('line',(lx,ly,lx+18,ly),series.color,dashed=series.dashed),
                      Mark('text',(lx+24,ly),series.color,text=series.label)])
    if unavailable:
        marks.append(Mark('text',(left,42),text='Unavailable measurements appear as gaps.'))
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
                **{'font-family':'sans-serif','font-size':'11','dominant-baseline':'middle',
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
    width=max(380,width); height=max(300,height)
    return ET.tostring(_svg_element(plot,width,height),encoding='unicode')


def plots_svg(plots: list[Plot],width=900,height=360) -> str:
    root=ET.Element('svg',xmlns='http://www.w3.org/2000/svg',width=str(width),height=str(height*len(plots)),
                    viewBox=f'0 0 {width} {height*len(plots)}')
    for index,plot in enumerate(plots):
        child=_svg_element(plot,width,height); child.set('y',str(index*height)); root.append(child)
    return ET.tostring(root,encoding='unicode')
