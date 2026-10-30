"""Plot data and exports faithfully represent measured results, including gaps."""
import xml.etree.ElementTree as ET

import pytest
from sparc.analysis.models import BenchmarkResult


def benchmark(network=False,complete=True):
    op='network_round_trip' if network else 'encrypt'
    return BenchmarkResult(metadata={'test_type':'network' if network else 'local_cryptographic'},samples=[],summary=[
        dict(operation=op,payload_bytes=16384,mean_ns=3000,throughput_bytes_s=1048576,goodput_bytes_s=2097152),
        dict(operation=op,payload_bytes=64,mean_ns=1000,throughput_bytes_s=0,goodput_bytes_s=0),
        dict(operation=op,payload_bytes=1024,mean_ns=None,throughput_bytes_s=None,goodput_bytes_s=None),
    ],complete=complete)


def test_benchmark_plots_sort_workloads_convert_units_and_keep_missing_values():
    from sparc.analysis.plots import benchmark_plots
    duration,rate=benchmark_plots(benchmark(),('encrypt','decrypt'))
    assert duration.series[0].points==((64,1.0),(1024,None),(16384,3.0))
    assert rate.series[0].points==((64,0.0),(1024,None),(16384,1.0))
    assert duration.y_label=='Duration (µs)'
    assert rate.y_label=='Local cryptographic throughput (MiB/s)'


def test_network_plots_never_label_goodput_as_primitive_throughput():
    from sparc.analysis.plots import benchmark_plots
    duration,rate=benchmark_plots(benchmark(True))
    assert 'Network' in duration.title
    assert rate.series[0].points[-1][1]==2.0
    assert rate.y_label=='Verified network goodput (MiB/s)'


def test_svg_is_parseable_escapes_labels_and_shows_incomplete_and_missing_data():
    from sparc.analysis.plots import benchmark_plots,plot_svg
    from dataclasses import replace
    plot=replace(benchmark_plots(benchmark(complete=False))[0],title='Encrypt <image> & text')
    svg=plot_svg(plot)
    root=ET.fromstring(svg)
    text=' '.join(root.itertext())
    assert 'Encrypt <image> & text' in text and 'Incomplete' in text
    assert 'Unavailable' in text and 'µs' in text
    # A missing midpoint must not be bridged with a line pretending it was measured.
    series_lines=root.findall('.//{http://www.w3.org/2000/svg}polyline[@class="series"]')
    assert all(len(line.attrib['points'].split())<3 for line in series_lines)


def test_sensitivity_charts_use_each_metrics_actual_expectation():
    from sparc.analysis.plots import sensitivity_plots
    from sparc.analysis.sensitivity import run_sensitivity
    plots=sensitivity_plots(run_sensitivity(42,1))
    assert len(plots)==5
    expectations=[p.series[1].points[0][1] for p in plots[:3]]
    assert expectations==[50,99.609375,93.75]
    assert 'character-level proxy' in plots[1].title
    assert plots[1].series[2].points[0][1]==100
    assert plots[1].series[2].label=='Coursework target (100%)'


def test_geometry_is_finite_for_zero_single_workload_and_nan():
    from sparc.analysis.plots import benchmark_plots,plot_svg
    result=BenchmarkResult({},[],[dict(operation='encrypt',payload_bytes=64,mean_ns=0,throughput_bytes_s=float('nan'))],True)
    for plot in benchmark_plots(result):
        svg=plot_svg(plot,400,300)
        root=ET.fromstring(svg)
        for node in root.iter():
            for key in ('x','y','cx','cy','width','height'):
                value=node.get(key)
                if value and not value.endswith('%'):
                    import math
                    assert math.isfinite(float(value))


def test_plot_labels_have_distinct_workload_positions_and_horizontal_units():
    from sparc.analysis.plots import benchmark_plots,drawing
    plot=benchmark_plots(benchmark())[0]
    marks=drawing(plot)
    ticks=[m for m in marks if m.kind=='text' and m.text in ('64','1024','16384')]
    assert ticks[1].xy[0]-ticks[0].xy[0]>100
    assert next(m for m in marks if m.text==plot.y_label).angle==0
    assert ticks[-1].anchor=='e'


def test_duration_includes_p95_without_inventing_missing_percentiles():
    from sparc.analysis.plots import benchmark_plots
    result=BenchmarkResult({'warmups':2,'repetitions':3},[],[
        dict(operation='encrypt',payload_bytes=64,count=3,mean_ns=2000,p95_ns=5000),
        dict(operation='encrypt',payload_bytes=16384,count=0,mean_ns=None,p95_ns=None),
    ],False)
    duration,_=benchmark_plots(result)
    assert duration.series[1].label=='Encryption p95'
    assert duration.series[1].points==((64,5.0),(16384,None))
    assert duration.series[1].dashed
    assert any('n=3' in line and '64' in line for line in duration.notes)


def test_payload_positions_use_numeric_log_spacing_for_uneven_workloads():
    from sparc.analysis.plots import Plot,Series,drawing
    plot=Plot('Sizes','Bytes','µs',(Series('Mean',((64,1),(128,2),(16384,3)),'blue'),),True,x_scale='log')
    ticks=[m for m in drawing(plot) if m.kind=='text' and m.text in ('64','128','16384')]
    x={m.text:m.xy[0] for m in ticks}
    assert (x['128']-x['64'])/(x['16384']-x['64'])==pytest.approx(1/8)


def test_avalanche_distributions_preserve_each_modes_counts_and_output_bits():
    from dataclasses import replace
    from sparc.analysis.models import Difference,LabResult
    from sparc.analysis.sensitivity import sensitivity_trial
    from sparc.analysis.plots import sensitivity_plots
    trial=sensitivity_trial(42,0,'plaintext',0)
    a=replace(trial,baseline_ciphertext=bytes(16),modified_ciphertext=b'\x80'+bytes(15),difference=Difference(100/128,100/16,100/32))
    b=replace(a,modified_ciphertext=b'\xc0'+bytes(15),difference=Difference(200/128,100/16,100/32))
    c=replace(a,mode='key',modified_ciphertext=b'\x40'+bytes(15))
    # Summary is intentionally empty: distributions must use actual trials.
    plots=sensitivity_plots(LabResult(42,1,[a,b,c],{},False))
    histogram=next(p for p in plots if p.title=='Bit-change distribution')
    assert histogram.series[0].points[0]==(2.5,100.0)
    assert sum(y for x,y in histogram.series[0].points)==100
    frequency=next(p for p in plots if p.title=='Output-bit change frequency')
    assert frequency.series[0].points[:3]==((0,100.0),(1,50.0),(2,0.0))
    assert frequency.series[1].points[:3]==((0,0.0),(1,100.0),(2,0.0))
    overview=plots[0]
    assert not overview.series[0].connected
    assert overview.series[0].ranges[0]==(0,100/128,200/128)


def test_empty_avalanche_and_single_trial_do_not_claim_distributions():
    from sparc.analysis.plots import sensitivity_plots,plots_svg
    from sparc.analysis.models import LabResult
    from sparc.analysis.sensitivity import sensitivity_trial
    empty=sensitivity_plots(LabResult(42,1,[],{},False))
    assert all(y is None for x,y in empty[0].series[0].points)
    assert not any(p.title=='Bit-change distribution' for p in empty)
    single=sensitivity_plots(sensitivity_trial(42,0,'key',255))
    assert len(single)==3
    assert 'Single trial' in plots_svg(single)


def test_svg_carries_available_run_context_but_never_raw_operands():
    from sparc.analysis.plots import benchmark_plots,plots_svg
    from dataclasses import replace
    result=replace(benchmark(),metadata=dict(run_id='run<&>',utc='2026-10-30T12:00:00+00:00',
        warmups=2,repetitions=3,python='3.12',platform='Test OS',evidence_mode='loopback',key='DO_NOT_EXPORT'))
    svg=plots_svg(benchmark_plots(result))
    text=' '.join(ET.fromstring(svg).itertext())
    for value in ('run<&>','2026-10-30','Warmups: 2','Repetitions: 3','Test OS','loopback'):
        assert value in text
    assert 'DO_NOT_EXPORT' not in svg
