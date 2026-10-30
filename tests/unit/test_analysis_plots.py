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
    assert duration.y_label=='Mean duration (µs)'
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
    assert len(plots)==3
    expectations=[p.series[1].points[0][1] for p in plots]
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
