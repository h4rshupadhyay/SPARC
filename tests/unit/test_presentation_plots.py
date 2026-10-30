"""Presentation statistics preserve their physical meaning and raw evidence."""
from dataclasses import replace
import pytest
from sparc.analysis.models import BenchmarkResult, LabResult
from sparc.analysis.plots import benchmark_plots, sensitivity_plots, drawing
from sparc.analysis.sensitivity import sensitivity_trial

def test_signing_rate_depends_on_operation_time_not_associated_plaintext_size():
    result=BenchmarkResult({},[],[dict(operation='sign',payload_bytes=size,count=2,
        mean_ns=2000,p95_ns=3000,throughput_bytes_s=size*500000) for size in (64,16384)],True)
    plots=benchmark_plots(result,('sign',))
    rate=plots[1]
    assert rate.y_label=='Operations/s'
    assert rate.series[0].points==((64,500000),(16384,500000))
    assert 'near-constant' in ' '.join(rate.notes)

def test_empirical_distribution_uses_actual_sample_quartiles():
    result=BenchmarkResult({},[dict(operation='encrypt',payload_bytes=64,elapsed_ns=n,success=True)
        for n in (1000,2000,3000,4000)], [dict(operation='encrypt',payload_bytes=64,count=4,mean_ns=2500,p95_ns=4000)],True)
    distributions=[p for p in benchmark_plots(result,('encrypt',)) if 'distribution' in p.title.lower()]
    assert distributions, 'empirical timing distribution is missing'
    assert distributions[0].series[0].boxes==((64,1,1.75,2.5,3.25,4),)

def test_single_trial_reference_spans_plot_and_exact_change_count_is_visible():
    plot=sensitivity_plots(sensitivity_trial(42,0,'plaintext',0))[0]
    marks=drawing(plot)
    assert any(m.kind=='line' and m.dashed and m.xy[0]<400<m.xy[2] for m in marks)
    assert any('61 / 128' in m.text for m in marks)

def test_conditional_frequencies_expose_biases_that_pooling_cancels():
    base=sensitivity_trial(42,0,'plaintext',0)
    a=replace(base,baseline_ciphertext=bytes(16),modified_ciphertext=b'\xaa'*16,bit_index=0)
    b=replace(base,baseline_ciphertext=bytes(16),modified_ciphertext=b'\x55'*16,bit_index=1)
    plots=sensitivity_plots(LabResult(42,1,[a,b],{},False),conditional=True)
    conditional=next(p for p in plots if p.title=='Conditional plaintext-bit changes')
    assert conditional.matrix[0][:2]==(100,0)
    assert conditional.matrix[1][:2]==(0,100)
    assert conditional.matrix[2][0] is None
    aggregate=next(p for p in plots if p.title=='Output-bit change frequency')
    assert all(y==50 for _,y in aggregate.series[0].points)

def test_local_benchmark_supports_nine_bounded_workload_sizes():
    from sparc.analysis.benchmark import run_local_benchmarks
    sizes=(64,128,256,512,1024,2048,4096,8192,16384)
    result=run_local_benchmarks(sizes,0,1)
    assert result.complete and len(result.samples)==54
    assert result.metadata['sizes']==list(sizes)

def test_histogram_reference_is_at_fifty_percent_with_explicit_definition():
    trial=sensitivity_trial(42,0,'plaintext',0)
    plot=next(p for p in sensitivity_plots(LabResult(42,1,[trial],{},True)) if p.title=='Bit-change distribution')
    assert plot.x_reference==50
    marks=drawing(plot)
    assert any(m.kind=='line' and m.dashed and m.xy[0]==m.xy[2] for m in marks)
    assert any(m.text=='50% reference' for m in marks)
