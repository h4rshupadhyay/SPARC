"""Nominal capture-time bins conserve bytes and remain bounded."""
from decimal import Decimal
from importlib import import_module
import pytest

def accumulator():
    try: module=import_module('sparc.traffic.rates')
    except ModuleNotFoundError: pytest.fail('capture-time rate bins are missing')
    return module.CaptureRateBins()

def test_nominal_one_second_bins_preserve_fixture_bytes():
    bins=accumulator()
    for timestamp,length in zip(('1','2','3','4','5'),(54,54,46,42,66)):
        bins.add(Decimal(timestamp),length)
    result=bins.finish()
    assert result['available'] and result['width_s']=='1'
    assert result['captured_bytes']==[54,54,46,42,66]
    assert sum(result['captured_bytes'])==262
    assert result['bytes_s']==['54','54','46','42','66']
    assert 'nominal' in result['definition'] and 'partial' in result['definition']

def test_long_and_out_of_order_captures_coarsen_without_losing_bytes():
    bins=accumulator()
    for timestamp in ('0','10000','5000','-10000','20000'):
        bins.add(Decimal(timestamp),100)
    result=bins.finish()
    assert len(result['captured_bytes'])<=200
    assert sum(result['captured_bytes'])==500
    assert Decimal(result['width_s'])>1

@pytest.mark.parametrize('timestamps',[[],['1'],['1','1'],['2','1']])
def test_missing_or_nonpositive_capture_interval_never_invents_a_rate(timestamps):
    bins=accumulator()
    for timestamp in timestamps: bins.add(Decimal(timestamp),54)
    result=bins.finish()
    assert result['available'] is False and not result['bytes_s']

def test_subsecond_and_negative_epochs_use_floor_boundaries():
    bins=accumulator()
    for timestamp,length in (('-0.1',20),('0.1',30),('1.0',40)):
        bins.add(Decimal(timestamp),length)
    result=bins.finish()
    assert result['origin_timestamp']=='-1'
    assert result['captured_bytes']==[20,30,40]

def test_summary_includes_rate_bins_without_changing_aggregate_definition(tmp_path):
    from test_traffic_summary import _modules,_row,_write
    summary,index=_modules(); path=tmp_path/'capture.sqlite'
    _write(index,[_row(1,'1',100),_row(2,'3',80)],path)
    report=summary.summarize_database(path)
    assert report.captured_bytes_s==Decimal(90)
    assert report.metadata['capture_rate_bins']['captured_bytes']==[100,0,80]
