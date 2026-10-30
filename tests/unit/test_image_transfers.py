"""Transfer lifecycle with deterministic in-memory record delivery and real files."""
import hashlib
import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from sparc.models import SparcError


def wait(predicate, timeout=4):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        if predicate(): return
        time.sleep(.005)
    assert predicate(), 'transfer condition timed out'


class Wire:
    def __init__(self):
        self.peer=None; self.drop=set(); self.records=[]; self.errors=[]
    def enqueue(self,payload,control=False):
        self.records.append(payload.copy())
        if payload['kind'] not in self.drop:
            self.peer.handle(SimpleNamespace(payload=payload.copy(),inspection=None), {'fixture':'evidence'})
    def enqueue_bulk(self,payload): self.enqueue(payload)
    def _terminate(self,error):
        self.errors.append(error)
        self.owner.close()


@pytest.fixture
def transfers():
    from sparc.peer.transfers import TransferManager
    a,b=Wire(),Wire(); ea=[]; eb=[]; audits=[]
    ma=TransferManager(a,ea.append,lambda k,m:audits.append((k,m)), 'b'*64)
    mb=TransferManager(b,eb.append,lambda k,m:audits.append((k,m)), 'a'*64)
    a.peer=mb; b.peer=ma; a.owner=ma; b.owner=mb
    yield ma,mb,a,b,ea,eb,audits
    ma.close(); mb.close(); assert ma.join(2); assert mb.join(2)


def image(tmp_path,large=False):
    from PIL import Image
    path=tmp_path/'source.png'
    im=Image.frombytes('RGB',(320,300),os.urandom(320*300*3)) if large else Image.new('RGB',(12,8),'navy')
    im.save(path); return path


def statuses(events,tid): return [e.data['status'] for e in events if e.data['transfer_id']==tid]

def offer(ma,eb,path):
    tid=ma.send_image(path)
    wait(lambda:'offered' in statuses(eb,tid))
    return tid


def test_image_streaming_preserves_bytes_and_retains_completion_evidence(transfers,tmp_path):
    ma,mb,a,b,ea,eb,audits=transfers
    src=image(tmp_path,True); dst=tmp_path/'received.png'
    tid=offer(ma,eb,src); mb.respond(tid,dst)
    wait(lambda:'verified' in statuses(ea,tid))
    assert dst.read_bytes()==src.read_bytes()
    chunks=[p for p in a.records if p['kind']=='file_chunk']
    assert len(chunks)>4 and max(p['byte_count'] for p in chunks)==65536
    assert [p['offset'] for p in chunks]==[i*65536 for i in range(len(chunks))]
    assert {k for k,m in audits}=={'image_received','image_delivered'}
    assert all(m['sha256']==hashlib.sha256(src.read_bytes()).hexdigest() for k,m in audits)
    assert not list(tmp_path.glob('.sparc-image-*'))


def test_rejects_offer_without_creating_file(transfers,tmp_path):
    ma,mb,a,b,ea,eb,_=transfers
    tid=offer(ma,eb,image(tmp_path)); mb.respond(tid,None)
    wait(lambda:'rejected' in statuses(ea,tid))
    assert not any(p['kind']=='file_chunk' for p in a.records)
    assert not list(tmp_path.glob('.sparc-image-*'))


@pytest.mark.parametrize('symlink',[False,True])
def test_destination_collision_never_overwrites_existing_content(transfers,tmp_path,symlink):
    ma,mb,a,b,ea,eb,_=transfers
    tid=offer(ma,eb,image(tmp_path)); dst=tmp_path/'exists.png'
    if symlink: dst.symlink_to(tmp_path/'absent')
    else: dst.write_bytes(b'keep me')
    with pytest.raises(SparcError): mb.respond(tid,dst)
    assert dst.is_symlink() if symlink else dst.read_bytes()==b'keep me'


def test_cancel_window_is_bounded_and_partial_file_removed(transfers,tmp_path):
    ma,mb,a,b,ea,eb,_=transfers
    b.drop.add('file_chunk_ack')
    tid=offer(ma,eb,image(tmp_path,True)); mb.respond(tid,tmp_path/'received.png')
    wait(lambda:len([p for p in a.records if p['kind']=='file_chunk'])==4)
    time.sleep(.03)
    assert len([p for p in a.records if p['kind']=='file_chunk'])==4
    ma.cancel(tid)
    wait(lambda:'canceled' in statuses(eb,tid))
    wait(lambda:not list(tmp_path.glob('.sparc-image-*')))
    assert not (tmp_path/'received.png').exists()


def test_lost_result_is_unconfirmed_and_published_receiver_file_survives(transfers,tmp_path,monkeypatch):
    import sparc.peer.transfers as module
    monkeypatch.setattr(module,'ACK_TIMEOUT',.08)
    ma,mb,a,b,ea,eb,_=transfers
    b.drop.add('file_result')
    src=image(tmp_path); dst=tmp_path/'received.png'
    tid=offer(ma,eb,src); mb.respond(tid,dst)
    wait(lambda:'unconfirmed' in statuses(ea,tid))
    assert dst.read_bytes()==src.read_bytes()
    assert 'verified' in statuses(eb,tid)


def test_source_change_is_detected_and_never_published(transfers,tmp_path):
    ma,mb,a,b,ea,eb,_=transfers
    src=image(tmp_path); tid=offer(ma,eb,src)
    src.write_bytes(b'changed')
    mb.respond(tid,tmp_path/'received.png')
    wait(lambda:'failed' in statuses(ea,tid))
    assert not (tmp_path/'received.png').exists()


def test_unknown_transfer_id_is_a_protocol_error(transfers):
    ma,*_=transfers
    with pytest.raises(SparcError):
        ma.handle(SimpleNamespace(payload=dict(kind='file_result',transfer_id='e'*32,size=1,sha256='0'*64,status='verified'),inspection=None),{})


def test_receiver_audit_failure_never_sends_verified_result(transfers,tmp_path):
    ma,mb,a,b,ea,eb,_=transfers
    def fail(*args): raise SparcError('audit_storage_failed','injected disk failure')
    mb.audit=fail
    tid=offer(ma,eb,image(tmp_path)); dst=tmp_path/'received.png'; mb.respond(tid,dst)
    wait(lambda:bool(b.errors))
    assert not any(p['kind']=='file_result' for p in b.records)
    assert 'verified' not in statuses(eb,tid)
    # Publication precedes audit: committed bytes must not be rolled back.
    assert dst.exists()


def test_directory_sync_failure_keeps_published_file_unconfirmed(transfers,tmp_path,monkeypatch):
    ma,mb,a,b,ea,eb,_=transfers
    def fail(path): raise OSError('directory fsync failed')
    monkeypatch.setattr(mb,'_sync_directory',fail)
    src=image(tmp_path); dst=tmp_path/'received.png'
    tid=offer(ma,eb,src); mb.respond(tid,dst)
    wait(lambda:'unconfirmed' in statuses(eb,tid))
    assert dst.read_bytes()==src.read_bytes()
    assert not any(p['kind']=='file_result' for p in b.records)
    assert not list(tmp_path.glob('.sparc-image-*'))


def test_receive_hash_mismatch_fails_session_and_cleans_partial(transfers,tmp_path):
    ma,mb,a,b,ea,eb,_=transfers
    original=a.enqueue_bulk
    def corrupt(payload):
        original({**payload,'sha256':'0'*64})
    a.enqueue_bulk=corrupt
    tid=offer(ma,eb,image(tmp_path)); mb.respond(tid,tmp_path/'received.png')
    wait(lambda:bool(b.errors))
    assert b.errors[0].code=='image_integrity_failed'
    wait(lambda:not list(tmp_path.glob('.sparc-image-*')))
    assert not (tmp_path/'received.png').exists()


def test_incoming_offer_expiration_and_tombstones_are_bounded(transfers,tmp_path,monkeypatch):
    import sparc.peer.transfers as module
    ma,mb,a,b,ea,eb,_=transfers
    tid=offer(ma,eb,image(tmp_path))
    monkeypatch.setattr(module,'OFFER_TIMEOUT',.01)
    time.sleep(.02); mb.poll()
    assert 'canceled' in statuses(eb,tid)
    with mb._condition:
        for i in range(200): mb._remember(f'{i:032x}')
        assert len(mb._recent)==128
        mb._recent=type(mb._recent)((key,time.monotonic()-31) for key in mb._recent)
        mb._expire_recent(); assert not mb._recent


def test_disconnect_cancels_workers_and_late_callbacks_cannot_resurrect_transfer(transfers,tmp_path):
    ma,mb,a,b,ea,eb,_=transfers
    b.drop.add('file_chunk_ack')
    tid=offer(ma,eb,image(tmp_path,True)); mb.respond(tid,tmp_path/'received.png')
    wait(lambda:any(p['kind']=='file_chunk' for p in a.records))
    ma.close(); mb.close(); assert ma.join(1); assert mb.join(1)
    before=len(eb)
    mb.handle(SimpleNamespace(payload=dict(kind='file_offer',transfer_id='f'*32),inspection=None),{})
    assert len(eb)==before
    assert not list(tmp_path.glob('.sparc-image-*'))


def test_full_service_event_queue_retains_terminal_image_state_without_blocking():
    from sparc.peer.service import _ServiceEventQueue
    from sparc.models import ServiceEvent
    q=_ServiceEventQueue(1)
    q.advance_generation(1)
    q.put_nowait(ServiceEvent('message',{}))
    for state in ('offered','transferring','verified'):
        q.publish_image(ServiceEvent('image_transfer',dict(transfer_id='f'*32,status=state)),1)
    assert q.get_nowait().kind=='message'
    assert q.get_nowait().data['status']=='verified'
    assert q.empty()


def test_transfer_control_queue_never_blocks_a_record_callback():
    from test_session_writer import _session
    from sparc.models import Limits
    session,*_=_session(limits=Limits(control_queue=1))
    session.enqueue_transfer_control(dict(kind='file_cancel'))
    started=time.monotonic()
    with pytest.raises(SparcError): session.enqueue_transfer_control(dict(kind='file_cancel'))
    assert time.monotonic()-started<.1
    session.close()
