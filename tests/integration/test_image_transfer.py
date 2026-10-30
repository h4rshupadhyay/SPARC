"""Real authenticated loopback peers transfer images through normal records."""
import hashlib
import json
import time

from conftest import wait_event


def image_event(service, tid, status, timeout=8):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        event=service.events.get(timeout=max(.01,end-time.monotonic()))
        if event.kind=='image_transfer' and event.data['transfer_id']==tid and event.data['status']==status:
            return event
    raise AssertionError('image state not observed')


def test_real_peers_transfer_image_and_text_both_directions(peer_pair,tmp_path):
    from PIL import Image
    from sparc.audit import verify_log
    from sparc.audit_format import verify_peer_evidence
    a,b=peer_pair.alice,peer_pair.bob
    for i,(sender,receiver,fmt) in enumerate(((a,b,'PNG'),(b,a,'JPEG'))):
        src=tmp_path/f'source{i}.bin'; dst=tmp_path/f'received{i}.bin'
        Image.new('RGB',(100,80),'navy').save(src,format=fmt)
        tid=sender.send_image(src)
        image_event(receiver,tid,'offered')
        receiver.respond_to_image(tid,dst)
        message=sender.send_text('text while image transfers')
        image_event(receiver,tid,'verified')
        image_event(sender,tid,'verified')
        sender.wait_for_receipt(message,timeout=6)
        assert src.read_bytes()==dst.read_bytes()
    for service in (a,b):
        records=[json.loads(row)['body'] for row in (service.data_dir/'audit.jsonl').read_text().splitlines()]
        completed=[r for r in records if r['event'] in ('image_received','image_delivered')]
        assert len(completed)==2
        for r in completed: verify_peer_evidence(r['metadata'])
        assert verify_log(service.data_dir/'audit.jsonl',service._identity.public_bytes,service._audit.checkpoint_path).valid


def test_runtime_image_survives_disconnect_and_is_removed_on_service_close(peer_pair, tmp_path):
    from PIL import Image
    from sparc.images import save_image_copy

    sender, receiver = peer_pair.alice, peer_pair.bob
    source = tmp_path / 'source.png'
    saved = tmp_path / 'saved.png'
    Image.new('RGB', (90, 70), 'navy').save(source)
    tid = sender.send_image(source)
    image_event(receiver, tid, 'offered')
    cached = receiver.receive_image(tid)
    image_event(receiver, tid, 'verified')
    image_event(sender, tid, 'verified')
    assert cached.read_bytes() == source.read_bytes()
    assert receiver.data_dir not in cached.parents
    receiver.disconnect()
    assert cached.exists()
    save_image_copy(cached, saved)
    receiver.close()
    assert not cached.exists() and not cached.parent.exists()
    assert saved.read_bytes() == source.read_bytes()
