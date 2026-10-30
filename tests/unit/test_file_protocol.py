"""File envelopes use the existing authenticated records, with bounded evidence."""

import base64
import hashlib
import struct

import pytest

from sparc.models import SparcError
from sparc.protocol.messages import signing_projection, validate_application
from sparc.protocol.framing import Frame
from test_records_protect import _established_pair


TID = 'a' * 32
DIGEST = hashlib.sha256(b'image').hexdigest()


def payloads():
    return [
        dict(kind='file_offer', transfer_id=TID, filename='snow.png', size=5,
             sha256=DIGEST, media_type='image/png', chunk_size=65536),
        dict(kind='file_decision', transfer_id=TID, decision='accept', reason='accepted'),
        dict(kind='file_chunk', transfer_id=TID, index=0, offset=0, byte_count=5,
             sha256=DIGEST, data=base64.b64encode(b'image').decode()),
        dict(kind='file_chunk_ack', transfer_id=TID, index=0, sha256=DIGEST, status='stored'),
        dict(kind='file_complete', transfer_id=TID, size=5, sha256=DIGEST),
        dict(kind='file_result', transfer_id=TID, size=5, sha256=DIGEST, status='verified'),
        dict(kind='file_cancel', transfer_id=TID, reason='canceled'),
    ]


@pytest.mark.parametrize('payload', payloads())
def test_file_envelopes_validate_unsigned_signed_and_projected(payload):
    from sparc.protocol.files import validate_file
    validate_application(payload, signed=False)
    validate_application({**payload, 'signature': base64.b64encode(bytes(64)).decode()})
    projection = signing_projection(payload)
    assert 'signature' not in projection
    assert 'data' not in projection
    validate_file(projection, projection=True)


@pytest.mark.parametrize('name', ['../x.png', '/x.png', 'a\\b.png', '.', '..', 'x\x00.png', 'x\n.png', 'x'*256])
def test_offer_rejects_unsafe_names(name):
    with pytest.raises(SparcError):
        validate_application({**payloads()[0], 'filename': name}, signed=False)


@pytest.mark.parametrize('index,key,value', [
    (0,'size',True), (0,'size',104857601), (0,'size',0), (0,'chunk_size',4096),
    (0,'media_type','text/plain'), (1,'decision','maybe'), (1,'reason','x'*256),
    (2,'index',True), (2,'offset',1), (2,'byte_count',65537), (2,'data','!'),
    (2,'data','aW1hZ2U'), (3,'status','verified'), (4,'sha256','A'*64),
    (5,'status','stored'), (6,'transfer_id','A'*32),
])
def test_file_envelopes_are_strict(index,key,value):
    with pytest.raises(SparcError):
        validate_application({**payloads()[index], key:value}, signed=False)


def unpack(protected):
    wire = protected.frame
    return Frame(wire[4], wire[5:], struct.unpack('>I', wire[:4])[0])


def test_maximum_chunk_real_codec_roundtrip_and_bounded_inspections():
    sender, receiver, *_ = _established_pair()
    data = bytes(range(256))*256
    payload = {**payloads()[2], 'byte_count':len(data),
               'data':base64.b64encode(data).decode(), 'sha256':hashlib.sha256(data).hexdigest()}
    sealed = sender.protect(payload)
    assert len(sealed.frame)-4 <= 131072
    assert data not in sealed.frame
    opened = receiver.open(unpack(sealed))
    assert opened.payload['data'] == payload['data']
    for inspection in (sealed.inspection, opened.inspection):
        assert inspection.message_id == TID
        assert len(inspection.ciphertext) == 4096
        assert inspection.ciphertext_length > 4096
        assert inspection.sha256 == payload['sha256']
    assert opened.inspection.computed_sha256 == payload['sha256']


def test_signed_but_false_chunk_digest_fails_closed():
    sender, receiver, *_ = _established_pair()
    sealed = sender.protect({**payloads()[2], 'sha256':'0'*64})
    with pytest.raises(SparcError, match='digest'):
        receiver.open(unpack(sealed))
    with pytest.raises(SparcError):
        receiver.open(unpack(sealed))


@pytest.mark.parametrize('kind,event', [('file_complete','image_received'), ('file_result','image_delivered')])
def test_persisted_image_completion_binds_peer_evidence(kind,event):
    from sparc.audit import AuditLog, verify_log
    from sparc.audit_format import _validate_metadata
    sender, receiver, identity, _ = _established_pair()
    payload = next(p for p in payloads() if p['kind'] == kind)
    opened = receiver.open(unpack(sender.protect(payload)))
    evidence = dict(public_key=base64.b64encode(identity.public_bytes).decode(),
                    session_id=sender.session_id.hex(), direction=0, sequence=opened.sequence,
                    projection=signing_projection(opened.payload), signature=opened.payload['signature'])
    metadata = dict(transfer_id=TID, sha256=DIGEST, size=5, peer_evidence=evidence)
    _validate_metadata(metadata,event)
    for key,value in [('transfer_id','b'*32), ('size',6), ('sha256','0'*64)]:
        with pytest.raises(SparcError):
            _validate_metadata({**metadata,key:value},event)
    with pytest.raises(SparcError):
        _validate_metadata({k:v for k,v in metadata.items() if k!='peer_evidence'},event)


def test_small_chunk_inspection_excludes_the_authentication_tag():
    sender, receiver, *_ = _established_pair()
    sealed = sender.protect(payloads()[2])
    opened = receiver.open(unpack(sealed))
    assert sealed.inspection.ciphertext == opened.inspection.ciphertext
    assert len(sealed.inspection.ciphertext) == sealed.inspection.ciphertext_length


@pytest.mark.parametrize('key,value', [('media_type',[]), ('filename','\ud800'), ('size',-1)])
def test_invalid_offer_values_are_domain_errors(key,value):
    with pytest.raises(SparcError):
        validate_application({**payloads()[0],key:value}, signed=False)
