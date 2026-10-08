import hashlib
import json
import struct
import base64

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import base64


_KEYS = (b"i" * 32, b"r" * 32)
_SESSION_ID = b"S" * 32
_TRANSCRIPT_HASH = "0123456789abcdef" * 4


def _identity(seed):
    from sparc.models import Identity

    private = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return Identity(private, public, hashlib.sha256(public).hexdigest())


def _pair():
    from sparc.models import Role
    from sparc.protocol.records import SessionCodec

    initiator = _identity(1)
    responder = _identity(2)
    initiator_codec = SessionCodec(
        identity=initiator,
        peer_key=responder.public_bytes,
        role=Role.INITIATOR,
        keys=_KEYS,
        session_id=_SESSION_ID,
    )
    responder_codec = SessionCodec(
        identity=responder,
        peer_key=initiator.public_bytes,
        role=Role.RESPONDER,
        keys=_KEYS,
        session_id=_SESSION_ID,
    )
    return initiator_codec, responder_codec


def _frame_from_wire(wire):
    from sparc.protocol.framing import Frame

    length = struct.unpack(">I", wire[:4])[0]
    return Frame(kind=wire[4], body=wire[5:], length=length)


def _encrypted_frame(kind, key, session_id, direction, sequence, plaintext, *, corrupt_tag=False):
    from sparc.protocol.framing import Frame

    sequence_bytes = sequence.to_bytes(8, "big")
    length = 1 + 32 + 8 + len(plaintext) + 16
    length_bytes = length.to_bytes(4, "big")
    aad = (
        b"SPARC-v1 record\x00"
        + bytes((kind,))
        + session_id
        + bytes((direction,))
        + sequence_bytes
        + length_bytes
    )
    nonce = b"\x00" * 4 + sequence_bytes
    ciphertext_and_tag = AESGCM(key).encrypt(nonce, plaintext, aad)
    if corrupt_tag:
        ciphertext_and_tag = ciphertext_and_tag[:-1] + bytes([ciphertext_and_tag[-1] ^ 1])
    return Frame(
        kind=kind,
        body=session_id + sequence_bytes + ciphertext_and_tag,
        length=length,
    )


def _finished_plaintext():
    return json.dumps(
        {"kind": "finished", "transcript_sha256": _TRANSCRIPT_HASH},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def _counter(codec, field):
    return getattr(codec, field)


def test_finished_consumes_sequence_zero():
    initiator, responder = _pair()
    finished = {"kind": "finished", "transcript_sha256": _TRANSCRIPT_HASH}

    responder_sent = responder.protect(finished, frame_type=4)
    assert responder_sent.inspection is None
    responder_frame = _frame_from_wire(responder_sent.frame)
    assert responder_frame.kind == 4
    assert responder_frame.length == len(responder_sent.frame) - 4
    assert responder_frame.body[32:40] == b"\x00" * 8

    # Independently verify responder->initiator key selection, nonce, AAD and plaintext.
    prefix = responder_sent.frame[:4]
    sequence_bytes = b"\x00" * 8
    expected_aad = b"SPARC-v1 record\x00" + b"\x04" + _SESSION_ID + b"\x01" + sequence_bytes + prefix
    recovered = AESGCM(_KEYS[1]).decrypt(b"\x00" * 4 + sequence_bytes, responder_frame.body[40:], expected_aad)
    assert recovered == _finished_plaintext()

    opened_by_initiator = initiator.open(responder_frame)
    assert opened_by_initiator.payload == finished
    assert opened_by_initiator.inspection is None
    assert _counter(responder, "_send_next") == 1
    assert _counter(initiator, "_receive_next") == 1

    initiator_sent = initiator.protect(finished, frame_type=5)
    assert initiator_sent.inspection is None
    initiator_frame = _frame_from_wire(initiator_sent.frame)
    assert initiator_frame.kind == 5
    assert initiator_frame.body[32:40] == b"\x00" * 8
    prefix = initiator_sent.frame[:4]
    expected_aad = b"SPARC-v1 record\x00" + b"\x05" + _SESSION_ID + b"\x00" + sequence_bytes + prefix
    recovered = AESGCM(_KEYS[0]).decrypt(b"\x00" * 4 + sequence_bytes, initiator_frame.body[40:], expected_aad)
    assert recovered == _finished_plaintext()

    opened_by_responder = responder.open(initiator_frame)
    assert opened_by_responder.payload == finished
    assert opened_by_responder.inspection is None
    assert _counter(initiator, "_send_next") == 1
    assert _counter(responder, "_receive_next") == 1


def test_application_protect_and_open_are_gated_until_finished_exchange():
    from sparc.models import SparcError

    initiator, responder = _pair()
    application_payload = {
        "kind": "chat",
        "message_id": "0123456789abcdef0123456789abcdef",
        "text": "hello",
        "byte_count": 5,
        "sha256": hashlib.sha256(b"hello").hexdigest(),
        "signature": base64.b64encode(b"s" * 64).decode("ascii"),
    }
    with pytest.raises(SparcError):
        initiator.protect(application_payload, frame_type=6)
    with pytest.raises(SparcError):
        responder.protect(application_payload, frame_type=6)

    initiator, _ = _pair()
    app_plaintext = json.dumps(
        application_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")
    incoming = _encrypted_frame(6, _KEYS[0], _SESSION_ID, 0, 1, app_plaintext)
    with pytest.raises(SparcError):
        initiator.open(incoming)
    _, responder = _pair()
    incoming = _encrypted_frame(6, _KEYS[1], _SESSION_ID, 1, 1, app_plaintext)
    with pytest.raises(SparcError):
        responder.open(incoming)


@pytest.mark.parametrize(
    "frame_factory",
    [
        lambda: _encrypted_frame(5, _KEYS[1], _SESSION_ID, 1, 0, _finished_plaintext()),
        lambda: _encrypted_frame(4, _KEYS[0], _SESSION_ID, 0, 0, _finished_plaintext()),
        lambda: _encrypted_frame(4, _KEYS[1], _SESSION_ID, 0, 0, _finished_plaintext()),
        lambda: _encrypted_frame(4, _KEYS[1], _SESSION_ID, 1, 1, _finished_plaintext()),
        lambda: _encrypted_frame(4, _KEYS[1], _SESSION_ID, 1, 0, _finished_plaintext(), corrupt_tag=True),
        lambda: _short_frame(),
    ],
    ids=("wrong-kind", "wrong-direction-key", "wrong-direction", "sequence-gap", "bad-tag", "short-body"),
)
def test_invalid_finished_does_not_advance_receive_counter(frame_factory):
    from sparc.models import SparcError

    initiator, _ = _pair()
    with pytest.raises(SparcError):
        initiator.open(frame_factory())
    assert _counter(initiator, "_receive_next") == 0
    with pytest.raises(SparcError):
        initiator.open(_encrypted_frame(4, _KEYS[1], _SESSION_ID, 1, 0, _finished_plaintext()))


def _short_frame():
    from sparc.protocol.framing import Frame

    return Frame(kind=4, body=bytes(56), length=57)


def test_finished_replay_does_not_advance_counter_again():
    from sparc.models import SparcError

    initiator, responder = _pair()
    wire = responder.protect({"kind": "finished", "transcript_sha256": _TRANSCRIPT_HASH}, frame_type=4)
    frame = _frame_from_wire(wire.frame)
    initiator.open(frame)
    assert _counter(initiator, "_receive_next") == 1
    with pytest.raises(SparcError):
        initiator.open(frame)
    assert _counter(initiator, "_receive_next") == 1


def test_role_cannot_send_the_other_roles_finished_type():
    from sparc.models import SparcError

    initiator, responder = _pair()
    finished = {"kind": "finished", "transcript_sha256": _TRANSCRIPT_HASH}
    with pytest.raises(SparcError):
        initiator.protect(finished, frame_type=4)
    with pytest.raises(SparcError):
        responder.protect(finished, frame_type=5)


def test_out_of_range_seeded_counters_never_wrap_or_produce_records():
    from sparc.models import SparcError

    initiator, responder = _pair()
    initiator._send_next = 2**64
    with pytest.raises(SparcError) as send_error:
        initiator.protect({"kind": "finished", "transcript_sha256": _TRANSCRIPT_HASH}, frame_type=5)
    assert send_error.value.code == "counter_exhausted"
    assert initiator._send_next == 2**64

    responder._receive_next = 2**64
    incoming = _encrypted_frame(4, _KEYS[1], _SESSION_ID, 1, 0, _finished_plaintext())
    with pytest.raises(SparcError) as receive_error:
        responder.open(incoming)
    assert receive_error.value.code == "counter_exhausted"
    assert responder._receive_next == 2**64
