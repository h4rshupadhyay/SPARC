import base64
import hashlib

import pytest


MESSAGE_ID = "0123456789abcdef0123456789abcdef"
RUN_ID = "fedcba9876543210fedcba9876543210"
SHA256 = "a" * 64
SIGNATURE = base64.b64encode(b"s" * 64).decode("ascii")


def _chat(**changes):
    payload = {
        "kind": "chat",
        "message_id": MESSAGE_ID,
        "text": "hello",
        "byte_count": 5,
        "sha256": hashlib.sha256(b"hello").hexdigest(),
    }
    payload.update(changes)
    return payload


def _chat_without_hash():
    payload = _chat()
    del payload["sha256"]
    return payload


def test_unicode_hash_and_byte_bound():
    from sparc.protocol.messages import prepare_text

    text = "é" * 8192
    payload, hash_ns = prepare_text(text, MESSAGE_ID)
    encoded = text.encode("utf-8")
    assert payload == {
        "kind": "chat",
        "message_id": MESSAGE_ID,
        "text": text,
        "byte_count": 16384,
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }
    assert type(hash_ns) is int and hash_ns >= 0

    from sparc.models import SparcError

    with pytest.raises(SparcError) as raised:
        prepare_text("é" * 8193, MESSAGE_ID)
    assert getattr(raised.value, "code", None) == "invalid_text"


def test_lone_surrogate_is_local_error():
    from sparc.models import SparcError
    from sparc.protocol.messages import prepare_text

    with pytest.raises(SparcError) as raised:
        prepare_text("bad\ud800text", MESSAGE_ID)
    assert raised.value.code == "invalid_text"


def test_empty_text_rejected():
    from sparc.models import SparcError
    from sparc.protocol.messages import prepare_text

    with pytest.raises(SparcError) as raised:
        prepare_text("", MESSAGE_ID)
    assert raised.value.code == "invalid_text"


def test_prepare_text_benchmark_has_run_id_and_hash_timing_excludes_encoding(monkeypatch):
    from sparc.protocol import messages

    clock = [100]
    real_sha256 = messages.hashlib.sha256

    class TextWithMeasuredEncoding(str):
        def encode(self, *args, **kwargs):
            clock[0] += 1_000_000
            return super().encode(*args, **kwargs)

    class FormattedDigest(bytes):
        def hex(self):
            clock[0] += 1_000
            return super().hex()

    class FakeDigest:
        def __init__(self, digest):
            self._digest = digest

        def digest(self):
            clock[0] += 13
            return FormattedDigest(self._digest.digest())

        def hexdigest(self):
            clock[0] += 1_000
            return self._digest.hexdigest()

    def fake_sha256(data):
        assert data == b"measured"
        clock[0] += 11
        return FakeDigest(real_sha256(data))

    monkeypatch.setattr(messages.time, "perf_counter_ns", lambda: clock[0])
    monkeypatch.setattr(messages.hashlib, "sha256", fake_sha256)
    payload, hash_ns = messages.prepare_text(TextWithMeasuredEncoding("measured"), MESSAGE_ID, RUN_ID)
    assert payload == {
        "kind": "benchmark",
        "run_id": RUN_ID,
        "message_id": MESSAGE_ID,
        "text": "measured",
        "byte_count": 8,
        "sha256": real_sha256(b"measured").hexdigest(),
    }
    assert hash_ns == 24


@pytest.mark.parametrize(
    "payload",
    [
        _chat(extra="unknown"),
        _chat_without_hash(),
        {"kind": "file", "name": "x"},
        _chat(kind="unsupported"),
        _chat(byte_count=True),
        _chat(byte_count=0),
        _chat(message_id=MESSAGE_ID.upper()),
        _chat(message_id="a" * 31),
        _chat(sha256="A" * 64),
        _chat(sha256="a" * 63),
        {
            "kind": "benchmark",
            "run_id": RUN_ID.upper(),
            "message_id": MESSAGE_ID,
            "text": "x",
            "byte_count": 1,
            "sha256": hashlib.sha256(b"x").hexdigest(),
        },
        {"kind": "ack", "message_id": MESSAGE_ID, "sha256": SHA256, "status": "pending"},
        {"kind": "ping", "ping_id": MESSAGE_ID, "timestamp": 1},
        _chat(text=""),
        _chat(text="é" * 8193, byte_count=16386),
    ],
)
def test_schema_rejections(payload):
    from sparc.models import SparcError
    from sparc.protocol.messages import validate_application

    with pytest.raises(SparcError) as raised:
        validate_application(payload, signed=False)
    assert raised.value.code == "invalid_schema"


def test_signed_schema_requires_canonical_base64_signature():
    from sparc.models import SparcError
    from sparc.protocol.messages import validate_application

    valid = _chat(signature=SIGNATURE)
    validate_application(valid)

    for signature in ("A" * 85 + "B==", "not base64", SIGNATURE[:-1], " " + SIGNATURE):
        with pytest.raises(SparcError) as raised:
            validate_application(_chat(signature=signature))
        assert raised.value.code == "invalid_base64"

    with pytest.raises(SparcError) as raised:
        validate_application(_chat(), signed=True)
    assert raised.value.code == "invalid_schema"


def test_unsigned_and_signed_field_sets_are_exact():
    from sparc.models import SparcError
    from sparc.protocol.messages import validate_application

    unsigned = _chat()
    validate_application(unsigned, signed=False)
    with pytest.raises(SparcError):
        validate_application(unsigned, signed=True)
    with pytest.raises(SparcError):
        validate_application({**unsigned, "signature": SIGNATURE}, signed=False)


def test_benchmark_ack_ping_and_pong_schema_acceptance():
    from sparc.protocol.messages import validate_application

    validate_application(
        {
            "kind": "benchmark",
            "run_id": RUN_ID,
            "message_id": MESSAGE_ID,
            "text": "x",
            "byte_count": 1,
            "sha256": hashlib.sha256(b"x").hexdigest(),
            "signature": SIGNATURE,
        }
    )
    validate_application(
        {"kind": "ack", "message_id": MESSAGE_ID, "sha256": SHA256, "status": "verified", "signature": SIGNATURE}
    )
    validate_application({"kind": "ping", "ping_id": MESSAGE_ID, "signature": SIGNATURE})
    validate_application({"kind": "pong", "ping_id": MESSAGE_ID, "signature": SIGNATURE})


def test_decode_base64_requires_canonical_standard_encoding():
    from sparc.models import SparcError
    from sparc.protocol.messages import decode_base64

    encoded = base64.b64encode(b"x" * 64).decode("ascii")
    assert decode_base64(encoded, 64) == b"x" * 64
    for invalid in (encoded.rstrip("="), " " + encoded, "A" * 85 + "B==", "-" + encoded[1:]):
        with pytest.raises(SparcError) as raised:
            decode_base64(invalid, 64)
        assert raised.value.code == "invalid_base64"


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (
            _chat(signature=SIGNATURE),
            {
                "kind": "chat",
                "message_id": MESSAGE_ID,
                "byte_count": 5,
                "sha256": hashlib.sha256(b"hello").hexdigest(),
            },
        ),
        (
            {
                "kind": "benchmark",
                "run_id": RUN_ID,
                "message_id": MESSAGE_ID,
                "text": "hello",
                "byte_count": 5,
                "sha256": hashlib.sha256(b"hello").hexdigest(),
                "signature": SIGNATURE,
            },
            {
                "kind": "benchmark",
                "run_id": RUN_ID,
                "message_id": MESSAGE_ID,
                "byte_count": 5,
                "sha256": hashlib.sha256(b"hello").hexdigest(),
            },
        ),
        (
            {"kind": "ack", "message_id": MESSAGE_ID, "sha256": SHA256, "status": "verified"},
            {"kind": "ack", "message_id": MESSAGE_ID, "sha256": SHA256, "status": "verified"},
        ),
        ({"kind": "ping", "ping_id": MESSAGE_ID}, {"kind": "ping", "ping_id": MESSAGE_ID}),
        ({"kind": "pong", "ping_id": MESSAGE_ID}, {"kind": "pong", "ping_id": MESSAGE_ID}),
    ],
)
def test_projection_omits_only_text_for_chat_and_benchmark(payload, expected):
    from sparc.protocol.messages import signing_projection

    original = dict(payload)
    projection = signing_projection(payload)
    assert projection == expected
    assert projection is not payload
    assert payload == original
