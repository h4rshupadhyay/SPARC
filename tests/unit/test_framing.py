import socket
import struct
import threading
import time

import pytest


def test_partial_reads_round_trip():
    from sparc.models import Limits
    from sparc.protocol.framing import pack_frame, read_frame

    receiver, sender = socket.socketpair()
    cancel = threading.Event()
    expected = b"split across several TCP reads"
    encoded = pack_frame(1, expected)

    def send_pieces():
        for start, end in ((0, 2), (2, 5), (5, 9), (9, len(encoded))):
            sender.sendall(encoded[start:end])
            time.sleep(0.01)

    writer = threading.Thread(target=send_pieces)
    try:
        writer.start()
        frame = read_frame(receiver, cancel, None, Limits())
        assert (frame.kind, frame.body, frame.length) == (1, expected, len(expected) + 1)
    finally:
        writer.join(timeout=1)
        receiver.close()
        sender.close()
    assert not writer.is_alive()


@pytest.mark.parametrize("length", [0, 131073])
def test_prefix_rejected_before_body_read(length):
    from sparc.models import Limits, SparcError
    from sparc.protocol.framing import read_frame

    receiver, sender = socket.socketpair()
    try:
        sender.sendall(struct.pack(">I", length))
        with pytest.raises(SparcError) as raised:
            read_frame(receiver, threading.Event(), None, Limits())
        assert raised.value.code == "malformed_frame"
    finally:
        receiver.close()
        sender.close()


@pytest.mark.parametrize("kind", [0, 7, 255])
def test_invalid_frame_type_rejected(kind):
    from sparc.models import Limits, SparcError
    from sparc.protocol.framing import read_frame

    receiver, sender = socket.socketpair()
    try:
        sender.sendall(struct.pack(">I", 1) + bytes([kind]))
        with pytest.raises(SparcError) as raised:
            read_frame(receiver, threading.Event(), None, Limits())
        assert raised.value.code == "malformed_frame"
    finally:
        receiver.close()
        sender.close()


def test_json_frame_8k_limit():
    from sparc.models import Limits, SparcError
    from sparc.protocol.framing import pack_frame

    limits = Limits()
    with pytest.raises(SparcError) as raised:
        pack_frame(1, b"x" * (limits.handshake_json_bytes))
    assert raised.value.code == "malformed_frame"
    assert len(pack_frame(1, b"x" * (limits.handshake_json_bytes - 1))) == limits.handshake_json_bytes + 4


def test_frame_type_bounds_and_encrypted_minimum():
    from sparc.models import Limits, SparcError
    from sparc.protocol.framing import pack_frame

    with pytest.raises(SparcError):
        pack_frame(2, b"x" * 131072)
    with pytest.raises(SparcError):
        pack_frame(6, b"x" * 56)  # Type + 32-byte session + 8-byte sequence + tag + nonempty ciphertext.
    assert len(pack_frame(6, b"x" * 57)) == 4 + 58


def test_cancel_and_partial_frame_timeout():
    from sparc.models import Limits, SparcError
    from sparc.protocol.framing import read_frame

    receiver, sender = socket.socketpair()
    cancel = threading.Event()
    try:
        threading.Timer(0.05, cancel.set).start()
        started = time.monotonic()
        with pytest.raises(SparcError) as raised:
            read_frame(receiver, cancel, None, Limits(cancel_poll_seconds=0.1))
        assert raised.value.code == "canceled"
        assert time.monotonic() - started < 1.0
    finally:
        receiver.close()
        sender.close()

    receiver, sender = socket.socketpair()
    limits = Limits(frame_timeout_seconds=0.15)
    try:
        # No bytes means no incomplete-frame timer, even after the configured interval.
        started = time.monotonic()
        outcome = []

        def wait_for_frame():
            try:
                read_frame(receiver, threading.Event(), None, limits)
            except Exception as exc:  # Captured to make the timeout observable in this test thread.
                outcome.append(exc)

        reader = threading.Thread(target=wait_for_frame)
        reader.start()
        time.sleep(0.25)
        assert reader.is_alive()
        assert not outcome
        sender.sendall(b"\x00")
        reader.join(timeout=1)
        assert not reader.is_alive()
        assert len(outcome) == 1
        assert isinstance(outcome[0], SparcError)
        assert outcome[0].code == "frame_timeout"
        assert time.monotonic() - started >= 0.15
    finally:
        receiver.close()
        sender.close()


def test_supplied_handshake_deadline_applies_to_idle_socket():
    from sparc.models import Limits, SparcError
    from sparc.protocol.framing import read_frame

    receiver, sender = socket.socketpair()
    try:
        deadline = time.monotonic() + 0.15
        with pytest.raises(SparcError) as raised:
            read_frame(receiver, threading.Event(), deadline, Limits(cancel_poll_seconds=0.05))
        assert raised.value.code == "handshake_timeout"
    finally:
        receiver.close()
        sender.close()
