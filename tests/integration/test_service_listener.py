"""C5c listener lifecycle and startup boundaries."""

import json
import socket
import threading

import pytest

from sparc.audit import AuditLog
from sparc.models import Limits, ServiceEvent, SparcError
from sparc.peer.service import PeerService


def test_listener_reports_actual_port_and_stop(tmp_path):
    service = PeerService(tmp_path)
    try:
        endpoint = service.start_listener("127.0.0.1", 0)
        assert endpoint.ip == "127.0.0.1"
        assert endpoint.port > 0
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(0.2)
        try:
            assert probe.connect_ex((endpoint.ip, endpoint.port)) == 0
        finally:
            probe.close()
        service.stop_listener()

        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.settimeout(0.2)
        try:
            assert probe.connect_ex((endpoint.ip, endpoint.port)) != 0
        finally:
            probe.close()
    finally:
        service.close()


def test_second_connection_is_busy_before_handshake(tmp_path):
    service = PeerService(tmp_path)
    first = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    second = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        endpoint = service.start_listener("127.0.0.1", 0)
        first.settimeout(1)
        second.settimeout(1)
        first.connect((endpoint.ip, endpoint.port))
        second.connect((endpoint.ip, endpoint.port))
        assert second.recv(1) == b""
        first.settimeout(0.05)
        with pytest.raises(socket.timeout):
            first.recv(1)
    finally:
        first.close()
        second.close()
        service.close()


def test_event_queue_cancel_wakes_producer(tmp_path):
    limits = Limits(event_queue=1, cancel_poll_seconds=0.01)
    service = PeerService(tmp_path, limits=limits)
    service._emit(ServiceEvent("test", {"index": 1}))
    started = threading.Event()
    finished = threading.Event()
    result = []

    def blocked_emit():
        started.set()
        try:
            service._emit(ServiceEvent("test", {"index": 2}))
        except SparcError as error:
            result.append(error.code)
        finally:
            finished.set()

    producer = threading.Thread(target=blocked_emit)
    producer.start()
    try:
        assert started.wait(timeout=1)
        service.close()
        assert finished.wait(timeout=1)
        assert result == ["operation_cancelled"]
    finally:
        service.close()
        producer.join(timeout=1)
        assert not producer.is_alive()


def test_bad_startup_audit_blocks_service(tmp_path):
    (tmp_path / "audit.jsonl").write_bytes(b"not a signed audit chain\n")
    with pytest.raises(SparcError) as raised:
        PeerService(tmp_path)
    assert raised.value.code == "audit_verification_failed"


def test_zero_head_checkpoint_log_id_survives_service_restart(tmp_path):
    service = PeerService(tmp_path)
    service.close()
    checkpoint = json.loads((tmp_path / "audit-checkpoint.json").read_text("utf-8"))
    first_log_id = checkpoint["body"]["log_id"]
    assert checkpoint["body"]["last_record_number"] == 0

    restarted = PeerService(tmp_path)
    restarted.close()
    checkpoint = json.loads((tmp_path / "audit-checkpoint.json").read_text("utf-8"))
    assert checkpoint["body"]["log_id"] == first_log_id


def test_checkpoint_publication_failure_exposes_no_listener_or_worker(tmp_path, monkeypatch):
    calls = {"socket": 0, "thread_start": 0}

    def fail_checkpoint(self, path):
        raise SparcError("audit_storage_failed", "injected checkpoint publication failure")

    real_socket = socket.socket

    def observe_socket(*args, **kwargs):
        calls["socket"] += 1
        return real_socket(*args, **kwargs)

    original_start = threading.Thread.start

    def observe_start(thread):
        calls["thread_start"] += 1
        return original_start(thread)

    monkeypatch.setattr(AuditLog, "export_checkpoint", fail_checkpoint)
    monkeypatch.setattr(socket, "socket", observe_socket)
    monkeypatch.setattr(threading.Thread, "start", observe_start)
    with pytest.raises(SparcError) as raised:
        PeerService(tmp_path)
    assert raised.value.code == "audit_storage_failed"
    assert calls == {"socket": 0, "thread_start": 0}
