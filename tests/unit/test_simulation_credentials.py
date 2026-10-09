"""Private bounded credential handoff contracts for spawned simulation peers."""

from __future__ import annotations

import base64
import importlib
import inspect
import json
import multiprocessing
import multiprocessing.process
from pathlib import Path
import queue
import secrets
from types import SimpleNamespace

import pytest

from sparc.encoding import canonical
from sparc.models import Endpoint, SparcError


def _simulation_api():
    module = importlib.import_module("scripts.simulate_peers")
    runner = getattr(module, "run_simulation", None)
    assert callable(runner), "run_simulation API is missing"
    return module, runner


def _credential_api():
    codec = importlib.import_module("sparc.identity_codec")
    credentials = getattr(codec, "IdentityCredentials", None)
    request = getattr(codec, "IdentityUnlockRequest", None)
    assert credentials is not None, "IdentityCredentials API is missing"
    assert request is not None, "IdentityUnlockRequest API is missing"
    return credentials, request


def test_simulation_requires_explicit_keyword_only_credential_provider():
    module, runner = _simulation_api()
    signature = inspect.signature(runner)
    parameter = signature.parameters.get("credential_provider")
    assert parameter is not None, "run_simulation must accept credential_provider"
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is None
    assert getattr(module, "SimulationCredentialProvider", None) is not None


def test_simulation_requires_provider_before_spawn_or_directory_creation(tmp_path, monkeypatch):
    _module, runner = _simulation_api()
    data_root = tmp_path / "must-not-exist"
    before = {child.pid for child in multiprocessing.active_children() if child.pid is not None}
    starts = []

    def forbidden_start(process, *_args, **_kwargs):
        starts.append(process)
        raise AssertionError("simulation started a child before obtaining credentials")

    monkeypatch.setattr(multiprocessing.process.BaseProcess, "start", forbidden_start)
    with pytest.raises(SparcError) as raised:
        runner(data_root)

    after = {child.pid for child in multiprocessing.active_children() if child.pid is not None}
    assert raised.value.code == "identity_credentials_required"
    assert starts == []
    assert not data_root.exists()
    assert after == before


class _EOFConnection:
    def __init__(self):
        self.outputs = []
        self.maximums = []
        self.closed = False

    def poll(self, _timeout=0):
        return True

    def recv_bytes(self, maxlength=None):
        self.maximums.append(maxlength)
        raise EOFError

    def send(self, message):
        self.outputs.append(message)

    def close(self):
        self.closed = True


def test_cancel_and_coordinator_eof_leave_no_children(
    tmp_path, monkeypatch
):
    module, runner = _simulation_api()
    service_module = importlib.import_module("sparc.peer.service")
    cancellation_root = tmp_path / "cancel-before-start"
    before = {child.pid for child in multiprocessing.active_children() if child.pid is not None}
    starts = []

    def forbidden_start(process, *_args, **_kwargs):
        starts.append(process)
        raise AssertionError("canceled simulation started a child")

    monkeypatch.setattr(multiprocessing.process.BaseProcess, "start", forbidden_start)
    with pytest.raises(SparcError) as canceled:
        runner(cancellation_root, credential_provider=lambda _peer, _request: None)
    assert canceled.value.code == "identity_unlock_cancelled"
    assert not cancellation_root.exists()
    assert starts == []

    constructions = []

    class ForbiddenService:
        def __init__(self, *_args, **_kwargs):
            constructions.append(True)
            raise AssertionError("EOF must stop child startup before service construction")

    monkeypatch.setattr(service_module, "PeerService", ForbiddenService)
    child_root = tmp_path / "child-eof"
    connection = _EOFConnection()
    module._child_main("alice", str(child_root), 0, "simulation", connection)

    after = {child.pid for child in multiprocessing.active_children() if child.pid is not None}
    assert connection.maximums == [4096]
    assert connection.closed
    assert constructions == []
    assert not child_root.exists()
    assert any(
        item.get("kind") == "ERROR"
        and item.get("code") in {"identity_credentials_required", "child_startup_failed"}
        for item in connection.outputs
    )
    assert after == before


class _CredentialConnection:
    def __init__(self, payload: bytes):
        self.payload = payload
        self.outputs = []
        self.maximums = []
        self._polled_credential = False
        self.closed = False

    def poll(self, _timeout=0):
        if not self._polled_credential:
            return True
        return True

    def recv_bytes(self, maxlength=None):
        self.maximums.append(maxlength)
        if not self._polled_credential:
            self._polled_credential = True
            return self.payload
        raise AssertionError("child requested an unexpected second credential message")

    def recv(self):
        return {"action": "STOP"}

    def send(self, message):
        self.outputs.append(message)

    def close(self):
        self.closed = True


def test_child_credential_wire_is_bounded_canonical_and_private(monkeypatch, tmp_path):
    module, _runner = _simulation_api()
    credentials_type, request_type = _credential_api()
    identity_module = importlib.import_module("sparc.identity")
    service_module = importlib.import_module("sparc.peer.service")
    phrase = secrets.token_urlsafe(32).encode("ascii")
    observed = []
    captured_services = []
    data_dir = tmp_path / "alice"
    identity = SimpleNamespace(status="encrypted_locked", fingerprint="a" * 64)
    monkeypatch.setattr(identity_module, "inspect_identity", lambda _path: identity)

    def capture_unlock(data_dir, *, credential_provider, cancelled=None):
        observed.append(
            credential_provider(request_type("unlock", Path(data_dir), "a" * 64))
        )
        return object()

    class FakeService:
        def __init__(self, *_args, credential_provider=None, **_kwargs):
            if credential_provider is not None:
                observed.append(
                    credential_provider(
                        request_type("unlock", data_dir, "a" * 64)
                    )
                )
            captured_services.append(self)
            self.own_fingerprint = "a" * 64
            self.events = queue.Queue()
            self.state = "listening"

        @classmethod
        def _from_unlocked_store(cls, _handle):
            return cls()

        def start_listener(self, host, port):
            return Endpoint(host, port or 54321)

        def close(self):
            pass

    monkeypatch.setattr(identity_module, "_unlock_store", capture_unlock)
    monkeypatch.setattr(service_module, "PeerService", FakeService)

    wire = {
        "kind": "IDENTITY_CREDENTIALS",
        "passphrase": base64.b64encode(phrase).decode("ascii"),
        "confirmation": "",
    }
    payload = canonical(wire)
    assert len(payload) <= 4096
    connection = _CredentialConnection(payload)

    module._child_main("alice", str(data_dir), 0, "simulation", connection)

    assert connection.maximums, "child must read the credential frame with a bound"
    assert connection.maximums[0] == 4096
    assert observed == [credentials_type(phrase, None)]
    assert len(captured_services) == 1
    assert connection.closed
    serialized_messages = json.dumps(connection.outputs, sort_keys=True)
    assert phrase.decode("ascii") not in serialized_messages
    assert base64.b64encode(phrase).decode("ascii") not in serialized_messages
    assert all(set(item) != {"kind", "passphrase", "confirmation"} for item in connection.outputs)


@pytest.mark.parametrize("wire_error", ["null_confirmation", "noncanonical"])
def test_child_rejects_invalid_wire_before_service_creation(
    monkeypatch, tmp_path, wire_error
):
    module, _runner = _simulation_api()
    _credentials_type, _request_type = _credential_api()
    service_module = importlib.import_module("sparc.peer.service")
    created = []

    class ForbiddenService:
        def __init__(self, *_args, **_kwargs):
            created.append(True)
            raise AssertionError("invalid IPC credentials reached service construction")

    monkeypatch.setattr(service_module, "PeerService", ForbiddenService)
    wire = {
        "kind": "IDENTITY_CREDENTIALS",
        "passphrase": base64.b64encode(secrets.token_bytes(24)).decode("ascii"),
        "confirmation": None if wire_error == "null_confirmation" else "",
    }
    if wire_error == "null_confirmation":
        payload = json.dumps(wire, sort_keys=True, separators=(",", ":")).encode("utf-8")
    else:
        payload = canonical(wire) + b" "
    connection = _CredentialConnection(payload)

    module._child_main("bob", str(tmp_path / "bob"), 0, "simulation", connection)

    assert connection.maximums == [4096]
    assert created == []
    assert connection.closed
    assert any(
        item.get("kind") == "ERROR"
        and item.get("code") == "identity_credentials_invalid"
        for item in connection.outputs
    )
    assert not (tmp_path / "bob").exists()
