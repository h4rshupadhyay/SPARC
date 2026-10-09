"""C7b connection-view tests using real Tk widgets and public service calls."""

from __future__ import annotations

import queue
import socket
import threading
import tkinter as tk
from tkinter import TclError, ttk

import pytest

from sparc.gui.connection import ConnectionTab
from sparc.identity import load_identity
from sparc.models import Endpoint, ServiceEvent, SparcError
from sparc.peer.service import PeerService


def _root_or_skip():
    try:
        root = tk.Tk()
    except TclError as exc:
        pytest.skip(f"Tk display unavailable: {exc}")
    root.withdraw()
    notebook = ttk.Notebook(root)
    notebook.pack()
    return root, notebook


def _walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from _walk(child)


def _texts(widget):
    result = []
    for child in _walk(widget):
        try:
            value = child.cget("text")
        except tk.TclError:
            continue
        if value:
            result.append(str(value))
    return result


def _pump(root, predicate, timeout=1.0):
    import time

    deadline = time.monotonic() + timeout
    while not predicate() and time.monotonic() < deadline:
        root.update()
        time.sleep(0.005)
    root.update()


class FakeService:
    own_fingerprint = "a" * 64

    def __init__(self):
        self.events = queue.Queue()
        self.calls = []
        self.remembered = []
        self.live_peer = None

    def start_listener(self, ip, port):
        self.calls.append(("start_listener", ip, port))
        return Endpoint(ip, port)

    def stop_listener(self):
        self.calls.append(("stop_listener",))

    def connect(self, endpoint):
        self.calls.append(("connect", endpoint))

    def disconnect(self):
        self.calls.append(("disconnect",))

    def respond_to_pairing(self, request_id, approved):
        self.calls.append(("respond_to_pairing", request_id, approved))

    def trusted_peers(self):
        return list(self.remembered)

    def connected_peer(self):
        return self.live_peer

    def close(self):
        self.calls.append(("close",))


def _make_tab(service=None):
    root, notebook = _root_or_skip()
    tab = ConnectionTab(notebook, service or FakeService())
    notebook.add(tab.widget, text="Connection")
    root.update()
    return root, tab


def test_listening_port_is_not_configured_port_until_started():
    service = FakeService()
    root, tab = _make_tab(service)
    texts = _texts(tab.widget)
    assert "47655" in texts
    assert "0.0.0.0" in texts
    assert any("not listening" in text.lower() or "stopped" in text.lower() for text in texts)
    assert not any("listening on 0.0.0.0:47655" in text.lower() for text in texts)
    tab.handle_event(ServiceEvent("state", {
        "state": "listening", "reason": "listener_started",
        "endpoint": {"ip": "0.0.0.0", "port": 47655},
    }))
    root.update()
    assert any("listening" in text.lower() for text in _texts(tab.widget))
    tab.close()
    root.destroy()


def test_interfaces_have_labels_and_copyable_endpoints(monkeypatch):
    import psutil

    interfaces = {
        "Wi-Fi": [type("Addr", (), {"family": socket.AF_INET, "address": "192.168.1.8"})()],
        "Ethernet": [type("Addr", (), {"family": socket.AF_INET, "address": "10.0.0.8"})()],
    }
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: interfaces)
    monkeypatch.setattr("socket.gethostname", lambda: "sparc-host")
    copied = []
    root, tab = _make_tab()
    tab.widget.clipboard_clear = lambda: None
    tab.widget.clipboard_append = copied.append

    texts = _texts(tab.widget)
    assert "Your device IP addresses" in texts
    assert "Wi-Fi" in " ".join(texts)
    assert "Ethernet" in " ".join(texts)
    assert "192.168.1.8" in texts
    assert "10.0.0.8" in texts
    assert "sparc-host" in " ".join(texts)
    assert any("all ipv4" in text.lower() or "all interfaces" in text.lower() for text in texts)
    copy_buttons = [w for w in _walk(tab.widget)
                    if isinstance(w, ttk.Button) and "copy" in str(w.cget("text")).lower()]
    assert copy_buttons, "reachable endpoint needs a Copy control"
    copy_buttons[0].invoke()
    root.update()
    assert copied
    tab.close()
    root.destroy()


def test_pairing_shows_immutable_own_and_peer_fingerprints():
    service = FakeService()
    root, tab = _make_tab(service)
    request_data = {
        "request_id": "request-17",
        "own_fingerprint": "1" * 64,
        "candidate_fingerprint": "2" * 64,
        "endpoint": {"ip": "192.0.2.20", "port": 47655},
    }
    request = ServiceEvent("pairing_request", request_data)
    tab.handle_event(request)
    request_data["own_fingerprint"] = "3" * 64
    request_data["candidate_fingerprint"] = "4" * 64
    root.update()
    visible = " ".join(_texts(tab.widget))
    assert "1" * 64 in visible
    assert "2" * 64 in visible

    buttons = {str(w.cget("text")).strip().lower(): w for w in _walk(tab.widget)
               if isinstance(w, ttk.Button)}
    approve = next(w for label, w in buttons.items() if "approve" in label)
    approve.invoke()
    _pump(root, lambda: ("respond_to_pairing", "request-17", True) in service.calls)
    assert ("respond_to_pairing", "request-17", True) in service.calls

    service.calls.clear()
    tab.handle_event(ServiceEvent("pairing_request", {
        **request.data, "request_id": "request-18",
    }))
    root.update()
    buttons = [w for w in _walk(tab.widget) if isinstance(w, ttk.Button)]
    reject = next(w for w in buttons if "reject" in str(w.cget("text")).lower())
    reject.invoke()
    _pump(root, lambda: ("respond_to_pairing", "request-18", False) in service.calls)
    assert ("respond_to_pairing", "request-18", False) in service.calls

    tab.handle_event(ServiceEvent("state", {
        "state": "error", "reason": "changed_identity", "endpoint": None,
    }))
    root.update()
    assert any("blocked" in text.lower() or "changed" in text.lower()
               for text in _texts(tab.widget))
    assert any("forget peer" in text.lower() for text in _texts(tab.widget))
    tab.close()
    root.destroy()


@pytest.mark.parametrize(
    "state", ["stopped", "listening", "connecting", "handshaking", "connected", "error"]
)
def test_state_change_invalidates_old_pairing_approval(state):
    service = FakeService()
    root, tab = _make_tab(service)
    tab.handle_event(ServiceEvent("pairing_request", {
        "request_id": "request-19",
        "own_fingerprint": "1" * 64,
        "candidate_fingerprint": "2" * 64,
        "endpoint": {"ip": "192.0.2.21", "port": 47655},
    }))
    root.update()
    assert "disabled" not in next(
        button.state() for button in _walk(tab.widget)
        if isinstance(button, ttk.Button) and "approve" in button.cget("text").lower()
    )

    tab.handle_event(ServiceEvent("state", {"state": state, "reason": "state_changed"}))
    root.update()
    approve = next(button for button in _walk(tab.widget)
                   if isinstance(button, ttk.Button) and "approve" in button.cget("text").lower())
    assert "disabled" in approve.state()
    approve.invoke()
    root.update()
    assert not any(call[0] == "respond_to_pairing" for call in service.calls)
    tab.close()
    root.destroy()


def test_connected_peer_uses_live_authenticated_identity_not_remembered_ip(tmp_path):
    service = FakeService()
    service.remembered = [{
        "fingerprint": "b" * 64,
        "label": "other remembered peer",
        "endpoint": Endpoint("192.0.2.40", 41000),
    }]
    service.live_peer = {
        "fingerprint": "a" * 64,
        "endpoint": Endpoint("192.0.2.40", 52000),
    }
    root, tab = _make_tab(service)
    tab.handle_event(ServiceEvent("state", {"state": "connected", "reason": "session_established"}))
    root.update()
    assert tab._peer_fingerprint.get() == "a" * 64
    assert tab._peer_endpoint.get() == "Connected peer endpoint: 192.0.2.40:52000"
    tab.close()
    root.destroy()


@pytest.mark.parametrize(
    "state", ["listening", "stopped", "error", "connecting", "handshaking", "reconnecting"]
)
def test_nonconnected_states_clear_authenticated_peer_display(state):
    service = FakeService()
    old_fingerprint = "a" * 64
    service.live_peer = {
        "fingerprint": old_fingerprint,
        "endpoint": Endpoint("192.0.2.40", 52000),
    }
    root, tab = _make_tab(service)
    copied = []
    tab.widget.clipboard_clear = lambda: None
    tab.widget.clipboard_append = copied.append
    tab.handle_event(ServiceEvent("state", {"state": "connected", "reason": "session_established"}))
    root.update()
    assert tab._peer_fingerprint.get() == old_fingerprint
    assert "192.0.2.40:52000" in tab._peer_endpoint.get()

    service.live_peer = None
    tab.handle_event(ServiceEvent("state", {"state": state, "reason": "state_changed"}))
    root.update()
    assert tab._peer_fingerprint.get() == "Not connected"
    assert tab._peer_endpoint.get() == ""
    copy_button = next(
        button for button in _walk(tab.widget)
        if isinstance(button, ttk.Button) and "copy peer fingerprint" in button.cget("text").lower()
    )
    copy_button.invoke()
    assert old_fingerprint not in copied

    candidate = "b" * 64
    tab.handle_event(ServiceEvent("pairing_request", {
        "request_id": "fresh-request-31",
        "own_fingerprint": "c" * 64,
        "candidate_fingerprint": candidate,
        "endpoint": {"ip": "192.0.2.41", "port": 47655},
    }))
    root.update()
    assert candidate in tab._pairing_text.get()
    assert tab._pending_pairing[0] == "fresh-request-31"
    assert "Connected peer endpoint" not in tab._peer_endpoint.get()
    tab.close()
    root.destroy()


def test_connection_controls_reachable_at_supported_sizes(monkeypatch):
    import psutil

    interfaces = {
        f"Interface {index}": [
            type("Addr", (), {
                "family": socket.AF_INET,
                "address": f"192.0.2.{index + 1}",
            })()
        ]
        for index in range(4)
    }
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: interfaces)

    for width, height in ((960, 760), (800, 640)):
        root, notebook = _root_or_skip()
        service = FakeService()
        service.remembered = [{
            "fingerprint": "d" * 64,
            "label": "Remembered peer",
            "endpoint": Endpoint("192.0.2.20", 47655),
        }]
        tab = ConnectionTab(notebook, service)
        notebook.add(tab.widget, text="Connection")
        notebook.pack_configure(fill="both", expand=True)
        root.tk.call("tk", "scaling", 1.8)
        root.geometry(f"{width}x{height}")
        root.deiconify()
        tab.handle_event(ServiceEvent("pairing_request", {
            "request_id": "layout-request",
            "own_fingerprint": "1" * 64,
            "candidate_fingerprint": "2" * 64,
            "endpoint": {"ip": "192.0.2.21", "port": 47655},
        }))
        root.update()
        assert any(isinstance(child, ttk.Scrollbar)
                   and str(child.cget("orient")).lower() == "vertical"
                   for child in _walk(tab.widget))
        peer_list = next(child for child in _walk(tab.widget) if isinstance(child, tk.Listbox))
        peer_list.selection_set(0)
        root.update()

        buttons = [child for child in _walk(tab.widget) if isinstance(child, ttk.Button)]
        required = (
            "approve", "reject", "forget peer", "start listening", "stop listening",
            "connect", "disconnect",
        )
        selected = [next(button for button in buttons
                         if term in str(button.cget("text")).lower()) for term in required]
        for button in selected:
            button.focus_force()
            root.update()
            left = button.winfo_rootx() - root.winfo_rootx()
            top = button.winfo_rooty() - root.winfo_rooty()
            assert button.winfo_ismapped()
            assert 0 <= left and left + button.winfo_width() <= root.winfo_width()
            assert 0 <= top and top + button.winfo_height() <= root.winfo_height()

        # Listener and peer controls can wrap onto multiple rows, but each
        # action must remain fully inside the available width.
        for button in selected[-4:]:
            left = button.winfo_rootx() - root.winfo_rootx()
            assert left + button.winfo_width() <= root.winfo_width()
        tab.close()
        root.destroy()


@pytest.mark.parametrize(("ip", "port", "valid"), [
    ("192.0.2.1", "1", True),
    ("192.0.2.1", "65535", True),
    ("localhost", "80", False),
    ("192.0.2.1", "0", False),
    ("192.0.2.1", "65536", False),
    ("192.0.2.1", "abc", False),
])
def test_literal_ipv4_and_port_validation(ip, port, valid):
    service = FakeService()
    root, tab = _make_tab(service)
    entries = [w for w in _walk(tab.widget) if isinstance(w, ttk.Entry)]
    assert len(entries) >= 4, "bind and peer address/port must remain editable"
    # Peer fields follow the bind fields in the connection form.
    entries[-2].delete(0, tk.END)
    entries[-2].insert(0, ip)
    entries[-1].delete(0, tk.END)
    entries[-1].insert(0, port)
    connect = next(w for w in _walk(tab.widget)
                   if isinstance(w, ttk.Button) and "connect" in str(w.cget("text")).lower())
    connect.invoke()
    if valid:
        _pump(root, lambda: any(call[0] == "connect" for call in service.calls))
    else:
        root.update()
    calls = [call for call in service.calls if call[0] == "connect"]
    assert bool(calls) is valid
    if calls:
        assert calls[0][1] == Endpoint(ip, int(port))
    else:
        assert any("invalid" in text.lower() or "ipv4" in text.lower()
                   or "port" in text.lower() for text in _texts(tab.widget))
    tab.close()
    root.destroy()


def test_forget_peer_requires_explicit_action_and_audit(tmp_path, monkeypatch, credential_provider):
    service = PeerService(tmp_path, credential_provider=credential_provider)
    remote_identity = load_identity(tmp_path / "remote", credential_provider=credential_provider)
    endpoint = Endpoint("192.0.2.30", 47655)
    service._trust.pin(remote_identity.public_bytes, endpoint)
    fingerprint = remote_identity.fingerprint
    order = []
    original_append = service._audit.append
    original_forget = service._trust.forget

    def append_then_record(kind, metadata):
        result = original_append(kind, metadata)
        order.append(("audit", kind, metadata.copy()))
        return result

    def forget_then_record(value):
        order.append(("forget", value, service.trusted_peers()))
        return original_forget(value)

    monkeypatch.setattr(service._audit, "append", append_then_record)
    monkeypatch.setattr(service._trust, "forget", forget_then_record)
    service.forget_peer(fingerprint)
    assert [entry[0] for entry in order] == ["audit", "forget", "audit"]
    expected = {"fingerprint": fingerprint, "endpoint": "192.0.2.30:47655"}
    assert order[0][1:] == ("trust_changed", {**expected, "state": "forget_requested"})
    assert order[1][1] == fingerprint and len(order[1][2]) == 1
    assert order[2][1:] == ("trust_changed", {**expected, "state": "forgotten"})
    assert service.trusted_peers() == []
    service.close()


@pytest.mark.parametrize(("fail_on", "expected_present"), [(1, True), (2, False)])
def test_forget_audit_failures_are_truthful_and_fail_closed(
    tmp_path, monkeypatch, fail_on, expected_present,
    credential_provider,
):
    service = PeerService(tmp_path, credential_provider=credential_provider)
    remote_identity = load_identity(tmp_path / "remote", credential_provider=credential_provider)
    endpoint = Endpoint("192.0.2.31", 47655)
    service._trust.pin(remote_identity.public_bytes, endpoint)
    fingerprint = remote_identity.fingerprint

    original_append = service._audit.append
    calls = []

    def fail_append(kind, metadata):
        calls.append((kind, dict(metadata)))
        if len(calls) == fail_on:
            raise SparcError("audit_storage_failed", "injected failure")
        return original_append(kind, metadata)

    monkeypatch.setattr(service._audit, "append", fail_append)
    with pytest.raises(SparcError) as caught:
        service.forget_peer(fingerprint)
    assert caught.value.code == "audit_storage_failed"
    peers = [peer["fingerprint"] for peer in service.trusted_peers()]
    assert (fingerprint in peers) is expected_present
    assert service._audit_failed
    assert [metadata["state"] for _kind, metadata in calls] == (
        ["forget_requested"] if fail_on == 1 else ["forget_requested", "forgotten"]
    )
    service.close()


def test_forget_refuses_occupied_slot_without_audit_or_mutation(tmp_path, monkeypatch, credential_provider):
    service = PeerService(tmp_path, credential_provider=credential_provider)
    remote_identity = load_identity(tmp_path / "remote", credential_provider=credential_provider)
    endpoint = Endpoint("192.0.2.32", 47655)
    service._trust.pin(remote_identity.public_bytes, endpoint)
    fingerprint = remote_identity.fingerprint
    calls = []
    monkeypatch.setattr(service._audit, "append", lambda *args: calls.append(args))
    service._slot = type("ActiveAttempt", (), {"peer_fingerprint": fingerprint})()
    with pytest.raises(SparcError) as caught:
        service.forget_peer(fingerprint)
    assert caught.value.code == "busy"
    assert calls == []
    assert [peer["fingerprint"] for peer in service.trusted_peers()] == [fingerprint]
    service._slot = None
    service.close()


def test_forget_invalid_or_absent_fingerprint_has_no_audit_or_mutation(tmp_path, monkeypatch, credential_provider):
    service = PeerService(tmp_path, credential_provider=credential_provider)
    remote_identity = load_identity(tmp_path / "remote", credential_provider=credential_provider)
    endpoint = Endpoint("192.0.2.36", 47655)
    service._trust.pin(remote_identity.public_bytes, endpoint)
    calls = []
    monkeypatch.setattr(service._audit, "append", lambda *args: calls.append(("audit", args)))
    monkeypatch.setattr(service._trust, "forget", lambda *args: calls.append(("forget", args)))
    with pytest.raises(SparcError) as invalid:
        service.forget_peer("BAD")
    assert invalid.value.code == "invalid_fingerprint"
    with pytest.raises(SparcError) as absent:
        service.forget_peer("f" * 64)
    assert absent.value.code == "invalid_state"
    assert calls == []
    assert [peer["fingerprint"] for peer in service.trusted_peers()] == [
        remote_identity.fingerprint
    ]
    service.close()


def test_forget_trust_write_failure_has_no_completion_record(tmp_path, monkeypatch, credential_provider):
    service = PeerService(tmp_path, credential_provider=credential_provider)
    remote_identity = load_identity(tmp_path / "remote", credential_provider=credential_provider)
    service._trust.pin(remote_identity.public_bytes, Endpoint("192.0.2.37", 47655))
    fingerprint = remote_identity.fingerprint
    records = []
    original_append = service._audit.append

    def record_append(kind, metadata):
        result = original_append(kind, metadata)
        records.append((kind, dict(metadata)))
        return result

    def fail_forget(_fingerprint):
        raise SparcError("trust_write_failed", "injected trust failure")

    monkeypatch.setattr(service._audit, "append", record_append)
    monkeypatch.setattr(service._trust, "forget", fail_forget)
    with pytest.raises(SparcError) as caught:
        service.forget_peer(fingerprint)
    assert caught.value.code == "trust_write_failed"
    assert [metadata["state"] for kind, metadata in records if kind == "trust_changed"] == [
        "forget_requested"
    ]
    assert [peer["fingerprint"] for peer in service.trusted_peers()] == [fingerprint]
    assert not service._audit_failed
    service.close()


def test_forget_barrier_serializes_networking_and_second_forget(tmp_path, monkeypatch, credential_provider):
    service = PeerService(tmp_path, credential_provider=credential_provider)
    remote_identity = load_identity(tmp_path / "remote", credential_provider=credential_provider)
    endpoint = Endpoint("192.0.2.33", 47655)
    service._trust.pin(remote_identity.public_bytes, endpoint)
    fingerprint = remote_identity.fingerprint
    listener_endpoint = service.start_listener("127.0.0.1", 0)
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    errors = []
    original_append = service._audit.append

    def held_append(kind, metadata):
        if not entered.is_set():
            entered.set()
            assert release.wait(2), "test did not release held audit operation"
        return original_append(kind, metadata)

    monkeypatch.setattr(service._audit, "append", held_append)

    def forget():
        try:
            service.forget_peer(fingerprint)
        except Exception as exc:
            errors.append(exc)
        finally:
            finished.set()

    worker = threading.Thread(target=forget)
    worker.start()
    try:
        assert entered.wait(1)
        lock_acquired = threading.Event()

        def acquire_service_lock():
            with service._state_lock:
                lock_acquired.set()

        probe = threading.Thread(target=acquire_service_lock)
        probe.start()
        assert lock_acquired.wait(0.5), "audit append ran while holding the service state lock"
        probe.join(1)

        for operation in (
            lambda: service.connect(Endpoint("127.0.0.1", listener_endpoint.port)),
            lambda: service.forget_peer(fingerprint),
        ):
            with pytest.raises(SparcError) as caught:
                operation()
            assert caught.value.code == "busy"

        # An already-live listener may accept TCP while forget is reserved,
        # but the connection must be discarded before a C3 pairing request.
        client = socket.create_connection((listener_endpoint.ip, listener_endpoint.port), timeout=1)
        client.settimeout(1)
        assert client.recv(1) == b""
        client.close()
        service.stop_listener()
        with pytest.raises(SparcError) as listener_error:
            service.start_listener("127.0.0.1", 0)
        assert listener_error.value.code == "busy"
        queued = []
        while True:
            try:
                queued.append(service.events.get_nowait())
            except queue.Empty:
                break
        assert not any(event.kind == "pairing_request" for event in queued)
    finally:
        release.set()
        worker.join(2)
        service.close()
    assert not worker.is_alive()
    assert finished.is_set()
    assert errors == []
    assert service.trusted_peers() == []


def test_close_before_forget_mutation_cancels_removal(tmp_path, monkeypatch, credential_provider):
    service = PeerService(tmp_path, credential_provider=credential_provider)
    remote_identity = load_identity(tmp_path / "remote", credential_provider=credential_provider)
    service._trust.pin(remote_identity.public_bytes, Endpoint("192.0.2.34", 47655))
    fingerprint = remote_identity.fingerprint
    entered, release = threading.Event(), threading.Event()
    errors, records = [], []
    original_append = service._audit.append
    original_forget = service._trust.forget

    def held_intent(kind, metadata):
        records.append((kind, dict(metadata)))
        result = original_append(kind, metadata)
        entered.set()
        assert release.wait(2)
        return result

    def record_mutation(value):
        records.append(("mutation", value))
        original_forget(value)

    monkeypatch.setattr(service._audit, "append", held_intent)
    monkeypatch.setattr(service._trust, "forget", record_mutation)
    worker = threading.Thread(target=lambda: _capture_error(
        lambda: service.forget_peer(fingerprint), errors
    ))
    worker.start()
    try:
        assert entered.wait(1)
        service.close()
    finally:
        release.set()
        worker.join(2)
    assert not worker.is_alive()
    assert errors and isinstance(errors[0], SparcError)
    assert errors[0].code == "operation_cancelled"
    assert not any(item[0] == "mutation" for item in records)
    assert [peer["fingerprint"] for peer in service.trusted_peers()] == [fingerprint]
    assert [metadata["state"] for kind, metadata in records if kind == "trust_changed"] == [
        "forget_requested"
    ]


def test_close_after_forget_mutation_starts_finishes_and_audits(tmp_path, monkeypatch, credential_provider):
    service = PeerService(tmp_path, credential_provider=credential_provider)
    remote_identity = load_identity(tmp_path / "remote", credential_provider=credential_provider)
    service._trust.pin(remote_identity.public_bytes, Endpoint("192.0.2.35", 47655))
    fingerprint = remote_identity.fingerprint
    entered, release = threading.Event(), threading.Event()
    errors, records = [], []
    original_append = service._audit.append
    original_forget = service._trust.forget

    def record_append(kind, metadata):
        result = original_append(kind, metadata)
        records.append((kind, dict(metadata)))
        return result

    def held_mutation(value):
        entered.set()
        assert release.wait(2)
        original_forget(value)

    monkeypatch.setattr(service._audit, "append", record_append)
    monkeypatch.setattr(service._trust, "forget", held_mutation)
    worker = threading.Thread(target=lambda: _capture_error(
        lambda: service.forget_peer(fingerprint), errors
    ))
    worker.start()
    try:
        assert entered.wait(1)
        service.close()
    finally:
        release.set()
        worker.join(2)
    assert not worker.is_alive()
    assert errors == []
    assert service.trusted_peers() == []
    assert [metadata["state"] for kind, metadata in records if kind == "trust_changed"] == [
        "forget_requested", "forgotten"
    ]


def _capture_error(operation, errors):
    try:
        operation()
    except Exception as exc:
        errors.append(exc)
