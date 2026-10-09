"""Real-Tk interaction tests for responsive, private identity unlocking."""

from __future__ import annotations

import importlib
import queue
import threading
import time
import tkinter as tk
import tkinter.ttk as ttk

import pytest


def _unlock_api():
    try:
        module = importlib.import_module("sparc.gui.identity_unlock")
    except ModuleNotFoundError as error:
        if error.name == "sparc.gui.identity_unlock":
            pytest.fail("the responsive GUI identity unlock module must be implemented")
        raise
    function = getattr(module, "unlock_identity_for_gui", None)
    assert callable(function), "GUI unlock entrypoint is missing"
    return function


def _root_or_skip():
    try:
        root = tk.Tk()
    except tk.TclError as error:
        pytest.skip(f"Tk display is unavailable: {error}")
    root.withdraw()
    return root


def _walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from _walk(child)


def _dialog(root):
    for child in root.winfo_children():
        if isinstance(child, tk.Toplevel):
            return child
    return None


def _entries(top):
    return [
        child for child in _walk(top)
        if isinstance(child, (tk.Entry, ttk.Entry))
    ]


def _buttons(top):
    return [
        child for child in _walk(top)
        if isinstance(child, (tk.Button, ttk.Button))
    ]


def _visible_text(top):
    pieces = []
    for widget in _walk(top):
        if isinstance(widget, (tk.Label, ttk.Label)):
            pieces.append(str(widget.cget("text")))
            variable = widget.cget("textvariable")
            if variable:
                pieces.append(str(widget.getvar(variable)))
    return " ".join(pieces)


def _button(top, fragment):
    target = fragment.casefold()
    return next(
        button for button in _buttons(top)
        if target in str(button.cget("text")).casefold()
    )


def _submit_button(top):
    return next(
        button for button in _buttons(top)
        if any(word in str(button.cget("text")).casefold()
               for word in ("unlock", "create", "encrypt", "retry"))
    )


def _fill(entries, values):
    assert len(entries) >= len(values)
    for entry, value in zip(entries, values):
        entry.delete(0, "end")
        entry.insert(0, value)


def _track_tk_calls_and_after_ids(monkeypatch):
    main_thread = threading.get_ident()
    tk_threads = set()
    scheduled = set()
    original_after = tk.Misc.after
    original_after_cancel = tk.Misc.after_cancel

    def track_method(owner, name):
        original = getattr(owner, name)

        def tracked(widget, *args, **kwargs):
            tk_threads.add(threading.get_ident())
            return original(widget, *args, **kwargs)

        monkeypatch.setattr(owner, name, tracked)

    for method_name in ("get", "insert", "delete"):
        track_method(tk.Entry, method_name)
        track_method(ttk.Entry, method_name)
    track_method(tk.Misc, "configure")
    track_method(tk.Wm, "protocol")

    def tracked_after(widget, delay, callback=None, *args):
        tk_threads.add(threading.get_ident())
        if callback is None:
            return original_after(widget, delay)
        holder = {}

        def dispatch():
            scheduled.discard(holder.get("id"))
            return callback(*args)

        after_id = original_after(widget, delay, dispatch)
        holder["id"] = after_id
        scheduled.add(after_id)
        return after_id

    def tracked_after_cancel(widget, after_id):
        tk_threads.add(threading.get_ident())
        scheduled.discard(after_id)
        return original_after_cancel(widget, after_id)

    monkeypatch.setattr(tk.Misc, "after", tracked_after)
    monkeypatch.setattr(tk.Misc, "after_cancel", tracked_after_cancel)
    return main_thread, tk_threads, scheduled


def _capture_background_queue_payloads(monkeypatch):
    main_thread = threading.get_ident()
    payloads = []
    original_put = queue.Queue.put

    def observe_put(instance, item, *args, **kwargs):
        if threading.get_ident() != main_thread:
            payloads.append(item)
        return original_put(instance, item, *args, **kwargs)

    monkeypatch.setattr(queue.Queue, "put", observe_put)
    return payloads


def test_gui_cancel_while_kdf_blocked_starts_no_service(
    tmp_path, monkeypatch
):
    unlock = _unlock_api()
    codec = importlib.import_module("sparc.identity_codec")
    from sparc.models import SparcError

    root = _root_or_skip()
    main_thread, tk_threads, scheduled = _track_tk_calls_and_after_ids(monkeypatch)
    started_threads = []
    original_start = threading.Thread.start
    original_derive = codec._derive_key
    entered_kdf = threading.Event()
    release_kdf = threading.Event()
    cancel_seen = threading.Event()

    def track_start(thread, *args, **kwargs):
        started_threads.append(thread)
        return original_start(thread, *args, **kwargs)

    def block_kdf(passphrase, salt):
        entered_kdf.set()
        release_kdf.wait(timeout=5)
        return original_derive(passphrase, salt)

    monkeypatch.setattr(threading.Thread, "start", track_start)
    monkeypatch.setattr(codec, "_derive_key", block_kdf)
    phrase = "valid passphrase for creation"

    def submit():
        top = _dialog(root)
        if top is None or len(_entries(top)) < 2:
            root.after(10, submit)
            return
        _fill(_entries(top), ["short", "short"])
        _submit_button(top).invoke()
        root.after(80, submit_valid)

    def submit_valid():
        top = _dialog(root)
        assert top is not None and not entered_kdf.is_set()
        _fill(_entries(top), [phrase, phrase])
        _submit_button(top).invoke()
        root.after(10, wait_for_kdf)

    def wait_for_kdf():
        top = _dialog(root)
        if not entered_kdf.is_set() or top is None:
            root.after(10, wait_for_kdf)
            return
        assert str(_button(top, "cancel").cget("state")) != "disabled"
        _button(top, "cancel").invoke()
        cancel_seen.set()
        root.after(20, release_kdf.set)

    root.after(20, submit)
    try:
        with pytest.raises(SparcError) as raised:
            unlock(root, tmp_path / "blocked-create")
        assert raised.value.code == "identity_unlock_cancelled"
        assert entered_kdf.is_set() and cancel_seen.is_set()
        assert not (tmp_path / "blocked-create" / "identity.json").exists()
        assert all(not worker.is_alive() for worker in started_threads)
        assert scheduled == set()
        assert tk_threads == {main_thread}
    finally:
        release_kdf.set()
        root.destroy()


def test_gui_validation_retry_and_safe_error(tmp_path, monkeypatch):
    unlock = _unlock_api()
    identity = importlib.import_module("sparc.identity")
    codec = importlib.import_module("sparc.identity_codec")
    credentials = identity.IdentityCredentials(
        "  秘密の phrase 🛰️ that remains private  ".encode("utf-8"), None
    )

    def known_provider(request):
        return identity.IdentityCredentials(
            credentials.passphrase,
            credentials.passphrase if request.purpose in {"create", "migrate"} else None,
        )

    root = _root_or_skip()
    main_thread, tk_threads, scheduled = _track_tk_calls_and_after_ids(monkeypatch)
    data_dir = tmp_path / "retry"
    identity.load_identity(data_dir, credential_provider=known_provider)
    secret = credentials.passphrase.decode("utf-8")
    wrong = "incorrect phrase for retry"
    payloads = _capture_background_queue_payloads(monkeypatch)
    kdf_calls = []
    original_derive = codec._derive_key

    def count_derive(passphrase, salt):
        kdf_calls.append(True)
        return original_derive(passphrase, salt)

    monkeypatch.setattr(codec, "_derive_key", count_derive)
    attempts = []

    def first_submit():
        top = _dialog(root)
        if top is None or not _entries(top):
            root.after(10, first_submit)
            return
        entry = _entries(top)[0]
        assert entry.cget("show") != ""
        entry.insert(0, "x" * 1025)
        _button(top, "unlock").invoke()
        root.after(100, submit_wrong_phrase)

    def submit_wrong_phrase():
        top = _dialog(root)
        assert top is not None
        assert kdf_calls == []
        entry = _entries(top)[0]
        entry.delete(0, "end")
        entry.insert(0, wrong)
        _submit_button(top).invoke()
        root.after(20, wait_for_retry)

    def wait_for_retry():
        top = _dialog(root)
        if top is None:
            return
        retry_buttons = [button for button in _buttons(top)
                         if str(button.cget("text")).casefold() == "retry"]
        if not retry_buttons:
            root.after(20, wait_for_retry)
            return
        attempts.append(True)
        visible_text = _visible_text(top)
        assert wrong not in visible_text
        entry = _entries(top)[0]
        entry.delete(0, "end")
        entry.insert(0, secret)
        retry_buttons[0].invoke()

    root.after(20, first_submit)
    try:
        handle = unlock(root, data_dir)
        assert attempts == [True]
        assert len(kdf_calls) == 2
        assert not hasattr(handle, "passphrase")
        assert all(isinstance(payload, str) for payload in payloads)
        assert all(secret not in payload and wrong not in payload for payload in payloads)
        assert tk_threads == {main_thread}
        assert scheduled == set()
    finally:
        root.destroy()


@pytest.mark.parametrize("close_target", ["dialog", "root"])
def test_gui_close_during_migration_keeps_identity(
    tmp_path, legacy_identity_store, monkeypatch, close_target
):
    unlock = _unlock_api()
    gui_module = importlib.import_module("sparc.gui.identity_unlock")
    codec = importlib.import_module("sparc.identity_codec")
    from sparc.models import SparcError
    data_dir = tmp_path / "close-migration"
    old = legacy_identity_store(data_dir)
    identity_path = data_dir / "identity.json"
    before = identity_path.read_bytes()
    root = _root_or_skip()
    main_thread, tk_threads, scheduled = _track_tk_calls_and_after_ids(monkeypatch)
    started_threads = []
    original_start = threading.Thread.start
    original_derive = codec._derive_key
    entered = threading.Event()
    release = threading.Event()
    closed_while_busy = []
    observed_cancellation = []
    callback_errors = []
    phrase = "migration phrase long enough"
    prior_root_close = root.protocol("WM_DELETE_WINDOW")
    real_unlock = gui_module._unlock_store

    def retain_cancel_predicate(*args, **kwargs):
        predicate = kwargs.get("cancelled")
        cancellation_event = getattr(predicate, "__self__", None)
        if cancellation_event is not None:
            started_threads.append(cancellation_event)
        return real_unlock(*args, **kwargs)

    monkeypatch.setattr(gui_module, "_unlock_store", retain_cancel_predicate)

    def track_start(thread, *args, **kwargs):
        started_threads.append(thread)
        return original_start(thread, *args, **kwargs)

    def block_kdf(passphrase, salt):
        entered.set()
        release.wait(timeout=5)
        return original_derive(passphrase, salt)

    monkeypatch.setattr(threading.Thread, "start", track_start)
    monkeypatch.setattr(codec, "_derive_key", block_kdf)

    def report_callback_exception(_type, value, _traceback):
        callback_errors.append(value)
        release.set()
        for cancellation_event in started_threads:
            if isinstance(cancellation_event, threading.Event):
                cancellation_event.set()
        top = _dialog(root) if exists(root) else None
        if top is not None:
            script = top.protocol("WM_DELETE_WINDOW")
            if script:
                top.tk.eval(script)

    root.report_callback_exception = report_callback_exception

    def exists(widget):
        try:
            return bool(widget.winfo_exists())
        except tk.TclError:
            return False

    def submit():
        if time.monotonic() > deadline:
            callback_errors.append(TimeoutError("migration dialog did not become ready"))
            release.set()
            for cancellation_event in started_threads:
                if isinstance(cancellation_event, threading.Event):
                    cancellation_event.set()
            if exists(root):
                root.destroy()
            return
        top = _dialog(root)
        if top is None or len(_entries(top)) < 2:
            root.after(10, submit)
            return
        labels = _visible_text(top)
        assert old.fingerprint in labels
        assert "migrat" in labels.casefold()
        _fill(_entries(top), [phrase, phrase])
        _button(top, "encrypt").invoke()
        root.after(10, close_when_busy)

    def close_when_busy():
        top = _dialog(root)
        if not entered.is_set() or top is None:
            if time.monotonic() > deadline:
                callback_errors.append(TimeoutError("migration dialog did not reach KDF"))
                release.set()
                if exists(root):
                    root.destroy()
                return
            root.after(10, close_when_busy)
            return
        if close_target == "dialog":
            protocol_script = top.protocol("WM_DELETE_WINDOW")
            top.tk.eval(protocol_script)
        else:
            root_protocol = root.protocol("WM_DELETE_WINDOW")
            if root_protocol and root_protocol != prior_root_close:
                root.tk.eval(root_protocol)
            else:
                # Before root-close handling is installed, simulate the
                # window manager destroying the root while the dialog is modal.
                root.destroy()
        closed_while_busy.append(exists(root) and _dialog(root) is not None)
        for cancellation_event in started_threads:
            if isinstance(cancellation_event, threading.Event):
                observed_cancellation.append(cancellation_event.is_set())
        if exists(root):
            root.after(20, release.set)

    deadline = time.monotonic() + 6.0
    root.after(20, submit)
    outcome = None
    post_root_close = None
    try:
        try:
            unlock(root, data_dir)
        except Exception as error:
            outcome = error
        if exists(root):
            post_root_close = root.protocol("WM_DELETE_WINDOW")
    finally:
        outstanding_after = tuple(scheduled)
        for cancellation_event in started_threads:
            if isinstance(cancellation_event, threading.Event):
                cancellation_event.set()
        release.set()
        for worker in started_threads:
            if isinstance(worker, threading.Thread):
                worker.join(timeout=3)
        for after_id in tuple(scheduled):
            try:
                root.after_cancel(after_id)
            except tk.TclError:
                pass
            scheduled.discard(after_id)
        if exists(root):
            root.destroy()
    assert isinstance(outcome, SparcError)
    assert outcome.code == "identity_unlock_cancelled"
    assert callback_errors == []
    assert closed_while_busy == [True]
    assert observed_cancellation == [True]
    assert not any(
        isinstance(worker, threading.Thread) and worker.is_alive()
        for worker in started_threads
    )
    if close_target == "root":
        assert outstanding_after == ()
        assert post_root_close == prior_root_close
    assert identity_path.read_bytes() == before
    assert old.public_bytes
    assert scheduled == set()
    assert tk_threads == {main_thread}


def test_gui_worker_handoff_and_setup_cleanup(tmp_path, monkeypatch):
    unlock = _unlock_api()
    payloads = _capture_background_queue_payloads(monkeypatch)
    identity = importlib.import_module("sparc.identity")
    data_dir = tmp_path / "handoff"
    credentials = identity.IdentityCredentials(b"known GUI handoff phrase", None)

    def known_provider(request):
        return identity.IdentityCredentials(
            credentials.passphrase,
            credentials.passphrase if request.purpose in {"create", "migrate"} else None,
        )

    expected = identity.load_identity(data_dir, credential_provider=known_provider)
    root = _root_or_skip()
    main_thread, tk_threads, scheduled = _track_tk_calls_and_after_ids(monkeypatch)

    def submit():
        top = _dialog(root)
        if top is None or not _entries(top):
            root.after(10, submit)
            return
        _entries(top)[0].insert(0, credentials.passphrase.decode("utf-8"))
        _button(top, "unlock").invoke()

    root.after(20, submit)
    try:
        handle = unlock(root, data_dir)
        consumed_dir, loaded = identity._consume_unlocked_store(handle)
        assert consumed_dir == data_dir.resolve()
        assert loaded.public_bytes == expected.public_bytes
        assert all(isinstance(payload, str) for payload in payloads)
        assert not any(isinstance(payload, (bytes, identity._UnlockedStore)) for payload in payloads)
        assert tk_threads == {main_thread}
        assert scheduled == set()
    finally:
        root.destroy()
