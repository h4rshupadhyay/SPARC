"""Hidden terminal credential adapter contract tests."""

from __future__ import annotations

import getpass
import importlib
import io
import os
from pathlib import Path
import pytest
import sys
try:
    import pty
except ImportError:  # pragma: no cover - Windows console coverage is platform-specific.
    pty = None

from sparc.models import SparcError


def _console_api():
    try:
        module = importlib.import_module("sparc.identity_unlock")
    except ModuleNotFoundError as error:
        if error.name == "sparc.identity_unlock":
            pytest.fail("the terminal identity credential adapter must be implemented")
        raise
    function = getattr(module, "console_credentials", None)
    assert callable(function), "console_credentials API is missing"
    return module, function


def _request(module, purpose="unlock"):
    codec = importlib.import_module("sparc.identity_codec")
    request_type = getattr(codec, "IdentityUnlockRequest", None)
    assert request_type is not None, "IdentityUnlockRequest is missing"
    return request_type(purpose, Path("/unused/test-store"), None)


def _allow_terminal(monkeypatch, module):
    if pty is None:
        pytest.skip("pseudo-terminal fixture is available only on POSIX")
    master_fd, slave_fd = pty.openpty()
    opened = set()
    original_open = os.open

    def fake_os_open(path, flags, *args, **kwargs):
        if os.fspath(path) == "/dev/tty":
            fd = os.dup(slave_fd)
            opened.add(fd)
            return fd
        return original_open(path, flags, *args, **kwargs)

    def fake_builtin_open(path, mode="r", *args, **kwargs):
        if os.fspath(path) == "/dev/tty":
            fd = os.dup(slave_fd)
            opened.add(fd)
            return os.fdopen(fd, mode)
        return open(path, mode, *args, **kwargs)

    monkeypatch.setattr(module.os, "open", fake_os_open)
    monkeypatch.setattr(module, "open", fake_builtin_open, raising=False)
    if hasattr(module, "_has_controlling_terminal"):
        monkeypatch.setattr(module, "_has_controlling_terminal", lambda: True)
    if hasattr(module, "_open_controlling_terminal"):
        from contextlib import nullcontext

        monkeypatch.setattr(module, "_open_controlling_terminal", lambda: nullcontext())
    return master_fd, slave_fd, opened


def _close_test_terminal(master_fd, slave_fd, opened):
    for descriptor in {*opened, master_fd, slave_fd}:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _set_prompt(monkeypatch, module, function):
    prompt_api = getattr(module, "getpass", None)
    if prompt_api is not None and callable(getattr(prompt_api, "getpass", None)):
        monkeypatch.setattr(prompt_api, "getpass", function)
    else:
        monkeypatch.setattr(module, "getpass", function)


def test_console_credentials_masks_and_encodes_unicode_with_confirmation(monkeypatch):
    module, console_credentials = _console_api()
    master_fd, slave_fd, opened = _allow_terminal(monkeypatch, module)
    values = iter(["  秘密の phrase 🛰️ remains private  ", "  秘密の phrase 🛰️ remains private  "])
    prompts = []

    def hidden_prompt(prompt, *args, **kwargs):
        prompts.append(prompt)
        return next(values)

    _set_prompt(monkeypatch, module, hidden_prompt)
    request = _request(module, "create")
    try:
        credentials = console_credentials(request)
    finally:
        _close_test_terminal(master_fd, slave_fd, opened)

    phrase = "  秘密の phrase 🛰️ remains private  ".encode("utf-8")
    assert credentials.passphrase == phrase
    assert credentials.confirmation == phrase
    assert len(prompts) == 2
    assert all(phrase.decode("utf-8") not in prompt for prompt in prompts)


def test_console_unlock_asks_once_and_preserves_bytes(monkeypatch):
    module, console_credentials = _console_api()
    master_fd, slave_fd, opened = _allow_terminal(monkeypatch, module)
    prompts = []
    phrase = "  unlock phrase with Unicode é  "
    _set_prompt(
        monkeypatch, module,
        lambda prompt, **_kwargs: (prompts.append(prompt) or phrase),
    )
    try:
        credentials = console_credentials(_request(module, "unlock"))
    finally:
        _close_test_terminal(master_fd, slave_fd, opened)

    assert credentials.passphrase == phrase.encode("utf-8")
    assert credentials.confirmation is None
    assert len(prompts) == 1


def test_console_warning_requires_credentials_without_echo_fallback(monkeypatch):
    module, console_credentials = _console_api()
    master_fd, slave_fd, opened = _allow_terminal(monkeypatch, module)

    def no_hidden_prompt(*_args, **_kwargs):
        raise getpass.GetPassWarning("echo may be enabled")

    _set_prompt(monkeypatch, module, no_hidden_prompt)
    try:
        with pytest.raises(SparcError) as raised:
            console_credentials(_request(module))
    finally:
        _close_test_terminal(master_fd, slave_fd, opened)
    assert getattr(raised.value, "code", None) == "identity_credentials_required"
    assert "echo may be enabled" not in str(raised.value)


@pytest.mark.parametrize("failure", [EOFError(), KeyboardInterrupt()])
def test_console_eof_and_ctrl_c_are_safe_cancellation(monkeypatch, failure):
    module, console_credentials = _console_api()
    master_fd, slave_fd, opened = _allow_terminal(monkeypatch, module)

    def cancel_prompt(*_args, **_kwargs):
        raise failure

    _set_prompt(monkeypatch, module, cancel_prompt)
    try:
        result = console_credentials(_request(module))
    finally:
        _close_test_terminal(master_fd, slave_fd, opened)
    assert result is None


def test_console_requires_a_controlling_terminal_without_prompt(monkeypatch):
    if pty is None:
        pytest.skip("controlling-terminal fixture is available only on POSIX")
    module, console_credentials = _console_api()
    prompt_calls = []
    monkeypatch.setattr(module, "open", lambda *_a, **_k: (_ for _ in ()).throw(OSError("no tty")), raising=False)
    real_os_open = os.open

    def no_tty(path, flags, *args, **kwargs):
        if os.fspath(path) == "/dev/tty":
            raise OSError("no controlling terminal")
        return real_os_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(module.os, "open", no_tty)
    _set_prompt(monkeypatch, module, lambda *_a, **_k: prompt_calls.append(True))
    monkeypatch.setattr(sys, "stdin", io.StringIO("not a terminal"))

    with pytest.raises(SparcError) as raised:
        console_credentials(_request(module))
    assert getattr(raised.value, "code", None) == "identity_credentials_required"
    assert prompt_calls == []


def test_console_rejects_mismatched_new_passphrases(monkeypatch):
    module, console_credentials = _console_api()
    master_fd, slave_fd, opened = _allow_terminal(monkeypatch, module)
    values = iter(["a long enough first phrase", "a different long enough phrase"])
    _set_prompt(monkeypatch, module, lambda *_a, **_k: next(values))
    try:
        with pytest.raises(SparcError) as raised:
            console_credentials(_request(module, "migrate"))
    finally:
        _close_test_terminal(master_fd, slave_fd, opened)
    assert getattr(raised.value, "code", None) == "identity_credentials_invalid"
