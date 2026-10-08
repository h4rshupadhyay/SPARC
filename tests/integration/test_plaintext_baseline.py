"""Contracts for the isolated synthetic plaintext comparison CLI."""

from __future__ import annotations

import os
from pathlib import Path
import queue
import socket
import struct
import subprocess
import sys
import threading
import time

import pytest


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = PROJECT_ROOT / "scripts" / "plaintext_baseline.py"
IP = "127.0.0.1"
MAX_TEXT_BYTES = 16 * 1024


def _environment() -> dict[str, str]:
    environment = os.environ.copy()
    source_path = str(PROJECT_ROOT / "src")
    environment["PYTHONPATH"] = os.pathsep.join(
        part for part in (source_path, environment.get("PYTHONPATH", "")) if part
    )
    return environment


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind((IP, 0))
        return listener.getsockname()[1]


def _read_exact(connection: socket.socket, count: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < count:
        chunk = connection.recv(count - len(chunks))
        if not chunk:
            raise AssertionError("sender closed before the complete frame arrived")
        chunks.extend(chunk)
    return bytes(chunks)


def _stop(process: subprocess.Popen[str]) -> None:
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=2)


def test_baseline_wire_contains_synthetic_text():
    text = "LAB ONLY — plaintext probe: café 雪 🔐"
    payload = text.encode("utf-8")
    port = _free_port()
    received: list[bytes] = []
    failures: list[BaseException] = []
    ready = threading.Event()

    def receive_one_frame() -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.settimeout(5)
                listener.bind((IP, port))
                listener.listen(1)
                ready.set()
                connection, _address = listener.accept()
                with connection:
                    connection.settimeout(5)
                    size = struct.unpack("!I", _read_exact(connection, 4))[0]
                    received.append(_read_exact(connection, size))
        except BaseException as exc:
            failures.append(exc)

    server = threading.Thread(target=receive_one_frame, daemon=True)
    server.start()
    try:
        assert ready.wait(timeout=2), "raw TCP receiver did not become ready"
        sender = subprocess.run(
            [sys.executable, str(SCRIPT), "send", "--ip", IP, "--port", str(port), "--text", text],
            cwd=PROJECT_ROOT,
            env=_environment(),
            text=True,
            capture_output=True,
            timeout=12,
            check=False,
        )
    finally:
        server.join(timeout=6)

    assert not server.is_alive(), "raw TCP receiver did not finish"
    assert not failures, failures
    assert sender.returncode == 0, sender.stderr
    assert received == [payload]
    assert payload in received[0]


def test_receiver_cli_accepts_one_message_and_exits():
    text = "receiver CLI got café, 雪, and 🚀"
    port = _free_port()
    receiver = subprocess.Popen(
        [sys.executable, str(SCRIPT), "listen", "--ip", IP, "--port", str(port)],
        cwd=PROJECT_ROOT,
        env=_environment(),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=1,
    )
    readiness: queue.Queue[str] = queue.Queue(maxsize=1)

    def read_startup_line() -> None:
        assert receiver.stdout is not None
        readiness.put(receiver.stdout.readline())

    reader = threading.Thread(target=read_startup_line, daemon=True)
    reader.start()
    try:
        try:
            startup = readiness.get(timeout=5)
        except queue.Empty:
            startup = ""
        assert "Listening" in startup, "receiver did not announce readiness"

        sender = subprocess.run(
            [sys.executable, str(SCRIPT), "send", "--ip", IP, "--port", str(port), "--text", text],
            cwd=PROJECT_ROOT,
            env=_environment(),
            text=True,
            capture_output=True,
            timeout=12,
            check=False,
        )
        assert sender.returncode == 0, sender.stderr
        stdout, stderr = receiver.communicate(timeout=5)
        assert receiver.returncode == 0, stderr
        assert text in startup + stdout
    finally:
        _stop(receiver)
        reader.join(timeout=2)


def test_baseline_is_lab_labeled_and_not_a_secure_runtime_toggle():
    baseline_help = subprocess.run(
        [sys.executable, str(SCRIPT), "--help"],
        cwd=PROJECT_ROOT,
        env=_environment(),
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert baseline_help.returncode == 0, baseline_help.stderr
    assert "LAB ONLY: plaintext baseline" in baseline_help.stdout

    secure_help = subprocess.run(
        [sys.executable, "-m", "sparc", "--help"],
        cwd=PROJECT_ROOT,
        env=_environment(),
        text=True,
        capture_output=True,
        timeout=10,
        check=False,
    )
    assert secure_help.returncode == 0, secure_help.stderr
    assert "baseline" not in secure_help.stdout.lower()
    assert "plaintext" not in secure_help.stdout.lower()


@pytest.mark.parametrize(
    "command",
    [
        ["send", "--ip", "not-an-ip", "--port", "47656", "--text", "hello"],
        ["listen", "--ip", "not-an-ip", "--port", "47656"],
        ["send", "--ip", IP, "--port", "0", "--text", "hello"],
        ["listen", "--ip", IP, "--port", "65536"],
        ["send", "--ip", IP, "--port", "47656", "--text", "é" * (MAX_TEXT_BYTES // 2 + 1)],
    ],
)
def test_invalid_endpoint_and_oversized_utf8_text_are_rejected_locally(command):
    result = subprocess.run(
        [sys.executable, str(SCRIPT), *command],
        cwd=PROJECT_ROOT,
        env=_environment(),
        text=True,
        capture_output=True,
        timeout=5,
        check=False,
    )
    assert result.returncode != 0
    assert "Traceback" not in result.stderr
