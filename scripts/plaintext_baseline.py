"""Standalone lab-only plaintext baseline for synthetic local comparisons."""

from __future__ import annotations

import argparse
import ipaddress
import socket
import struct
import sys
import time


MAX_TEXT_BYTES = 16 * 1024
SOCKET_DEADLINE_SECONDS = 10.0
LAB_LABEL = "LAB ONLY: plaintext baseline"


class BaselineError(Exception):
    """A user-facing validation, framing, or network error."""


def _ipv4(value: str) -> str:
    try:
        address = ipaddress.IPv4Address(value)
    except ipaddress.AddressValueError as exc:
        raise argparse.ArgumentTypeError("IP must be a canonical IPv4 address") from exc
    if str(address) != value:
        raise argparse.ArgumentTypeError("IP must be a canonical IPv4 address")
    return value


def _port(value: str) -> int:
    try:
        port = int(value, 10)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer from 1 through 65535") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be an integer from 1 through 65535")
    return port


def _payload(text: str) -> bytes:
    try:
        payload = text.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise BaselineError("text must be valid UTF-8") from exc
    if len(payload) > MAX_TEXT_BYTES:
        raise BaselineError(f"UTF-8 text must be at most {MAX_TEXT_BYTES} bytes")
    return payload


def _recv_exact(connection: socket.socket, size: int, deadline: float) -> bytes:
    data = bytearray()
    while len(data) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise BaselineError("timed out receiving plaintext frame")
        connection.settimeout(remaining)
        try:
            chunk = connection.recv(size - len(data))
        except socket.timeout as exc:
            raise BaselineError("timed out receiving plaintext frame") from exc
        if not chunk:
            raise BaselineError("connection closed before the plaintext frame was complete")
        data.extend(chunk)
    return bytes(data)


def _listen(ip: str, port: int) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.settimeout(SOCKET_DEADLINE_SECONDS)
        listener.bind((ip, port))
        listener.listen(1)
        print(f"{LAB_LABEL} — Listening on {ip}:{port}", flush=True)
        try:
            connection, _peer = listener.accept()
        except socket.timeout as exc:
            raise BaselineError("timed out waiting for a sender") from exc

        with connection:
            deadline = time.monotonic() + SOCKET_DEADLINE_SECONDS
            header = _recv_exact(connection, 4, deadline)
            size = struct.unpack("!I", header)[0]
            if size > MAX_TEXT_BYTES:
                raise BaselineError(f"received text exceeds {MAX_TEXT_BYTES} UTF-8 bytes")
            payload = _recv_exact(connection, size, deadline)
        try:
            text = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise BaselineError("received plaintext is not valid UTF-8") from exc
        print(f"{LAB_LABEL} — Received: {text}", flush=True)
    return 0


def _send(ip: str, port: int, payload: bytes) -> int:
    frame = struct.pack("!I", len(payload)) + payload
    try:
        with socket.create_connection((ip, port), timeout=SOCKET_DEADLINE_SECONDS) as connection:
            connection.settimeout(SOCKET_DEADLINE_SECONDS)
            connection.sendall(frame)
    except socket.timeout as exc:
        raise BaselineError("timed out sending plaintext frame") from exc
    print(f"{LAB_LABEL} — Sent {len(payload)} UTF-8 bytes to {ip}:{port}", flush=True)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=LAB_LABEL,
        epilog="For synthetic lab comparisons only. This tool sends plaintext over TCP.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    listen_parser = commands.add_parser("listen", help="receive one lab plaintext message")
    listen_parser.add_argument("--ip", required=True, type=_ipv4)
    listen_parser.add_argument("--port", required=True, type=_port)

    send_parser = commands.add_parser("send", help="send one lab plaintext message")
    send_parser.add_argument("--ip", required=True, type=_ipv4)
    send_parser.add_argument("--port", required=True, type=_port)
    send_parser.add_argument("--text", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "listen":
            return _listen(args.ip, args.port)
        return _send(args.ip, args.port, _payload(args.text))
    except (BaselineError, OSError) as exc:
        print(f"{LAB_LABEL} error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(f"\n{LAB_LABEL} cancelled", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
