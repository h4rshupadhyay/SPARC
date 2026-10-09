"""Explicit hidden terminal credential adapter for identity workflows."""

from __future__ import annotations

import getpass
import os
import warnings

from .identity_codec import IdentityCredentials, IdentityUnlockRequest
from .models import SparcError


def _require_controlling_terminal() -> None:
    """Fail closed unless hidden input can use a real controlling console."""
    if os.name == "posix":
        try:
            descriptor = os.open("/dev/tty", os.O_RDWR)
        except OSError as error:
            raise SparcError(
                "identity_credentials_required",
                "Identity credentials require a controlling terminal",
            ) from error
        try:
            if not os.isatty(descriptor):
                raise SparcError(
                    "identity_credentials_required",
                    "Identity credentials require a controlling terminal",
                )
        finally:
            os.close(descriptor)
        return

    if os.name == "nt":
        try:
            import ctypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.GetStdHandle.argtypes = [ctypes.c_ulong]
            kernel32.GetStdHandle.restype = ctypes.c_void_p
            kernel32.GetConsoleMode.argtypes = [
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_ulong),
            ]
            kernel32.GetConsoleMode.restype = ctypes.c_int
            handle = kernel32.GetStdHandle(-10)  # STD_INPUT_HANDLE
            mode = ctypes.c_ulong()
            if not handle or not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                raise OSError("no usable console input handle")
        except (AttributeError, OSError) as error:
            raise SparcError(
                "identity_credentials_required",
                "Identity credentials require an interactive console",
            ) from error
        return

    raise SparcError(
        "identity_credentials_required",
        "Identity credentials require an interactive terminal",
    )


def _prompt_hidden(prompt: str) -> str:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass(prompt)
    except getpass.GetPassWarning as error:
        raise SparcError(
            "identity_credentials_required",
            "Hidden identity input is unavailable on this terminal",
        ) from error


def _encode_passphrase(value: str, *, creating: bool) -> bytes:
    if type(value) is not str:
        raise SparcError("identity_credentials_invalid", "Identity credentials are invalid")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise SparcError("identity_credentials_invalid", "Identity credentials are invalid") from error
    if creating:
        if len(value) < 15 or not 15 <= len(encoded) <= 1024:
            raise SparcError("identity_credentials_invalid", "Identity credentials are invalid")
    elif not 1 <= len(encoded) <= 1024:
        raise SparcError("identity_credentials_invalid", "Identity credentials are invalid")
    return encoded


def console_credentials(
    request: IdentityUnlockRequest,
) -> IdentityCredentials | None:
    """Read hidden credentials from a controlling terminal, or return cancellation."""
    if type(request) is not IdentityUnlockRequest:
        raise SparcError("identity_credentials_invalid", "Identity credential request is invalid")
    if request.purpose not in {"create", "migrate", "unlock"}:
        raise SparcError("identity_credentials_invalid", "Identity credential request is invalid")
    _require_controlling_terminal()

    creating = request.purpose in {"create", "migrate"}
    action = {
        "create": "Create",
        "migrate": "Encrypt existing",
        "unlock": "Unlock",
    }[request.purpose]
    try:
        strength_guidance = (
            " (use a long, unique phrase to resist offline guessing; length alone cannot guarantee strength)"
            if creating
            else ""
        )
        passphrase_text = _prompt_hidden(
            f"{action} SPARC identity passphrase{strength_guidance}: "
        )
        passphrase = _encode_passphrase(passphrase_text, creating=creating)
        confirmation = None
        if creating:
            confirmation_text = _prompt_hidden("Confirm SPARC identity passphrase: ")
            confirmation = _encode_passphrase(confirmation_text, creating=True)
            if confirmation != passphrase:
                raise SparcError(
                    "identity_credentials_invalid",
                    "Identity passphrase entries do not match",
                )
    except (EOFError, KeyboardInterrupt):
        return None
    return IdentityCredentials(passphrase, confirmation)
