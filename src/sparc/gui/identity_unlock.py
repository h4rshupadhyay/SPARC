"""Responsive, masked Tk credential collection for local identity startup."""

from __future__ import annotations

import queue
import threading
import tkinter as tk
from tkinter import ttk
from pathlib import Path

from ..identity import _unlock_store
from ..identity_codec import IdentityCredentials, IdentityInfo, IdentityUnlockRequest
from ..models import SparcError


_POLL_MS = 50
_ERROR_TEXT = {
    "identity_unlock_failed": "Could not unlock the identity. Check the passphrase and retry.",
    "identity_credentials_invalid": "The passphrase entries are invalid or do not match.",
    "identity_crypto_unavailable": "The required identity encryption support is unavailable.",
    "identity_changed": "The identity changed while it was being unlocked. Cancel and reopen SPARC.",
    "identity_busy": "Identity storage is busy. Please retry.",
}


def _purpose(info: IdentityInfo) -> str:
    if info.status == "absent":
        return "create"
    if info.status == "legacy_unencrypted":
        return "migrate"
    return "unlock"


def _safe_error(code: str) -> str:
    return _ERROR_TEXT.get(code, f"Identity could not be opened ({code}).")


def unlock_identity_for_gui(root: tk.Misc, data_dir: Path):
    """Prompt on the Tk thread and return an opaque unlocked-store handle."""
    from ..identity import inspect_identity

    directory = Path(data_dir)
    info = inspect_identity(directory)
    purpose = _purpose(info)
    creating = purpose in {"create", "migrate"}
    cancellation = threading.Event()
    ui_queue: queue.Queue[str] = queue.Queue()
    result_lock = threading.Lock()
    result_slot: dict[str, object] = {}
    state: dict[str, object] = {
        "worker": None,
        "after_id": None,
        "cancel_requested": False,
        "terminal_code": None,
        "terminal": False,
        "outcome": None,
    }
    active_credentials: dict[str, bytes] = {}

    dialog = tk.Toplevel(root)
    dialog.title("Unlock SPARC identity")
    if root.winfo_viewable():
        dialog.transient(root)
    dialog.resizable(False, False)
    dialog.protocol("WM_DELETE_WINDOW", lambda: request_cancel())
    dialog.bind("<Escape>", lambda _event: request_cancel())

    body = ttk.Frame(dialog, padding=16)
    body.grid(row=0, column=0, sticky="nsew")
    body.columnconfigure(0, weight=1)
    if purpose == "create":
        heading = "Create an encrypted SPARC identity"
        passphrase_label = "New passphrase (15 or more characters)"
        submit_label = "Create identity"
    elif purpose == "migrate":
        heading = "Encrypt the existing SPARC identity"
        passphrase_label = "New passphrase (15 or more characters)"
        submit_label = "Encrypt identity"
    else:
        heading = "Unlock the SPARC identity"
        passphrase_label = "Passphrase"
        submit_label = "Unlock identity"
    ttk.Label(body, text=heading).grid(row=0, column=0, sticky="w", pady=(0, 8))
    if creating:
        ttk.Label(
            body,
            text=(
                "Use a long, unique phrase to resist offline guessing; the length minimum "
                "alone cannot guarantee strength."
            ),
            wraplength=440,
        ).grid(row=1, column=0, sticky="w", pady=(0, 6))
    if info.fingerprint is not None:
        ttk.Label(body, text=f"Unverified fingerprint: {info.fingerprint}").grid(
            row=2, column=0, sticky="w", pady=(0, 6)
        )
    if purpose == "migrate":
        ttk.Label(
            body,
            text="Migration encryption preserves the existing identity key and fingerprint.",
            wraplength=440,
        ).grid(row=3, column=0, sticky="w", pady=(0, 8))

    field_row = 4 if creating else 3
    ttk.Label(body, text=passphrase_label).grid(
        row=field_row, column=0, sticky="w", pady=(4, 2)
    )
    passphrase_entry = ttk.Entry(body, show="•", width=48)
    passphrase_entry.grid(row=field_row + 1, column=0, sticky="ew")
    entries = [passphrase_entry]
    if creating:
        ttk.Label(body, text="Confirm passphrase").grid(
            row=field_row + 2, column=0, sticky="w", pady=(8, 2)
        )
        confirmation_entry = ttk.Entry(body, show="•", width=48)
        confirmation_entry.grid(row=field_row + 3, column=0, sticky="ew")
        entries.append(confirmation_entry)

    status_row = field_row + (4 if creating else 2)
    status = tk.StringVar(master=dialog, value="")
    ttk.Label(body, textvariable=status, wraplength=440).grid(
        row=status_row, column=0, sticky="w", pady=(8, 4)
    )
    button_row = status_row + 1
    buttons = ttk.Frame(body)
    buttons.grid(row=button_row, column=0, sticky="e", pady=(8, 0))
    submit = ttk.Button(buttons, text=submit_label)
    submit.grid(row=0, column=0, padx=(0, 8))
    cancel_button = ttk.Button(buttons, text="Cancel")
    cancel_button.grid(row=0, column=1)

    def clear_fields() -> None:
        for entry in entries:
            try:
                entry.delete(0, tk.END)
            except tk.TclError:
                pass
        active_credentials.clear()

    def cancel_poll() -> None:
        after_id = state.get("after_id")
        state["after_id"] = None
        if after_id is not None:
            try:
                dialog.after_cancel(after_id)
            except tk.TclError:
                pass

    def close_dialog(code: str) -> None:
        if state["terminal"]:
            return
        state["terminal"] = True
        state["terminal_code"] = code
        cancel_poll()
        clear_fields()
        try:
            if dialog.grab_current() is dialog:
                dialog.grab_release()
        except tk.TclError:
            pass
        try:
            dialog.destroy()
        except tk.TclError:
            pass

    def request_cancel() -> None:
        if state["terminal"]:
            return
        state["cancel_requested"] = True
        cancellation.set()
        cancel_button.configure(state=tk.DISABLED)
        submit.configure(state=tk.DISABLED)
        clear_fields()
        status.set("Canceling identity operation…")
        if state["worker"] is None:
            close_dialog("identity_unlock_cancelled")

    def poll_worker() -> None:
        state["after_id"] = None
        if state["terminal"]:
            return
        outcome = None
        try:
            state["outcome"] = ui_queue.get_nowait()
        except queue.Empty:
            pass
        outcome = state["outcome"]
        worker = state["worker"]
        if worker is not None and worker.is_alive():
            state["after_id"] = dialog.after(_POLL_MS, poll_worker)
            return
        if worker is not None:
            worker.join()
            state["worker"] = None
        if outcome == "success":
            state["outcome"] = None
            with result_lock:
                handle = result_slot.get("handle")
            if state["cancel_requested"]:
                with result_lock:
                    result_slot.pop("handle", None)
                close_dialog("identity_unlock_cancelled")
            elif handle is None:
                close_dialog("identity_unlock_failed")
            else:
                close_dialog("success")
            return
        if outcome is not None:
            state["outcome"] = None
            if state["cancel_requested"] or outcome == "identity_unlock_cancelled":
                close_dialog("identity_unlock_cancelled")
                return
            clear_fields()
            status.set(_safe_error(outcome))
            submit.configure(text="Retry", state=tk.NORMAL)
            cancel_button.configure(state=tk.NORMAL)
            passphrase_entry.focus_set()
            return
        if state["cancel_requested"]:
            close_dialog("identity_unlock_cancelled")
            return
        state["after_id"] = dialog.after(_POLL_MS, poll_worker)

    def start_unlock() -> None:
        if state["terminal"] or state["worker"] is not None:
            return
        passphrase = passphrase_entry.get()
        confirmation = entries[1].get() if creating else None
        try:
            encoded = passphrase.encode("utf-8", errors="strict")
            confirmation_bytes = (
                confirmation.encode("utf-8", errors="strict")
                if confirmation is not None else None
            )
        except UnicodeEncodeError:
            status.set("Passphrase must contain valid Unicode text.")
            return
        if creating:
            if len(passphrase) < 15 or not 15 <= len(encoded) <= 1024:
                status.set("Use at least 15 characters and no more than 1024 UTF-8 bytes.")
                return
            if confirmation != passphrase:
                status.set("Passphrase entries do not match.")
                return
        elif not 1 <= len(encoded) <= 1024:
            status.set("Passphrase must contain between 1 and 1024 UTF-8 bytes.")
            return

        active_credentials.clear()
        active_credentials["passphrase"] = encoded
        if confirmation_bytes is not None:
            active_credentials["confirmation"] = confirmation_bytes
        submit.configure(state=tk.DISABLED)
        cancel_button.configure(state=tk.NORMAL)
        status.set("Unlocking identity…")

        expected_purpose = purpose

        def provider(request: IdentityUnlockRequest):
            if request.purpose != expected_purpose:
                raise SparcError("identity_changed", "Identity changed while credentials were entered")
            phrase = active_credentials.pop("passphrase", None)
            confirmation_value = active_credentials.pop("confirmation", None)
            if phrase is None:
                raise SparcError("identity_credentials_invalid", "Identity credentials are invalid")
            return IdentityCredentials(phrase, confirmation_value)

        def worker_main() -> None:
            try:
                handle = _unlock_store(
                    directory,
                    credential_provider=provider,
                    cancelled=cancellation.is_set,
                )
            except SparcError as error:
                ui_queue.put(error.code)
            except Exception:
                ui_queue.put("identity_unlock_failed")
            else:
                with result_lock:
                    result_slot["handle"] = handle
                ui_queue.put("success")

        try:
            worker = threading.Thread(target=worker_main, name="sparc-identity-unlock")
            state["worker"] = worker
            worker.start()
        except Exception:
            state["worker"] = None
            clear_fields()
            status.set("Identity unlock could not be started. Retry or cancel.")
            submit.configure(text="Retry", state=tk.NORMAL)
            return
        state["after_id"] = dialog.after(_POLL_MS, poll_worker)

    submit.configure(command=start_unlock)
    cancel_button.configure(command=request_cancel)

    prior_root_close = root.protocol("WM_DELETE_WINDOW")
    try:
        root.protocol("WM_DELETE_WINDOW", request_cancel)
        dialog.wait_visibility()
        passphrase_entry.focus_set()
        dialog.grab_set()
        root.wait_window(dialog)
    except tk.TclError:
        # The root or dialog may have been destroyed outside the normal WM
        # protocol. The worker still owns an operation that must reach a safe
        # cancellation boundary before startup can return.
        if state["terminal_code"] is None:
            state["terminal_code"] = "identity_unlock_cancelled"
    finally:
        successful = state["terminal_code"] == "success"
        if not successful:
            state["cancel_requested"] = True
            cancellation.set()
            if state["terminal_code"] is None:
                state["terminal_code"] = "identity_unlock_cancelled"
        cancel_poll()
        clear_fields()
        if not successful:
            with result_lock:
                result_slot.pop("handle", None)
        worker = state.get("worker")
        if worker is not None:
            worker.join()
            state["worker"] = None
        try:
            if root.winfo_exists():
                root.tk.call(
                    "wm", "protocol", root._w, "WM_DELETE_WINDOW", prior_root_close
                )
        except tk.TclError:
            pass
        try:
            if dialog.winfo_exists():
                if dialog.grab_current() is dialog:
                    dialog.grab_release()
                dialog.destroy()
        except tk.TclError:
            pass

    code = state["terminal_code"]
    if code == "success":
        with result_lock:
            handle = result_slot.pop("handle", None)
        if handle is None:
            raise SparcError("identity_unlock_failed", "Identity could not be opened")
        return handle
    if code == "identity_unlock_cancelled":
        raise SparcError("identity_unlock_cancelled", "Identity operation was canceled")
    raise SparcError("identity_unlock_failed", "Identity could not be opened")
