"""F1b native Windows ACL, reparse-point and replacement checks."""

from __future__ import annotations

import hashlib
import ctypes
import importlib
import os
from pathlib import Path
import secrets
import stat
import sys
from types import SimpleNamespace

import pytest


def test_windows_native_layout_and_acl_size_are_platform_independent():
    """Native layout declarations stay checkable without invoking Win32 APIs."""
    try:
        adapter = importlib.import_module("sparc._windows_identity_storage")
    except ModuleNotFoundError as error:
        if error.name == "msvcrt":
            pytest.fail("Windows layout helpers must be importable without Windows runtime")
        raise

    info_type = getattr(adapter, "_BY_HANDLE_FILE_INFORMATION", None)
    assert info_type is not None, "Windows file information must use a typed native structure"
    assert ctypes.sizeof(info_type) == 52
    expected_offsets = {
        "dwFileAttributes": 0,
        "ftCreationTime": 4,
        "ftLastAccessTime": 12,
        "ftLastWriteTime": 20,
        "dwVolumeSerialNumber": 28,
        "nFileSizeHigh": 32,
        "nFileSizeLow": 36,
        "nNumberOfLinks": 40,
        "nFileIndexHigh": 44,
        "nFileIndexLow": 48,
    }
    assert {
        name: getattr(info_type, name).offset for name in expected_offsets
    } == expected_offsets

    acl_limit = getattr(adapter, "_MAX_ACL_BYTES", None)
    assert isinstance(acl_limit, int) and 0 < acl_limit <= 65535


def test_windows_temporary_cleanup_does_not_remove_substituted_path(tmp_path, monkeypatch):
    """The temporary cleanup boundary is testable without invoking Win32."""
    _storage, adapter = _windows_storage()
    substituted_paths = []

    def replace_temp_name_then_fail(_descriptor, path):
        path = Path(path)
        path.unlink()
        path.write_bytes(b"pre-existing replacement")
        substituted_paths.append(path)
        raise OSError("injected private ACL failure")

    monkeypatch.setattr(adapter, "_initialize_private_file_descriptor", replace_temp_name_then_fail)
    with pytest.raises(OSError):
        adapter.write_encrypted_temporary(tmp_path, "identity.json", b"encrypted candidate")
    assert len(substituted_paths) == 1
    assert substituted_paths[0].read_bytes() == b"pre-existing replacement"


def test_windows_lock_closes_stream_when_unlock_fails(tmp_path, monkeypatch):
    """Exercise cleanup control flow with a fake lock shim, not fake Win32 calls."""
    _storage, adapter = _windows_storage()
    lock_path = tmp_path / ".identity.lock"
    lock_path.write_bytes(b"\0")

    class Stream:
        closed = False

        def seek(self, *_args):
            return 1

        def fileno(self):
            return 9

        def close(self):
            self.closed = True

    stream = Stream()
    calls = []

    def locking(_fd, operation, _length):
        calls.append(operation)
        if operation == 2:
            raise OSError("injected unlock failure")

    shim = SimpleNamespace(LK_NBLCK=1, LK_UNLCK=2, locking=locking)
    monkeypatch.setitem(sys.modules, "msvcrt", shim)
    monkeypatch.setattr(adapter, "secure_identity_file", lambda _path, **_kwargs: None)
    monkeypatch.setattr(adapter, "open_regular_file", lambda _path, writable=False: stream)
    with pytest.raises(OSError, match="unlock failure"):
        with adapter.identity_file_lock(lock_path):
            pass
    assert calls == [shim.LK_NBLCK, shim.LK_UNLCK]
    assert stream.closed


def test_private_acl_policy_preserves_absent_zero_and_narrow_grants():
    """ACL policy must never invent rights when the existing ACL grants less."""
    try:
        adapter = importlib.import_module("sparc._windows_identity_storage")
    except ModuleNotFoundError as error:
        if error.name == "sparc._windows_identity_storage":
            pytest.fail("the Windows identity ACL policy API must be implemented")
        raise
    policy = getattr(adapter, "_private_acl_grants", None)
    assert callable(policy), "Windows storage must expose its testable ACL grant policy"

    user, system, unrelated = "S-user", "S-1-5-18", "S-everyone"
    assert policy({}, user, system) == {}
    assert policy({user: 0}, user, system) == {user: 0}
    assert policy({user: 0x00120089}, user, system) == {user: 0x00120089}
    assert policy({system: 0x00120089, unrelated: 0x001F01FF}, user, system) == {
        system: 0x00120089
    }


def test_native_directory_binding_api_is_exposed_without_platform_calls():
    try:
        adapter = importlib.import_module("sparc._windows_identity_storage")
    except ModuleNotFoundError as error:
        if error.name == "sparc._windows_identity_storage":
            pytest.fail("the Windows directory binding API must be implemented")
        raise
    assert callable(getattr(adapter, "open_directory_chain", None)), (
        "Windows storage must retain checked component handles through private operations"
    )


def test_new_private_acl_api_accepts_the_live_creation_descriptor():
    try:
        adapter = importlib.import_module("sparc._windows_identity_storage")
    except ModuleNotFoundError as error:
        if error.name == "sparc._windows_identity_storage":
            pytest.fail("the Windows handle-based initial ACL API must be implemented")
        raise
    assert callable(getattr(adapter, "_initialize_private_file_descriptor", None)), (
        "new-object ACL initialization must consume the still-open creation descriptor"
    )


def test_temporary_initial_acl_cannot_widen_a_substituted_file(tmp_path, monkeypatch):
    _storage, adapter = _windows_storage()
    initializer = getattr(adapter, "_initialize_private_file_descriptor", None)
    assert callable(initializer), "new-object ACL initialization must consume a live descriptor"
    created = {}
    real_mkstemp = adapter.tempfile.mkstemp

    def capture_temp(*args, **kwargs):
        descriptor, name = real_mkstemp(*args, **kwargs)
        created.update(descriptor=descriptor, path=Path(name))
        return descriptor, name

    def substitute_during_initial_acl(descriptor, path):
        assert descriptor == created["descriptor"]
        original = os.fstat(descriptor)
        assert Path(path) == created["path"]
        path = Path(path)
        path.unlink()
        path.write_bytes(b"pre-existing file protection must remain unchanged")
        os.chmod(path, 0o640)
        replacement = path.stat()
        assert (original.st_dev, original.st_ino) != (replacement.st_dev, replacement.st_ino)

    monkeypatch.setattr(adapter.tempfile, "mkstemp", capture_temp)
    monkeypatch.setattr(adapter, "_initialize_private_file_descriptor", substitute_during_initial_acl)
    monkeypatch.setattr(
        adapter, "secure_identity_file",
        lambda *_args, **_kwargs: pytest.fail("new-object ACL must not reopen a pathname"),
    )
    from sparc.models import SparcError

    with pytest.raises(SparcError) as error:
        adapter.write_encrypted_temporary(tmp_path, "identity.json", b"ciphertext candidate")
    assert error.value.code == "data_permissions_failed"
    replacement = created["path"]
    assert replacement.read_bytes() == b"pre-existing file protection must remain unchanged"
    assert stat.S_IMODE(replacement.stat().st_mode) == 0o640
    assert list(tmp_path.iterdir()) == [replacement]


def test_new_lock_initial_acl_cannot_widen_a_substituted_file(tmp_path, monkeypatch):
    _storage, adapter = _windows_storage()
    initializer = getattr(adapter, "_initialize_private_file_descriptor", None)
    assert callable(initializer), "new-object ACL initialization must consume a live descriptor"
    import sys

    lock_path = tmp_path / ".identity.lock"
    created = {}
    real_open = os.open

    def capture_create(file, flags, *args, **kwargs):
        descriptor = real_open(file, flags, *args, **kwargs)
        if Path(file) == lock_path and flags & os.O_CREAT:
            created["descriptor"] = descriptor
            created["path"] = lock_path
        return descriptor

    def substitute_during_initial_acl(descriptor, path):
        assert descriptor == created["descriptor"]
        assert Path(path) == lock_path
        original = os.fstat(descriptor)
        lock_path.unlink()
        lock_path.write_bytes(b"replacement lock content")
        os.chmod(lock_path, 0o640)
        replacement = lock_path.stat()
        assert (original.st_dev, original.st_ino) != (replacement.st_dev, replacement.st_ino)

    shim = __import__("types").SimpleNamespace(LK_NBLCK=1, LK_UNLCK=2, locking=lambda *_args: None)
    monkeypatch.setitem(sys.modules, "msvcrt", shim)
    monkeypatch.setattr(os, "open", capture_create)
    monkeypatch.setattr(adapter, "_initialize_private_file_descriptor", substitute_during_initial_acl)
    monkeypatch.setattr(
        adapter, "secure_identity_file",
        lambda *_args, **_kwargs: pytest.fail("new lock ACL must not reopen a pathname"),
    )
    monkeypatch.setattr(
        adapter, "open_regular_file",
        lambda *_args, **_kwargs: pytest.fail("substituted lock must be rejected before opening"),
    )
    from sparc.models import SparcError

    with pytest.raises(SparcError) as error:
        with adapter.identity_file_lock(lock_path):
            pytest.fail("substituted lock must not be acquired")
    assert error.value.code == "data_permissions_failed"
    assert lock_path.read_bytes() == b"replacement lock content"
    assert stat.S_IMODE(lock_path.stat().st_mode) == 0o640


def _windows_storage():
    from importlib import import_module

    try:
        storage = import_module("sparc.identity_storage")
        adapter = import_module("sparc._windows_identity_storage")
    except ModuleNotFoundError as error:
        if error.name not in {
            "sparc.identity_storage",
            "sparc._windows_identity_storage",
        }:
            raise
        pytest.fail("the F1b Windows identity storage API must be implemented")
    for module, names in (
        (storage, ("publish_identity",)),
        (adapter, ("prepare_private_directory", "open_regular_file")),
    ):
        missing = [name for name in names if not callable(getattr(module, name, None))]
        assert not missing, f"Windows identity storage is missing its API: {missing}"
    return storage, adapter


def _candidate():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from sparc.identity_codec import encode_identity
    from sparc.models import Identity

    private = Ed25519PrivateKey.generate()
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    identity = Identity(private, public, hashlib.sha256(public).hexdigest())
    return encode_identity(identity, secrets.token_hex(32).encode("ascii"))


def _current_user_sid():
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.OpenProcessToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)
    ]
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    token = wintypes.HANDLE()
    current_process = kernel32.GetCurrentProcess()
    if not advapi32.OpenProcessToken(current_process, 0x0008, ctypes.byref(token)):
        raise OSError(ctypes.get_last_error(), "OpenProcessToken failed")
    try:
        needed = wintypes.DWORD()
        advapi32.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        token_user = ctypes.create_string_buffer(needed.value)
        if not advapi32.GetTokenInformation(
            token, 1, token_user, needed, ctypes.byref(needed)
        ):
            raise OSError(ctypes.get_last_error(), "GetTokenInformation failed")
        sid = ctypes.cast(token_user, ctypes.POINTER(ctypes.c_void_p))[0]
        sid_text = wintypes.LPWSTR()
        if not advapi32.ConvertSidToStringSidW(sid, ctypes.byref(sid_text)):
            raise OSError(ctypes.get_last_error(), "ConvertSidToStringSidW failed")
        try:
            return sid_text.value
        finally:
            kernel32.LocalFree(sid_text)
    finally:
        kernel32.CloseHandle(token)


def _native_dacl(path: Path):
    """Return DACL protection plus (allow/deny, SID text) ACEs."""
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi32.GetSecurityDescriptorControl.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.WORD), ctypes.POINTER(wintypes.DWORD)
    ]
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.GetAclInformation.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_int
    ]
    advapi32.GetAclInformation.restype = wintypes.BOOL
    advapi32.GetAce.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)
    ]
    advapi32.GetAce.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)
    ]
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    owner = ctypes.c_void_p()
    group = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    result = advapi32.GetNamedSecurityInfoW(
        str(path),
        1,  # SE_FILE_OBJECT
        0x00000004,  # DACL_SECURITY_INFORMATION
        ctypes.byref(owner),
        ctypes.byref(group),
        ctypes.byref(dacl),
        None,
        ctypes.byref(descriptor),
    )
    if result:
        raise OSError(result, "GetNamedSecurityInfoW failed")
    try:
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not advapi32.GetSecurityDescriptorControl(
            descriptor, ctypes.byref(control), ctypes.byref(revision)
        ):
            raise OSError(ctypes.get_last_error(), "GetSecurityDescriptorControl failed")
        present = wintypes.BOOL()
        defaulted = wintypes.BOOL()
        dacl_pointer = ctypes.c_void_p()
        if not advapi32.GetSecurityDescriptorDacl(
            descriptor,
            ctypes.byref(present),
            ctypes.byref(dacl_pointer),
            ctypes.byref(defaulted),
        ):
            raise OSError(ctypes.get_last_error(), "GetSecurityDescriptorDacl failed")
        assert present.value and dacl_pointer.value, f"{path} has a NULL/missing DACL"

        class ACL_SIZE_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("AceCount", wintypes.DWORD),
                ("AclBytesInUse", wintypes.DWORD),
                ("AclBytesFree", wintypes.DWORD),
            ]

        info = ACL_SIZE_INFORMATION()
        if not advapi32.GetAclInformation(
            dacl_pointer, ctypes.byref(info), ctypes.sizeof(info), 2
        ):
            raise OSError(ctypes.get_last_error(), "GetAclInformation failed")
        aces = []
        for index in range(info.AceCount):
            ace_pointer = ctypes.c_void_p()
            if not advapi32.GetAce(dacl_pointer, index, ctypes.byref(ace_pointer)):
                raise OSError(ctypes.get_last_error(), "GetAce failed")
            ace_type = ctypes.cast(ace_pointer, ctypes.POINTER(ctypes.c_ubyte))[0]
            if ace_type not in (0, 1):  # ACCESS_ALLOWED_ACE / ACCESS_DENIED_ACE
                continue
            sid_pointer = ctypes.c_void_p(ace_pointer.value + 8)  # header + access mask
            sid_text = wintypes.LPWSTR()
            if not advapi32.ConvertSidToStringSidW(
                sid_pointer, ctypes.byref(sid_text)
            ):
                raise OSError(ctypes.get_last_error(), "ACE SID conversion failed")
            try:
                mask = int.from_bytes(ctypes.string_at(ace_pointer.value + 4, 4), "little")
                aces.append(("allow" if ace_type == 0 else "deny", sid_text.value, mask))
            finally:
                kernel32.LocalFree(sid_text)
        return bool(control.value & 0x1000), aces  # SE_DACL_PROTECTED
    finally:
        kernel32.LocalFree(descriptor)


def _set_native_dacl_sddl(path: Path, sddl: str):
    import ctypes
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL
    advapi.GetSecurityDescriptorDacl.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    advapi.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ]
    advapi.SetNamedSecurityInfoW.restype = wintypes.DWORD
    descriptor = ctypes.c_void_p()
    if not advapi.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None
    ):
        raise OSError(ctypes.get_last_error(), "could not build restricted test ACL")
    try:
        present = wintypes.BOOL()
        defaulted = wintypes.BOOL()
        dacl = ctypes.c_void_p()
        if not advapi.GetSecurityDescriptorDacl(
            descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
        ):
            raise OSError(ctypes.get_last_error(), "could not inspect restricted test ACL")
        if not present.value or not dacl.value:
            raise AssertionError("test fixture must have a non-NULL DACL")
        result = advapi.SetNamedSecurityInfoW(
            str(path), 1, 0x00000004 | 0x80000000,
            None, None, dacl, None,
        )
        if result:
            raise OSError(result, "could not apply restricted test ACL")
    finally:
        kernel.LocalFree(descriptor)


@pytest.mark.skipif(os.name != "nt", reason="requires real Windows file and ACL semantics")
def test_windows_private_acl_and_reparse_rejection(tmp_path):
    storage, adapter = _windows_storage()
    directory = tmp_path / "sparc-private"
    directory.mkdir()
    _unprotected, initial_aces = _native_dacl(directory)
    initial_denies = {sid for kind, sid, _mask in initial_aces if kind == "deny"}
    adapter.prepare_private_directory(directory)
    path = directory / "identity.json"
    first = _candidate()
    second = _candidate()
    storage.publish_identity(path, expected=None, candidate=first)

    current_user = _current_user_sid()
    allowed_sids = {current_user, "S-1-5-18"}  # current user and LocalSystem only
    for secured in (directory, path, directory / ".identity.lock"):
        protected, aces = _native_dacl(secured)
        assert protected, f"{secured} DACL is not protected from inheritance"
        allow_sids = {sid for kind, sid, _mask in aces if kind == "allow"}
        assert allow_sids, f"{secured} has no usable allow ACE"
        assert allow_sids <= allowed_sids, f"unexpected group grant on {secured}: {allow_sids}"
        if secured == directory:
            deny_sids = {sid for kind, sid, _mask in aces if kind == "deny"}
            assert initial_denies <= deny_sids, "private ACL discarded an existing denial"

    held = adapter.open_regular_file(path)
    try:
        assert held.read() == first
        storage.publish_identity(path, expected=first, candidate=second)
        assert path.read_bytes() == second
        held.seek(0)
        assert held.read() == first
    finally:
        held.close()



@pytest.mark.skipif(os.name != "nt", reason="requires real Windows reparse-point semantics")
def test_windows_reparse_point_rejected(tmp_path):
    _storage, adapter = _windows_storage()
    target = tmp_path / "target.json"
    target.write_bytes(b"target remains unchanged")
    before = target.read_bytes()
    link = tmp_path / "identity-link.json"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"Windows symlink privilege is unavailable: {error}")
    from sparc.models import SparcError

    with pytest.raises(SparcError):
        adapter.open_regular_file(link)
    assert target.read_bytes() == before


@pytest.mark.skipif(os.name != "nt", reason="requires real Windows DACL semantics")
def test_windows_acl_does_not_add_missing_system_grant(tmp_path):
    _storage, adapter = _windows_storage()
    path = tmp_path / "restricted.json"
    path.write_bytes(b"ciphertext")
    sid = _current_user_sid()
    _set_native_dacl_sddl(path, f"D:P(A;;GR;;;{sid})")
    before_bytes = path.read_bytes()
    before_protected, before_aces = _native_dacl(path)

    adapter.secure_identity_file(path)
    protected, aces = _native_dacl(path)
    allow_masks = {principal: mask for kind, principal, mask in aces if kind == "allow"}
    assert protected and before_protected
    assert allow_masks == {sid: 0x80000000}
    assert path.read_bytes() == before_bytes
    assert [(kind, principal, mask) for kind, principal, mask in aces] == before_aces


@pytest.mark.skipif(os.name != "nt", reason="requires real Windows DACL semantics")
@pytest.mark.parametrize(
    "sddl",
    [
        "D:P(A;;GA;;;SY)",  # no current-user allow
        "D:P(A;;0x00000000;;;{user})",  # explicit zero current-user grant
        "D:P(D;;GA;;;WD)",  # deny-only protected DACL
    ],
)
def test_windows_unusable_restricted_acl_fails_without_widening(tmp_path, sddl):
    _storage, adapter = _windows_storage()
    from sparc.models import SparcError

    path = tmp_path / "unusable-restricted.json"
    payload = b"ciphertext remains unchanged"
    path.write_bytes(payload)
    expanded_sddl = sddl.format(user=_current_user_sid())
    _set_native_dacl_sddl(path, expanded_sddl)
    before_acl = _native_dacl(path)
    before_bytes = path.read_bytes()
    with pytest.raises(SparcError) as error:
        adapter.secure_identity_file(path)
    assert error.value.code == "data_permissions_failed"
    assert _native_dacl(path) == before_acl
    assert path.read_bytes() == before_bytes


@pytest.mark.skipif(os.name != "nt", reason="requires real Windows DACL semantics")
def test_windows_denials_and_read_only_mask_survive_acl_tightening(tmp_path):
    _storage, adapter = _windows_storage()
    path = tmp_path / "denied-read-only.json"
    path.write_bytes(b"ciphertext")
    sid = _current_user_sid()
    _set_native_dacl_sddl(path, f"D:P(D;;GW;;;WD)(A;;GR;;;{sid})")
    before_bytes = path.read_bytes()
    adapter.secure_identity_file(path)
    protected, aces = _native_dacl(path)
    assert protected
    assert {principal: mask for kind, principal, mask in aces if kind == "allow"} == {
        sid: 0x80000000
    }
    assert ("deny", "S-1-1-0", 0x40000000) in aces
    assert path.read_bytes() == before_bytes


@pytest.mark.skipif(os.name != "nt", reason="requires real Windows DACL semantics")
def test_windows_new_temp_is_secured_before_ciphertext_write(tmp_path, monkeypatch):
    _storage, adapter = _windows_storage()
    real_initialize = adapter._initialize_private_file_descriptor
    observations = []

    def initialize_and_inspect_empty(descriptor, path):
        real_initialize(descriptor, path)
        path = Path(path)
        assert path.stat().st_size == 0
        protected, aces = _native_dacl(path)
        assert protected
        allow_sids = {sid for kind, sid, _mask in aces if kind == "allow"}
        assert allow_sids and allow_sids <= {_current_user_sid(), "S-1-5-18"}
        observations.append(path)

    monkeypatch.setattr(adapter, "_initialize_private_file_descriptor", initialize_and_inspect_empty)
    payload = b'{"version":2,"ciphertext":"only"}'
    path = adapter.write_encrypted_temporary(tmp_path, "identity.json", payload)
    assert observations == [path]
    assert path.read_bytes() == payload


@pytest.mark.skipif(os.name != "nt", reason="requires real Windows directory handle semantics")
def test_windows_component_handles_prevent_directory_rename(tmp_path):
    _storage, adapter = _windows_storage()
    root = tmp_path / "sparc"
    root.mkdir()
    adapter.prepare_private_directory(root)
    moved = tmp_path / "sparc-moved"
    with adapter.open_directory_chain(root):
        with pytest.raises(OSError):
            root.rename(moved)
    assert root.is_dir()
    assert not moved.exists()
