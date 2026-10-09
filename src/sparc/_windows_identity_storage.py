"""Narrow Win32 ACL, reparse-safe file and lock adapter for identity storage."""

from __future__ import annotations

from contextlib import contextmanager
import ctypes
import errno
import os
from pathlib import Path
import stat
import tempfile
import time
from dataclasses import dataclass
from ctypes import wintypes
from typing import Iterator

from .models import SparcError

_FILE_ATTRIBUTE_DIRECTORY = 0x10
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_OPEN_EXISTING = 3
_OPEN_ALWAYS = 4
_FILE_SHARE_ALL = 0x7
_FILE_SHARE_NO_DELETE = 0x3
_FILE_ALL_ACCESS = 0x001F01FF
_MAX_ACL_BYTES = 65535
_DACL_SECURITY_INFORMATION = 0x00000004
_OWNER_SECURITY_INFORMATION = 0x00000001
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_ACCESS_ALLOWED_ACE_TYPE = 0
_ACCESS_DENIED_ACE_TYPES = {1, 6, 10, 12}
_LOCK_SECONDS = 2.0
_POLL_SECONDS = 0.05


class _FILETIME(ctypes.Structure):
    _fields_ = [
        ("dwLowDateTime", ctypes.c_uint32),
        ("dwHighDateTime", ctypes.c_uint32),
    ]


class _BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", ctypes.c_uint32),
        ("ftCreationTime", _FILETIME),
        ("ftLastAccessTime", _FILETIME),
        ("ftLastWriteTime", _FILETIME),
        ("dwVolumeSerialNumber", ctypes.c_uint32),
        ("nFileSizeHigh", ctypes.c_uint32),
        ("nFileSizeLow", ctypes.c_uint32),
        ("nNumberOfLinks", ctypes.c_uint32),
        ("nFileIndexHigh", ctypes.c_uint32),
        ("nFileIndexLow", ctypes.c_uint32),
    ]


def _fail(message: str) -> SparcError:
    return SparcError("data_permissions_failed", message)


def _cancelled(cancelled) -> bool:
    if cancelled is None:
        return False
    try:
        return bool(cancelled())
    except Exception as exc:
        raise SparcError("identity_unlock_cancelled", "Identity operation was canceled") from exc


def _apis():
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.OpenProcessToken.argtypes = [
        wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)
    ]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [
        wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi.GetTokenInformation.restype = wintypes.BOOL
    advapi.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi.SetNamedSecurityInfoW.argtypes = [
        wintypes.LPWSTR, ctypes.c_int, wintypes.DWORD, ctypes.c_void_p,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ]
    advapi.SetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi.GetSecurityInfo.argtypes = [
        wintypes.HANDLE, ctypes.c_int, wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    advapi.GetSecurityInfo.restype = wintypes.DWORD
    advapi.SetSecurityInfo.argtypes = [
        wintypes.HANDLE, ctypes.c_int, wintypes.DWORD,
        ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ]
    advapi.SetSecurityInfo.restype = wintypes.DWORD
    advapi.InitializeAcl.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
    advapi.InitializeAcl.restype = wintypes.BOOL
    advapi.AddAce.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD
    ]
    advapi.AddAce.restype = wintypes.BOOL
    advapi.AddAccessAllowedAceEx.argtypes = [
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p
    ]
    advapi.AddAccessAllowedAceEx.restype = wintypes.BOOL
    advapi.GetAclInformation.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.c_int
    ]
    advapi.GetAclInformation.restype = wintypes.BOOL
    advapi.GetAce.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    advapi.GetAce.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)
    ]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi.ConvertStringSidToSidW.argtypes = [wintypes.LPWSTR, ctypes.POINTER(ctypes.c_void_p)]
    advapi.ConvertStringSidToSidW.restype = wintypes.BOOL
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CreateFileW.argtypes = [
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
        wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
    ]
    kernel.CreateFileW.restype = wintypes.HANDLE
    kernel.GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE, ctypes.c_void_p
    ]
    kernel.GetFileInformationByHandle.restype = wintypes.BOOL
    kernel.GetFileType.argtypes = [wintypes.HANDLE]
    kernel.GetFileType.restype = wintypes.DWORD
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    return advapi, kernel


def _user_sid() -> str:
    advapi, kernel = _apis()
    token = wintypes.HANDLE()
    if not advapi.OpenProcessToken(kernel.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
        raise _fail("Could not identify the current Windows user")
    try:
        needed = wintypes.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(needed))
        if not needed.value:
            raise _fail("Could not identify the current Windows user")
        token_user = ctypes.create_string_buffer(needed.value)
        if not advapi.GetTokenInformation(
            token, 1, token_user, needed, ctypes.byref(needed)
        ):
            raise _fail("Could not identify the current Windows user")
        sid = ctypes.cast(token_user, ctypes.POINTER(ctypes.c_void_p))[0]
        text = wintypes.LPWSTR()
        if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
            raise _fail("Could not identify the current Windows user")
        try:
            return text.value
        finally:
            kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))
    finally:
        kernel.CloseHandle(token)


def _sid_to_text(sid) -> str:
    advapi, kernel = _apis()
    text = wintypes.LPWSTR()
    if not advapi.ConvertSidToStringSidW(sid, ctypes.byref(text)):
        raise _fail("Could not inspect Windows access control entries")
    try:
        return text.value
    finally:
        kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))


def _path_info(path: Path):
    info = path.lstat()
    attrs = getattr(info, "st_file_attributes", 0)
    if attrs & _FILE_ATTRIBUTE_REPARSE_POINT or stat.S_ISLNK(info.st_mode):
        raise _fail("Identity storage must not contain reparse points")
    return info


@dataclass(frozen=True)
class _DirectoryChain:
    handles: tuple
    created_final: bool = False

    @property
    def final_handle(self):
        return self.handles[-1]


def _open_directory_component(path: Path, *, final: bool, private: bool = True):
    before = _path_info(path)
    if not stat.S_ISDIR(before.st_mode):
        raise _fail("Identity path component is not a directory")
    _advapi, kernel = _apis()
    access = 0x00000080 | (0x00020000 | 0x00040000 if final and private else 0)
    handle = kernel.CreateFileW(
        str(path), access, _FILE_SHARE_NO_DELETE, None,
        _OPEN_EXISTING,
        _FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        code = ctypes.get_last_error()
        if code in (2, 3):
            raise FileNotFoundError(code, "identity directory component is absent", str(path))
        raise OSError(code, "Could not open identity directory component", str(path))
    try:
        data = _BY_HANDLE_FILE_INFORMATION()
        if not kernel.GetFileInformationByHandle(handle, ctypes.byref(data)):
            raise OSError(ctypes.get_last_error(), "Could not inspect directory handle")
        if not (data.dwFileAttributes & _FILE_ATTRIBUTE_DIRECTORY):
            raise _fail("Identity path component is not a directory")
        if data.dwFileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise _fail("Identity path component is a reparse point")
        path_info = _path_info(path)
        file_index = (data.nFileIndexHigh << 32) | data.nFileIndexLow
        identity = (data.dwVolumeSerialNumber, file_index)
        if (before.st_dev, before.st_ino) != identity or (path_info.st_dev, path_info.st_ino) != identity:
            raise _fail("Identity path component changed during inspection")
        return handle
    except BaseException:
        _apis()[1].CloseHandle(handle)
        raise


@contextmanager
def open_directory_chain(path: Path, *, create: bool = False, private: bool = True):
    """Hold every checked path component without delete sharing."""
    absolute = Path(os.path.abspath(os.fspath(path)))
    if ".." in Path(path).parts:
        raise _fail("Identity storage path contains an unsafe component")
    handles = []
    current = Path(absolute.anchor)
    created_final = False
    try:
        try:
            handles.append(_open_directory_component(
                current, final=not absolute.parts[1:], private=private
            ))
        except FileNotFoundError:
            raise _fail("Could not open identity path root")
        for index, part in enumerate(absolute.parts[1:]):
            current = current / part
            created = False
            try:
                final = index == len(absolute.parts[1:]) - 1
                handle = _open_directory_component(current, final=final, private=private)
            except FileNotFoundError:
                if not create:
                    raise
                current.mkdir(mode=0o700)
                created = True
                handle = _open_directory_component(current, final=final, private=private)
            handles.append(handle)
            if index == len(absolute.parts[1:]) - 1:
                created_final = created
        yield _DirectoryChain(tuple(handles), created_final)
    except SparcError:
        raise
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise _fail("Could not safely bind identity directory path") from exc
    finally:
        _advapi, kernel = _apis()
        for handle in reversed(handles):
            kernel.CloseHandle(handle)


def _validate_components(path: Path) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    if ".." in Path(path).parts:
        raise _fail("Identity storage path contains an unsafe component")
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        attrs = getattr(info, "st_file_attributes", 0)
        if attrs & _FILE_ATTRIBUTE_REPARSE_POINT or stat.S_ISLNK(info.st_mode):
            raise _fail("Identity storage path contains a reparse point")
    return absolute


def _security(path: Path, information: int):
    advapi, kernel = _apis()
    owner = ctypes.c_void_p()
    group = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    result = advapi.GetNamedSecurityInfoW(
        str(path), 1, information, ctypes.byref(owner), ctypes.byref(group),
        ctypes.byref(dacl), None, ctypes.byref(descriptor),
    )
    if result:
        raise OSError(result, "GetNamedSecurityInfoW failed")
    return advapi, kernel, owner, dacl, descriptor


def _security_handle(handle, information: int):
    advapi, kernel = _apis()
    owner = ctypes.c_void_p()
    group = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    descriptor = ctypes.c_void_p()
    result = advapi.GetSecurityInfo(
        handle, 1, information, ctypes.byref(owner), ctypes.byref(group),
        ctypes.byref(dacl), None, ctypes.byref(descriptor),
    )
    if result:
        raise OSError(result, "GetSecurityInfo failed")
    return advapi, kernel, owner, dacl, descriptor


def _check_owner(path: Path) -> None:
    advapi, kernel, owner, _dacl, descriptor = _security(path, _OWNER_SECURITY_INFORMATION)
    try:
        if not owner.value or _sid_to_text(owner) != _user_sid():
            raise _fail("Identity directory or file is not owned by the current user")
    finally:
        kernel.LocalFree(descriptor)


def _check_owner_handle(handle) -> None:
    _advapi, kernel, owner, _dacl, descriptor = _security_handle(
        handle, _OWNER_SECURITY_INFORMATION
    )
    try:
        if not owner.value or _sid_to_text(owner) != _user_sid():
            raise _fail("Identity directory or file is not owned by the current user")
    finally:
        kernel.LocalFree(descriptor)


def _dacl_entries(advapi, kernel, dacl):
    if not dacl.value:
        raise _fail("A NULL Windows DACL is not permitted")

    class ACL_INFO(ctypes.Structure):
        _fields_ = [("AceCount", wintypes.DWORD), ("AclBytesInUse", wintypes.DWORD), ("AclBytesFree", wintypes.DWORD)]

    info = ACL_INFO()
    if not advapi.GetAclInformation(dacl, ctypes.byref(info), ctypes.sizeof(info), 2):
        raise _fail("Could not inspect Windows access control entries")
    entries = []
    grants = {}
    for index in range(info.AceCount):
        ace = ctypes.c_void_p()
        if not advapi.GetAce(dacl, index, ctypes.byref(ace)):
            raise _fail("Could not inspect Windows access control entries")
        header = ctypes.cast(ace, ctypes.POINTER(ctypes.c_ubyte * 4)).contents
        ace_type, size = header[0], int.from_bytes(bytes(header[2:4]), "little")
        raw = ctypes.string_at(ace, size)
        if ace_type in _ACCESS_DENIED_ACE_TYPES:
            entries.append((ace_type, raw))
            continue
        if ace_type != _ACCESS_ALLOWED_ACE_TYPE:
            raise _fail("Unsupported Windows access control entry")
        mask = int.from_bytes(raw[4:8], "little")
        sid = ctypes.c_void_p(ace.value + 8)
        sid_text = _sid_to_text(sid)
        entries.append((ace_type, raw))
        if sid_text in {_user_sid(), "S-1-5-18"}:
            grants[sid_text] = grants.get(sid_text, 0) | mask
    return entries, grants


def _private_acl_grants(existing_grants, user_sid: str, system_sid: str) -> dict[str, int]:
    """Keep only existing rights for the two permitted principals.

    Missing and zero masks stay missing and zero. Callers must fail closed if
    the resulting ACL would make the private object unusable.
    """
    return {
        sid: existing_grants[sid]
        for sid in (user_sid, system_sid)
        if sid in existing_grants
    }


def _set_private_dacl_handle(handle) -> None:
    advapi, kernel, _owner, dacl, descriptor = _security_handle(
        handle, _DACL_SECURITY_INFORMATION
    )
    user_sid_text = _user_sid()
    sid_ptrs = []
    try:
        entries, grants = _dacl_entries(advapi, kernel, dacl)
        sid_values = []
        for sid_text in (user_sid_text, "S-1-5-18"):
            sid = ctypes.c_void_p()
            if not advapi.ConvertStringSidToSidW(sid_text, ctypes.byref(sid)):
                raise _fail("Could not construct private Windows access controls")
            sid_ptrs.append(sid)
            sid_values.append((sid_text, sid))

        advapi.GetLengthSid.argtypes = [ctypes.c_void_p]
        advapi.GetLengthSid.restype = wintypes.DWORD
        preserved_denials = [
            raw for ace_type, raw in entries if ace_type in _ACCESS_DENIED_ACE_TYPES
        ]
        selected_grants = _private_acl_grants(grants, user_sid_text, "S-1-5-18")
        if not selected_grants.get(user_sid_text, 0):
            raise _fail("Existing Windows ACL does not grant the current user access")
        acl_size = 8 + sum(map(len, preserved_denials))
        acl_size += sum(
            8 + advapi.GetLengthSid(sid)
            for sid_text, sid in sid_values
            if sid_text in selected_grants
        )
        if acl_size > min(_MAX_ACL_BYTES, 0xFFFF):
            raise _fail("Windows access control list exceeds the supported size")
        acl_buffer = ctypes.create_string_buffer(acl_size)
        acl = ctypes.cast(acl_buffer, ctypes.c_void_p)
        if not advapi.InitializeAcl(acl, len(acl_buffer), 2):
            raise _fail("Could not construct private Windows access controls")
        for raw in preserved_denials:
            raw_buffer = ctypes.create_string_buffer(raw)
            if not advapi.AddAce(acl, 2, 0xFFFFFFFF, raw_buffer, len(raw)):
                raise _fail("Could not preserve Windows access denials")
        for sid_text, sid in sid_values:
            if sid_text not in selected_grants:
                continue
            rights = selected_grants[sid_text]
            if not advapi.AddAccessAllowedAceEx(acl, 2, 0, rights, sid):
                raise _fail("Could not grant private Windows identity access")
        result = advapi.SetSecurityInfo(
            handle, 1, _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
            None, None, acl, None,
        )
        if result:
            raise _fail("Could not secure private Windows identity access")
    finally:
        kernel.LocalFree(descriptor)
        for sid in sid_ptrs:
            kernel.LocalFree(sid)


def _initialize_private_dacl_handle(handle) -> None:
    """Deliberately provision a newly-created F1 object for user and SYSTEM."""
    advapi, kernel = _apis()
    sid_ptrs = []
    try:
        sids = []
        for sid_text in (_user_sid(), "S-1-5-18"):
            sid = ctypes.c_void_p()
            if not advapi.ConvertStringSidToSidW(sid_text, ctypes.byref(sid)):
                raise _fail("Could not construct initial private Windows access controls")
            sid_ptrs.append(sid)
            sids.append(sid)
        advapi.GetLengthSid.argtypes = [ctypes.c_void_p]
        advapi.GetLengthSid.restype = wintypes.DWORD
        acl_size = 8 + sum(8 + advapi.GetLengthSid(sid) for sid in sids)
        if acl_size > 0xFFFF:
            raise _fail("Windows access control list exceeds the supported size")
        acl_buffer = ctypes.create_string_buffer(acl_size)
        acl = ctypes.cast(acl_buffer, ctypes.c_void_p)
        if not advapi.InitializeAcl(acl, len(acl_buffer), 2):
            raise _fail("Could not construct initial private Windows access controls")
        for sid in sids:
            if not advapi.AddAccessAllowedAceEx(acl, 2, 0, _FILE_ALL_ACCESS, sid):
                raise _fail("Could not grant initial private Windows access")
        result = advapi.SetSecurityInfo(
            handle, 1, _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
            None, None, acl, None,
        )
        if result:
            raise _fail("Could not apply initial private Windows access controls")
    finally:
        for sid in sid_ptrs:
            kernel.LocalFree(sid)


def _initialize_private_file_descriptor(descriptor: int, path: Path) -> None:
    """Initialize a newly-created file only through a handle proven to match fd."""
    if os.name != "nt":
        raise _fail("Native Windows ACL initialization is unavailable")
    creation_info = os.fstat(descriptor)
    native = _open_native(Path(path), access=0x00020000 | 0x00040000)
    _advapi, kernel = _apis()
    try:
        data = _BY_HANDLE_FILE_INFORMATION()
        if not kernel.GetFileInformationByHandle(native, ctypes.byref(data)):
            raise _fail("Could not verify newly-created identity file handle")
        file_index = (data.nFileIndexHigh << 32) | data.nFileIndexLow
        if (creation_info.st_dev, creation_info.st_ino) != (
            data.dwVolumeSerialNumber, file_index
        ):
            raise _fail("New identity file path no longer names its creation handle")
        _initialize_private_dacl_handle(native)
    finally:
        kernel.CloseHandle(native)


def _open_native(path: Path, *, access: int, directory: bool = False):
    _validate_components(path.parent)
    advapi, kernel = _apis()
    handle = kernel.CreateFileW(
        str(path), access, _FILE_SHARE_ALL, None, _OPEN_EXISTING,
        _FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_BACKUP_SEMANTICS, None,
    )
    invalid = ctypes.c_void_p(-1).value
    if handle == invalid:
        code = ctypes.get_last_error()
        if code in (2, 3):
            raise FileNotFoundError(code, "identity file is absent", str(path))
        raise OSError(code, "Could not open identity file", str(path))
    try:
        data = _BY_HANDLE_FILE_INFORMATION()
        if not kernel.GetFileInformationByHandle(handle, ctypes.byref(data)):
            raise OSError(ctypes.get_last_error(), "Could not inspect identity file handle")
        attrs = data.dwFileAttributes
        is_directory = bool(attrs & _FILE_ATTRIBUTE_DIRECTORY)
        if attrs & _FILE_ATTRIBUTE_REPARSE_POINT or is_directory != directory:
            raise _fail("Identity path is not a regular non-reparse file")
        try:
            path_info = _path_info(path)
        except FileNotFoundError as exc:
            raise _fail("Identity file changed during inspection") from exc
        volume = data.dwVolumeSerialNumber
        link_count = data.nNumberOfLinks
        file_index = (data.nFileIndexHigh << 32) | data.nFileIndexLow
        if not directory and (kernel.GetFileType(handle) != 1 or link_count != 1):
            raise _fail("Identity file must not have additional hard links")
        if (path_info.st_dev, path_info.st_ino) != (volume, file_index):
            raise _fail("Identity file changed during inspection")
        _check_owner_handle(handle)
        return handle
    except BaseException:
        kernel.CloseHandle(handle)
        raise


def _open_handle(path: Path, *, writable: bool = False):
    access = _GENERIC_READ | (_GENERIC_WRITE if writable else 0)
    handle = _open_native(path, access=access)
    _advapi, kernel = _apis()
    handle_value = handle if isinstance(handle, int) else handle.value
    fd = None
    try:
        fd = msvcrt.open_osfhandle(
            handle_value, os.O_BINARY | (os.O_RDWR if writable else os.O_RDONLY)
        )
        handle = None
        stream = os.fdopen(fd, "r+b" if writable else "rb")
        fd = None
        return stream
    finally:
        if handle is not None:
            kernel.CloseHandle(handle)
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def prepare_private_directory(path: Path, *, _chain: _DirectoryChain | None = None) -> None:
    absolute = Path(os.path.abspath(os.fspath(path)))
    try:
        if _chain is None:
            with open_directory_chain(absolute, create=True) as chain:
                _prepare_private_directory_handle(chain)
        else:
            _prepare_private_directory_handle(_chain)
    except SparcError:
        raise
    except OSError as exc:
        raise _fail("Could not secure the private SPARC directory") from exc


def _prepare_private_directory_handle(chain: _DirectoryChain) -> None:
    handle = chain.final_handle
    _check_owner_handle(handle)
    if chain.created_final:
        _initialize_private_dacl_handle(handle)
    else:
        _set_private_dacl_handle(handle)
    _check_owner_handle(handle)


def secure_identity_file(
    path: Path, *, allow_missing: bool = False, initialize: bool = False
) -> None:
    try:
        if os.name == "nt":
            with open_directory_chain(Path(path).parent):
                _secure_identity_file_bound(
                    path, allow_missing=allow_missing, initialize=initialize
                )
            return
        _secure_identity_file_bound(path, allow_missing=allow_missing, initialize=initialize)
    except SparcError:
        raise
    except OSError as exc:
        raise _fail("Could not secure private identity file") from exc


def _secure_identity_file_bound(
    path: Path, *, allow_missing: bool = False, initialize: bool = False
) -> None:
    absolute = _validate_components(Path(path))
    try:
        info = _path_info(absolute)
    except FileNotFoundError:
        if allow_missing:
            return
        raise
    if not stat.S_ISREG(info.st_mode):
        raise _fail("Identity path is not a regular file")
    handle = _open_native(
        absolute, access=0x00020000 | 0x00040000
    )  # READ_CONTROL | WRITE_DAC
    try:
        _check_owner_handle(handle)
        if initialize:
            _initialize_private_dacl_handle(handle)
        else:
            _set_private_dacl_handle(handle)
    finally:
        _apis()[1].CloseHandle(handle)


def open_regular_file(path: Path, *, writable: bool = False):
    if os.name == "nt":
        with open_directory_chain(Path(path).parent, private=False):
            return _open_handle(Path(path), writable=writable)
    return _open_handle(Path(path), writable=writable)


def write_encrypted_temporary(directory: Path, filename: str, candidate: bytes) -> Path:
    if os.name == "nt":
        with open_directory_chain(directory):
            return _write_encrypted_temporary_bound(directory, filename, candidate)
    return _write_encrypted_temporary_bound(directory, filename, candidate)


def _write_encrypted_temporary_bound(directory: Path, filename: str, candidate: bytes) -> Path:
    descriptor, name = tempfile.mkstemp(prefix=f".{filename}.", suffix=".tmp", dir=directory)
    path = Path(name)
    try:
        original_info = os.fstat(descriptor)
        original_identity = (original_info.st_dev, original_info.st_ino)
        current = path.lstat()
        if (current.st_dev, current.st_ino) != original_identity:
            raise _fail("Temporary identity file changed during creation")
        _initialize_private_file_descriptor(descriptor, path)
        # Keep the creation handle live until publication/cleanup so its file
        # identity cannot be recycled after an attacker substitutes the name.
        current = path.lstat()
        if (current.st_dev, current.st_ino) != original_identity:
            raise _fail("Temporary identity file changed during preparation")
        with open_regular_file(path, writable=True) as stream:
            opened_info = os.fstat(stream.fileno())
            if (opened_info.st_dev, opened_info.st_ino) != original_identity:
                raise _fail("Temporary identity file changed before writing")
            stream.write(candidate)
            stream.flush()
            os.fsync(stream.fileno())
        return path
    except BaseException:
        try:
            original_info = os.fstat(descriptor)
            original_identity = (original_info.st_dev, original_info.st_ino)
            current = path.lstat()
            if (current.st_dev, current.st_ino) == original_identity:
                path.unlink()
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)


def sync_directory(_directory: Path) -> None:
    # Windows replacement uses the OS replacement primitive; readback is the
    # available portable durability check for directory metadata.
    return None


@contextmanager
def identity_file_lock(path: Path, *, cancelled=None) -> Iterator[None]:
    if os.name == "nt":
        parent = Path(path).parent
        with open_directory_chain(parent, create=True) as chain:
            prepare_private_directory(parent, _chain=chain)
            with _identity_file_lock_bound(path, cancelled=cancelled):
                yield
        return
    with _identity_file_lock_bound(path, cancelled=cancelled):
        yield


@contextmanager
def _identity_file_lock_bound(path: Path, *, cancelled=None) -> Iterator[None]:
    import msvcrt

    path = _validate_components(Path(path))
    created = False
    creation_descriptor = None
    stream = None
    acquired = False
    try:
        _path_info(path)
    except FileNotFoundError:
        try:
            creation_descriptor = os.open(
                path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600
            )
            created = True
        except FileExistsError:
            pass
        except OSError as exc:
            raise _fail("Could not create private identity lock") from exc
    try:
        if created:
            created_info = os.fstat(creation_descriptor)
            _initialize_private_file_descriptor(creation_descriptor, path)
            current = path.lstat()
            if (current.st_dev, current.st_ino) != (created_info.st_dev, created_info.st_ino):
                raise _fail("New identity lock path no longer names its creation handle")
        else:
            secure_identity_file(path)
        stream = open_regular_file(path, writable=True)
        if created:
            stream_info = os.fstat(stream.fileno())
            if (stream_info.st_dev, stream_info.st_ino) != (
                created_info.st_dev, created_info.st_ino
            ):
                raise _fail("Identity lock changed before it was opened")
        if stream.seek(0, os.SEEK_END) == 0:
            stream.write(b"\0")
            stream.flush()
            os.fsync(stream.fileno())
        deadline = time.monotonic() + _LOCK_SECONDS
        while True:
            if _cancelled(cancelled):
                raise SparcError("identity_unlock_cancelled", "Identity operation was canceled")
            try:
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                acquired = True
                break
            except OSError as exc:
                if exc.errno not in (errno.EACCES, errno.EDEADLK, errno.EAGAIN):
                    raise _fail("Could not acquire identity lock") from exc
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SparcError("identity_busy", "Identity storage is busy; try again")
                time.sleep(min(_POLL_SECONDS, remaining))
        yield
    finally:
        try:
            if acquired:
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            if stream is not None:
                stream.close()
            if creation_descriptor is not None:
                os.close(creation_descriptor)
