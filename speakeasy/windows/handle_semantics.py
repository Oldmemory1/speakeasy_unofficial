# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.

"""Handle-domain policy for APIs emulated from the Win32 signature database.

The signature database records only that an API returns ``h`` (a handle). It
does not record which *domain* the handle belongs to, and those domains are not
interchangeable:

* ``KERNEL``: an NT kernel-object handle (event, file, mapping, process,
  thread, job, semaphore, timer, transaction, socket, service, ...). These are
  opaque numbers allocated by :class:`speakeasy.windows.objman.HandleAllocator`.
* ``HGLOBAL``: a global-memory data handle. In Speakeasy an HGLOBAL is the
  address of a mapped, readable block (see ``kernel32.GlobalAlloc``), not a
  kernel-object number.
* ``HWND``: a window/GUI handle (HWND, HICON, HMENU, HHOOK, ...), which refers
  to a GUI object rather than a kernel object.
* ``HGDI``: a GDI object handle (HPEN, HBRUSH, HBITMAP, HDC, HRGN, ...).
* ``HMODULE``: a loaded-module base address (HMODULE/HINSTANCE), which is a
  pointer-like value rather than a kernel-object handle.
* ``UNKNOWN``: the signature database does not identify the domain.

``HandleAllocator.new_handle`` can only produce the first kind, and even then
only a bare number with no object behind it. Substituting a fresh kernel handle
for any other domain turns an API failure into a fake success; the guest then
dereferences, calls or passes the value as an object of the wrong kind. The
representative case is ``ole32.OleDuplicateData``: the signature says ``h`` but
the real return is an HGLOBAL, and the guest's NULL check fell through to
``call eax`` at the first kernel handle value (0x220).

The registries below are explicit and auditable. Membership is deliberately
narrow: only APIs whose documented return is a kernel-object handle keep the
legacy ``new_handle()`` allocation. Everything else - including any API added to
the signature database later - defaults to NULL, because a fabricated kernel
handle is never a valid HGLOBAL/HWND/HGDIOBJ/HMODULE.
"""

from __future__ import annotations

from collections.abc import Callable
from enum import Enum

import speakeasy.winenv.api.sigdb as sigdb

# Kernel-object handle APIs: Create*/Open*/FindFirst* families whose return
# value is an NT object manager handle. Audited against the ret=h entries of the
# bundled Win32 metadata signatures; HMODULE (LoadLibrary*/GetModuleHandle*),
# HRSRC (FindResource*) and HWND (GetConsoleWindow) are intentionally excluded.
KERNEL_HANDLE_APIS: dict[str, frozenset[str]] = {
    "kernel32": frozenset(
        {
            "BeginUpdateResourceA",
            "BeginUpdateResourceW",
            "CreateActCtxA",
            "CreateActCtxW",
            "CreateBoundaryDescriptorA",
            "CreateBoundaryDescriptorW",
            "CreateConsoleScreenBuffer",
            "CreateEventA",
            "CreateEventExA",
            "CreateEventExW",
            "CreateEventW",
            "CreateFile2",
            "CreateFileA",
            "CreateFileMappingA",
            "CreateFileMappingFromApp",
            "CreateFileMappingNumaA",
            "CreateFileMappingNumaW",
            "CreateFileMappingW",
            "CreateFileTransactedA",
            "CreateFileTransactedW",
            "CreateFileW",
            "CreateIoCompletionPort",
            "CreateJobObjectA",
            "CreateJobObjectW",
            "CreateMailslotA",
            "CreateMailslotW",
            "CreateMemoryResourceNotification",
            "CreateMutexA",
            "CreateMutexExA",
            "CreateMutexExW",
            "CreateMutexW",
            "CreateNamedPipeA",
            "CreateNamedPipeW",
            "CreatePrivateNamespaceA",
            "CreatePrivateNamespaceW",
            "CreateRemoteThread",
            "CreateRemoteThreadEx",
            "CreateSemaphoreA",
            "CreateSemaphoreExA",
            "CreateSemaphoreExW",
            "CreateSemaphoreW",
            "CreateThread",
            "CreateThreadpool",
            "CreateTimerQueue",
            "CreateToolhelp32Snapshot",
            "CreateWaitableTimerA",
            "CreateWaitableTimerExA",
            "CreateWaitableTimerExW",
            "CreateWaitableTimerW",
            "FindFirstChangeNotificationA",
            "FindFirstChangeNotificationW",
            "FindFirstFileA",
            "FindFirstFileExA",
            "FindFirstFileExW",
            "FindFirstFileNameTransactedW",
            "FindFirstFileNameW",
            "FindFirstFileTransactedA",
            "FindFirstFileTransactedW",
            "FindFirstFileW",
            "FindFirstStreamTransactedW",
            "FindFirstStreamW",
            "FindFirstVolumeA",
            "FindFirstVolumeMountPointA",
            "FindFirstVolumeMountPointW",
            "FindFirstVolumeW",
            "GetCurrentProcess",
            "GetCurrentThread",
            "GetProcessHeap",
            "GetStdHandle",
            "HeapCreate",
            "OpenEventA",
            "OpenEventW",
            "OpenFileById",
            "OpenFileMappingA",
            "OpenFileMappingW",
            "OpenJobObjectA",
            "OpenJobObjectW",
            "OpenMutexA",
            "OpenMutexW",
            "OpenPrivateNamespaceA",
            "OpenPrivateNamespaceW",
            "OpenProcess",
            "OpenSemaphoreA",
            "OpenSemaphoreW",
            "OpenThread",
            "OpenWaitableTimerA",
            "OpenWaitableTimerW",
            "PowerCreateRequest",
            "ReOpenFile",
            "SetTimerQueueTimer",
        }
    ),
    "advapi32": frozenset(
        {
            "CreateServiceA",
            "CreateServiceW",
            "OpenBackupEventLogA",
            "OpenBackupEventLogW",
            "OpenEventLogA",
            "OpenEventLogW",
            "OpenSCManagerA",
            "OpenSCManagerW",
            "OpenServiceA",
            "OpenServiceW",
            "RegisterEventSourceA",
            "RegisterEventSourceW",
            "RegisterServiceCtrlHandlerA",
            "RegisterServiceCtrlHandlerExA",
            "RegisterServiceCtrlHandlerExW",
            "RegisterServiceCtrlHandlerW",
        }
    ),
    "ktmw32": frozenset(
        {
            "CreateEnlistment",
            "CreateResourceManager",
            "CreateTransaction",
            "CreateTransactionManager",
            "OpenEnlistment",
            "OpenResourceManager",
            "OpenTransaction",
            "OpenTransactionManager",
            "OpenTransactionManagerById",
        }
    ),
    "ws2_32": frozenset(
        {
            "WSAAccept",
            "WSAAsyncGetHostByAddr",
            "WSAAsyncGetHostByName",
            "WSAAsyncGetProtoByName",
            "WSAAsyncGetProtoByNumber",
            "WSAAsyncGetServByName",
            "WSAAsyncGetServByPort",
            "WSACreateEvent",
            "WSAJoinLeaf",
            "WSASocketA",
            "WSASocketW",
            "accept",
            "socket",
        }
    ),
}

# HGLOBAL data-handle APIs. In Speakeasy the value is a mapped memory block.
HGLOBAL_HANDLE_APIS: dict[str, frozenset[str]] = {
    "kernel32": frozenset({"GlobalAlloc", "GlobalReAlloc", "LocalAlloc", "LocalReAlloc"}),
    "ole32": frozenset({"OleDuplicateData"}),
}

# HMODULE/HINSTANCE APIs: the value is a module base address, not a kernel handle.
HMODULE_HANDLE_APIS: dict[str, frozenset[str]] = {
    "kernel32": frozenset(
        {
            "GetModuleHandleA",
            "GetModuleHandleW",
            "LoadLibraryA",
            "LoadLibraryExA",
            "LoadLibraryExW",
            "LoadLibraryW",
            "LoadPackagedLibrary",
        }
    ),
    "ole32": frozenset({"CoLoadLibrary"}),
}

# Non-kernel GUI-domain handle APIs outside the user32 DLL-wide rule.
HWND_HANDLE_APIS: dict[str, frozenset[str]] = {
    "kernel32": frozenset({"GetConsoleWindow"}),
    "avicap32": frozenset({"capCreateCaptureWindowA", "capCreateCaptureWindowW"}),
    "comctl32": frozenset(
        {
            "CreateStatusWindowA",
            "CreateStatusWindowW",
            "CreateToolbarEx",
            "CreateUpDownControl",
        }
    ),
    "msvfw32": frozenset({"MCIWndCreateA", "MCIWndCreateW"}),
    "shell32": frozenset(
        {
            "DuplicateIcon",
            "ExtractAssociatedIconA",
            "ExtractAssociatedIconExA",
            "ExtractAssociatedIconExW",
            "ExtractAssociatedIconW",
            "ExtractIconA",
            "ExtractIconW",
        }
    ),
}

# DLLs whose ret=h APIs are window/GUI handles (HWND, HICON, HMENU, HHOOK, ...).
GUI_HANDLE_DLLS = frozenset({"user32"})
# DLLs whose ret=h APIs are GDI object handles (HPEN, HBRUSH, HBITMAP, HDC, ...).
GDI_HANDLE_DLLS = frozenset({"gdi32"})


class HandleReturnDomain(Enum):
    """Handle domain of an API's ``ret=h`` value."""

    KERNEL = "kernel"
    HGLOBAL = "hglobal"
    HWND = "hwnd"
    HGDI = "hgdi"
    HMODULE = "hmodule"
    UNKNOWN = "unknown"


def classify_signature_handle_return(dll: str, name: str) -> HandleReturnDomain:
    """Return the handle domain declared for ``dll!name``, or UNKNOWN.

    Only the signature database's bare ``h`` return type is available here, so
    the answer comes from the explicit registries above. An unregistered API is
    UNKNOWN by design: the engine must not invent a handle domain for it.
    """
    canon = sigdb.normalize_dll(dll)
    if name in KERNEL_HANDLE_APIS.get(canon, ()):
        return HandleReturnDomain.KERNEL
    if name in HGLOBAL_HANDLE_APIS.get(canon, ()):
        return HandleReturnDomain.HGLOBAL
    if name in HMODULE_HANDLE_APIS.get(canon, ()):
        return HandleReturnDomain.HMODULE
    if name in HWND_HANDLE_APIS.get(canon, ()):
        return HandleReturnDomain.HWND
    if canon in GUI_HANDLE_DLLS:
        return HandleReturnDomain.HWND
    if canon in GDI_HANDLE_DLLS:
        return HandleReturnDomain.HGDI
    return HandleReturnDomain.UNKNOWN


def signature_handle_return(
    dll: str,
    name: str,
    allocate_kernel_handle: Callable[[], int] | None = None,
) -> int:
    """Default return value for a ``ret=h`` API emulated from its signature.

    Only a KERNEL-domain API may receive a fresh kernel-object handle, and only
    when the caller supplies an allocator (the emulator's ObjectManager). Data,
    GUI, module and unknown domains return NULL: a fabricated kernel handle is
    not a valid substitute for those object kinds. The returned 0 is the API's
    documented failure value for a handle-returning call.
    """
    domain = classify_signature_handle_return(dll, name)
    if domain is HandleReturnDomain.KERNEL and allocate_kernel_handle is not None:
        return allocate_kernel_handle()
    return 0
