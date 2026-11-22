"""Contract tests for ``OpenProcess(current_pid)`` (FX-020).

``HandleObject|AddressSpace / open_process|current_pid``: the executing process
must be openable by its own PID even though ``run_module()`` does not
materialize the top-level :class:`Process` in the configured ``self.processes``
table.  Opening it must return a real process handle through the existing
object manager, and ``VirtualProtectEx`` on that handle must take the
current-process ``VirtualProtect`` path (return 1 with the real old
protection).  Negative behavior is frozen by FX12-rv2: an unknown PID keeps
FALSE/``ERROR_INVALID_PARAMETER`` and an invalid handle keeps
FALSE/``ERROR_INVALID_HANDLE``.

The positive path uses a synthetic x86 PE32 with no import table: the entry
resolves ``GetCurrentProcessId``/``OpenProcess``/``VirtualProtectEx`` through
the emulator's API stubs, calls them, then writes a marker byte into a separate
image page.  ``tests/synthetic_pe.py`` supplies the PE layout.
"""

from __future__ import annotations

import struct

import speakeasy.common as common
import speakeasy.winenv.arch as e_arch
from speakeasy import Speakeasy
from speakeasy.windows.page_protection import PAGE_WRITECOPY
from speakeasy.winenv.defs.windows import windows as windefs
from tests.synthetic_pe import build_pe

PAGE_EXECUTE_READ = windefs.PAGE_EXECUTE_READ
PAGE_READWRITE = windefs.PAGE_READWRITE
ERROR_SUCCESS = windefs.ERROR_SUCCESS
ERROR_INVALID_HANDLE = windefs.ERROR_INVALID_HANDLE
ERROR_INVALID_PARAMETER = windefs.ERROR_INVALID_PARAMETER

IMAGE_BASE = 0x400000
TEXT_RVA = 0x1000
TEXT_VSIZE = 0x2000
DATA_RVA = 0x3000
IMAGE_SIZE = 0x4000
# A page of the image that is distinct from the entry page and never executed.
TARGET_RVA = 0x2800
MARKER_RVA = 0x2900

OUT_PID = 0x00
OUT_HANDLE = 0x08
OUT_VPROTECT = 0x10
OUT_OLD = 0x18

INVALID_HANDLE = 0x12345678
UNKNOWN_PID = 0x7FFF1234

PROCESS_VM_OPERATION = 0x0008
PAGE_SIZE = 0x1000


class _Code:
    """Tiny x86 emitter for the fixed call sequence, with named 32-bit patches."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.patches: list[tuple[str, int, int, int]] = []

    def _imm32(self, key: str, addend: int = 0) -> None:
        self.patches.append((key, len(self.buf), addend, 4))
        self.buf += b"\x00\x00\x00\x00"

    def push_imm32(self, value: int) -> None:
        self.buf += b"\x68" + struct.pack("<I", value & 0xFFFFFFFF)

    def push_abs(self, key: str, addend: int = 0) -> None:
        """``push dword ptr [key+addend]`` (FF 35 imm32)."""
        self.buf += b"\xFF\x35"
        self._imm32(key, addend)

    def mov_eax_abs(self, key: str) -> None:
        """``mov eax, [key]`` (B8 imm32)."""
        self.buf += b"\xB8"
        self._imm32(key)

    def mov_ptr_eax(self, key: str) -> None:
        """``mov dword ptr [key], eax`` (A3 imm32)."""
        self.buf += b"\xA3"
        self._imm32(key)

    def call_eax(self) -> None:
        self.buf += b"\xFF\xD0"

    def mov_byte_ptr_abs(self, key: str, value: int) -> None:
        """``mov byte ptr [key], imm8`` (C6 05 imm32 imm8)."""
        self.buf += b"\xC6\x05"
        self._imm32(key)
        self.buf += bytes([value])

    def ret(self) -> None:
        self.buf += b"\xC3"


def _emit_open_self(*, data_rva: int, target_rva: int) -> tuple[bytes, list]:
    """Build the entry sequence: GetCurrentProcessId -> OpenProcess -> VTEx -> write.

    The entry stores the PID, the returned handle and the ``VirtualProtectEx``
    return value in ``.data`` and writes ``0x41`` into a separate image page.
    """
    c = _Code()
    c.mov_eax_abs("getpid")
    c.call_eax()
    c.mov_ptr_eax("out_pid")

    c.push_abs("out_pid")  # dwProcessId = self PID
    c.push_imm32(0)  # bInheritHandle
    c.push_imm32(PROCESS_VM_OPERATION)  # dwDesiredAccess
    c.mov_eax_abs("open_process")
    c.call_eax()
    c.mov_ptr_eax("out_handle")

    c.push_imm32(IMAGE_BASE + data_rva + OUT_OLD)  # lpflOldProtect
    c.push_imm32(PAGE_READWRITE)  # flNewProtect
    c.push_imm32(PAGE_SIZE)  # dwSize
    c.push_imm32(IMAGE_BASE + target_rva)  # lpAddress
    c.push_abs("out_handle")  # hProcess
    c.mov_eax_abs("vprotect_ex")
    c.call_eax()
    c.mov_ptr_eax("out_vprotect")

    c.mov_byte_ptr_abs("marker", 0x41)
    c.ret()
    return bytes(c.buf), c.patches


def _load_values(emu, module) -> dict[str, int]:
    return {
        "getpid": emu.get_proc("kernel32", "GetCurrentProcessId"),
        "open_process": emu.get_proc("kernel32", "OpenProcess"),
        "vprotect_ex": emu.get_proc("kernel32", "VirtualProtectEx"),
        "out_pid": module.base + DATA_RVA + OUT_PID,
        "out_handle": module.base + DATA_RVA + OUT_HANDLE,
        "out_vprotect": module.base + DATA_RVA + OUT_VPROTECT,
        "marker": module.base + MARKER_RVA,
    }


def _start_open_self(config) -> tuple[Speakeasy, object, object, dict[str, int], dict[str, int]]:
    """Load and run the synthetic open-self PE, returning the observed values."""
    code, patches = _emit_open_self(data_rva=DATA_RVA, target_rva=TARGET_RVA)
    image = build_pe(
        e_arch.ARCH_X86,
        code,
        text_vsize=TEXT_VSIZE,
        image_size=IMAGE_SIZE,
        data_rva=DATA_RVA,
    )
    se = Speakeasy(config=config, argv=[])
    module = se.load_module(data=image)
    emu = se.emu
    values = _load_values(emu, module)
    for key, offset, addend, size in patches:
        value = (values[key] + addend) & ((1 << (size * 8)) - 1)
        emu.mem_write(module.base + TEXT_RVA + offset, value.to_bytes(size, "little"))

    se.run_module(module)
    observed = {
        "pid": int.from_bytes(emu.mem_read(module.base + DATA_RVA + OUT_PID, 4), "little"),
        "handle": int.from_bytes(emu.mem_read(module.base + DATA_RVA + OUT_HANDLE, 4), "little"),
        "vprotect": int.from_bytes(emu.mem_read(module.base + DATA_RVA + OUT_VPROTECT, 4), "little"),
        "old": int.from_bytes(emu.mem_read(module.base + DATA_RVA + OUT_OLD, 4), "little"),
        "marker": int.from_bytes(emu.mem_read(module.base + MARKER_RVA, 4), "little"),
    }
    return se, module, emu, observed, values


def _kernel32(emu):
    return emu.api.load_api_handler("kernel32")


def _zero_old_ptr(emu, module) -> int:
    addr = module.base + DATA_RVA + 0x100
    emu.mem_write(addr, b"\x00" * 4)
    return addr


def test_get_process_by_id_resolves_current_process(config) -> None:
    """The executing process is addressable by PID without entering the table."""
    se = Speakeasy(config=config, argv=[])
    try:
        module = se.load_module(data=build_pe(e_arch.ARCH_X86, b"\xC3"))
        se.run_module(module)
        report = se.get_report()
        assert report.entry_points[0].error is None

        emu = se.emu
        current = emu.get_current_process()
        assert current is not None
        assert emu.get_process_by_id(current.id) is current

        # The configured process table is the separate enumeration namespace;
        # resolving by PID must not require materializing the top-level object.
        processes = emu.get_processes()
        assert current not in processes
        system = emu.get_process_by_id(4)
        assert system is not None
        assert system.pid == 4
        assert system.name == "System"
        assert emu.get_process_by_id(UNKNOWN_PID) is None
        assert emu.get_process_by_id(0) is None
    finally:
        se.shutdown()


def test_open_process_self_returns_valid_handle(config) -> None:
    se, _module, emu, observed, _values = _start_open_self(config)
    try:
        current = emu.get_current_process()
        assert current is not None
        assert observed["pid"] == current.id
        assert observed["handle"] != 0
        assert emu.get_object_from_handle(observed["handle"]) is current
        assert emu.get_last_error() == ERROR_SUCCESS
        assert se.get_report().entry_points[0].error is None
    finally:
        se.shutdown()


def test_virtual_protect_ex_on_self_handle(config) -> None:
    se, module, emu, observed, _values = _start_open_self(config)
    try:
        target = module.base + TARGET_RVA
        assert observed["handle"] != 0
        assert observed["vprotect"] == 1
        assert observed["old"] == PAGE_EXECUTE_READ
        assert observed["marker"] == 0x41
        # Image-page write protection keeps its existing semantics: the write
        # converts the page to copy-on-write rather than a plain RW page.
        assert emu.get_address_win_protection(target) == PAGE_WRITECOPY
        assert emu.get_address_perms(target) == (common.PERM_MEM_READ | common.PERM_MEM_WRITE)
        assert se.get_report().entry_points[0].error is None
    finally:
        se.shutdown()


def test_open_process_invalid_pid_unchanged(config) -> None:
    se, module, emu, _observed, _values = _start_open_self(config)
    try:
        k32 = _kernel32(emu)
        assert k32.OpenProcess(emu, [PROCESS_VM_OPERATION, 0, 0]) == 0
        assert emu.get_last_error() == ERROR_INVALID_PARAMETER
        assert k32.OpenProcess(emu, [PROCESS_VM_OPERATION, 0, UNKNOWN_PID]) == 0
        assert emu.get_last_error() == ERROR_INVALID_PARAMETER
        assert module.base == IMAGE_BASE
    finally:
        se.shutdown()


def test_virtual_protect_ex_invalid_handle_unchanged(config) -> None:
    se, module, emu, _observed, _values = _start_open_self(config)
    try:
        k32 = _kernel32(emu)
        target = module.base + TARGET_RVA
        old_ptr = _zero_old_ptr(emu, module)
        assert (
            k32.VirtualProtectEx(emu, [0, target, PAGE_SIZE, PAGE_READWRITE, old_ptr])
            == 0
        )
        assert emu.get_last_error() == ERROR_INVALID_HANDLE
        assert emu.mem_read(old_ptr, 4) == b"\x00" * 4
        assert (
            k32.VirtualProtectEx(
                emu, [INVALID_HANDLE, target, PAGE_SIZE, PAGE_READWRITE, old_ptr]
            )
            == 0
        )
        assert emu.get_last_error() == ERROR_INVALID_HANDLE
        assert emu.mem_read(old_ptr, 4) == b"\x00" * 4
    finally:
        se.shutdown()


def test_close_and_reopen_self_handle(config) -> None:
    se, module, emu, observed, _values = _start_open_self(config)
    try:
        k32 = _kernel32(emu)
        current = emu.get_current_process()
        handle = observed["handle"]
        assert handle != 0

        assert k32.CloseHandle(emu, [handle]) == 1
        reopened = k32.OpenProcess(emu, [PROCESS_VM_OPERATION, 0, current.id])
        assert reopened != 0
        assert reopened != handle
        assert emu.get_object_from_handle(reopened) is current
        assert emu.get_last_error() == ERROR_SUCCESS

        # The entry page was executed but never written: a second image page
        # still opens through the reopened handle with its real old protection.
        other_page = module.base + TEXT_RVA
        old_ptr = _zero_old_ptr(emu, module)
        assert (
            k32.VirtualProtectEx(
                emu, [reopened, other_page, PAGE_SIZE, PAGE_READWRITE, old_ptr]
            )
            == 1
        )
        assert int.from_bytes(emu.mem_read(old_ptr, 4), "little") == PAGE_EXECUTE_READ
        assert emu.get_last_error() == ERROR_SUCCESS
    finally:
        se.shutdown()
