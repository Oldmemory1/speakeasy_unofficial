"""Contract tests for Nt/ZwProtectVirtualMemory page protection (FX-009).

``MemoryProtection / virtualprotect`` requires the NT protect service to:

* read ``*BaseAddress`` / ``*NumberOfBytesToProtect`` and round the base down /
  the size up to page boundaries;
* apply the requested ``PAGE_*`` protection to exactly the covered pages
  (shared helper ``speakeasy.windows.page_protection.apply_page_protection``);
* write the rounded base/size and ``*OldAccessProtection`` (first affected
  page) back to guest memory on success;
* resolve ``ProcessHandle`` (current-process pseudo handle or a process object
  handle) and fail invalid handles/parameters/unmapped ranges with a non-zero
  NTSTATUS instead of silently reporting ``STATUS_SUCCESS``.

The x86 shellcode tests drive the real ``ntoskrnl`` handler through the same
``ntdll.NtProtectVirtualMemory`` import-normalization path used by the
representative sample.  The rounding test invokes the handler directly so the
literal ``base=0x1003, size=1`` contract from the work order (write back
``0x1000/0x1000``) can be frozen on page ``0x1000`` (the shellcode image lives
there; nothing executes after the direct call).
"""

from __future__ import annotations

import struct

import speakeasy.common as common
import speakeasy.windows.objman as objman
from speakeasy import Speakeasy
from speakeasy.winenv.api.kernelmode.ntoskrnl import Ntoskrnl

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000

STATUS_SUCCESS = 0
STATUS_ACCESS_VIOLATION = 0xC0000005
STATUS_INVALID_HANDLE = 0xC0000008
STATUS_INVALID_PARAMETER = 0xC000000D

UNMAPPED_ADDRESS = 0x30000000
INVALID_HANDLE = 0x12345678
NO_OLD_PROTECT = 0xFFFFFFFF


class _Asm:
    """Small x86 emitter with absolute fixups resolved after loading."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.patches: list[list] = []

    def imm32(self, key: str, addend: int = 0) -> None:
        offset = len(self.buf)
        self.buf += b"\x00\x00\x00\x00"
        self.patches.append([offset, key, addend])

    def push_imm8(self, value: int) -> None:
        self.buf += bytes((0x6A, value & 0xFF))

    def push_imm32(self, value: int) -> None:
        self.buf += b"\x68" + struct.pack("<I", value & 0xFFFFFFFF)

    def push_abs(self, key: str, addend: int = 0) -> None:
        self.buf += b"\x68"
        self.imm32(key, addend)

    def mov_eax_abs(self, key: str, addend: int = 0) -> None:
        self.buf += b"\xB8"
        self.imm32(key, addend)

    def mov_eax_ptr_abs(self, key: str, addend: int = 0) -> None:
        self.buf += b"\x8B\x05"
        self.imm32(key, addend)

    def mov_ptr_abs_eax(self, key: str, addend: int = 0) -> None:
        self.buf += b"\x89\x05"
        self.imm32(key, addend)

    def mov_ptr_abs_imm32(self, key: str, value: int, addend: int = 0) -> None:
        self.buf += b"\xC7\x05"
        self.imm32(key, addend)
        self.buf += struct.pack("<I", value & 0xFFFFFFFF)

    def call_eax(self) -> None:
        self.buf += b"\xFF\xD0"

    def ret(self) -> None:
        self.buf += b"\xC3"


def _apply_patches(emu, base: int, patches: list[list], values: dict[str, int]) -> None:
    for offset, key, addend in patches:
        emu.mem_write(base + offset, struct.pack("<I", (values[key] + addend) & 0xFFFFFFFF))


def _emit_alloc(asm: _Asm, *, size: int, protect: int) -> None:
    """Emit VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, protect)."""
    asm.push_imm8(protect)
    asm.push_imm32(MEM_COMMIT | MEM_RESERVE)
    asm.push_imm32(size)
    asm.push_imm32(0)
    asm.mov_eax_abs("alloc")
    asm.call_eax()


def _emit_nt_protect(
    asm: _Asm,
    *,
    base_slot: int,
    size_slot: int,
    old_slot: int,
    new_protect: int,
    handle_imm: int,
) -> None:
    """Emit NtProtectVirtualMemory(handle, &base, &size, new_prot, &old)."""
    asm.push_abs("data", old_slot)
    if new_protect <= 0xFF:
        asm.push_imm8(new_protect)
    else:
        asm.push_imm32(new_protect)
    asm.push_abs("data", size_slot)
    asm.push_abs("data", base_slot)
    asm.push_imm32(handle_imm)
    asm.mov_eax_abs("ntprotect")
    asm.call_eax()


# Data slot layout shared by the shellcode tests.
D_TARGET = 0x00
D_ADDR = 0x04
D_SIZE = 0x08
D_OLD = 0x0C
D_RET = 0x10
D_RET2 = 0x14
D_RET3 = 0x18
D_RET4 = 0x1C
D_DATA_SIZE = 0x100


def _build_make_writable() -> tuple[bytes, list[list], int]:
    """Allocate a read-only page, protect it PAGE_EXECUTE_READWRITE."""
    asm = _Asm()
    _emit_alloc(asm, size=0x2000, protect=PAGE_READONLY)
    asm.mov_ptr_abs_eax("data", D_TARGET)

    asm.mov_ptr_abs_eax("data", D_ADDR)
    asm.mov_ptr_abs_imm32("data", 0x1000, D_SIZE)
    asm.mov_ptr_abs_imm32("data", NO_OLD_PROTECT, D_OLD)

    _emit_nt_protect(
        asm,
        base_slot=D_ADDR,
        size_slot=D_SIZE,
        old_slot=D_OLD,
        new_protect=PAGE_EXECUTE_READWRITE,
        handle_imm=0xFFFFFFFF,
    )
    asm.mov_ptr_abs_eax("data", D_RET)
    asm.ret()

    code = bytes(asm.buf)
    data_offset = len(code)
    code += b"\x00" * D_DATA_SIZE
    return code, asm.patches, data_offset


def test_nt_protect_virtual_memory_makes_readonly_page_writable(config):
    code, patches, data_offset = _build_make_writable()

    se = Speakeasy(config=config)
    try:
        sc_addr = se.load_shellcode(data=code, arch="x86")
        emu = se.emu
        values = {
            "sc": sc_addr,
            "data": sc_addr + data_offset,
            "alloc": emu.get_proc("kernel32", "VirtualAlloc"),
            "ntprotect": emu.get_proc("ntdll", "NtProtectVirtualMemory"),
        }
        assert all(values.values())
        _apply_patches(emu, sc_addr, patches, values)

        se.run_shellcode(sc_addr)
        report = se.get_report()
        entry = report.entry_points[0]
        assert entry.error is None, entry.error

        data_addr = sc_addr + data_offset

        def read(offset: int) -> int:
            return int.from_bytes(emu.mem_read(data_addr + offset, 4), "little")

        target = read(D_TARGET)
        assert target & 0xFFF == 0
        # STATUS_SUCCESS and the rounded IN OUT values are written back.
        assert read(D_RET) == STATUS_SUCCESS
        assert read(D_ADDR) == target
        assert read(D_SIZE) == 0x1000
        # The first affected page was read-only before the call.
        assert read(D_OLD) == PAGE_READONLY
        # The page is really writable now and carries the requested Win32 value.
        assert emu.get_address_perms(target) & common.PERM_MEM_WRITE
        assert emu.get_address_perms(target) & common.PERM_MEM_EXEC
        assert emu.get_address_win_protection(target) == PAGE_EXECUTE_READWRITE
    finally:
        se.shutdown()


def test_nt_protect_virtual_memory_rounds_base_and_size(config):
    # A full 0x1000-byte shellcode image keeps page 0x1000 mapped as one page;
    # the code is never executed, the handler is called directly.
    se = Speakeasy(config=config)
    try:
        se.load_shellcode(data=b"\xC3" + b"\x00" * 0xFFF, arch="x86")
        emu = se.emu
        handler = Ntoskrnl(emu)

        scratch = emu.mem_map(0x100, tag="test.fx009.scratch", perms=common.PERM_MEM_RW)
        base_ptr = scratch
        size_ptr = scratch + 4
        old_ptr = scratch + 8
        emu.mem_write(base_ptr, (0x1003).to_bytes(4, "little"))
        emu.mem_write(size_ptr, (1).to_bytes(4, "little"))
        emu.mem_write(old_ptr, struct.pack("<I", NO_OLD_PROTECT))

        before_2000 = emu.get_address_perms(0x2000)

        proc = objman.Process(emu)
        emu.add_object(proc)
        handle = emu.get_object_handle(proc)
        assert handle

        rv = handler.ZwProtectVirtualMemory(
            emu, [handle, base_ptr, size_ptr, PAGE_READWRITE, old_ptr]
        )

        def host_read(addr: int) -> int:
            return int.from_bytes(emu.mem_read(addr, 4), "little")

        assert rv == STATUS_SUCCESS
        # base=0x1003 rounds down, size=1 rounds up: 0x1000 / 0x1000.
        assert host_read(base_ptr) == 0x1000
        assert host_read(size_ptr) == 0x1000
        # Old protection comes from the first affected page (shellcode image
        # page 0x1000 is RWX before the call).
        assert host_read(old_ptr) == PAGE_EXECUTE_READWRITE
        assert emu.get_address_perms(0x1000) == common.PERM_MEM_RW
        # The neighbouring page keeps its previous protection.
        assert emu.get_address_perms(0x2000) == before_2000
    finally:
        se.shutdown()


def _build_failure_cases() -> tuple[bytes, list[list], int]:
    """Drive four failing calls on a read-only private page."""
    asm = _Asm()
    _emit_alloc(asm, size=0x1000, protect=PAGE_READONLY)
    asm.mov_ptr_abs_eax("data", D_TARGET)
    asm.mov_ptr_abs_eax("data", D_ADDR)
    asm.mov_ptr_abs_imm32("data", 0x1000, D_SIZE)
    asm.mov_ptr_abs_imm32("data", NO_OLD_PROTECT, D_OLD)

    # 1. Invalid base protection value.
    _emit_nt_protect(
        asm,
        base_slot=D_ADDR,
        size_slot=D_SIZE,
        old_slot=D_OLD,
        new_protect=0x55,
        handle_imm=0xFFFFFFFF,
    )
    asm.mov_ptr_abs_eax("data", D_RET)

    # 2. Unmapped address.
    asm.mov_ptr_abs_imm32("data", UNMAPPED_ADDRESS, D_ADDR)
    _emit_nt_protect(
        asm,
        base_slot=D_ADDR,
        size_slot=D_SIZE,
        old_slot=D_OLD,
        new_protect=PAGE_READWRITE,
        handle_imm=0xFFFFFFFF,
    )
    asm.mov_ptr_abs_eax("data", D_RET2)

    # 3. Invalid (unresolvable) process handle on a valid range.
    asm.mov_eax_ptr_abs("data", D_TARGET)
    asm.mov_ptr_abs_eax("data", D_ADDR)
    _emit_nt_protect(
        asm,
        base_slot=D_ADDR,
        size_slot=D_SIZE,
        old_slot=D_OLD,
        new_protect=PAGE_READWRITE,
        handle_imm=INVALID_HANDLE,
    )
    asm.mov_ptr_abs_eax("data", D_RET3)

    # 4. Missing OldAccessProtection pointer.
    asm.push_imm32(0)
    asm.push_imm8(PAGE_READWRITE)
    asm.push_abs("data", D_SIZE)
    asm.push_abs("data", D_ADDR)
    asm.push_imm32(0xFFFFFFFF)
    asm.mov_eax_abs("ntprotect")
    asm.call_eax()
    asm.mov_ptr_abs_eax("data", D_RET4)

    asm.ret()

    code = bytes(asm.buf)
    data_offset = len(code)
    code += b"\x00" * D_DATA_SIZE
    return code, asm.patches, data_offset


def test_nt_protect_virtual_memory_rejects_invalid_inputs(config):
    code, patches, data_offset = _build_failure_cases()

    se = Speakeasy(config=config)
    try:
        sc_addr = se.load_shellcode(data=code, arch="x86")
        emu = se.emu
        values = {
            "sc": sc_addr,
            "data": sc_addr + data_offset,
            "alloc": emu.get_proc("kernel32", "VirtualAlloc"),
            "ntprotect": emu.get_proc("ntdll", "NtProtectVirtualMemory"),
        }
        assert all(values.values())
        assert emu.get_address_map(UNMAPPED_ADDRESS) is None
        _apply_patches(emu, sc_addr, patches, values)

        se.run_shellcode(sc_addr)
        report = se.get_report()
        entry = report.entry_points[0]
        assert entry.error is None, entry.error

        data_addr = sc_addr + data_offset

        def read(offset: int) -> int:
            return int.from_bytes(emu.mem_read(data_addr + offset, 4), "little")

        target = read(D_TARGET)
        assert read(D_RET) == STATUS_INVALID_PARAMETER
        assert read(D_RET2) == STATUS_ACCESS_VIOLATION
        assert read(D_RET3) == STATUS_INVALID_HANDLE
        assert read(D_RET4) == STATUS_ACCESS_VIOLATION
        # No failing call may silently change the page or write the old value.
        assert emu.get_address_perms(target) == common.PERM_MEM_READ
        assert read(D_OLD) == NO_OLD_PROTECT
    finally:
        se.shutdown()
