"""Contract tests for the COM task allocator (FX-007).

``PointerAllocator / cotaskmemalloc``: ``CoTaskMemAlloc`` is a memory allocator,
not a status API. ``CoTaskMemAlloc(cb)`` returns a writable block of ``cb``
bytes (or NULL on failure), ``CoTaskMemFree`` releases only blocks owned by the
allocator, and ``CoTaskMemRealloc`` reallocates while preserving the old
contents.

Speakeasy had no ``CoTaskMemAlloc`` handler. The signature database declares
``ret=p`` and the fallback in ``windows/winemu.py`` returns 0 for pointer
returns ("nothing happened"), which an allocator caller reads as a failed
allocation. The CE packer payload does:

```asm
95f73 push 0Ch          ; 12-byte context block
95f75 call allocator    ; ole32.CoTaskMemAlloc by name/signature
95f7d mov esi, eax      ; ESI = allocation result
95f87 call CreateEventA ; returns a real event handle in EAX
95f8c mov [esi], eax    ; write 0 -> invalid_write address=0
```

These tests drive the real handlers from x86 shellcode loaded by the engine; no
batch sample is executed. The reference behaviour is the COM task allocator
contract (Wine ole32/ole2.c ``CoTaskMemAlloc``/``CoTaskMemRealloc`` wrappers over
the IMalloc implementation, plus the win32metadata declarations in
``resources/win32/signatures.json``).
"""

from __future__ import annotations

import struct
from contextlib import contextmanager

import pytest
from unicorn import UcError

import speakeasy.common as common
from speakeasy import Speakeasy

S_RET = 0x00
S_RET2 = 0x04
S_ESI = 0x08
S_HANDLE = 0x0C
S_FOREIGN = 0x10
DATA_SIZE = 0x40

ESI_SENTINEL = 0xCAFEBABE
FOREIGN_PAYLOAD = b"FOREIGN!" + b"\x00" * 8


class _Asm:
    """Small x86 emitter with absolute fixups resolved after loading."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.patches: list[tuple[int, str, int]] = []

    def imm32(self, key: str, addend: int = 0) -> None:
        offset = len(self.buf)
        self.buf += b"\x00\x00\x00\x00"
        self.patches.append((offset, key, addend))

    def push_imm32(self, value: int) -> None:
        self.buf += b"\x68" + struct.pack("<I", value & 0xFFFFFFFF)

    def push_abs(self, key: str, addend: int = 0) -> None:
        self.buf += b"\x68"
        self.imm32(key, addend)

    def push_mem_abs(self, key: str, addend: int = 0) -> None:
        self.buf += b"\xff\x35"
        self.imm32(key, addend)

    def mov_eax_abs(self, key: str, addend: int = 0) -> None:
        self.buf += b"\xb8"
        self.imm32(key, addend)

    def mov_eax_mem_abs(self, key: str, addend: int = 0) -> None:
        self.buf += b"\xa1"
        self.imm32(key, addend)

    def mov_mem_abs_eax(self, key: str, addend: int = 0) -> None:
        self.buf += b"\xa3"
        self.imm32(key, addend)

    def mov_mem_abs_esi(self, key: str, addend: int = 0) -> None:
        self.buf += b"\x89\x35"
        self.imm32(key, addend)

    def mov_esi_imm32(self, value: int) -> None:
        self.buf += b"\xbe" + struct.pack("<I", value & 0xFFFFFFFF)

    def mov_ptr_eax_imm32(self, value: int) -> None:
        self.buf += b"\xc7\x00" + struct.pack("<I", value & 0xFFFFFFFF)

    def mov_ptr_eax_disp_imm32(self, disp: int, value: int) -> None:
        self.buf += b"\xc7\x40" + struct.pack("<B", disp & 0xFF) + struct.pack("<I", value & 0xFFFFFFFF)

    def mov_ptr_esi_eax(self) -> None:
        self.buf += b"\x89\x06"

    def call_eax(self) -> None:
        self.buf += b"\xff\xd0"

    def ret(self) -> None:
        self.buf += b"\xc3"


@contextmanager
def _guest(config, asm: _Asm, *, map_foreign: bool = False):
    """Load and run x86 shellcode, then expose the live emulator for checks.

    ``asm`` patches may reference ``"data"`` (the appended data block) and
    ``"api:<dll>.<name>"`` (the engine's import stub for that export). When
    ``map_foreign`` is true, a separate mapped page is created at
    ``[data + S_FOREIGN]`` so allocator ownership tests can prove foreign
    memory is never freed.
    """
    code = bytes(asm.buf)
    data_offset = len(code)
    code += b"\x00" * DATA_SIZE

    se = Speakeasy(config=config)
    try:
        sc_addr = se.load_shellcode(data=code, arch="x86")
        emu = se.emu
        assert emu is not None
        data_addr = sc_addr + data_offset

        values: dict[str, int] = {"data": data_addr}
        for _offset, key, _addend in asm.patches:
            if key.startswith("api:") and key not in values:
                dll, name = key[4:].split(".", 1)
                values[key] = emu.get_proc(dll, name)
        assert all(values.values()), values

        if map_foreign:
            foreign = emu.mem_map(0x1000, tag="test.fx007.foreign")
            emu.mem_write(foreign, FOREIGN_PAYLOAD)
            emu.mem_write(data_addr + S_FOREIGN, foreign.to_bytes(4, "little"))

        for offset, key, addend in asm.patches:
            emu.mem_write(
                sc_addr + offset,
                struct.pack("<I", (values[key] + addend) & 0xFFFFFFFF),
            )

        se.run_shellcode(sc_addr)
        yield emu, se.get_report(), data_addr
    finally:
        se.shutdown()


def _read_u32(emu, addr: int) -> int:
    return int.from_bytes(emu.mem_read(addr, 4), "little")


def _alloc_call(asm: _Asm, size: int, store: int) -> None:
    asm.push_imm32(size)
    asm.mov_eax_abs("api:ole32.CoTaskMemAlloc")
    asm.call_eax()
    asm.mov_mem_abs_eax("data", store)


def _free_call(asm: _Asm, ptr_slot: int) -> None:
    asm.push_mem_abs("data", ptr_slot)
    asm.mov_eax_abs("api:ole32.CoTaskMemFree")
    asm.call_eax()


def _realloc_call(asm: _Asm, ptr_slot: int, size: int, store: int) -> None:
    asm.push_imm32(size)
    asm.push_mem_abs("data", ptr_slot)
    asm.mov_eax_abs("api:ole32.CoTaskMemRealloc")
    asm.call_eax()
    asm.mov_mem_abs_eax("data", store)


def _task_handler(emu):
    handler, func = emu.api.get_export_func_handler("ole32", "CoTaskMemAlloc")
    assert handler is not None and func is not None
    return handler


def test_cotaskmem_alloc_returns_writable_page_aligned_block(config):
    """The allocator hands back a page-aligned block the guest can write."""
    asm = _Asm()
    _alloc_call(asm, 12, S_RET)
    asm.mov_ptr_eax_imm32(0xAABBCCDD)
    asm.mov_ptr_eax_disp_imm32(8, 0x11223344)
    asm.ret()

    with _guest(config, asm) as (emu, report, data):
        assert report.entry_points[0].error is None, report.entry_points[0].error
        addr = _read_u32(emu, data + S_RET)
        assert addr != 0
        assert addr & 0xFFF == 0
        perms = emu.get_address_perms(addr)
        assert perms & common.PERM_MEM_READ
        assert perms & common.PERM_MEM_WRITE

        block = emu.mem_read(addr, 12)
        assert block[:4] == b"\xdd\xcc\xbb\xaa"
        assert block[4:8] == b"\x00\x00\x00\x00"
        assert block[8:12] == b"\x44\x33\x22\x11"

        handler = _task_handler(emu)
        assert handler._task_allocs[addr] == 12


def test_cotaskmem_alloc_zero_size_returns_non_null_block(config):
    """``CoTaskMemAlloc(0)`` still yields a non-NULL block, as on Windows."""
    asm = _Asm()
    _alloc_call(asm, 0, S_RET)
    asm.ret()

    with _guest(config, asm) as (emu, report, data):
        assert report.entry_points[0].error is None, report.entry_points[0].error
        addr = _read_u32(emu, data + S_RET)
        assert addr != 0
        assert addr & 0xFFF == 0
        assert _task_handler(emu)._task_allocs[addr] == 0


def test_cotaskmem_alloc_oversized_request_returns_null(config):
    """A cb too large for the emulator is a real allocation failure -> NULL."""
    from speakeasy.winenv.api.usermode.ole32 import Ole32

    max_alloc = getattr(Ole32, "MAX_TASK_ALLOC", None)
    assert max_alloc is not None, "Ole32.MAX_TASK_ALLOC is part of the allocator contract"

    asm = _Asm()
    _alloc_call(asm, 0xFFFFFFFF, S_RET)
    _alloc_call(asm, max_alloc + 1, S_RET2)
    asm.ret()

    with _guest(config, asm) as (emu, report, data):
        assert report.entry_points[0].error is None, report.entry_points[0].error
        assert _read_u32(emu, data + S_RET) == 0
        assert _read_u32(emu, data + S_RET2) == 0
        handler = _task_handler(emu)
        assert handler._task_allocs == {}


def test_cotaskmem_realloc_preserves_old_contents(config):
    """Realloc returns a distinct non-zero block and copies the old contents."""
    asm = _Asm()
    _alloc_call(asm, 12, S_RET)
    asm.mov_ptr_eax_imm32(0xAABBCCDD)
    asm.mov_ptr_eax_disp_imm32(4, 0x11223344)
    _realloc_call(asm, S_RET, 32, S_RET2)
    asm.ret()

    with _guest(config, asm) as (emu, report, data):
        assert report.entry_points[0].error is None, report.entry_points[0].error
        old = _read_u32(emu, data + S_RET)
        new = _read_u32(emu, data + S_RET2)
        assert old != 0 and new != 0
        assert new != old
        assert new & 0xFFF == 0
        assert emu.mem_read(new, 8) == b"\xdd\xcc\xbb\xaa\x44\x33\x22\x11"
        with pytest.raises(UcError):
            emu.mem_read(old, 1)

        handler = _task_handler(emu)
        assert old not in handler._task_allocs
        assert handler._task_allocs[new] == 32


def test_cotaskmem_realloc_null_pointer_behaves_like_alloc(config):
    """``CoTaskMemRealloc(NULL, cb)`` allocates a fresh block."""
    asm = _Asm()
    # S_FOREIGN is zero-initialized here (no foreign mapping), so pv = NULL.
    _realloc_call(asm, S_FOREIGN, 16, S_RET)
    asm.ret()

    with _guest(config, asm) as (emu, report, data):
        assert report.entry_points[0].error is None, report.entry_points[0].error
        addr = _read_u32(emu, data + S_RET)
        assert addr != 0
        assert addr & 0xFFF == 0
        assert _task_handler(emu)._task_allocs[addr] == 16


def test_cotaskmem_realloc_unknown_pointer_returns_null(config):
    """A pointer the allocator does not own is not reallocated or freed."""
    asm = _Asm()
    _realloc_call(asm, S_FOREIGN, 16, S_RET)
    asm.ret()

    with _guest(config, asm, map_foreign=True) as (emu, report, data):
        assert report.entry_points[0].error is None, report.entry_points[0].error
        assert _read_u32(emu, data + S_RET) == 0
        foreign = _read_u32(emu, data + S_FOREIGN)
        assert emu.mem_read(foreign, len(FOREIGN_PAYLOAD)) == FOREIGN_PAYLOAD
        assert _task_handler(emu)._task_allocs == {}


def test_cotaskmem_realloc_zero_size_frees_block(config):
    """``CoTaskMemRealloc(pv, 0)`` frees the tracked block and returns NULL."""
    asm = _Asm()
    _alloc_call(asm, 12, S_RET)
    _realloc_call(asm, S_RET, 0, S_RET2)
    asm.ret()

    with _guest(config, asm) as (emu, report, data):
        assert report.entry_points[0].error is None, report.entry_points[0].error
        old = _read_u32(emu, data + S_RET)
        assert old != 0
        assert _read_u32(emu, data + S_RET2) == 0
        with pytest.raises(UcError):
            emu.mem_read(old, 1)
        assert _task_handler(emu)._task_allocs == {}


def test_cotaskmem_free_releases_only_owned_blocks(config):
    """Owned memory is unmapped once; double free is a no-op."""
    asm = _Asm()
    _alloc_call(asm, 12, S_RET)
    _free_call(asm, S_RET)
    _free_call(asm, S_RET)
    asm.ret()

    with _guest(config, asm) as (emu, report, data):
        assert report.entry_points[0].error is None, report.entry_points[0].error
        addr = _read_u32(emu, data + S_RET)
        assert addr != 0
        with pytest.raises(UcError):
            emu.mem_read(addr, 1)
        assert _task_handler(emu)._task_allocs == {}


def test_cotaskmem_free_leaves_foreign_mapped_memory_alone(config):
    """Freeing an untracked pointer must not unmap image or foreign memory."""
    asm = _Asm()
    _free_call(asm, S_FOREIGN)
    asm.ret()

    with _guest(config, asm, map_foreign=True) as (emu, report, data):
        assert report.entry_points[0].error is None, report.entry_points[0].error
        foreign = _read_u32(emu, data + S_FOREIGN)
        assert emu.mem_read(foreign, len(FOREIGN_PAYLOAD)) == FOREIGN_PAYLOAD
        assert emu.get_address_map(foreign) is not None


def test_ce_mechanism_reproducer(config):
    """The 0x95f73..0x95f8c CE pattern: allocation -> CreateEventA -> store."""
    asm = _Asm()
    _alloc_call(asm, 12, S_RET)
    asm.mov_eax_mem_abs("data", S_RET)
    asm.buf += b"\x89\xc6"  # mov esi, eax
    asm.push_imm32(0)
    asm.push_imm32(0)
    asm.push_imm32(0)
    asm.push_imm32(0)
    asm.mov_eax_abs("api:kernel32.CreateEventA")
    asm.call_eax()
    asm.mov_ptr_esi_eax()
    asm.mov_mem_abs_eax("data", S_HANDLE)
    asm.mov_mem_abs_esi("data", S_ESI)
    asm.ret()

    with _guest(config, asm) as (emu, report, data):
        assert report.entry_points[0].error is None, report.entry_points[0].error
        ptr = _read_u32(emu, data + S_RET)
        handle = _read_u32(emu, data + S_HANDLE)
        esi = _read_u32(emu, data + S_ESI)
        assert ptr != 0
        assert ptr & 0xFFF == 0
        assert handle != 0
        assert esi == ptr
        assert _read_u32(emu, ptr) == handle


def test_create_event_returns_nonzero_and_preserves_esi(config):
    """Regression: CreateEventA keeps returning a handle and never edits ESI."""
    asm = _Asm()
    asm.mov_esi_imm32(ESI_SENTINEL)
    asm.push_imm32(0)
    asm.push_imm32(0)
    asm.push_imm32(0)
    asm.push_imm32(0)
    asm.mov_eax_abs("api:kernel32.CreateEventA")
    asm.call_eax()
    asm.mov_mem_abs_eax("data", S_HANDLE)
    asm.mov_mem_abs_esi("data", S_ESI)
    asm.ret()

    with _guest(config, asm) as (emu, report, data):
        assert report.entry_points[0].error is None, report.entry_points[0].error
        assert _read_u32(emu, data + S_HANDLE) != 0
        assert _read_u32(emu, data + S_ESI) == ESI_SENTINEL


def test_unrelated_ret_p_api_still_returns_null(config):
    """The fix is not a global ret=p policy: an unhandled pointer API returns 0."""
    asm = _Asm()
    asm.push_imm32(0)
    asm.mov_eax_abs("api:kernel32.AddDllDirectory")
    asm.call_eax()
    asm.mov_mem_abs_eax("data", S_RET)
    asm.ret()

    with _guest(config, asm) as (emu, report, data):
        assert report.entry_points[0].error is None, report.entry_points[0].error
        assert _read_u32(emu, data + S_RET) == 0
