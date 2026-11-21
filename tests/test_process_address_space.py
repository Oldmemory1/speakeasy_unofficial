"""Contract tests for per-process address spaces (FX-012).

``AddressSpace / per_process_isolation`` requires that ``VirtualAllocEx`` and
``WriteProcessMemory`` operate on the **target** process's virtual address
view, not on the caller's single global address space:

* a requested base occupied in the target view fails with
  ``ERROR_INVALID_ADDRESS`` instead of being relocated around the caller's
  image;
* WPM writes the target view only; the caller's PE image is unchanged;
* ``ReadProcessMemory`` reads the target view;
* an invalid process handle returns FALSE/NULL + ``ERROR_INVALID_HANDLE``
  instead of raising;
* same-process WPM writes a read-only page (temporary protection bypass) and
  restores the page protection afterwards;
* unmapped shadow pages fail explicitly instead of fabricating success.

The tests use a synthetic x86 PE32 at ``0x400000`` plus a model-only child
process created from the same image (the representative sample's shape). The
shadow view is bookkeeping: child code is never executed in these tests.
"""

from __future__ import annotations

import struct
from contextlib import contextmanager

import pytest

import speakeasy.common as common
from speakeasy import Speakeasy
from speakeasy.windows import page_protection
from speakeasy.windows.process_memory import (
    ERROR_INVALID_ADDRESS,
    ERROR_NOACCESS,
    ERROR_PARTIAL_COPY,
    ProcessAddressSpace,
    ProcessMemoryError,
)
from speakeasy.winenv.defs.windows import windows as windefs

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000

ERROR_INVALID_HANDLE = windefs.ERROR_INVALID_HANDLE
ERROR_INVALID_PARAMETER = windefs.ERROR_INVALID_PARAMETER

IMAGE_BASE = 0x400000
IMAGE_SIZE = 0x5000
TEXT_RVA = 0x1000
DATA_RVA = 0x2000
FREE_CHILD_BASE = 0x600000
UNMAPPED_CHILD_ADDRESS = 0x900000
INVALID_HANDLE = 0x12345678

PAYLOAD = bytes(range(0x100)) * 4  # 0x400 bytes


def _tiny_pe() -> bytes:
    """Build a minimal PE32 (ImageBase 0x400000) whose entry is xor eax,eax; ret."""
    image = bytearray(0x600)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x40)
    image[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", image, 0x44, 0x14C, 2, 0, 0, 0, 0xE0, 0x0102)
    offset = 0x58

    def put(fmt: str, *values: int) -> None:
        nonlocal offset
        struct.pack_into(fmt, image, offset, *values)
        offset += struct.calcsize(fmt)

    put("<H", 0x10B)  # PE32
    put("<BB", 1, 0)
    put("<I", 0x200)  # SizeOfCode
    put("<I", 0x200)  # SizeOfInitializedData
    put("<I", 0)
    put("<I", TEXT_RVA)  # AddressOfEntryPoint
    put("<I", TEXT_RVA)  # BaseOfCode
    put("<I", DATA_RVA)  # BaseOfData
    put("<I", IMAGE_BASE)
    put("<I", 0x1000)
    put("<I", 0x200)
    put("<HH", 6, 0)
    put("<HH", 0, 0)
    put("<HH", 6, 1)
    put("<I", 0)
    put("<I", IMAGE_SIZE)
    put("<I", 0x200)  # SizeOfHeaders
    put("<I", 0)
    put("<HH", 3, 0)  # console subsystem
    put("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)
    put("<II", 0, 16)
    for _ in range(16):
        put("<II", 0, 0)
    assert offset == 0x58 + 0xE0

    section_offset = 0x138
    for name, vaddr, vsize, raw_size, raw_ptr, chars in (
        (b".text", TEXT_RVA, 0x1000, 0x200, 0x200, 0x60000020),
        (b".data", DATA_RVA, 0x1000, 0x200, 0x400, 0xC0000040),
    ):
        image[section_offset : section_offset + 8] = name.ljust(8, b"\x00")
        struct.pack_into(
            "<IIIIIIHHI",
            image,
            section_offset + 8,
            vsize,
            vaddr,
            raw_size,
            raw_ptr,
            0,
            0,
            0,
            0,
            chars,
        )
        section_offset += 40

    image[0x200:0x203] = b"\x31\xc0\xc3"  # xor eax,eax; ret
    return bytes(image)


@contextmanager
def _running_emulator_with_child(config):
    se = Speakeasy(config=config, argv=[])
    try:
        module = se.load_module(data=_tiny_pe())
        se.run_module(module, all_entrypoints=True)
        report = se.get_report()
        assert report.entry_points[0].error is None, report.entry_points[0].error
        emu = se.emu
        assert module.base == IMAGE_BASE
        child = emu.create_process(path=emu._root_emu_path, child=True)
        assert child.pe_data is not None
        yield se, emu, child
    finally:
        se.shutdown()


def _kernel32(emu):
    return emu.api.load_api_handler("kernel32")


def _parent_buffer(emu, data: bytes) -> int:
    size = max(0x1000, len(data))
    addr = emu.mem_map(size, tag="test.fx012.buffer", perms=common.PERM_MEM_RWX)
    emu.mem_write(addr, data)
    return addr


# ---------------------------------------------------------------------------
# ProcessAddressSpace unit contract
# ---------------------------------------------------------------------------


def test_shadow_image_occupies_image_base_and_rejects_alloc() -> None:
    space = ProcessAddressSpace(pid=1, pointer_bits=32)
    assert space.map_pe_image(_tiny_pe()) == IMAGE_BASE
    assert not space.is_free(IMAGE_BASE, 1)
    assert not space.is_free(IMAGE_BASE, IMAGE_SIZE)

    with pytest.raises(ProcessMemoryError) as excinfo:
        space.virtual_alloc(
            IMAGE_BASE,
            0x6000,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    assert excinfo.value.win_error == ERROR_INVALID_ADDRESS


def test_shadow_read_write_and_protection_bypass() -> None:
    space = ProcessAddressSpace(pid=2, pointer_bits=32)
    space.map_pe_image(_tiny_pe())

    assert space.read(IMAGE_BASE, 2) == b"MZ"
    assert space.write(IMAGE_BASE, PAYLOAD) == len(PAYLOAD)
    assert space.read(IMAGE_BASE, len(PAYLOAD)) == PAYLOAD

    with pytest.raises(ProcessMemoryError) as excinfo:
        space.write(IMAGE_BASE, b"\x00", bypass_protection=False)
    assert excinfo.value.win_error == ERROR_NOACCESS


def test_shadow_unmapped_access_fails_explicitly() -> None:
    space = ProcessAddressSpace(pid=3, pointer_bits=32)
    space.map_pe_image(_tiny_pe())

    with pytest.raises(ProcessMemoryError) as excinfo:
        space.read(UNMAPPED_CHILD_ADDRESS, 0x10)
    assert excinfo.value.win_error == ERROR_NOACCESS

    with pytest.raises(ProcessMemoryError) as excinfo:
        space.write(UNMAPPED_CHILD_ADDRESS, b"\xcc")
    assert excinfo.value.win_error == ERROR_PARTIAL_COPY


def test_shadow_free_base_allocation_and_protection() -> None:
    space = ProcessAddressSpace(pid=4, pointer_bits=32)
    space.map_pe_image(_tiny_pe())

    base = space.virtual_alloc(
        FREE_CHILD_BASE,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    )
    assert base == FREE_CHILD_BASE
    assert space.is_free(FREE_CHILD_BASE, 1) is False
    assert space.write(base, b"abcd", bypass_protection=False) == 4
    assert space.read(base, 4) == b"abcd"

    protected = space.protect(base, 0x1000, PAGE_READONLY)
    assert protected == (FREE_CHILD_BASE, 0x1000, PAGE_READWRITE)
    with pytest.raises(ProcessMemoryError) as excinfo:
        space.write(base, b"x", bypass_protection=False)
    assert excinfo.value.win_error == ERROR_NOACCESS


def test_shadow_rejects_invalid_pe_and_parameters() -> None:
    space = ProcessAddressSpace(pid=5, pointer_bits=32)
    with pytest.raises(ProcessMemoryError) as excinfo:
        space.map_pe_image(b"not a PE image")
    assert excinfo.value.win_error == ERROR_INVALID_PARAMETER

    with pytest.raises(ProcessMemoryError) as excinfo:
        space.virtual_alloc(0x10000, 0x1000, MEM_COMMIT, PAGE_NOACCESS & 0xFE)
    assert excinfo.value.win_error == ERROR_INVALID_PARAMETER


# ---------------------------------------------------------------------------
# API-level contract: target view selection
# ---------------------------------------------------------------------------


def test_virtual_allocex_uses_target_view_not_parent(config) -> None:
    with _running_emulator_with_child(config) as (_se, emu, child):
        k32 = _kernel32(emu)
        handle = emu.get_object_handle(child)

        rv = k32.VirtualAllocEx(
            emu,
            [handle, IMAGE_BASE, 0x6000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE],
        )
        assert rv == 0
        assert rv != 0x40C000
        assert rv != 0x406000
        assert emu.get_last_error() == ERROR_INVALID_ADDRESS

        rv = k32.VirtualAllocEx(
            emu,
            [handle, FREE_CHILD_BASE, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE],
        )
        assert rv == FREE_CHILD_BASE
        # The child allocation exists only in the child's shadow view.
        assert emu.get_address_map(FREE_CHILD_BASE) is None


def test_writeprocessmemory_targets_child_and_preserves_parent(config) -> None:
    with _running_emulator_with_child(config) as (_se, emu, child):
        k32 = _kernel32(emu)
        handle = emu.get_object_handle(child)
        parent_before = emu.mem_read(IMAGE_BASE, len(PAYLOAD))
        src = _parent_buffer(emu, PAYLOAD)
        bytes_written = emu.mem_map(0x1000, tag="test.fx012.written", perms=common.PERM_MEM_RWX)

        rv = k32.WriteProcessMemory(
            emu, [handle, IMAGE_BASE, src, len(PAYLOAD), bytes_written]
        )
        assert rv is True
        assert emu.mem_read(IMAGE_BASE, len(PAYLOAD)) == parent_before
        assert int.from_bytes(emu.mem_read(bytes_written, 4), "little") == len(PAYLOAD)

        dst = _parent_buffer(emu, b"\x00" * len(PAYLOAD))
        rv = k32.ReadProcessMemory(emu, [handle, IMAGE_BASE, dst, len(PAYLOAD), 0])
        assert rv is True
        assert emu.mem_read(dst, len(PAYLOAD)) == PAYLOAD
        # The caller's image is still the original PE, not the payload.
        assert emu.mem_read(IMAGE_BASE, len(PAYLOAD)) == parent_before

        # The representative sample also writes 0x2600 bytes at the parent
        # .text VA 0x401000; the bytes at 0x4018A2 (baseline fault PC) must
        # not change either.
        text_payload = bytes(range(0x100)) * 0x26  # 0x2600 bytes
        text_src = _parent_buffer(emu, text_payload)
        text_before = emu.mem_read(IMAGE_BASE + TEXT_RVA, len(text_payload))
        rv = k32.WriteProcessMemory(
            emu,
            [handle, IMAGE_BASE + TEXT_RVA, text_src, len(text_payload), 0],
        )
        assert rv is True
        assert emu.mem_read(IMAGE_BASE + TEXT_RVA, len(text_payload)) == text_before
        assert emu.mem_read(IMAGE_BASE + TEXT_RVA + 0x8A2, 8) == text_before[0x8A2:0x8AA]


def test_writeprocessmemory_unmapped_target_fails(config) -> None:
    with _running_emulator_with_child(config) as (_se, emu, child):
        k32 = _kernel32(emu)
        handle = emu.get_object_handle(child)
        src = _parent_buffer(emu, PAYLOAD)

        rv = k32.WriteProcessMemory(
            emu, [handle, UNMAPPED_CHILD_ADDRESS, src, len(PAYLOAD), 0]
        )
        assert rv is False
        assert emu.get_last_error() == ERROR_PARTIAL_COPY


def test_invalid_process_handle_returns_error_not_exception(config) -> None:
    with _running_emulator_with_child(config) as (_se, emu, _child):
        k32 = _kernel32(emu)
        src = _parent_buffer(emu, PAYLOAD)

        assert (
            k32.WriteProcessMemory(emu, [INVALID_HANDLE, IMAGE_BASE, src, 4, 0])
            is False
        )
        assert emu.get_last_error() == ERROR_INVALID_HANDLE
        assert k32.VirtualAllocEx(
            emu, [INVALID_HANDLE, 0, 0x1000, MEM_COMMIT, PAGE_READWRITE]
        ) == 0
        assert emu.get_last_error() == ERROR_INVALID_HANDLE
        assert (
            k32.ReadProcessMemory(emu, [INVALID_HANDLE, IMAGE_BASE, src, 4, 0])
            is False
        )
        assert emu.get_last_error() == ERROR_INVALID_HANDLE


# ---------------------------------------------------------------------------
# Same-process WriteProcessMemory semantics
# ---------------------------------------------------------------------------


def test_same_process_wpm_writes_readonly_page_and_restores_protection(config) -> None:
    with _running_emulator_with_child(config) as (_se, emu, _child):
        k32 = _kernel32(emu)
        page = emu.mem_map(0x1000, tag="test.fx012.ro", perms=common.PERM_MEM_RWX)
        emu.mem_write(page, b"\x00" * 0x1000)
        result = page_protection.apply_page_protection(
            emu, page, 0x1000, PAGE_READONLY
        )
        assert result.success is True
        src = _parent_buffer(emu, PAYLOAD)

        rv = k32.WriteProcessMemory(emu, [k32.get_max_int(), page, src, len(PAYLOAD), 0])
        assert rv is True
        assert emu.mem_read(page, len(PAYLOAD)) == PAYLOAD
        assert emu.get_address_perms(page) == common.PERM_MEM_READ
        assert emu.get_address_win_protection(page) == PAGE_READONLY


def test_same_process_wpm_unmapped_target_fails_without_silent_write(config) -> None:
    with _running_emulator_with_child(config) as (_se, emu, _child):
        k32 = _kernel32(emu)
        src = _parent_buffer(emu, PAYLOAD)
        target = 0x9F0000
        assert emu.get_address_map(target) is None

        rv = k32.WriteProcessMemory(emu, [k32.get_max_int(), target, src, 4, 0])
        assert rv is False
        assert emu.get_last_error() == ERROR_PARTIAL_COPY
