"""Phase-3 contract tests for per-process address spaces (FX-012-extended).

FX-012 modelled a target process's virtual-address view as a bookkeeping
``ProcessAddressSpace``.  Phase 3 adds the remaining ``AddressSpace /
per_process_isolation`` semantics:

* bytes observed in a child process's own runtime memory are projected back
  into that process's shadow view (runtime-write backfill), while the parent
  view stays unchanged;
* a process that has a loaded PE module (``process.pe``) but no raw
  ``process.pe_data`` is seeded from the mapped PE image (headers/sections/
  protections) instead of starting with an empty view;
* ``VirtualFreeEx`` releases or decommits pages in the target view; a released
  page fails later WPM/RPM and its base can be allocated again.

Child execution is still ``model_only`` in the engine.  The runtime-write tests
inject controlled bytes through the explicit backfill interface; they never
claim that a child process executed.
"""

from __future__ import annotations

import pytest

import speakeasy.common as common
from speakeasy import Speakeasy
from speakeasy.windows import objman
from speakeasy.windows.page_protection import apply_page_protection
from speakeasy.windows.process_memory import (
    ERROR_INVALID_ADDRESS,
    ERROR_NOACCESS,
    ERROR_PARTIAL_COPY,
    MEM_DECOMMIT,
    MEM_RELEASE,
    ProcessAddressSpace,
    ProcessMemoryError,
)
from speakeasy.winenv.defs.windows import windows as windefs
from tests.test_process_address_space import (
    FREE_CHILD_BASE,
    IMAGE_BASE,
    IMAGE_SIZE,
    INVALID_HANDLE,
    MEM_COMMIT,
    MEM_RESERVE,
    PAGE_READONLY,
    PAGE_READWRITE,
    PAYLOAD,
    TEXT_RVA,
    UNMAPPED_CHILD_ADDRESS,
    _kernel32,
    _parent_buffer,
    _running_emulator_with_child,
    _tiny_pe,
)

PAGE_EXECUTE_READ = windefs.PAGE_EXECUTE_READ
PAGE_WRITECOPY = 0x08
ERROR_INVALID_PARAMETER = windefs.ERROR_INVALID_PARAMETER
ERROR_SUCCESS = windefs.ERROR_SUCCESS


def _tiny_memory_image() -> bytes:
    """Return the memory-mapped form of ``_tiny_pe`` at ImageBase 0x400000."""
    raw = _tiny_pe()
    image = bytearray(IMAGE_SIZE)
    image[0:0x200] = raw[0:0x200]
    image[0x1000:0x1200] = raw[0x200:0x400]  # .text
    image[0x2000:0x2200] = raw[0x400:0x600]  # .data
    return bytes(image)


def _tiny_page_protections() -> dict[int, int]:
    protections = {
        IMAGE_BASE + offset: windefs.PAGE_NOACCESS for offset in range(0, IMAGE_SIZE, 0x1000)
    }
    protections[IMAGE_BASE] = PAGE_READONLY
    protections[IMAGE_BASE + 0x1000] = PAGE_EXECUTE_READ
    protections[IMAGE_BASE + 0x2000] = PAGE_WRITECOPY
    return protections


# ---------------------------------------------------------------------------
# ProcessAddressSpace: runtime-write backfill
# ---------------------------------------------------------------------------


def test_capture_runtime_write_projects_bytes_and_checks_pages() -> None:
    space = ProcessAddressSpace(pid=21, pointer_bits=32)
    space.map_pe_image(_tiny_pe())

    payload = b"\xAA" * 0x20
    assert space.capture_runtime_write(IMAGE_BASE + TEXT_RVA, payload) == len(payload)
    assert space.read(IMAGE_BASE + TEXT_RVA, len(payload)) == payload

    # Image headers are PAGE_READONLY.  The observed-write path may bypass the
    # stale protection, but the strict mode must refuse and must not mutate.
    header_before = space.read(IMAGE_BASE, 2)
    with pytest.raises(ProcessMemoryError) as excinfo:
        space.capture_runtime_write(IMAGE_BASE, b"\x00\x00", bypass_protection=False)
    assert excinfo.value.win_error == ERROR_NOACCESS
    assert space.read(IMAGE_BASE, 2) == header_before

    # Unmapped pages fail explicitly, and a range that crosses into an
    # unmapped page fails before any byte is mutated.
    with pytest.raises(ProcessMemoryError) as excinfo:
        space.capture_runtime_write(UNMAPPED_CHILD_ADDRESS, b"\xCC")
    assert excinfo.value.win_error == ERROR_PARTIAL_COPY

    base = space.virtual_alloc(
        FREE_CHILD_BASE, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    )
    region_before = space.read(base, 0x1000)
    with pytest.raises(ProcessMemoryError) as excinfo:
        space.capture_runtime_write(base + 0xF00, b"\x11" * 0x200)
    assert excinfo.value.win_error == ERROR_PARTIAL_COPY
    assert space.read(base, 0x1000) == region_before


def test_sync_runtime_region_updates_bytes_and_protections() -> None:
    space = ProcessAddressSpace(pid=22, pointer_bits=32)
    base = space.virtual_alloc(
        FREE_CHILD_BASE, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    )
    data = bytes(range(0x100)) * 0x20  # 0x2000 bytes

    assert space.sync_runtime_region(base, data, page_protections=[PAGE_READONLY] * 2) == len(data)
    assert space.read(base, len(data)) == data
    assert space.query(base)["protect"] == PAGE_READONLY
    with pytest.raises(ProcessMemoryError) as excinfo:
        space.write(base, b"x", bypass_protection=False)
    assert excinfo.value.win_error == ERROR_NOACCESS

    # Invalid protection lists fail before mutation.
    with pytest.raises(ProcessMemoryError) as excinfo:
        space.sync_runtime_region(base, b"\x00" * 0x1000, page_protections=[])
    assert excinfo.value.win_error == ERROR_INVALID_PARAMETER
    assert space.read(base, 4) == data[:4]

    # A snapshot larger than the committed region fails explicitly.
    with pytest.raises(ProcessMemoryError) as excinfo:
        space.sync_runtime_region(base + 0x1000, b"\x00" * 0x2000)
    assert excinfo.value.win_error == ERROR_PARTIAL_COPY


# ---------------------------------------------------------------------------
# ProcessAddressSpace: memory-mapped image seeding (pe-only children)
# ---------------------------------------------------------------------------


def test_map_loaded_image_seeds_headers_sections_and_protections() -> None:
    space = ProcessAddressSpace(pid=23, pointer_bits=32)
    image = _tiny_memory_image()
    protections = _tiny_page_protections()

    assert space.map_loaded_image(IMAGE_BASE, IMAGE_SIZE, image, protections) == IMAGE_BASE
    assert space.read(IMAGE_BASE, 2) == b"MZ"
    assert space.read(IMAGE_BASE + TEXT_RVA, 3) == b"\x31\xc0\xc3"

    header = space.query(IMAGE_BASE)
    assert header["is_image"] is True
    assert header["protect"] == PAGE_READONLY
    assert space.query(IMAGE_BASE + TEXT_RVA)["protect"] == PAGE_EXECUTE_READ
    assert space.query(IMAGE_BASE + 0x2000)["protect"] == PAGE_WRITECOPY
    assert space.query(IMAGE_BASE + 0x4000)["protect"] == windefs.PAGE_NOACCESS

    # The image range is occupied in this view.
    with pytest.raises(ProcessMemoryError) as excinfo:
        space.virtual_alloc(
            IMAGE_BASE, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
        )
    assert excinfo.value.win_error == ERROR_INVALID_ADDRESS

    with pytest.raises(ProcessMemoryError) as excinfo:
        space.map_loaded_image(IMAGE_BASE, IMAGE_SIZE, image, protections)
    assert excinfo.value.win_error == ERROR_INVALID_ADDRESS


def test_map_loaded_image_rejects_incomplete_or_short_input() -> None:
    image = _tiny_memory_image()
    protections = _tiny_page_protections()

    missing_page = dict(protections)
    del missing_page[IMAGE_BASE + 0x3000]
    space = ProcessAddressSpace(pid=24, pointer_bits=32)
    with pytest.raises(ProcessMemoryError) as excinfo:
        space.map_loaded_image(IMAGE_BASE, IMAGE_SIZE, image, missing_page)
    assert excinfo.value.win_error == ERROR_INVALID_PARAMETER
    assert space.regions == ()

    with pytest.raises(ProcessMemoryError) as excinfo:
        space.map_loaded_image(IMAGE_BASE, IMAGE_SIZE, b"MZ", protections)
    assert excinfo.value.win_error == ERROR_INVALID_PARAMETER
    assert space.regions == ()


# ---------------------------------------------------------------------------
# ProcessAddressSpace: VirtualFreeEx / unmap
# ---------------------------------------------------------------------------


def test_unmap_release_frees_region_and_rejects_invalid_release() -> None:
    space = ProcessAddressSpace(pid=25, pointer_bits=32)
    base = space.virtual_alloc(
        FREE_CHILD_BASE, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    )
    assert space.unmap(base, 0, MEM_RELEASE) == (base, 0x2000)
    assert space.is_free(base, 0x2000) is True
    with pytest.raises(ProcessMemoryError) as excinfo:
        space.read(base, 1)
    assert excinfo.value.win_error == ERROR_NOACCESS
    with pytest.raises(ProcessMemoryError) as excinfo:
        space.write(base, b"x")
    assert excinfo.value.win_error == ERROR_PARTIAL_COPY

    with pytest.raises(ProcessMemoryError) as excinfo:
        space.unmap(base, 0, MEM_RELEASE)
    assert excinfo.value.win_error == ERROR_INVALID_ADDRESS

    assert space.virtual_alloc(
        base, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    ) == base
    with pytest.raises(ProcessMemoryError) as excinfo:
        space.unmap(base, 0x1000, MEM_RELEASE)
    assert excinfo.value.win_error == ERROR_INVALID_PARAMETER
    with pytest.raises(ProcessMemoryError) as excinfo:
        space.unmap(base + 0x1000, 0, MEM_RELEASE)
    assert excinfo.value.win_error == ERROR_INVALID_ADDRESS
    with pytest.raises(ProcessMemoryError) as excinfo:
        space.unmap(base, 0, 0)
    assert excinfo.value.win_error == ERROR_INVALID_PARAMETER
    with pytest.raises(ProcessMemoryError) as excinfo:
        space.unmap(base, 0, MEM_RELEASE | MEM_DECOMMIT)
    assert excinfo.value.win_error == ERROR_INVALID_PARAMETER


def test_unmap_decommit_keeps_reservation_and_allows_recommit() -> None:
    space = ProcessAddressSpace(pid=26, pointer_bits=32)
    base = space.virtual_alloc(
        FREE_CHILD_BASE, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    )
    assert space.write(base, b"A" * 0x1000, bypass_protection=False) == 0x1000

    assert space.unmap(base, 0x1000, MEM_DECOMMIT) == (base, 0x1000)
    assert space.is_free(base, 0x1000) is False  # reservation retained
    with pytest.raises(ProcessMemoryError) as excinfo:
        space.read(base, 1)
    assert excinfo.value.win_error == ERROR_NOACCESS
    # Even the WriteProcessMemory bypass must not write decommitted pages.
    with pytest.raises(ProcessMemoryError) as excinfo:
        space.write(base, b"x")
    assert excinfo.value.win_error == ERROR_PARTIAL_COPY
    snapshot = space.query(base)
    assert snapshot["state"] == MEM_RESERVE
    assert snapshot["protect"] == windefs.PAGE_NOACCESS

    assert space.virtual_alloc(base, 0x1000, MEM_COMMIT, PAGE_READONLY) == base
    assert space.read(base, 1) == b"\x00"  # recommit zero-fills
    with pytest.raises(ProcessMemoryError) as excinfo:
        space.write(base, b"x", bypass_protection=False)
    assert excinfo.value.win_error == ERROR_NOACCESS
    # The untouched second page keeps its committed contents.
    assert space.read(base + 0x1000, 1) == b"\x00"

    assert space.unmap(base, 0, MEM_RELEASE) == (base, 0x2000)
    assert space.is_free(base, 0x2000) is True


# ---------------------------------------------------------------------------
# API level: runtime write backfill and pe-only shadow seeding
# ---------------------------------------------------------------------------


def test_runtime_write_backfill_visible_to_readprocessmemory(config) -> None:
    with _running_emulator_with_child(config) as (_se, emu, child):
        k32 = _kernel32(emu)
        handle = emu.get_object_handle(child)
        parent_before = emu.mem_read(IMAGE_BASE + TEXT_RVA, len(PAYLOAD))

        assert (
            emu.capture_process_runtime_write(child, IMAGE_BASE + TEXT_RVA, PAYLOAD)
            == len(PAYLOAD)
        )

        dst = _parent_buffer(emu, b"\x00" * len(PAYLOAD))
        rv = k32.ReadProcessMemory(
            emu, [handle, IMAGE_BASE + TEXT_RVA, dst, len(PAYLOAD), 0]
        )
        assert rv is True
        assert emu.mem_read(dst, len(PAYLOAD)) == PAYLOAD
        # The parent/caller view never sees the child's runtime bytes.
        assert emu.mem_read(IMAGE_BASE + TEXT_RVA, len(PAYLOAD)) == parent_before

        # The current process has no shadow view to backfill.
        with pytest.raises(ProcessMemoryError):
            emu.capture_process_runtime_write(
                emu.get_current_process(), IMAGE_BASE, b"\x00"
            )


def test_pe_only_child_shadow_seeded_from_loaded_module(config) -> None:
    se = Speakeasy(config=config, argv=[])
    try:
        module = se.load_module(data=_tiny_pe())
        se.run_module(module, all_entrypoints=True)
        report = se.get_report()
        assert report.entry_points[0].error is None, report.entry_points[0].error
        emu = se.emu

        child_module = emu.load_module_by_name(
            "tinychild",
            emu_path="C:\\Windows\\System32\\tinychild.dll",
            base=0x700000,
            image_data=_tiny_pe(),
        )
        child = emu.new_object(objman.Process)
        child.pe = child_module
        child.pe_data = None
        child.path = "C:\\Windows\\System32\\tinychild.dll"
        emu.child_processes.append(child)

        space = emu.get_process_address_space(child)
        assert space is not None
        base = child_module.base
        assert space.read(base, 2) == b"MZ"
        assert space.read(base + TEXT_RVA, 3) == b"\x31\xc0\xc3"
        assert space.query(base)["is_image"] is True
        assert space.query(base)["protect"] == PAGE_READONLY
        assert space.query(base + TEXT_RVA)["protect"] == PAGE_EXECUTE_READ

        # Cross-process writes target the seeded view only; the loaded module
        # bytes in the shared emulator memory stay unchanged.
        k32 = _kernel32(emu)
        handle = emu.get_object_handle(child)
        global_before = emu.mem_read(base + TEXT_RVA, 3)
        src = _parent_buffer(emu, b"XYZ")
        assert k32.WriteProcessMemory(emu, [handle, base + TEXT_RVA, src, 3, 0]) is True
        assert space.read(base + TEXT_RVA, 3) == b"XYZ"
        assert emu.mem_read(base + TEXT_RVA, 3) == global_before
    finally:
        se.shutdown()


def test_pe_only_child_without_loadable_image_fails_explicitly(config) -> None:
    with _running_emulator_with_child(config) as (_se, emu, _child):
        orphan = emu.new_object(objman.Process)
        orphan.pe = object()  # no base/image_size/sections
        orphan.pe_data = None
        emu.child_processes.append(orphan)

        with pytest.raises(ProcessMemoryError):
            emu.get_process_address_space(orphan)
        # A failed seed is not cached as an empty view.
        assert orphan.address_space is None
        with pytest.raises(ProcessMemoryError):
            emu.get_process_address_space(orphan)


# ---------------------------------------------------------------------------
# API level: VirtualFreeEx
# ---------------------------------------------------------------------------


def test_virtual_free_ex_release_unmaps_child_and_allows_reuse(config) -> None:
    with _running_emulator_with_child(config) as (_se, emu, child):
        k32 = _kernel32(emu)
        handle = emu.get_object_handle(child)
        parent_before = emu.mem_read(IMAGE_BASE, len(PAYLOAD))

        base = k32.VirtualAllocEx(
            emu,
            [handle, FREE_CHILD_BASE, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE],
        )
        assert base == FREE_CHILD_BASE
        src = _parent_buffer(emu, PAYLOAD)
        assert k32.WriteProcessMemory(emu, [handle, base, src, len(PAYLOAD), 0]) is True
        assert emu.get_address_map(base) is None  # never in the parent view

        # Invalid release requests fail without unmapping the region.
        assert k32.VirtualFreeEx(emu, [handle, base, 0x2000, MEM_RELEASE]) is False
        assert emu.get_last_error() == ERROR_INVALID_PARAMETER
        assert k32.VirtualFreeEx(emu, [handle, base + 0x1000, 0, MEM_RELEASE]) is False
        assert emu.get_last_error() == ERROR_INVALID_ADDRESS
        assert k32.VirtualFreeEx(emu, [handle, base, 0, 0]) is False
        assert emu.get_last_error() == ERROR_INVALID_PARAMETER

        assert k32.VirtualFreeEx(emu, [handle, base, 0, MEM_RELEASE]) is True
        assert emu.get_last_error() == ERROR_SUCCESS
        assert emu.mem_read(IMAGE_BASE, len(PAYLOAD)) == parent_before

        # The released pages are unmapped in the target view.
        rpm_dst = _parent_buffer(emu, b"\x00" * 0x10)
        assert k32.ReadProcessMemory(emu, [handle, base, rpm_dst, 0x10, 0]) is False
        assert emu.get_last_error() == ERROR_NOACCESS
        assert k32.WriteProcessMemory(emu, [handle, base, src, 4, 0]) is False
        assert emu.get_last_error() == ERROR_PARTIAL_COPY

        # The base is free again in the target view.
        assert (
            k32.VirtualAllocEx(
                emu,
                [handle, base, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE],
            )
            == base
        )
        assert emu.get_address_map(base) is None


def test_virtual_free_ex_decommit_keeps_child_reservation(config) -> None:
    with _running_emulator_with_child(config) as (_se, emu, child):
        k32 = _kernel32(emu)
        handle = emu.get_object_handle(child)
        base = k32.VirtualAllocEx(
            emu,
            [handle, FREE_CHILD_BASE, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE],
        )
        assert base == FREE_CHILD_BASE
        src = _parent_buffer(emu, PAYLOAD)
        assert k32.WriteProcessMemory(emu, [handle, base, src, 4, 0]) is True

        assert k32.VirtualFreeEx(emu, [handle, base, 0x1000, MEM_DECOMMIT]) is True
        assert emu.get_last_error() == ERROR_SUCCESS
        # Decommitted pages are inaccessible even through WPM.
        assert k32.WriteProcessMemory(emu, [handle, base, src, 4, 0]) is False
        assert emu.get_last_error() == ERROR_PARTIAL_COPY
        # The reservation remains, and MEM_COMMIT can recommit it.
        assert (
            k32.VirtualAllocEx(emu, [handle, base, 0x1000, MEM_COMMIT, PAGE_READWRITE])
            == base
        )
        assert k32.WriteProcessMemory(emu, [handle, base, src, 4, 0]) is True
        assert k32.VirtualFreeEx(emu, [handle, base, 0, MEM_RELEASE]) is True


def test_virtual_free_ex_invalid_handle_returns_error(config) -> None:
    with _running_emulator_with_child(config) as (_se, emu, child):
        k32 = _kernel32(emu)
        assert (
            k32.VirtualFreeEx(emu, [INVALID_HANDLE, FREE_CHILD_BASE, 0, MEM_RELEASE])
            is False
        )
        assert emu.get_last_error() == windefs.ERROR_INVALID_HANDLE

        handle = emu.get_object_handle(child)
        assert k32.VirtualFreeEx(emu, [handle, 0, 0, MEM_RELEASE]) is False
        assert emu.get_last_error() == ERROR_INVALID_PARAMETER


def test_virtual_free_ex_current_process_keeps_existing_semantics(config) -> None:
    with _running_emulator_with_child(config) as (_se, emu, _child):
        k32 = _kernel32(emu)
        page = emu.mem_map(0x1000, tag="test.fx012ext.self", perms=common.PERM_MEM_RWX)
        pseudo = k32.get_max_int()
        # The current-process path delegates to the existing VirtualFree
        # handler, which returns 1 (not a normalized bool).
        assert k32.VirtualFreeEx(emu, [pseudo, page, 0, MEM_RELEASE]) == 1


def test_same_process_wpm_readonly_page_still_works(config) -> None:
    with _running_emulator_with_child(config) as (_se, emu, _child):
        k32 = _kernel32(emu)
        page = emu.mem_map(0x1000, tag="test.fx012ext.ro", perms=common.PERM_MEM_RWX)
        emu.mem_write(page, b"\x00" * 0x1000)
        result = apply_page_protection(emu, page, 0x1000, PAGE_READONLY)
        assert result.success is True
        src = _parent_buffer(emu, PAYLOAD)

        assert k32.WriteProcessMemory(emu, [k32.get_max_int(), page, src, len(PAYLOAD), 0]) is True
        assert emu.mem_read(page, len(PAYLOAD)) == PAYLOAD
        assert emu.get_address_perms(page) == common.PERM_MEM_READ
        assert emu.get_address_win_protection(page) == PAGE_READONLY
