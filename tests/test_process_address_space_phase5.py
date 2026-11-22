"""Phase-5 contract tests for per-process address spaces (FX12-extended-rv2).

``AddressSpace / per_process_isolation`` phase 5 closes the residual gaps of
FX12-extended-rv1:

* child-attributed runtime mappings outside the mapped image are projected into
  the child's shadow view and become visible through ``ReadProcessMemory``;
* ``VirtualAllocEx`` reservations are modeled as reserved-but-uncommitted
  shadow pages, can be given physical backing for one explicit child run, and
  never leak a global mapping after the run;
* runtime ``PAGE_*`` changes are synchronized into the shadow, and
  ``VirtualProtectEx(child, ...)`` never mutates the caller's/global page.

The tests combine unit contracts on :class:`ProcessAddressSpace` with the real
opt-in child scheduler (synthetic x86 PE32) and controlled emulator stubs for
paths that a minimal synthetic PE cannot reach without an import table.
"""

from __future__ import annotations

import struct
from types import SimpleNamespace

import pytest

import speakeasy.common as common
from speakeasy.windows.child_execution import (
    ChildExecutionOptions,
    ChildExecutionState,
    ChildOutcome,
    LoadedChildImage,
    create_engine_child_scheduler,
)
from speakeasy.windows.child_execution.runtime_backend import (
    EngineChildExecutionBackend,
)
from speakeasy.windows.page_protection import (
    apply_page_protection,
    emulator_page_win_protection,
)
from speakeasy.windows.process_memory import (
    ERROR_INVALID_ADDRESS,
    ERROR_NOACCESS,
    ERROR_PARTIAL_COPY,
    MAX_SHADOW_REGION_SIZE,
    MEM_COMMIT,
    MEM_RESERVE,
    ProcessAddressSpace,
    ProcessMemoryError,
)
from speakeasy.winenv.defs.windows import windows as windefs
from tests.test_child_execution_runtime_backfill import (
    CHILD_IMAGE_SIZE,
    CHILD_PAYLOAD,
    PAGE_SIZE,
    _drain,
    _prepare_child,
    _request,
    _target,
)
from tests.test_process_address_space import (
    FREE_CHILD_BASE,
    IMAGE_BASE,
    IMAGE_SIZE,
    INVALID_HANDLE,
    PAGE_READONLY,
    PAGE_READWRITE,
    TEXT_RVA,
    _kernel32,
    _parent_buffer,
    _running_emulator_with_child,
    _tiny_pe,
)

PAGE_NOACCESS = windefs.PAGE_NOACCESS
PAGE_EXECUTE_READ = windefs.PAGE_EXECUTE_READ
PAGE_EXECUTE_READWRITE = windefs.PAGE_EXECUTE_READWRITE
ERROR_INVALID_HANDLE = windefs.ERROR_INVALID_HANDLE
ERROR_INVALID_PARAMETER = windefs.ERROR_INVALID_PARAMETER

CHILD_ENTRY_RVA = 0x1000
SHADOW_IMAGE_BASE = IMAGE_BASE
OUTSIDE_TARGET = 0x51000
UNCHANGED_CHILD_MAP = 0x52000


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _child_pe_writing_absolute(target: int, payload: bytes = CHILD_PAYLOAD) -> bytes:
    """Build a tiny x86 PE32 whose entry writes ``payload`` to ``target``.

    Entry code (RVA 0x1000)::

        mov dword [target], imm32    ; C7 05 <target> <payload>
        ret                          ; C3

    The absolute address makes the child write independent of relocation, so
    the test observes a runtime page outside the mapped image.
    """

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
    put("<I", CHILD_ENTRY_RVA)  # AddressOfEntryPoint
    put("<I", CHILD_ENTRY_RVA)  # BaseOfCode
    put("<I", 0x2000)  # BaseOfData
    put("<I", IMAGE_BASE)  # preferred ImageBase; forces relocation
    put("<I", 0x1000)
    put("<I", 0x200)
    put("<HH", 6, 0)
    put("<HH", 0, 0)
    put("<HH", 6, 1)
    put("<I", 0)
    put("<I", CHILD_IMAGE_SIZE)
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
        (b".text", CHILD_ENTRY_RVA, 0x1000, 0x200, 0x200, 0x60000020),
        (b".data", 0x2000, 0x1000, 0x200, 0x400, 0xC0000040),
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

    code = b"\xC7\x05" + int(target).to_bytes(4, "little") + payload + b"\xC3"
    image[0x200 : 0x200 + len(code)] = code
    return bytes(image)


def _shadow_image_bytes(space: ProcessAddressSpace) -> bytes:
    """Return the shadow bytes of the seeded image (for diffing in stubs)."""

    for region in space.regions:
        if region.is_image:
            return bytes(region.data[:IMAGE_SIZE]).ljust(IMAGE_SIZE, b"\x00")
    raise AssertionError("shadow view has no image region")


class _NoOpHook:
    """Hook handle that only records its disable."""

    def __init__(self) -> None:
        self.disabled = False

    def disable(self) -> None:
        self.disabled = True


class _RecordingSpace(ProcessAddressSpace):
    """Shadow view that records every projection interface call."""

    def __init__(self, pid: int) -> None:
        super().__init__(pid=pid, pointer_bits=32)
        self.sync_region_calls: list[tuple[int, int]] = []
        self.sync_protection_calls: list[tuple[int, tuple[int, ...]]] = []
        self.adopt_calls: list[tuple[int, int, str]] = []

    def sync_runtime_region(self, base, data, *, page_protections=None):  # type: ignore[override]
        self.sync_region_calls.append((base, len(data)))
        return super().sync_runtime_region(base, data, page_protections=page_protections)

    def sync_runtime_protections(self, base, page_protections):  # type: ignore[override]
        self.sync_protection_calls.append((base, tuple(page_protections)))
        return super().sync_runtime_protections(base, page_protections)

    def adopt_runtime_region(self, base, size, data, **kwargs):  # type: ignore[override]
        self.adopt_calls.append((base, size, kwargs.get("tag", "")))
        return super().adopt_runtime_region(base, size, data, **kwargs)


class _ImageRuntimeEmulator:
    """Controlled emulator that exposes one relocated image and its protections.

    ``change_protection`` makes ``start()`` record a runtime-only protection
    change (no bytes change), mirroring a guest ``VirtualProtect`` call on the
    executing child's image page.
    """

    def __init__(
        self,
        process,
        thread,
        space: ProcessAddressSpace,
        *,
        runtime_base: int,
        image_size: int,
        change_protection: bool,
    ) -> None:
        self.curr_process = process
        self.curr_thread = thread
        self.run_queue: list[object] = []
        self.runs: list[object] = []
        self.instruction_budget_exhausted = False
        self.page_size = PAGE_SIZE
        self._space = space
        self._runtime_base = runtime_base
        self._image_size = image_size
        self._before = _shadow_image_bytes(space)
        self._after = self._before
        self._change_protection = change_protection
        # Runtime protections start identical to the seeded shadow image so a
        # test only observes the change it explicitly introduces.
        self._win_protects: dict[int, int] = {}
        self._perms: dict[int, int] = {}
        for page_offset in range(0, image_size, PAGE_SIZE):
            shadow_page = SHADOW_IMAGE_BASE + page_offset
            self._win_protects[runtime_base + page_offset] = space.query(shadow_page)["protect"]
            self._perms[runtime_base + page_offset] = common.PERM_MEM_RWX
        self._mapped = True
        self.protection_changed = False

    def get_executing_process_address_space(self, process):
        assert process is self.curr_process
        return self._space

    def get_mem_maps(self):
        if not self._mapped:
            return []
        return [
            SimpleNamespace(
                base=self._runtime_base,
                size=self._image_size,
                tag=f"emu.module.child.0x{self._runtime_base:x}",
                prot=common.PERM_MEM_RWX,
                flags=0,
                free=False,
                process=None,
                is_image=True,
            )
        ]

    def get_address_map(self, address: int):
        if self._mapped and self._runtime_base <= address < self._runtime_base + self._image_size:
            return self.get_mem_maps()[0]
        return None

    def get_address_win_protection(self, address: int):
        page = address & ~(PAGE_SIZE - 1)
        return self._win_protects.get(page)

    def get_address_perms(self, address: int):
        if self.get_address_map(address) is None:
            return None
        page = address & ~(PAGE_SIZE - 1)
        return self._perms.get(page, common.PERM_MEM_RWX)

    def mem_read(self, address: int, size: int) -> bytes:
        assert address == self._runtime_base
        assert size == self._image_size
        return self._after if self.protection_changed else self._before

    def materialize_process_shadow(self, process):
        assert process is self.curr_process
        self.materialize_calls = getattr(self, "materialize_calls", 0) + 1
        return ()

    def release_materialized_process_shadow(self, regions) -> None:
        assert tuple(regions) == ()

    def add_code_hook(self, _callback, *, begin: int, end: int) -> _NoOpHook:
        assert end >= begin
        return _NoOpHook()

    def add_run(self, run: object) -> None:
        self.run_queue.append(run)
        self.runs.append(run)

    def start(self) -> None:
        run = self.runs[-1]
        run.num_apis = 0
        if self._change_protection:
            self.protection_changed = True
            page = self._runtime_base + CHILD_ENTRY_RVA
            self._win_protects[page] = PAGE_READONLY
            self._perms[page] = common.PERM_MEM_READ

    def stop(self) -> None:
        """Accept stop requests without changing state."""


class _NewMapAdoptionEmulator(_ImageRuntimeEmulator):
    """Report one child-attributed map created only after the run."""

    def __init__(self, process, thread, space: ProcessAddressSpace, *, runtime_base: int, image_size: int):
        super().__init__(
            process,
            thread,
            space,
            runtime_base=runtime_base,
            image_size=image_size,
            change_protection=False,
        )
        self._new_map: SimpleNamespace | None = None
        self.adopted_after_run = False

    def get_mem_maps(self):
        maps = super().get_mem_maps()
        if self._new_map is not None:
            maps = maps + [self._new_map]
        return maps

    def get_address_map(self, address: int):
        if self._new_map is not None and self._new_map.base <= address < self._new_map.base + self._new_map.size:
            return self._new_map
        return super().get_address_map(address)

    def get_address_win_protection(self, address: int):
        page = address & ~(PAGE_SIZE - 1)
        return self._win_protects.get(page)

    def get_address_perms(self, address: int):
        mm = self.get_address_map(address)
        if mm is None:
            return None
        return mm.prot

    def mem_read(self, address: int, size: int) -> bytes:
        if self._new_map is not None and address == self._new_map.base:
            assert size == self._new_map.size
            return self.payload
        return super().mem_read(address, size)

    def start(self) -> None:
        super().start()
        self.payload = CHILD_PAYLOAD + b"\x00" * (PAGE_SIZE - len(CHILD_PAYLOAD))
        self._new_map = SimpleNamespace(
            base=0x700000,
            size=PAGE_SIZE,
            tag="api.VirtualAlloc.test.0x700000",
            prot=common.PERM_MEM_READ | common.PERM_MEM_WRITE,
            flags=PAGE_READWRITE,
            free=False,
            process=self.curr_process,
            is_image=False,
        )
        self.adopted_after_run = True


class _MaterializedFreeEmulator:
    """Materialize one shadow region, then free it during the synthetic run."""

    def __init__(self, process, thread, space: ProcessAddressSpace, *, runtime_base: int, image_size: int):
        self.curr_process = process
        self.curr_thread = thread
        self.run_queue: list[object] = []
        self.runs: list[object] = []
        self.instruction_budget_exhausted = False
        self.page_size = PAGE_SIZE
        self._space = space
        self._runtime_base = runtime_base
        self._image_size = image_size
        self._before = _shadow_image_bytes(space)
        self.materialized_base = 0x50000
        self.materialized_size = PAGE_SIZE
        self.materialized_tag = f"emu.child_shadow.pid{process.pid}"
        self.materialize_calls = 0
        self.release_calls = 0
        self._map_present = False
        self._win_protects: dict[int, int] = {}
        self._perms: dict[int, int] = {}
        for page_offset in range(0, image_size, PAGE_SIZE):
            shadow_page = SHADOW_IMAGE_BASE + page_offset
            self._win_protects[runtime_base + page_offset] = space.query(shadow_page)["protect"]
            self._perms[runtime_base + page_offset] = common.PERM_MEM_RWX

    def get_executing_process_address_space(self, process):
        assert process is self.curr_process
        return self._space

    def get_mem_maps(self):
        return []

    def get_address_map(self, address: int):
        if self._runtime_base <= address < self._runtime_base + self._image_size:
            return SimpleNamespace(
                base=self._runtime_base,
                size=self._image_size,
                tag="emu.module.child",
                prot=common.PERM_MEM_RWX,
                flags=0,
                free=False,
                process=None,
                is_image=True,
            )
        if self._map_present and self.materialized_base <= address < self.materialized_base + self.materialized_size:
            return SimpleNamespace(
                base=self.materialized_base,
                size=self.materialized_size,
                tag=self.materialized_tag,
                prot=common.PERM_MEM_RW,
                flags=PAGE_READWRITE,
                free=False,
                process=self.curr_process,
                is_image=False,
            )
        return None

    def get_address_win_protection(self, address: int):
        page = address & ~(PAGE_SIZE - 1)
        return self._win_protects.get(page)

    def get_address_perms(self, address: int):
        page = address & ~(PAGE_SIZE - 1)
        return self._perms.get(page)

    def mem_read(self, address: int, size: int) -> bytes:
        assert address == self._runtime_base
        assert size == self._image_size
        return self._before

    def materialize_process_shadow(self, process):
        assert process is self.curr_process
        self.materialize_calls += 1
        self._map_present = True
        return (
            SimpleNamespace(
                base=self.materialized_base,
                size=self.materialized_size,
                tag=self.materialized_tag,
            ),
        )

    def release_materialized_process_shadow(self, regions) -> None:
        self.release_calls += 1
        released = tuple(regions)
        assert len(released) == 1
        assert released[0].base == self.materialized_base
        assert released[0].size == self.materialized_size
        assert released[0].tag == self.materialized_tag
        assert self.get_address_map(self.materialized_base) is None

    def add_code_hook(self, _callback, *, begin: int, end: int) -> _NoOpHook:
        assert end >= begin
        return _NoOpHook()

    def add_run(self, run: object) -> None:
        self.run_queue.append(run)
        self.runs.append(run)

    def start(self) -> None:
        run = self.runs[-1]
        run.num_apis = 0
        self._map_present = False  # the child freed the materialized mapping

    def stop(self) -> None:
        """Accept stop requests without changing state."""


def _loaded_image(runtime_base: int, image_size: int) -> LoadedChildImage:
    return LoadedChildImage(
        request_launch_id="runtime-backfill-child",
        module=SimpleNamespace(
            base=runtime_base,
            image_size=image_size,
            emu_path=r"C:\probe\child.exe",
        ),
        image_base=runtime_base,
        entrypoint_address=runtime_base + CHILD_ENTRY_RVA,
    )


def _context(process, thread, runtime_base: int):
    return SimpleNamespace(
        process=process,
        thread=thread,
        run=SimpleNamespace(
            start_addr=runtime_base + CHILD_ENTRY_RVA,
            num_apis=0,
            error=None,
        ),
    )


def _budget_hooks():
    return SimpleNamespace(
        observe_api=lambda: True,
        observe_instructions=lambda count=1: True,
        should_continue=lambda: True,
    )


def _backend_request():
    """Build the launch request shared by the controlled backend stubs."""

    return _request(b"fx12rv2")


# ---------------------------------------------------------------------------
# Unit: reserve-only shadow semantics
# ---------------------------------------------------------------------------


def test_reserve_only_pages_are_uncommitted_until_mem_commit() -> None:
    space = ProcessAddressSpace(pid=501, pointer_bits=32)
    base = space.virtual_alloc(FREE_CHILD_BASE, 0x2000, MEM_RESERVE, PAGE_READWRITE)

    assert base == FREE_CHILD_BASE
    snapshot = space.query(base)
    assert snapshot["state"] == MEM_RESERVE
    assert snapshot["protect"] == PAGE_NOACCESS
    assert snapshot["allocation_protect"] == PAGE_READWRITE
    assert space.is_free(base, 1) is False

    with pytest.raises(ProcessMemoryError) as excinfo:
        space.read(base, 1)
    assert excinfo.value.win_error == ERROR_NOACCESS
    with pytest.raises(ProcessMemoryError) as excinfo:
        space.write(base, b"x")
    assert excinfo.value.win_error == ERROR_PARTIAL_COPY

    assert space.virtual_alloc(base, 0x1000, MEM_COMMIT, PAGE_READONLY) == base
    snapshot = space.query(base)
    assert snapshot["state"] == MEM_COMMIT
    assert snapshot["protect"] == PAGE_READONLY
    assert space.read(base, 1) == b"\x00"  # commit zero-fills
    with pytest.raises(ProcessMemoryError) as excinfo:
        space.write(base, b"x", bypass_protection=False)
    assert excinfo.value.win_error == ERROR_NOACCESS
    # The second page is still reserved only.
    assert space.query(base + PAGE_SIZE)["state"] == MEM_RESERVE


def test_mem_commit_reserve_keeps_committed_behavior() -> None:
    space = ProcessAddressSpace(pid=502, pointer_bits=32)
    base = space.virtual_alloc(
        FREE_CHILD_BASE, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    )
    assert space.query(base)["state"] == MEM_COMMIT
    assert space.write(base, b"abcd", bypass_protection=False) == 4
    assert space.read(base, 4) == b"abcd"


# ---------------------------------------------------------------------------
# Unit: adopt_runtime_region
# ---------------------------------------------------------------------------


def test_adopt_runtime_region_creates_and_overwrites() -> None:
    space = ProcessAddressSpace(pid=503, pointer_bits=32)
    payload = bytes(range(0x100)) * 16  # 0x1000 bytes
    region = space.adopt_runtime_region(
        FREE_CHILD_BASE,
        PAGE_SIZE,
        payload,
        page_protections=[PAGE_READWRITE],
        allocation_protect=PAGE_READWRITE,
        tag="api.VirtualAlloc.test",
    )

    assert region.base == FREE_CHILD_BASE
    assert region.size == PAGE_SIZE
    assert region.is_image is False
    assert region.tag == "api.VirtualAlloc.test"
    assert space.read(FREE_CHILD_BASE, PAGE_SIZE) == payload
    snapshot = space.query(FREE_CHILD_BASE)
    assert snapshot["protect"] == PAGE_READWRITE
    assert snapshot["allocation_protect"] == PAGE_READWRITE
    assert snapshot["state"] == MEM_COMMIT

    replacement = b"\xAA" * PAGE_SIZE
    returned = space.adopt_runtime_region(
        FREE_CHILD_BASE,
        PAGE_SIZE,
        replacement,
        page_protections=[PAGE_READONLY],
        allocation_protect=PAGE_READWRITE,
        tag="api.VirtualAlloc.test",
    )
    assert returned is region
    assert space.read(FREE_CHILD_BASE, PAGE_SIZE) == replacement
    assert space.query(FREE_CHILD_BASE)["protect"] == PAGE_READONLY
    with pytest.raises(ProcessMemoryError) as excinfo:
        space.write(FREE_CHILD_BASE, b"x", bypass_protection=False)
    assert excinfo.value.win_error == ERROR_NOACCESS


def test_adopt_runtime_region_rejects_invalid_input_without_mutation() -> None:
    space = ProcessAddressSpace(pid=504, pointer_bits=32)
    payload = b"\x00" * PAGE_SIZE

    with pytest.raises(ProcessMemoryError) as excinfo:
        space.adopt_runtime_region(
            FREE_CHILD_BASE + 1,
            PAGE_SIZE,
            payload,
            page_protections=[PAGE_READWRITE],
            allocation_protect=PAGE_READWRITE,
        )
    assert excinfo.value.win_error == ERROR_INVALID_ADDRESS

    with pytest.raises(ProcessMemoryError) as excinfo:
        space.adopt_runtime_region(
            FREE_CHILD_BASE,
            PAGE_SIZE,
            b"\x00",
            page_protections=[PAGE_READWRITE],
            allocation_protect=PAGE_READWRITE,
        )
    assert excinfo.value.win_error == ERROR_INVALID_PARAMETER

    with pytest.raises(ProcessMemoryError) as excinfo:
        space.adopt_runtime_region(
            FREE_CHILD_BASE,
            PAGE_SIZE,
            payload,
            page_protections=[],
            allocation_protect=PAGE_READWRITE,
        )
    assert excinfo.value.win_error == ERROR_INVALID_PARAMETER

    with pytest.raises(ProcessMemoryError) as excinfo:
        space.adopt_runtime_region(
            FREE_CHILD_BASE,
            PAGE_SIZE,
            payload,
            page_protections=[0x7F],
            allocation_protect=PAGE_READWRITE,
        )
    assert excinfo.value.win_error == ERROR_INVALID_PARAMETER

    with pytest.raises(ProcessMemoryError) as excinfo:
        space.adopt_runtime_region(
            FREE_CHILD_BASE,
            PAGE_SIZE,
            payload,
            page_protections=[PAGE_READWRITE],
            allocation_protect=0x7F,
        )
    assert excinfo.value.win_error == ERROR_INVALID_PARAMETER

    # Misaligned size is an address error, validated before allocation.
    with pytest.raises(ProcessMemoryError) as excinfo:
        space.adopt_runtime_region(
            FREE_CHILD_BASE,
            0x1800,
            b"\x00" * 0x1800,
            page_protections=[PAGE_READWRITE, PAGE_READWRITE],
            allocation_protect=PAGE_READWRITE,
        )
    assert excinfo.value.win_error == ERROR_INVALID_ADDRESS

    # Oversize is rejected without allocating host memory.
    with pytest.raises(ProcessMemoryError) as excinfo:
        space.adopt_runtime_region(
            FREE_CHILD_BASE,
            MAX_SHADOW_REGION_SIZE + PAGE_SIZE,
            b"",
            page_protections=[],
            allocation_protect=PAGE_READWRITE,
        )
    assert excinfo.value.win_error == ERROR_INVALID_ADDRESS

    assert space.regions == ()
    assert space.is_free(FREE_CHILD_BASE, PAGE_SIZE) is True


def test_adopt_runtime_region_rejects_overlap_and_size_mismatch() -> None:
    space = ProcessAddressSpace(pid=505, pointer_bits=32)
    space.virtual_alloc(
        FREE_CHILD_BASE, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    )

    with pytest.raises(ProcessMemoryError) as excinfo:
        space.adopt_runtime_region(
            FREE_CHILD_BASE,
            PAGE_SIZE,
            b"\x00" * PAGE_SIZE,
            page_protections=[PAGE_READWRITE],
            allocation_protect=PAGE_READWRITE,
        )
    assert excinfo.value.win_error == ERROR_INVALID_ADDRESS
    assert space.query(FREE_CHILD_BASE)["size"] == 0x2000

    with pytest.raises(ProcessMemoryError) as excinfo:
        space.adopt_runtime_region(
            FREE_CHILD_BASE + PAGE_SIZE,
            PAGE_SIZE,
            b"\x00" * PAGE_SIZE,
            page_protections=[PAGE_READWRITE],
            allocation_protect=PAGE_READWRITE,
        )
    assert excinfo.value.win_error == ERROR_INVALID_ADDRESS


# ---------------------------------------------------------------------------
# Unit: sync_runtime_protections
# ---------------------------------------------------------------------------


def test_sync_runtime_protections_changes_protection_without_bytes() -> None:
    space = ProcessAddressSpace(pid=506, pointer_bits=32)
    base = space.virtual_alloc(
        FREE_CHILD_BASE, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    )
    payload = bytes(range(0x100)) * 0x20
    assert space.write(base, payload, bypass_protection=False) == len(payload)

    updated = space.sync_runtime_protections(base, [PAGE_READONLY, PAGE_EXECUTE_READ])
    assert updated == 2
    assert space.query(base)["protect"] == PAGE_READONLY
    assert space.query(base + PAGE_SIZE)["protect"] == PAGE_EXECUTE_READ
    assert space.read(base, len(payload)) == payload  # bytes untouched


def test_sync_runtime_protections_rejects_invalid_ranges_without_mutation() -> None:
    space = ProcessAddressSpace(pid=507, pointer_bits=32)
    base = space.virtual_alloc(
        FREE_CHILD_BASE, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    )
    reserved = space.virtual_alloc(
        FREE_CHILD_BASE + 0x10000, PAGE_SIZE, MEM_RESERVE, PAGE_READWRITE
    )

    with pytest.raises(ProcessMemoryError) as excinfo:
        space.sync_runtime_protections(base, [])
    assert excinfo.value.win_error == ERROR_INVALID_PARAMETER

    with pytest.raises(ProcessMemoryError) as excinfo:
        space.sync_runtime_protections(base, [PAGE_READWRITE, PAGE_READWRITE])
    assert excinfo.value.win_error == ERROR_INVALID_ADDRESS  # second page is unmapped

    with pytest.raises(ProcessMemoryError) as excinfo:
        space.sync_runtime_protections(base, [0x7F])
    assert excinfo.value.win_error == ERROR_INVALID_PARAMETER

    with pytest.raises(ProcessMemoryError) as excinfo:
        space.sync_runtime_protections(base + 1, [PAGE_READONLY])
    assert excinfo.value.win_error == ERROR_INVALID_ADDRESS

    with pytest.raises(ProcessMemoryError) as excinfo:
        space.sync_runtime_protections(0x900000, [PAGE_READONLY])
    assert excinfo.value.win_error == ERROR_INVALID_ADDRESS

    with pytest.raises(ProcessMemoryError) as excinfo:
        space.sync_runtime_protections(reserved, [PAGE_READONLY])
    assert excinfo.value.win_error == ERROR_PARTIAL_COPY

    assert space.query(base)["protect"] == PAGE_READWRITE


# ---------------------------------------------------------------------------
# Unit: emulator_page_win_protection precedence
# ---------------------------------------------------------------------------


def test_emulator_page_win_protection_precedence(config) -> None:
    with _running_emulator_with_child(config) as (_se, emu, _child):
        page = emu.mem_map(
            PAGE_SIZE,
            tag="test.fx12rv2.prec",
            perms=common.PERM_MEM_READ | common.PERM_MEM_WRITE,
            flags=PAGE_READWRITE,
        )
        assert emulator_page_win_protection(emu, page) == PAGE_READWRITE

        result = apply_page_protection(emu, page, PAGE_SIZE, PAGE_READONLY)
        assert result.success is True
        assert emulator_page_win_protection(emu, page) == PAGE_READONLY

        assert emulator_page_win_protection(emu, 0x9F0000) is None
        # Loaded image pages keep their recorded per-page value.
        assert emulator_page_win_protection(emu, IMAGE_BASE + TEXT_RVA) == PAGE_EXECUTE_READ


# ---------------------------------------------------------------------------
# Integration: VirtualProtectEx isolation (phase C1)
# ---------------------------------------------------------------------------


def test_virtual_protect_ex_updates_child_shadow_not_parent(config) -> None:
    with _running_emulator_with_child(config) as (_se, emu, child):
        k32 = _kernel32(emu)
        handle = emu.get_object_handle(child)
        space = emu.get_process_address_space(child)
        assert space is not None
        target = IMAGE_BASE + TEXT_RVA
        old_ptr = _parent_buffer(emu, b"\x00" * 4)
        parent_protect_before = emulator_page_win_protection(emu, target)
        parent_perms_before = emu.get_address_perms(target)
        shadow_old = space.query(target)["protect"]
        assert parent_protect_before == PAGE_EXECUTE_READ

        assert (
            k32.VirtualProtectEx(emu, [handle, target, PAGE_SIZE, PAGE_NOACCESS, old_ptr])
            == 1
        )
        assert int.from_bytes(emu.mem_read(old_ptr, 4), "little") == shadow_old
        assert space.query(target)["protect"] == PAGE_NOACCESS
        # The caller's/global page is untouched (baseline bug changed 0x20 -> 0x1).
        assert emulator_page_win_protection(emu, target) == parent_protect_before
        assert emu.get_address_perms(target) == parent_perms_before

        # A decommitted target page is an explicit failure, not a synthetic old value.
        base = k32.VirtualAllocEx(
            emu,
            [handle, FREE_CHILD_BASE, 0x2000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE],
        )
        assert base == FREE_CHILD_BASE
        assert k32.VirtualFreeEx(emu, [handle, base, PAGE_SIZE, 0x4000]) is True
        old_ptr2 = _parent_buffer(emu, b"\x00" * 4)
        assert (
            k32.VirtualProtectEx(
                emu, [handle, base, PAGE_SIZE, PAGE_READONLY, old_ptr2]
            )
            == 0
        )
        assert emu.get_last_error() == ERROR_INVALID_ADDRESS
        assert emu.mem_read(old_ptr2, 4) == b"\x00" * 4

        # Null lpflOldProtect and invalid handles keep explicit Win32 errors.
        assert (
            k32.VirtualProtectEx(emu, [handle, target, PAGE_SIZE, PAGE_READONLY, 0])
            == 0
        )
        assert emu.get_last_error() == ERROR_INVALID_PARAMETER
        assert (
            k32.VirtualProtectEx(
                emu, [INVALID_HANDLE, target, PAGE_SIZE, PAGE_READONLY, old_ptr]
            )
            == 0
        )
        assert emu.get_last_error() == ERROR_INVALID_HANDLE


def test_virtual_protect_ex_current_process_path_unchanged(config) -> None:
    with _running_emulator_with_child(config) as (_se, emu, _child):
        k32 = _kernel32(emu)
        page = emu.mem_map(PAGE_SIZE, tag="test.fx12rv2.self", perms=common.PERM_MEM_RWX)
        old_ptr = _parent_buffer(emu, b"\x00" * 4)
        assert (
            k32.VirtualProtectEx(
                emu, [k32.get_max_int(), page, PAGE_SIZE, PAGE_READONLY, old_ptr]
            )
            == 1
        )
        assert emu.get_address_win_protection(page) == PAGE_READONLY
        assert int.from_bytes(emu.mem_read(old_ptr, 4), "little") == PAGE_EXECUTE_READWRITE


# ---------------------------------------------------------------------------
# Integration: outside-image runtime mappings (phase A)
# ---------------------------------------------------------------------------


def test_child_write_to_outside_image_runtime_map_is_backfilled(config) -> None:
    child_data = _child_pe_writing_absolute(OUTSIDE_TARGET)
    with _running_emulator_with_child(config) as (se, emu, child):
        k32 = _prepare_child(emu, child, child_data)
        parent = emu.get_current_process()
        handle = emu.get_object_handle(child)

        # A runtime mapping attributed to the child, outside the image span.
        emu.set_current_process(child)
        try:
            runtime_base = k32.VirtualAlloc(
                emu,
                [OUTSIDE_TARGET, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE],
            )
        finally:
            emu.set_current_process(parent)
        assert runtime_base == OUTSIDE_TARGET
        runtime_map = emu.get_address_map(runtime_base)
        assert runtime_map is not None and runtime_map.process is child

        parent_image_before = emu.mem_read(IMAGE_BASE, 0x10)
        parent_protect_before = emulator_page_win_protection(emu, IMAGE_BASE + TEXT_RVA)
        scheduler = create_engine_child_scheduler(
            se,
            ChildExecutionOptions(enabled=True, max_depth=1, max_children_per_root=1),
        )
        result = _drain(scheduler, _request(child_data), _target(child_data), child)

        assert result.state is ChildExecutionState.COMPLETED
        assert result.outcome is ChildOutcome.OK
        assert result.entrypoint_reached is True
        assert emu.mem_read(runtime_base, len(CHILD_PAYLOAD)) == CHILD_PAYLOAD

        space = child.address_space
        assert space is not None
        assert space.read(runtime_base, len(CHILD_PAYLOAD)) == CHILD_PAYLOAD
        snapshot = space.query(runtime_base)
        assert snapshot["state"] == MEM_COMMIT
        assert snapshot["protect"] == PAGE_READWRITE
        assert snapshot["allocation_protect"] == PAGE_READWRITE

        dst = _parent_buffer(emu, b"\x00" * len(CHILD_PAYLOAD))
        assert (
            k32.ReadProcessMemory(
                emu, [handle, runtime_base, dst, len(CHILD_PAYLOAD), 0]
            )
            is True
        )
        assert emu.mem_read(dst, len(CHILD_PAYLOAD)) == CHILD_PAYLOAD

        # Parent view: its image and protections are unchanged; the global map
        # at the target is still the child's own runtime map (no projection).
        assert emu.mem_read(IMAGE_BASE, 0x10) == parent_image_before
        assert emulator_page_win_protection(emu, IMAGE_BASE + TEXT_RVA) == parent_protect_before
        assert emu.get_address_map(runtime_base).process is child


def test_unchanged_outside_image_mapping_is_not_adopted(config) -> None:
    child_data = _child_pe_writing_absolute(OUTSIDE_TARGET)
    with _running_emulator_with_child(config) as (se, emu, child):
        _prepare_child(emu, child, child_data)
        parent = emu.get_current_process()
        k32 = _kernel32(emu)
        emu.set_current_process(child)
        try:
            changed = k32.VirtualAlloc(
                emu,
                [OUTSIDE_TARGET, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE],
            )
            unchanged = k32.VirtualAlloc(
                emu,
                [UNCHANGED_CHILD_MAP, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE],
            )
        finally:
            emu.set_current_process(parent)
        assert changed == OUTSIDE_TARGET
        assert unchanged == UNCHANGED_CHILD_MAP

        scheduler = create_engine_child_scheduler(
            se,
            ChildExecutionOptions(enabled=True, max_depth=1, max_children_per_root=1),
        )
        result = _drain(scheduler, _request(child_data), _target(child_data), child)

        assert result.state is ChildExecutionState.COMPLETED
        space = child.address_space
        assert space is not None
        assert space.read(OUTSIDE_TARGET, len(CHILD_PAYLOAD)) == CHILD_PAYLOAD
        # The map the child never wrote is not adopted into the shadow.
        assert space.is_free(UNCHANGED_CHILD_MAP, PAGE_SIZE) is True


def test_new_child_mapping_during_run_is_adopted() -> None:
    space = _RecordingSpace(pid=601)
    space.map_pe_image(_tiny_pe())
    process = SimpleNamespace(pid=601)
    process.address_space = space
    thread = SimpleNamespace(tid=602, process=process)
    runtime_base = 0x270000
    emulator = _NewMapAdoptionEmulator(
        process, thread, space, runtime_base=runtime_base, image_size=IMAGE_SIZE
    )

    result = EngineChildExecutionBackend(emulator).run(
        _backend_request(),
        SimpleNamespace(),
        _loaded_image(runtime_base, IMAGE_SIZE),
        _context(process, thread, runtime_base),
        _budget_hooks(),
    )

    assert result.run_indexes == (0,)
    assert space.adopt_calls == [(0x700000, PAGE_SIZE, "api.VirtualAlloc.test.0x700000")]
    assert space.read(0x700000, len(CHILD_PAYLOAD)) == CHILD_PAYLOAD
    snapshot = space.query(0x700000)
    assert snapshot["protect"] == PAGE_READWRITE
    assert snapshot["allocation_protect"] == PAGE_READWRITE
    # The image bytes did not change, so the image is not re-projected.
    assert space.sync_region_calls == []


# ---------------------------------------------------------------------------
# Integration: VirtualAllocEx reservations and materialization (phase B)
# ---------------------------------------------------------------------------


def test_materialized_reservation_carries_child_write_and_is_released(config) -> None:
    target = 0x50000
    child_data = _child_pe_writing_absolute(target)
    with _running_emulator_with_child(config) as (se, emu, child):
        k32 = _prepare_child(emu, child, child_data)
        parent = emu.get_current_process()
        handle = emu.get_object_handle(child)
        base = k32.VirtualAllocEx(
            emu, [handle, target, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE]
        )
        assert base == target
        space = child.address_space
        assert space is not None
        assert space.query(base)["state"] == MEM_COMMIT
        assert space.query(base)["protect"] == PAGE_READWRITE
        assert emu.get_address_map(base) is None  # shadow-only before execution

        parent_image_before = emu.mem_read(IMAGE_BASE, 0x10)
        parent_protect_before = emulator_page_win_protection(emu, IMAGE_BASE + TEXT_RVA)
        scheduler = create_engine_child_scheduler(
            se,
            ChildExecutionOptions(enabled=True, max_depth=1, max_children_per_root=1),
        )
        result = _drain(scheduler, _request(child_data), _target(child_data), child)

        assert result.state is ChildExecutionState.COMPLETED
        assert result.outcome is ChildOutcome.OK
        assert result.entrypoint_reached is True
        assert emu.get_address_map(base) is None  # released after the run
        assert space.read(base, len(CHILD_PAYLOAD)) == CHILD_PAYLOAD

        dst = _parent_buffer(emu, b"\x00" * len(CHILD_PAYLOAD))
        assert (
            k32.ReadProcessMemory(emu, [handle, base, dst, len(CHILD_PAYLOAD), 0])
            is True
        )
        assert emu.mem_read(dst, len(CHILD_PAYLOAD)) == CHILD_PAYLOAD
        assert emu.mem_read(IMAGE_BASE, 0x10) == parent_image_before
        assert emulator_page_win_protection(emu, IMAGE_BASE + TEXT_RVA) == parent_protect_before
        assert emu.get_current_process() is parent


def test_reserved_only_reservation_faults_child_write(config) -> None:
    target = 0x52000
    child_data = _child_pe_writing_absolute(target)
    with _running_emulator_with_child(config) as (se, emu, child):
        _prepare_child(emu, child, child_data)
        handle = emu.get_object_handle(child)
        base = _kernel32(emu).VirtualAllocEx(
            emu, [handle, target, PAGE_SIZE, MEM_RESERVE, PAGE_READWRITE]
        )
        assert base == target
        space = child.address_space
        assert space is not None
        assert space.query(base)["state"] == MEM_RESERVE
        assert space.query(base)["protect"] == PAGE_NOACCESS

        scheduler = create_engine_child_scheduler(
            se,
            ChildExecutionOptions(enabled=True, max_depth=1, max_children_per_root=1),
        )
        result = _drain(scheduler, _request(child_data), _target(child_data), child)

        assert result.state is ChildExecutionState.FAILED
        assert result.outcome is ChildOutcome.ERROR
        assert result.termination_reason.value == "invalid_memory"
        assert result.entrypoint_reached is True
        assert emu.get_address_map(base) is None
        assert space.query(base)["state"] == MEM_RESERVE


def test_decommitted_reservation_faults_child_write(config) -> None:
    target = 0x53000
    child_data = _child_pe_writing_absolute(target)
    with _running_emulator_with_child(config) as (se, emu, child):
        _prepare_child(emu, child, child_data)
        k32 = _kernel32(emu)
        handle = emu.get_object_handle(child)
        base = k32.VirtualAllocEx(
            emu, [handle, target, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE]
        )
        assert base == target
        assert k32.VirtualFreeEx(emu, [handle, base, PAGE_SIZE, 0x4000]) is True
        space = child.address_space
        assert space is not None
        assert space.query(base)["state"] == MEM_RESERVE

        scheduler = create_engine_child_scheduler(
            se,
            ChildExecutionOptions(enabled=True, max_depth=1, max_children_per_root=1),
        )
        result = _drain(scheduler, _request(child_data), _target(child_data), child)

        assert result.state is ChildExecutionState.FAILED
        assert result.termination_reason.value == "invalid_memory"
        assert emu.get_address_map(base) is None
        assert space.query(base)["state"] == MEM_RESERVE


def test_materialization_collision_fails_explicitly_without_leak(config) -> None:
    target = 0x54000
    child_data = _child_pe_writing_absolute(target)
    with _running_emulator_with_child(config) as (se, emu, child):
        _prepare_child(emu, child, child_data)
        k32 = _kernel32(emu)
        handle = emu.get_object_handle(child)
        parent_page = emu.mem_map(
            PAGE_SIZE, base=target, tag="test.fx12rv2.collision", perms=common.PERM_MEM_RWX
        )
        assert parent_page == target
        assert k32.VirtualAllocEx(
            emu, [handle, target, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE]
        ) == target
        space = child.address_space
        assert space is not None
        assert space.query(target)["state"] == MEM_COMMIT

        scheduler = create_engine_child_scheduler(
            se,
            ChildExecutionOptions(enabled=True, max_depth=1, max_children_per_root=1),
        )
        result = _drain(scheduler, _request(child_data), _target(child_data), child)

        assert result.state is ChildExecutionState.FAILED
        assert result.outcome is ChildOutcome.ERROR
        assert result.termination_reason.value == "invalid_memory"
        assert result.entrypoint_reached is False
        assert result.run_indexes == ()
        assert result.error is not None
        assert "487" in result.error.message
        # The parent mapping is untouched and no child-shadow mapping leaked.
        survivor = emu.get_address_map(target)
        assert survivor is not None
        assert survivor.tag.startswith("test.fx12rv2.collision")
        assert not any(
            "child_shadow" in str(getattr(mm, "tag", "")) for mm in emu.get_mem_maps()
        )


def test_baseless_reservation_avoids_globally_occupied_ranges(config) -> None:
    with _running_emulator_with_child(config) as (_se, emu, child):
        k32 = _kernel32(emu)
        handle = emu.get_object_handle(child)
        held = emu.mem_map(
            PAGE_SIZE, base=0x10000, tag="test.fx12rv2.avoid", perms=common.PERM_MEM_RWX
        )
        assert held == 0x10000

        base = k32.VirtualAllocEx(
            emu, [handle, 0, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE]
        )
        assert base != 0
        assert base != held
        assert emu.get_address_map(base) is None
        space = child.address_space
        assert space is not None
        assert space.is_free(base, PAGE_SIZE) is False


def test_child_freed_materialized_region_is_released_from_shadow() -> None:
    space = _RecordingSpace(pid=701)
    space.map_pe_image(_tiny_pe())
    space.virtual_alloc(0x50000, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    process = SimpleNamespace(pid=701)
    process.address_space = space
    thread = SimpleNamespace(tid=702, process=process)
    runtime_base = 0x270000
    emulator = _MaterializedFreeEmulator(
        process, thread, space, runtime_base=runtime_base, image_size=IMAGE_SIZE
    )

    result = EngineChildExecutionBackend(emulator).run(
        _backend_request(),
        SimpleNamespace(),
        _loaded_image(runtime_base, IMAGE_SIZE),
        _context(process, thread, runtime_base),
        _budget_hooks(),
    )

    assert result.run_indexes == (0,)
    assert emulator.materialize_calls == 1
    assert emulator.release_calls == 1
    assert space.is_free(0x50000, PAGE_SIZE) is True
    # The child freed the map, so no bytes were projected and no adoption ran.
    assert space.sync_region_calls == []
    assert space.adopt_calls == []


# ---------------------------------------------------------------------------
# Integration: runtime protection sync (phase C2)
# ---------------------------------------------------------------------------


def test_protection_only_runtime_change_is_synced_to_shadow() -> None:
    space = _RecordingSpace(pid=801)
    space.map_pe_image(_tiny_pe())
    process = SimpleNamespace(pid=801)
    process.address_space = space
    thread = SimpleNamespace(tid=802, process=process)
    runtime_base = 0x270000
    emulator = _ImageRuntimeEmulator(
        process,
        thread,
        space,
        runtime_base=runtime_base,
        image_size=IMAGE_SIZE,
        change_protection=True,
    )
    shadow_page = SHADOW_IMAGE_BASE + CHILD_ENTRY_RVA
    bytes_before = space.read(shadow_page, 0x10)

    result = EngineChildExecutionBackend(emulator).run(
        _backend_request(),
        SimpleNamespace(),
        _loaded_image(runtime_base, IMAGE_SIZE),
        _context(process, thread, runtime_base),
        _budget_hooks(),
    )

    assert result.run_indexes == (0,)
    assert space.query(shadow_page)["protect"] == PAGE_READONLY
    assert space.read(shadow_page, 0x10) == bytes_before  # bytes untouched
    assert space.sync_region_calls == []
    assert space.sync_protection_calls == [(shadow_page, (PAGE_READONLY,))]


def test_no_runtime_change_does_not_sync_or_project() -> None:
    space = _RecordingSpace(pid=803)
    space.map_pe_image(_tiny_pe())
    process = SimpleNamespace(pid=803)
    process.address_space = space
    thread = SimpleNamespace(tid=804, process=process)
    runtime_base = 0x270000
    emulator = _ImageRuntimeEmulator(
        process,
        thread,
        space,
        runtime_base=runtime_base,
        image_size=IMAGE_SIZE,
        change_protection=False,
    )

    result = EngineChildExecutionBackend(emulator).run(
        _backend_request(),
        SimpleNamespace(),
        _loaded_image(runtime_base, IMAGE_SIZE),
        _context(process, thread, runtime_base),
        _budget_hooks(),
    )

    assert result.run_indexes == (0,)
    assert space.sync_region_calls == []
    assert space.sync_protection_calls == []
    assert space.adopt_calls == []
