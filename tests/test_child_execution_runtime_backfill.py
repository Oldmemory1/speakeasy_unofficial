"""Automatic child-runtime backfill wiring for the opt-in scheduler.

FX12-extended-rv1 (``AddressSpace / per_process_isolation``, phase 4) wires
:class:`EngineChildExecutionBackend` to the FX-012-extended per-process shadow
view:

* when the opt-in scheduled backend actually executes a child in the shared
  emulator memory, pages of the child's mapped image whose runtime bytes
  changed are projected into that child's :class:`ProcessAddressSpace`
  (``capture_runtime_write``); a missing view is seeded first, exactly as
  ``ReadProcessMemory`` would seed it;
* the parent's own virtual-address view is never modified;
* a shadow page that no longer maps the runtime image fails explicitly
  instead of silently succeeding;
* nothing is backfilled when no child code executes.

The tests drive the real opt-in factory :func:`create_engine_child_scheduler`
with a synthetic x86 child PE.  The child entry computes its own runtime base
(``call $+5; pop eax``) and writes ``0x11223344`` to its ``.data`` page, so the
assertions hold even though the loader relocates the child image away from its
preferred ``0x400000`` base.
"""

from __future__ import annotations

import hashlib
import struct
from types import SimpleNamespace

import speakeasy.common as common
from speakeasy.windows.child_execution import (
    AdmissionDecision,
    BudgetUsage,
    ChildExecutionOptions,
    ChildExecutionState,
    ChildLaunchRequest,
    ChildOutcome,
    ChildTargetSource,
    ExecutionBudget,
    LoadedChildImage,
    ParentRunOutcome,
    ResolvedChildTarget,
    TargetPayloadRef,
    create_engine_child_scheduler,
)
from speakeasy.windows.child_execution.runtime_backend import (
    EngineChildExecutionBackend,
)
from speakeasy.windows.process_memory import (
    ERROR_PARTIAL_COPY,
    MEM_DECOMMIT,
    MEM_RESERVE,
)
from tests.test_process_address_space import (
    IMAGE_BASE,
    _running_emulator_with_child,
)

PAGE_SIZE = 0x1000
CHILD_IMAGE_SIZE = 0x5000
CHILD_ENTRY_RVA = 0x1000
CHILD_DATA_RVA = 0x2000
CHILD_PAYLOAD = b"\x44\x33\x22\x11"  # 0x11223344 little endian
SHADOW_WRITE_ADDR = IMAGE_BASE + CHILD_DATA_RVA


def _child_pe() -> bytes:
    """Build a tiny x86 PE32 whose entry writes ``CHILD_PAYLOAD`` to ``.data``.

    Entry code (RVA 0x1000)::

        call $+5                     ; E8 00 00 00 00
        pop eax                      ; 58
        mov dword [eax+0xFFB], imm   ; C7 80 FB 0F 00 00 <payload>
        ret                          ; C3

    After ``call``/``pop``, ``eax`` is ``runtime_base + 0x1005``; adding
    ``0xFFB`` yields ``runtime_base + 0x2000`` even after relocation.  The
    preferred ImageBase is ``0x400000`` (the parent's base), so the loader must
    relocate the child image.
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
    put("<I", CHILD_DATA_RVA)  # BaseOfData
    put("<I", IMAGE_BASE)  # preferred ImageBase; forces relocation
    put("<I", 0x1000)  # SectionAlignment
    put("<I", 0x200)  # FileAlignment
    put("<HH", 6, 0)
    put("<HH", 0, 0)
    put("<HH", 6, 1)
    put("<I", 0)
    put("<I", CHILD_IMAGE_SIZE)  # SizeOfImage
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
        (b".data", CHILD_DATA_RVA, 0x1000, 0x200, 0x400, 0xC0000040),
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

    code = (
        b"\xE8\x00\x00\x00\x00"  # call $+5
        b"\x58"  # pop eax
        b"\xC7\x80\xFB\x0F\x00\x00"  # mov dword [eax+0xFFB], imm32
        + CHILD_PAYLOAD
        + b"\xC3"  # ret
    )
    image[0x200 : 0x200 + len(code)] = code
    return bytes(image)


def _request(data: bytes) -> ChildLaunchRequest:
    """Build one depth-one launch whose budget matches the parent."""

    return ChildLaunchRequest(
        launch_id="runtime-backfill-child",
        root_sample_sha256="a" * 64,
        parent_launch_id=None,
        source_api="CreateProcess",
        parent_pid=100,
        parent_tid=101,
        depth=1,
        target=r"C:\probe\child.exe",
        normalized_target=r"C:\probe\child.exe",
        working_directory=r"C:\probe",
        command_line=r"C:\probe\child.exe",
        command_sha256=hashlib.sha256(b"child command").hexdigest(),
        parent_budget=ExecutionBudget(
            timeout_seconds=10.0,
            max_api_count=100,
            max_instructions=10000,
        ),
    )


def _target(data: bytes) -> ResolvedChildTarget:
    """Build resolved target evidence for the synthetic child bytes."""

    digest = hashlib.sha256(data).hexdigest()
    return ResolvedChildTarget(
        source=ChildTargetSource.FIXTURE,
        normalized_path=r"C:\probe\child.exe",
        payload_ref=TargetPayloadRef(
            source=ChildTargetSource.FIXTURE,
            sha256=digest,
            size=len(data),
            emu_path=r"C:\probe\child.exe",
            data=data,
        ),
        sha256=digest,
        size=len(data),
        file_format="pe",
        arch="x86",
        module_type="exe",
        entrypoint_rva=CHILD_ENTRY_RVA,
        resolved=True,
        reason=None,
    )


def _prepare_child(emu, child, data: bytes) -> object:
    """Point one emulator-created child process at the synthetic image bytes.

    ``create_process`` eagerly seeds ``pe_data`` from the root path; replacing
    it with the exact bytes the scheduler will load gives the child shadow a
    real pre-execution image view, as in the representative hollowing shape.
    Returns the kernel32 handler.
    """

    child.pe_data = data
    child.pe = None
    child.address_space = None
    return emu.api.load_api_handler("kernel32")


def _drain(scheduler, request: ChildLaunchRequest, target: ResolvedChildTarget, child):
    """Submit one eligible launch and drain it with an ok parent outcome."""

    scheduler.submit(
        request,
        target,
        AdmissionDecision(
            eligible=True,
            state=ChildExecutionState.ELIGIBLE,
            reason=None,
        ),
        child,
    )
    results = scheduler.drain(
        ParentRunOutcome(
            status="ok",
            termination_reason="normal_exit",
            coverage_complete=True,
            budget=request.parent_budget,
            usage=BudgetUsage(),
        )
    )
    assert len(results) == 1
    return results[0]


def _marker_buffer(emu, data: bytes, tag: str) -> int:
    """Map one writable buffer holding ``data`` for API input/output."""

    addr = emu.mem_map(PAGE_SIZE, tag=tag, perms=common.PERM_MEM_RWX)
    emu.mem_write(addr, data)
    return addr


# ---------------------------------------------------------------------------
# Opt-in scheduled backend: automatic runtime-image backfill
# ---------------------------------------------------------------------------


def test_optin_child_execution_backfills_preexisting_shadow(config) -> None:
    """A child's runtime write reaches its pre-existing shadow, not the parent."""

    child_data = _child_pe()
    with _running_emulator_with_child(config) as (se, emu, child):
        k32 = _prepare_child(emu, child, child_data)
        handle = emu.get_object_handle(child)

        parent_before = emu.mem_read(SHADOW_WRITE_ADDR, len(CHILD_PAYLOAD))
        marker = _marker_buffer(emu, b"\xAA" * len(CHILD_PAYLOAD), "test.fx12rv1.wpm")
        # The parent must touch the child before execution so that the shadow
        # view exists and the lazy re-seed path cannot mask a missing backfill.
        assert (
            k32.WriteProcessMemory(
                emu, [handle, SHADOW_WRITE_ADDR, marker, len(CHILD_PAYLOAD), 0]
            )
            is True
        )
        space = child.address_space
        assert space is not None
        assert space.read(SHADOW_WRITE_ADDR, len(CHILD_PAYLOAD)) == b"\xAA" * 4

        request = _request(child_data)
        target = _target(child_data)
        scheduler = create_engine_child_scheduler(
            se,
            ChildExecutionOptions(enabled=True, max_depth=1, max_children_per_root=1),
        )
        result = _drain(scheduler, request, target, child)

        # The child genuinely executed and wrote its own runtime image.
        assert result.state is ChildExecutionState.COMPLETED
        assert result.outcome is ChildOutcome.OK
        assert result.termination_reason.value == "normal_exit"
        assert result.entrypoint_reached is True
        assert result.error is None
        assert result.run_indexes
        assert emu.mem_read(int(child.pe.base) + CHILD_DATA_RVA, 4) == CHILD_PAYLOAD

        # The runtime page is backfilled into the child's shadow view.
        assert space.read(SHADOW_WRITE_ADDR, len(CHILD_PAYLOAD)) == CHILD_PAYLOAD
        dst = _marker_buffer(emu, b"\x00" * len(CHILD_PAYLOAD), "test.fx12rv1.rpm")
        assert (
            k32.ReadProcessMemory(
                emu, [handle, SHADOW_WRITE_ADDR, dst, len(CHILD_PAYLOAD), 0]
            )
            is True
        )
        assert emu.mem_read(dst, len(CHILD_PAYLOAD)) == CHILD_PAYLOAD

        # The parent/caller view at the same virtual address stays unchanged.
        assert emu.mem_read(SHADOW_WRITE_ADDR, len(CHILD_PAYLOAD)) == parent_before


def test_optin_child_seeds_missing_shadow_and_backfills(config) -> None:
    """A child without a prior shadow gets one seeded and backfilled."""

    child_data = _child_pe()
    with _running_emulator_with_child(config) as (se, emu, child):
        k32 = _prepare_child(emu, child, child_data)
        handle = emu.get_object_handle(child)
        parent_before = emu.mem_read(SHADOW_WRITE_ADDR, len(CHILD_PAYLOAD))
        assert child.address_space is None

        request = _request(child_data)
        target = _target(child_data)
        scheduler = create_engine_child_scheduler(
            se,
            ChildExecutionOptions(enabled=True, max_depth=1, max_children_per_root=1),
        )
        result = _drain(scheduler, request, target, child)

        assert result.state is ChildExecutionState.COMPLETED
        assert result.entrypoint_reached is True
        # The backend creates the same bookkeeping view ReadProcessMemory would
        # create and projects the changed runtime page into it.
        space = child.address_space
        assert space is not None
        assert space.read(SHADOW_WRITE_ADDR, len(CHILD_PAYLOAD)) == CHILD_PAYLOAD

        dst = _marker_buffer(emu, b"\x00" * len(CHILD_PAYLOAD), "test.fx12rv1.lazy")
        assert (
            k32.ReadProcessMemory(
                emu, [handle, SHADOW_WRITE_ADDR, dst, len(CHILD_PAYLOAD), 0]
            )
            is True
        )
        assert emu.mem_read(dst, len(CHILD_PAYLOAD)) == CHILD_PAYLOAD
        assert emu.mem_read(SHADOW_WRITE_ADDR, len(CHILD_PAYLOAD)) == parent_before


def test_decommitted_shadow_image_page_fails_explicitly(config) -> None:
    """A runtime write into a decommitted shadow page is an explicit failure."""

    child_data = _child_pe()
    with _running_emulator_with_child(config) as (se, emu, child):
        k32 = _prepare_child(emu, child, child_data)
        handle = emu.get_object_handle(child)

        # Create the shadow view, then decommit exactly the runtime-written
        # page.  The region stays reserved, so this is the capture-time
        # "page is not committed" path, not a missing shadow view.
        assert (
            k32.VirtualFreeEx(
                emu, [handle, SHADOW_WRITE_ADDR, PAGE_SIZE, MEM_DECOMMIT]
            )
            is True
        )
        space = child.address_space
        assert space is not None
        assert space.query(SHADOW_WRITE_ADDR)["state"] == MEM_RESERVE

        request = _request(child_data)
        target = _target(child_data)
        scheduler = create_engine_child_scheduler(
            se,
            ChildExecutionOptions(enabled=True, max_depth=1, max_children_per_root=1),
        )
        result = _drain(scheduler, request, target, child)

        assert result.state is ChildExecutionState.FAILED
        assert result.outcome is ChildOutcome.ERROR
        assert result.termination_reason.value == "invalid_memory"
        assert result.entrypoint_reached is True
        assert result.run_indexes
        assert result.error is not None
        assert "backfill" in result.error.message.casefold()
        assert str(ERROR_PARTIAL_COPY) in result.error.message
        # The child did execute and write its runtime image; the failure is the
        # explicit projection refusal, not a fabricated execution claim.
        assert emu.mem_read(int(child.pe.base) + CHILD_DATA_RVA, 4) == CHILD_PAYLOAD


# ---------------------------------------------------------------------------
# Controlled backend: nothing executed means nothing backfilled
# ---------------------------------------------------------------------------


class _NoOpHook:
    """Hook handle that only records its disable."""

    def __init__(self) -> None:
        self.disabled = False

    def disable(self) -> None:
        """Record one disable."""

        self.disabled = True


class _RecordingShadow:
    """Image-shaped shadow view that records any projection attempt."""

    def __init__(self, image_base: int, image_size: int) -> None:
        self.image_base = image_base
        self.image_size = image_size
        self.capture_calls: list[tuple[int, bytes]] = []
        self.regions = (
            SimpleNamespace(base=image_base, size=image_size, is_image=True),
        )

    def capture_runtime_write(self, base: int, data: bytes) -> int:
        """Record a projection attempt; the no-execution test must never call it."""

        self.capture_calls.append((base, bytes(data)))
        return len(data)

    def query(self, address: int) -> dict[str, object]:
        """Report a stable committed image page for protection comparisons."""

        return {
            "base": self.image_base,
            "size": self.image_size,
            "protect": 0x02,
            "allocation_protect": 0x02,
            "tag": "image",
            "is_image": True,
            "state": 0x1000,
        }

    def adaptor_guard(self, name: str) -> None:
        raise AssertionError(f"no-execution child must not call {name}")

    def adopt_runtime_region(self, *_args, **_kwargs):
        self.adaptor_guard("adopt_runtime_region")

    def sync_runtime_region(self, *_args, **_kwargs):
        self.adaptor_guard("sync_runtime_region")

    def sync_runtime_protections(self, *_args, **_kwargs):
        self.adaptor_guard("sync_runtime_protections")


class _NoExecutionEmulator:
    """Queue a run without executing or changing any runtime bytes."""

    def __init__(self, process, thread, image_base: int, image_size: int) -> None:
        self.curr_process = process
        self.curr_thread = thread
        self.run_queue: list[object] = []
        self.runs: list[object] = []
        self.instruction_budget_exhausted = False
        self.page_size = PAGE_SIZE
        self._image_base = image_base
        self._image_size = image_size

    def mem_read(self, address: int, size: int) -> bytes:
        """Return the stable initial image bytes."""

        assert address == self._image_base
        assert size == self._image_size
        return b"\x00" * size

    def get_mem_maps(self) -> list[object]:
        """Report no child-attributed runtime mappings."""

        return []

    def get_address_map(self, address: int):
        """Expose the synthetic image mapping for protection sampling."""

        if self._image_base <= address < self._image_base + self._image_size:
            return SimpleNamespace(
                base=self._image_base,
                size=self._image_size,
                tag="emu.module.child",
                prot=common.PERM_MEM_RWX,
                flags=0,
                free=False,
                process=None,
                is_image=True,
            )
        return None

    def get_address_win_protection(self, _address: int) -> int:
        """Match the recording shadow's stable page protection."""

        return 0x02

    def get_address_perms(self, _address: int) -> int:
        """Return synthetic read/write/execute permissions."""

        return common.PERM_MEM_RWX

    def get_executing_process_address_space(self, process) -> _RecordingShadow:
        """Return the explicit shadow view owned by the synthetic process."""

        assert process is self.curr_process
        return process.address_space

    def add_code_hook(self, _callback, *, begin: int, end: int) -> _NoOpHook:
        """Accept the instruction/entry hooks without executing them."""

        assert end >= begin
        return _NoOpHook()

    def add_run(self, run: object) -> None:
        """Record the queued child run."""

        self.run_queue.append(run)
        self.runs.append(run)

    def start(self) -> None:
        """Do not execute anything: the run queue drains with no writes."""

        self.run_queue.clear()

    def stop(self) -> None:
        """Accept stop requests without changing state."""


def test_no_execution_does_not_backfill() -> None:
    """A child run that performs no writes must not project anything."""

    image_base = 0x270000
    image_size = 0x2000
    process = SimpleNamespace(pid=202)
    process.address_space = _RecordingShadow(image_base, image_size)
    thread = SimpleNamespace(tid=203)
    emulator = _NoExecutionEmulator(process, thread, image_base, image_size)
    context = SimpleNamespace(
        process=process,
        thread=thread,
        run=SimpleNamespace(start_addr=image_base + 0x1000, num_apis=0, error=None),
    )
    image = LoadedChildImage(
        request_launch_id="no-execution-child",
        module=SimpleNamespace(
            base=image_base,
            image_size=image_size,
            emu_path=r"C:\probe\child.exe",
        ),
        image_base=image_base,
        entrypoint_address=image_base + 0x1000,
    )
    request = ChildLaunchRequest(
        launch_id="no-execution-child",
        root_sample_sha256="b" * 64,
        parent_launch_id=None,
        source_api="CreateProcess",
        parent_pid=100,
        parent_tid=101,
        depth=1,
        target=r"C:\probe\child.exe",
        normalized_target=r"C:\probe\child.exe",
        working_directory=r"C:\probe",
        command_line=r"C:\probe\child.exe",
        command_sha256=hashlib.sha256(b"no execution").hexdigest(),
        parent_budget=ExecutionBudget(
            timeout_seconds=10.0,
            max_api_count=100,
            max_instructions=1000,
        ),
    )

    result = EngineChildExecutionBackend(emulator).run(
        request,
        SimpleNamespace(),
        image,
        context,
        SimpleNamespace(
            observe_api=lambda: True,
            observe_instructions=lambda count=1: True,
            should_continue=lambda: True,
        ),
    )

    assert result.run_indexes == (0,)
    assert process.address_space.capture_calls == []
