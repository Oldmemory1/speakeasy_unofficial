"""Contract tests for routing protected-page faults to guest VEH/SEH (FX-003).

Windows/Wine map a write, read or instruction fetch that hits a mapped page
with insufficient protection to ``STATUS_ACCESS_VIOLATION`` (0xC0000005) and
deliver it through the guest exception chain (VEH -> SEH -> UEF).  Speakeasy
used to terminate such faults directly:

* ``UC_MEM_WRITE_PROT`` -> ``_handle_prot_write`` -> ``invalid_protect_write``
  + run completion, never calling ``dispatch_seh``;
* ``UC_MEM_FETCH_PROT`` -> ``_handle_prot_fetch`` returned True silently when
  the address was not an import stub;
* ``UC_MEM_READ_PROT`` -> no branch at all in ``_hook_mem_unmapped``;
* vectored exception handlers were stored but never dispatched, and the
  ``First`` ordering was discarded.

These tests freeze the contract with a synthetic x86 shellcode that calls the
real ``kernel32.VirtualAlloc``/``VirtualProtect`` APIs to create a separate
target page and turn it read-only / no-access, plus inline SEH handlers and
registered VEH handlers:

* positive: a guest handler receives 0xC0000005, and either advances
  ``CONTEXT.Eip`` past the fault or restores PAGE_READWRITE and retries;
* ``PAGE_NOACCESS`` reads use the new protected-read branch;
* negative: without a handler the original fatal error, PC, fault address and
  access type are preserved (nothing is swallowed);
* VEH ordering: First-chance handlers run in reverse registration order before
  last-chance handlers, and a declining VEH chain still ends with the original
  error without unbounded handler replay.
"""

from __future__ import annotations

import struct

from speakeasy import Speakeasy

STATUS_ACCESS_VIOLATION = 0xC0000005
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
EXCEPTION_CONTINUE_SEARCH = 0
EXCEPTION_CONTINUE_EXECUTION = 0xFFFFFFFF

EXEC_MARKER = 0x600D600D
WRITTEN_VALUE = 0x41424344
WRITE_INSN_LEN = 6  # c7 00 <imm32>
READ_INSN_LEN = 2  # 8b 18

# Data slots appended to the shellcode image (RWX, never executed).
DATA_TARGET = 0  # DWORD: VirtualAlloc result
DATA_OLD_PROT = 4  # DWORD: lpflOldProtect scratch for VirtualProtect
DATA_OUT = 16  # start of observation slots
OUT_CODE = 0  # DWORD: exception code observed by the handler
OUT_HIT = 4  # DWORD: handler invocation count
OUT_EXEC = 8  # DWORD: marker executed after the faulting instruction
OUT_HIT_B = 12  # DWORD: second handler invocation count (VEH chain tests)


class _Asm:
    """Tiny x86 emitter with 32-bit absolute fixups resolved after loading."""

    def __init__(self) -> None:
        self.buf = bytearray()
        # (offset, key, addend); keys: sc / out / target / vp / alloc
        self.patches: list[list] = []

    def imm32(self, key: str, addend: int = 0) -> None:
        offset = len(self.buf)
        self.buf += b"\x00\x00\x00\x00"
        self.patches.append([offset, key, addend])

    def push_imm8(self, value: int) -> None:
        self.buf += bytes((0x6A, value & 0xFF))

    def push_imm32(self, value: int) -> None:
        self.buf += b"\x68" + struct.pack("<I", value)

    def push_abs(self, key: str, addend: int = 0) -> None:
        self.buf += b"\x68"
        self.imm32(key, addend)

    def mov_eax_imm(self, value: int) -> None:
        self.buf += b"\xb8" + struct.pack("<I", value & 0xFFFFFFFF)

    def mov_eax_abs(self, key: str, addend: int = 0) -> None:
        self.buf += b"\xb8"
        self.imm32(key, addend)

    def mov_eax_ptr_abs(self, key: str, addend: int = 0) -> None:
        self.buf += b"\x8b\x05"
        self.imm32(key, addend)

    def mov_ptr_abs_eax(self, key: str, addend: int = 0) -> None:
        self.buf += b"\x89\x05"
        self.imm32(key, addend)

    def mov_ptr_abs_edx(self, key: str, addend: int = 0) -> None:
        self.buf += b"\x89\x15"
        self.imm32(key, addend)

    def inc_ptr_abs(self, key: str, addend: int = 0) -> None:
        self.buf += b"\xff\x05"
        self.imm32(key, addend)

    def mov_ptr_abs_imm32(self, key: str, value: int, addend: int = 0) -> None:
        self.buf += b"\xc7\x05"
        self.imm32(key, addend)
        self.buf += struct.pack("<I", value & 0xFFFFFFFF)

    def mov_ptr_eax_imm32(self, value: int) -> None:
        self.buf += b"\xc7\x00" + struct.pack("<I", value & 0xFFFFFFFF)

    def mov_ebx_ptr_eax(self) -> None:
        self.buf += b"\x8b\x18"

    def add_ptr_ecx_imm8(self, disp: int, value: int) -> None:
        self.buf += b"\x83\x81" + struct.pack("<I", disp) + bytes((value & 0xFF,))

    def call_eax(self) -> None:
        self.buf += b"\xff\xd0"

    def jmp_eax(self) -> None:
        self.buf += b"\xff\xe0"

    def push_fs0(self) -> None:
        self.buf += bytes.fromhex("64FF3500000000")

    def mov_fs0_esp(self) -> None:
        self.buf += bytes.fromhex("64892500000000")

    def pop_fs0(self) -> None:
        self.buf += bytes.fromhex("648F0500000000")

    def pop_ecx(self) -> None:
        self.buf += b"\x59"

    def xor_eax(self) -> None:
        self.buf += b"\x31\xc0"

    def ret(self) -> None:
        self.buf += b"\xc3"

    def retn(self, count: int) -> None:
        self.buf += b"\xc2" + struct.pack("<H", count)


def _emit_restore_permissions(asm: _Asm) -> None:
    """Emit VirtualProtect(*target_slot, 0x1000, PAGE_READWRITE, &old)."""
    asm.push_abs("target", DATA_OLD_PROT)  # lpflOldProtect (must be non-NULL)
    asm.push_imm8(PAGE_READWRITE)
    asm.push_imm32(0x1000)
    asm.mov_eax_ptr_abs("target")
    asm.buf += b"\x50"  # push eax
    asm.mov_eax_abs("vp")
    asm.call_eax()


def _append_handler(
    asm: _Asm,
    *,
    frame: str,
    mode: str,
    skip_len: int | None,
    resume_offset: int | None,
    hit_slot: int = OUT_HIT,
) -> None:
    """Append a guest exception handler.

    ``frame="seh"`` uses the SEH callback arguments
    (ExceptionRecord, Registration, ContextRecord, DispatcherContext);
    ``frame="veh"`` receives a single EXCEPTION_POINTERS pointer.

    Modes: ``skip`` records the code/count and advances CONTEXT.Eip past the
    faulting instruction, returning CONTINUE_EXECUTION for VEH (the raw inline
    SEH continuation honours the edited Eip with CONTINUE_SEARCH);
    ``fix`` calls VirtualProtect(target, PAGE_READWRITE) and retries the
    instruction; ``resume`` sets CONTEXT.Eip to a fixed resume address.
    """
    if frame == "seh":
        asm.buf += b"\x8b\x54\x24\x04"  # mov edx, [esp+4]  ; ExceptionRecord
        asm.buf += b"\x8b\x12"  # mov edx, [edx]      ; ExceptionCode
        asm.mov_ptr_abs_edx("out", OUT_CODE)
        asm.inc_ptr_abs("out", hit_slot)
        if mode == "fix":
            _emit_restore_permissions(asm)
        asm.buf += b"\x8b\x4c\x24\x0c"  # mov ecx, [esp+0xC] ; ContextRecord
        if mode == "skip":
            assert skip_len is not None
            asm.add_ptr_ecx_imm8(0xB8, skip_len)  # CONTEXT.Eip += len
        elif mode == "resume":
            assert resume_offset is not None
            asm.buf += b"\xc7\x81" + struct.pack("<I", 0xB8)
            asm.imm32("sc", resume_offset)
        asm.xor_eax()  # EXCEPTION_CONTINUE_SEARCH
        asm.ret()
        return

    if frame != "veh":
        raise ValueError(f"unknown frame: {frame}")

    asm.buf += b"\x8b\x54\x24\x04"  # mov edx, [esp+4]  ; EXCEPTION_POINTERS
    asm.buf += b"\x8b\x02"  # mov eax, [edx]     ; ExceptionRecord
    asm.buf += b"\x8b\x00"  # mov eax, [eax]     ; ExceptionCode
    asm.mov_ptr_abs_eax("out", OUT_CODE)
    asm.inc_ptr_abs("out", hit_slot)
    if mode == "fix":
        _emit_restore_permissions(asm)
    asm.buf += b"\x8b\x54\x24\x04"  # mov edx, [esp+4]  ; reload arg
    asm.buf += b"\x8b\x4a\x04"  # mov ecx, [edx+4]  ; ContextRecord
    if mode == "skip":
        assert skip_len is not None
        asm.add_ptr_ecx_imm8(0xB8, skip_len)
    if mode in ("skip", "fix"):
        asm.mov_eax_imm(EXCEPTION_CONTINUE_EXECUTION)
    else:
        asm.xor_eax()  # EXCEPTION_CONTINUE_SEARCH
    asm.retn(4)


def _build_program(
    access: str,
    *,
    prot: int,
    seh_mode: str | None = None,
    veh_modes: tuple = (),
) -> tuple[bytes, list[list], dict]:
    """Build shellcode that allocates a target page, protects it, then faults.

    Returns ``(code, patches, offsets)`` where offsets maps ``fault`` (entry
    offset of the faulting instruction), ``resume`` (address after the fetch
    fault, if any), ``seh`` (offset of the inline SEH handler), ``veh``
    (offsets of the appended VEH handlers) and ``data`` (offset of the data
    slots appended to the image).
    """
    asm = _Asm()
    seh_placeholder: list | None = None

    # target = VirtualAlloc(NULL, 0x1000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
    asm.push_imm8(PAGE_READWRITE)
    asm.push_imm32(MEM_COMMIT | MEM_RESERVE)
    asm.push_imm32(0x1000)
    asm.push_imm32(0)
    asm.mov_eax_abs("alloc")
    asm.call_eax()
    asm.mov_ptr_abs_eax("target")

    if seh_mode is not None:
        asm.buf += b"\x68"
        seh_placeholder = [len(asm.buf), None, 0]
        asm.buf += b"\x00\x00\x00\x00"
        asm.patches.append(seh_placeholder)
        asm.push_fs0()
        asm.mov_fs0_esp()

    # VirtualProtect(target, 0x1000, prot, &old_prot)
    asm.push_abs("target", DATA_OLD_PROT)
    asm.push_imm8(prot)
    asm.push_imm32(0x1000)
    asm.mov_eax_ptr_abs("target")
    asm.buf += b"\x50"  # push eax
    asm.mov_eax_abs("vp")
    asm.call_eax()

    skip_len: int | None = None
    resume_offset: int | None = None
    if access == "write":
        asm.mov_eax_ptr_abs("target")
        fault_offset = len(asm.buf)
        asm.mov_ptr_eax_imm32(WRITTEN_VALUE)
        skip_len = WRITE_INSN_LEN
    elif access == "read":
        asm.mov_eax_ptr_abs("target")
        fault_offset = len(asm.buf)
        asm.mov_ebx_ptr_eax()
        skip_len = READ_INSN_LEN
    elif access == "fetch":
        asm.mov_eax_ptr_abs("target")
        fault_offset = len(asm.buf)
        asm.jmp_eax()
        resume_offset = len(asm.buf)
    else:
        raise ValueError(f"unknown access: {access}")

    asm.mov_ptr_abs_imm32("out", EXEC_MARKER, OUT_EXEC)

    if seh_mode is not None:
        asm.pop_fs0()
        asm.pop_ecx()
    asm.ret()

    offsets: dict = {"fault": fault_offset, "resume": resume_offset, "seh": None, "veh": []}

    if seh_mode is not None:
        offsets["seh"] = len(asm.buf)
        seh_placeholder[1] = "sc"
        seh_placeholder[2] = offsets["seh"]
        _append_handler(
            asm,
            frame="seh",
            mode=seh_mode,
            skip_len=skip_len,
            resume_offset=resume_offset,
        )

    for mode in veh_modes:
        if isinstance(mode, tuple):
            veh_mode, hit_slot = mode
        else:
            veh_mode, hit_slot = mode, OUT_HIT
        offsets["veh"].append(len(asm.buf))
        _append_handler(
            asm,
            frame="veh",
            mode=veh_mode,
            skip_len=skip_len,
            resume_offset=resume_offset,
            hit_slot=hit_slot,
        )

    offsets["data"] = len(asm.buf)
    asm.buf += b"\x00" * (DATA_OUT + OUT_HIT_B + 4)
    return bytes(asm.buf), asm.patches, offsets


def _run_program(
    config,
    *,
    access: str,
    prot: int,
    seh_mode: str | None = None,
    veh_modes: tuple = (),
    veh_registrations: tuple[tuple[int, int], ...] = (),
    dispatch_handlers: bool = True,
    timeout: int = 10,
):
    """Load/run the program and return (report, observation dict)."""
    cfg = config
    cfg["timeout"] = timeout
    cfg["exceptions"]["dispatch_handlers"] = dispatch_handlers

    code, patches, offsets = _build_program(access, prot=prot, seh_mode=seh_mode, veh_modes=veh_modes)

    se = Speakeasy(config=cfg)
    try:
        sc_addr = se.load_shellcode(data=code, arch="x86")
        emu = se.emu
        vp_stub = emu.get_proc("kernel32", "VirtualProtect")
        alloc_stub = emu.get_proc("kernel32", "VirtualAlloc")
        assert vp_stub is not None and alloc_stub is not None

        data_addr = sc_addr + offsets["data"]
        values = {
            "sc": sc_addr,
            "out": data_addr + DATA_OUT,
            "target": data_addr + DATA_TARGET,
            "vp": vp_stub,
            "alloc": alloc_stub,
        }
        for offset, key, addend in patches:
            emu.mem_write(sc_addr + offset, struct.pack("<I", (values[key] + addend) & 0xFFFFFFFF))

        for first, veh_index in veh_registrations:
            emu.add_vectored_exception_handler(first, sc_addr + offsets["veh"][veh_index])

        se.run_shellcode(sc_addr)
        report = se.get_report()
        target_va = int.from_bytes(emu.mem_read(data_addr + DATA_TARGET, 4), "little")
        read = lambda slot: int.from_bytes(emu.mem_read(data_addr + DATA_OUT + slot, 4), "little")  # noqa: E731
        target_value = 0
        if target_va:
            target_value = int.from_bytes(emu.mem_read(target_va, 4), "little")
        observations = {
            "code": read(OUT_CODE),
            "hit": read(OUT_HIT),
            "hit_b": read(OUT_HIT_B),
            "exec": read(OUT_EXEC),
            "target": target_value,
            "fault_va": sc_addr + offsets["fault"],
            "target_va": target_va,
        }
        return report, observations
    finally:
        se.shutdown()


def _entry_error(report):
    assert report.entry_points, "run produced no entry point report"
    return report.entry_points[0].error


# ---------------------------------------------------------------------------
# SEH routing of protected writes
# ---------------------------------------------------------------------------


def test_protected_write_is_dispatched_to_inline_seh(config):
    report, obs = _run_program(
        config,
        access="write",
        prot=PAGE_READONLY,
        seh_mode="skip",
    )

    error = _entry_error(report)
    assert error is None, error
    # Handler received the Windows access-violation status and ran exactly once.
    assert obs["code"] == STATUS_ACCESS_VIOLATION
    assert obs["hit"] == 1
    # CONTEXT.Eip advanced past the faulting store; the page stayed read-only.
    assert obs["exec"] == EXEC_MARKER
    assert obs["target"] == 0


def test_protected_write_seh_handler_can_restore_page_permissions(config):
    report, obs = _run_program(
        config,
        access="write",
        prot=PAGE_READONLY,
        seh_mode="fix",
    )

    error = _entry_error(report)
    assert error is None, error
    assert obs["code"] == STATUS_ACCESS_VIOLATION
    assert obs["hit"] == 1
    # The handler made the page writable and returned CONTINUE_SEARCH without
    # moving Eip, so the faulting store was retried and committed.
    assert obs["target"] == WRITTEN_VALUE
    assert obs["exec"] == EXEC_MARKER


# ---------------------------------------------------------------------------
# SEH routing of PAGE_NOACCESS reads (new INVAL_PERM_MEM_READ branch)
# ---------------------------------------------------------------------------


def test_protected_read_is_dispatched_to_inline_seh(config):
    report, obs = _run_program(
        config,
        access="read",
        prot=PAGE_NOACCESS,
        seh_mode="skip",
    )

    error = _entry_error(report)
    assert error is None, error
    assert obs["code"] == STATUS_ACCESS_VIOLATION
    assert obs["hit"] == 1
    assert obs["exec"] == EXEC_MARKER


def test_protected_read_without_seh_keeps_original_error(config):
    report, obs = _run_program(
        config,
        access="read",
        prot=PAGE_NOACCESS,
    )

    error = _entry_error(report)
    assert error is not None
    assert error.type == "invalid_prot_read"
    assert error.pc == obs["fault_va"]
    assert error.address == obs["target_va"]
    assert error.access_type == "read"
    assert obs["hit"] == 0
    assert obs["exec"] == 0


# ---------------------------------------------------------------------------
# SEH routing of protected instruction fetches
# ---------------------------------------------------------------------------


def test_protected_fetch_is_dispatched_to_inline_seh(config):
    report, obs = _run_program(
        config,
        access="fetch",
        prot=PAGE_READONLY,
        seh_mode="resume",
    )

    error = _entry_error(report)
    assert error is None, error
    assert obs["code"] == STATUS_ACCESS_VIOLATION
    assert obs["hit"] == 1
    assert obs["exec"] == EXEC_MARKER


def test_protected_fetch_without_seh_keeps_original_error(config):
    report, obs = _run_program(
        config,
        access="fetch",
        prot=PAGE_READONLY,
    )

    error = _entry_error(report)
    assert error is not None
    assert error.type == "invalid_protect_fetch"
    assert error.address == obs["target_va"]
    assert error.access_type == "fetch"
    assert obs["hit"] == 0
    assert obs["exec"] == 0


# ---------------------------------------------------------------------------
# Negatives: no handler / dispatch disabled must keep the original failure
# ---------------------------------------------------------------------------


def test_protected_write_without_seh_keeps_original_error(config):
    report, obs = _run_program(
        config,
        access="write",
        prot=PAGE_READONLY,
    )

    error = _entry_error(report)
    assert error is not None
    assert error.type == "invalid_protect_write"
    assert error.pc == obs["fault_va"]
    assert error.address == obs["target_va"]
    assert error.access_type == "write"
    assert error.instr
    assert obs["hit"] == 0
    assert obs["exec"] == 0


def test_protected_write_dispatch_disabled_keeps_original_error(config):
    report, obs = _run_program(
        config,
        access="write",
        prot=PAGE_READONLY,
        seh_mode="skip",
        dispatch_handlers=False,
    )

    error = _entry_error(report)
    assert error is not None
    assert error.type == "invalid_protect_write"
    assert error.pc == obs["fault_va"]
    assert error.address == obs["target_va"]
    assert error.access_type == "write"
    # The inline handler must not have run.
    assert obs["hit"] == 0
    assert obs["exec"] == 0


# ---------------------------------------------------------------------------
# VEH ordering and CONTINUE_EXECUTION semantics
# ---------------------------------------------------------------------------


def test_veh_first_handler_runs_before_last_chance_handler(config):
    # Registered: last-chance (index 0) first, then First (index 1). Windows
    # inserts First handlers at the front, so the First handler must run first.
    report, obs = _run_program(
        config,
        access="write",
        prot=PAGE_READONLY,
        veh_modes=("search", "skip"),
        veh_registrations=((0, 0), (1, 1)),
    )

    error = _entry_error(report)
    assert error is None, error
    assert obs["code"] == STATUS_ACCESS_VIOLATION
    # Only the First handler accepted; the last-chance handler never ran.
    assert obs["hit"] == 1
    assert obs["exec"] == EXEC_MARKER


def test_veh_handler_can_restore_page_permissions(config):
    report, obs = _run_program(
        config,
        access="write",
        prot=PAGE_READONLY,
        veh_modes=("fix",),
        veh_registrations=((1, 0),),
    )

    error = _entry_error(report)
    assert error is None, error
    assert obs["code"] == STATUS_ACCESS_VIOLATION
    assert obs["hit"] == 1
    # CONTINUE_EXECUTION reloaded the (unmodified) context; the retried store
    # succeeded because the VEH handler restored PAGE_READWRITE.
    assert obs["target"] == WRITTEN_VALUE
    assert obs["exec"] == EXEC_MARKER


def test_veh_declines_keep_original_error_without_runaway_retries(config):
    report, obs = _run_program(
        config,
        access="write",
        prot=PAGE_READONLY,
        veh_modes=(("search", OUT_HIT), ("search", OUT_HIT_B)),
        veh_registrations=((0, 0), (1, 1)),
    )

    error = _entry_error(report)
    assert error is not None
    assert error.type == "invalid_protect_write"
    assert error.pc == obs["fault_va"]
    assert error.address == obs["target_va"]
    assert error.access_type == "write"
    # Every VEH in the chain saw the exception, but the repeat guard bounds the
    # replay (dispatch_seh stops after _SEH_MAX_REPEAT = 4 attempts).
    assert 1 <= obs["hit"] <= 4
    assert 1 <= obs["hit_b"] <= 4
    assert obs["exec"] == 0


def test_veh_registry_preserves_first_and_last_chance_order():
    from speakeasy.windows.veh import VectoredExceptionRegistry

    registry = VectoredExceptionRegistry()
    registry.add(True, 0x1111)
    registry.add(False, 0x2222)
    registry.add(True, 0x3333)

    # First-chance handlers run in reverse registration order, followed by
    # last-chance handlers in registration order.
    assert registry.dispatch_order() == [0x3333, 0x1111, 0x2222]

    registry.remove(0x1111)
    assert registry.dispatch_order() == [0x3333, 0x2222]

    # Re-registering the same address replaces its previous ordering.
    registry.add(False, 0x3333)
    assert registry.dispatch_order() == [0x2222, 0x3333]
