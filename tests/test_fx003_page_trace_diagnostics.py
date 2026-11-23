"""FX-003 diagnostic contract tests: page-protection trace evidence.

The work order (``MemoryProtection / virtualprotect``) asks for *evidence only*:

* ``NtAllocateVirtualMemory``: ProcessHandle / BaseAddress / RegionSize /
  AllocationType / Protect and the resulting STATUS, so the report can show a
  requested ``PAGE_*`` value next to the protection the returned mapping
  actually carries.
* ``NtProtectVirtualMemory``: guest EAX/EDI/EBP/ESP (x64: RAX/RDI/RBP/RSP)
  before and after the handler plus the values written back to
  ``*BaseAddress`` / ``*NumberOfBytesToProtect`` / ``*OldAccessProtection``.
* ``VirtualProtect``: the page-by-page protection state before and after the
  change (emulator permissions and Win32 ``PAGE_*`` value).
* ``lstrcpyA/W``: source/destination pointers, the source string and the patch
  bytes the handler is about to write.

Every observation must be read-only: handler return values, page permissions,
exception dispatch and control flow are unchanged.  The tests below therefore
assert the new fields *and* the pre-existing behaviour on the same calls.

These tests fail against the pre-FX-003 implementation (no
``ctx["_api_observation"]`` for any of the four APIs) and pass once the
diagnostics are attached.
"""

from __future__ import annotations

import struct

import pytest
import unicorn as uc

import speakeasy.common as common
import speakeasy.windows.objman as objman
from speakeasy import Speakeasy
from speakeasy.report import ErrorInfo
from speakeasy.windows import page_protection, winemu
from speakeasy.winenv.api.kernelmode.ntoskrnl import Ntoskrnl
from speakeasy.winenv.api.usermode.kernel32 import Kernel32

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40

MEM_COMMIT = 0x1000

STATUS_SUCCESS = 0
STATUS_ACCESS_VIOLATION = 0xC0000005
STATUS_INVALID_PARAMETER = 0xC000000D

ERROR_INVALID_PARAMETER = 87
ERROR_INVALID_ADDRESS = 487

UNMAPPED_ADDRESS = 0x30000000
PSEUDO_HANDLE = 0xFFFFFFFF

OBSERVATION_KIND = "page_trace_diagnostic"


@pytest.fixture
def emu_env(config):
    """Loaded x86 emulator with a current process for pseudo-handle calls."""
    se = Speakeasy(config=config)
    try:
        se.load_shellcode(data=b"\xC3" + b"\x00" * 0xFFF, arch="x86")
        emu = se.emu
        proc = objman.Process(emu, name="fx003.exe", path="C:\\fx003.exe")
        proc.image = "fx003.exe"
        emu.add_object(proc)
        emu.set_current_process(proc)
        thread = objman.Thread(emu)
        emu.add_object(thread)
        emu.set_current_thread(thread)
        yield se, emu
    finally:
        se.shutdown()


def _observation(ctx):
    observation = ctx.get("_api_observation")
    assert isinstance(observation, dict), "handler attached no diagnostic observation"
    assert observation["kind"] == OBSERVATION_KIND
    assert observation["schema_version"] == 1
    return observation


def _read_u32(emu, addr):
    return int.from_bytes(emu.mem_read(addr, 4), "little")


def _scratch(emu, tag):
    return emu.mem_map(0x100, tag=tag, perms=common.PERM_MEM_RW)


def test_nt_allocate_trace_exposes_requested_protect_and_status(emu_env):
    _, emu = emu_env
    handler = Ntoskrnl(emu)
    scratch = _scratch(emu, "test.fx003.alloc")
    base_ptr = scratch
    size_ptr = scratch + 4
    emu.mem_write(base_ptr, b"\x00" * 4)
    emu.mem_write(size_ptr, struct.pack("<I", 0x1000))
    ctx = {"func_name": "ntdll.NtAllocateVirtualMemory"}

    rv = handler.ZwAllocateVirtualMemory(
        emu, [PSEUDO_HANDLE, base_ptr, 0, size_ptr, MEM_COMMIT, PAGE_EXECUTE_READWRITE], ctx
    )

    # Behaviour baseline (this FX is diagnostic-only).
    assert rv == STATUS_SUCCESS
    base_out = _read_u32(emu, base_ptr)
    assert base_out != 0
    actual_perms = emu.get_address_perms(base_out)

    observation = _observation(ctx)
    assert observation["api"] == "ntdll.NtAllocateVirtualMemory"
    assert observation["handler"] == "ntoskrnl.ZwAllocateVirtualMemory"
    assert observation["process_handle"] == "0xffffffff"
    assert observation["base_address_ptr"] == hex(base_ptr)
    assert observation["region_size_ptr"] == hex(size_ptr)
    assert observation["region_size"] == "0x1000"
    assert observation["allocation_type"] == "0x1000"
    assert observation["requested_protect"] == "0x40"
    assert "PAGE_EXECUTE_READWRITE" in observation["requested_protect_names"]
    assert observation["status"] == "0x0"
    assert observation["base_address_out"] == hex(base_out)
    # The page trace must state what the returned mapping really carries.
    assert observation["mapping"]["mapped"] is True
    assert observation["mapping"]["emu_perms"] == hex(actual_perms)


def test_nt_allocate_trace_makes_protect_mismatch_visible(emu_env):
    """PAGE_READONLY request vs. the protection the mapping actually got."""
    _, emu = emu_env
    handler = Ntoskrnl(emu)
    scratch = _scratch(emu, "test.fx003.alloc.ro")
    base_ptr = scratch
    size_ptr = scratch + 4
    emu.mem_write(base_ptr, b"\x00" * 4)
    emu.mem_write(size_ptr, struct.pack("<I", 0x1000))
    ctx = {"func_name": "ntdll.NtAllocateVirtualMemory"}

    rv = handler.ZwAllocateVirtualMemory(
        emu, [PSEUDO_HANDLE, base_ptr, 0, size_ptr, MEM_COMMIT, PAGE_READONLY], ctx
    )

    assert rv == STATUS_SUCCESS
    base_out = _read_u32(emu, base_ptr)
    # Baseline behaviour of this diagnostic attempt: the handler still maps the
    # region with the mem_alloc default permissions (Protect not applied yet).
    # If a later FX changes that semantics, update this diagnostic baseline.
    assert emu.get_address_perms(base_out) == common.PERM_MEM_NONE

    observation = _observation(ctx)
    assert observation["requested_protect"] == "0x2"
    # Requested and effective state are both reported, so the mismatch is
    # visible from the report alone (this is the point of FX-003).
    assert observation["mapping"]["emu_perms"] == "0x0"
    assert observation["mapping"]["win_protect"] == "0x1"


def test_nt_protect_trace_records_before_after_registers_and_writeback(emu_env):
    _, emu = emu_env
    handler = Ntoskrnl(emu)
    region = emu.mem_map(0x1000, tag="test.fx003.protect", perms=common.PERM_MEM_READ)
    scratch = _scratch(emu, "test.fx003.ptrs")
    base_ptr, size_ptr, old_ptr = scratch, scratch + 4, scratch + 8
    emu.mem_write(base_ptr, struct.pack("<I", region))
    emu.mem_write(size_ptr, struct.pack("<I", 0x1000))
    emu.mem_write(old_ptr, struct.pack("<I", 0xFFFFFFFF))
    emu.reg_write("eax", 0x11111111)
    emu.reg_write("edi", 0x22222222)
    emu.reg_write("ebp", 0x33333333)
    emu.reg_write("esp", 0x44444444)
    ctx = {"func_name": "ntdll.NtProtectVirtualMemory"}

    rv = handler.ZwProtectVirtualMemory(
        emu, [PSEUDO_HANDLE, base_ptr, size_ptr, PAGE_EXECUTE_READWRITE, old_ptr], ctx
    )

    # Behaviour baseline: STATUS_SUCCESS, page-rounded write-back, old protect.
    assert rv == STATUS_SUCCESS
    assert _read_u32(emu, base_ptr) == region
    assert _read_u32(emu, size_ptr) == 0x1000
    assert _read_u32(emu, old_ptr) == PAGE_READONLY
    assert emu.get_address_win_protection(region) == PAGE_EXECUTE_READWRITE

    observation = _observation(ctx)
    assert observation["api"] == "ntdll.NtProtectVirtualMemory"
    assert observation["handler"] == "ntoskrnl.ZwProtectVirtualMemory"
    assert observation["process_handle"] == "0xffffffff"
    assert observation["base_address_value"] == hex(region)
    assert observation["region_size_value"] == "0x1000"
    assert observation["requested_protect"] == "0x40"
    assert observation["status"] == "0x0"
    before = observation["registers_before"]
    after = observation["registers_after"]
    for name, expected in (
        ("eax", "0x11111111"),
        ("edi", "0x22222222"),
        ("ebp", "0x33333333"),
        ("esp", "0x44444444"),
    ):
        assert before[name] == expected
        # The handler must not clobber the focused registers it never touches.
        assert after[name] == expected
    assert observation["old_protect_written"] == hex(PAGE_READONLY)
    assert observation["base_address_written"] == hex(region)
    assert observation["region_size_written"] == "0x1000"
    assert observation["range_before"]["pages"][0]["win_protect"] == hex(PAGE_READONLY)
    assert observation["range_after"]["pages"][0]["win_protect"] == hex(PAGE_EXECUTE_READWRITE)


def test_nt_protect_failure_trace_and_status_unchanged(emu_env):
    _, emu = emu_env
    handler = Ntoskrnl(emu)
    region = emu.mem_map(0x1000, tag="test.fx003.protect.bad", perms=common.PERM_MEM_READ)
    scratch = _scratch(emu, "test.fx003.badptrs")
    base_ptr, size_ptr, old_ptr = scratch, scratch + 4, scratch + 8
    emu.mem_write(base_ptr, struct.pack("<I", region))
    emu.mem_write(size_ptr, struct.pack("<I", 0x1000))
    emu.mem_write(old_ptr, struct.pack("<I", 0xFFFFFFFF))
    ctx = {"func_name": "ntdll.NtProtectVirtualMemory"}

    rv = handler.ZwProtectVirtualMemory(
        emu, [PSEUDO_HANDLE, base_ptr, size_ptr, 0x55, old_ptr], ctx
    )

    assert rv == STATUS_INVALID_PARAMETER
    # The failed call must not change the page or write the old value.
    assert page_protection.current_win_protection(emu, region) == PAGE_READONLY
    assert _read_u32(emu, old_ptr) == 0xFFFFFFFF

    observation = _observation(ctx)
    assert observation["status"] == hex(STATUS_INVALID_PARAMETER)
    assert observation["old_protect_written"] is None


def test_virtual_protect_trace_records_per_page_state(emu_env):
    _, emu = emu_env
    handler = Kernel32(emu)
    region = emu.mem_map(0x2000, tag="test.fx003.vp", perms=common.PERM_MEM_READ)
    scratch = _scratch(emu, "test.fx003.vpptr")
    old_ptr = scratch
    emu.mem_write(old_ptr, struct.pack("<I", 0xFFFFFFFF))
    ctx = {"func_name": "kernel32.VirtualProtect"}

    rv = handler.VirtualProtect(emu, [region, 0x1800, PAGE_READWRITE, old_ptr], ctx)

    # Behaviour baseline: BOOL success, old protect of the first page, new perms.
    assert rv == 1
    assert _read_u32(emu, old_ptr) == PAGE_READONLY
    assert emu.get_address_perms(region) == (common.PERM_MEM_READ | common.PERM_MEM_WRITE)
    assert emu.get_address_win_protection(region) == PAGE_READWRITE

    observation = _observation(ctx)
    assert observation["api"] == "kernel32.VirtualProtect"
    assert observation["lp_address"] == hex(region)
    assert observation["dw_size"] == "0x1800"
    assert observation["new_protect"] == "0x4"
    assert observation["success"] is True
    assert observation["return_value"] == "0x1"
    assert observation["old_protect_written"] == hex(PAGE_READONLY)
    assert observation["pages_truncated"] is False
    pages = observation["pages"]
    # 0x1800 bytes starting at a page boundary cover exactly two pages.
    assert len(pages) == 2
    for page in pages:
        assert page["before"]["mapped"] is True
        assert page["before"]["win_protect"] == hex(PAGE_READONLY)
        assert page["after"]["win_protect"] == hex(PAGE_READWRITE)
        assert page["after"]["emu_perms"] == hex(common.PERM_MEM_READ | common.PERM_MEM_WRITE)
    assert pages[0]["address"] == hex(region)
    assert pages[1]["address"] == hex(region + 0x1000)


def test_virtual_protect_failure_trace_without_behaviour_change(emu_env):
    _, emu = emu_env
    handler = Kernel32(emu)
    region = emu.mem_map(0x1000, tag="test.fx003.vp.bad", perms=common.PERM_MEM_READ)
    scratch = _scratch(emu, "test.fx003.vpbadptr")
    old_ptr = scratch
    emu.mem_write(old_ptr, struct.pack("<I", 0xFFFFFFFF))
    before_perms = emu.get_address_perms(region)
    ctx = {"func_name": "kernel32.VirtualProtect"}

    rv = handler.VirtualProtect(emu, [region, 0x1000, 0x55, old_ptr], ctx)

    assert rv == 0
    assert emu.get_last_error() == ERROR_INVALID_PARAMETER
    assert emu.get_address_perms(region) == before_perms
    assert _read_u32(emu, old_ptr) == 0xFFFFFFFF

    observation = _observation(ctx)
    assert observation["success"] is False
    assert observation["return_value"] == "0x0"
    assert observation["error"] == hex(ERROR_INVALID_PARAMETER)
    assert observation["last_error"] == hex(ERROR_INVALID_PARAMETER)
    assert observation["old_protect_written"] is None
    assert observation["pages"][0]["after"]["win_protect"] == hex(PAGE_READONLY)

    # Counterexample: a NULL lpflOldProtect fails before any page is touched.
    ctx_null = {"func_name": "kernel32.VirtualProtect"}
    rv_null = handler.VirtualProtect(emu, [region, 0x1000, PAGE_READWRITE, 0], ctx_null)
    assert rv_null == 0
    assert emu.get_last_error() == ERROR_INVALID_PARAMETER
    assert emu.get_address_perms(region) == before_perms
    null_observation = _observation(ctx_null)
    assert null_observation["success"] is False
    assert null_observation["old_protect_ptr"] == "0x0"


def test_lstrcpy_trace_records_source_and_patch_bytes(emu_env):
    _, emu = emu_env
    handler = Kernel32(emu)
    scratch = _scratch(emu, "test.fx003.lstrcpy")
    src = scratch + 0x40
    dst = scratch + 0x50
    emu.mem_write(src, b"ABCD\x00")
    ctx = {"func_name": "kernel32.lstrcpyA"}

    rv = handler.lstrcpy(emu, [dst, src], ctx)

    # Behaviour baseline: lpString1 is returned and the NUL-terminated copy lands.
    assert rv == dst
    assert emu.mem_read(dst, 5) == b"ABCD\x00"

    observation = _observation(ctx)
    assert observation["api"] == "kernel32.lstrcpyA"
    assert observation["destination"] == hex(dst)
    assert observation["source"] == hex(src)
    assert observation["char_width"] == 1
    assert observation["source_preview"] == "ABCD"
    assert observation["destination_page"]["mapped"] is True
    assert observation["patch_byte_length"] == 5
    assert observation["patch_preview"] == b"ABCD\x00".hex()
    assert observation["patch_truncated"] is False


def test_lstrcpy_wide_trace_records_patch_bytes(emu_env):
    _, emu = emu_env
    handler = Kernel32(emu)
    scratch = _scratch(emu, "test.fx003.lstrcpyw")
    src = scratch + 0x40
    dst = scratch + 0x50
    emu.mem_write(src, "AB\x00".encode("utf-16le"))
    ctx = {"func_name": "kernel32.lstrcpyW"}

    rv = handler.lstrcpy(emu, [dst, src], ctx)

    assert rv == dst
    assert emu.mem_read(dst, 6) == "AB\x00".encode("utf-16le")
    observation = _observation(ctx)
    assert observation["api"] == "kernel32.lstrcpyW"
    assert observation["char_width"] == 2
    assert observation["patch_byte_length"] == 6
    assert observation["patch_preview"] == "AB\x00".encode("utf-16le").hex()


def test_lstrcpy_unmapped_destination_keeps_exception_and_records_evidence(emu_env):
    _, emu = emu_env
    handler = Kernel32(emu)
    scratch = _scratch(emu, "test.fx003.lstrcpy.unmapped")
    src = scratch + 0x40
    emu.mem_write(src, b"ABCD\x00")
    ctx = {"func_name": "kernel32.lstrcpyA"}

    # Behaviour baseline: the handler's write to an unmapped page still raises.
    with pytest.raises(uc.UcError):
        handler.lstrcpy(emu, [UNMAPPED_ADDRESS, src], ctx)

    # The evidence survives the exception because it was attached before the
    # write; winemu.attach_handler_observation then folds it into the report.
    observation = _observation(ctx)
    assert observation["destination"] == hex(UNMAPPED_ADDRESS)
    assert observation["destination_page"]["mapped"] is False
    assert observation["source_preview"] == "ABCD"
    assert observation["patch_preview"] == b"ABCD\x00".hex()


def test_attach_handler_observation_merges_into_error_report():
    observation = {"kind": OBSERVATION_KIND, "schema_version": 1, "api": "kernel32.lstrcpyA"}
    error = ErrorInfo(type="Invalid memory write (UC_ERR_WRITE_UNMAPPED)")

    winemu.attach_handler_observation(error, {"_api_observation": observation})

    assert error.type == "Invalid memory write (UC_ERR_WRITE_UNMAPPED)"
    assert error.diagnostics["api_observation"] is observation

    # Existing diagnostics are preserved, not replaced.
    existing = ErrorInfo(type="x", diagnostics={"kind": "api_trace_diagnostic"})
    winemu.attach_handler_observation(existing, {"_api_observation": observation})
    assert existing.diagnostics["kind"] == "api_trace_diagnostic"
    assert existing.diagnostics["api_observation"] is observation

    # Missing/non-dict observations leave the error untouched.
    untouched = ErrorInfo(type="y")
    winemu.attach_handler_observation(untouched, {})
    winemu.attach_handler_observation(untouched, None)
    winemu.attach_handler_observation(untouched, {"_api_observation": "not-a-dict"})
    assert untouched.diagnostics is None
