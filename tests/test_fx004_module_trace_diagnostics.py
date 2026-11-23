"""FX-004 diagnostic contract tests: module unload / module table / synthetic module mapping.

The work order (``Loader / loadlibrary``) asks for *evidence only* around three
failure mechanisms:

* ``LdrUnloadDll`` / ``FreeLibrary``: the unload argument, the API return
  value, whether the loaded-module table actually changed, and the caller
  registers (EAX/EBX/ECX/EDX or x64 equivalents) that later participate in
  address computation.
* ``GetModuleHandleExW``: flags (including ``FROM_ADDRESS``), the module-name
  argument, the ``phModule`` write-back, the module table, and the miss reason.
* ``LoadLibraryA`` / ``GetProcAddress``: the requested name, the returned
  module/export address, the loaded module's base/size/loader and per-section
  mapping/readability, and the target-address provenance (mapping, module,
  section, sentinel membership).

Every observation must be read-only: handler return values, module tables,
page permissions, exception dispatch and control flow are unchanged.  The
tests therefore assert the new evidence *and* the pre-existing behaviour on
the same calls.

These tests fail against the pre-FX-004 implementation (no
``module_trace_diagnostic`` observation for any of these calls) and pass once
the diagnostics are attached.
"""

from __future__ import annotations

import lzma
import struct
from pathlib import Path

import pytest

from speakeasy import Speakeasy
from speakeasy.windows import common as wincommon

BINS = Path(__file__).resolve().parent / "bins"
PRIMARY_EXE = "seh_test_x86.exe.xz"
TEST_DLL = "dll_test_x86.dll.xz"

DROP_PATH = r"C:\Windows\temp\fx004_dropped.dll"
DROPPED_EXPORT_ONE_RVA = 0x1030

GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS = 0x4

OBSERVATION_KIND = "module_trace_diagnostic"
MERGE_KEY = "module_unload_trace"

_NEXT_STRING_PAGE = [0x1E800000]


def _bin(name: str) -> bytes:
    with lzma.open(BINS / name) as fh:
        return fh.read()


@pytest.fixture
def engine(config):
    """Speakeasy with the test EXE loaded as the primary (is_exe) module."""
    se = Speakeasy(config=config)
    try:
        se.load_module(data=_bin(PRIMARY_EXE))
        yield se
    finally:
        se.shutdown()


def _kernel32(emu):
    return emu.api.load_api_handler("kernel32")


def _alloc_string(emu, text: str) -> int:
    # GetProcAddress treats pointers below 0x10000 as ordinals.
    base = _NEXT_STRING_PAGE[0]
    _NEXT_STRING_PAGE[0] += 0x1000
    addr = emu.mem_map(0x1000, base=base, tag="fx004.test")
    emu.mem_write(addr, text.encode("ascii") + b"\x00")
    return addr


def _alloc_wstring(emu, text: str) -> int:
    base = _NEXT_STRING_PAGE[0]
    _NEXT_STRING_PAGE[0] += 0x1000
    addr = emu.mem_map(0x1000, base=base, tag="fx004.test.w")
    emu.mem_write(addr, text.encode("utf-16le") + b"\x00\x00")
    return addr


def _scratch(emu, size=0x100) -> int:
    return emu.mem_map(size, tag="fx004.test.scratch")


def _load_library(emu, name: str):
    name_ptr = _alloc_string(emu, name)
    ctx = {"func_name": "kernel32.LoadLibraryA"}
    rv = _kernel32(emu).LoadLibrary(emu, [name_ptr], ctx)
    return rv, ctx


def _get_proc_address(emu, hmod: int, name: str):
    name_ptr = _alloc_string(emu, name)
    ctx = {"func_name": "kernel32.GetProcAddress"}
    rv = _kernel32(emu).GetProcAddress(emu, [hmod, name_ptr], ctx)
    return rv, ctx


def _observation(ctx):
    observation = ctx.get("_api_observation")
    assert isinstance(observation, dict), "handler attached no diagnostic observation"
    return observation


def _module_observation(ctx):
    observation = _observation(ctx)
    if observation.get("kind") == OBSERVATION_KIND:
        return observation
    nested = observation.get(MERGE_KEY)
    assert isinstance(nested, dict), (
        f"no {OBSERVATION_KIND!r} observation (top-level kind="
        f"{observation.get('kind')!r}, keys={sorted(observation)})"
    )
    return nested


def _api_events(report, api_name):
    events = report.entry_points[0].events or []
    return [
        event
        for event in events
        if getattr(event, "event", None) == "api"
        and getattr(event, "api_name", None) == api_name
    ]


def _api_event(report, api_name):
    matches = _api_events(report, api_name)
    assert matches, f"no {api_name} event recorded"
    return matches[-1]


class _X86Asm:
    def __init__(self) -> None:
        self.buf = bytearray()
        self.patches: list[tuple[int, str]] = []

    def imm32(self, key: str) -> None:
        offset = len(self.buf)
        self.buf += b"\x00\x00\x00\x00"
        self.patches.append((offset, key))

    def push_imm32(self, value: int) -> None:
        self.buf += b"\x68" + struct.pack("<I", value & 0xFFFFFFFF)

    def push_abs(self, key: str) -> None:
        self.buf += b"\x68"
        self.imm32(key)

    def mov_eax_abs(self, key: str) -> None:
        self.buf += b"\xb8"
        self.imm32(key)

    def call_eax(self) -> None:
        self.buf += b"\xff\xd0"

    def ret(self) -> None:
        self.buf += b"\xc3"


def _run_x86_calls(config, calls):
    """Run ``(dll, name, [args])`` calls from x86 shellcode; return the report.

    ``args`` items are immediates.  A final ``ret`` ends the run through the
    engine's return sentinel.
    """
    asm = _X86Asm()
    api_keys = []
    for index, (dll, name, args) in enumerate(calls):
        api_key = f"api{index}"
        api_keys.append((api_key, dll, name))
        for arg in reversed(args):
            assert isinstance(arg, int)
            asm.push_imm32(arg)
        asm.mov_eax_abs(api_key)
        asm.call_eax()
    asm.ret()

    code = bytes(asm.buf)
    se = Speakeasy(config=config)
    try:
        sc_addr = se.load_shellcode(data=code, arch="x86")
        emu = se.emu
        assert emu is not None
        values = {}
        for api_key, dll, name in api_keys:
            values[api_key] = emu.get_proc(dll, name)
        assert all(values.values())
        for offset, key in asm.patches:
            emu.mem_write(sc_addr + offset, struct.pack("<I", values[key] & 0xFFFFFFFF))
        se.run_shellcode(sc_addr)
        return se.get_report(), emu
    finally:
        se.shutdown()


# ---------------------------------------------------------------------------
# FreeLibrary: unload evidence, module table unchanged, continue execution
# ---------------------------------------------------------------------------


def test_free_library_observation_reports_handle_and_unchanged_module_table(engine):
    emu = engine.emu
    kernel32 = emu.get_mod_by_name("kernel32")
    assert kernel32 is not None

    ctx = {"func_name": "kernel32.FreeLibrary"}
    rv = _kernel32(emu).FreeLibrary(emu, [kernel32.base], ctx)

    # Behaviour baseline: the handler still returns TRUE.
    assert rv is True
    observation = _module_observation(ctx)
    assert observation["kind"] == OBSERVATION_KIND
    assert observation["schema_version"] == 1
    assert observation["api"] == "kernel32.FreeLibrary"
    assert observation["domain"] == "loader_unload"
    assert observation["arguments"]["handle"] == hex(kernel32.base)
    assert observation["module_before"]["name"].lower() == "kernel32.dll"
    assert observation["module_before"]["base"] == hex(kernel32.base)
    assert observation["return_value"] == "0x1"
    # The loaded-module snapshot must show that no module was removed.
    assert observation["module_present_after"] is True
    assert observation["module_unloaded"] is False
    after = observation["module_table_after"]
    assert after["count"] == observation["module_count_before"]
    bases = {entry["base"] for entry in after["modules"]}
    assert hex(kernel32.base) in bases
    # Caller provenance is present and explicit even on a direct handler call.
    assert "registers" in observation["caller"]


def test_free_library_of_unloaded_handle_keeps_true_and_reports_miss(engine):
    emu = engine.emu
    ctx = {"func_name": "kernel32.FreeLibrary"}
    rv = _kernel32(emu).FreeLibrary(emu, [0xDEADBEEF], ctx)

    # Negative case: the engine's existing TRUE return is unchanged; the
    # diagnostic must make the absent/unmatched module explicit.
    assert rv is True
    observation = _module_observation(ctx)
    assert observation["arguments"]["handle"] == "0xdeadbeef"
    assert observation["module_before"] is None
    assert observation["module_present_after"] is False
    assert observation["module_unloaded"] is False
    assert observation["miss_reason"] == "handle_not_in_module_table"


def test_free_library_then_continue_execution_reports_and_completes(config):
    se = Speakeasy(config=config)
    try:
        asm = _X86Asm()
        asm.push_imm32(0)  # placeholder, patched below with the kernel32 base
        asm.mov_eax_abs("free")
        asm.call_eax()
        asm.push_imm32(0)
        asm.mov_eax_abs("exit")
        asm.call_eax()
        code = bytes(asm.buf)
        sc_addr = se.load_shellcode(data=code, arch="x86")
        emu = se.emu
        assert emu is not None
        kernel32 = emu.get_mod_by_name("kernel32")
        assert kernel32 is not None
        free_stub = emu.get_proc("kernel32", "FreeLibrary")
        exit_stub = emu.get_proc("kernel32", "ExitProcess")
        assert free_stub and exit_stub
        # The first `push imm32` lives at offset 1.
        emu.mem_write(sc_addr + 1, struct.pack("<I", kernel32.base))
        values = {"free": free_stub, "exit": exit_stub}
        for offset, key in asm.patches:
            emu.mem_write(sc_addr + offset, struct.pack("<I", values[key]))

        se.run_shellcode(sc_addr)
        report = se.get_report()
    finally:
        se.shutdown()

    entry = report.entry_points[0]
    assert entry.error is None, entry.error
    event = _api_event(report, "kernel32.FreeLibrary")
    observation = event.observation
    assert isinstance(observation, dict)
    trace = observation.get(MERGE_KEY)
    assert isinstance(trace, dict), (
        "FreeLibrary observation must keep the FX-015 scatter fields and add "
        f"the {MERGE_KEY!r} trace (keys={sorted(observation)})"
    )
    assert observation.get("kind") != OBSERVATION_KIND  # FX-015 top level preserved
    assert trace["kind"] == OBSERVATION_KIND
    assert trace["module_unloaded"] is False
    assert trace["return_value"] == "0x1"
    # Execution continued past the unload call to ExitProcess.
    assert _api_events(report, "kernel32.ExitProcess")


# ---------------------------------------------------------------------------
# LdrUnloadDll: signature-emulated unload with no handler
# ---------------------------------------------------------------------------


def test_ldr_unload_dll_signature_call_records_arguments_and_status(config):
    report, emu = _run_x86_calls(
        config,
        [
            ("ntdll", "LdrUnloadDll", [0xDEADBEEF]),
            ("kernel32", "ExitProcess", [0]),
        ],
    )

    entry = report.entry_points[0]
    assert entry.error is None, entry.error
    event = _api_event(report, "ntdll.LdrUnloadDll")
    observation = event.observation
    assert isinstance(observation, dict), "signature-emulated LdrUnloadDll has no observation"
    assert observation["kind"] == OBSERVATION_KIND
    assert observation["schema_version"] == 1
    assert observation["api"] == "ntdll.LdrUnloadDll"
    assert observation["domain"] == "loader_unload"
    assert observation["emulated_from_signature"] is True
    assert observation["handler"] is None
    assert observation["signature_source"] == "phnt"
    assert observation["signature_return_kind"] == "i32"
    assert observation["arguments"]["argument_name"] == "DllHandle"
    assert observation["arguments"]["dll_handle"] == "0xdeadbeef"
    # The handle does not match a loaded module.
    assert observation["module_before"] is None
    # Behaviour baseline of the signature fallback: i32 default 0 (success-like).
    assert observation["return_value"] == "0x0"
    assert observation["return_status"] == "STATUS_SUCCESS"
    # The signature path performs no unload; the evidence says so explicitly.
    assert observation["unload_implemented"] is False
    assert observation["module_table"]["count"] > 0
    assert observation["caller"]["call_pc"] is not None
    assert "eax" in observation["caller"]["registers"]
    assert "ebx" in observation["caller"]["register_provenance"]


def test_ldr_unload_dll_valid_module_returns_zero_without_unloading(config):
    se = Speakeasy(config=config)
    try:
        asm = _X86Asm()
        asm.push_imm32(0)  # placeholder, patched below with the kernel32 base
        asm.mov_eax_abs("unload")
        asm.call_eax()
        asm.push_imm32(0)
        asm.mov_eax_abs("exit")
        asm.call_eax()
        code = bytes(asm.buf)
        sc_addr = se.load_shellcode(data=code, arch="x86")
        emu = se.emu
        assert emu is not None
        kernel32 = emu.get_mod_by_name("kernel32")
        assert kernel32 is not None
        unload_stub = emu.get_proc("ntdll", "LdrUnloadDll")
        exit_stub = emu.get_proc("kernel32", "ExitProcess")
        assert unload_stub and exit_stub
        # DllHandle = a really loaded module; first `push imm32` is at offset 1.
        emu.mem_write(sc_addr + 1, struct.pack("<I", kernel32.base))
        values = {"unload": unload_stub, "exit": exit_stub}
        for offset, key in asm.patches:
            emu.mem_write(sc_addr + offset, struct.pack("<I", values[key]))
        se.run_shellcode(sc_addr)
        report = se.get_report()
        # The module is still loaded after the call.
        still_loaded = emu.get_module_by_handle(kernel32.base)
    finally:
        se.shutdown()

    entry = report.entry_points[0]
    assert entry.error is None, entry.error
    event = _api_event(report, "ntdll.LdrUnloadDll")
    observation = event.observation
    assert isinstance(observation, dict)
    assert observation["arguments"]["dll_handle"] == hex(kernel32.base)
    assert observation["module_before"]["base"] == hex(kernel32.base)
    assert observation["return_value"] == "0x0"
    assert observation["unload_implemented"] is False
    assert still_loaded is not None


# ---------------------------------------------------------------------------
# GetModuleHandleExW: flags / name / phModule / module table
# ---------------------------------------------------------------------------


def test_get_module_handle_ex_w_hit_reports_module_and_writeback(engine):
    emu = engine.emu
    kernel32 = emu.get_mod_by_name("kernel32")
    assert kernel32 is not None
    name_ptr = _alloc_wstring(emu, "kernel32.dll")
    ph_module = _scratch(emu)
    emu.mem_write(ph_module, b"\x00" * 4)

    ctx = {"func_name": "kernel32.GetModuleHandleExW"}
    rv = _kernel32(emu).GetModuleHandleEx(emu, [0, name_ptr, ph_module], ctx)

    # Behaviour baseline: same HMODULE and the same write-back.
    assert rv == kernel32.base
    assert int.from_bytes(emu.mem_read(ph_module, 4), "little") == kernel32.base

    observation = _module_observation(ctx)
    assert observation["kind"] == OBSERVATION_KIND
    assert observation["api"] == "kernel32.GetModuleHandleExW"
    assert observation["domain"] == "loader_module_handle"
    assert observation["flags"] == "0x0"
    assert observation["from_address"] is False
    assert observation["lp_module_name"] == "kernel32.dll"
    assert observation["module_name_kind"] == "name"
    assert observation["ph_module"] == hex(ph_module)
    assert observation["ph_module_written"] == hex(kernel32.base)
    assert observation["return_value"] == hex(kernel32.base)
    assert observation["module_found"] is True
    assert observation["module"]["base"] == hex(kernel32.base)
    table = observation["module_table_before"]
    assert table["count"] > 0
    assert hex(kernel32.base) in {entry["base"] for entry in table["modules"]}


def test_get_module_handle_ex_w_miss_reports_zero_and_reason(engine):
    emu = engine.emu
    name_ptr = _alloc_wstring(emu, "fx004_definitely_not_loaded.dll")
    ph_module = _scratch(emu)
    emu.mem_write(ph_module, b"\xAA" * 4)

    ctx = {"func_name": "kernel32.GetModuleHandleExW"}
    rv = _kernel32(emu).GetModuleHandleEx(emu, [0, name_ptr, ph_module], ctx)

    # Behaviour baseline: miss still returns 0 and writes 0.
    assert rv == 0
    assert int.from_bytes(emu.mem_read(ph_module, 4), "little") == 0

    observation = _module_observation(ctx)
    assert observation["lp_module_name"] == "fx004_definitely_not_loaded.dll"
    assert observation["return_value"] == "0x0"
    assert observation["ph_module_written"] == "0x0"
    assert observation["module_found"] is False
    assert observation["module"] is None
    assert observation["miss_reason"] == "name_not_in_module_table"


def test_get_module_handle_ex_w_from_address_flag_is_explicit(engine):
    emu = engine.emu
    kernel32 = emu.get_mod_by_name("kernel32")
    assert kernel32 is not None
    ph_module = _scratch(emu)
    emu.mem_write(ph_module, b"\x00" * 4)

    ctx = {"func_name": "kernel32.GetModuleHandleExW"}
    rv = _kernel32(emu).GetModuleHandleEx(
        emu, [GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, kernel32.base, ph_module], ctx
    )

    # Behaviour baseline is unchanged: the handler still treats the argument as
    # a name string and misses.  The diagnostic must expose the flag semantics.
    assert rv == 0
    observation = _module_observation(ctx)
    assert observation["flags"] == "0x4"
    assert observation["from_address"] is True
    assert "GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS" in observation["flags_names"]
    assert observation["module_name_kind"] == "address"
    assert observation["lp_module_name"] is None
    assert observation["address_module"]["base"] == hex(kernel32.base)
    # Explicit semantics mismatch: FROM_ADDRESS means an address, but the
    # current handler resolved it through the string-name path.
    assert observation["handler_treats_address_as_name"] is True
    assert observation["return_value"] == "0x0"


# ---------------------------------------------------------------------------
# LoadLibraryA: synthetic module base/size/section mapping
# ---------------------------------------------------------------------------


def test_load_library_guest_pe_reports_sections_and_mapping(engine):
    emu = engine.emu
    emu.fileman.add_existing_file(DROP_PATH, _bin(TEST_DLL))

    rv, ctx = _load_library(emu, DROP_PATH)
    assert rv != 0
    mod = emu.get_mod_by_name("fx004_dropped")
    assert mod is not None and mod.base == rv

    observation = _module_observation(ctx)
    assert observation["kind"] == OBSERVATION_KIND
    assert observation["api"] == "kernel32.LoadLibraryA"
    assert observation["domain"] == "loader_load"
    assert observation["lp_lib_file_name"] == DROP_PATH
    assert observation["normalized_name"] == "fx004_dropped"
    assert observation["return_value"] == hex(rv)
    assert observation["module_loaded"] is True
    assert observation["miss_reason"] is None
    loaded = observation["loaded_module"]
    assert loaded["base"] == hex(rv)
    assert loaded["image_size"] != "0x0"
    assert loaded["loader"] is not None  # e.g. "PeLoader"
    assert loaded["sections"], "loaded module has no section trace"
    section = loaded["sections"][0]
    for key in ("name", "virtual_address", "virtual_size", "start", "end", "mapping", "readable"):
        assert key in section
    assert loaded["header"]["readable"] is True
    after = observation["module_table_after"]
    assert hex(rv) in {entry["base"] for entry in after["modules"]}


def test_load_library_unknown_dll_reports_failed_load(engine):
    emu = engine.emu
    before = {entry["base"] for entry in _module_observation_count(emu)}

    rv, ctx = _load_library(emu, "fx004_definitely_not_a_system_dll")

    assert rv == 0  # behaviour baseline
    observation = _module_observation(ctx)
    assert observation["return_value"] == "0x0"
    assert observation["module_loaded"] is False
    assert observation["loaded_module"] is None
    assert observation["miss_reason"] == "returned_null"
    after = observation["module_table_after"]
    assert {entry["base"] for entry in after["modules"]} == before


def _module_observation_count(emu):
    """Return module-table entries before the call (test helper only)."""
    return [
        {"name": getattr(mod, "name", None), "base": hex(mod.base)}
        for mod in emu.modules
    ]


# ---------------------------------------------------------------------------
# GetProcAddress: export resolution and target-page provenance
# ---------------------------------------------------------------------------


def test_get_proc_address_real_export_reports_target_provenance(engine):
    emu = engine.emu
    emu.fileman.add_existing_file(DROP_PATH, _bin(TEST_DLL))
    hmod, _ = _load_library(emu, DROP_PATH)
    assert hmod != 0

    rv, ctx = _get_proc_address(emu, hmod, "emu_test_one")

    # Behaviour baseline: a real PE export resolves to its mapped code address.
    assert rv == hmod + DROPPED_EXPORT_ONE_RVA
    observation = _module_observation(ctx)
    assert observation["kind"] == OBSERVATION_KIND
    assert observation["api"] == "kernel32.GetProcAddress"
    assert observation["domain"] == "loader_get_proc_address"
    assert observation["h_module"] == hex(hmod)
    assert observation["module"]["base"] == hex(hmod)
    assert observation["lp_proc_name"] == "emu_test_one"
    assert observation["export_found"] is True
    assert observation["export"]["address"] == hex(rv)
    assert observation["return_value"] == hex(rv)
    assert observation["resolved_is_sentinel"] is False
    assert observation["sentinel_target"] is None
    target = observation["target"]
    assert target["address"] == hex(rv)
    assert target["mapping"]["mapped"] is True
    assert target["readable"] is True
    assert target["module"]["base"] == hex(hmod)
    assert target["section"] is not None
    assert observation["module_header"]["readable"] is True


def test_get_proc_address_handler_export_reports_sentinel_dispatch(engine):
    emu = engine.emu
    kernel32 = emu.get_mod_by_name("kernel32")
    assert kernel32 is not None

    rv, ctx = _get_proc_address(emu, kernel32.base, "CreateFileA")

    # Behaviour baseline: handler-backed exports resolve to a dispatch sentinel.
    assert rv != 0
    assert wincommon.EMU_RESERVED <= rv < wincommon.EMU_RESERVED_END
    observation = _module_observation(ctx)
    assert observation["export_found"] is True
    assert observation["resolved_is_sentinel"] is True
    assert observation["sentinel_target"]["module"] == "kernel32"
    assert observation["sentinel_target"]["function"] == "CreateFileA"
    assert observation["target"]["address"] == hex(rv)


def test_get_proc_address_missing_export_reports_null_handle_and_miss(engine):
    emu = engine.emu
    emu.fileman.add_existing_file(DROP_PATH, _bin(TEST_DLL))
    hmod, _ = _load_library(emu, DROP_PATH)
    assert hmod != 0

    rv, ctx = _get_proc_address(emu, hmod, "Fx004MissingFromDroppedDll")

    # Behaviour baseline: a missing export of a loaded non-EXE module still
    # returns the existing dispatch sentinel policy.
    assert rv != 0
    assert wincommon.EMU_RESERVED <= rv < wincommon.EMU_RESERVED_END
    observation = _module_observation(ctx)
    assert observation["export_found"] is False
    assert observation["export"] is None
    assert observation["resolved_is_sentinel"] is True
    assert observation["miss_reason"] == "export_not_in_module"

    rv_null, ctx_null = _get_proc_address(emu, 0, "CreateFileA")
    assert rv_null == 0  # behaviour baseline
    null_observation = _module_observation(ctx_null)
    assert null_observation["h_module"] == "0x0"
    assert null_observation["module"] is None
    assert null_observation["return_value"] == "0x0"
    assert null_observation["miss_reason"] == "null_or_unknown_module_handle"


# ---------------------------------------------------------------------------
# Diagnostic helpers must never change behaviour or raise
# ---------------------------------------------------------------------------


def test_loader_handlers_keep_their_return_contracts(engine):
    """One mixed pass over the four handlers: values identical to pre-FX-004."""
    emu = engine.emu
    kernel32 = emu.get_mod_by_name("kernel32")
    assert kernel32 is not None

    free_ctx = {"func_name": "kernel32.FreeLibrary"}
    assert _kernel32(emu).FreeLibrary(emu, [kernel32.base], free_ctx) is True

    name_ptr = _alloc_wstring(emu, "kernel32.dll")
    ph_module = _scratch(emu)
    ex_ctx = {"func_name": "kernel32.GetModuleHandleExW"}
    assert _kernel32(emu).GetModuleHandleEx(emu, [0, name_ptr, ph_module], ex_ctx) == kernel32.base

    rv, gpa_ctx = _get_proc_address(emu, kernel32.base, "CreateFileA")
    assert wincommon.EMU_RESERVED <= rv < wincommon.EMU_RESERVED_END

    unknown, load_ctx = _load_library(emu, "fx004_definitely_not_a_system_dll")
    assert unknown == 0
    # Every call attached a trace (top-level or merged) without raising.
    for ctx in (free_ctx, ex_ctx, gpa_ctx, load_ctx):
        assert isinstance(_module_observation(ctx), dict)
