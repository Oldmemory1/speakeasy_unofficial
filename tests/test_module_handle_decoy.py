"""Contract tests for known-system-module synthesis and GetModuleHandle lookup (FX-014).

``Loader / getmodulehandle_msjava``: two module-existence gaps.

* ``GetModuleHandle`` only walked the PEB-visible module list and discarded the
  requested name on a miss.
* ``LoadLibrary`` returned NULL for known Windows system DLLs that Speakeasy
  does not model with an API handler (``msjava``, ``sechost``, ...), even
  though a real Windows/Wine host can load them.

The fix consults all loaded modules first, records misses, and synthesizes an
export-table decoy for names explicitly listed in
``modules.synthesized_system_modules``.  Genuinely unknown DLLs still return
NULL.  COM failure semantics are FX-005's domain: loading a decoy must not
change ``CoGetClassObject`` behaviour, so a regression test also exercises the
unknown-CLSID path from the same engine.

These tests drive the real handlers from x86 shellcode loaded by the engine;
no batch sample is executed.
"""

from __future__ import annotations

import logging
import struct
import uuid

import pytest

from speakeasy import Speakeasy

S_RET = 0x00
SLOT_SIZE = 0x4

REGDB_E_CLASSNOTREG = 0x80040154
SENTINEL = 0xDEADBEEF

CLSID_UNKNOWN = uuid.UUID("{3EFB1800-C2A1-11CF-960C-0080C7C2BA87}").bytes_le
IID_IUNKNOWN = uuid.UUID("{00000001-0000-0000-C000-000000000046}").bytes_le


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

    def push_ptr_abs(self, key: str, addend: int = 0) -> None:
        self.buf += b"\xff\x35"
        self.imm32(key, addend)

    def mov_eax_abs(self, key: str, addend: int = 0) -> None:
        self.buf += b"\xb8"
        self.imm32(key, addend)

    def mov_ptr_abs_eax(self, key: str, addend: int = 0) -> None:
        self.buf += b"\xa3"
        self.imm32(key, addend)

    def call_eax(self) -> None:
        self.buf += b"\xff\xd0"

    def ret(self) -> None:
        self.buf += b"\xc3"


class SlotValue:
    """Call argument passed by value from a named return slot."""

    def __init__(self, alias: str) -> None:
        self.alias = alias


class _Program:
    """Guest program: named strings/blobs, named return slots, resolved calls."""

    def __init__(self) -> None:
        self.asm = _Asm()
        self.data: dict[str, bytes] = {}
        self.slots: list[str] = []
        self.initial: dict[str, int] = {}

    def string(self, alias: str, value: str) -> str:
        self.data[alias] = value.encode("ascii") + b"\x00"
        return alias

    def blob(self, alias: str, value: bytes) -> str:
        self.data[alias] = value
        return alias

    def slot(self, alias: str, initial: int = 0) -> str:
        self.slots.append(alias)
        self.initial[alias] = initial
        return alias

    def call(self, dll: str, api: str, *args: str | int | SlotValue) -> str:
        """Emit ``dll!api(args...)`` and store the return value in a fresh slot."""
        result = self.slot(f"ret{len(self.slots)}")
        for arg in reversed(args):
            if isinstance(arg, SlotValue):
                self.asm.push_ptr_abs(f"slot:{arg.alias}")
            elif isinstance(arg, int):
                self.asm.push_imm32(arg)
            elif arg in self.data:
                self.asm.push_abs(f"data:{arg}")
            else:
                self.asm.push_abs(f"slot:{arg}")
        self.asm.mov_eax_abs(f"api:{dll}.{api}")
        self.asm.call_eax()
        self.asm.mov_ptr_abs_eax(f"slot:{result}", S_RET)
        return result

    def ret(self) -> None:
        self.asm.ret()


class _RunResult:
    def __init__(self, values: dict[str, int], modules: list[tuple[str, int, list[str]]]) -> None:
        self.values = values
        self.modules = modules

    def get(self, alias: str) -> int:
        return self.values[alias]

    def module_by_name(self, name: str) -> tuple[str, int, list[str]] | None:
        lowered = name.lower()
        for mod_name, base, exports in self.modules:
            if mod_name.lower() == lowered:
                return mod_name, base, exports
        return None


def _run_program(config, program: _Program) -> _RunResult:
    code = bytes(program.asm.buf)

    data = bytearray()
    offsets: dict[str, int] = {}
    for alias, blob in program.data.items():
        offsets[f"data:{alias}"] = len(data)
        data += blob
    while len(data) % SLOT_SIZE:
        data += b"\x00"
    for alias in program.slots:
        offsets[f"slot:{alias}"] = len(data)
        data += struct.pack("<I", program.initial.get(alias, 0) & 0xFFFFFFFF)
    data += b"\x00" * 0x10

    se = Speakeasy(config=config)
    try:
        sc_addr = se.load_shellcode(data=code + bytes(data), arch="x86")
        emu = se.emu
        assert emu is not None
        base = sc_addr + len(code)
        values: dict[str, int] = {key: base + offset for key, offset in offsets.items()}
        for _, key, _ in program.asm.patches:
            if key.startswith("api:") and key not in values:
                dll, api = key.split(":", 1)[1].split(".", 1)
                values[key] = emu.get_proc(dll, api)
        assert all(values.values()), f"unresolved program fixups: {values}"

        for offset, key, addend in program.asm.patches:
            emu.mem_write(
                sc_addr + offset,
                struct.pack("<I", (values[key] + addend) & 0xFFFFFFFF),
            )

        # Initialize explicit slot values before the guest runs.
        for alias, initial in program.initial.items():
            emu.mem_write(values[f"slot:{alias}"], struct.pack("<I", initial & 0xFFFFFFFF))

        se.run_shellcode(sc_addr)
        report = se.get_report()
        entry = report.entry_points[0]
        assert entry.error is None, entry.error

        slot_values = {
            alias: int.from_bytes(emu.mem_read(values[f"slot:{alias}"], 4), "little") for alias in program.slots
        }
        modules = [
            (mod.name or mod.get_base_name(), mod.base, [exp.name for exp in mod.get_exports() if exp.name])
            for mod in emu.modules
        ]
        return _RunResult(slot_values, modules)
    finally:
        se.shutdown()


def _call_string_api(config, dll: str, api: str, name: str) -> tuple[int, _RunResult]:
    program = _Program()
    program.string("name", name)
    result_slot = program.call(dll, api, "name")
    program.ret()
    result = _run_program(config, program)
    return result.get(result_slot), result


@pytest.mark.parametrize("name", ["msjava", "MSJAVA.DLL", "sechost"])
def test_load_library_synthesizes_known_system_module_with_exports(config, name):
    lookup_name = name[:-4] if name.lower().endswith(".dll") else name
    rv, result = _call_string_api(config, "kernel32", "LoadLibraryA", name)

    assert rv != 0
    mod = result.module_by_name(lookup_name)
    assert mod is not None, f"{lookup_name} should be registered as a loaded module"
    _, base, exports = mod
    assert base == rv
    assert exports, f"{lookup_name} decoy must expose an export table"
    assert all(exports)


def test_load_library_decoy_resolves_proc_address(config):
    program = _Program()
    program.string("lib", "msjava")
    program.string("proc", "jio_snprintf")
    hmod = program.call("kernel32", "LoadLibraryA", "lib")
    proc = program.call("kernel32", "GetProcAddress", SlotValue(hmod), "proc")
    program.ret()

    result = _run_program(config, program)

    assert result.get(hmod) != 0
    # GetProcAddress returns a sentinel for unmodelled non-EXE modules; the
    # point is that it is non-NULL once the module exists.
    assert result.get(proc) != 0


def test_get_module_handle_miss_records_requested_name(config, caplog):
    with caplog.at_level(logging.INFO, logger="speakeasy.winenv.api.usermode.kernel32"):
        rv, _ = _call_string_api(config, "kernel32", "GetModuleHandleA", "MSJAVA.DLL")

    assert rv == 0
    messages = [record.getMessage() for record in caplog.records]
    assert any("MSJAVA.DLL" in message or "msjava" in message for message in messages), messages


def test_get_module_handle_returns_loaded_decoy_base(config):
    program = _Program()
    program.string("lib", "msjava")
    program.string("lookup", "MSJAVA.DLL")
    hmod = program.call("kernel32", "LoadLibraryA", "lib")
    found = program.call("kernel32", "GetModuleHandleA", "lookup")
    program.ret()

    result = _run_program(config, program)

    assert result.get(hmod) != 0
    assert result.get(found) == result.get(hmod)


def test_get_module_handle_finds_all_loaded_modules(config):
    # kernelbase is synthesized by the engine during bootstrap and is not an
    # API-handler module; GetModuleHandle must still return its base.
    rv, _ = _call_string_api(config, "kernel32", "GetModuleHandleA", "kernelbase.dll")

    assert rv != 0


def test_unknown_dll_still_returns_null(config, caplog):
    name = "fx014_definitely_not_a_system_dll"
    with caplog.at_level(logging.INFO, logger="speakeasy.winenv.api.usermode.kernel32"):
        load_rv, load_result = _call_string_api(config, "kernel32", "LoadLibraryA", name)
        handle_rv, handle_result = _call_string_api(config, "kernel32", "GetModuleHandleA", name)

    assert load_rv == 0
    assert load_result.module_by_name(name) is None
    assert handle_rv == 0
    assert handle_result.module_by_name(name) is None
    messages = [record.getMessage() for record in caplog.records]
    assert any(name in message for message in messages), messages


def test_loaded_msjava_decoy_does_not_mask_com_failure(config):
    """FX-005 semantics stay separate: a decoy module must not change COM results."""
    program = _Program()
    program.string("lib", "msjava")
    program.blob("clsid", CLSID_UNKNOWN)
    program.blob("iid", IID_IUNKNOWN)
    ppv = program.slot("ppv", SENTINEL)

    loaded = program.call("kernel32", "LoadLibraryA", "lib")
    com_rv = program.call("ole32", "CoGetClassObject", "clsid", 7, 0, "iid", ppv)
    program.ret()

    result = _run_program(config, program)

    assert result.get(loaded) != 0
    assert result.get(com_rv) == REGDB_E_CLASSNOTREG
    assert result.get(ppv) == 0


def test_synthesized_module_config_is_explicit_and_bounded():
    from speakeasy.config import get_default_config
    from speakeasy.windows.system_modules import is_synthesizable_system_module

    names = get_default_config().modules.synthesized_system_modules
    assert "msjava" in names
    assert "msvcr*" in names

    assert is_synthesizable_system_module("MSJAVA.DLL", names)
    assert is_synthesizable_system_module("msvcr71.dll", names)
    assert is_synthesizable_system_module("sechost", names)
    # Unlisted names and empty input never match: unknown DLLs stay NULL.
    assert not is_synthesizable_system_module("fx014_definitely_not_a_system_dll", names)
    assert not is_synthesizable_system_module("", names)

    # The list is configuration, not a hard-coded handler table: a profile can
    # narrow it and unknown names keep their Windows semantics.
    assert not is_synthesizable_system_module("msjava", ["version"])
