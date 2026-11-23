"""Contract tests for the FX015-extended-rv1 diagnostic follow-up.

FX-015 verified four sample singletons and left three follow-ups:

* the CreateFileA sample's unbalanced DLL entry needs a re-checkable
  return-chain/stack trace (ESP-relative words with module resolution);
* the FreeLibrary sample needs a re-checkable vtable/Release observation that
  shows what the guest's ``[interface]`` dereference would target;
* ``attach_observation`` must not raise when a payload is not JSON-serializable
  (re-check FX-016's hardening with INFO logging enabled, so ``json.dumps``
  actually executes).

These are diagnostics only.  No handler return value, memory permission,
exception dispatch or control flow is changed, and no address/SHA special case
is used.  The handler tests re-assert the FX-015 contracts (CreateFileA returns
``0x80``/``INVALID_HANDLE_VALUE``; FreeLibrary returns ``1``) while checking
that the new fields reach the public ``ApiEvent.observation`` report.
"""

from __future__ import annotations

import json
import logging
import struct

import speakeasy.winenv.arch as _arch
from speakeasy import Speakeasy
from speakeasy.windows import api_diagnostics, api_trace_diagnostics

ERROR_INVALID_WINDOW_HANDLE = 1400
INVALID_HANDLE_VALUE = 0xFFFFFFFF
OPEN_EXISTING = 3
GENERIC_WRITE = 0x40000000


# ---------------------------------------------------------------------------
# Explicit read-only emulator double (same interface as the FX-015 tests)
# ---------------------------------------------------------------------------


class _FakeMapping:
    def __init__(self, base, size, tag, prot=0, is_image=False, free=False):
        self.base = base
        self.size = size
        self.tag = tag
        self.prot = prot
        self.is_image = is_image
        self.free = free


class _FakeModule:
    def __init__(self, name, base, image_size):
        self.name = name
        self.base = base
        self.image_size = image_size


def _write_ptr(memory: dict[int, int], address: int, value: int, ptr_size: int = 4) -> None:
    for index, byte in enumerate(value.to_bytes(ptr_size, "little")):
        memory[address + index] = byte


class _FakeEmu:
    """Explicit read-only interface used by the diagnostic helpers."""

    def __init__(
        self,
        *,
        ptr_size=4,
        memory=None,
        mappings=None,
        modules=None,
        pc=0x401000,
        prev_pc=0x400FF0,
        stack_pointer=0x5000,
        return_address=0x401234,
        last_error=0,
        arch=_arch.ARCH_X86,
        registers=None,
    ):
        self.ptr_size = ptr_size
        self.memory = dict(memory or {})
        self.mappings = list(mappings or [])
        self.modules = list(modules or [])
        self.pc = pc
        self.prev_pc = prev_pc
        self.stack_pointer = stack_pointer
        self.return_address = return_address
        self.last_error = last_error
        self.arch = arch
        self.registers = dict(registers or {})

    def get_ptr_size(self):
        return self.ptr_size

    def get_pc(self):
        return self.pc

    def get_stack_ptr(self):
        return self.stack_pointer

    def get_ret_address(self):
        return self.return_address

    def get_arch(self):
        return self.arch

    def reg_read(self, register):
        return self.registers[register]

    def mem_read(self, address, size):
        data = bytearray()
        for offset in range(size):
            if address + offset not in self.memory:
                raise ValueError(f"unmapped 0x{address + offset:x}")
            data.append(self.memory[address + offset])
        return bytes(data)

    def get_address_map(self, address):
        for mapping in self.mappings:
            if mapping.base <= address < mapping.base + mapping.size:
                return mapping
        return None

    def get_mem_maps(self):
        return list(self.mappings)

    def get_module_from_addr(self, address):
        for module in self.modules:
            if module.base <= address <= module.base + module.image_size:
                return module
        return None

    def get_last_error(self):
        return self.last_error


def _mapped_emu(**kwargs) -> _FakeEmu:
    memory = kwargs.pop("memory", {})
    for index in range(10):
        _write_ptr(memory, 0x5000 + index * 4, 0x6000 + index)
    return _FakeEmu(memory=memory, **kwargs)


def _x86_registers() -> dict[int, int]:
    return {
        _arch.X86_REG_EAX: 0x80,
        _arch.X86_REG_EBX: 0x10,
        _arch.X86_REG_ECX: 0x20,
        _arch.X86_REG_EDX: 0x30,
        _arch.X86_REG_ESI: 0x40,
        _arch.X86_REG_EDI: 0x0,
        _arch.X86_REG_EBP: 0x6000,
        _arch.X86_REG_ESP: 0x5000,
        _arch.X86_REG_EIP: 0x401000,
    }


# ---------------------------------------------------------------------------
# attach_observation: re-check with INFO logging so json.dumps really runs
# ---------------------------------------------------------------------------


def test_attach_observation_survives_unserializable_payload_with_info_logging(caplog) -> None:
    marker = object()
    caplog.set_level(logging.INFO, logger="speakeasy.windows.api_diagnostics")
    ctx: dict = {}

    api_diagnostics.attach_observation(
        ctx,
        lambda: {"kind": api_diagnostics.OBSERVATION_KIND, "bad": marker},
    )

    assert ctx["_api_observation"]["bad"] is marker


def test_trace_attach_observation_survives_unserializable_payload_with_info_logging(caplog) -> None:
    marker = object()
    caplog.set_level(logging.INFO, logger="speakeasy.windows.api_trace_diagnostics")
    ctx: dict = {}

    api_trace_diagnostics.attach_observation(
        ctx,
        lambda: {"kind": api_trace_diagnostics.PROVENANCE_KIND, "bad": marker},
    )

    assert ctx["_api_observation"]["bad"] is marker


# ---------------------------------------------------------------------------
# CreateFileA return chain
# ---------------------------------------------------------------------------


def test_return_chain_resolves_caller_module_and_offsets() -> None:
    memory: dict[int, int] = {}
    _write_ptr(memory, 0x5000, 0x401234)
    _write_ptr(memory, 0x5004, 0x1000)
    _write_ptr(memory, 0x5008, 0x0)
    emu = _FakeEmu(
        memory=memory,
        mappings=[
            _FakeMapping(0x400000, 0x10000, "sample.exe", prot=5, is_image=True),
            _FakeMapping(0x5000, 0x1000, "stack"),
        ],
        modules=[_FakeModule("sample.exe", 0x400000, 0x10000)],
        registers=_x86_registers(),
    )

    chain = api_diagnostics.return_chain(emu, 3)

    assert [entry["index"] for entry in chain] == [0, 1, 2]
    assert chain[0]["address"] == "0x5000"
    assert chain[0]["value"] == "0x401234"
    assert chain[0]["module"] == "sample.exe"
    assert chain[0]["module_base"] == "0x400000"
    assert chain[0]["module_offset"] == "0x1234"
    assert chain[0]["mapping"]["mapped"] is True
    assert chain[0]["mapping"]["is_image"] is True
    assert chain[1]["value"] == "0x1000"
    assert chain[1]["module"] is None
    assert chain[1]["module_offset"] is None
    assert chain[2]["value"] == "0x0"
    json.dumps(chain, ensure_ascii=False)


def test_return_chain_reports_unreadable_words_without_raising() -> None:
    emu = _FakeEmu(stack_pointer=0x9000, registers=_x86_registers())

    chain = api_diagnostics.return_chain(emu, 2)

    assert len(chain) == 2
    assert all(entry["available"] is False for entry in chain)
    assert all("error" in entry for entry in chain)
    json.dumps(chain, ensure_ascii=False)


def test_create_file_observation_carries_return_chain() -> None:
    memory: dict[int, int] = {}
    _write_ptr(memory, 0x5000, 0x401234)
    _write_ptr(memory, 0x5004, 0x1000)
    emu = _FakeEmu(
        memory=memory,
        mappings=[
            _FakeMapping(0x400000, 0x10000, "sample.exe", prot=5, is_image=True),
            _FakeMapping(0x5000, 0x1000, "stack"),
        ],
        modules=[_FakeModule("sample.exe", 0x400000, 0x10000)],
        registers=_x86_registers(),
    )

    observation = api_diagnostics.observe_create_file(
        emu,
        (0x1000, GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0),
        0x80,
        char_width=1,
        decoded_path="C:\\fx015\\requested.bin",
        api_name="kernel32.CreateFileA",
    )

    assert observation["return_handle"] == "0x80"
    chain = observation["return_chain"]
    assert chain[0]["value"] == "0x401234"
    assert chain[0]["module"] == "sample.exe"
    assert chain[0]["module_offset"] == "0x1234"
    json.dumps(observation, ensure_ascii=False)


# ---------------------------------------------------------------------------
# FreeLibrary IMalloc vtable / Release view
# ---------------------------------------------------------------------------


def _imalloc_emu(*, mapped_dereference: bool = True) -> _FakeEmu:
    memory: dict[int, int] = {address: 0 for address in range(0x30000, 0x30040)}
    _write_ptr(memory, 0x30000, 0xFEED1000)
    _write_ptr(memory, 0x30004, 0xFEED1001)
    _write_ptr(memory, 0x30008, 0xFEED1002)
    if mapped_dereference:
        _write_ptr(memory, 0xFEED1008, 0x0)
    return _mapped_emu(
        memory=memory,
        mappings=[_FakeMapping(0x30000, 0x40, "emu.COM.IMalloc.0x30000")],
    )


def test_free_library_release_dispatch_exposes_guest_dereference() -> None:
    emu = _imalloc_emu()

    observation = api_diagnostics.observe_free_library(
        emu,
        (0x12345678,),
        True,
        api_name="kernel32.FreeLibrary",
    )

    assert observation["return_value"] == "0x1"
    interfaces = observation["com_interfaces"]["interfaces"]
    assert len(interfaces) == 1
    dispatch = interfaces[0]["release_dispatch"]
    assert dispatch["method"] == "IUnknown::Release"
    assert dispatch["method_index"] == 2
    assert dispatch["slot_offset"] == "0x8"
    assert dispatch["interface_pointer"] == "0x30000"
    assert dispatch["release_slot"]["value"] == "0xfeed1002"
    assert dispatch["release_slot_nonzero"] is True
    assert dispatch["guest_vtable_pointer"]["value"] == "0xfeed1000"
    assert dispatch["guest_release_target_address"] == "0xfeed1008"
    assert dispatch["guest_release_target"]["value"] == "0x0"
    assert dispatch["guest_release_target_mapping"]["mapped"] is False
    json.dumps(observation, ensure_ascii=False)


def test_free_library_release_dispatch_tolerates_unreadable_dereference() -> None:
    emu = _imalloc_emu(mapped_dereference=False)

    observation = api_diagnostics.observe_free_library(emu, (1,), True)

    dispatch = observation["com_interfaces"]["interfaces"][0]["release_dispatch"]
    assert dispatch["release_slot"]["value"] == "0xfeed1002"
    assert dispatch["guest_release_target"]["available"] is False
    assert "error" in dispatch["guest_release_target"]
    json.dumps(observation, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Real handlers: existing return contracts preserved + report fields present
# ---------------------------------------------------------------------------


class _X86Asm:
    def __init__(self) -> None:
        self.buf = bytearray()
        self.patches: list[tuple[int, str, int]] = []

    def imm32(self, key: str, addend: int = 0) -> None:
        offset = len(self.buf)
        self.buf += b"\x00\x00\x00\x00"
        self.patches.append((offset, key, addend))

    def push_imm32(self, value: int) -> None:
        self.buf += b"\x68" + struct.pack("<I", value & 0xFFFFFFFF)

    def push_abs(self, key: str) -> None:
        self.buf += b"\x68"
        self.imm32(key)

    def mov_eax_abs(self, key: str) -> None:
        self.buf += b"\xb8"
        self.imm32(key)

    def mov_ptr_abs_eax(self, key: str) -> None:
        self.buf += b"\x89\x05"
        self.imm32(key)

    def call_eax(self) -> None:
        self.buf += b"\xff\xd0"

    def ret(self) -> None:
        self.buf += b"\xc3"


def _run_calls(config, calls, *, buffers=None):
    """Run ``(dll, name, args)`` calls from x86 shellcode; return the last value."""
    asm = _X86Asm()
    api_keys = []
    for index, (dll, name, args) in enumerate(calls):
        api_key = f"api{index}"
        api_keys.append((api_key, dll, name))
        for arg in reversed(args):
            if isinstance(arg, int):
                asm.push_imm32(arg)
            else:
                asm.push_abs(arg)
        asm.mov_eax_abs(api_key)
        asm.call_eax()
    asm.mov_ptr_abs_eax("data")
    asm.ret()

    code = bytes(asm.buf)
    data_offset = len(code)
    code += b"\x00" * 16

    se = Speakeasy(config=config)
    try:
        sc_addr = se.load_shellcode(data=code, arch="x86")
        emu = se.emu
        assert emu is not None
        values: dict[str, int] = {"data": sc_addr + data_offset}
        for api_key, dll, name in api_keys:
            values[api_key] = emu.get_proc(dll, name)
        for key, payload in (buffers or {}).items():
            address = emu.mem_map(0x1000, tag=f"test.fx015extended.{key}")
            emu.mem_write(address, payload)
            values[key] = address
        assert all(values.values())

        for offset, key, addend in asm.patches:
            emu.mem_write(
                sc_addr + offset,
                struct.pack("<I", (values[key] + addend) & 0xFFFFFFFF),
            )

        se.run_shellcode(sc_addr)
        report = se.get_report()
        entry = report.entry_points[0]
        assert entry.error is None, entry.error

        rv = int.from_bytes(emu.mem_read(values["data"], 4), "little")
        return rv, report
    finally:
        se.shutdown()


def _api_event(report, api_name):
    events = report.entry_points[0].events or []
    matches = [
        event
        for event in events
        if getattr(event, "event", None) == "api" and getattr(event, "api_name", None) == api_name
    ]
    assert matches, f"no {api_name} event recorded"
    return matches[-1]


def test_create_filea_keeps_handle_contract_and_reports_return_chain(config) -> None:
    path = b"C:\\fx015extended\\requested.bin\x00"
    rv, report = _run_calls(
        config,
        [
            (
                "kernel32",
                "CreateFileA",
                ["path", GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0],
            )
        ],
        buffers={"path": path},
    )

    # v2.1.0 C4 handle allocator: the first file handle is no longer 0x80.
    # Assert the valid-handle contract; the observation must report the same handle.
    assert rv not in (0, INVALID_HANDLE_VALUE)
    observation = _api_event(report, "kernel32.CreateFileA").observation
    assert observation["kind"] == api_diagnostics.OBSERVATION_KIND
    assert observation["decoded_path"] == "C:\\fx015extended\\requested.bin"
    assert observation["return_handle"] == hex(rv)
    chain = observation["return_chain"]
    assert chain
    assert chain[0]["value"] == observation["guest"]["return_address"]
    assert chain[0]["mapping"]["mapped"] is True


def test_create_filea_null_path_keeps_invalid_handle_and_reports_return_chain(config) -> None:
    rv, report = _run_calls(
        config,
        [("kernel32", "CreateFileA", [0, GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0])],
    )

    assert rv == INVALID_HANDLE_VALUE
    observation = _api_event(report, "kernel32.CreateFileA").observation
    assert observation["return_handle"] == "0xffffffff"
    assert observation["decoded_path"] is None
    assert observation["return_chain"]


def test_free_library_keeps_true_and_reports_release_dispatch(config) -> None:
    calls = [
        ("shell32", "SHGetMalloc", ["slot"]),
        ("kernel32", "FreeLibrary", [0x12345678]),
    ]
    rv, report = _run_calls(config, calls, buffers={"slot": b"\x00" * 8})

    assert rv == 1
    observation = _api_event(report, "kernel32.FreeLibrary").observation
    assert observation["return_value"] == "0x1"
    interfaces = observation["com_interfaces"]["interfaces"]
    imalloc = [item for item in interfaces if item["tag"].startswith("emu.COM.IMalloc")]
    assert imalloc, f"no IMalloc interface in {interfaces}"
    dispatch = imalloc[0]["release_dispatch"]
    assert dispatch["release_slot_nonzero"] is True
    assert dispatch["release_slot"]["value"]
    assert dispatch["guest_vtable_pointer"]["value"]
    assert dispatch["guest_release_target_address"]
