"""Contract tests for the FX-016 API-trace diagnostics.

FX-016 is a diagnostic work item for no-PC/nonfatal and low-confidence
scatters.  These tests pin the additive evidence contract:

* every API event carries JSON-safe provenance (args/ret, API-return
  registers, module, call-site/return address, bounded stack window);
* ``SetLastError`` records guest control-flow provenance without changing its
  ``None`` return or LastError write;
* ``WaitForSingleObject`` records handle/stack provenance without changing its
  wait-code policy;
* fault reports carry a fakeout-page marker and last-API caller/return context;
* failure paths still preserve the original error type/PC/address/access type.

No batch sample is executed.  No environment variables, monkey patches,
address/SHA special cases or handler semantic changes are used.
"""

from __future__ import annotations

import json
import struct

import speakeasy.winenv.arch as _arch
from speakeasy import Speakeasy
from speakeasy.windows import api_diagnostics, api_trace_diagnostics

GET_TICK_COUNT = 0
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102


# ---------------------------------------------------------------------------
# Explicit emulator double for the pure observation helpers
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
    def __init__(self, name, base, image_size, path=None):
        self.name = name
        self.base = base
        self.image_size = image_size
        self.path = path


class _FakeObject:
    def __init__(self, name, object_id=7, address=0x9000, type_name="Event"):
        self.name = name
        self.id = object_id
        self.address = address
        self._type_name = type_name

    def get_class_name(self):
        return self._type_name


def _write_ptr(memory: dict[int, int], address: int, value: int, ptr_size: int = 4) -> None:
    for index, byte in enumerate(value.to_bytes(ptr_size, "little")):
        memory[address + index] = byte


class _FakeEmu:
    """Explicit read-only seam used by the diagnostic helpers."""

    def __init__(
        self,
        *,
        ptr_size=4,
        memory=None,
        mappings=None,
        pc=0x401000,
        prev_pc=0x400FF0,
        stack_pointer=0x5000,
        return_address=0x401234,
        last_error=0,
        arch=_arch.ARCH_X86,
        registers=None,
        modules=None,
        objects=None,
    ):
        self.ptr_size = ptr_size
        self.memory = dict(memory or {})
        self.mappings = list(mappings or [])
        self.pc = pc
        self.prev_pc = prev_pc
        self.stack_pointer = stack_pointer
        self.return_address = return_address
        self.last_error = last_error
        self.arch = arch
        self.registers = dict(registers or {})
        self.modules = list(modules or [])
        self.objects = dict(objects or {})

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

    def get_last_error(self):
        return self.last_error

    def get_module_from_addr(self, address):
        for module in self.modules:
            if module.base <= address < module.base + module.image_size:
                return module
        return None

    def get_object_from_handle(self, handle):
        return self.objects.get(handle)


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
        _arch.X86_REG_EDI: 0x50,
        _arch.X86_REG_EBP: 0x6000,
        _arch.X86_REG_ESP: 0x5000,
        _arch.X86_REG_EIP: 0x401000,
    }


# ---------------------------------------------------------------------------
# Pure observation helpers
# ---------------------------------------------------------------------------


def test_api_provenance_contract_is_json_safe() -> None:
    image = _FakeModule("sample.exe", 0x400000, 0x10000, path="C:\\sample.exe")
    emu = _mapped_emu(
        registers=_x86_registers(),
        modules=[image],
        mappings=[
            _FakeMapping(0x400000, 0x10000, "sample.exe", prot=5, is_image=True),
            _FakeMapping(0x700000, 0x1000, "api.heap.0x700000", prot=3),
        ],
    )

    provenance = api_trace_diagnostics.api_provenance(
        emu,
        api_name="user32.FindWindowA",
        argv=(0x400100, 0x700000),
        ret=0,
        call_pc=0x400800,
        display=["lpClassName: 0x400100", "lpWindowName: 0x700000"],
    )

    assert provenance["kind"] == api_trace_diagnostics.PROVENANCE_KIND
    assert provenance["schema_version"] == api_trace_diagnostics.SCHEMA_VERSION
    assert provenance["api"] == "user32.FindWindowA"
    assert provenance["call_pc"] == "0x400800"
    assert provenance["handler_pc"] == "0x401000"
    assert provenance["previous_pc"] == "0x400ff0"
    assert provenance["return_address"] == "0x401234"
    assert provenance["caller"]["module"] == "sample.exe"
    assert provenance["caller"]["module_offset"] == "0x1234"
    assert provenance["arguments"][0]["value"] == "0x400100"
    assert provenance["arguments"][0]["display"] == "lpClassName: 0x400100"
    assert provenance["arguments"][0]["pointer"]["mapped"] is True
    assert provenance["arguments"][1]["pointer"]["mapped"] is True
    assert provenance["arguments"][1]["pointer"]["mapping"]["tag"] == "api.heap.0x700000"
    assert provenance["return_value"] == "0x0"
    assert provenance["registers"]["eax"] == "0x80"
    assert len(provenance["stack_words"]) == api_trace_diagnostics.MAX_STACK_WORDS
    assert provenance["stack_words"][0]["value"] == "0x6000"
    assert provenance["last_error"] == "0x0"
    assert provenance["arguments_truncated"] is False
    json.dumps(provenance, ensure_ascii=False)


def test_api_provenance_bounds_arguments_and_reports_unreadable_memory() -> None:
    emu = _FakeEmu(memory={}, registers={})  # nothing readable

    provenance = api_trace_diagnostics.api_provenance(
        emu,
        api_name="oleaut32.SysAllocStringLen",
        argv=tuple(range(40)),
        ret=0x5BE21C89,
        call_pc=None,
    )

    assert len(provenance["arguments"]) == api_trace_diagnostics.MAX_ARGUMENTS
    assert provenance["arguments_truncated"] is True
    assert provenance["registers"]["eax"] is None
    assert all(word["available"] is False for word in provenance["stack_words"])
    assert provenance["return_pointer"]["mapped"] is False
    assert provenance["return_pointer"]["value"] == "0x5be21c89"
    json.dumps(provenance, ensure_ascii=False)


def test_api_provenance_sanitizes_non_json_text() -> None:
    emu = _FakeEmu()
    provenance = api_trace_diagnostics.api_provenance(
        emu,
        api_name="kernel32.GetStringTypeW",
        argv=["\ud800bad"],
        ret=None,
        call_pc=0x401000,
    )

    # Lone surrogates from guest string decoding must not break report JSON.
    json.dumps(provenance, ensure_ascii=False)
    assert "\ud800" not in provenance["arguments"][0]["value"]


def test_pointer_and_module_provenance_report_unknowns_explicitly() -> None:
    image = _FakeModule("guest.exe", 0x401000, 0x1000)
    emu = _FakeEmu(
        modules=[image],
        mappings=[_FakeMapping(0x401000, 0x1000, "guest.exe", is_image=True)],
    )

    assert api_trace_diagnostics.pointer_provenance(emu, None)["value"] is None
    assert api_trace_diagnostics.pointer_provenance(emu, "text")["mapped"] is False
    assert api_trace_diagnostics.pointer_provenance(emu, 0)["mapped"] is False

    mapped = api_trace_diagnostics.pointer_provenance(emu, 0x401010)
    assert mapped["mapped"] is True
    assert mapped["module"] == "guest.exe"
    assert mapped["module_offset"] == "0x10"

    unmapped = api_trace_diagnostics.pointer_provenance(emu, 0xFEED0000)
    assert unmapped["mapped"] is False
    assert unmapped["module"] is None


def test_set_last_error_observation_contract() -> None:
    emu = _mapped_emu(registers=_x86_registers(), last_error=0x2)

    observation = api_trace_diagnostics.observe_set_last_error(emu, [0x5A])

    assert observation["kind"] == api_trace_diagnostics.PROVENANCE_KIND
    assert observation["diagnostic"] == "set_last_error"
    assert observation["api"] == "kernel32.SetLastError"
    assert observation["set_value"] == "0x5a"
    assert observation["previous_last_error"] == "0x2"
    assert observation["return_address"] == "0x401234"
    assert observation["registers"]["esi"] == "0x40"
    assert observation["stack_words"][0]["value"] == "0x6000"
    json.dumps(observation, ensure_ascii=False)


def test_wait_for_single_object_observation_contract() -> None:
    event = _FakeObject("test-event", object_id=9, address=0x9000, type_name="Event")
    emu = _mapped_emu(registers=_x86_registers(), objects={0x220: event})

    timeout = api_trace_diagnostics.observe_wait_for_single_object(
        emu,
        [0x220, 1],
        WAIT_TIMEOUT,
    )

    assert timeout["diagnostic"] == "wait_for_single_object"
    assert timeout["handle"] == "0x220"
    assert timeout["timeout_ms"] == "0x1"
    assert timeout["return_value"] == "0x102"
    assert timeout["wait_result"] == "WAIT_TIMEOUT"
    assert timeout["handle_provenance"]["found"] is True
    assert timeout["handle_provenance"]["object_type"] == "Event"
    assert timeout["handle_provenance"]["object_name"] == "test-event"
    assert timeout["registers"]["eax"] == "0x80"
    json.dumps(timeout, ensure_ascii=False)

    signalled = api_trace_diagnostics.observe_wait_for_single_object(
        emu,
        [0x220, 0],
        WAIT_OBJECT_0,
    )
    assert signalled["wait_result"] == "WAIT_OBJECT_0"

    missing = api_trace_diagnostics.observe_wait_for_single_object(emu, [0x999, 0], 0)
    assert missing["handle_provenance"]["found"] is False
    assert missing["handle_provenance"]["handle"] == "0x999"


def test_error_diagnostics_marks_fakeout_and_last_api() -> None:
    emu = _mapped_emu(registers=_x86_registers())
    last_api = {
        "api": "kernel32.SetLastError",
        "call_pc": "0x402631",
        "return_address": "0x402636",
    }

    diagnostics = api_trace_diagnostics.error_diagnostics(
        emu,
        description="invalid_fetch",
        address=0x11E,
        access_type="fetch",
        pc=0x11E,
        pc_module=None,
        last_api=last_api,
        api_tail=[last_api],
    )

    assert diagnostics["kind"] == api_trace_diagnostics.PROVENANCE_KIND
    assert diagnostics["fakeout"]["base"] == "0x0"
    assert diagnostics["fakeout"]["contains_fault"] is True
    assert diagnostics["fakeout"]["temporary"] is True
    assert diagnostics["last_api"] == last_api
    assert diagnostics["api_tail"] == [last_api]
    assert diagnostics["registers"]["eax"] == "0x80"
    json.dumps(diagnostics, ensure_ascii=False)

    non_fault = api_trace_diagnostics.error_diagnostics(
        emu,
        description="max_api_count",
        address=0,
        access_type=None,
        pc=0x401000,
        pc_module="sample.exe+0x0",
        last_api=None,
        api_tail=[],
    )
    assert "fakeout" not in non_fault
    assert non_fault["last_api"] is None


def test_attach_observation_never_raises_for_unserializable_values() -> None:
    ctx: dict = {}
    marker = object()
    api_trace_diagnostics.attach_observation(
        ctx,
        lambda: {"kind": api_trace_diagnostics.PROVENANCE_KIND, "bad": marker},
    )
    # The observation is still attached for the report; only the log line is
    # skipped when the payload is not JSON-serializable.
    assert ctx["_api_observation"]["bad"] is marker

    api_trace_diagnostics.attach_observation(ctx, lambda: (_ for _ in ()).throw(RuntimeError("x")))
    assert "_api_observation" in ctx


def test_fx015_attach_observation_survives_unserializable_values() -> None:
    ctx: dict = {}
    api_diagnostics.attach_observation(
        ctx,
        lambda: {"kind": api_diagnostics.OBSERVATION_KIND, "bad": object()},
    )
    assert ctx["_api_observation"]["kind"] == api_diagnostics.OBSERVATION_KIND


# ---------------------------------------------------------------------------
# Real handlers: behaviour is unchanged and provenance is reported
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

    def mov_eax_imm32(self, value: int) -> None:
        self.buf += b"\xb8" + struct.pack("<I", value & 0xFFFFFFFF)

    def mov_ptr_abs_eax(self, key: str) -> None:
        self.buf += b"\x89\x05"
        self.imm32(key)

    def call_eax(self) -> None:
        self.buf += b"\xff\xd0"

    def read_eax_ptr(self) -> None:
        self.buf += b"\x8b\x00"

    def ret(self) -> None:
        self.buf += b"\xc3"


def _run_asm(config, asm: _X86Asm, *, api_calls, buffers=None, finalize=True):
    """Assemble and run ``asm`` with API/buffer address patches resolved."""
    if finalize:
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
        for key, dll, name in api_calls:
            values[key] = emu.get_proc(dll, name)
        for key, payload in (buffers or {}).items():
            address = emu.mem_map(0x1000, tag=f"test.fx016.{key}")
            emu.mem_write(address, payload)
            values[key] = address
        for offset, key, addend in asm.patches:
            emu.mem_write(
                sc_addr + offset,
                struct.pack("<I", (values[key] + addend) & 0xFFFFFFFF),
            )
        se.run_shellcode(sc_addr)
        report = se.get_report()
        entry = report.entry_points[0]
        stored = int.from_bytes(emu.mem_read(values["data"], 4), "little")
        return stored, report, entry, emu
    finally:
        se.shutdown()


def _api_events(report):
    return [
        event
        for event in (report.entry_points[0].events or [])
        if getattr(event, "event", None) == "api"
    ]


def _api_event(report, api_name):
    matches = [event for event in _api_events(report) if event.api_name == api_name]
    assert matches, f"no {api_name} event recorded"
    return matches[-1]


def test_set_last_error_keeps_none_return_and_records_provenance(config) -> None:
    asm = _X86Asm()
    api_calls = [("api0", "kernel32", "SetLastError")]
    asm.push_imm32(0x5A)
    asm.mov_eax_abs("api0")
    asm.call_eax()

    stored, report, entry, emu = _run_asm(config, asm, api_calls=api_calls)

    assert entry.error is None, entry.error
    # SetLastError returns None: the handler must not write EAX with 0x5a.
    assert stored != 0x5A
    assert emu.get_last_error() == 0x5A

    event = _api_event(report, "kernel32.SetLastError")
    assert event.ret_val is None
    observation = event.observation
    assert observation["kind"] == api_trace_diagnostics.PROVENANCE_KIND
    assert observation["diagnostic"] == "set_last_error"
    assert observation["set_value"] == "0x5a"
    assert observation["return_address"]
    assert observation["registers"]
    assert event.provenance["api"] == "kernel32.SetLastError"
    assert event.provenance["registers"]
    json.dumps(event.provenance, ensure_ascii=False)


def test_wait_for_single_object_keeps_wait_codes_and_records_provenance(config) -> None:
    for timeout_ms, expected in ((0, WAIT_OBJECT_0), (1, WAIT_TIMEOUT)):
        asm = _X86Asm()
        api_calls = [("api0", "kernel32", "WaitForSingleObject")]
        asm.push_imm32(timeout_ms)
        asm.push_imm32(0x1234)
        asm.mov_eax_abs("api0")
        asm.call_eax()

        stored, report, entry, _ = _run_asm(config, asm, api_calls=api_calls)

        assert entry.error is None, entry.error
        assert stored == expected
        event = _api_event(report, "kernel32.WaitForSingleObject")
        assert event.ret_val == hex(expected)
        observation = event.observation
        assert observation["diagnostic"] == "wait_for_single_object"
        assert observation["handle"] == "0x1234"
        assert observation["timeout_ms"] == hex(timeout_ms)
        assert observation["return_value"] == hex(expected)
        assert observation["handle_provenance"]["found"] is False
        assert event.provenance["arguments"][0]["value"] == "0x1234"


def test_every_api_event_has_json_safe_provenance(config) -> None:
    asm = _X86Asm()
    calls = [
        ("api0", "kernel32", "GetTickCount"),
        ("api1", "kernel32", "WaitForSingleObject"),
    ]
    for key in ("api1",):
        asm.push_imm32(0)
        asm.push_imm32(0x1234)
        asm.mov_eax_abs(key)
        asm.call_eax()
    asm.mov_eax_abs("api0")
    asm.call_eax()

    _, report, entry, _ = _run_asm(config, asm, api_calls=calls)

    assert entry.error is None, entry.error
    events = _api_events(report)
    assert {event.api_name for event in events} >= {
        "kernel32.GetTickCount",
        "kernel32.WaitForSingleObject",
    }
    for event in events:
        assert event.provenance is not None
        json.dumps(event.provenance, ensure_ascii=False)
    report.model_dump_json()  # pydantic serialization must accept the new field


# ---------------------------------------------------------------------------
# Error reports: semantics preserved, fakeout/last-API diagnostics added
# ---------------------------------------------------------------------------


def _run_fault(config, asm: _X86Asm, api_calls):
    _, report, entry, _ = _run_asm(config, asm, api_calls=api_calls, finalize=False)
    assert entry.error is not None
    return entry.error


def test_invalid_read_keeps_semantics_and_adds_fakeout_diagnostics(config) -> None:
    asm = _X86Asm()
    # call GetTickCount, then mov eax, 0xdeadbeef; mov eax, [eax]
    asm.mov_eax_abs("api0")
    asm.call_eax()
    asm.mov_eax_imm32(0xDEADBEEF)
    asm.read_eax_ptr()

    error = _run_fault(config, asm, [("api0", "kernel32", "GetTickCount")])

    assert error.type == "invalid_read"
    assert error.address == 0xDEADBEEF
    assert error.access_type == "read"
    assert error.diagnostics is not None
    assert error.diagnostics["fakeout"]["base"] == "0xdeadb000"
    assert error.diagnostics["fakeout"]["contains_fault"] is True
    assert error.diagnostics["last_api"]["api"] == "kernel32.GetTickCount"
    assert error.diagnostics["last_api"]["return_address"]
    assert "fakeout_page=0xdeadb000" in error.context_summary
    assert "last_api=kernel32.GetTickCount" in error.context_summary


def test_invalid_write_keeps_semantics_and_adds_fakeout_diagnostics(config) -> None:
    asm = _X86Asm()
    asm.mov_eax_imm32(0xDEADBEEF)
    asm.buf += b"\x89\x18"  # mov [eax], ebx

    error = _run_fault(config, asm, [])

    assert error.type == "invalid_write"
    assert error.address == 0xDEADBEEF
    assert error.access_type == "write"
    assert error.diagnostics["fakeout"]["base"] == "0xdeadb000"
    assert "fakeout_page=0xdeadb000" in error.context_summary


def test_invalid_fetch_keeps_semantics_and_adds_fakeout_diagnostics(config) -> None:
    asm = _X86Asm()
    asm.mov_eax_imm32(0xDEADBEEF)
    asm.buf += b"\xff\xe0"  # jmp eax

    error = _run_fault(config, asm, [])

    assert error.type == "invalid_fetch"
    assert error.pc == 0xDEADBEEF
    # The engine retries the fakeout page once before recording the terminal
    # fetch address; the fault class/PC semantics are unchanged by diagnostics.
    assert error.address in {0xDEADBEEF, 0xDEADC000}
    assert error.access_type == "fetch"
    fakeout_base = hex(error.address & ~0xFFF)
    assert error.diagnostics["fakeout"]["base"] == fakeout_base
    assert error.diagnostics["fakeout"]["contains_fault"] is True
    assert f"fakeout_page={fakeout_base}" in error.context_summary
