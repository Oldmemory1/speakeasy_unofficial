"""Contract tests for the FX-015 scatter diagnostics.

FX-015 is a diagnostic work item: the new ``speakeasy.windows.api_diagnostics``
helpers must add observable evidence for four scattered failures without
changing any handler's return value, memory permissions, exception dispatch or
control flow.  These tests cover:

* the observation schema for ``CreateFileA``, ``FreeLibrary`` (IMalloc vtable),
  ``GetStockObject`` (HGDIOBJ pseudo-handle) and ``IsZoomed``/``HeapAlloc``;
* bounded, exception-safe guest reads (unreadable memory is reported, not
  raised);
* the existing handler contracts driven through x86 shellcode: the return
  values are the same as before and the observation is recorded in the public
  ``ApiEvent.observation`` report field.

No batch sample is executed.  No environment variables, monkey patches,
address/SHA special cases or handler semantic changes are used.
"""

from __future__ import annotations

import struct

import speakeasy.winenv.arch as _arch
from speakeasy import Speakeasy
from speakeasy.windows import api_diagnostics
from speakeasy.winenv.api.usermode.gdi32 import GDI32

ERROR_INVALID_WINDOW_HANDLE = 1400
INVALID_HANDLE_VALUE = 0xFFFFFFFF
OPEN_EXISTING = 3
GENERIC_WRITE = 0x40000000


# ---------------------------------------------------------------------------
# Lightweight explicit emulator double for the pure observation helpers
# ---------------------------------------------------------------------------


class _FakeMapping:
    def __init__(self, base, size, tag, prot=0, is_image=False, free=False):
        self.base = base
        self.size = size
        self.tag = tag
        self.prot = prot
        self.is_image = is_image
        self.free = free


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

    def get_last_error(self):
        return self.last_error


def _mapped_emu(**kwargs) -> _FakeEmu:
    memory = kwargs.pop("memory", {})
    for index in range(10):
        _write_ptr(memory, 0x5000 + index * 4, 0x6000 + index)
    return _FakeEmu(memory=memory, **kwargs)


# ---------------------------------------------------------------------------
# Observation schema and safety
# ---------------------------------------------------------------------------


def test_create_file_observation_records_arguments_and_guest_context() -> None:
    emu = _mapped_emu(
        registers={
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
    )
    argv = (0x1000, GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0)

    observation = api_diagnostics.observe_create_file(
        emu,
        argv,
        0x80,
        char_width=1,
        decoded_path="C:\\Windows\\system32\\svchost.exe",
        api_name="kernel32.CreateFileA",
    )

    assert observation["kind"] == api_diagnostics.OBSERVATION_KIND
    assert observation["schema_version"] == api_diagnostics.SCHEMA_VERSION
    assert observation["api"] == "kernel32.CreateFileA"
    assert observation["diagnostic"] == "create_file"
    assert observation["char_width"] == 1
    assert observation["arguments"]["lp_file_name"] == "0x1000"
    assert observation["arguments"]["desired_access"] == hex(GENERIC_WRITE)
    assert observation["arguments"]["creation_disposition"] == "0x3"
    assert observation["decoded_path"] == "C:\\Windows\\system32\\svchost.exe"
    assert observation["return_handle"] == "0x80"
    assert observation["last_error"] == "0x0"
    assert observation["guest"]["pc"] == "0x401000"
    assert observation["guest"]["return_address"] == "0x401234"
    assert observation["guest"]["registers"]["edi"] == "0x50"
    assert len(observation["stack_words"]) == 8
    assert observation["stack_words"][0]["value"] == "0x6000"
    assert observation["stack_words"][1]["value"] == "0x6001"


def test_unreadable_guest_memory_is_reported_not_raised() -> None:
    emu = _FakeEmu(memory={}, registers={})
    observation = api_diagnostics.observe_create_file(
        emu,
        (0, 0, 0, 0, 0, 0, 0),
        INVALID_HANDLE_VALUE,
        char_width=1,
        decoded_path=None,
        api_name="kernel32.CreateFileA",
    )

    assert observation["guest"]["pc"] == "0x401000"
    assert observation["guest"]["registers"]["eax"] is None
    assert len(observation["stack_words"]) == 8
    assert all(word["available"] is False for word in observation["stack_words"])
    assert observation["stack_words"][0]["error"] == "ValueError"


def test_get_stock_object_observation_matches_pseudo_handle_model() -> None:
    valid = api_diagnostics.observe_get_stock_object(
        1,
        0x7004,
        valid=True,
        api_name="gdi32.GetStockObject",
        handle_base=GDI32.STOCK_OBJECT_HANDLE_BASE,
    )

    assert valid["kind"] == api_diagnostics.OBSERVATION_KIND
    assert valid["diagnostic"] == "get_stock_object"
    assert valid["stock_object"] == "0x1"
    assert valid["valid_selector"] is True
    assert valid["returned_handle"] == "0x7004"
    assert valid["matches_pseudo_handle_formula"] is True
    assert valid["wine_semantics"]["type"] == "HGDIOBJ_pseudo_handle"
    assert valid["wine_semantics"]["invalid_value"] == "0x0"
    assert valid["wine_semantics"]["opaque"] is True

    invalid = api_diagnostics.observe_get_stock_object(
        9,
        0,
        valid=False,
        api_name="gdi32.GetStockObject",
        handle_base=GDI32.STOCK_OBJECT_HANDLE_BASE,
    )

    assert invalid["valid_selector"] is False
    assert invalid["returned_handle"] == "0x0"
    assert invalid["matches_pseudo_handle_formula"] is False


def test_heap_alloc_observation_flags_nonnull_unmapped_return() -> None:
    emu = _mapped_emu()

    bogus = api_diagnostics.observe_heap_alloc(
        emu,
        0x1000,
        0,
        0xFFFFD5A1,
        0xFFFFD5A1,
        api_name="kernel32.HeapAlloc",
    )

    assert bogus["kind"] == api_diagnostics.OBSERVATION_KIND
    assert bogus["diagnostic"] == "heap_alloc"
    assert bogus["requested_size"] == "0xffffd5a1"
    assert bogus["requested_size_signed"] == -0x2A5F
    assert bogus["return_value"] == "0xffffd5a1"
    assert bogus["allocation_status"] == api_diagnostics._HEAP_ALLOC_STATUS_UNMAPPED
    assert bogus["returned_mapping"]["mapped"] is False

    mapping = _FakeMapping(0x30000, 0x1000, "api.heap.HeapAlloc.0x30000")
    mapped_emu = _mapped_emu(mappings=[mapping])
    mapped = api_diagnostics.observe_heap_alloc(
        mapped_emu,
        0x1000,
        0,
        0x20,
        0x30000,
        api_name="kernel32.HeapAlloc",
    )

    assert mapped["allocation_status"] == api_diagnostics._HEAP_ALLOC_STATUS_MAPPED
    assert mapped["returned_mapping"]["tag"] == "api.heap.HeapAlloc.0x30000"

    null = api_diagnostics.observe_heap_alloc(
        emu,
        0x1000,
        0,
        0x20,
        0,
        api_name="kernel32.HeapAlloc",
    )
    assert null["allocation_status"] == api_diagnostics._HEAP_ALLOC_STATUS_NULL


def test_free_library_observation_snapshots_live_com_vtable_slots() -> None:
    memory: dict[int, int] = {address: 0 for address in range(0x30000, 0x30040)}
    _write_ptr(memory, 0x30000, 0xFEED1000)
    _write_ptr(memory, 0x30004, 0xFEED1001)
    _write_ptr(memory, 0x30008, 0xFEED1002)
    emu = _mapped_emu(
        memory=memory,
        mappings=[_FakeMapping(0x30000, 0x40, "emu.COM.IMalloc.0x30000")],
    )

    observation = api_diagnostics.observe_free_library(
        emu,
        (0x12345678,),
        True,
        api_name="kernel32.FreeLibrary",
    )

    assert observation["kind"] == api_diagnostics.OBSERVATION_KIND
    assert observation["diagnostic"] == "free_library"
    assert observation["h_lib_module"] == "0x12345678"
    assert observation["return_value"] == "0x1"
    assert observation["com_interfaces"]["available"] is True
    assert observation["com_interfaces"]["count"] == 1
    interface = observation["com_interfaces"]["interfaces"][0]
    assert interface["tag"] == "emu.COM.IMalloc.0x30000"
    assert [slot["nonzero"] for slot in interface["slots"][:4]] == [True, True, True, False]
    assert interface["slots"][3]["value"] == "0x0"

    many = _mapped_emu(
        mappings=[
            _FakeMapping(0x30000 + index * 0x100, 0x40, f"emu.COM.IMalloc.0x{0x30000 + index * 0x100:x}")
            for index in range(3)
        ]
    )
    capped = api_diagnostics.observe_free_library(many, (1,), True, max_interfaces=2, max_slots=4)
    assert capped["com_interfaces"]["count"] == 3
    assert len(capped["com_interfaces"]["interfaces"]) == 2
    assert capped["com_interfaces"]["interfaces_truncated"] is True


def test_is_zoomed_observation_fields() -> None:
    emu = _mapped_emu(last_error=ERROR_INVALID_WINDOW_HANDLE)
    observation = api_diagnostics.observe_is_zoomed(
        emu,
        0x1234,
        0,
        ERROR_INVALID_WINDOW_HANDLE,
        window_known=False,
        api_name="user32.IsZoomed",
    )

    assert observation["kind"] == api_diagnostics.OBSERVATION_KIND
    assert observation["diagnostic"] == "is_zoomed"
    assert observation["h_wnd"] == "0x1234"
    assert observation["return_value"] == "0x0"
    assert observation["truthy"] is False
    assert observation["window_known"] is False
    assert observation["last_error"] == "0x578"


def test_attach_observation_never_raises() -> None:
    def _boom():
        raise RuntimeError("diagnostic failure")

    ctx: dict = {}
    api_diagnostics.attach_observation(ctx, _boom)
    assert "_api_observation" not in ctx

    api_diagnostics.attach_observation(ctx, lambda: None)
    assert "_api_observation" not in ctx

    api_diagnostics.attach_observation(None, lambda: {"kind": "x"})

    observation = {"kind": api_diagnostics.OBSERVATION_KIND, "schema_version": 1}
    api_diagnostics.attach_observation(ctx, lambda: observation)
    assert ctx["_api_observation"] is observation


# ---------------------------------------------------------------------------
# Real handlers: existing return contracts preserved + report field present
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


def _run_calls(config, calls, *, buffers=None, read_size=0):
    """Run a list of (dll, name, [args]) calls from x86 shellcode.

    ``args`` items are immediates except the ``"<buffer>"`` strings, which push
    the address of a mapped buffer.  The last call's return value is stored to
    a data slot.  Returns ``(return_value, last_call_bytes, report)``.
    """
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
            address = emu.mem_map(0x1000, tag=f"test.fx015.{key}")
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
        call_bytes = None
        if read_size and rv:
            call_bytes = emu.mem_read(rv, read_size)
        return rv, call_bytes, report
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


def test_get_stock_object_handler_keeps_pseudo_handle_and_reports(config) -> None:
    rv, _, report = _run_calls(config, [("gdi32", "GetStockObject", [1])])

    assert rv == 0x7004
    observation = _api_event(report, "gdi32.GetStockObject").observation
    assert observation["kind"] == api_diagnostics.OBSERVATION_KIND
    assert observation["diagnostic"] == "get_stock_object"
    assert observation["stock_object"] == "0x1"
    assert observation["valid_selector"] is True
    assert observation["returned_handle"] == "0x7004"
    assert observation["matches_pseudo_handle_formula"] is True
    assert observation["api"] == "gdi32.GetStockObject"


def test_get_stock_object_invalid_selector_still_returns_null(config) -> None:
    rv, _, report = _run_calls(config, [("gdi32", "GetStockObject", [9])])

    assert rv == 0
    observation = _api_event(report, "gdi32.GetStockObject").observation
    assert observation["valid_selector"] is False
    assert observation["returned_handle"] == "0x0"


def test_free_library_keeps_true_and_records_imalloc_slots(config) -> None:
    # Create a live IMalloc through the real SHGetMalloc handler, then call
    # FreeLibrary; the FreeLibrary observation must expose the vtable slots.
    calls = [
        ("shell32", "SHGetMalloc", ["slot"]),
        ("kernel32", "FreeLibrary", [0x12345678]),
    ]
    rv, _, report = _run_calls(config, calls, buffers={"slot": b"\x00" * 8})

    assert rv == 1
    observation = _api_event(report, "kernel32.FreeLibrary").observation
    assert observation["kind"] == api_diagnostics.OBSERVATION_KIND
    assert observation["diagnostic"] == "free_library"
    assert observation["h_lib_module"] == "0x12345678"
    assert observation["return_value"] == "0x1"
    interfaces = observation["com_interfaces"]["interfaces"]
    imalloc = [item for item in interfaces if item["tag"].startswith("emu.COM.IMalloc")]
    assert imalloc, f"no IMalloc interface in {interfaces}"
    slots = imalloc[0]["slots"]
    # IUnknown.QueryInterface / AddRef / Release are hooked and non-zero.
    # v2.1.0 also implements IMalloc.Alloc/Realloc/Free/GetSize/DidAlloc/
    # HeapMinimize (com_api), so the whole 9-entry vtable is filled; the slots
    # past the vtable stay zero.
    assert all(slots[index]["nonzero"] is True for index in range(9))
    assert slots[9]["value"] == "0x0"


def test_heap_alloc_keeps_mapped_chunk_contract_and_reports_size(config) -> None:
    rv, chunk, report = _run_calls(
        config,
        [("kernel32", "HeapAlloc", [0xDEADBEEF, 0, 0x20])],
        read_size=0x20,
    )

    assert rv != 0
    assert chunk == b"\x00" * 0x20
    observation = _api_event(report, "kernel32.HeapAlloc").observation
    assert observation["requested_size"] == "0x20"
    assert observation["return_value"] == hex(rv)
    assert observation["allocation_status"] == api_diagnostics._HEAP_ALLOC_STATUS_MAPPED
    assert observation["returned_mapping"]["mapped"] is True
    assert observation["heap_handle"] == "0xdeadbeef"


def test_create_filea_keeps_handle_contract_and_reports(config) -> None:
    # tests/test.json maps every emulated path to resources/files/default.bin,
    # so OPEN_EXISTING succeeds and the handler returns a valid handle.
    path = b"C:\\fx015\\requested.bin\x00"
    rv, _, report = _run_calls(
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

    # v2.1.0 C4 handle allocator: assert the valid-handle contract, not the
    # old first-handle value 0x80; the observation must report the same handle.
    assert rv not in (0, INVALID_HANDLE_VALUE)
    observation = _api_event(report, "kernel32.CreateFileA").observation
    assert observation["kind"] == api_diagnostics.OBSERVATION_KIND
    assert observation["diagnostic"] == "create_file"
    assert observation["decoded_path"] == "C:\\fx015\\requested.bin"
    assert observation["char_width"] == 1
    assert observation["return_handle"] == hex(rv)
    assert observation["last_error"] == "0x0"
    assert observation["arguments"]["creation_disposition"] == "0x3"
    assert observation["guest"]["return_address"]
    assert observation["stack_words"][1]["value"] == observation["arguments"]["lp_file_name"]


def test_create_filea_null_path_keeps_invalid_handle(config) -> None:
    rv, _, report = _run_calls(
        config,
        [("kernel32", "CreateFileA", [0, GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0])],
    )

    assert rv == INVALID_HANDLE_VALUE
    observation = _api_event(report, "kernel32.CreateFileA").observation
    assert observation["decoded_path"] is None
    assert observation["arguments"]["lp_file_name"] == "0x0"
    assert observation["return_handle"] == "0xffffffff"


def test_is_zoomed_keeps_bool_contract_and_reports_false(config) -> None:
    rv, _, report = _run_calls(config, [("user32", "IsZoomed", [0x1234])])

    assert rv == 0
    observation = _api_event(report, "user32.IsZoomed").observation
    assert observation["kind"] == api_diagnostics.OBSERVATION_KIND
    assert observation["diagnostic"] == "is_zoomed"
    assert observation["h_wnd"] == "0x1234"
    assert observation["return_value"] == "0x0"
    assert observation["truthy"] is False
    assert observation["window_known"] is False
    assert observation["last_error"] == hex(ERROR_INVALID_WINDOW_HANDLE)
