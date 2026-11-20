"""Contract tests for the FX-011 BOOL return policy and explicit BOOL handlers.

``GUI.bool_fallback``: a BOOL return type says "nonzero == true" but not *which*
question is being answered. Speakeasy used to answer every signature-only BOOL
import with TRUE, fabricating both a predicate ("the condition holds") and a
state change ("the operation succeeded"). The contract under test:

* signature-only ``predicate_bool`` imports return FALSE and leave LastError
  untouched (a false condition is not an error);
* signature-only ``status_bool`` imports return FALSE and set a real failure
  code (``ERROR_CALL_NOT_IMPLEMENTED``), because the emulator cannot perform
  the state change;
* ``AdjustTokenGroups`` validates the token handle (invalid handle -> FALSE +
  ``ERROR_INVALID_HANDLE``) and reads/writes ``TOKEN_GROUPS`` for a valid token;
* ``IsZoomed`` reports the window's actual maximize state.

No batch samples are executed here. No environment variables, no monkey
patching, no address/SHA special cases in production code.
"""

from __future__ import annotations

import struct

import pytest

import speakeasy.winenv.arch as _arch
from speakeasy import Speakeasy
from speakeasy.windows import bool_semantics, objman, token_groups
from speakeasy.winenv.api import sigdb
from speakeasy.winenv.api.usermode.advapi32 import AdvApi32
from speakeasy.winenv.defs.windows import windows as windefs

ERROR_INVALID_HANDLE = 6
ERROR_CALL_NOT_IMPLEMENTED = 120
ERROR_INVALID_WINDOW_HANDLE = 1400

SW_MAXIMIZE = 3
SW_RESTORE = 9
WS_MAXIMIZE = 0x01000000

SLOT = 4


# ---------------------------------------------------------------------------
# x86 shellcode emitter (absolute 32-bit fixups resolved after loading)
# ---------------------------------------------------------------------------


class _X86Asm:
    def __init__(self) -> None:
        self.buf = bytearray()
        self.patches: list[tuple[int, tuple, int]] = []

    def _imm32(self, key: tuple, addend: int = 0) -> None:
        offset = len(self.buf)
        self.buf += b"\x00\x00\x00\x00"
        self.patches.append((offset, key, addend))

    def push_imm32(self, value: int) -> None:
        self.buf += b"\x68" + struct.pack("<I", value & 0xFFFFFFFF)

    def push_slot(self, offset: int) -> None:
        self.buf += b"\xFF\x35"
        self._imm32(("data",), offset)

    def mov_eax_api(self, dll: str, name: str) -> None:
        self.buf += b"\xB8"
        self._imm32(("api", dll, name))

    def call_eax(self) -> None:
        self.buf += b"\xFF\xD0"

    def store_eax(self, offset: int) -> None:
        self.buf += b"\xA3"
        self._imm32(("data",), offset)

    def ret(self) -> None:
        self.buf += b"\xC3"


# ---------------------------------------------------------------------------
# AMD64 shellcode emitter (Microsoft x64: RCX/RDX/R8/R9 + stack args)
# ---------------------------------------------------------------------------


class _X64Asm:
    def __init__(self) -> None:
        self.buf = bytearray()
        self.patches: list[tuple[int, tuple, int, int]] = []

    def _imm(self, key: tuple, addend: int = 0, size: int = 8) -> None:
        offset = len(self.buf)
        self.buf += b"\x00" * size
        self.patches.append((offset, key, addend, size))

    def alloc_frame(self) -> None:
        # 0x20 shadow space + 8 stack arguments, 16-byte aligned before call.
        self.buf += b"\x48\x83\xEC\x68"

    def free_frame(self) -> None:
        self.buf += b"\x48\x83\xC4\x68"

    def zero_stack_args(self) -> None:
        self.buf += b"\x31\xC0"  # xor eax, eax
        for offset in range(0x20, 0x60, 8):
            self.buf += b"\x48\x89\x44\x24" + bytes([offset])

    def xor_rcx(self) -> None:
        self.buf += b"\x31\xC9"

    def xor_rdx(self) -> None:
        self.buf += b"\x31\xD2"

    def xor_r8(self) -> None:
        self.buf += b"\x45\x31\xC0"

    def mov_r9_imm32(self, value: int) -> None:
        self.buf += b"\x49\xC7\xC1" + struct.pack("<i", value)

    def mov_rdx_imm32(self, value: int) -> None:
        self.buf += b"\x48\xC7\xC2" + struct.pack("<i", value)

    def mov_rcx_slot(self, offset: int) -> None:
        self.buf += b"\x48\x8B\x0C\x25"
        self._imm(("data",), addend=offset, size=4)

    def mov_rax_api(self, dll: str, name: str) -> None:
        self.buf += b"\x48\xB8"
        self._imm(("api", dll, name), size=8)

    def call_rax(self) -> None:
        self.buf += b"\xFF\xD0"

    def store_rax(self, offset: int) -> None:
        self.buf += b"\x48\xA3"
        self._imm(("data",), addend=offset, size=8)

    def ret(self) -> None:
        self.buf += b"\xC3"


def _run_x86(config, asm: _X86Asm, data_size: int, read_offsets: tuple[int, ...]):
    """Load ``asm`` as x86 shellcode and return (slots, report)."""
    code = bytes(asm.buf) + b"\x00" * data_size
    data_off = len(asm.buf)
    se = Speakeasy(config=config)
    try:
        sc = se.load_shellcode(data=code, arch="x86")
        emu = se.emu
        assert emu is not None
        data_addr = sc + data_off
        values: dict[tuple, int] = {("data",): data_addr}
        for offset, key, addend in asm.patches:
            if key[0] == "api":
                _, dll, name = key
                addr = emu.get_proc(dll, name)
                assert addr, f"get_proc failed for {dll}!{name}"
                values[key] = addr
            target = values[key] + addend
            emu.mem_write(sc + offset, struct.pack("<I", target & 0xFFFFFFFF))

        se.run_shellcode(sc)
        report = se.get_report()
        entry = report.entry_points[0]
        assert entry.error is None, entry.error
        slots = {
            offset: int.from_bytes(emu.mem_read(data_addr + offset, SLOT), "little")
            for offset in read_offsets
        }
        return slots, report
    finally:
        se.shutdown()


def _run_x64(config, asm: _X64Asm, data_size: int, read_offsets: tuple[int, ...]):
    """Load ``asm`` as AMD64 shellcode and return (slots, report)."""
    code = bytes(asm.buf) + b"\x00" * data_size
    data_off = len(asm.buf)
    se = Speakeasy(config=config)
    try:
        sc = se.load_shellcode(data=code, arch="amd64")
        emu = se.emu
        assert emu is not None
        data_addr = sc + data_off
        values: dict[tuple, int] = {("data",): data_addr}
        for offset, key, addend, size in asm.patches:
            if key[0] == "api":
                _, dll, name = key
                addr = emu.get_proc(dll, name)
                assert addr, f"get_proc failed for {dll}!{name}"
                values[key] = addr
            target = values[key] + addend
            emu.mem_write(
                sc + offset,
                struct.pack("<I" if size == 4 else "<Q", target & (2 ** (size * 8) - 1)),
            )

        se.run_shellcode(sc)
        report = se.get_report()
        entry = report.entry_points[0]
        assert entry.error is None, entry.error
        slots = {
            offset: int.from_bytes(emu.mem_read(data_addr + offset, 8), "little")
            for offset in read_offsets
        }
        return slots, report
    finally:
        se.shutdown()


def _api_events(report):
    return [e for e in (report.entry_points[0].events or []) if e.event == "api"]


# ---------------------------------------------------------------------------
# Handler-level harness for AdvApi32.AdjustTokenGroups
# ---------------------------------------------------------------------------


class _Allocator:
    def __init__(self) -> None:
        self._next_id = 0x4000

    def allocate_kernel_object_id(self) -> int:
        self._next_id += 4
        return self._next_id


class _HandlerEmu:
    """Minimal emulator surface used by the advapi32 token handler."""

    def __init__(self, ptr_size: int = 4) -> None:
        self.ptr_size = ptr_size
        self.memory: dict[int, int] = {}
        self.last_error: int | None = None
        self.handles: dict[int, object] = {}
        self.handle_allocator = _Allocator()

    def get_arch(self) -> int:
        return _arch.ARCH_X86 if self.ptr_size == 4 else _arch.ARCH_AMD64

    def get_ptr_size(self) -> int:
        return self.ptr_size

    def get_object_from_handle(self, handle: int):
        return self.handles.get(handle)

    def get_address_map(self, _address: int):
        return None

    def mem_write(self, address: int, data: bytes) -> None:
        for offset, value in enumerate(data):
            self.memory[address + offset] = value

    def mem_read(self, address: int, size: int) -> bytes:
        try:
            return bytes(self.memory[address + offset] for offset in range(size))
        except KeyError as exc:
            raise RuntimeError(f"unmapped read at {address:#x}") from exc

    def set_last_error(self, value: int) -> None:
        self.last_error = value


def _advapi_handler(emu: _HandlerEmu) -> AdvApi32:
    handler = AdvApi32.__new__(AdvApi32)
    handler.emu = emu
    handler.ptr_size = emu.ptr_size
    return handler


def _token_groups_buffer(ptr_size: int, entries: list[tuple[int, int]]) -> bytes:
    header = 4 if ptr_size == 4 else 8
    entry_size = 8 if ptr_size == 4 else 16
    buf = bytearray(header + entry_size * len(entries))
    buf[0:4] = struct.pack("<I", len(entries))
    for index, (sid, attributes) in enumerate(entries):
        base = header + index * entry_size
        buf[base : base + ptr_size] = sid.to_bytes(ptr_size, "little")
        buf[base + ptr_size : base + ptr_size + 4] = struct.pack("<I", attributes)
    return bytes(buf)


# ---------------------------------------------------------------------------
# Signature-library classification
# ---------------------------------------------------------------------------


def test_bool_signatures_are_classified_status_or_predicate():
    if not sigdb.get_default_database().available:
        pytest.skip("bundled signature database not generated")

    db = sigdb.get_default_database()

    def semantics(dll: str, name: str) -> str:
        sig = db.lookup(dll, name, "x86")
        assert sig is not None, f"missing signature for {dll}!{name}"
        return sigdb.bool_return_semantics(dll, name, sig)

    # Explicitly known APIs keep their real semantic even when the generated
    # SetLastError flag is absent (status) or present (predicate).
    assert semantics("advapi32", "AdjustTokenGroups") == sigdb.BOOL_SEMANTICS_STATUS
    assert semantics("user32", "IsZoomed") == sigdb.BOOL_SEMANTICS_PREDICATE
    assert semantics("kernel32", "SetCurrentDirectoryW") == sigdb.BOOL_SEMANTICS_STATUS
    assert semantics("user32", "IsClipboardFormatAvailable") == sigdb.BOOL_SEMANTICS_PREDICATE
    assert semantics("advapi32", "IsTokenRestricted") == sigdb.BOOL_SEMANTICS_PREDICATE

    # Unlisted APIs fall back to the signature's SetLastError flag ...
    assert semantics("kernel32", "MoveFileExW") == sigdb.BOOL_SEMANTICS_STATUS
    assert semantics("kernel32", "IsThreadAFiber") == sigdb.BOOL_SEMANTICS_PREDICATE

    # ... and a BOOL API with no signature information is a predicate.
    assert sigdb.bool_return_semantics("unknown", "NoSuchApi", None) == sigdb.BOOL_SEMANTICS_PREDICATE


def test_bool_registries_are_disjoint_and_known():
    for dll in set(sigdb.PREDICATE_BOOL_APIS) & set(sigdb.STATUS_BOOL_APIS):
        overlap = sigdb.PREDICATE_BOOL_APIS[dll] & sigdb.STATUS_BOOL_APIS[dll]
        assert not overlap, f"{dll} classified twice: {sorted(overlap)}"


def test_default_bool_result_is_false_for_both_classes():
    status_sig = sigdb.FuncSig(
        name="AdjustTokenGroups",
        dll="advapi32",
        ret="b",
        params=(),
        set_last_error=True,
    )
    predicate_sig = sigdb.FuncSig(
        name="IsZoomed",
        dll="user32",
        ret="b",
        params=(),
        set_last_error=False,
    )
    assert bool_semantics.default_bool_return(status_sig) == 0
    assert bool_semantics.default_bool_return(predicate_sig) == 0
    assert bool_semantics.last_error_for_default(status_sig) == ERROR_CALL_NOT_IMPLEMENTED
    assert bool_semantics.last_error_for_default(predicate_sig) is None


# ---------------------------------------------------------------------------
# AdjustTokenGroups
# ---------------------------------------------------------------------------


def test_adjust_token_groups_invalid_handle_sets_invalid_handle_error():
    emu = _HandlerEmu()
    handler = _advapi_handler(emu)

    rv = handler.AdjustTokenGroups(emu, [0, 1, 0, 0, 0, 0])

    assert rv == 0
    assert emu.last_error == ERROR_INVALID_HANDLE


def test_adjust_token_groups_non_token_handle_is_invalid():
    emu = _HandlerEmu()
    handler = _advapi_handler(emu)
    emu.handles[0x220] = object()  # a valid kernel object, but not a Token

    rv = handler.AdjustTokenGroups(emu, [0x220, 1, 0, 0, 0, 0])

    assert rv == 0
    assert emu.last_error == ERROR_INVALID_HANDLE


@pytest.mark.parametrize("ptr_size", [4, 8])
def test_adjust_token_groups_reads_and_writes_token_groups(ptr_size):
    emu = _HandlerEmu(ptr_size)
    handler = _advapi_handler(emu)
    token = objman.Token(emu)
    emu.handles[0x220] = token

    new_state = 0x5000
    previous_state = 0x7000
    return_length = 0x8000
    groups = [(0x6000, 0x1), (0x6020, 0x2)]
    payload = _token_groups_buffer(ptr_size, groups)
    emu.mem_write(new_state, payload)

    rv = handler.AdjustTokenGroups(
        emu,
        [0x220, 0, new_state, len(payload), previous_state, return_length],
    )

    assert rv == 1
    assert emu.last_error == windefs.ERROR_SUCCESS
    assert token_groups.get_token_groups(token) == tuple(
        token_groups.TokenGroupEntry(sid=sid, attributes=attributes)
        for sid, attributes in groups
    )
    # PreviousState is the pre-call state: empty on the first adjustment.
    header = 4 if ptr_size == 4 else 8
    written = emu.mem_read(previous_state, header)
    assert struct.unpack("<I", written[:4])[0] == 0
    assert struct.unpack("<I", emu.mem_read(return_length, 4))[0] == header

    # A second call observes the applied state as the previous state.
    rv = handler.AdjustTokenGroups(
        emu,
        [0x220, 0, new_state, len(payload), previous_state + 0x100, return_length],
    )
    assert rv == 1
    entry_size = 8 if ptr_size == 4 else 16
    expected_len = header + entry_size * len(groups)
    assert struct.unpack("<I", emu.mem_read(return_length, 4))[0] == expected_len
    written = emu.mem_read(previous_state + 0x100, expected_len)
    assert struct.unpack("<I", written[:4])[0] == len(groups)
    for index, (sid, attributes) in enumerate(groups):
        base = header + index * entry_size
        assert int.from_bytes(written[base : base + ptr_size], "little") == sid
        assert struct.unpack("<I", written[base + ptr_size : base + ptr_size + 4])[0] == attributes


def test_adjust_token_groups_reset_to_default_clears_groups():
    emu = _HandlerEmu()
    handler = _advapi_handler(emu)
    token = objman.Token(emu)
    emu.handles[0x220] = token
    payload = _token_groups_buffer(4, [(0x6000, 0x1)])
    emu.mem_write(0x5000, payload)

    assert handler.AdjustTokenGroups(emu, [0x220, 0, 0x5000, len(payload), 0, 0]) == 1
    assert token_groups.get_token_groups(token)

    assert handler.AdjustTokenGroups(emu, [0x220, 1, 0, 0, 0, 0]) == 1
    assert token_groups.get_token_groups(token) == ()


def test_adjust_token_groups_rejects_missing_or_undersized_new_state():
    emu = _HandlerEmu()
    handler = _advapi_handler(emu)
    token = objman.Token(emu)
    emu.handles[0x220] = token

    assert handler.AdjustTokenGroups(emu, [0x220, 0, 0, 0, 0, 0]) == 0
    assert emu.last_error == windefs.ERROR_INVALID_PARAMETER

    payload = _token_groups_buffer(4, [(0x6000, 0x1)])
    emu.mem_write(0x5000, payload)
    assert handler.AdjustTokenGroups(emu, [0x220, 0, 0x5000, 4, 0, 0]) == 0
    assert emu.last_error == windefs.ERROR_INSUFFICIENT_BUFFER
    assert token_groups.get_token_groups(token) == ()


def test_adjust_token_groups_sample_shape_returns_false_and_last_error(config):
    """The representative sample's call shape: TokenHandle 0, ResetToDefault TRUE."""
    asm = _X86Asm()
    asm.push_imm32(0)  # ReturnLength
    asm.push_imm32(0)  # PreviousState
    asm.push_imm32(0)  # BufferLength
    asm.push_imm32(0)  # NewState
    asm.push_imm32(1)  # ResetToDefault
    asm.push_imm32(0)  # TokenHandle (invalid)
    asm.mov_eax_api("advapi32", "AdjustTokenGroups")
    asm.call_eax()
    asm.store_eax(0)

    asm.mov_eax_api("kernel32", "GetLastError")
    asm.call_eax()
    asm.store_eax(4)
    asm.ret()

    slots, report = _run_x86(config, asm, 0x10, (0, 4))
    events = _api_events(report)
    assert [e.api_name for e in events] == [
        "advapi32.AdjustTokenGroups",
        "kernel32.GetLastError",
    ]
    assert events[0].ret_val == "0x0"
    assert slots[0] == 0
    assert slots[4] == ERROR_INVALID_HANDLE


# ---------------------------------------------------------------------------
# IsZoomed
# ---------------------------------------------------------------------------


def _create_window_x86(asm: _X86Asm, slot: int, style: int = 0) -> None:
    # 12 arguments pushed right-to-left:
    # (dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight,
    #  hWndParent, hMenu, hInstance, lpParam).
    for value in reversed((0, 0, 0, style, 0, 0, 0, 0, 0, 0, 0, 0)):
        asm.push_imm32(value)
    asm.mov_eax_api("user32", "CreateWindowExW")
    asm.call_eax()
    asm.store_eax(slot)


def test_is_zoomed_tracks_show_window_state(config):
    asm = _X86Asm()
    _create_window_x86(asm, 0)  # ordinary window, not maximized

    asm.push_slot(0)
    asm.mov_eax_api("user32", "IsZoomed")
    asm.call_eax()
    asm.store_eax(4)

    asm.push_imm32(SW_MAXIMIZE)
    asm.push_slot(0)
    asm.mov_eax_api("user32", "ShowWindow")
    asm.call_eax()
    asm.store_eax(8)

    asm.push_slot(0)
    asm.mov_eax_api("user32", "IsZoomed")
    asm.call_eax()
    asm.store_eax(12)

    asm.push_imm32(SW_RESTORE)
    asm.push_slot(0)
    asm.mov_eax_api("user32", "ShowWindow")
    asm.call_eax()
    asm.store_eax(16)

    asm.push_slot(0)
    asm.mov_eax_api("user32", "IsZoomed")
    asm.call_eax()
    asm.store_eax(20)

    asm.push_imm32(0xDEAD)  # unknown HWND
    asm.mov_eax_api("user32", "IsZoomed")
    asm.call_eax()
    asm.store_eax(24)

    asm.mov_eax_api("kernel32", "GetLastError")
    asm.call_eax()
    asm.store_eax(28)
    asm.ret()

    slots, _report = _run_x86(config, asm, 0x40, (0, 4, 12, 20, 24, 28))

    assert slots[0] != 0
    assert slots[4] == 0, "a plain window must not report as zoomed"
    assert slots[12] == 1, "ShowWindow(SW_MAXIMIZE) must make IsZoomed TRUE"
    assert slots[20] == 0, "ShowWindow(SW_RESTORE) must clear the zoomed state"
    assert slots[24] == 0, "an unknown HWND is not zoomed"
    assert slots[28] == ERROR_INVALID_WINDOW_HANDLE


def test_is_zoomed_sees_ws_maximize_style(config):
    asm = _X86Asm()
    _create_window_x86(asm, 0, style=WS_MAXIMIZE)
    asm.push_slot(0)
    asm.mov_eax_api("user32", "IsZoomed")
    asm.call_eax()
    asm.store_eax(4)
    asm.ret()

    slots, _report = _run_x86(config, asm, 0x10, (0, 4))
    assert slots[0] != 0
    assert slots[4] == 1


def test_is_zoomed_amd64(config):
    asm = _X64Asm()
    asm.alloc_frame()
    asm.zero_stack_args()
    asm.xor_rcx()
    asm.xor_rdx()
    asm.xor_r8()
    asm.mov_r9_imm32(WS_MAXIMIZE)
    asm.mov_rax_api("user32", "CreateWindowExW")
    asm.call_rax()
    asm.store_rax(0)

    asm.mov_rcx_slot(0)
    asm.mov_rax_api("user32", "IsZoomed")
    asm.call_rax()
    asm.store_rax(8)

    asm.mov_rcx_slot(0)
    asm.mov_rdx_imm32(SW_RESTORE)
    asm.mov_rax_api("user32", "ShowWindow")
    asm.call_rax()
    asm.store_rax(16)

    asm.mov_rcx_slot(0)
    asm.mov_rax_api("user32", "IsZoomed")
    asm.call_rax()
    asm.store_rax(24)

    asm.free_frame()
    asm.ret()

    slots, _report = _run_x64(config, asm, 0x40, (0, 8, 24))
    assert slots[0] != 0
    assert slots[8] == 1
    assert slots[24] == 0


# ---------------------------------------------------------------------------
# Signature fallback policy (the old unconditional TRUE)
# ---------------------------------------------------------------------------


def test_status_bool_signature_fallback_returns_false_with_error(config):
    asm = _X86Asm()
    asm.push_imm32(0)  # dwFlags
    asm.push_imm32(0)  # lpNewFileName
    asm.push_imm32(0)  # lpExistingFileName
    asm.mov_eax_api("kernel32", "MoveFileExW")
    asm.call_eax()
    asm.store_eax(0)

    asm.mov_eax_api("kernel32", "GetLastError")
    asm.call_eax()
    asm.store_eax(4)
    asm.ret()

    slots, report = _run_x86(config, asm, 0x10, (0, 4))
    events = _api_events(report)
    assert [e.api_name for e in events] == ["kernel32.MoveFileExW", "kernel32.GetLastError"]
    assert events[0].ret_val == "0x0", "status BOOL must not fabricate TRUE"
    assert slots[0] == 0
    assert slots[4] == ERROR_CALL_NOT_IMPLEMENTED


def test_predicate_bool_signature_fallback_returns_false_without_error(config):
    asm = _X86Asm()
    asm.push_imm32(0x1234)
    asm.mov_eax_api("kernel32", "SetLastError")
    asm.call_eax()

    asm.mov_eax_api("kernel32", "IsThreadAFiber")
    asm.call_eax()
    asm.store_eax(0)

    asm.mov_eax_api("kernel32", "GetLastError")
    asm.call_eax()
    asm.store_eax(4)
    asm.ret()

    slots, report = _run_x86(config, asm, 0x10, (0, 4))
    events = _api_events(report)
    assert [e.api_name for e in events] == [
        "kernel32.SetLastError",
        "kernel32.IsThreadAFiber",
        "kernel32.GetLastError",
    ]
    assert events[1].ret_val == "0x0", "predicate BOOL must not fabricate TRUE"
    assert slots[0] == 0
    assert slots[4] == 0x1234, "a false predicate is not an error"
