"""Contract tests for per-window ``GWL_*`` long-value storage (FX-010).

``GUI.getwindowlong``: Windows windows carry long-sized attributes selected by
``nIndex``. ``SetWindowLong(hwnd, nIndex, value)`` stores the value and returns
the previous one (0 when unset); ``GetWindowLong(hwnd, nIndex)`` returns the
stored value or 0. ``GWL_WNDPROC`` (``-4``) is backed by the window's procedure
state; ``GWL_USERDATA`` (``-21``) is a free-form pointer slot.

Speakeasy used to return the hardcoded ``2`` from ``GetWindowLong`` for every
``(hWnd, nIndex)``, and ``SetWindowLong`` only updated the window procedure and
returned ``1``. Sample ``8c02e07a`` calls ``GetWindowLongW(hwnd, GWL_USERDATA)``
and treats a non-NULL result as an object pointer: ``test esi,esi; jz`` was
intended to take the NULL path, but ``esi = 2`` fell through to
``mov eax, [esi]`` and the run died with ``invalid_read`` at 0x2.

These tests drive the real user32 handlers from synthetic shellcode (x86 and
AMD64). No batch sample is executed. No environment variables, no monkey
patching, no address/SHA special cases in production code.
"""

from __future__ import annotations

import struct

from speakeasy import Speakeasy

GWL_WNDPROC = -4
GWL_USERDATA = -21
GWL_STYLE = -16

SLOT = 4  # bytes per result slot in the guest data page


class _X86Asm:
    """Tiny x86 emitter with absolute 32-bit fixups resolved after loading."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.patches: list[tuple[int, tuple, int]] = []

    def _imm32(self, key: tuple, addend: int = 0) -> None:
        offset = len(self.buf)
        self.buf += b"\x00\x00\x00\x00"
        self.patches.append((offset, key, addend))

    def push_imm32(self, value: int) -> None:
        self.buf += b"\x68" + struct.pack("<I", value & 0xFFFFFFFF)

    def push_api(self, dll: str, name: str) -> None:
        self.buf += b"\x68"
        self._imm32(("api", dll, name))

    def push_sc(self, addend: int = 0) -> None:
        self.buf += b"\x68"
        self._imm32(("sc",), addend)

    def push_slot(self, offset: int) -> None:
        # push dword ptr [data + offset]
        self.buf += b"\xFF\x35"
        self._imm32(("data",), offset)

    def mov_eax_api(self, dll: str, name: str) -> None:
        self.buf += b"\xB8"
        self._imm32(("api", dll, name))

    def call_eax(self) -> None:
        self.buf += b"\xFF\xD0"

    def store_eax(self, offset: int) -> None:
        # mov dword ptr [data + offset], eax
        self.buf += b"\xA3"
        self._imm32(("data",), offset)

    def ret(self) -> None:
        self.buf += b"\xC3"


class _X64Asm:
    """Tiny Microsoft-x64 emitter with absolute fixups resolved after loading."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.patches: list[tuple[int, tuple, int, int]] = []

    def _imm(self, key: tuple, addend: int = 0, size: int = 8) -> None:
        offset = len(self.buf)
        self.buf += b"\x00" * size
        self.patches.append((offset, key, addend, size))

    def sub_rsp(self, amount: int = 0x28) -> None:
        self.buf += b"\x48\x83\xEC" + bytes([amount])

    def add_rsp(self, amount: int = 0x28) -> None:
        self.buf += b"\x48\x83\xC4" + bytes([amount])

    def mov_rax_api(self, dll: str, name: str) -> None:
        self.buf += b"\x48\xB8"
        self._imm(("api", dll, name), size=8)

    def mov_rcx_slot(self, offset: int) -> None:
        # mov rcx, qword ptr [data + offset]
        self.buf += b"\x48\x8B\x0C\x25"
        self._imm(("data",), addend=offset, size=4)

    def mov_rdx_imm32(self, value: int) -> None:
        # mov rdx, sign-extended imm32
        self.buf += b"\x48\xC7\xC2" + struct.pack("<i", value)

    def mov_r8_imm64(self, value: int) -> None:
        self.buf += b"\x49\xB8" + struct.pack("<Q", value & 0xFFFFFFFFFFFFFFFF)

    def call_rax(self) -> None:
        self.buf += b"\xFF\xD0"

    def store_rax(self, offset: int) -> None:
        # mov qword ptr [data + offset], rax
        self.buf += b"\x48\xA3"
        self._imm(("data",), addend=offset, size=8)

    def ret(self) -> None:
        self.buf += b"\xC3"


def _run_sequence(config, asm, data_size: int, read_offsets: tuple[int, ...], arch: str):
    """Load ``asm`` as shellcode, run it, return (slots, user32_handler).

    ``slots`` maps guest data offsets to 32-bit (x86) or 64-bit (x64) values.
    The user32 handler instance is the one that served the run, so its
    ``sessman`` reflects the window state mutated by the guest.
    """
    code = bytes(asm.buf) + b"\x00" * data_size
    data_off = len(asm.buf)
    word = 8 if arch == "amd64" else 4
    se = Speakeasy(config=config)
    try:
        sc = se.load_shellcode(data=code, arch=arch)
        emu = se.emu
        assert emu is not None
        data_addr = sc + data_off
        values: dict[tuple, int] = {("sc",): sc, ("data",): data_addr}
        for patch in asm.patches:
            if len(patch) == 3:
                offset, key, addend = patch
                size = 4
            else:
                offset, key, addend, size = patch
            if key[0] == "api":
                _, dll, name = key
                addr = emu.get_proc(dll, name)
                assert addr, f"get_proc failed for {dll}!{name}"
                values[key] = addr
            target = values[key] + addend
            packed = struct.pack("<I" if size == 4 else "<Q", target & (2 ** (size * 8) - 1))
            emu.mem_write(sc + offset, packed)

        se.run_shellcode(sc)
        report = se.get_report()
        entry = report.entry_points[0]
        assert entry.error is None, entry.error

        slots = {}
        for offset in read_offsets:
            raw = emu.mem_read(data_addr + offset, word)
            slots[offset] = int.from_bytes(raw, "little")
        handler, _ = emu.api.get_export_func_handler("user32", "GetWindowLong")
        assert handler is not None
        return slots, handler
    finally:
        se.shutdown()


def _desktop_window(asm: _X86Asm, slot: int) -> None:
    asm.mov_eax_api("user32", "GetDesktopWindow")
    asm.call_eax()
    asm.store_eax(slot)


def _create_window(asm: _X86Asm, slot: int) -> None:
    """CreateWindowExW with all-zero arguments: an ordinary session window."""
    for _ in range(12):
        asm.push_imm32(0)
    asm.mov_eax_api("user32", "CreateWindowExW")
    asm.call_eax()
    asm.store_eax(slot)


def test_get_window_long_unset_returns_zero(config):
    """A window with no stored user data returns 0, never the old hardcoded 2."""
    asm = _X86Asm()
    _create_window(asm, 0)
    asm.push_imm32(GWL_USERDATA & 0xFFFFFFFF)
    asm.push_slot(0)
    asm.mov_eax_api("user32", "GetWindowLongW")
    asm.call_eax()
    asm.store_eax(4)
    asm.ret()

    slots, handler = _run_sequence(config, asm, 0x20, (0, 4), "x86")
    hwnd = slots[0]

    assert hwnd != 0
    assert slots[4] == 0


def test_set_get_window_long_user_data_roundtrip_and_old_value(config):
    """SetWindowLong stores GWL_USERDATA and returns the previous value."""
    p1 = 0x12345678
    p2 = 0x0BADBEEF
    asm = _X86Asm()
    _desktop_window(asm, 0)

    asm.push_imm32(p1)  # dwNewLong
    asm.push_imm32(GWL_USERDATA & 0xFFFFFFFF)  # nIndex
    asm.push_slot(0)  # hWnd
    asm.mov_eax_api("user32", "SetWindowLongW")
    asm.call_eax()
    asm.store_eax(4)  # previous value

    asm.push_imm32(GWL_USERDATA & 0xFFFFFFFF)
    asm.push_slot(0)
    asm.mov_eax_api("user32", "GetWindowLongW")
    asm.call_eax()
    asm.store_eax(8)

    asm.push_imm32(p2)
    asm.push_imm32(GWL_USERDATA & 0xFFFFFFFF)
    asm.push_slot(0)
    asm.mov_eax_api("user32", "SetWindowLongW")
    asm.call_eax()
    asm.store_eax(12)

    asm.push_imm32(GWL_USERDATA & 0xFFFFFFFF)
    asm.push_slot(0)
    asm.mov_eax_api("user32", "GetWindowLongW")
    asm.call_eax()
    asm.store_eax(16)
    asm.ret()

    slots, _handler = _run_sequence(config, asm, 0x40, (4, 8, 12, 16), "x86")

    assert slots[4] == 0, "first SetWindowLong must return the unset default 0"
    assert slots[8] == p1
    assert slots[12] == p1, "second SetWindowLong must return the previous value"
    assert slots[16] == p2


def test_gwl_wndproc_matches_window_proc_state(config):
    """GWL_WNDPROC round-trips and stays consistent with set_window_proc."""
    asm = _X86Asm()

    # An ordinary window created through CreateWindowExW lives in the
    # SessionManager window table, so set_window_proc applies to it.
    for _ in range(12):
        asm.push_imm32(0)
    asm.mov_eax_api("user32", "CreateWindowExW")
    asm.call_eax()
    asm.store_eax(0)  # hWnd

    asm.push_sc(0x20)  # dwNewLong: plausible code pointer
    asm.push_imm32(GWL_WNDPROC & 0xFFFFFFFF)
    asm.push_slot(0)
    asm.mov_eax_api("user32", "SetWindowLongW")
    asm.call_eax()
    asm.store_eax(4)

    asm.push_imm32(GWL_WNDPROC & 0xFFFFFFFF)
    asm.push_slot(0)
    asm.mov_eax_api("user32", "GetWindowLongW")
    asm.call_eax()
    asm.store_eax(8)
    asm.ret()

    slots, handler = _run_sequence(config, asm, 0x40, (0, 4, 8), "x86")
    hwnd = slots[0]

    assert hwnd != 0
    assert handler.sessman.get_window(hwnd) is not None
    assert slots[4] == 0
    assert slots[8] != 0, "GWL_WNDPROC must not be reported as zero after Set"
    assert handler.sessman.get_window_proc(hwnd) == slots[8]


def test_window_long_state_is_per_window_and_per_index(config):
    """Values are keyed by (hWnd, nIndex); other slots stay at their default 0."""
    p1 = 0x51515151
    p2 = 0x62626262
    asm = _X86Asm()
    _create_window(asm, 0)  # hwnd1

    # CreateWindowExW with all-zero arguments: a second, ordinary window.
    _create_window(asm, 4)  # hwnd2

    asm.push_imm32(p1)
    asm.push_imm32(GWL_USERDATA & 0xFFFFFFFF)
    asm.push_slot(0)
    asm.mov_eax_api("user32", "SetWindowLongW")
    asm.call_eax()
    asm.store_eax(8)

    asm.push_imm32(p2)
    asm.push_imm32(GWL_USERDATA & 0xFFFFFFFF)
    asm.push_slot(4)
    asm.mov_eax_api("user32", "SetWindowLongW")
    asm.call_eax()
    asm.store_eax(12)

    asm.push_imm32(GWL_USERDATA & 0xFFFFFFFF)
    asm.push_slot(0)
    asm.mov_eax_api("user32", "GetWindowLongW")
    asm.call_eax()
    asm.store_eax(16)

    asm.push_imm32(GWL_USERDATA & 0xFFFFFFFF)
    asm.push_slot(4)
    asm.mov_eax_api("user32", "GetWindowLongW")
    asm.call_eax()
    asm.store_eax(20)

    asm.push_imm32(GWL_STYLE & 0xFFFFFFFF)
    asm.push_slot(0)
    asm.mov_eax_api("user32", "GetWindowLongW")
    asm.call_eax()
    asm.store_eax(24)
    asm.ret()

    slots, handler = _run_sequence(config, asm, 0x60, (0, 4, 16, 20, 24), "x86")
    assert slots[4] != 0
    assert slots[4] != slots[0]
    assert handler.sessman.get_window(slots[4]) is not None
    assert slots[16] == p1
    assert slots[20] == p2
    assert slots[24] == 0, "GWL_STYLE was never set and must not inherit GWL_USERDATA"


def test_gwl_wndproc_on_unknown_window_is_not_fabricated(config):
    """A non-existent hWnd cannot acquire a window procedure through SetWindowLong."""
    asm = _X86Asm()
    asm.push_sc(0x20)
    asm.push_imm32(GWL_WNDPROC & 0xFFFFFFFF)
    asm.push_imm32(0xDEAD)
    asm.mov_eax_api("user32", "SetWindowLongW")
    asm.call_eax()
    asm.store_eax(0)

    asm.push_imm32(GWL_WNDPROC & 0xFFFFFFFF)
    asm.push_imm32(0xDEAD)
    asm.mov_eax_api("user32", "GetWindowLongW")
    asm.call_eax()
    asm.store_eax(4)
    asm.ret()

    slots, handler = _run_sequence(config, asm, 0x20, (0, 4), "x86")

    assert slots[0] == 0
    assert slots[4] == 0
    assert handler.sessman.get_window_proc(0xDEAD) is None


def test_window_long_ptr_roundtrips_on_amd64(config):
    """GetWindowLongPtr/SetWindowLongPtr store LONG_PTR; GetWindowLong truncates."""
    p64 = 0x1122334455667788
    asm = _X64Asm()
    asm.sub_rsp()

    asm.mov_rax_api("user32", "GetDesktopWindow")
    asm.call_rax()
    asm.store_rax(0)

    asm.mov_rax_api("user32", "SetWindowLongPtrW")
    asm.mov_rcx_slot(0)
    asm.mov_rdx_imm32(GWL_USERDATA)
    asm.mov_r8_imm64(p64)
    asm.call_rax()
    asm.store_rax(8)

    asm.mov_rax_api("user32", "GetWindowLongPtrW")
    asm.mov_rcx_slot(0)
    asm.mov_rdx_imm32(GWL_USERDATA)
    asm.call_rax()
    asm.store_rax(16)

    asm.mov_rax_api("user32", "GetWindowLongW")
    asm.mov_rcx_slot(0)
    asm.mov_rdx_imm32(GWL_USERDATA)
    asm.call_rax()
    asm.store_rax(24)

    asm.add_rsp()
    asm.ret()

    slots, handler = _run_sequence(config, asm, 0x40, (0, 8, 16, 24), "amd64")
    hwnd = slots[0]

    assert hwnd != 0
    assert slots[8] == 0
    assert slots[16] == p64
    assert slots[24] == p64 & 0xFFFFFFFF


def test_window_state_explicit_interface():
    """WindowState normalizes sign-extended indices and keeps per-key defaults."""
    from speakeasy.windows.window_state import (
        WindowState,
        canonical_window_long_index,
        mask_window_long_value,
    )

    assert canonical_window_long_index(-4) == 0xFFFFFFFC
    assert canonical_window_long_index(0xFFFFFFFFFFFFFFFC) == 0xFFFFFFFC
    assert canonical_window_long_index(-21) == 0xFFFFFFEB
    assert mask_window_long_value(0x1122334455667788, 4) == 0x55667788
    assert mask_window_long_value(0x1122334455667788, 8) == 0x1122334455667788

    state = WindowState()
    assert state.get(0x1234, -21) == 0
    assert state.set(0x1234, -21, 0xCAFE) == 0
    assert state.get(0x1234, -21) == 0xCAFE
    assert state.set(0x1234, 0xFFFFFFFFFFFFFFEB, 0xBEEF) == 0xCAFE
    assert state.get(0x1234, 0xFFFFFFEB) == 0xBEEF
    assert state.get(0x1235, -21) == 0
    assert state.get(0x1234, -16) == 0
