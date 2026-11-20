"""Contract tests for CRT initializer table traversal (FX-008).

``CRT / initterm``: ``_initterm`` and ``_initterm_e`` must traverse
``[pfbegin, pfend)`` in order, skip NULL entries and call every non-NULL
initializer. ``_initterm_e`` stops at the first initializer that returns
non-zero and returns that value; ``_initterm`` ignores initializer return
values. Empty and all-NULL tables return 0.

Speakeasy's handlers were empty stubs: they read ``pfbegin``/``pfend`` and
returned 0 without reading the table or executing any initializer, so global
constructors/initialization never ran.

These tests drive the real handlers from x86/x64 shellcode loaded by the
engine. The guest builds a CRT-style function pointer table in its data block,
calls the import stub, and the initializer functions write markers back into
that block. No batch sample is executed.
"""

from __future__ import annotations

import struct
from contextlib import contextmanager

import pytest

from speakeasy import Speakeasy

# Shellcode data block layout (pointer-sized table, then marker slots).
D_TABLE = 0x00
D_RV = 0x20
D_A = 0x24
D_B = 0x28
D_NEST = 0x2C
D_ORDER = 0x30
DATA_SIZE = 0x40


class _Asm32:
    """Minimal x86 emitter with absolute fixups resolved after loading."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.patches: list[tuple[int, str, int]] = []

    def imm32(self, key: str, addend: int = 0) -> None:
        offset = len(self.buf)
        self.buf += b"\x00\x00\x00\x00"
        self.patches.append((offset, key, addend))

    def push_imm(self, key: str, addend: int = 0) -> None:
        self.buf += b"\x68"
        self.imm32(key, addend)

    def push_imm32(self, value: int) -> None:
        self.buf += b"\x68" + struct.pack("<I", value & 0xFFFFFFFF)

    def mov_eax(self, key: str, addend: int = 0) -> None:
        self.buf += b"\xb8"
        self.imm32(key, addend)

    def mov_eax_imm32(self, value: int) -> None:
        self.buf += b"\xb8" + struct.pack("<I", value & 0xFFFFFFFF)

    def call_eax(self) -> None:
        self.buf += b"\xff\xd0"

    def add_esp_imm8(self, value: int) -> None:
        self.buf += b"\x83\xc4" + struct.pack("<B", value & 0xFF)

    def mov_mem_eax(self, data_off: int) -> None:
        self.buf += b"\xa3"
        self.imm32("data", data_off)

    def mov_mem_imm32(self, data_off: int, value: int) -> None:
        self.buf += b"\xc7\x05"
        self.imm32("data", data_off)
        self.buf += struct.pack("<I", value & 0xFFFFFFFF)

    def ret(self) -> None:
        self.buf += b"\xc3"


class _Asm64:
    """Minimal x64 emitter with absolute fixups resolved after loading."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.patches: list[tuple[int, str, int]] = []

    def imm64(self, key: str, addend: int = 0) -> None:
        offset = len(self.buf)
        self.buf += b"\x00" * 8
        self.patches.append((offset, key, addend))

    def mov_r11(self, key: str, addend: int = 0) -> None:
        self.buf += b"\x49\xbb"
        self.imm64(key, addend)

    def mov_rcx_r11(self) -> None:
        self.buf += b"\x4c\x89\xd9"

    def mov_rdx_r11(self) -> None:
        self.buf += b"\x4c\x89\xda"

    def mov_ecx_imm32(self, value: int) -> None:
        self.buf += b"\xb9" + struct.pack("<I", value & 0xFFFFFFFF)

    def mov_rax(self, key: str, addend: int = 0) -> None:
        self.buf += b"\x48\xb8"
        self.imm64(key, addend)

    def mov_eax_imm32(self, value: int) -> None:
        self.buf += b"\xb8" + struct.pack("<I", value & 0xFFFFFFFF)

    def call_rax(self) -> None:
        self.buf += b"\xff\xd0"

    def mov_mem_r11_eax(self) -> None:
        self.buf += b"\x41\x89\x03"

    def mov_mem_r11_imm32(self, value: int) -> None:
        self.buf += b"\x41\xc7\x03" + struct.pack("<I", value & 0xFFFFFFFF)

    def ret(self) -> None:
        self.buf += b"\xc3"


def _build(
    arch: str,
    api: str,
    entry_count: int,
    *,
    init_a_returns: int | None = None,
    nested_api: bool = False,
    init_a_calls_narrow_argv: bool = False,
) -> tuple[object, int, int]:
    """Build entry + initA + initB shellcode.

    The entry point calls ``api`` with ``(table, table + entry_count * ptr)``,
    stores the API return value in ``D_RV`` and returns to the engine.
    ``initA``/``initB`` write the order marker and their own marker; ``initA``
    may return a value or call ``kernel32.GetTickCount`` first.
    """
    asm = _Asm64() if arch == "x64" else _Asm32()
    if arch == "x64":
        asm.mov_r11("data", D_TABLE)
        asm.mov_rcx_r11()
        asm.mov_r11("data", D_TABLE + entry_count * 8)
        asm.mov_rdx_r11()
        asm.mov_rax(f"api:{api}")
        asm.call_rax()
        asm.mov_r11("data", D_RV)
        asm.mov_mem_r11_eax()
        asm.ret()

        init_a = len(asm.buf)
        if nested_api:
            asm.mov_rax("api:kernel32.GetTickCount")
            asm.call_rax()
            asm.mov_r11("data", D_NEST)
            asm.mov_mem_r11_eax()
        asm.mov_r11("data", D_ORDER)
        asm.mov_mem_r11_imm32(1)
        asm.mov_r11("data", D_A)
        asm.mov_mem_r11_imm32(1)
        if init_a_calls_narrow_argv:
            asm.mov_ecx_imm32(1)
            asm.mov_rax("api:msvcrt._configure_narrow_argv")
            asm.call_rax()
        if init_a_returns is not None:
            asm.mov_eax_imm32(init_a_returns)
        asm.ret()

        init_b = len(asm.buf)
        asm.mov_r11("data", D_ORDER)
        asm.mov_mem_r11_imm32(2)
        asm.mov_r11("data", D_B)
        asm.mov_mem_r11_imm32(1)
        asm.ret()
    else:
        asm.push_imm("data", D_TABLE + entry_count * 4)
        asm.push_imm("data", D_TABLE)
        asm.mov_eax(f"api:{api}")
        asm.call_eax()
        asm.add_esp_imm8(8)  # cdecl caller cleans the two pointer arguments
        asm.mov_mem_eax(D_RV)
        asm.ret()

        init_a = len(asm.buf)
        if nested_api:
            asm.mov_eax("api:kernel32.GetTickCount")
            asm.call_eax()
            asm.mov_mem_eax(D_NEST)
        asm.mov_mem_imm32(D_ORDER, 1)
        asm.mov_mem_imm32(D_A, 1)
        if init_a_calls_narrow_argv:
            asm.push_imm32(1)
            asm.mov_eax("api:msvcrt._configure_narrow_argv")
            asm.call_eax()
            asm.add_esp_imm8(4)
        if init_a_returns is not None:
            asm.mov_eax_imm32(init_a_returns)
        asm.ret()

        init_b = len(asm.buf)
        asm.mov_mem_imm32(D_ORDER, 2)
        asm.mov_mem_imm32(D_B, 1)
        asm.ret()

    return asm, init_a, init_b


def _build_call1(arch: str, api: str, arg: int) -> object:
    """Build shellcode that calls ``api(arg)`` and stores the 32-bit result.

    The guest calls the import stub with one integer argument, stores EAX/RAX
    into ``D_RV`` and returns to the engine. Used to drive CRT init-stub return
    semantics through the real API dispatcher.
    """
    asm = _Asm64() if arch == "x64" else _Asm32()
    if arch == "x64":
        asm.mov_r11("data", D_RV)
        asm.mov_ecx_imm32(arg)
        asm.mov_rax(f"api:{api}")
        asm.call_rax()
        asm.mov_mem_r11_eax()
        asm.ret()
    else:
        asm.push_imm32(arg)
        asm.mov_eax(f"api:{api}")
        asm.call_eax()
        asm.add_esp_imm8(4)  # cdecl caller cleans the single argument
        asm.mov_mem_eax(D_RV)
        asm.ret()
    return asm


@contextmanager
def _guest(config, arch, asm, entries, init_a_off, init_b_off):
    """Load/run the scenario and expose the live emulator, report and data base."""
    code = bytes(asm.buf)
    data_offset = len(code)
    code += b"\x00" * DATA_SIZE

    se = Speakeasy(config=config)
    try:
        sc_addr = se.load_shellcode(data=code, arch=arch)
        emu = se.emu
        assert emu is not None
        data_addr = sc_addr + data_offset

        values: dict[str, int] = {"data": data_addr, "code": sc_addr}
        for _offset, key, _addend in asm.patches:
            if key.startswith("api:") and key not in values:
                dll, name = key[4:].split(".", 1)
                values[key] = emu.get_proc(dll, name)
        assert all(values.values()), values

        width = 8 if arch == "x64" else 4
        mask = (1 << (width * 8)) - 1
        for offset, key, addend in asm.patches:
            emu.mem_write(sc_addr + offset, ((values[key] + addend) & mask).to_bytes(width, "little"))

        table = bytearray()
        for entry in entries:
            if entry is None:
                table += b"\x00" * width
            else:
                addr = {"initA": sc_addr + init_a_off, "initB": sc_addr + init_b_off}[entry]
                table += addr.to_bytes(width, "little")
        emu.mem_write(data_addr + D_TABLE, bytes(table))

        se.run_shellcode(sc_addr)
        yield emu, se.get_report(), data_addr
    finally:
        se.shutdown()


def _u32(emu, addr: int) -> int:
    return int.from_bytes(emu.mem_read(addr, 4), "little")


def _api_events(report):
    entry = report.entry_points[0]
    return [e for e in (entry.events or []) if getattr(e, "api_name", None)]


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_initterm_runs_non_null_initializers_in_order(config, arch):
    """Both non-NULL entries execute, NULL is skipped, the API returns 0."""
    asm, init_a, init_b = _build(arch, "msvcrt._initterm", 3)

    with _guest(config, arch, asm, [None, "initA", "initB"], init_a, init_b) as (emu, report, data):
        entry = report.entry_points[0]
        assert entry.error is None, entry.error
        assert _u32(emu, data + D_A) == 1
        assert _u32(emu, data + D_B) == 1
        assert _u32(emu, data + D_ORDER) == 2, "initB must run after initA"
        assert _u32(emu, data + D_RV) == 0

        names = [e.api_name for e in _api_events(report)]
        assert "msvcrt._initterm" in names


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_initterm_ignores_nonzero_initializer_results(config, arch):
    """``_initterm`` is void: a non-zero initializer result does not stop the loop."""
    asm, init_a, init_b = _build(arch, "msvcrt._initterm", 3, init_a_returns=7)

    with _guest(config, arch, asm, [None, "initA", "initB"], init_a, init_b) as (emu, report, data):
        entry = report.entry_points[0]
        assert entry.error is None, entry.error
        assert _u32(emu, data + D_A) == 1
        assert _u32(emu, data + D_B) == 1
        assert _u32(emu, data + D_ORDER) == 2
        assert _u32(emu, data + D_RV) == 0


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_initterm_e_stops_at_first_nonzero_result(config, arch):
    """The failing initializer's value is returned; later entries do not run."""
    asm, init_a, init_b = _build(arch, "msvcrt._initterm_e", 3, init_a_returns=7)

    with _guest(config, arch, asm, [None, "initA", "initB"], init_a, init_b) as (emu, report, data):
        entry = report.entry_points[0]
        assert entry.error is None, entry.error
        assert _u32(emu, data + D_A) == 1
        assert _u32(emu, data + D_B) == 0, "initB must not run after initA returns 7"
        assert _u32(emu, data + D_ORDER) == 1
        assert _u32(emu, data + D_RV) == 7


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_initterm_empty_table_returns_zero(config, arch):
    """``pfbegin == pfend`` traverses nothing and returns 0."""
    asm, init_a, init_b = _build(arch, "msvcrt._initterm", 0)

    with _guest(config, arch, asm, [], init_a, init_b) as (emu, report, data):
        entry = report.entry_points[0]
        assert entry.error is None, entry.error
        assert _u32(emu, data + D_A) == 0
        assert _u32(emu, data + D_B) == 0
        assert _u32(emu, data + D_ORDER) == 0
        assert _u32(emu, data + D_RV) == 0


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_initterm_e_all_null_table_returns_zero(config, arch):
    """An all-NULL table calls nothing and returns 0."""
    asm, init_a, init_b = _build(arch, "msvcrt._initterm_e", 2)

    with _guest(config, arch, asm, [None, None], init_a, init_b) as (emu, report, data):
        entry = report.entry_points[0]
        assert entry.error is None, entry.error
        assert _u32(emu, data + D_A) == 0
        assert _u32(emu, data + D_B) == 0
        assert _u32(emu, data + D_ORDER) == 0
        assert _u32(emu, data + D_RV) == 0


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_initializer_can_call_apis(config, arch):
    """Initializers are ordinary guest code: they may call APIs again."""
    asm, init_a, init_b = _build(arch, "msvcrt._initterm", 3, nested_api=True)

    with _guest(config, arch, asm, [None, "initA", "initB"], init_a, init_b) as (emu, report, data):
        entry = report.entry_points[0]
        assert entry.error is None, entry.error
        assert _u32(emu, data + D_A) == 1
        assert _u32(emu, data + D_B) == 1
        assert _u32(emu, data + D_ORDER) == 2
        assert _u32(emu, data + D_NEST) != 0, "GetTickCount must return a tick inside initA"

        names = [e.api_name for e in _api_events(report)]
        assert "kernel32.GetTickCount" in names


# ---------------------------------------------------------------------------
# UCRT startup initializer compatibility (FX-008 attempt 2)
#
# FX-008 makes CRT initializer tables execute. The UCRT startup initializers
# then call narrow-argv / narrow-environment / file-mode initialization
# imports and branch on their ``errno_t`` results. Those handlers used to
# return ``None``; ``do_call_return`` skips the return register for ``None``,
# so EAX kept a stale non-zero value and the UCRT fast-fail path ran
# (the six suite pass->fail regressions). These tests pin the errno_t
# contract at the handler and at the initializer-chain level.
# ---------------------------------------------------------------------------

EINVAL = 22
O_TEXT = 0x4000
O_BINARY = 0x8000


@pytest.mark.parametrize("arch", ["x86", "x64"])
@pytest.mark.parametrize("mode", [0, 1, 2])
def test_configure_narrow_argv_valid_mode_returns_zero(config, arch, mode):
    """``_configure_narrow_argv`` is ``errno_t``: every valid mode returns 0."""
    asm = _build_call1(arch, "msvcrt._configure_narrow_argv", mode)

    with _guest(config, arch, asm, [], 0, 0) as (emu, report, data):
        entry = report.entry_points[0]
        assert entry.error is None, entry.error
        assert _u32(emu, data + D_RV) == 0

        names = [e.api_name for e in _api_events(report)]
        assert "msvcrt._configure_narrow_argv" in names


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_configure_narrow_argv_invalid_mode_returns_einval(config, arch):
    """A mode outside the documented enum returns EINVAL, never a fake 0."""
    asm = _build_call1(arch, "msvcrt._configure_narrow_argv", 3)

    with _guest(config, arch, asm, [], 0, 0) as (emu, report, data):
        entry = report.entry_points[0]
        assert entry.error is None, entry.error
        assert _u32(emu, data + D_RV) == EINVAL


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_initialize_narrow_environment_returns_zero(config, arch):
    """``_initialize_narrow_environment`` is ``errno_t``: success is 0."""
    asm = _build_call1(arch, "msvcrt._initialize_narrow_environment", 0)

    with _guest(config, arch, asm, [], 0, 0) as (emu, report, data):
        entry = report.entry_points[0]
        assert entry.error is None, entry.error
        assert _u32(emu, data + D_RV) == 0

        names = [e.api_name for e in _api_events(report)]
        assert "msvcrt._initialize_narrow_environment" in names


@pytest.mark.parametrize("arch", ["x86", "x64"])
@pytest.mark.parametrize("mode", [O_TEXT, O_BINARY])
def test_set_fmode_valid_modes_return_zero(config, arch, mode):
    """``_set_fmode`` is ``errno_t``: _O_TEXT and _O_BINARY return 0."""
    asm = _build_call1(arch, "msvcrt._set_fmode", mode)

    with _guest(config, arch, asm, [], 0, 0) as (emu, report, data):
        entry = report.entry_points[0]
        assert entry.error is None, entry.error
        assert _u32(emu, data + D_RV) == 0

        names = [e.api_name for e in _api_events(report)]
        assert "msvcrt._set_fmode" in names


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_set_fmode_invalid_mode_returns_einval(config, arch):
    """An unsupported file mode returns EINVAL, matching the UCRT contract."""
    asm = _build_call1(arch, "msvcrt._set_fmode", 1)

    with _guest(config, arch, asm, [], 0, 0) as (emu, report, data):
        entry = report.entry_points[0]
        assert entry.error is None, entry.error
        assert _u32(emu, data + D_RV) == EINVAL


@pytest.mark.parametrize("arch", ["x86", "x64"])
def test_initializer_configure_narrow_argv_success_keeps_initterm_e_running(config, arch):
    """A UCRT startup initializer returning 0 must not stop ``_initterm_e``.

    This is the engine-test-binary path: an initializer calls
    ``_configure_narrow_argv(1)`` and returns its ``errno_t`` result. A handler
    that leaves EAX stale (returns ``None``) makes the initializer return a
    non-zero failure value, ``_initterm_e`` stops, and the process fast-fails.
    """
    asm, init_a, init_b = _build(arch, "msvcrt._initterm_e", 2, init_a_calls_narrow_argv=True)

    with _guest(config, arch, asm, ["initA", "initB"], init_a, init_b) as (emu, report, data):
        entry = report.entry_points[0]
        assert entry.error is None, entry.error
        assert _u32(emu, data + D_A) == 1
        assert _u32(emu, data + D_B) == 1, "initB must still run after a successful argv init"
        assert _u32(emu, data + D_ORDER) == 2
        assert _u32(emu, data + D_RV) == 0

        names = [e.api_name for e in _api_events(report)]
        assert "msvcrt._configure_narrow_argv" in names
