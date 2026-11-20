"""Contract tests for ``ret=h`` return semantics (FX-006).

``HandleObject.fake_handle``: a HANDLE is an opaque per-domain object reference,
not a pointer and not a universal number. The Win32 metadata signature database
only records ``ret=h``; it does not record the handle domain. Speakeasy used to
answer every unhooked ``ret=h`` API with ``ObjectManager.new_handle()``, i.e. the
first value from ``HandleAllocator._kernel_object_handle`` (0x220), regardless of
whether the API returns a kernel object handle, an HGLOBAL, an HWND or an HGDIOBJ.

``ole32.OleDuplicateData(HGLOBAL hSrc, CLIPFORMAT cfFormat, UINT uiFlags)`` is
the representative case: it returns an HGLOBAL (a mapped data block) or NULL on
failure. With ``hSrc = NULL`` Wine returns NULL (ole32/ole2.c:3094 default path
calls GlobalSize(NULL), which is 0), but Speakeasy returned 0x220. The sample's
``test eax,eax; je`` NULL check therefore fell through to ``call eax`` and the
sample died on an ``invalid_fetch`` at 0x220.

These tests drive the real handlers from x86 shellcode loaded by the engine; no
batch sample is executed.
"""

from __future__ import annotations

import struct

from speakeasy import Speakeasy

S_RET = 0x00
DATA_SIZE = 0x10

# Standard clipboard format that carries an HGLOBAL, and one that carries a
# GDI object handle (which Speakeasy cannot duplicate).
CF_TEXT = 1
CF_BITMAP = 2


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

    def mov_eax_abs(self, key: str, addend: int = 0) -> None:
        self.buf += b"\xb8"
        self.imm32(key, addend)

    def mov_ptr_abs_eax(self, key: str, addend: int = 0) -> None:
        self.buf += b"\x89\x05"
        self.imm32(key, addend)

    def call_eax(self) -> None:
        self.buf += b"\xff\xd0"

    def ret(self) -> None:
        self.buf += b"\xc3"


def _run_handle_call(
    config,
    dll: str,
    name: str,
    args: list[int | str],
    *,
    source: bytes = b"",
    read_size: int = 0,
) -> tuple[int, bytes | None, int | None]:
    """Call ``dll!name`` from x86 shellcode and return ``(rv, dest_bytes, source)``.

    ``args`` items are pushed right-to-left; an int is an immediate and the
    string ``"source"`` pushes the address of the mapped source block. When
    ``read_size`` is non-zero and the return value is non-NULL, the first
    ``read_size`` bytes at the return value are read back before shutdown (so a
    fabricated, unmapped handle fails the test instead of looking successful).
    """
    asm = _Asm()
    for arg in reversed(args):
        if isinstance(arg, int):
            asm.push_imm32(arg)
        else:
            assert arg == "source"
            asm.push_abs("source")
    asm.mov_eax_abs("api")
    asm.call_eax()
    asm.mov_ptr_abs_eax("data", S_RET)
    asm.ret()

    code = bytes(asm.buf)
    data_offset = len(code)
    code += b"\x00" * DATA_SIZE

    se = Speakeasy(config=config)
    try:
        sc_addr = se.load_shellcode(data=code, arch="x86")
        emu = se.emu
        assert emu is not None
        data_addr = sc_addr + data_offset
        values: dict[str, int] = {
            "sc": sc_addr,
            "data": data_addr,
            "api": emu.get_proc(dll, name),
        }
        source_addr = None
        if source:
            source_addr = emu.mem_map(0x1000, tag="test.fx006.source")
            emu.mem_write(source_addr, source)
            values["source"] = source_addr
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

        rv = int.from_bytes(emu.mem_read(data_addr + S_RET, 4), "little")
        dest = None
        if read_size and rv:
            dest = emu.mem_read(rv, read_size)
        return rv, dest, source_addr
    finally:
        se.shutdown()


def test_ole_duplicate_data_null_source_returns_null(config):
    """OleDuplicateData(NULL, 0, 0): Wine's GlobalSize(NULL) failure path -> NULL."""
    rv, _, _ = _run_handle_call(config, "ole32", "OleDuplicateData", [0, 0, 0])

    assert rv == 0


def test_ole_duplicate_data_copies_source_block(config):
    """A valid HGLOBAL source is duplicated into a new, readable block."""
    payload = bytes(range(256)) * 16  # exactly one mapped page
    rv, dest, source_addr = _run_handle_call(
        config,
        "ole32",
        "OleDuplicateData",
        ["source", CF_TEXT, 0],
        source=payload,
        read_size=len(payload),
    )

    assert rv != 0
    assert rv != source_addr
    assert dest == payload


def test_ole_duplicate_data_unsupported_gdi_format_returns_null(config):
    """CF_BITMAP needs a GDI bitmap object, which a kernel handle cannot fake."""
    payload = bytes(range(256)) * 16
    rv, _, _ = _run_handle_call(
        config,
        "ole32",
        "OleDuplicateData",
        ["source", CF_BITMAP, 0],
        source=payload,
    )

    assert rv == 0


def test_unknown_ret_h_api_does_not_fabricate_kernel_handle(config):
    """An unhooked ret=h API not registered as a kernel handle returns NULL.

    ``gdi32.CreatePen`` returns an HPEN (GDI object handle). It has no handler,
    so it exercises the signature fallback. Before the fix the fallback called
    new_handle() and returned 0x220, the first kernel handle value.
    """
    rv, _, _ = _run_handle_call(config, "gdi32", "CreatePen", [0, 1, 0])

    assert rv == 0


def test_unhooked_kernel_handle_api_still_gets_a_handle(config):
    """Compatibility: a known kernel-object handle API keeps a fresh non-NULL handle."""
    rv, _, _ = _run_handle_call(config, "kernel32", "CreateTimerQueue", [])

    assert rv != 0


def test_handle_domains_are_classified_explicitly():
    from speakeasy.windows.handle_semantics import (
        HandleReturnDomain,
        classify_signature_handle_return,
    )

    assert classify_signature_handle_return("ole32", "OleDuplicateData") is HandleReturnDomain.HGLOBAL
    assert classify_signature_handle_return("KERNEL32.DLL", "CreateTimerQueue") is HandleReturnDomain.KERNEL
    assert classify_signature_handle_return("user32", "CreateWindowExA") is HandleReturnDomain.HWND
    assert classify_signature_handle_return("gdi32", "CreatePen") is HandleReturnDomain.HGDI
    assert classify_signature_handle_return("kernel32", "LoadLibraryA") is HandleReturnDomain.HMODULE
    assert classify_signature_handle_return("kernel32", "FutureUnregisteredApi") is HandleReturnDomain.UNKNOWN


def test_signature_handle_default_only_allocates_for_kernel_domain():
    from speakeasy.windows.handle_semantics import signature_handle_return

    allocated: list[int] = []

    def allocate() -> int:
        allocated.append(1)
        return 0x220

    assert signature_handle_return("kernel32", "CreateTimerQueue", allocate) == 0x220
    assert allocated == [1]

    # Data/GUI/module handles and unknown APIs never receive a kernel handle.
    assert signature_handle_return("ole32", "OleDuplicateData", allocate) == 0
    assert signature_handle_return("user32", "CreateWindowExA", allocate) == 0
    assert signature_handle_return("gdi32", "CreatePen", allocate) == 0
    assert signature_handle_return("kernel32", "LoadLibraryA", allocate) == 0
    assert signature_handle_return("kernel32", "FutureUnregisteredApi", allocate) == 0
    # Without an object manager a kernel handle cannot be allocated at all.
    assert signature_handle_return("kernel32", "CreateTimerQueue", None) == 0
