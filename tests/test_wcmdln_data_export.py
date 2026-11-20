"""Contract tests for CRT ``_wcmdln`` / ``__p__wcmdln`` data exports (FX-008-extended).

``CRT / data_export``: ``msvcr80._wcmdln`` is a **data import**. The Windows
loader binds its IAT slot to the address of the writable ``wchar_t *_wcmdln``
pointer cell; the cell itself points at the NUL-terminated UTF-16LE command
line. ``__p__wcmdln()`` returns the same cell address.

Speakeasy only implemented ``_acmdln``. With no ``@impdata("_wcmdln")``
handler, ``WindowsEmulator.load_image`` left the loader import sentinel in the
IAT slot, and a guest dereference was served the import-probe prologue
``48 8b c4`` (0xc48b48 on AMD64) as if it were the wide command-line pointer.

These tests build synthetic PEs with a real import directory (MSVCR80
``_wcmdln`` and ``__p__wcmdln``) and drive the engine:

* positive: the IAT slot resolves to a writable pointer cell, ``*cell`` is the
  UTF-16LE command line sourced from the emulator command line, and
  ``__p__wcmdln`` returns the same cell;
* control: the existing ``_acmdln`` data import is unchanged;
* negative: a genuinely missing CRT data export keeps its sentinel and the
  reserved-page import-probe behaviour, and an unmapped read without a handler
  still records ``invalid_read``.

No batch sample is executed. No environment variables or monkey patching.
"""

from __future__ import annotations

import struct

import pytest

from speakeasy import Speakeasy
from speakeasy.common import PERM_MEM_WRITE
from speakeasy.windows.common import EMU_RESERVE_SIZE, EMU_RESERVED
from speakeasy.windows.import_sentinel import import_probe_prefix
from speakeasy.winenv import arch as e_arch
from speakeasy.winenv.defs.windows.windows import PAGE_READONLY

IMAGE_BASE = 0x400000
TEXT_RVA = 0x1000
RDATA_RVA = 0x2000
DATA_RVA = 0x3000
IMAGE_SIZE = 0x4000

IMPORT_DESC_RVA = RDATA_RVA + 0x00
ILT_RVA = RDATA_RVA + 0x28
IAT_RVA = RDATA_RVA + 0x40
HINT_WCMDLN_RVA = RDATA_RVA + 0x60
HINT_P_WCMDLN_RVA = RDATA_RVA + 0x70
DLL_NAME_RVA = RDATA_RVA + 0x80

# .data marker slots (all pointer-sized, spaced 8 bytes apart).
M_CELL = DATA_RVA + 0x00
M_STR = DATA_RVA + 0x08
M_CHARS = DATA_RVA + 0x10
M_RB = DATA_RVA + 0x18
M_P = DATA_RVA + 0x20

COMMAND_LINE = r"C:\test\wcmdln.exe alpha beta"
UNMAPPED_VA = 0xDEADB000


def _build_pe(arch: int, imports: list[str], text: bytes) -> bytes:
    """Build a minimal PE32/PE32+ with one import descriptor (MSVCR80.dll).

    The import directory, ILT, IAT and strings live in a read-only ``.rdata``
    section; the IAT slots start out pointing at the hint/name entries (the
    loader replaces them with sentinels/handlers, exactly like a real image).
    ``imports`` names the imported symbols in order (data or function).
    """
    is_64 = arch == e_arch.ARCH_AMD64
    image = bytearray(0x800)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x40)
    image[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into(
        "<HHIIIHH",
        image,
        0x44,
        0x8664 if is_64 else 0x14C,
        3,
        0,
        0,
        0,
        0xF0 if is_64 else 0xE0,
        0x0102,
    )

    opt = 0x58
    opt_size = 0xF0 if is_64 else 0xE0
    struct.pack_into("<H", image, opt, 0x20B if is_64 else 0x10B)
    struct.pack_into("<BB", image, opt + 2, 1, 0)
    struct.pack_into("<I", image, opt + 4, 0x200)  # SizeOfCode
    struct.pack_into("<I", image, opt + 8, 0x400)  # SizeOfInitializedData
    struct.pack_into("<I", image, opt + 12, 0)  # SizeOfUninitializedData
    struct.pack_into("<I", image, opt + 16, TEXT_RVA)  # AddressOfEntryPoint
    struct.pack_into("<I", image, opt + 20, TEXT_RVA)  # BaseOfCode
    if is_64:
        struct.pack_into("<Q", image, opt + 24, IMAGE_BASE)
        struct.pack_into("<I", image, opt + 32, 0x1000)  # SectionAlignment
        struct.pack_into("<I", image, opt + 36, 0x200)  # FileAlignment
        major_os = opt + 40
        image_ver = opt + 44
        subsystem_ver = opt + 48
        win32_ver = opt + 52
        size_of_image = opt + 56
        size_of_headers = opt + 60
        checksum = opt + 64
        subsystem = opt + 68
        stack_reserve = opt + 72
        heap_reserve = opt + 88
        loader_flags = opt + 104
        num_dirs = opt + 108
        dirs = opt + 112
    else:
        struct.pack_into("<I", image, opt + 24, IMAGE_BASE)  # BaseOfData
        struct.pack_into("<I", image, opt + 28, IMAGE_BASE)  # ImageBase
        struct.pack_into("<I", image, opt + 32, 0x1000)
        struct.pack_into("<I", image, opt + 36, 0x200)
        major_os = opt + 40
        image_ver = opt + 44
        subsystem_ver = opt + 48
        win32_ver = opt + 52
        size_of_image = opt + 56
        size_of_headers = opt + 60
        checksum = opt + 64
        subsystem = opt + 68
        stack_reserve = opt + 72
        heap_reserve = opt + 80
        loader_flags = opt + 88
        num_dirs = opt + 92
        dirs = opt + 96

    struct.pack_into("<HH", image, major_os, 6, 0)
    struct.pack_into("<HH", image, image_ver, 0, 0)
    struct.pack_into("<HH", image, subsystem_ver, 6, 1)
    struct.pack_into("<I", image, win32_ver, 0)
    struct.pack_into("<I", image, size_of_image, IMAGE_SIZE)
    struct.pack_into("<I", image, size_of_headers, 0x200)
    struct.pack_into("<I", image, checksum, 0)
    struct.pack_into("<HH", image, subsystem, 3, 0)
    if is_64:
        struct.pack_into("<QQ", image, stack_reserve, 0x100000, 0x1000)
        struct.pack_into("<QQ", image, heap_reserve, 0x100000, 0x1000)
    else:
        struct.pack_into("<II", image, stack_reserve, 0x100000, 0x1000)
        struct.pack_into("<II", image, heap_reserve, 0x100000, 0x1000)
    struct.pack_into("<I", image, loader_flags, 0)
    struct.pack_into("<I", image, num_dirs, 16)
    # DataDirectory[1] = import table (RVA, size).
    struct.pack_into("<II", image, dirs + 8, IMPORT_DESC_RVA, 40)
    assert dirs + 16 * 8 == opt + opt_size

    section_table = opt + opt_size

    def section(index: int, name: bytes, vsize: int, rva: int, raw_size: int, raw_ptr: int, chars: int) -> None:
        off = section_table + index * 40
        image[off : off + 8] = name.ljust(8, b"\x00")
        struct.pack_into("<IIIIIIHHI", image, off + 8, vsize, rva, raw_size, raw_ptr, 0, 0, 0, 0, chars)

    section(0, b".text", 0x1000, TEXT_RVA, 0x200, 0x200, 0x60000020)
    section(1, b".rdata", 0x1000, RDATA_RVA, 0x200, 0x400, 0x40000040)
    section(2, b".data", 0x1000, DATA_RVA, 0x200, 0x600, 0xC0000040)

    ptr = 8 if is_64 else 4
    # The paired _wcmdln/__p__wcmdln PE needs two hint/name entries spaced
    # 0x10 apart; single-import PEs use the first slot; an import-free PE
    # leaves the descriptor all-zero.
    if not imports:
        name_rvas = []
    elif len(imports) == 1:
        name_rvas = [HINT_WCMDLN_RVA]
    elif len(imports) == 2:
        name_rvas = [HINT_WCMDLN_RVA, HINT_P_WCMDLN_RVA]
    else:
        raise AssertionError(f"unsupported import count: {len(imports)}")

    rdata = bytearray(0x200)

    def put_rva(rva: int, data: bytes) -> None:
        off = rva - RDATA_RVA
        rdata[off : off + len(data)] = data

    if imports:
        # IMAGE_IMPORT_DESCRIPTOR (OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk).
        struct.pack_into("<IIIII", rdata, IMPORT_DESC_RVA - RDATA_RVA, ILT_RVA, 0, 0, DLL_NAME_RVA, IAT_RVA)
        # Null descriptor terminator stays zero.

        for imp_index, name in enumerate(imports):
            encoded = b"\x00\x00" + name.encode("ascii") + b"\x00"
            put_rva(name_rvas[imp_index], encoded)

        for imp_index, name in enumerate(imports):
            rva = name_rvas[imp_index]
            struct.pack_into("<Q" if is_64 else "<I", rdata, ILT_RVA - RDATA_RVA + imp_index * ptr, rva)
            struct.pack_into("<Q" if is_64 else "<I", rdata, IAT_RVA - RDATA_RVA + imp_index * ptr, rva)

        put_rva(DLL_NAME_RVA, b"MSVCR80.dll\x00")

    image[0x400 : 0x400 + 0x200] = rdata
    assert len(text) <= 0x200
    image[0x200 : 0x200 + len(text)] = text
    return bytes(image)


def _u32(value: int) -> bytes:
    return struct.pack("<I", value)


def _u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def _text_wcmdln_pair(is_64: bool) -> bytes:
    """Guest: resolve _wcmdln, read/write the cell, then call __p__wcmdln()."""
    iat0 = IMAGE_BASE + IAT_RVA
    iat1 = iat0 + (8 if is_64 else 4)
    code = bytearray()
    if is_64:
        code += b"\x48\xA1" + _u64(iat0)  # mov rax, [iat0]
        code += b"\x48\xA3" + _u64(IMAGE_BASE + M_CELL)  # mov [m_cell], rax
        code += b"\x48\x8B\x18"  # mov rbx, [rax]
        code += b"\x48\x89\x1C\x25" + _u32(IMAGE_BASE + M_STR)  # mov [m_str], rbx
        code += b"\x8B\x0B"  # mov ecx, [rbx]
        code += b"\x89\x0C\x25" + _u32(IMAGE_BASE + M_CHARS)  # mov [m_chars], ecx
        code += b"\x48\x89\x18"  # mov [rax], rbx (cell is writable)
        code += b"\x48\x8B\x08"  # mov rcx, [rax]
        code += b"\x48\x89\x0C\x25" + _u32(IMAGE_BASE + M_RB)  # mov [m_rb], rcx
        code += b"\x48\xA1" + _u64(iat1)  # mov rax, [iat1]
        code += b"\xFF\xD0"  # call rax
        code += b"\x48\xA3" + _u64(IMAGE_BASE + M_P)  # mov [m_p], rax
    else:
        code += b"\xA1" + _u32(iat0)  # mov eax, [iat0]
        code += b"\xA3" + _u32(IMAGE_BASE + M_CELL)  # mov [m_cell], eax
        code += b"\x8B\x18"  # mov ebx, [eax]
        code += b"\x89\x1D" + _u32(IMAGE_BASE + M_STR)  # mov [m_str], ebx
        code += b"\x8B\x0B"  # mov ecx, [ebx]
        code += b"\x89\x0D" + _u32(IMAGE_BASE + M_CHARS)  # mov [m_chars], ecx
        code += b"\x89\x18"  # mov [eax], ebx (cell is writable)
        code += b"\x8B\x08"  # mov ecx, [eax]
        code += b"\x89\x0D" + _u32(IMAGE_BASE + M_RB)  # mov [m_rb], ecx
        code += b"\xA1" + _u32(iat1)  # mov eax, [iat1]
        code += b"\xFF\xD0"  # call eax
        code += b"\xA3" + _u32(IMAGE_BASE + M_P)  # mov [m_p], eax
    code += b"\xC3"  # ret
    return bytes(code)


def _text_acmdln(is_64: bool) -> bytes:
    """Guest: resolve _acmdln, store the cell and the ANSI string pointer."""
    iat0 = IMAGE_BASE + IAT_RVA
    code = bytearray()
    if is_64:
        code += b"\x48\xA1" + _u64(iat0)
        code += b"\x48\xA3" + _u64(IMAGE_BASE + M_CELL)
        code += b"\x48\x8B\x18"
        code += b"\x48\x89\x1C\x25" + _u32(IMAGE_BASE + M_STR)
        code += b"\x8B\x0B"
        code += b"\x89\x0C\x25" + _u32(IMAGE_BASE + M_CHARS)
    else:
        code += b"\xA1" + _u32(iat0)
        code += b"\xA3" + _u32(IMAGE_BASE + M_CELL)
        code += b"\x8B\x18"
        code += b"\x89\x1D" + _u32(IMAGE_BASE + M_STR)
        code += b"\x8B\x0B"
        code += b"\x89\x0D" + _u32(IMAGE_BASE + M_CHARS)
    code += b"\xC3"
    return bytes(code)


def _text_missing_data(is_64: bool) -> bytes:
    """Guest: read the IAT slot, then read at that (sentinel) address."""
    iat0 = IMAGE_BASE + IAT_RVA
    code = bytearray()
    if is_64:
        code += b"\x48\xA1" + _u64(iat0)  # mov rax, [iat0]
        code += b"\x48\x8B\x18"  # mov rbx, [rax]
        code += b"\x48\x89\x1C\x25" + _u32(IMAGE_BASE + M_STR)  # mov [m_str], rbx
    else:
        code += b"\xA1" + _u32(iat0)
        code += b"\x8B\x18"
        code += b"\x89\x1D" + _u32(IMAGE_BASE + M_STR)
    code += b"\xC3"
    return bytes(code)


def _text_unmapped_read(is_64: bool) -> bytes:
    code = bytearray()
    if is_64:
        code += b"\x48\xA1" + _u64(UNMAPPED_VA)  # mov rax, [unmapped]
    else:
        code += b"\xA1" + _u32(UNMAPPED_VA)  # mov eax, [unmapped]
    code += b"\xC3"
    return bytes(code)


def _run_pe(config, pe: bytes, command_line: str | None = None):
    cfg = config
    if command_line is not None:
        cfg["command_line"] = command_line
    se = Speakeasy(config=cfg, argv=[])
    try:
        module = se.load_module(data=pe)
        se.run_module(module, all_entrypoints=True)
        return se.get_report(), se.emu
    finally:
        se.shutdown()


def _read_ptr(emu, va: int) -> int:
    return int.from_bytes(emu.mem_read(va, emu.get_ptr_size()), "little")


def _read_wide_string(emu, va: int, max_bytes: int = 512) -> str:
    raw = bytes(emu.mem_read(va, max_bytes))
    chars = bytearray()
    for offset in range(0, len(raw) - 1, 2):
        pair = raw[offset : offset + 2]
        if pair == b"\x00\x00":
            break
        chars += pair
    return bytes(chars).decode("utf-16le")


def _assert_not_sentinel(value: int) -> None:
    assert not (EMU_RESERVED <= value <= EMU_RESERVED + EMU_RESERVE_SIZE), hex(value)


@pytest.mark.parametrize("arch", [e_arch.ARCH_X86, e_arch.ARCH_AMD64], ids=["x86", "x64"])
def test_wcmdln_data_import_is_a_wide_command_line_cell(config, arch):
    is_64 = arch == e_arch.ARCH_AMD64
    pe = _build_pe(arch, ["_wcmdln", "__p__wcmdln"], _text_wcmdln_pair(is_64))
    report, emu = _run_pe(config, pe, command_line=COMMAND_LINE)

    entry = report.entry_points[0]
    assert entry.error is None, entry.error

    iat_va = IMAGE_BASE + IAT_RVA
    cell = _read_ptr(emu, IMAGE_BASE + M_CELL)
    assert cell != 0
    _assert_not_sentinel(cell)
    assert emu.get_address_map(cell) is not None
    # The loader bound the IAT slot to that pointer cell.
    assert int.from_bytes(emu.mem_read(iat_va, emu.get_ptr_size()), "little") == cell

    str_ptr = _read_ptr(emu, IMAGE_BASE + M_STR)
    assert str_ptr != 0
    _assert_not_sentinel(str_ptr)
    text = _read_wide_string(emu, str_ptr)
    assert text == COMMAND_LINE
    # The guest read the first two wide characters through the cell.
    assert _read_ptr(emu, IMAGE_BASE + M_CHARS) & 0xFFFFFFFF == int.from_bytes(
        COMMAND_LINE.encode("utf-16le")[:4], "little"
    )
    # The guest wrote the string pointer back into the cell and read it again:
    # the pointer cell is writable and stable.
    assert _read_ptr(emu, IMAGE_BASE + M_RB) == str_ptr
    assert emu.get_address_map(cell + emu.get_ptr_size()) is not None
    # __p__wcmdln() returns the same pointer cell as the data import.
    assert _read_ptr(emu, IMAGE_BASE + M_P) == cell

    # The IAT page itself stays read-only image data (no .rdata widening).
    assert emu.get_address_win_protection(iat_va) == PAGE_READONLY
    perms = emu.get_address_perms(iat_va)
    assert perms is not None and not (perms & PERM_MEM_WRITE)


@pytest.mark.parametrize("arch", [e_arch.ARCH_X86, e_arch.ARCH_AMD64], ids=["x86", "x64"])
def test_acmdln_data_import_is_unaffected(config, arch):
    is_64 = arch == e_arch.ARCH_AMD64
    pe = _build_pe(arch, ["_acmdln"], _text_acmdln(is_64))
    report, emu = _run_pe(config, pe, command_line=COMMAND_LINE)

    entry = report.entry_points[0]
    assert entry.error is None, entry.error

    cell = _read_ptr(emu, IMAGE_BASE + M_CELL)
    assert cell != 0
    _assert_not_sentinel(cell)
    str_ptr = _read_ptr(emu, IMAGE_BASE + M_STR)
    assert str_ptr != 0
    _assert_not_sentinel(str_ptr)
    ansi = bytes(emu.mem_read(str_ptr, len(COMMAND_LINE)))
    assert ansi.decode("utf-8") == COMMAND_LINE


@pytest.mark.parametrize("arch", [e_arch.ARCH_X86, e_arch.ARCH_AMD64], ids=["x86", "x64"])
def test_missing_crt_data_export_keeps_sentinel_and_probe(config, arch):
    is_64 = arch == e_arch.ARCH_AMD64
    pe = _build_pe(arch, ["_no_such_crt_data_"], _text_missing_data(is_64))
    report, emu = _run_pe(config, pe, command_line=COMMAND_LINE)

    entry = report.entry_points[0]
    assert entry.error is None, entry.error

    ptr = emu.get_ptr_size()
    iat_value = int.from_bytes(emu.mem_read(IMAGE_BASE + IAT_RVA, ptr), "little")
    assert EMU_RESERVED <= iat_value <= EMU_RESERVED + EMU_RESERVE_SIZE

    # A read *at* the sentinel still uses the import-probe prefix path: the
    # guest-visible value is the architecture prologue, not CRT data.
    prefix = import_probe_prefix(arch)
    expected = int.from_bytes((prefix + b"\x00" * ptr)[:ptr], "little")
    assert _read_ptr(emu, IMAGE_BASE + M_STR) == expected


@pytest.mark.parametrize("arch", [e_arch.ARCH_X86, e_arch.ARCH_AMD64], ids=["x86", "x64"])
def test_unhandled_invalid_read_is_preserved(config, arch):
    is_64 = arch == e_arch.ARCH_AMD64
    pe = _build_pe(arch, [], _text_unmapped_read(is_64))
    report, _ = _run_pe(config, pe)

    entry = report.entry_points[0]
    assert entry.error is not None
    assert entry.error.type == "invalid_read"
    assert entry.error.address == UNMAPPED_VA
