"""FX-001: image-section DEP opt-out for writable image pages.

``MemoryProtection / image_page_cow``: a process image whose Optional Header
``DllCharacteristics`` clears ``IMAGE_DLLCHARACTERISTICS_NX_COMPAT`` opted out
of DEP.  Wine then disables no-exec enforcement (``dlls/ntdll/loader.c:1585-1591``)
and ``mprotect_exec`` adds ``PROT_EXEC`` to readable views
(``dlls/ntdll/unix/virtual.c:1647-1659``).  Speakeasy modelled that policy only
for private ``VirtualAlloc`` views, so packed samples that decrypt code into a
writable image page and jump to it stopped with ``invalid_protect_fetch``.

These tests use synthetic PE32/PE32+ images with three sections:

* ``.text``  -- executable, holds the entry code;
* ``.data``  -- two writable non-executable pages (PAGE_WRITECOPY image view);
* ``.rdata`` -- read-only, writable, or no-access image page depending on the
  scenario.

Positive contracts:
* NXCOMPAT clear + code written into a writable ``.data`` page executes, only
  the faulting page gains ``PERM_MEM_EXEC``, and the guest-visible Win32
  protection stays ``PAGE_WRITECOPY``;
* NXCOMPAT clear + a raw-size-zero writable ``rdata`` section (the packed
  ``4b0cf113`` shape) executes after the guest writes code into it;
* NXCOMPAT clear + the entry point itself inside a writable ``.data`` page
  (the ``1066cc48``/``a6a15ad6`` shape) executes.

Negative contracts (must keep the protected-fetch failure):
* NXCOMPAT set on the same image;
* a read-only ``.rdata`` image page;
* a no-access image page;
* a non-image private ``VirtualAlloc`` PAGE_READONLY page.

No sample SHA, failure address, or environment variable participates in the
decision: the policy comes from the PE header and the page class.
"""

from __future__ import annotations

import struct

import pytest

import speakeasy.common as common
from speakeasy import Speakeasy
from speakeasy.windows.dep_policy import (
    ImageDepPolicy,
    policy_from_dll_characteristics,
)
from speakeasy.windows.page_protection import current_win_protection
from speakeasy.winenv import arch as e_arch

IMAGE_BASE = 0x400000
TEXT_RVA = 0x1000
DATA_RVA = 0x2000
RDATA_RVA = 0x4000
IMAGE_SIZE = 0x5000

HEADERS_SIZE = 0x200
TEXT_RAW = 0x200
DATA_RAW = 0x1400
RDATA_RAW = 0x200
TEXT_RAW_PTR = 0x200
DATA_RAW_PTR = 0x400
RDATA_RAW_PTR = 0x1800

DATA_VSIZE = 0x2000  # two pages: marker page + guest-written code page
RDATA_VSIZE = 0x1000

MARKER_OFF = 0x08
DATA_CODE_OFF = 0x1100
RDATA_CODE_OFF = 0x100
RDATA_PREBUILT_OFF = 0x10

EXEC_MARKER = 0x600D600D

PAGE_READONLY = 0x02
PAGE_WRITECOPY = 0x08
PAGE_READWRITE = 0x04
MEM_COMMIT_RESERVE = 0x3000

NXCOMPAT_DLL_CHARACTERISTICS = 0x8140
OPT_OUT_DLL_CHARACTERISTICS = 0x0000

TEXT_CHARS = 0x60000020  # code | execute | read
DATA_CHARS = 0xC0000040  # initialized data | read | write
RDATA_READONLY_CHARS = 0x40000040  # initialized data | read
RDATA_NOACCESS_CHARS = 0x00000040  # initialized data only
RDATA_WRITABLE_CHARS = 0xC0000040  # initialized data | read | write


# ---------------------------------------------------------------------------
# Minimal PE32 / PE32+ image builder
# ---------------------------------------------------------------------------


def _build_pe(
    arch: int,
    *,
    dll_characteristics: int,
    entry_rva: int = TEXT_RVA,
    text_code: bytes = b"",
    data_code: bytes = b"",
    rdata_data: bytes = b"",
    rdata_chars: int = RDATA_READONLY_CHARS,
    rdata_raw_size: int | None = None,
) -> bytes:
    """Build a synthetic PE with .text, two-page .data and a .rdata section.

    Args:
        arch: ``e_arch.ARCH_X86`` or ``e_arch.ARCH_AMD64``.
        dll_characteristics: Raw Optional Header ``DllCharacteristics``.
        entry_rva: ``AddressOfEntryPoint`` RVA (default: start of .text).
        text_code: Raw bytes placed in ``.text``.
        data_code: Raw bytes placed at the start of ``.data`` (entry-in-data
            scenarios place code at ``DATA_RVA + DATA_CODE_OFF`` instead; the
            caller then embeds it in ``data_code`` padded to the right offset).
        rdata_data: Raw bytes placed at the start of ``.rdata``.
        rdata_chars: Section characteristics of ``.rdata``.
        rdata_raw_size: ``SizeOfRawData`` for ``.rdata``; ``None`` uses
            ``max(len(rdata_data), RDATA_RAW)``.  Pass ``0`` for the packed
            raw-size-zero shape.
    """
    if arch not in (e_arch.ARCH_X86, e_arch.ARCH_AMD64):
        raise ValueError(f"unsupported architecture: {arch}")
    if len(text_code) > TEXT_RAW:
        raise ValueError("text code does not fit in the synthetic .text section")
    if len(data_code) > DATA_RAW:
        raise ValueError("data code does not fit in the synthetic .data section")

    if rdata_raw_size is None:
        rdata_raw_size = max(len(rdata_data), RDATA_RAW)
    if len(rdata_data) > rdata_raw_size:
        raise ValueError("rdata data does not fit in its raw section")

    is_64 = arch == e_arch.ARCH_AMD64
    opt_size = 0xF0 if is_64 else 0xE0
    file_size = RDATA_RAW_PTR + rdata_raw_size
    image = bytearray(file_size)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x40)
    image[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into(
        "<HHIIIHH",
        image,
        0x44,
        0x8664 if is_64 else 0x14C,
        3,  # NumberOfSections
        0,
        0,
        0,
        opt_size,
        0x0022 if is_64 else 0x0102,
    )

    opt = 0x58
    struct.pack_into("<H", image, opt, 0x20B if is_64 else 0x10B)
    struct.pack_into("<BB", image, opt + 2, 1, 0)
    struct.pack_into("<I", image, opt + 4, TEXT_RAW)  # SizeOfCode
    struct.pack_into("<I", image, opt + 8, DATA_RAW + rdata_raw_size)  # SizeOfInitializedData
    struct.pack_into("<I", image, opt + 12, 0)  # SizeOfUninitializedData
    struct.pack_into("<I", image, opt + 16, entry_rva)  # AddressOfEntryPoint
    struct.pack_into("<I", image, opt + 20, TEXT_RVA)  # BaseOfCode
    if is_64:
        struct.pack_into("<Q", image, opt + 24, IMAGE_BASE)
        struct.pack_into("<I", image, opt + 32, 0x1000)  # SectionAlignment
        struct.pack_into("<I", image, opt + 36, 0x200)  # FileAlignment
        struct.pack_into("<HH", image, opt + 40, 6, 0)
        struct.pack_into("<HH", image, opt + 44, 0, 0)
        struct.pack_into("<HH", image, opt + 48, 6, 0)
        struct.pack_into("<I", image, opt + 52, 0)
        struct.pack_into("<I", image, opt + 56, IMAGE_SIZE)  # SizeOfImage
        struct.pack_into("<I", image, opt + 60, HEADERS_SIZE)  # SizeOfHeaders
        struct.pack_into("<I", image, opt + 64, 0)  # CheckSum
        struct.pack_into("<HH", image, opt + 68, 3, dll_characteristics)
        struct.pack_into("<QQ", image, opt + 72, 0x100000, 0x1000)
        struct.pack_into("<QQ", image, opt + 88, 0x100000, 0x1000)
        struct.pack_into("<I", image, opt + 104, 0)
        struct.pack_into("<I", image, opt + 108, 16)
        assert opt + 112 + 16 * 8 == opt + opt_size
    else:
        struct.pack_into("<I", image, opt + 24, DATA_RVA)  # BaseOfData
        struct.pack_into("<I", image, opt + 28, IMAGE_BASE)
        struct.pack_into("<I", image, opt + 32, 0x1000)
        struct.pack_into("<I", image, opt + 36, 0x200)
        struct.pack_into("<HH", image, opt + 40, 6, 0)
        struct.pack_into("<HH", image, opt + 44, 0, 0)
        struct.pack_into("<HH", image, opt + 48, 6, 0)
        struct.pack_into("<I", image, opt + 52, 0)
        struct.pack_into("<I", image, opt + 56, IMAGE_SIZE)
        struct.pack_into("<I", image, opt + 60, HEADERS_SIZE)
        struct.pack_into("<I", image, opt + 64, 0)
        struct.pack_into("<HH", image, opt + 68, 3, dll_characteristics)
        struct.pack_into("<II", image, opt + 72, 0x100000, 0x1000)
        struct.pack_into("<II", image, opt + 80, 0x100000, 0x1000)
        struct.pack_into("<I", image, opt + 88, 0)
        struct.pack_into("<I", image, opt + 92, 16)
        assert opt + 96 + 16 * 8 == opt + opt_size

    section_table = opt + opt_size

    def section(
        index: int,
        name: bytes,
        vsize: int,
        rva: int,
        raw_size: int,
        raw_ptr: int,
        chars: int,
    ) -> None:
        off = section_table + index * 40
        image[off : off + 8] = name.ljust(8, b"\x00")
        struct.pack_into(
            "<IIIIIIHHI",
            image,
            off + 8,
            vsize,
            rva,
            raw_size,
            raw_ptr,
            0,
            0,
            0,
            0,
            chars,
        )

    section(0, b".text", 0x1000, TEXT_RVA, TEXT_RAW, TEXT_RAW_PTR, TEXT_CHARS)
    section(1, b".data", DATA_VSIZE, DATA_RVA, DATA_RAW, DATA_RAW_PTR, DATA_CHARS)
    section(
        2,
        b".rdata",
        RDATA_VSIZE,
        RDATA_RVA,
        rdata_raw_size,
        RDATA_RAW_PTR if rdata_raw_size else 0,
        rdata_chars,
    )

    image[TEXT_RAW_PTR : TEXT_RAW_PTR + len(text_code)] = text_code
    image[DATA_RAW_PTR : DATA_RAW_PTR + len(data_code)] = data_code
    if rdata_raw_size:
        image[RDATA_RAW_PTR : RDATA_RAW_PTR + len(rdata_data)] = rdata_data
    return bytes(image)


# ---------------------------------------------------------------------------
# Guest instruction emitters
# ---------------------------------------------------------------------------

# A patch is (key, image-relative offset, width).


def _emit_call_image_page(arch: int, origin_rva: int) -> tuple[bytes, list[tuple[str, int, int]]]:
    """Emit: write ``ret`` into *target*, call it, then store the marker."""
    buf = bytearray()
    patches: list[tuple[str, int, int]] = []
    if arch == e_arch.ARCH_AMD64:
        buf += b"\x48\xB8"  # mov rax, imm64
        patches.append(("target", origin_rva + len(buf), 8))
        buf += b"\x00" * 8
        buf += b"\xC6\x00\xC3"  # mov byte ptr [rax], 0xC3
        buf += b"\xFF\xD0"  # call rax
        buf += b"\x48\xB8"  # mov rax, imm64
        patches.append(("out_marker", origin_rva + len(buf), 8))
        buf += b"\x00" * 8
        buf += b"\xC7\x00" + struct.pack("<I", EXEC_MARKER)  # mov dword ptr [rax], marker
    else:
        buf += b"\xB8"  # mov eax, imm32
        patches.append(("target", origin_rva + len(buf), 4))
        buf += b"\x00" * 4
        buf += b"\xC6\x00\xC3"  # mov byte ptr [eax], 0xC3
        buf += b"\xFF\xD0"  # call eax
        buf += b"\xC7\x05"  # mov dword ptr [imm32], marker
        patches.append(("out_marker", origin_rva + len(buf), 4))
        buf += b"\x00" * 4
        buf += struct.pack("<I", EXEC_MARKER)
    buf += b"\xC3"
    return bytes(buf), patches


def _emit_call_absolute(arch: int, origin_rva: int) -> tuple[bytes, list[tuple[str, int, int]]]:
    """Emit: call *target* directly; on failure the marker stays zero."""
    buf = bytearray()
    patches: list[tuple[str, int, int]] = []
    if arch == e_arch.ARCH_AMD64:
        buf += b"\x48\xB8"  # mov rax, imm64
        patches.append(("target", origin_rva + len(buf), 8))
        buf += b"\x00" * 8
        buf += b"\xFF\xD0"  # call rax
        buf += b"\x48\xB8"
        patches.append(("out_marker", origin_rva + len(buf), 8))
        buf += b"\x00" * 8
        buf += b"\xC7\x00" + struct.pack("<I", EXEC_MARKER)
    else:
        buf += b"\xB8"
        patches.append(("target", origin_rva + len(buf), 4))
        buf += b"\x00" * 4
        buf += b"\xFF\xD0"  # call eax
        buf += b"\xC7\x05"
        patches.append(("out_marker", origin_rva + len(buf), 4))
        buf += b"\x00" * 4
        buf += struct.pack("<I", EXEC_MARKER)
    buf += b"\xC3"
    return bytes(buf), patches


def _emit_store_marker(arch: int, origin_rva: int) -> tuple[bytes, list[tuple[str, int, int]]]:
    """Emit the entry body used inside a writable image page: marker + ret."""
    buf = bytearray()
    patches: list[tuple[str, int, int]] = []
    if arch == e_arch.ARCH_AMD64:
        buf += b"\x48\xB8"  # mov rax, imm64
        patches.append(("out_marker", origin_rva + len(buf), 8))
        buf += b"\x00" * 8
        buf += b"\xC7\x00" + struct.pack("<I", EXEC_MARKER)
    else:
        buf += b"\xC7\x05"  # mov dword ptr [imm32], marker
        patches.append(("out_marker", origin_rva + len(buf), 4))
        buf += b"\x00" * 4
        buf += struct.pack("<I", EXEC_MARKER)
    buf += b"\xC3"
    return bytes(buf), patches


def _emit_virtual_alloc_call(arch: int, protect: int, origin_rva: int) -> tuple[bytes, list[tuple[str, int, int]]]:
    """Emit: VirtualAlloc(protect), then call the returned page."""
    buf = bytearray()
    patches: list[tuple[str, int, int]] = []
    if arch == e_arch.ARCH_AMD64:
        buf += b"\x48\x83\xEC\x28"  # sub rsp, 0x28
        buf += b"\x31\xC9"  # xor ecx, ecx
        buf += b"\x48\xC7\xC2" + struct.pack("<I", 0x1000)  # mov rdx, 0x1000
        buf += b"\x49\xC7\xC0" + struct.pack("<I", MEM_COMMIT_RESERVE)  # mov r8, 0x3000
        buf += b"\x41\xB9" + struct.pack("<I", protect)  # mov r9d, protect
        buf += b"\x48\xB8"  # mov rax, VirtualAlloc stub
        patches.append(("alloc", origin_rva + len(buf), 8))
        buf += b"\x00" * 8
        buf += b"\xFF\xD0"  # call rax
        buf += b"\x48\x89\xC3"  # mov rbx, rax
        buf += b"\x48\xB8"
        patches.append(("out_alloc", origin_rva + len(buf), 8))
        buf += b"\x00" * 8
        buf += b"\x48\x89\x18"  # mov [rax], rbx
        buf += b"\x48\x89\xD8"  # mov rax, rbx
        buf += b"\xFF\xD0"  # call rax
        buf += b"\x48\xB8"
        patches.append(("out_marker", origin_rva + len(buf), 8))
        buf += b"\x00" * 8
        buf += b"\xC7\x00" + struct.pack("<I", EXEC_MARKER)
        buf += b"\x48\x83\xC4\x28"  # add rsp, 0x28
    else:
        buf += b"\x68" + struct.pack("<I", protect)  # push protect
        buf += b"\x68" + struct.pack("<I", MEM_COMMIT_RESERVE)  # push type
        buf += b"\x68" + struct.pack("<I", 0x1000)  # push size
        buf += b"\x6A\x00"  # push 0 (lpAddress)
        buf += b"\xB8"
        patches.append(("alloc", origin_rva + len(buf), 4))
        buf += b"\x00" * 4
        buf += b"\xFF\xD0"  # call eax
        buf += b"\xA3"
        patches.append(("out_alloc", origin_rva + len(buf), 4))
        buf += b"\x00" * 4
        buf += b"\xFF\xD0"  # call eax
        buf += b"\xC7\x05"
        patches.append(("out_marker", origin_rva + len(buf), 4))
        buf += b"\x00" * 4
        buf += struct.pack("<I", EXEC_MARKER)
    buf += b"\xC3"
    return bytes(buf), patches


# ---------------------------------------------------------------------------
# Execution harness
# ---------------------------------------------------------------------------


def _run_pe(config, arch: int, pe: bytes, patches, values: dict[str, int]):
    """Load, patch and run a synthetic PE; return execution observations."""
    se = Speakeasy(config=config, argv=[])
    try:
        module = se.load_module(data=pe)
        emu = se.emu
        assert module.base == IMAGE_BASE, hex(module.base)
        for key, offset, width in patches:
            emu.mem_write(
                module.base + offset,
                (values[key] & ((1 << (width * 8)) - 1)).to_bytes(width, "little"),
            )
        se.run_module(module)
        report = se.get_report()
        run = report.entry_points[0] if report.entry_points else None
        error = getattr(run, "error", None) if run is not None else "no entry point"
        marker_addr = module.base + DATA_RVA + MARKER_OFF
        marker = int.from_bytes(emu.mem_read(marker_addr, 4), "little")
        return {
            "error": error,
            "marker": marker,
            "module": module,
            "emu": emu,
            "policy": module.get_dep_policy(),
        }
    finally:
        se.shutdown()


def _image_values(module, target_off: int, *, data_target: bool = True) -> dict[str, int]:
    base = module.base + (DATA_RVA if data_target else RDATA_RVA)
    return {
        "target": base + target_off,
        "out_marker": module.base + DATA_RVA + MARKER_OFF,
    }


# ---------------------------------------------------------------------------
# Policy unit tests
# ---------------------------------------------------------------------------


def test_image_page_exec_allowed_requires_opt_out_image_and_writable() -> None:
    from speakeasy.windows.dep_policy import image_page_exec_allowed

    opt_out = policy_from_dll_characteristics(OPT_OUT_DLL_CHARACTERISTICS)
    nx_compat = policy_from_dll_characteristics(NXCOMPAT_DLL_CHARACTERISTICS)
    assert isinstance(opt_out, ImageDepPolicy)

    assert image_page_exec_allowed(
        opt_out, is_image_page=True, page_readable=True, page_writable=True
    )
    # Read-only image pages keep their protection.
    assert not image_page_exec_allowed(
        opt_out, is_image_page=True, page_readable=True, page_writable=False
    )
    # No-access image pages keep their protection.
    assert not image_page_exec_allowed(
        opt_out, is_image_page=True, page_readable=False, page_writable=True
    )
    # Non-image pages are governed by the VirtualAlloc rule, not this one.
    assert not image_page_exec_allowed(
        opt_out, is_image_page=False, page_readable=True, page_writable=True
    )
    # NXCOMPAT images keep DEP enabled.
    assert not image_page_exec_allowed(
        nx_compat, is_image_page=True, page_readable=True, page_writable=True
    )
    # Unknown policy keeps DEP enabled.
    assert not image_page_exec_allowed(
        None, is_image_page=True, page_readable=True, page_writable=True
    )


# ---------------------------------------------------------------------------
# Positive: writable image pages become executable under the DEP opt-out
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("arch", [e_arch.ARCH_X86, e_arch.ARCH_AMD64], ids=["x86", "x64"])
def test_opt_out_writable_image_data_page_executes(config, arch):
    code, patches = _emit_call_image_page(arch, TEXT_RVA)
    pe = _build_pe(
        arch,
        dll_characteristics=OPT_OUT_DLL_CHARACTERISTICS,
        text_code=code,
    )

    values = {
        "target": IMAGE_BASE + DATA_RVA + DATA_CODE_OFF,
        "out_marker": IMAGE_BASE + DATA_RVA + MARKER_OFF,
        "out_alloc": 0,
        "alloc": 0,
    }
    result = _run_pe(config, arch, pe, patches, values)
    assert result["error"] is None, result["error"]

    emu = result["emu"]
    code_addr = IMAGE_BASE + DATA_RVA + DATA_CODE_OFF
    marker_addr = IMAGE_BASE + DATA_RVA + MARKER_OFF
    assert result["marker"] == EXEC_MARKER
    assert emu.get_address_perms(code_addr) & common.PERM_MEM_EXEC
    # Only the faulting page was changed; its neighbour stays non-executable.
    assert not (emu.get_address_perms(marker_addr) & common.PERM_MEM_EXEC)
    # The guest-visible Win32 protection is still PAGE_WRITECOPY.
    assert current_win_protection(emu, code_addr) == PAGE_WRITECOPY
    assert result["policy"] is not None
    assert result["policy"].dep_disabled


@pytest.mark.parametrize("arch", [e_arch.ARCH_X86, e_arch.ARCH_AMD64], ids=["x86", "x64"])
def test_opt_out_writable_image_rdata_page_executes(config, arch):
    """Packed ``4b0cf113`` shape: raw-size-zero writable rdata section."""
    code, patches = _emit_call_image_page(arch, TEXT_RVA)
    pe = _build_pe(
        arch,
        dll_characteristics=OPT_OUT_DLL_CHARACTERISTICS,
        text_code=code,
        rdata_chars=RDATA_WRITABLE_CHARS,
        rdata_raw_size=0,
    )

    se = Speakeasy(config=config, argv=[])
    try:
        module = se.load_module(data=pe)
        emu = se.emu
        values = _image_values(module, RDATA_CODE_OFF, data_target=False)
        for key, offset, width in patches:
            emu.mem_write(
                module.base + offset,
                (values[key] & ((1 << (width * 8)) - 1)).to_bytes(width, "little"),
            )
        se.run_module(module)
        report = se.get_report()
        run = report.entry_points[0]
        assert run.error is None, run.error

        code_addr = module.base + RDATA_RVA + RDATA_CODE_OFF
        assert int.from_bytes(emu.mem_read(module.base + DATA_RVA + MARKER_OFF, 4), "little") == EXEC_MARKER
        assert emu.get_address_perms(code_addr) & common.PERM_MEM_EXEC
        assert current_win_protection(emu, code_addr) == PAGE_WRITECOPY
    finally:
        se.shutdown()


@pytest.mark.parametrize("arch", [e_arch.ARCH_X86, e_arch.ARCH_AMD64], ids=["x86", "x64"])
def test_opt_out_entry_in_writable_image_page_executes(config, arch):
    """Packed ``1066cc48``/``a6a15ad6`` shape: PE entry inside a writable page."""
    entry_rva = DATA_RVA + DATA_CODE_OFF
    code, patches = _emit_store_marker(arch, entry_rva)
    data_code = bytes(DATA_CODE_OFF) + code
    pe = _build_pe(
        arch,
        dll_characteristics=OPT_OUT_DLL_CHARACTERISTICS,
        entry_rva=entry_rva,
        data_code=data_code,
    )

    values = {
        "out_marker": IMAGE_BASE + DATA_RVA + MARKER_OFF,
        "out_alloc": 0,
        "alloc": 0,
        "target": 0,
    }
    result = _run_pe(config, arch, pe, patches, values)
    assert result["error"] is None, result["error"]
    assert result["marker"] == EXEC_MARKER
    emu = result["emu"]
    entry_addr = IMAGE_BASE + entry_rva
    assert emu.get_address_perms(entry_addr) & common.PERM_MEM_EXEC
    # The marker page (first .data page) keeps its non-executable protection.
    assert not (emu.get_address_perms(IMAGE_BASE + DATA_RVA + MARKER_OFF) & common.PERM_MEM_EXEC)
    assert current_win_protection(emu, entry_addr) == PAGE_WRITECOPY


# ---------------------------------------------------------------------------
# Negative: NXCOMPAT=1 images keep the protected-fetch failure
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("arch", [e_arch.ARCH_X86, e_arch.ARCH_AMD64], ids=["x86", "x64"])
def test_nx_compat_writable_image_data_page_still_faults(config, arch):
    code, patches = _emit_call_image_page(arch, TEXT_RVA)
    pe = _build_pe(
        arch,
        dll_characteristics=NXCOMPAT_DLL_CHARACTERISTICS,
        text_code=code,
    )

    values = {
        "target": IMAGE_BASE + DATA_RVA + DATA_CODE_OFF,
        "out_marker": IMAGE_BASE + DATA_RVA + MARKER_OFF,
        "out_alloc": 0,
        "alloc": 0,
    }
    result = _run_pe(config, arch, pe, patches, values)
    error = result["error"]
    assert error is not None
    assert error.type == "invalid_protect_fetch"
    assert error.address == IMAGE_BASE + DATA_RVA + DATA_CODE_OFF
    assert error.access_type == "fetch"
    assert result["marker"] == 0
    assert not (result["emu"].get_address_perms(error.address) & common.PERM_MEM_EXEC)
    assert result["policy"] is not None and not result["policy"].dep_disabled


# ---------------------------------------------------------------------------
# Negative: read-only and no-access image pages keep their protection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("arch", [e_arch.ARCH_X86, e_arch.ARCH_AMD64], ids=["x86", "x64"])
def test_opt_out_readonly_rdata_fetch_still_faults(config, arch):
    code, patches = _emit_call_absolute(arch, TEXT_RVA)
    pe = _build_pe(
        arch,
        dll_characteristics=OPT_OUT_DLL_CHARACTERISTICS,
        text_code=code,
        rdata_data=b"\xC3",  # prebuilt code byte in a read-only page
    )

    values = {
        "target": IMAGE_BASE + RDATA_RVA + RDATA_PREBUILT_OFF,
        "out_marker": IMAGE_BASE + DATA_RVA + MARKER_OFF,
        "out_alloc": 0,
        "alloc": 0,
    }
    # The prebuilt byte must sit at RDATA_PREBUILT_OFF; pad the raw data.
    pe = bytearray(pe)
    pe[RDATA_RAW_PTR + RDATA_PREBUILT_OFF] = 0xC3
    result = _run_pe(config, arch, bytes(pe), patches, values)

    error = result["error"]
    assert error is not None
    assert error.type == "invalid_protect_fetch"
    assert error.address == IMAGE_BASE + RDATA_RVA + RDATA_PREBUILT_OFF
    assert error.access_type == "fetch"
    assert result["marker"] == 0
    perms = result["emu"].get_address_perms(error.address)
    assert perms is not None and perms & common.PERM_MEM_READ
    assert not (perms & common.PERM_MEM_EXEC)
    assert current_win_protection(result["emu"], error.address) == PAGE_READONLY


@pytest.mark.parametrize("arch", [e_arch.ARCH_X86, e_arch.ARCH_AMD64], ids=["x86", "x64"])
def test_opt_out_noaccess_image_page_still_faults(config, arch):
    code, patches = _emit_call_absolute(arch, TEXT_RVA)
    pe = _build_pe(
        arch,
        dll_characteristics=OPT_OUT_DLL_CHARACTERISTICS,
        text_code=code,
        rdata_chars=RDATA_NOACCESS_CHARS,
        rdata_data=b"\xC3",
    )
    pe = bytearray(pe)
    pe[RDATA_RAW_PTR + RDATA_PREBUILT_OFF] = 0xC3

    values = {
        "target": IMAGE_BASE + RDATA_RVA + RDATA_PREBUILT_OFF,
        "out_marker": IMAGE_BASE + DATA_RVA + MARKER_OFF,
        "out_alloc": 0,
        "alloc": 0,
    }
    result = _run_pe(config, arch, bytes(pe), patches, values)

    error = result["error"]
    assert error is not None
    assert error.type == "invalid_protect_fetch"
    assert error.address == IMAGE_BASE + RDATA_RVA + RDATA_PREBUILT_OFF
    assert error.access_type == "fetch"
    assert result["marker"] == 0
    perms = result["emu"].get_address_perms(error.address)
    assert perms is not None and not (perms & common.PERM_MEM_EXEC)


# ---------------------------------------------------------------------------
# Negative: the private VirtualAlloc rule is unchanged
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("arch", [e_arch.ARCH_X86, e_arch.ARCH_AMD64], ids=["x86", "x64"])
def test_opt_out_readonly_virtual_alloc_still_faults(config, arch):
    code, patches = _emit_virtual_alloc_call(arch, PAGE_READONLY, TEXT_RVA)
    pe = _build_pe(
        arch,
        dll_characteristics=OPT_OUT_DLL_CHARACTERISTICS,
        text_code=code,
    )

    se = Speakeasy(config=config, argv=[])
    try:
        module = se.load_module(data=pe)
        emu = se.emu
        stub = emu.get_proc("kernel32", "VirtualAlloc")
        assert stub is not None
        values = {
            "alloc": stub,
            "out_alloc": module.base + DATA_RVA + 0x10,
            "out_marker": module.base + DATA_RVA + MARKER_OFF,
        }
        for key, offset, width in patches:
            emu.mem_write(
                module.base + offset,
                (values[key] & ((1 << (width * 8)) - 1)).to_bytes(width, "little"),
            )
        se.run_module(module)
        report = se.get_report()
        run = report.entry_points[0]
        error = run.error
        ptr_size = 8 if arch == e_arch.ARCH_AMD64 else 4
        alloc = int.from_bytes(emu.mem_read(module.base + DATA_RVA + 0x10, ptr_size), "little")
        marker = int.from_bytes(emu.mem_read(module.base + DATA_RVA + MARKER_OFF, 4), "little")
        assert error is not None
        assert error.type == "invalid_protect_fetch"
        assert error.address == alloc
        assert error.access_type == "fetch"
        assert marker == 0
        assert current_win_protection(emu, alloc) == PAGE_READONLY
    finally:
        se.shutdown()
