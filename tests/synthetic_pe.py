"""Minimal synthetic PE images for entry-context tests (FX-019).

The builder produces a PE32 or PE32+ image with one executable ``.text``
section and one writable ``.data`` section and no imports.  Callers provide
the raw ``.text`` code emitted through :class:`CodeBuffer`; absolute 32-bit
operands are recorded as named *patches* so tests can fill in guest addresses
after the module has been loaded and mapped.

This module is test-only infrastructure; no production code imports it.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

import speakeasy.winenv.arch as e_arch

IMAGE_BASE = 0x400000
TEXT_RVA = 0x1000
DATA_RVA = 0x2000
TEXT_RAW = 0x200
DATA_RAW = 0x400


@dataclass(frozen=True)
class CodePatch:
    """One 32-bit absolute operand embedded in the generated ``.text``."""

    key: str
    offset: int  # offset from the start of ``.text``
    width: int = 4


class CodeBuffer:
    """Small instruction emitter for the fixed test code shapes."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.patches: list[CodePatch] = []

    def _imm32(self, key: str) -> None:
        self.patches.append(CodePatch(key=key, offset=len(self.buf)))
        self.buf += b"\x00\x00\x00\x00"

    def _opcode_imm32(self, opcode: bytes, key: str) -> None:
        self.buf += opcode
        self._imm32(key)

    def mov_ptr_abs_eax(self, key: str) -> None:
        """x86: ``mov dword ptr [disp32], eax`` (A3 imm32)."""
        self._opcode_imm32(b"\xA3", key)

    def mov_ptr_abs_ebx(self, key: str) -> None:
        """x86: ``mov dword ptr [disp32], ebx`` (89 1D imm32)."""
        self._opcode_imm32(b"\x89\x1D", key)

    def mov_ptr_abs_ecx(self, key: str) -> None:
        """x86: ``mov dword ptr [disp32], ecx`` (89 0D imm32)."""
        self._opcode_imm32(b"\x89\x0D", key)

    def mov_ptr_abs_ecx_x64(self, key: str) -> None:
        """x64: ``mov dword ptr [disp32], ecx`` (89 0C 25 imm32)."""
        self._opcode_imm32(b"\x89\x0C\x25", key)

    def mov_ptr_abs_edx_x64(self, key: str) -> None:
        """x64: ``mov dword ptr [disp32], edx`` (89 14 25 imm32)."""
        self._opcode_imm32(b"\x89\x14\x25", key)

    def mov_ecx_ptr_ebx_disp8(self, disp: int) -> None:
        """x86: ``mov ecx, dword ptr [ebx + disp8]`` (8B 4B disp8)."""
        if not 0 <= disp <= 0xFF:
            raise ValueError("disp must fit in one unsigned byte")
        self.buf += b"\x8B\x4B" + bytes([disp])

    def ret(self) -> None:
        """``ret`` (C3)."""
        self.buf += b"\xC3"


def build_pe(
    arch: int,
    code: bytes,
    *,
    text_vsize: int = 0x1000,
    image_size: int = 0x3000,
    data_rva: int = DATA_RVA,
) -> bytes:
    """Build a minimal PE image containing the supplied ``.text`` code.

    Args:
        arch: ``e_arch.ARCH_X86`` or ``e_arch.ARCH_AMD64``.
        code: Raw ``.text`` bytes; must fit in a 0x200-byte raw section.
        text_vsize: Virtual size of ``.text``.
        image_size: ``SizeOfImage`` recorded in the optional header.
        data_rva: Virtual address of the writable ``.data`` section.

    Raises:
        ValueError: If *arch* is unsupported or *code* is too large.
    """
    if arch not in (e_arch.ARCH_X86, e_arch.ARCH_AMD64):
        raise ValueError(f"unsupported architecture: {arch}")
    if len(code) > TEXT_RAW:
        raise ValueError("code does not fit in the synthetic .text section")

    is_64 = arch == e_arch.ARCH_AMD64
    opt_size = 0xF0 if is_64 else 0xE0
    image = bytearray(0x600)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x40)
    image[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into(
        "<HHIIIHH",
        image,
        0x44,
        0x8664 if is_64 else 0x14C,
        2,
        0,
        0,
        0,
        opt_size,
        0x0022 if is_64 else 0x0102,
    )

    opt = 0x58
    struct.pack_into("<H", image, opt, 0x20B if is_64 else 0x10B)
    struct.pack_into("<BB", image, opt + 2, 1, 0)  # linker major/minor
    struct.pack_into("<I", image, opt + 4, TEXT_RAW)  # SizeOfCode
    struct.pack_into("<I", image, opt + 8, TEXT_RAW)  # SizeOfInitializedData
    struct.pack_into("<I", image, opt + 16, TEXT_RVA)  # AddressOfEntryPoint
    struct.pack_into("<I", image, opt + 20, TEXT_RVA)  # BaseOfCode

    if is_64:
        struct.pack_into("<Q", image, opt + 24, IMAGE_BASE)
        struct.pack_into("<I", image, opt + 32, 0x1000)  # SectionAlignment
        struct.pack_into("<I", image, opt + 36, 0x200)  # FileAlignment
        struct.pack_into("<HH", image, opt + 40, 6, 0)  # OS version
        struct.pack_into("<HH", image, opt + 44, 0, 0)  # image version
        struct.pack_into("<HH", image, opt + 48, 6, 0)  # subsystem version
        struct.pack_into("<I", image, opt + 52, 0)  # Win32VersionValue
        struct.pack_into("<I", image, opt + 56, image_size)
        struct.pack_into("<I", image, opt + 60, TEXT_RAW)  # SizeOfHeaders
        struct.pack_into("<I", image, opt + 64, 0)  # CheckSum
        struct.pack_into("<HH", image, opt + 68, 3, 0)  # subsystem
        struct.pack_into("<QQ", image, opt + 72, 0x100000, 0x1000)
        struct.pack_into("<QQ", image, opt + 88, 0x100000, 0x1000)
        struct.pack_into("<I", image, opt + 104, 0)  # LoaderFlags
        struct.pack_into("<I", image, opt + 108, 16)  # NumberOfRvaAndSizes
    else:
        struct.pack_into("<I", image, opt + 24, data_rva)  # BaseOfData
        struct.pack_into("<I", image, opt + 28, IMAGE_BASE)
        struct.pack_into("<I", image, opt + 32, 0x1000)
        struct.pack_into("<I", image, opt + 36, 0x200)
        struct.pack_into("<HH", image, opt + 40, 6, 0)
        struct.pack_into("<HH", image, opt + 44, 0, 0)
        struct.pack_into("<HH", image, opt + 48, 6, 0)
        struct.pack_into("<I", image, opt + 52, 0)
        struct.pack_into("<I", image, opt + 56, image_size)
        struct.pack_into("<I", image, opt + 60, TEXT_RAW)
        struct.pack_into("<I", image, opt + 64, 0)
        struct.pack_into("<HH", image, opt + 68, 3, 0)
        struct.pack_into("<II", image, opt + 72, 0x100000, 0x1000)
        struct.pack_into("<II", image, opt + 80, 0x100000, 0x1000)
        struct.pack_into("<I", image, opt + 88, 0)
        struct.pack_into("<I", image, opt + 92, 16)

    section_table = opt + opt_size

    def section(
        index: int,
        name: bytes,
        vsize: int,
        vaddr: int,
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
            vaddr,
            raw_size,
            raw_ptr,
            0,
            0,
            0,
            0,
            chars,
        )

    section(0, b".text", text_vsize, TEXT_RVA, TEXT_RAW, TEXT_RAW, 0x60000020)
    section(1, b".data", 0x1000, data_rva, TEXT_RAW, DATA_RAW, 0xC0000040)
    image[TEXT_RAW : TEXT_RAW + len(code)] = code
    return bytes(image)


def apply_patches(emu, module, patches: list[CodePatch], values: dict[str, int]) -> None:
    """Write the named 32-bit patch values into the mapped ``.text`` section.

    Args:
        emu: The Speakeasy emulator exposing ``mem_write``.
        module: The loaded module (``module.base`` is the image base).
        patches: Patch records produced by :class:`CodeBuffer`.
        values: Map of patch key to guest value.
    """
    for patch in patches:
        value = values[patch.key]
        mask = (1 << (patch.width * 8)) - 1
        emu.mem_write(
            module.base + TEXT_RVA + patch.offset,
            (value & mask).to_bytes(patch.width, "little"),
        )
