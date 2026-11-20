"""Contract tests for dispatching illegal instructions (#UD) to guest SEH (FX-002).

Windows and Wine raise ``STATUS_ILLEGAL_INSTRUCTION`` (0xC000001D) when the CPU
decodes an undefined opcode and deliver it through the guest exception chain.
The samples in this FX (``0F 3F 07 0B`` / ``vpcext`` probes) install an inline
x86 SEH frame whose handler stores the exception code, writes
``CONTEXT.Ebx = -1`` and advances ``CONTEXT.Eip`` past the illegal opcode.

The tests freeze that contract with a synthetic PE32:

* positive: an inline SEH handler receives 0xC000001D, its CONTEXT edits are
  applied on continuation and the instruction after the illegal opcode runs;
* negative: the same illegal opcode without a handler, and with
  ``dispatch_handlers`` disabled, still terminates with the original
  ``Invalid instruction (UC_ERR_INSN_INVALID)`` error;
* safety: a handler that does not advance Eip terminates via
  ``_SEH_MAX_REPEAT`` instead of re-executing forever.
"""

from __future__ import annotations

import struct

from speakeasy import Speakeasy

IMAGE_BASE = 0x400000
TEXT_RVA = 0x1000
DATA_RVA = 0x2000

ENTRY_VA = IMAGE_BASE + TEXT_RVA
OUT_EXEC_VA = IMAGE_BASE + DATA_RVA
OUT_EBX_VA = OUT_EXEC_VA + 4
OUT_CODE_VA = OUT_EXEC_VA + 8
OUT_COUNT_VA = OUT_EXEC_VA + 12

ILLEGAL_OPCODE = bytes.fromhex("0F3F070B")
ILLEGAL_VA_NO_SEH = ENTRY_VA + 5  # mov eax, 1 precedes it
ILLEGAL_VA_WITH_SEH = ENTRY_VA + 24  # SEH install (5+7+7) + mov eax, 1
STATUS_ILLEGAL_INSTRUCTION = 0xC000001D
EXEC_MARKER = 0x600D600D


def _u32(value: int) -> bytes:
    return struct.pack("<I", value)


def _handler_bytes(*, advance_eip: bool) -> bytes:
    """Inline SEH handler: record the code, edit CONTEXT, return 0."""
    code = bytearray()
    if advance_eip:
        code += b"\x8B\x54\x24\x04"  # mov edx, [esp+4]   ; ExceptionRecord
        code += b"\x8B\x12"  # mov edx, [edx]     ; ExceptionCode
        code += b"\x89\x15" + _u32(OUT_CODE_VA)
        code += b"\x8B\x4C\x24\x0C"  # mov ecx, [esp+0xC] ; ContextRecord
        code += b"\xC7\x81" + _u32(0xA4) + _u32(0xFFFFFFFF)  # CONTEXT.Ebx = -1
        code += b"\x83\x81" + _u32(0xB8) + b"\x04"  # CONTEXT.Eip += 4
    else:
        code += b"\x8B\x15" + _u32(OUT_COUNT_VA)  # mov edx, [out_count]
        code += b"\x83\xC2\x01"  # add edx, 1
        code += b"\x89\x15" + _u32(OUT_COUNT_VA)  # mov [out_count], edx
        code += b"\x8B\x4C\x24\x0C"  # mov ecx, [esp+0xC]
        code += b"\xC7\x81" + _u32(0xA4) + _u32(0xFFFFFFFF)  # CONTEXT.Ebx = -1
    code += b"\x31\xC0"  # xor eax, eax (EXCEPTION_CONTINUE_SEARCH)
    code += b"\xC3"  # ret
    return bytes(code)


def _build_text(*, seh: bool, advance_eip: bool = True, loop_iterations: int = 0) -> bytes:
    """Assemble the entry point and optional inline SEH handler.

    ``seh=False`` reproduces the negative case: the illegal opcode is executed
    without any registered handler.  ``advance_eip=False`` installs a handler
    that modifies CONTEXT.Ebx but never advances Eip, exercising the repeat
    guard.  ``loop_iterations>0`` re-executes the same illegal instruction PC
    from a counted loop.
    """
    code = bytearray()

    if seh:
        # push handler (patched below); push fs:[0]; mov fs:[0], esp
        code += b"\x68" + _u32(0xDEADBEEF)
        code += bytes.fromhex("64FF3500000000")
        code += bytes.fromhex("64892500000000")
    if loop_iterations:
        code += b"\xB9" + _u32(loop_iterations)  # mov ecx, iterations
        loop_start = len(code)
    code += b"\xB8\x01\x00\x00\x00"  # mov eax, 1 (anti-VM probe setup)
    code += ILLEGAL_OPCODE

    if loop_iterations:
        code += b"\xFF\x05" + _u32(OUT_COUNT_VA)  # inc dword [out_count]
        code += b"\x49"  # dec ecx
        jnz_pos = len(code)
        code += b"\x75\x00"  # jnz loop_start (patched)
        code[jnz_pos + 1] = (loop_start - (jnz_pos + 2)) & 0xFF
    else:
        code += b"\xC7\x05" + _u32(OUT_EXEC_VA) + _u32(EXEC_MARKER)
        code += b"\x89\x1D" + _u32(OUT_EBX_VA)  # mov [out_ebx], ebx
    if seh:
        code += b"\x59"  # pop ecx (drop handler)
        code += bytes.fromhex("648F0500000000")  # pop dword fs:[0]
    code += b"\xC3"  # ret

    if not seh:
        return bytes(code)

    handler_offset = len(code)
    code += _handler_bytes(advance_eip=advance_eip)

    handler_va = ENTRY_VA + handler_offset
    struct.pack_into("<I", code, 1, handler_va)
    return bytes(code)


def _build_pe(*, seh: bool, advance_eip: bool = True, loop_iterations: int = 0) -> bytes:
    """Build a minimal PE32 with a .text section and a writable .data section."""
    image = bytearray(0x600)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x40)
    image[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", image, 0x44, 0x14C, 2, 0, 0, 0, 0xE0, 0x0102)

    offset = 0x58

    def put(fmt: str, *values: int) -> None:
        nonlocal offset
        struct.pack_into(fmt, image, offset, *values)
        offset += struct.calcsize(fmt)

    put("<H", 0x10B)  # PE32
    put("<BB", 1, 0)
    put("<I", 0x200)  # SizeOfCode
    put("<I", 0x200)  # SizeOfInitializedData
    put("<I", 0)  # SizeOfUninitializedData
    put("<I", TEXT_RVA)  # AddressOfEntryPoint
    put("<I", TEXT_RVA)  # BaseOfCode
    put("<I", DATA_RVA)  # BaseOfData
    put("<I", IMAGE_BASE)
    put("<I", 0x1000)  # SectionAlignment
    put("<I", 0x200)  # FileAlignment
    put("<HH", 6, 0)
    put("<HH", 0, 0)
    put("<HH", 6, 1)
    put("<I", 0)
    put("<I", 0x3000)  # SizeOfImage
    put("<I", 0x200)  # SizeOfHeaders
    put("<I", 0)
    put("<HH", 3, 0)  # console subsystem
    put("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)
    put("<II", 0, 16)
    for _ in range(16):
        put("<II", 0, 0)
    assert offset == 0x58 + 0xE0

    section_offset = 0x138

    def section(
        name: bytes,
        virtual_size: int,
        virtual_address: int,
        raw_size: int,
        raw_pointer: int,
        characteristics: int,
    ) -> None:
        nonlocal section_offset
        image[section_offset : section_offset + 8] = name.ljust(8, b"\x00")
        struct.pack_into(
            "<IIIIIIHHI",
            image,
            section_offset + 8,
            virtual_size,
            virtual_address,
            raw_size,
            raw_pointer,
            0,
            0,
            0,
            0,
            characteristics,
        )
        section_offset += 40

    section(b".text", 0x1000, TEXT_RVA, 0x200, 0x200, 0x60000020)
    section(b".data", 0x1000, DATA_RVA, 0x200, 0x400, 0xC0000040)

    text = _build_text(seh=seh, advance_eip=advance_eip, loop_iterations=loop_iterations)
    assert len(text) <= 0x200
    image[0x200 : 0x200 + len(text)] = text
    return bytes(image)


def _run_pe(config, pe_bytes):
    se = Speakeasy(config=config, argv=[])
    try:
        module = se.load_module(data=pe_bytes)
        se.run_module(module, all_entrypoints=True)
        report = se.get_report()
        emu = se.emu
        values = {
            name: int.from_bytes(emu.mem_read(va, 4), "little")
            for name, va in (
                ("exec", OUT_EXEC_VA),
                ("ebx", OUT_EBX_VA),
                ("code", OUT_CODE_VA),
                ("count", OUT_COUNT_VA),
            )
        }
        return report, values
    finally:
        se.shutdown()


def test_illegal_instruction_is_dispatched_to_inline_seh(config):
    cfg = config
    cfg["exceptions"]["dispatch_handlers"] = True

    report, values = _run_pe(cfg, _build_pe(seh=True))

    entry = report.entry_points[0]
    assert entry.error is None, entry.error
    # The handler saw the Windows #UD status code.
    assert values["code"] == STATUS_ILLEGAL_INSTRUCTION
    # CONTEXT.Ebx = -1 was applied when the handler context was reloaded.
    assert values["ebx"] == 0xFFFFFFFF
    # CONTEXT.Eip += 4 resumed after the illegal opcode.
    assert values["exec"] == EXEC_MARKER


def test_illegal_instruction_without_seh_keeps_original_error(config):
    cfg = config
    cfg["exceptions"]["dispatch_handlers"] = True

    report, values = _run_pe(cfg, _build_pe(seh=False))

    entry = report.entry_points[0]
    assert entry.error is not None
    assert entry.error.type == "Invalid instruction (UC_ERR_INSN_INVALID)"
    assert entry.error.pc == ILLEGAL_VA_NO_SEH
    assert entry.error.address == ILLEGAL_VA_NO_SEH
    # The instruction after the illegal opcode must not have executed.
    assert values["exec"] == 0
    assert values["code"] == 0


def test_illegal_instruction_dispatch_disabled_keeps_original_error(config):
    cfg = config
    cfg["exceptions"]["dispatch_handlers"] = False

    report, values = _run_pe(cfg, _build_pe(seh=True))

    entry = report.entry_points[0]
    assert entry.error is not None
    assert entry.error.type == "Invalid instruction (UC_ERR_INSN_INVALID)"
    assert entry.error.pc == ILLEGAL_VA_WITH_SEH
    assert values["code"] == 0
    assert values["exec"] == 0


def test_repeated_illegal_instruction_at_same_pc_is_dispatched_each_time(config):
    cfg = config
    cfg["exceptions"]["dispatch_handlers"] = True

    report, values = _run_pe(cfg, _build_pe(seh=True, loop_iterations=6))

    entry = report.entry_points[0]
    assert entry.error is None, entry.error
    # Every iteration faults at the same PC and is delivered to the handler.
    assert values["count"] == 6
    assert values["code"] == STATUS_ILLEGAL_INSTRUCTION


def test_handler_that_does_not_advance_eip_stops_after_repeat_guard(config):
    cfg = config
    cfg["exceptions"]["dispatch_handlers"] = True

    report, values = _run_pe(cfg, _build_pe(seh=True, advance_eip=False))

    entry = report.entry_points[0]
    assert entry.error is not None
    assert entry.error.type == "Invalid instruction (UC_ERR_INSN_INVALID)"
    # The handler ran, but the repeated fault tripped _SEH_MAX_REPEAT (4).
    assert values["count"] == 1 + (4 - 1)
    assert values["exec"] == 0
