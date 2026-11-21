"""Contract tests for image DEP opt-out (FX-003-004-extended).

``MemoryProtection / dep_opt_out``: a PE whose Optional Header
``DllCharacteristics`` does not set ``IMAGE_DLLCHARACTERISTICS_NX_COMPAT``
(``DllCharacteristics=0``) is an explicit DEP opt-out.  Windows/Wine then run
the process without no-exec enforcement: Wine's loader calls
``NtSetInformationProcess(ProcessExecuteFlags, MEM_EXECUTE_OPTION_ENABLE)``
(``dlls/ntdll/loader.c:1585-1591``) and ``mprotect_exec`` adds ``PROT_EXEC`` to
readable views (``dlls/ntdll/unix/virtual.c:1647-1659``).  Speakeasy did not
model that policy, so the packed-loader samples (PE32, DllCharacteristics=0)
stopped with ``invalid_protect_fetch`` on the ``PAGE_READWRITE`` page returned
by ``VirtualAlloc`` before their loader loop could run.

These tests build minimal PE32/PE32+ images whose entry point calls the real
``kernel32.VirtualAlloc`` handler, writes ``ret`` into the returned page, and
executes it:

* opt-out (DllCharacteristics=0) + PAGE_READWRITE: execution succeeds;
* NXCOMPAT set (DllCharacteristics=0x8140): the same execution still records
  ``invalid_protect_fetch`` at the allocation;
* opt-out + PAGE_READONLY: execution still faults (only writable pages are
  relaxed; ``.rdata``/resource/read-only protections are untouched);
* after an opt-out grant the recorded Win32 protection stays PAGE_READWRITE,
  so the relaxation is not a global RWX conversion visible to VirtualQuery.

No sample SHA, no failure address, and no environment variable participates in
the decision: the policy comes from the PE header of the process image.
"""

from __future__ import annotations

import struct

import pytest

import speakeasy.common as common
from speakeasy import Speakeasy
from speakeasy.windows.dep_policy import (
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
    ImageDepPolicy,
    dep_opt_out,
    policy_from_dll_characteristics,
)
from speakeasy.windows.page_protection import current_win_protection
from speakeasy.winenv import arch as e_arch

IMAGE_BASE = 0x400000
TEXT_RVA = 0x1000
DATA_RVA = 0x2000
IMAGE_SIZE = 0x3000
TEXT_RAW = 0x200
DATA_RAW = 0x400

DATA_OUT_ALLOC = 0x00
DATA_OUT_MARKER = 0x08
EXEC_MARKER = 0x600D600D

PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
MEM_COMMIT_RESERVE = 0x3000

NXCOMPAT_DLL_CHARACTERISTICS = 0x8140
OPT_OUT_DLL_CHARACTERISTICS = 0x0000


# ---------------------------------------------------------------------------
# Minimal PE32 / PE32+ image builder
# ---------------------------------------------------------------------------


def _build_pe(arch: int, *, dll_characteristics: int, code: bytes) -> bytes:
    """Build a minimal PE32/PE32+ with .text code and a writable .data slot page.

    No import directory is used: the tests patch ``kernel32.VirtualAlloc``'s
    import-sentinel address directly into the emitted code after loading.
    """
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
        2,  # NumberOfSections
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
    struct.pack_into("<I", image, opt + 8, TEXT_RAW)  # SizeOfInitializedData
    struct.pack_into("<I", image, opt + 12, 0)  # SizeOfUninitializedData
    struct.pack_into("<I", image, opt + 16, TEXT_RVA)  # AddressOfEntryPoint
    struct.pack_into("<I", image, opt + 20, TEXT_RVA)  # BaseOfCode
    if is_64:
        struct.pack_into("<Q", image, opt + 24, IMAGE_BASE)
        struct.pack_into("<I", image, opt + 32, 0x1000)  # SectionAlignment
        struct.pack_into("<I", image, opt + 36, 0x200)  # FileAlignment
        struct.pack_into("<HH", image, opt + 40, 6, 0)  # OS version
        struct.pack_into("<HH", image, opt + 44, 0, 0)  # Image version
        struct.pack_into("<HH", image, opt + 48, 6, 0)  # Subsystem version
        struct.pack_into("<I", image, opt + 52, 0)  # Win32VersionValue
        struct.pack_into("<I", image, opt + 56, IMAGE_SIZE)  # SizeOfImage
        struct.pack_into("<I", image, opt + 60, TEXT_RAW)  # SizeOfHeaders
        struct.pack_into("<I", image, opt + 64, 0)  # CheckSum
        struct.pack_into("<HH", image, opt + 68, 3, dll_characteristics)
        struct.pack_into("<QQ", image, opt + 72, 0x100000, 0x1000)  # stack
        struct.pack_into("<QQ", image, opt + 88, 0x100000, 0x1000)  # heap
        struct.pack_into("<I", image, opt + 104, 0)  # LoaderFlags
        struct.pack_into("<I", image, opt + 108, 16)  # NumberOfRvaAndSizes
        assert opt + 112 + 16 * 8 == opt + opt_size
    else:
        struct.pack_into("<I", image, opt + 24, DATA_RVA)  # BaseOfData
        struct.pack_into("<I", image, opt + 28, IMAGE_BASE)
        struct.pack_into("<I", image, opt + 32, 0x1000)  # SectionAlignment
        struct.pack_into("<I", image, opt + 36, 0x200)  # FileAlignment
        struct.pack_into("<HH", image, opt + 40, 6, 0)  # OS version
        struct.pack_into("<HH", image, opt + 44, 0, 0)  # Image version
        struct.pack_into("<HH", image, opt + 48, 6, 0)  # Subsystem version
        struct.pack_into("<I", image, opt + 52, 0)  # Win32VersionValue
        struct.pack_into("<I", image, opt + 56, IMAGE_SIZE)  # SizeOfImage
        struct.pack_into("<I", image, opt + 60, TEXT_RAW)  # SizeOfHeaders
        struct.pack_into("<I", image, opt + 64, 0)  # CheckSum
        struct.pack_into("<HH", image, opt + 68, 3, dll_characteristics)
        struct.pack_into("<II", image, opt + 72, 0x100000, 0x1000)  # stack
        struct.pack_into("<II", image, opt + 80, 0x100000, 0x1000)  # heap
        struct.pack_into("<I", image, opt + 88, 0)  # LoaderFlags
        struct.pack_into("<I", image, opt + 92, 16)  # NumberOfRvaAndSizes
        assert opt + 96 + 16 * 8 == opt + opt_size

    section_table = opt + opt_size

    def section(index: int, name: bytes, vsize: int, rva: int, raw_size: int, raw_ptr: int, chars: int) -> None:
        off = section_table + index * 40
        image[off : off + 8] = name.ljust(8, b"\x00")
        struct.pack_into("<IIIIIIHHI", image, off + 8, vsize, rva, raw_size, raw_ptr, 0, 0, 0, 0, chars)

    section(0, b".text", 0x1000, TEXT_RVA, TEXT_RAW, TEXT_RAW, 0x60000020)
    section(1, b".data", 0x1000, DATA_RVA, TEXT_RAW, DATA_RAW, 0xC0000040)

    assert len(code) <= TEXT_RAW, hex(len(code))
    image[TEXT_RAW : TEXT_RAW + len(code)] = code
    return bytes(image)


# ---------------------------------------------------------------------------
# Guest entry code
# ---------------------------------------------------------------------------


def _emit_x86(protect: int, *, write_code: bool) -> tuple[bytes, list[tuple[str, int, int]]]:
    """x86 entry: VirtualAlloc, optionally write ret and call the page.

    Returns ``(code, patches)``; patch entries are ``(key, offset, size)``.
    """
    buf = bytearray()
    patches: list[tuple[str, int, int]] = []

    buf += b"\x68" + struct.pack("<I", protect)  # push protect
    buf += b"\x68" + struct.pack("<I", MEM_COMMIT_RESERVE)  # push type
    buf += b"\x68" + struct.pack("<I", 0x1000)  # push size
    buf += b"\x6A\x00"  # push 0 (lpAddress)
    buf += b"\xB8"
    patches.append(("alloc", len(buf), 4))
    buf += b"\x00\x00\x00\x00"  # mov eax, VirtualAlloc stub
    buf += b"\xFF\xD0"  # call eax
    buf += b"\xA3"
    patches.append(("out_alloc", len(buf), 4))
    buf += b"\x00\x00\x00\x00"  # mov [out_alloc], eax
    if write_code:
        buf += b"\xC6\x00\xC3"  # mov byte ptr [eax], 0xC3 (ret)
    buf += b"\xFF\xD0"  # call eax (execute the allocation)
    buf += b"\xC7\x05"
    patches.append(("out_marker", len(buf), 4))
    buf += b"\x00\x00\x00\x00"
    buf += struct.pack("<I", EXEC_MARKER)  # mov dword ptr [out_marker], marker
    buf += b"\xC3"  # ret
    return bytes(buf), patches


def _emit_x64(protect: int, *, write_code: bool) -> tuple[bytes, list[tuple[str, int, int]]]:
    """x64 entry: VirtualAlloc, optionally write ret and call the page."""
    buf = bytearray()
    patches: list[tuple[str, int, int]] = []

    # Win64 ABI: reserve 0x28 bytes (0x20 shadow + alignment) before calls.
    buf += b"\x48\x83\xEC\x28"  # sub rsp, 0x28
    buf += b"\x31\xC9"  # xor ecx, ecx
    buf += b"\x48\xC7\xC2" + struct.pack("<I", 0x1000)  # mov rdx, 0x1000
    buf += b"\x49\xC7\xC0" + struct.pack("<I", MEM_COMMIT_RESERVE)  # mov r8, 0x3000
    buf += b"\x41\xB9" + struct.pack("<I", protect)  # mov r9d, protect
    buf += b"\x48\xB8"
    patches.append(("alloc", len(buf), 8))
    buf += b"\x00" * 8  # mov rax, VirtualAlloc stub
    buf += b"\xFF\xD0"  # call rax
    buf += b"\x48\x89\xC3"  # mov rbx, rax
    buf += b"\x48\xB8"
    patches.append(("out_alloc", len(buf), 8))
    buf += b"\x00" * 8  # mov rax, out_alloc
    buf += b"\x48\x89\x18"  # mov [rax], rbx
    if write_code:
        buf += b"\xC6\x03\xC3"  # mov byte ptr [rbx], 0xC3 (ret)
    buf += b"\x48\x89\xD8"  # mov rax, rbx
    buf += b"\xFF\xD0"  # call rax (execute the allocation)
    buf += b"\x48\xB8"
    patches.append(("out_marker", len(buf), 8))
    buf += b"\x00" * 8  # mov rax, out_marker
    buf += b"\xC7\x00" + struct.pack("<I", EXEC_MARKER)  # mov dword ptr [rax], marker
    buf += b"\x48\x83\xC4\x28"  # add rsp, 0x28
    buf += b"\xC3"  # ret
    return bytes(buf), patches


# ---------------------------------------------------------------------------
# Execution harness
# ---------------------------------------------------------------------------


def _run_pe(config, arch: int, *, dll_characteristics: int, protect: int, write_code: bool):
    is_64 = arch == e_arch.ARCH_AMD64
    emit = _emit_x64 if is_64 else _emit_x86
    code, patches = emit(protect, write_code=write_code)
    pe = _build_pe(arch, dll_characteristics=dll_characteristics, code=code)

    se = Speakeasy(config=config, argv=[])
    try:
        module = se.load_module(data=pe)
        emu = se.emu
        assert module.base == IMAGE_BASE, hex(module.base)
        stub = emu.get_proc("kernel32", "VirtualAlloc")
        assert stub is not None
        values = {
            "alloc": stub,
            "out_alloc": module.base + DATA_RVA + DATA_OUT_ALLOC,
            "out_marker": module.base + DATA_RVA + DATA_OUT_MARKER,
        }
        for key, offset, size in patches:
            emu.mem_write(
                module.base + TEXT_RVA + offset,
                (values[key] & ((1 << (size * 8)) - 1)).to_bytes(size, "little"),
            )

        se.run_module(module)
        report = se.get_report()
        run = report.entry_points[0] if report.entry_points else None
        error = getattr(run, "error", None) if run is not None else "no entry point"

        ptr_size = 8 if is_64 else 4
        alloc = int.from_bytes(emu.mem_read(module.base + DATA_RVA + DATA_OUT_ALLOC, ptr_size), "little")
        marker = int.from_bytes(emu.mem_read(module.base + DATA_RVA + DATA_OUT_MARKER, 4), "little")
        perms = emu.get_address_perms(alloc) if alloc else None
        win_protect = current_win_protection(emu, alloc) if alloc else None
        module_policy = module.get_dep_policy()
        return {
            "error": error,
            "alloc": alloc,
            "marker": marker,
            "perms": perms,
            "win_protect": win_protect,
            "policy": module_policy,
        }
    finally:
        se.shutdown()


# ---------------------------------------------------------------------------
# Policy unit tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected_opt_out"),
    [
        (0x0000, True),
        (0x0040, True),  # DYNAMIC_BASE only: NXCOMPAT still clear
        (0x0100, False),  # NXCOMPAT set
        (0x8140, False),  # typical NXCOMPAT image
    ],
)
def test_dep_policy_reads_nxcompat_bit(value: int, expected_opt_out: bool) -> None:
    policy = policy_from_dll_characteristics(value)
    assert isinstance(policy, ImageDepPolicy)
    assert policy.dll_characteristics == value
    assert policy.nx_compat is (not expected_opt_out)
    assert policy.dep_disabled is expected_opt_out
    assert dep_opt_out(policy) is expected_opt_out


def test_dep_policy_unknown_header_keeps_dep_enabled() -> None:
    assert policy_from_dll_characteristics(None) is None
    assert dep_opt_out(None) is False


def test_nxcompat_constant_matches_pe_header_bit() -> None:
    assert IMAGE_DLLCHARACTERISTICS_NX_COMPAT == 0x0100
    assert NXCOMPAT_DLL_CHARACTERISTICS & IMAGE_DLLCHARACTERISTICS_NX_COMPAT
    assert not (OPT_OUT_DLL_CHARACTERISTICS & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)


# ---------------------------------------------------------------------------
# Positive: explicit DEP opt-out allows execution from a writable allocation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("arch", [e_arch.ARCH_X86, e_arch.ARCH_AMD64], ids=["x86", "x64"])
def test_opt_out_rw_allocation_executes(config, arch):
    result = _run_pe(
        config,
        arch,
        dll_characteristics=OPT_OUT_DLL_CHARACTERISTICS,
        protect=PAGE_READWRITE,
        write_code=True,
    )

    assert result["error"] is None, result["error"]
    assert result["alloc"], "VirtualAlloc returned no allocation"
    assert result["marker"] == EXEC_MARKER
    assert result["policy"] is not None and result["policy"].dep_disabled
    # The page gained executable permission internally...
    assert result["perms"] is not None and result["perms"] & common.PERM_MEM_EXEC
    # ...but the Win32 protection the guest observes is still PAGE_READWRITE.
    assert result["win_protect"] == PAGE_READWRITE


# ---------------------------------------------------------------------------
# Negative: NXCOMPAT=1 images keep the protected-fetch failure
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("arch", [e_arch.ARCH_X86, e_arch.ARCH_AMD64], ids=["x86", "x64"])
def test_nx_compat_rw_allocation_still_faults(config, arch):
    result = _run_pe(
        config,
        arch,
        dll_characteristics=NXCOMPAT_DLL_CHARACTERISTICS,
        protect=PAGE_READWRITE,
        write_code=True,
    )

    error = result["error"]
    assert error is not None
    assert error.type == "invalid_protect_fetch"
    assert error.address == result["alloc"]
    assert error.access_type == "fetch"
    assert result["marker"] == 0
    assert result["policy"] is not None and not result["policy"].dep_disabled


# ---------------------------------------------------------------------------
# Negative: opt-out does not make read-only pages executable
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("arch", [e_arch.ARCH_X86, e_arch.ARCH_AMD64], ids=["x86", "x64"])
def test_opt_out_readonly_allocation_still_faults(config, arch):
    result = _run_pe(
        config,
        arch,
        dll_characteristics=OPT_OUT_DLL_CHARACTERISTICS,
        protect=PAGE_READONLY,
        write_code=False,
    )

    error = result["error"]
    assert error is not None
    assert error.type == "invalid_protect_fetch"
    assert error.address == result["alloc"]
    assert error.access_type == "fetch"
    assert result["marker"] == 0
    assert result["win_protect"] == PAGE_READONLY


# ---------------------------------------------------------------------------
# DEP is a process policy, not an exception-dispatch policy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("arch", [e_arch.ARCH_X86, e_arch.ARCH_AMD64], ids=["x86", "x64"])
def test_opt_out_rw_execution_without_exception_dispatch(config, arch):
    config["exceptions"]["dispatch_handlers"] = False
    result = _run_pe(
        config,
        arch,
        dll_characteristics=OPT_OUT_DLL_CHARACTERISTICS,
        protect=PAGE_READWRITE,
        write_code=True,
    )

    assert result["error"] is None, result["error"]
    assert result["marker"] == EXEC_MARKER
