"""Contract tests for VirtualProtect page ranges and image write-copy (FX-004).

``MemoryProtection / image_page_cow`` covers two defects that are distinct from
the FX-003 exception-dispatch gap:

* ``VirtualProtect(lpAddress, dwSize, ...)`` must protect the pages covering
  ``[lpAddress, lpAddress+dwSize)``.  The old implementation rounded the size
  without the low 12 bits of ``lpAddress`` (``0x400780 + 0x2000`` touched two
  pages instead of three) and assigned ``MemMap.prot`` for the whole containing
  map, so unrelated pages of the same map inherited the new protection.
* Writable image pages are file-backed and are reported by Windows/Wine as
  ``PAGE_WRITECOPY`` / ``PAGE_EXECUTE_WRITECOPY``.  Wine's image mapping sets
  ``VPROT_WRITECOPY`` for ``IMAGE_SCN_MEM_WRITE`` sections only
  (``dlls/ntdll/unix/virtual.c:3004-3008``); an explicit
  ``VirtualProtect(PAGE_READONLY)`` maps to ``VPROT_READ`` and removes write
  permission (``virtual.c:1602-1635`` and ``set_protection``).  COW must not be
  used as a way around an explicit read-only request.

The tests freeze the contract at the API level: x86 shellcode drives the real
kernel32 handlers on a private VirtualAlloc region, and a synthetic PE32 with a
writable image ``.data`` page exercises the image write-copy path.  The Wine
semantics are taken from the read-only Wine source tree; no Wine process and no
batch sample is executed here.
"""

from __future__ import annotations

import struct

import pytest

from speakeasy import Speakeasy, common
from speakeasy.memmgr import MemMap, MemoryManager
from speakeasy.profiler_events import ApiEvent, EventType
from speakeasy.windows import page_protection
from speakeasy.windows.page_protection import (
    apply_page_protection,
    emu_perms_to_win_protect,
    image_protection_for_emu_perms,
    page_span,
    win_protect_to_emu_perms,
)
from speakeasy.windows.winemu import get_page_protection_runs
from speakeasy.winenv.defs.enums import PAGE_PROTECTION_FLAGS
from speakeasy.winenv.defs.nt import ddk
from speakeasy.winenv.defs.windows import windows as windefs
from tests.guest_harness import Deref, get_api, guest_call, read_pointer
from tests.handler_harness import alloc, call, start_process

PAGE = 0x1000
RX = common.PERM_MEM_RX
RW = common.PERM_MEM_RW


PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000

STATUS_ACCESS_VIOLATION = 0xC0000005
EXEC_MARKER = 0x600D600D
WRITTEN_INITIAL = 0x41424344
WRITTEN_AFTER_RW = 0x11223344
BLOCKED_WRITE = 0xDEADBEEF
MBI_SIZE = 28
MBI_PROTECT_OFFSET = 20


class _Asm:
    """Small x86 emitter with absolute fixups resolved after loading."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.patches: list[list] = []

    def imm32(self, key: str, addend: int = 0) -> None:
        offset = len(self.buf)
        self.buf += b"\x00\x00\x00\x00"
        self.patches.append([offset, key, addend])

    def push_imm8(self, value: int) -> None:
        self.buf += bytes((0x6A, value & 0xFF))

    def push_imm32(self, value: int) -> None:
        self.buf += b"\x68" + struct.pack("<I", value & 0xFFFFFFFF)

    def push_abs(self, key: str, addend: int = 0) -> None:
        self.buf += b"\x68"
        self.imm32(key, addend)

    def push_eax(self) -> None:
        self.buf += b"\x50"

    def mov_eax_abs(self, key: str, addend: int = 0) -> None:
        self.buf += b"\xb8"
        self.imm32(key, addend)

    def mov_eax_imm(self, value: int) -> None:
        self.buf += b"\xb8" + struct.pack("<I", value & 0xFFFFFFFF)

    def mov_eax_ptr_abs(self, key: str, addend: int = 0) -> None:
        self.buf += b"\x8b\x05"
        self.imm32(key, addend)

    def mov_eax_ptr_imm32(self, value: int) -> None:
        self.buf += b"\x8b\x05" + struct.pack("<I", value & 0xFFFFFFFF)

    def mov_ptr_abs_eax(self, key: str, addend: int = 0) -> None:
        self.buf += b"\x89\x05"
        self.imm32(key, addend)

    def mov_ptr_abs_imm32(self, key: str, value: int, addend: int = 0) -> None:
        self.buf += b"\xc7\x05"
        self.imm32(key, addend)
        self.buf += struct.pack("<I", value & 0xFFFFFFFF)

    def mov_ptr_eax_imm32(self, value: int) -> None:
        self.buf += b"\xc7\x00" + struct.pack("<I", value & 0xFFFFFFFF)

    def add_eax_imm32(self, value: int) -> None:
        self.buf += b"\x05" + struct.pack("<I", value & 0xFFFFFFFF)

    def add_ptr_ecx_imm8(self, disp: int, value: int) -> None:
        self.buf += b"\x83\x81" + struct.pack("<I", disp) + bytes((value & 0xFF,))

    def inc_ptr_abs(self, key: str, addend: int = 0) -> None:
        self.buf += b"\xff\x05"
        self.imm32(key, addend)

    def call_eax(self) -> None:
        self.buf += b"\xff\xd0"

    def xor_eax(self) -> None:
        self.buf += b"\x31\xc0"

    def ret(self) -> None:
        self.buf += b"\xc3"

    def push_fs0(self) -> None:
        self.buf += bytes.fromhex("64FF3500000000")

    def mov_fs0_esp(self) -> None:
        self.buf += bytes.fromhex("64892500000000")

    def pop_fs0(self) -> None:
        self.buf += bytes.fromhex("648F0500000000")

    def pop_ecx(self) -> None:
        self.buf += b"\x59"


def _apply_patches(emu, base: int, patches: list[list], values: dict[str, int]) -> None:
    for offset, key, addend in patches:
        emu.mem_write(base + offset, struct.pack("<I", (values[key] + addend) & 0xFFFFFFFF))


def _emit_virtual_protect(
    asm: _Asm,
    *,
    address_imm: int | None = None,
    address_key: str | None = None,
    address_addend: int = 0,
    size: int,
    protect: int,
    old_slot: int,
    ex: bool = False,
) -> None:
    """Emit VirtualProtect(Ex); ``old_slot`` is a "data" key offset."""
    asm.push_abs("data", old_slot)
    asm.push_imm8(protect)
    asm.push_imm32(size)
    if address_key is not None:
        asm.mov_eax_ptr_abs(address_key)
        if address_addend:
            asm.add_eax_imm32(address_addend)
        asm.push_eax()
    else:
        assert address_imm is not None
        asm.push_imm32(address_imm)
    if ex:
        asm.push_imm32(0xFFFFFFFF)  # pseudo-handle for VirtualProtectEx
    asm.mov_eax_abs("vpx" if ex else "vp")
    asm.call_eax()


def _emit_virtual_query(
    asm: _Asm,
    *,
    address_imm: int | None = None,
    address_key: str | None = None,
    address_addend: int = 0,
    mbi_slot: int,
    out_slot: int,
) -> None:
    """Emit VirtualQuery and copy MBI.Protect to a "data" slot."""
    asm.push_imm32(MBI_SIZE)
    asm.push_abs("data", mbi_slot)
    if address_key is not None:
        asm.mov_eax_ptr_abs(address_key)
        if address_addend:
            asm.add_eax_imm32(address_addend)
        asm.push_eax()
    else:
        assert address_imm is not None
        asm.push_imm32(address_imm)
    asm.mov_eax_abs("vq")
    asm.call_eax()
    asm.mov_eax_ptr_abs("data", mbi_slot + MBI_PROTECT_OFFSET)
    asm.mov_ptr_abs_eax("data", out_slot)


# ---------------------------------------------------------------------------
# Private-memory page range: lpAddress low bits, neighbours, old protection
# ---------------------------------------------------------------------------

SC_DATA_TARGET = 0x00
SC_DATA_OLD1 = 0x04
SC_DATA_OLD2 = 0x08
SC_DATA_EX_OLD = 0x0C
SC_DATA_VP_RET = 0x10
SC_DATA_EX_RET = 0x14
SC_DATA_Q0 = 0x20
SC_DATA_Q1 = 0x24
SC_DATA_Q2 = 0x28
SC_DATA_Q3 = 0x2C
SC_DATA_Q0E = 0x30
SC_DATA_Q1E = 0x34
SC_DATA_MBI = 0x100
SC_DATA_SIZE = 0x200


def _build_range_shellcode() -> tuple[bytes, list[list], int]:
    """VirtualAlloc 4 pages, protect [base+0x780, +0x2000), query each page.

    Also protects the range back to PAGE_READWRITE to check that
    ``lpflOldProtect`` reports the first affected page's current protection,
    and uses VirtualProtectEx for a single-page sub-range.
    """
    asm = _Asm()
    asm.push_imm8(PAGE_READWRITE)
    asm.push_imm32(MEM_COMMIT | MEM_RESERVE)
    asm.push_imm32(0x4000)
    asm.push_imm32(0)
    asm.mov_eax_abs("alloc")
    asm.call_eax()
    asm.mov_ptr_abs_eax("data", SC_DATA_TARGET)

    _emit_virtual_protect(
        asm,
        address_key="data",
        address_addend=0x780,
        size=0x2000,
        protect=PAGE_READONLY,
        old_slot=SC_DATA_OLD1,
    )
    asm.mov_ptr_abs_eax("data", SC_DATA_VP_RET)

    for index, slot in enumerate((SC_DATA_Q0, SC_DATA_Q1, SC_DATA_Q2, SC_DATA_Q3)):
        _emit_virtual_query(
            asm,
            address_key="data",
            address_addend=index * 0x1000,
            mbi_slot=SC_DATA_MBI,
            out_slot=slot,
        )

    _emit_virtual_protect(
        asm,
        address_key="data",
        address_addend=0x780,
        size=0x2000,
        protect=PAGE_READWRITE,
        old_slot=SC_DATA_OLD2,
    )

    _emit_virtual_protect(
        asm,
        address_key="data",
        address_addend=0x780,
        size=0x880,
        protect=PAGE_READONLY,
        old_slot=SC_DATA_EX_OLD,
        ex=True,
    )
    asm.mov_ptr_abs_eax("data", SC_DATA_EX_RET)
    _emit_virtual_query(
        asm,
        address_key="data",
        address_addend=0,
        mbi_slot=SC_DATA_MBI,
        out_slot=SC_DATA_Q0E,
    )
    _emit_virtual_query(
        asm,
        address_key="data",
        address_addend=0x1000,
        mbi_slot=SC_DATA_MBI,
        out_slot=SC_DATA_Q1E,
    )

    asm.ret()

    code = bytes(asm.buf)
    data_offset = len(code)
    code += b"\x00" * SC_DATA_SIZE
    return code, asm.patches, data_offset


def test_virtualprotect_range_covers_three_pages_and_preserves_neighbours(config):
    code, patches, data_offset = _build_range_shellcode()

    se = Speakeasy(config=config)
    try:
        sc_addr = se.load_shellcode(data=code, arch="x86")
        emu = se.emu
        values = {
            "sc": sc_addr,
            "data": sc_addr + data_offset,
            "alloc": emu.get_proc("kernel32", "VirtualAlloc"),
            "vp": emu.get_proc("kernel32", "VirtualProtect"),
            "vpx": emu.get_proc("kernel32", "VirtualProtectEx"),
            "vq": emu.get_proc("kernel32", "VirtualQuery"),
        }
        assert all(values.values())
        # Raw shellcode is private memory, not an image view.
        assert emu.get_address_map(sc_addr).is_image is False
        _apply_patches(emu, sc_addr, patches, values)

        se.run_shellcode(sc_addr)
        report = se.get_report()

        data_addr = sc_addr + data_offset

        def read(offset: int) -> int:
            return int.from_bytes(emu.mem_read(data_addr + offset, 4), "little")

        entry = report.entry_points[0]
        assert entry.error is None, entry.error
        # [0x780, 0x780+0x2000) covers pages 0, 1 and 2; page 3 stays writable.
        assert read(SC_DATA_Q0) == PAGE_READONLY
        assert read(SC_DATA_Q1) == PAGE_READONLY
        assert read(SC_DATA_Q2) == PAGE_READONLY
        assert read(SC_DATA_Q3) == PAGE_READWRITE
        # lpflOldProtect is the first affected page's protection, not the
        # map-wide allocation protection.
        assert read(SC_DATA_OLD1) == PAGE_READWRITE
        assert read(SC_DATA_OLD2) == PAGE_READONLY
        # VirtualProtectEx applies the same page-granular semantics.
        assert read(SC_DATA_EX_OLD) == PAGE_READWRITE
        assert read(SC_DATA_Q0E) == PAGE_READONLY
        assert read(SC_DATA_Q1E) == PAGE_READWRITE
        assert read(SC_DATA_VP_RET) == 1
        assert read(SC_DATA_EX_RET) == 1
    finally:
        se.shutdown()


# ---------------------------------------------------------------------------
# Synthetic PE32 with a writable image .data page (write-copy semantics)
# ---------------------------------------------------------------------------

IMAGE_BASE = 0x400000
TEXT_RVA = 0x1000
DATA_RVA = 0x2000
TEXT_VA = IMAGE_BASE + TEXT_RVA
DATA_VA = IMAGE_BASE + DATA_RVA
DATA_VALUE_VA = DATA_VA
DATA_SCRATCH_VA = DATA_VA + 0x1000  # second .data page: observation slots

# Scratch slots (second .data page, stays writable during the test).
PE_OLD = 0x00
PE_MBI = 0x20
PE_OUT_INITIAL = 0x50
PE_OUT_AFTER_RO = 0x54
PE_OUT_AFTER_RW = 0x58
PE_OUT_OLD_RO = 0x5C
PE_OUT_OLD_RW = 0x60
PE_OUT_VP_RET = 0x64
PE_OUT_VP_RET2 = 0x68
PE_OUT_CODE = 0x6C
PE_OUT_HIT = 0x70
PE_OUT_EXEC = 0x74
PE_OUT_BLOCKED_VALUE = 0x78
PE_SCRATCH_SIZE = 0x200


def _handler_bytes() -> bytes:
    code = bytearray()
    code += b"\x8b\x54\x24\x04"  # mov edx, [esp+4] ; ExceptionRecord
    code += b"\x8b\x12"  # mov edx, [edx] ; ExceptionCode
    code += b"\x89\x15" + struct.pack("<I", DATA_SCRATCH_VA + PE_OUT_CODE)
    code += b"\xff\x05" + struct.pack("<I", DATA_SCRATCH_VA + PE_OUT_HIT)
    code += b"\x8b\x4c\x24\x0c"  # mov ecx, [esp+0xC] ; ContextRecord
    code += b"\x83\x81" + struct.pack("<I", 0xB8) + b"\x06"  # CONTEXT.Eip += 6
    code += b"\x31\xc0"  # xor eax, eax (EXCEPTION_CONTINUE_SEARCH)
    code += b"\xc3"
    return bytes(code)


def _build_image_text(*, seh: bool) -> tuple[bytes, list[list], dict]:
    """Build the entry code and optional inline SEH handler.

    Returns ``(text, patches, offsets)``.  Patch keys: ``data`` (scratch page),
    ``sc`` (image text base), ``vp`` and ``vq`` (kernel32 stubs).
    """
    asm = _Asm()

    # First write while the page is still write-copy: must succeed.
    asm.mov_eax_imm(DATA_VALUE_VA)
    asm.mov_ptr_eax_imm32(WRITTEN_INITIAL)

    _emit_virtual_query(
        asm,
        address_imm=DATA_VA,
        mbi_slot=PE_MBI,
        out_slot=PE_OUT_INITIAL,
    )

    _emit_virtual_protect(
        asm,
        address_imm=DATA_VA,
        size=0x1000,
        protect=PAGE_READONLY,
        old_slot=PE_OLD,
    )
    asm.mov_ptr_abs_eax("data", PE_OUT_VP_RET)
    asm.mov_eax_ptr_abs("data", PE_OLD)
    asm.mov_ptr_abs_eax("data", PE_OUT_OLD_RO)
    _emit_virtual_query(
        asm,
        address_imm=DATA_VA,
        mbi_slot=PE_MBI,
        out_slot=PE_OUT_AFTER_RO,
    )

    handler_patch = None
    fault_offset = None
    if seh:
        asm.push_abs("sc", 0)  # handler VA; addend patched after the handler
        handler_patch = asm.patches[-1]
        asm.push_fs0()
        asm.mov_fs0_esp()

    asm.mov_eax_imm(DATA_VALUE_VA)
    fault_offset = len(asm.buf)
    asm.mov_ptr_eax_imm32(BLOCKED_WRITE)

    if seh:
        asm.pop_fs0()
        asm.pop_ecx()
        asm.mov_eax_ptr_imm32(DATA_VALUE_VA)
        asm.mov_ptr_abs_eax("data", PE_OUT_BLOCKED_VALUE)
        asm.mov_ptr_abs_imm32("data", EXEC_MARKER, PE_OUT_EXEC)

        # Restore PAGE_READWRITE: image pages return to write-copy.
        _emit_virtual_protect(
            asm,
            address_imm=DATA_VA,
            size=0x1000,
            protect=PAGE_READWRITE,
            old_slot=PE_OLD,
        )
        asm.mov_ptr_abs_eax("data", PE_OUT_VP_RET2)
        asm.mov_eax_ptr_abs("data", PE_OLD)
        asm.mov_ptr_abs_eax("data", PE_OUT_OLD_RW)
        _emit_virtual_query(
            asm,
            address_imm=DATA_VA,
            mbi_slot=PE_MBI,
            out_slot=PE_OUT_AFTER_RW,
        )

        asm.mov_eax_imm(DATA_VALUE_VA)
        asm.mov_ptr_eax_imm32(WRITTEN_AFTER_RW)

    asm.ret()

    offsets = {"fault": fault_offset, "handler": None}
    if seh:
        offsets["handler"] = len(asm.buf)
        handler_patch[2] = offsets["handler"]
        asm.buf += _handler_bytes()

    return bytes(asm.buf), asm.patches, offsets


def _build_pe(*, seh: bool) -> tuple[bytes, list[list], dict]:
    image = bytearray(0x800)
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
    put("<I", 0)
    put("<I", TEXT_RVA)  # AddressOfEntryPoint
    put("<I", TEXT_RVA)  # BaseOfCode
    put("<I", DATA_RVA)  # BaseOfData
    put("<I", IMAGE_BASE)
    put("<I", 0x1000)
    put("<I", 0x200)
    put("<HH", 6, 0)
    put("<HH", 0, 0)
    put("<HH", 6, 1)
    put("<I", 0)
    put("<I", 0x4000)  # SizeOfImage
    put("<I", 0x200)  # SizeOfHeaders
    put("<I", 0)
    put("<HH", 3, 0)
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
    section(b".data", 0x2000, DATA_RVA, 0x200, 0x400, 0xC0000040)

    text, patches, offsets = _build_image_text(seh=seh)
    assert len(text) <= 0x200, hex(len(text))
    image[0x200 : 0x200 + len(text)] = text
    return bytes(image), patches, offsets


def _run_image_pe(config, pe: bytes, patches: list[list], offsets: dict):
    se = Speakeasy(config=config, argv=[])
    try:
        module = se.load_module(data=pe)
        emu = se.emu
        base = module.base
        assert base == IMAGE_BASE, hex(base)
        text_va = base + TEXT_RVA
        values = {
            "sc": text_va,
            "data": base + DATA_RVA + 0x1000,
            "vp": emu.get_proc("kernel32", "VirtualProtect"),
            "vq": emu.get_proc("kernel32", "VirtualQuery"),
        }
        assert all(values.values())
        _apply_patches(emu, text_va, patches, values)

        se.run_module(module, all_entrypoints=True)
        report = se.get_report()
        scratch = values["data"]

        def read(offset: int) -> int:
            return int.from_bytes(emu.mem_read(scratch + offset, 4), "little")

        observations = {
            "initial": read(PE_OUT_INITIAL),
            "after_ro": read(PE_OUT_AFTER_RO),
            "after_rw": read(PE_OUT_AFTER_RW),
            "old_ro": read(PE_OUT_OLD_RO),
            "old_rw": read(PE_OUT_OLD_RW),
            "vp_ret": read(PE_OUT_VP_RET),
            "vp_ret2": read(PE_OUT_VP_RET2),
            "code": read(PE_OUT_CODE),
            "hit": read(PE_OUT_HIT),
            "exec": read(PE_OUT_EXEC),
            "blocked_value": read(PE_OUT_BLOCKED_VALUE),
            "final_value": int.from_bytes(emu.mem_read(base + DATA_RVA, 4), "little"),
            "data_page_perms": emu.get_address_perms(base + DATA_RVA),
            "data_win_protect": emu.get_address_win_protection(base + DATA_RVA),
            "fault_va": text_va + offsets["fault"] if offsets["fault"] is not None else None,
            "data_va": base + DATA_RVA,
        }
        return report, observations
    finally:
        se.shutdown()


def test_image_data_page_is_writecopy_and_explicit_readonly_removes_write(config):
    pe, patches, offsets = _build_pe(seh=True)
    report, obs = _run_image_pe(config, pe, patches, offsets)

    entry = report.entry_points[0]
    assert entry.error is None, entry.error
    # Writable image page is write-copy, not plain read-write.
    assert obs["initial"] == PAGE_WRITECOPY
    assert obs["vp_ret"] == 1
    assert obs["old_ro"] == PAGE_WRITECOPY
    # Explicit PAGE_READONLY really removes write permission.
    assert obs["after_ro"] == PAGE_READONLY
    # The write after RO faults and the inline SEH handler takes over.
    assert obs["code"] == STATUS_ACCESS_VIOLATION
    assert obs["hit"] == 1
    assert obs["exec"] == EXEC_MARKER
    assert obs["blocked_value"] == WRITTEN_INITIAL
    # PAGE_READWRITE on an image page returns to write-copy semantics.
    assert obs["vp_ret2"] == 1
    assert obs["old_rw"] == PAGE_READONLY
    assert obs["after_rw"] == PAGE_WRITECOPY
    assert obs["final_value"] == WRITTEN_AFTER_RW
    assert obs["data_page_perms"] & common.PERM_MEM_WRITE
    assert obs["data_win_protect"] == PAGE_WRITECOPY


def test_image_data_page_readonly_without_seh_keeps_fault(config):
    pe, patches, offsets = _build_pe(seh=False)
    report, obs = _run_image_pe(config, pe, patches, offsets)

    entry = report.entry_points[0]
    assert entry.error is not None
    assert entry.error.type == "invalid_protect_write"
    assert entry.error.pc == obs["fault_va"]
    assert entry.error.address == obs["data_va"]
    assert entry.error.access_type == "write"
    assert obs["hit"] == 0
    assert obs["exec"] == 0
    # The blocked write did not land; only the first (write-copy) write did.
    assert obs["final_value"] == WRITTEN_INITIAL


# ---------------------------------------------------------------------------
# Unit contract for the page-range helper, conversions and page state
# ---------------------------------------------------------------------------


class _RecordingEngine:
    def __init__(self) -> None:
        self.calls: list[tuple[int, int, int]] = []

    def mem_protect(self, addr: int, size: int, perms: int) -> None:
        self.calls.append((addr, size, perms))


def _manager(*maps: MemMap) -> MemoryManager:
    manager = MemoryManager()
    manager.emu_eng = _RecordingEngine()
    manager.maps.extend(maps)
    return manager


def _map(base: int, size: int, prot: int, *, flags: int = 0, is_image: bool = False) -> MemMap:
    return MemMap(base, size, "test.map", prot, flags, base, size, is_image=is_image)


def test_page_span_includes_lpaddress_low_bits() -> None:
    assert page_span(0x400780, 0x2000) == (0x400000, 0x403000)
    assert page_span(0x400780, 0x880) == (0x400000, 0x401000)
    assert page_span(0x400000, 0x1000) == (0x400000, 0x401000)
    assert page_span(0x401FFF, 1) == (0x401000, 0x402000)


def test_win_and_emu_protection_conversions_cover_writecopy() -> None:
    assert win_protect_to_emu_perms(PAGE_WRITECOPY) == common.PERM_MEM_RW
    assert win_protect_to_emu_perms(PAGE_EXECUTE_WRITECOPY) == common.PERM_MEM_RWX
    assert win_protect_to_emu_perms(PAGE_READONLY) == common.PERM_MEM_READ
    assert win_protect_to_emu_perms(PAGE_READWRITE) == common.PERM_MEM_RW
    assert emu_perms_to_win_protect(common.PERM_MEM_RW) == PAGE_READWRITE
    assert emu_perms_to_win_protect(common.PERM_MEM_READ) == PAGE_READONLY

    assert image_protection_for_emu_perms(common.PERM_MEM_RW) == PAGE_WRITECOPY
    assert image_protection_for_emu_perms(common.PERM_MEM_RWX) == PAGE_EXECUTE_WRITECOPY
    assert image_protection_for_emu_perms(common.PERM_MEM_RX) == PAGE_EXECUTE_READ
    assert image_protection_for_emu_perms(common.PERM_MEM_READ) == PAGE_READONLY


def test_apply_page_protection_updates_only_covered_pages() -> None:
    manager = _manager(_map(0x400000, 0x5000, common.PERM_MEM_RW))
    mm = manager.maps[0]

    result = apply_page_protection(manager, 0x400780, 0x2000, PAGE_READONLY)

    assert result.success
    assert result.old_protect == PAGE_READWRITE
    assert (result.start, result.end) == (0x400000, 0x403000)
    pages = [0x400000, 0x401000, 0x402000, 0x403000, 0x404000]
    assert [manager.get_address_perms(page) for page in pages] == [
        common.PERM_MEM_READ,
        common.PERM_MEM_READ,
        common.PERM_MEM_READ,
        common.PERM_MEM_RW,
        common.PERM_MEM_RW,
    ]
    # The map-wide protection is allocation state and must not be rewritten.
    assert mm.prot == common.PERM_MEM_RW
    assert manager.emu_eng.calls == [(0x400000, 0x3000, common.PERM_MEM_READ)]


def test_apply_page_protection_old_protect_is_first_page_current_state() -> None:
    # The allocation protection (flags) differs from the page's current
    # protection; lpflOldProtect must report the page state, not the flags.
    manager = _manager(_map(0x400000, 0x4000, common.PERM_MEM_RW, flags=PAGE_NOACCESS))

    first = apply_page_protection(manager, 0x400780, 0x2000, PAGE_READONLY)
    second = apply_page_protection(manager, 0x400780, 0x2000, PAGE_READWRITE)
    third = apply_page_protection(manager, 0x400000, 0x1000, PAGE_NOACCESS)

    assert first.old_protect == PAGE_READWRITE
    assert second.old_protect == PAGE_READONLY
    assert third.old_protect == PAGE_READWRITE  # page 0, not the map's old flags
    assert manager.get_address_perms(0x400000) == common.PERM_MEM_NONE


def test_apply_page_protection_is_all_or_nothing_for_unmapped_ranges() -> None:
    manager = _manager(_map(0x400000, 0x2000, common.PERM_MEM_RW))

    result = apply_page_protection(manager, 0x400780, 0x2000, PAGE_READONLY)

    assert not result.success
    assert result.error == page_protection.ERROR_INVALID_ADDRESS
    assert manager.emu_eng.calls == []
    assert manager.get_address_perms(0x400000) == common.PERM_MEM_RW
    assert manager.get_address_perms(0x401000) == common.PERM_MEM_RW


def test_apply_page_protection_rejects_zero_size_and_invalid_protection() -> None:
    manager = _manager(_map(0x400000, 0x1000, common.PERM_MEM_RW))

    zero = apply_page_protection(manager, 0x400000, 0, PAGE_READONLY)
    invalid = apply_page_protection(manager, 0x400000, 0x1000, 0x55)

    assert not zero.success
    assert zero.error == 87  # ERROR_INVALID_PARAMETER
    assert not invalid.success
    assert invalid.error == 87
    assert manager.emu_eng.calls == []
    assert manager.get_address_perms(0x400000) == common.PERM_MEM_RW


def test_apply_page_protection_ignores_modifier_bits() -> None:
    manager = _manager(_map(0x400000, 0x1000, common.PERM_MEM_RW))

    result = apply_page_protection(
        manager,
        0x400000,
        0x1000,
        PAGE_READONLY | page_protection.PAGE_NOCACHE | page_protection.PAGE_WRITECOMBINE,
    )

    assert result.success
    assert manager.get_address_perms(0x400000) == common.PERM_MEM_READ


def test_image_readwrite_becomes_writecopy_and_readonly_removes_write() -> None:
    manager = _manager(_map(0x400000, 0x3000, common.PERM_MEM_RW, is_image=True))
    # What the PE loader records for a writable image section.
    manager.mem_protect(0x400000, 0x3000, common.PERM_MEM_RW, win_protect=PAGE_WRITECOPY)

    rw = apply_page_protection(manager, 0x400780, 0x880, PAGE_READWRITE)
    assert rw.success
    assert rw.old_protect == PAGE_WRITECOPY  # image mapping starts as write-copy
    assert manager.get_address_win_protection(0x400000) == PAGE_WRITECOPY
    assert manager.get_address_perms(0x400000) == common.PERM_MEM_RW

    ro = apply_page_protection(manager, 0x400000, 0x1000, PAGE_READONLY)
    assert ro.success
    assert ro.old_protect == PAGE_WRITECOPY
    assert manager.get_address_win_protection(0x400000) == PAGE_READONLY
    assert manager.get_address_perms(0x400000) == common.PERM_MEM_READ

    back = apply_page_protection(manager, 0x400000, 0x1000, PAGE_READWRITE)
    assert back.success
    assert back.old_protect == PAGE_READONLY
    assert manager.get_address_win_protection(0x400000) == PAGE_WRITECOPY
    assert manager.get_address_perms(0x400000) == common.PERM_MEM_RW


def test_writecopy_on_private_virtualalloc_map_is_rejected() -> None:
    manager = _manager(_map(0x500000, 0x1000, common.PERM_MEM_RW, flags=PAGE_READWRITE))

    result = apply_page_protection(manager, 0x500000, 0x1000, PAGE_WRITECOPY)

    assert not result.success
    assert result.error == 87
    assert manager.emu_eng.calls == []
    assert manager.get_address_perms(0x500000) == common.PERM_MEM_RW

    image_manager = _manager(_map(0x500000, 0x1000, common.PERM_MEM_RW, is_image=True))
    accepted = apply_page_protection(image_manager, 0x500000, 0x1000, PAGE_WRITECOPY)
    assert accepted.success
    assert image_manager.get_address_win_protection(0x500000) == PAGE_WRITECOPY


def test_protection_region_separates_readwrite_from_writecopy() -> None:
    manager = _manager(_map(0x400000, 0x3000, common.PERM_MEM_RW, is_image=True))
    manager.mem_protect(0x400000, 0x1000, common.PERM_MEM_RW, win_protect=PAGE_WRITECOPY)
    manager.mem_protect(0x401000, 0x1000, common.PERM_MEM_RW, win_protect=PAGE_READWRITE)
    manager.mem_protect(0x402000, 0x1000, common.PERM_MEM_RW, win_protect=PAGE_WRITECOPY)

    assert manager.get_protection_region(0x400100) == (0x400000, 0x1000)
    assert manager.get_protection_region(0x401100) == (0x401000, 0x1000)
    assert manager.get_protection_region(0x402100) == (0x402000, 0x1000)

    manager.clear_page_protections(0x400000, 0x3000)
    assert manager.get_address_win_protection(0x400000) is None
    assert manager.get_protection_region(0x400100) == (0x400000, 0x3000)


def test_runs_merge_contiguous_pages_with_equal_perms():
    page_perms = {0x1000: RX, 0x2000: RX, 0x3000: RX, 0x4000: RW, 0x5000: RW}
    assert get_page_protection_runs(page_perms, PAGE) == [
        (0x1000, 0x3000, RX),
        (0x4000, 0x2000, RW),
    ]


def test_runs_split_at_gaps_and_ignore_insertion_order():
    page_perms = {0x5000: RX, 0x1000: RX, 0x2000: RX}
    assert get_page_protection_runs(page_perms, PAGE) == [
        (0x1000, 0x2000, RX),
        (0x5000, 0x1000, RX),
    ]


def test_runs_keep_perm_changes_separate():
    page_perms = {0x1000: RX, 0x2000: RW, 0x3000: RX}
    assert get_page_protection_runs(page_perms, PAGE) == [
        (0x1000, 0x1000, RX),
        (0x2000, 0x1000, RW),
        (0x3000, 0x1000, RX),
    ]


def test_protecting_an_empty_range_changes_nothing(dll_emu: Speakeasy) -> None:
    emu = dll_emu.emu
    base = emu.mem_map(PAGE, perms=RW, tag="test.empty_protect")
    before = list(emu.get_mem_regions())

    emu.mem_protect(base, 0, RX)
    assert list(emu.get_mem_regions()) == before


def test_virtual_protect_returns_the_protection_of_the_first_page(config) -> None:
    rw, rx = PAGE_PROTECTION_FLAGS.PAGE_READWRITE, PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READ
    ro_guard = PAGE_PROTECTION_FLAGS.PAGE_READONLY | PAGE_PROTECTION_FLAGS.PAGE_GUARD
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=bytes(0x1000), arch="x86")
        data = se.mem_alloc(0x100)
        page, results, olds = data, data + 0x10, data + 0x20
        virtual_protect = get_api(se, "kernel32", "VirtualProtect")
        mem_commit_reserve = windefs.MEM_COMMIT | windefs.MEM_RESERVE
        body = guest_call(4, get_api(se, "kernel32", "VirtualAlloc"), 0, 2 * PAGE, mem_commit_reserve, rw, store=page)
        protects = [
            (0, 2 * PAGE, rx),
            (PAGE, PAGE, PAGE_PROTECTION_FLAGS.PAGE_READONLY),
            (0, 2 * PAGE, ro_guard),
            (PAGE, PAGE, rw),
        ]
        for index, (offset, size, new) in enumerate(protects):
            # The code adds the offset to the base that VirtualAlloc returned.
            body += b"\xa1" + struct.pack("<I", page) + b"\x05" + struct.pack("<I", offset)
            body += b"\xa3" + struct.pack("<I", data + 4)
            args = (Deref(data + 4), size, new, olds + 4 * index)
            body += guest_call(4, virtual_protect, *args, store=results + 4 * index)
        se.mem_write(code, body + b"\xc3")
        se.run_shellcode(code)
        assert struct.unpack("<4I", se.mem_read(results, 16)) == (1, 1, 1, 1)
        assert struct.unpack("<4I", se.mem_read(olds, 16)) == (rw, rx, rx, ro_guard)


@pytest.mark.parametrize("bin_name", ["dll_test_x86.dll.xz", "dll_test_x64.dll.xz"])
def test_loaded_sections_have_expected_page_protections(config, load_test_bin, bin_name):
    se = Speakeasy(config=config)
    try:
        module = se.load_module(data=load_test_bin(bin_name))
        emu = se.emu
        page_size = emu.page_size

        expected: dict[int, int] = {}
        for sect in module.sections:
            start = (module.base + sect.virtual_address) & ~(page_size - 1)
            end = (module.base + sect.virtual_address + sect.virtual_size + page_size - 1) & ~(page_size - 1)
            for page in range(start, end, page_size):
                expected[page] = expected.get(page, 0) | sect.perms

        regions = list(emu.get_mem_regions())
        for page, perms in expected.items():
            region = next(r for r in regions if r[0] <= page <= r[1])
            assert region[2] == emu.emu_eng.perms[perms], hex(page)

        image_regions = [r for r in regions if module.base <= r[0] < module.base + module.image_size]
        assert len(image_regions) <= len(get_page_protection_runs(expected, page_size)) + 1
    finally:
        se.shutdown()


def get_rx_page(se: Speakeasy) -> int:
    module = se.emu.modules[0]
    sect = next(s for s in module.sections if s.perms == RX)
    return module.base + sect.virtual_address


def get_perms(se: Speakeasy, address: int) -> int:
    return next(p for start, end, p in se.emu.get_mem_regions() if start <= address <= end)


def protect(se: Speakeasy, address: int, size: int, new: int) -> tuple[int, int, int, int]:
    """Call ntdll!NtProtectVirtualMemory on the current process, and return the status and the three outputs."""
    ptr = "<I" if se.get_ptr_size() == 4 else "<Q"
    p_base = alloc(se, struct.pack(ptr, address))
    p_size = alloc(se, struct.pack(ptr, size))
    p_old = alloc(se, b"\xff" * 4)
    current_process = (1 << 8 * se.get_ptr_size()) - 1
    rv, _ = call(se, "ntdll", "NtProtectVirtualMemory", [current_process, p_base, p_size, new, p_old])
    base = struct.unpack(ptr, se.mem_read(p_base, se.get_ptr_size()))[0]
    size = struct.unpack(ptr, se.mem_read(p_size, se.get_ptr_size()))[0]
    old = struct.unpack("<I", se.mem_read(p_old, 4))[0]
    return rv, base, size, old


def test_commit_changes_the_perms_of_the_region_in_the_memory_layout(config) -> None:
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=bytes(0x1000), arch="x86")
        data = se.mem_alloc(0x100)
        reserved, committed = data, data + 4
        virtual_alloc = get_api(se, "kernel32", "VirtualAlloc")
        body = guest_call(
            4, virtual_alloc, 0, 4 * PAGE, windefs.MEM_RESERVE, PAGE_PROTECTION_FLAGS.PAGE_NOACCESS, store=reserved
        )
        args = (Deref(reserved), PAGE, windefs.MEM_COMMIT, PAGE_PROTECTION_FLAGS.PAGE_READWRITE)
        body += guest_call(4, virtual_alloc, *args, store=committed)
        se.mem_write(code, body + b"\xc3")
        se.run_shellcode(code)
        base, commit_base = struct.unpack("<2I", se.mem_read(data, 8))
        report = se.get_report()

    assert commit_base == base
    run = report.runs[0]
    assert run.memory is not None
    [region] = [r for r in run.memory.layout if r.tag == "api.VirtualAlloc"]
    assert (region.base, region.size, region.permissions) == (base, 4 * PAGE, "rw-")


@pytest.mark.parametrize("fixture", ["dll_emu", "dll64_emu"])
def test_ntdll_protect_virtual_memory_changes_page_protection(request, fixture: str) -> None:
    se = request.getfixturevalue(fixture)
    start_process(se)
    page = get_rx_page(se)
    next_perms = get_perms(se, page + PAGE)

    rv, base, size, old = protect(se, page + 0x10, 0x10, PAGE_PROTECTION_FLAGS.PAGE_READWRITE)
    assert (rv, base, size, old) == (ddk.STATUS_SUCCESS, page, PAGE, PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READ)
    assert get_perms(se, page) == se.emu.emu_eng.perms[RW]
    assert get_perms(se, page + PAGE) == next_perms

    rv, _, _, old = protect(se, page, PAGE, PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READ)
    # Adapted to the local FX-004 Wine write-copy semantics: the writable image
    # page reports PAGE_WRITECOPY (8), not PAGE_READWRITE (4); upstream expected
    # the latter.
    assert (rv, old) == (ddk.STATUS_SUCCESS, PAGE_PROTECTION_FLAGS.PAGE_WRITECOPY)
    assert get_perms(se, page) == se.emu.emu_eng.perms[RX]


def test_ntdll_protect_virtual_memory_spans_pages(dll64_emu: Speakeasy) -> None:
    se = dll64_emu
    start_process(se)
    page = get_rx_page(se)

    rv, base, size, _ = protect(se, page + 0xFF0, 0x20, PAGE_PROTECTION_FLAGS.PAGE_READWRITE)
    assert (rv, base, size) == (ddk.STATUS_SUCCESS, page, 2 * PAGE)
    assert get_perms(se, page + PAGE) == se.emu.emu_eng.perms[RW]


def test_ntdll_protect_virtual_memory_records_a_mem_protect_event(dll64_emu: Speakeasy) -> None:
    se = dll64_emu
    start_process(se)
    page = get_rx_page(se)

    protect(se, page + 0xFF0, 0x20, PAGE_PROTECTION_FLAGS.PAGE_READWRITE)
    protect(se, 0, PAGE, PAGE_PROTECTION_FLAGS.PAGE_READWRITE)
    events = [e for e in se.emu.get_current_run().events if e.event == EventType.MEM_PROTECT]
    assert [(e.base, e.size, e.permissions, e.pid) for e in events] == [(page, 2 * PAGE, "rw-", None)]


@pytest.mark.parametrize("api", ["VirtualProtect", "VirtualProtectEx"])
def test_virtual_protect_records_one_mem_protect_event_for_the_changed_pages(dll64_emu: Speakeasy, api: str) -> None:
    se = dll64_emu
    start_process(se)
    page = get_rx_page(se)
    p_old = alloc(se, b"\xff" * 4)
    rw = PAGE_PROTECTION_FLAGS.PAGE_READWRITE
    process = [(1 << 8 * se.get_ptr_size()) - 1] if api == "VirtualProtectEx" else []

    assert call(se, "kernel32", api, [*process, page + 0xFF0, 0x20, rw, p_old])[0] == 1
    assert get_perms(se, page + PAGE) == se.emu.emu_eng.perms[RW]
    assert call(se, "kernel32", api, [*process, page, 0, rw, p_old])[0] == 0
    assert call(se, "kernel32", api, [*process, 0, PAGE, rw, p_old])[0] == 0
    events = [e for e in se.emu.get_current_run().events if e.event == EventType.MEM_PROTECT]
    assert [(e.base, e.size, e.permissions, e.pid) for e in events] == [(page, 2 * PAGE, "rw-", None)]


def test_ntdll_protect_virtual_memory_fails_for_an_empty_or_unmapped_range(dll64_emu: Speakeasy) -> None:
    se = dll64_emu
    start_process(se)
    page = get_rx_page(se)
    rw = PAGE_PROTECTION_FLAGS.PAGE_READWRITE

    assert protect(se, page, 0, rw) == (ddk.STATUS_INVALID_PARAMETER, page, 0, 0xFFFFFFFF)
    # Adapted to the local FX-009 semantics: an unmapped NtProtectVirtualMemory
    # range returns STATUS_ACCESS_VIOLATION (0xC0000005); upstream expected
    # STATUS_CONFLICTING_ADDRESSES.
    assert protect(se, 0, PAGE, rw)[0] == ddk.STATUS_ACCESS_VIOLATION
    assert get_perms(se, page) == se.emu.emu_eng.perms[RX]


@pytest.mark.parametrize(
    "dll, api, success", [("kernel32", "VirtualProtect", 1), ("ntdll", "NtProtectVirtualMemory", ddk.STATUS_SUCCESS)]
)
def test_protect_changes_the_perms_of_the_region_in_the_memory_layout(config, dll: str, api: str, success: int) -> None:
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=bytes(0x1000), arch="x86")
        data = se.mem_alloc(0x100)
        page, size, old = data, data + 4, data + 8
        se.mem_write(size, struct.pack("<I", PAGE))
        body = guest_call(
            4,
            get_api(se, "kernel32", "VirtualAlloc"),
            0,
            PAGE,
            windefs.MEM_COMMIT | windefs.MEM_RESERVE,
            PAGE_PROTECTION_FLAGS.PAGE_READWRITE,
            store=page,
        )
        if api == "VirtualProtect":
            args = (Deref(page), PAGE, PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READ, old)
        else:
            args = (0xFFFFFFFF, page, size, PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READ, old)
        body += guest_call(4, get_api(se, dll, api), *args)
        se.mem_write(code, body + b"\xc3")
        se.run_shellcode(code)
        report = se.get_report()

    run = report.runs[0]
    [protect_call] = [e for e in run.events if isinstance(e, ApiEvent) and e.api_name == f"{dll}.{api}"]
    assert protect_call.return_value == success
    assert run.memory is not None
    [region] = [r for r in run.memory.layout if r.tag == "api.VirtualAlloc"]
    assert (region.size, region.permissions) == (PAGE, "r-x")


def test_memory_events_have_the_permissions_of_the_layout_region(config) -> None:
    with Speakeasy(config=config) as se:
        code = se.load_shellcode(data=b"\xcc" * 0x1000, arch="amd64")
        data = se.mem_alloc(0x1000)
        p_rw, p_rx, p_old = data, data + 8, data + 0x10
        call_api = lambda name, *args, **kw: guest_call(8, get_api(se, "kernel32", name), *args, **kw)  # noqa: E731
        current_process = 0xFFFFFFFFFFFFFFFF
        commit = 0x3000
        body = call_api("VirtualAlloc", 0, PAGE, commit, PAGE_PROTECTION_FLAGS.PAGE_READWRITE, store=p_rw)
        body += call_api("VirtualAlloc", 0, PAGE, commit, PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READWRITE, store=p_rx)
        body += call_api(
            "VirtualProtectEx", current_process, Deref(p_rx), PAGE, PAGE_PROTECTION_FLAGS.PAGE_EXECUTE_READ, p_old
        )
        se.mem_write(code, body + b"\xc3")
        se.run_shellcode(code)
        run = se.get_report().runs[0]
        rw, rx = read_pointer(se, p_rw), read_pointer(se, p_rx)

    assert run.error is None
    memory_events = (EventType.MEM_ALLOC, EventType.MEM_PROTECT)
    last_events = {e.base: (e.event, e.permissions) for e in run.events if e.event in memory_events}
    assert last_events == {rw: (EventType.MEM_ALLOC, "rw-"), rx: (EventType.MEM_PROTECT, "r-x")}
    regions = {region.base: region.permissions for region in run.memory.layout}
    assert {base: regions[base] for base in last_events} == {rw: "rw-", rx: "r-x"}
