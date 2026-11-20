"""Contract tests for per-thread implicit TLS (FX-001, TLS.per_thread_block).

The real Windows/Wine loader treats ``IMAGE_TLS_DIRECTORY.StartAddressOfRawData``
as an immutable template.  At module load it allocates a TLS index and writes it
to ``AddressOfIndex``; at thread creation it allocates a writable block of
``(End-Start+SizeOfZeroFill)`` bytes, copies the template, zero-fills the tail and
stores the block pointer in ``TEB->ThreadLocalStoragePointer[index]``.

The tests freeze that contract at two levels:

* ``TlsManager`` unit tests with an in-memory emulator double: index assignment,
  DWORD width of ``AddressOfIndex``, template copy, zero fill, multi-module /
  multi-thread isolation, idempotent re-initialisation and negative cases.
* A synthetic PE32 whose TLS template lives in read-only ``.rdata`` and whose
  ``AddressOfIndex`` lives in writable ``.data``.  Its entry point executes
  ``fs:[0x2c] -> [TlsIndex] -> [ecx+4] = imm`` exactly like the MSVC CRT path
  that fails at ``0x41fd92``.  Before the fix the run terminates with
  ``invalid_protect_write`` at ``StartAddressOfRawData+4``; after the fix the
  write lands in a writable per-thread copy and the template is unchanged.
"""

from __future__ import annotations

import struct

import pytest

from speakeasy import Speakeasy
from speakeasy.windows.loaders import PeLoader
from speakeasy.windows.tls import TlsDirectory, TlsError, TlsManager

# ---------------------------------------------------------------------------
# Synthetic PE32 constants
# ---------------------------------------------------------------------------

IMAGE_BASE = 0x400000
TEXT_RVA = 0x1000
RDATA_RVA = 0x2000
DATA_RVA = 0x3000
TLS_DIR_RVA = 0x2100

START_VA = IMAGE_BASE + RDATA_RVA  # TLS template in read-only .rdata
END_VA = START_VA + 8
INDEX_VA = IMAGE_BASE + DATA_RVA  # DWORD index in writable .data BSS
OUT_VALUE_VA = INDEX_VA + 4
OUT_BLOCK_VA = INDEX_VA + 8

TEMPLATE = bytes.fromhex("0000000000000080")
WRITTEN_VALUE = 0x12345678


def _build_pe(*, include_tls: bool) -> bytes:
    """Build a minimal PE32 with an optional TLS directory.

    The TLS variant's entry point performs the same TEB TLS access pattern as
    the failing samples and records proof of execution into ``.data``.
    """

    image = bytearray(0x800)
    image[0:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x40)
    image[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", image, 0x44, 0x14C, 3, 0, 0, 0, 0xE0, 0x0102)

    offset = 0x58

    def put(fmt: str, *values: int) -> None:
        nonlocal offset
        struct.pack_into(fmt, image, offset, *values)
        offset += struct.calcsize(fmt)

    put("<H", 0x10B)  # PE32 magic
    put("<BB", 1, 0)
    put("<I", 0x200)  # SizeOfCode
    put("<I", 0x400)  # SizeOfInitializedData
    put("<I", 0)  # SizeOfUninitializedData
    put("<I", TEXT_RVA)  # AddressOfEntryPoint
    put("<I", TEXT_RVA)  # BaseOfCode
    put("<I", RDATA_RVA)  # BaseOfData
    put("<I", IMAGE_BASE)
    put("<I", 0x1000)  # SectionAlignment
    put("<I", 0x200)  # FileAlignment
    put("<HH", 6, 0)  # OperatingSystemVersion
    put("<HH", 0, 0)  # ImageVersion
    put("<HH", 6, 1)  # SubsystemVersion
    put("<I", 0)  # Win32VersionValue
    put("<I", 0x4000)  # SizeOfImage
    put("<I", 0x200)  # SizeOfHeaders
    put("<I", 0)  # CheckSum
    put("<HH", 3, 0)  # Subsystem=console, DllCharacteristics
    put("<IIII", 0x100000, 0x1000, 0x100000, 0x1000)
    put("<II", 0, 16)  # LoaderFlags, NumberOfRvaAndSizes
    for directory_index in range(16):
        if directory_index == 9 and include_tls:  # IMAGE_DIRECTORY_ENTRY_TLS
            put("<II", TLS_DIR_RVA, 24)
        else:
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
    section(b".rdata", 0x1000, RDATA_RVA, 0x200, 0x400, 0x40000040)
    section(b".data", 0x1000, DATA_RVA, 0x200, 0x600, 0xC0000040)

    if include_tls:
        code = (
            b"\x64\xA1\x2C\x00\x00\x00"  # mov eax, fs:[0x2c]
            + b"\x8B\x0D"
            + struct.pack("<I", INDEX_VA)  # mov ecx, [TlsIndex]
            + b"\x8B\x0C\x88"  # mov ecx, [eax + ecx*4]
            + b"\xC7\x41\x04"
            + struct.pack("<I", WRITTEN_VALUE)  # mov dword [ecx+4], imm
            + b"\x8B\x51\x04"  # mov edx, [ecx+4]
            + b"\x89\x15"
            + struct.pack("<I", OUT_VALUE_VA)  # mov [out_value], edx
            + b"\x89\x0D"
            + struct.pack("<I", OUT_BLOCK_VA)  # mov [out_block], ecx
            + b"\xC3"
        )
        image[0x400 : 0x400 + len(TEMPLATE)] = TEMPLATE
        struct.pack_into(
            "<IIIIII",
            image,
            0x400 + 0x100,
            START_VA,
            END_VA,
            INDEX_VA,
            0,  # AddressOfCallBacks
            0,  # SizeOfZeroFill
            0,  # Characteristics
        )
    else:
        code = (
            b"\xC7\x05"
            + struct.pack("<I", OUT_VALUE_VA)
            + struct.pack("<I", 0x5A5A5A5A)
            + b"\xC3"
        )
    image[0x200 : 0x200 + len(code)] = code
    return bytes(image)


def _run_pe(config, pe_bytes):
    """Load and run a synthetic PE, returning the report and memory evidence."""

    se = Speakeasy(config=config, argv=[])
    try:
        module = se.load_module(data=pe_bytes)
        se.run_module(module, all_entrypoints=True)
        report = se.get_report()
        emu = se.emu
        thread = emu.get_current_thread()
        evidence = {
            "report": report,
            "module": module,
            "index": int.from_bytes(emu.mem_read(INDEX_VA, 4), "little"),
            "out_value": int.from_bytes(emu.mem_read(OUT_VALUE_VA, 4), "little"),
            "out_block": int.from_bytes(emu.mem_read(OUT_BLOCK_VA, 4), "little"),
            "template": emu.mem_read(START_VA, len(TEMPLATE)),
            "tls_pointer": thread.teb.object.ThreadLocalStoragePointer,
            "emu": emu,
        }
        return evidence
    finally:
        se.shutdown()


# ---------------------------------------------------------------------------
# Synthetic PE integration tests
# ---------------------------------------------------------------------------


def test_synthetic_pe_tls_write_succeeds_and_template_is_unchanged(config):
    evidence = _run_pe(config, _build_pe(include_tls=True))

    report = evidence["report"]
    assert report.entry_points
    assert report.entry_points[0].error is None, report.entry_points[0].error

    # The loader wrote the module index into writable .data.
    assert evidence["index"] == 0

    # The CRT-style write hit a per-thread writable copy, not the template.
    assert evidence["out_value"] == WRITTEN_VALUE
    block = evidence["out_block"]
    assert block != 0
    assert block != START_VA
    assert evidence["emu"].mem_read(block + 4, 4) == struct.pack("<I", WRITTEN_VALUE)

    # The read-only template was never modified.
    assert evidence["template"] == TEMPLATE

    # TEB points at the per-thread pointer array, whose slot 0 is the block.
    array = evidence["tls_pointer"]
    assert array != 0
    assert int.from_bytes(evidence["emu"].mem_read(array, 4), "little") == block


def test_pe_loader_exposes_parsed_tls_directory():
    loader = PeLoader(data=_build_pe(include_tls=True))
    image = loader.make_image()

    assert image.tls_directory == TlsDirectory(
        start=START_VA,
        end=END_VA,
        index_va=INDEX_VA,
        callbacks_va=0,
        zero_fill=0,
        characteristics=0,
    )
    assert image.tls_directory_va == IMAGE_BASE + TLS_DIR_RVA


def test_synthetic_pe_without_tls_directory_is_unaffected(config):
    evidence = _run_pe(config, _build_pe(include_tls=False))

    report = evidence["report"]
    assert report.entry_points
    assert report.entry_points[0].error is None
    assert evidence["out_value"] == 0x5A5A5A5A
    assert evidence["tls_pointer"] == 0


# ---------------------------------------------------------------------------
# TlsManager unit tests with an in-memory emulator double
# ---------------------------------------------------------------------------


class _MemoryEmu:
    """Minimal emulator double used by ``TlsManager`` unit tests."""

    def __init__(self, ptr_size: int = 4) -> None:
        self.ptr_size = ptr_size
        self._next = 0x100000
        self._ranges: list[tuple[int, int, bool]] = []
        self._memory: dict[int, int] = {}
        self.maps_created = 0

    def map(self, base: int, size: int, *, writable: bool = True, data: bytes = b"") -> None:
        self._ranges.append((base, max(size, 1), writable))
        for i, value in enumerate(data):
            self._memory[base + i] = value

    def _check(self, address: int, size: int, *, write: bool = False) -> None:
        for base, length, writable in self._ranges:
            if base <= address and address + size <= base + length:
                if write and not writable:
                    raise ValueError(f"write to read-only range at 0x{address:x}")
                return
        raise ValueError(f"invalid access at 0x{address:x}+{size}")

    def get_ptr_size(self) -> int:
        return self.ptr_size

    def mem_map(self, size, base=None, perms=None, tag=None):
        assert base is None, "TlsManager must let the emulator choose block addresses"
        address = self._next
        self._next += max(size, 0x10) + 0x10
        self.maps_created += 1
        self.map(address, max(size, 1))
        return address

    def mem_read(self, address: int, size: int) -> bytes:
        self._check(address, size)
        return bytes(self._memory.get(address + i, 0) for i in range(size))

    def mem_write(self, address: int, data: bytes) -> None:
        self._check(address, len(data), write=True)
        for i, value in enumerate(data):
            self._memory[address + i] = value


class _Thread:
    def __init__(self, tid: int) -> None:
        self.tid = tid


def _make_emu(*templates: tuple[int, bytes]) -> _MemoryEmu:
    emu = _MemoryEmu(ptr_size=4)
    for address, data in templates:
        emu.map(address, len(data), writable=False, data=data)
    return emu


def test_register_module_writes_dword_index():
    emu = _make_emu((0x500000, b"\x01\x02\x03\x04"), (0x500010, b"\x05\x06\x07\x08"))
    emu.map(0x600000, 8)
    manager = TlsManager()

    index0 = manager.register_module(
        emu,
        TlsDirectory(start=0x500000, end=0x500004, index_va=0x600000),
        module_name="first",
    )
    index1 = manager.register_module(
        emu,
        TlsDirectory(start=0x500010, end=0x500014, index_va=0x600004),
        module_name="second",
    )

    assert (index0, index1) == (0, 1)
    assert emu.mem_read(0x600000, 4) == struct.pack("<I", 0)
    assert emu.mem_read(0x600004, 4) == struct.pack("<I", 1)


def test_register_module_uses_dword_index_on_64_bit():
    emu = _MemoryEmu(ptr_size=8)
    emu.map(0x500000, 8, writable=False, data=b"\xAA" * 8)
    emu.map(0x600000, 8, data=b"\xAA" * 8)
    manager = TlsManager()

    index = manager.register_module(
        emu,
        TlsDirectory(start=0x500000, end=0x500008, index_va=0x600000),
    )

    assert index == 0
    # Windows/Wine write ULONG indices: exactly four bytes, pointer size is irrelevant.
    assert emu.mem_read(0x600000, 8) == b"\x00\x00\x00\x00\xAA\xAA\xAA\xAA"


def test_two_modules_two_threads_get_isolated_blocks():
    template_a = b"\x11\x22\x33\x44"
    template_b = b"\x55\x66"
    emu = _make_emu((0x500000, template_a), (0x500010, template_b))
    emu.map(0x600000, 8)
    manager = TlsManager()
    manager.register_module(
        emu, TlsDirectory(start=0x500000, end=0x500004, index_va=0x600000), module_name="a"
    )
    manager.register_module(
        emu,
        TlsDirectory(start=0x500010, end=0x500012, index_va=0x600004, zero_fill=2),
        module_name="b",
    )

    array1 = manager.init_thread(emu, _Thread(1))
    array2 = manager.init_thread(emu, _Thread(2))

    assert array1 is not None and array2 is not None
    slot1_a = int.from_bytes(emu.mem_read(array1, 4), "little")
    slot1_b = int.from_bytes(emu.mem_read(array1 + 4, 4), "little")
    slot2_a = int.from_bytes(emu.mem_read(array2, 4), "little")
    slot2_b = int.from_bytes(emu.mem_read(array2 + 4, 4), "little")

    assert len({slot1_a, slot1_b, slot2_a, slot2_b}) == 4
    assert emu.mem_read(slot1_a, 4) == template_a
    assert emu.mem_read(slot1_b, 4) == template_b + b"\x00\x00"
    assert emu.mem_read(slot2_a, 4) == template_a

    # Writing one thread's block must not touch the template or the other thread.
    emu.mem_write(slot1_a + 1, b"\xEE")
    assert emu.mem_read(0x500000, 4) == template_a
    assert emu.mem_read(slot2_a, 4) == template_a
    assert emu.mem_read(slot1_b, 4) == template_b + b"\x00\x00"


def test_init_thread_is_idempotent_and_extends_after_new_module():
    emu = _make_emu((0x500000, b"\x01\x02\x03\x04"), (0x500010, b"\x05\x06\x07\x08"))
    emu.map(0x600000, 12)
    manager = TlsManager()
    manager.register_module(
        emu, TlsDirectory(start=0x500000, end=0x500004, index_va=0x600000), module_name="a"
    )
    thread = _Thread(7)

    array = manager.init_thread(emu, thread)
    maps_after_first = emu.maps_created
    assert manager.init_thread(emu, thread) == array
    assert emu.maps_created == maps_after_first

    old_slot = int.from_bytes(emu.mem_read(array, 4), "little")
    manager.register_module(
        emu, TlsDirectory(start=0x500010, end=0x500014, index_va=0x600004), module_name="b"
    )
    new_array = manager.init_thread(emu, thread)

    assert new_array != array
    assert int.from_bytes(emu.mem_read(new_array, 4), "little") == old_slot
    new_slot = int.from_bytes(emu.mem_read(new_array + 4, 4), "little")
    assert new_slot not in (0, old_slot)
    assert emu.mem_read(new_slot, 4) == b"\x05\x06\x07\x08"


def test_empty_tls_directory_is_not_registered():
    emu = _MemoryEmu(ptr_size=4)
    emu.map(0x600000, 4, data=b"\xAA\xAA\xAA\xAA")
    manager = TlsManager()

    index = manager.register_module(
        emu,
        TlsDirectory(start=0x500000, end=0x500000, index_va=0x600000, callbacks_va=0),
    )

    assert index is None
    assert emu.mem_read(0x600000, 4) == b"\xAA\xAA\xAA\xAA"
    assert manager.init_thread(emu, _Thread(1)) is None


def test_callback_only_directory_gets_slot_but_no_block():
    emu = _MemoryEmu(ptr_size=4)
    emu.map(0x600000, 4, data=b"\xAA\xAA\xAA\xAA")
    manager = TlsManager()

    index = manager.register_module(
        emu,
        TlsDirectory(start=0x500000, end=0x500000, index_va=0x600000, callbacks_va=0x400000),
    )

    assert index == 0
    assert emu.mem_read(0x600000, 4) == b"\x00\x00\x00\x00"
    array = manager.init_thread(emu, _Thread(2))
    assert array is not None
    assert emu.mem_read(array, 4) == b"\x00\x00\x00\x00"


def test_invalid_tls_directory_is_rejected():
    emu = _MemoryEmu(ptr_size=4)
    emu.map(0x600000, 4, data=b"\xAA\xAA\xAA\xAA")
    manager = TlsManager()

    with pytest.raises(TlsError):
        manager.register_module(
            emu,
            TlsDirectory(start=0x500010, end=0x500000, index_va=0x600000),
        )
    assert emu.mem_read(0x600000, 4) == b"\xAA\xAA\xAA\xAA"


def test_missing_index_address_skips_write_but_keeps_slot():
    emu = _MemoryEmu(ptr_size=4)
    emu.map(0x500000, 4, writable=False, data=b"\x10\x20\x30\x40")
    manager = TlsManager()

    index = manager.register_module(
        emu,
        TlsDirectory(start=0x500000, end=0x500004, index_va=0),
    )

    assert index == 0
    array = manager.init_thread(emu, _Thread(3))
    assert array is not None
    slot = int.from_bytes(emu.mem_read(array, 4), "little")
    assert emu.mem_read(slot, 4) == b"\x10\x20\x30\x40"
