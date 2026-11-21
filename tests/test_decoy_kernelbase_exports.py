"""Contract tests for the synthesized kernelbase decoy export table (FX-013-extended).

``Loader / getprocaddress|getmodulehandle|loadlibrary`` follow-on: FX-014
synthesizes an export-table decoy for known-but-unmodelled system DLLs, but
``default_decoy_exports`` only exported the DLL stem.  A real Windows 7+
``kernelbase.dll`` implements the kernel32 API surface and exports
``GetProcAddress`` plus common module/memory/heap/error entry points.  Packers
such as the ``ae4de565`` sample walk the PEB module list and the PE export
directory by hand; a one-entry kernelbase table makes that walk underflow into
the export directory's ``TimeDateStamp`` and fault.

These tests inspect the real export-directory bytes of the mapped decoy image
(the same bytes a guest walker reads) and the engine's existing
``GetProcAddress`` contract.  They do not run batch samples.
"""

from __future__ import annotations

import logging
import struct

import pytest

from speakeasy import Speakeasy
from speakeasy.windows import common as wincommon
from speakeasy.windows.system_modules import (
    SystemModuleDecoyLoader,
    default_decoy_exports,
    is_synthesizable_system_module,
)
from speakeasy.winenv import arch as e_arch

KERNELBASE_BASE = 0x6F000000
KERNELBASE_PATH = r"C:\Windows\system32\kernelbase.dll"
DECOY_STEM = "kernelbase"

# The ae4de565 walker compares only the first eight bytes of each export name:
# ``mov eax, 0x50746547`` ("GetP") and ``mov eax, 0x41636f72`` ("rocA").
SAMPLE_EXPORT_PREFIX = b"GetProcA"

_NEXT_STRING_PAGE = [0x1E100000]


class _ExportDirectory:
    """Minimal IMAGE_EXPORT_DIRECTORY view over a memory-mapped PE image."""

    def __init__(self, image_data: bytes) -> None:
        self.data = image_data
        e_lfanew = struct.unpack_from("<I", image_data, 0x3C)[0]
        assert image_data[e_lfanew : e_lfanew + 4] == b"PE\x00\x00"
        coff = e_lfanew + 4
        optional_header = coff + 20
        magic = struct.unpack_from("<H", image_data, optional_header)[0]
        # DataDirectory follows the fixed OptionalHeader fields.
        data_dir_offset = optional_header + (96 if magic == 0x10B else 112)
        self.rva, self.size = struct.unpack_from("<II", image_data, data_dir_offset)
        assert self.rva and self.size, "decoy image must have an export directory"

        (
            self.characteristics,
            self.time_date_stamp,
            _major,
            _minor,
            self.name_rva,
            self.base,
            self.number_of_functions,
            self.number_of_names,
            self.address_of_functions,
            self.address_of_names,
            self.address_of_name_ordinals,
        ) = struct.unpack_from("<IIHHIIIIIII", image_data, self.rva)

    def name_at(self, index: int) -> str:
        name_rva = struct.unpack_from("<I", self.data, self.address_of_names + index * 4)[0]
        assert name_rva < len(self.data), f"name RVA {name_rva:#x} escapes the mapped image"
        end = self.data.index(b"\x00", name_rva)
        return self.data[name_rva:end].decode("ascii")

    def names(self) -> list[str]:
        return [self.name_at(index) for index in range(self.number_of_names)]

    def module_name(self) -> str:
        end = self.data.index(b"\x00", self.name_rva)
        return self.data[self.name_rva:end].decode("ascii")


def _decoy_image(name: str, arch: int) -> object:
    loader = SystemModuleDecoyLoader(
        name=name,
        arch=arch,
        base=KERNELBASE_BASE,
        emu_path=f"C:\\Windows\\system32\\{name}.dll",
    )
    return loader.make_image()


def _sample_walker(image_data: bytes, image_base: int, prefix: bytes) -> dict:
    """Replay the ae4de565 manual export-name walk over *image_data*.

    The guest scans ``AddressOfNames`` from ``NumberOfNames-1`` down to zero.
    Its loop has no lower-bound check, so a miss decrements ``ECX`` below zero
    and reads the export directory's ``TimeDateStamp`` as a name RVA.  Report
    that underflow address when it happens; the fix must make the match occur
    before it.
    """
    exports = _ExportDirectory(image_data)
    ecx = exports.number_of_names - 1
    while ecx >= 0:
        name = exports.name_at(ecx)
        if name.encode("ascii")[: len(prefix)] == prefix:
            return {"index": ecx, "name": name, "underflow_address": None}
        ecx -= 1

    underflow_address = (exports.time_date_stamp + image_base) & 0xFFFFFFFF
    return {"index": ecx, "name": None, "underflow_address": underflow_address}


def _engine(config) -> Speakeasy:
    """Speakeasy with a minimal shellcode module so bootstrap loads core DLLs."""
    se = Speakeasy(config=config)
    se.load_shellcode(data=b"\xc3", arch="x86")
    return se


def _kernel32(emu):
    return emu.api.load_api_handler("kernel32")


def _alloc_string(emu, text: str) -> int:
    base = _NEXT_STRING_PAGE[0]
    _NEXT_STRING_PAGE[0] += 0x1000
    addr = emu.mem_map(0x1000, base=base, tag="fx013ext.test")
    emu.mem_write(addr, text.encode("ascii") + b"\x00")
    return addr


def _get_proc_address(emu, hmod: int, name: str) -> int:
    name_ptr = _alloc_string(emu, name)
    return _kernel32(emu).GetProcAddress(emu, [hmod, name_ptr], None)


def _load_library(emu, name: str) -> int:
    name_ptr = _alloc_string(emu, name)
    return _kernel32(emu).LoadLibrary(emu, [name_ptr], {"func_name": "kernel32.LoadLibraryA"})


def _log_text(caplog) -> str:
    return "\n".join(record.getMessage() for record in caplog.records)


def test_default_decoy_exports_kernelbase_has_standard_surface():
    exports = default_decoy_exports("kernelbase")

    assert "GetProcAddress" in exports
    # The legacy structural placeholder (the DLL stem) is preserved.
    assert DECOY_STEM in exports
    assert len(exports) > 1
    assert all(exports)
    assert len(set(exports)) == len(exports)

    # Name matching is by DLL stem, so paths and casing behave identically.
    assert default_decoy_exports("KERNELBASE.DLL") == exports
    assert default_decoy_exports(KERNELBASE_PATH) == exports


@pytest.mark.parametrize("name", ["msjava", "MSJAVA.DLL", "sechost", "msvcr71", "fx013ext_not_a_module"])
def test_default_decoy_exports_fallback_preserved(name):
    stem = name.lower()
    if stem.endswith(".dll"):
        stem = stem[: -len(".dll")]
    assert default_decoy_exports(name) == (stem,)


def test_default_decoy_exports_empty_name_returns_empty():
    assert default_decoy_exports("") == ()
    assert default_decoy_exports(r"C:\Windows\system32\\") == ()


@pytest.mark.parametrize("arch", [e_arch.ARCH_X86, e_arch.ARCH_AMD64], ids=["x86", "x64"])
def test_kernelbase_decoy_export_directory_exposes_get_proc_address(arch):
    image = _decoy_image(DECOY_STEM, arch)
    assert image.image_base == KERNELBASE_BASE
    assert len(image.regions) == 1

    exports = _ExportDirectory(image.regions[0].data)

    assert exports.module_name() == DECOY_STEM
    assert exports.number_of_names == len(image.exports)
    names = exports.names()
    assert "GetProcAddress" in names
    assert DECOY_STEM in names
    assert len(names) > 1


@pytest.mark.parametrize("arch", [e_arch.ARCH_X86, e_arch.ARCH_AMD64], ids=["x86", "x64"])
def test_manual_export_walker_resolves_get_proc_address(arch):
    image = _decoy_image(DECOY_STEM, arch)

    result = _sample_walker(image.regions[0].data, image.image_base, SAMPLE_EXPORT_PREFIX)

    assert result["underflow_address"] is None
    assert result["index"] >= 0
    assert result["name"] == "GetProcAddress"


def test_unknown_export_stays_absent_from_kernelbase_decoy():
    image = _decoy_image(DECOY_STEM, e_arch.ARCH_X86)
    missing = "Fx013ExtNotAnExport"

    assert all(exp.name != missing for exp in image.exports)
    assert missing not in _ExportDirectory(image.regions[0].data).names()


def test_unknown_module_is_still_not_synthesized(config):
    from speakeasy.config import get_default_config

    name = "fx013ext_definitely_not_a_system_dll"
    patterns = get_default_config().modules.synthesized_system_modules
    assert "kernelbase" in patterns
    assert not is_synthesizable_system_module(name, patterns)

    se = _engine(config)
    try:
        emu = se.emu
        rv = _load_library(emu, name)
        assert rv == 0
        assert emu.get_mod_by_name(name) is None
    finally:
        se.shutdown()


def test_get_proc_address_null_hmod_still_returns_zero_with_log(config, caplog):
    se = _engine(config)
    try:
        emu = se.emu
        with caplog.at_level(logging.INFO):
            rv = _get_proc_address(emu, 0, "GetProcAddress")

        assert rv == 0
        text = _log_text(caplog)
        assert "hmod=0x0" in text
        assert "GetProcAddress" in text
        assert "modules=" in text
    finally:
        se.shutdown()


def test_engine_resolves_kernelbase_get_proc_address_through_export_table(config, caplog):
    se = _engine(config)
    try:
        emu = se.emu
        assert _load_library(emu, DECOY_STEM) != 0
        kernelbase = emu.get_mod_by_name(DECOY_STEM)
        assert kernelbase is not None
        # The module's own export table must name the export; the engine's
        # missing-export sentinel path (FX-013) is a different branch.
        assert kernelbase.get_export_by_name("GetProcAddress") is not None

        with caplog.at_level(logging.INFO):
            rv = _get_proc_address(emu, kernelbase.base, "GetProcAddress")

        assert rv != 0
        assert wincommon.EMU_RESERVED <= rv < wincommon.EMU_RESERVED_END
        assert "absent from the module export table" not in _log_text(caplog)
    finally:
        se.shutdown()


def test_engine_missing_export_of_kernelbase_decoy_keeps_sentinel_semantics(config, caplog):
    se = _engine(config)
    try:
        emu = se.emu
        assert _load_library(emu, DECOY_STEM) != 0
        kernelbase = emu.get_mod_by_name(DECOY_STEM)
        assert kernelbase is not None
        missing = "Fx013ExtNotAnExport"

        with caplog.at_level(logging.INFO):
            rv = _get_proc_address(emu, kernelbase.base, missing)

        # FX-013 fixF: a missing export of an already loaded non-EXE module is
        # an engine coverage gap and resolves through the dispatch sentinel.
        assert rv != 0
        assert wincommon.EMU_RESERVED <= rv < wincommon.EMU_RESERVED_END
        text = _log_text(caplog)
        assert "sentinel" in text.lower()
        assert missing in text
    finally:
        se.shutdown()


def test_existing_msjava_decoy_still_exposes_structural_export():
    image = _decoy_image("msjava", e_arch.ARCH_X86)
    names = _ExportDirectory(image.regions[0].data).names()

    assert names == ["msjava"]
    assert len(image.exports) == 1


def test_decoy_api_handler_module_is_explicit():
    kernelbase_loader = SystemModuleDecoyLoader(
        name=DECOY_STEM,
        arch=e_arch.ARCH_X86,
        base=KERNELBASE_BASE,
        emu_path=KERNELBASE_PATH,
    )
    msjava_loader = SystemModuleDecoyLoader(
        name="msjava",
        arch=e_arch.ARCH_X86,
        base=KERNELBASE_BASE,
        emu_path=r"C:\Windows\system32\msjava.dll",
    )

    # kernelbase implements the kernel32 API surface; unmodelled decoys have
    # no backing handler and remain structural placeholders.
    assert kernelbase_loader.api_handler_module == "kernel32"
    assert msjava_loader.api_handler_module is None


def test_kernelbase_export_stubs_dispatch_to_kernel32_handlers(config):
    se = _engine(config)
    try:
        emu = se.emu
        assert _load_library(emu, DECOY_STEM) != 0
        kernelbase = emu.get_mod_by_name(DECOY_STEM)
        assert kernelbase is not None

        for name in ("GetProcAddress", "VirtualAlloc", "GetLastError", "LoadLibraryA"):
            entry = kernelbase.get_export_by_name(name)
            assert entry is not None, name
            # Direct calls to the hand-resolved export must dispatch through
            # the engine's intercepted-export path, not the placeholder stub.
            assert emu.symbols.get(entry.address) == ("kernel32", name), name
    finally:
        se.shutdown()


def test_get_proc_address_on_kernelbase_export_returns_kernel32_sentinel(config):
    se = _engine(config)
    try:
        emu = se.emu
        assert _load_library(emu, DECOY_STEM) != 0
        kernelbase = emu.get_mod_by_name(DECOY_STEM)
        assert kernelbase is not None

        rv = _get_proc_address(emu, kernelbase.base, "LoadLibraryA")

        assert rv != 0
        assert wincommon.EMU_RESERVED <= rv < wincommon.EMU_RESERVED_END
        # The sentinel must be keyed to the handler module, otherwise the
        # guest's call would fall through as an unbacked "kernelbase" miss.
        assert emu.import_table[rv] == ("kernel32", "LoadLibraryA")
    finally:
        se.shutdown()
