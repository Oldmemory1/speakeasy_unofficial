"""Contract tests for the FX-013 dynamic loader resolution chain.

``Loader / getprocaddress|getmodulehandle|loadlibrary`` covers the runtime
module lookup used by package loaders:

* ``GetProcAddress`` must record ``hmod``/``lpProcName`` (and the loaded module
  candidates) when it cannot resolve a name, return NULL for a NULL handle or a
  missing export of the primary EXE, and keep returning a dispatch sentinel for
  handler-backed modules.
* A missing export of an already loaded non-EXE module is an emulator
  coverage gap, not a NULL: the engine returns an import sentinel that
  dispatches through the existing signature/handler path.
* ``GetProcAddress`` on a real PE module (loaded from a native path or a
  guest-visible file) returns the export's mapped code address, so the guest
  executes the module's own code as on Windows.
* ``LoadLibrary`` loads a PE that already exists in the emulated filesystem
  (packers drop/unpack a DLL and call ``LoadLibraryA`` on the path). Known
  system DLLs keep using FX-014's synthesized decoys; genuinely unknown names
  and non-PEY files still return NULL with a readable diagnostic.

The tests call the real handlers through the engine; no batch sample runs.
"""

from __future__ import annotations

import logging
import lzma
from pathlib import Path

import pytest

from speakeasy import Speakeasy
from speakeasy.windows import common as wincommon

BINS = Path(__file__).resolve().parent / "bins"
PRIMARY_EXE = "seh_test_x86.exe.xz"
TEST_DLL = "dll_test_x86.dll.xz"

SYSTEM_DLLS = [
    "KERNEL32.dll",
    "USER32.dll",
    "GDI32.dll",
    "ADVAPI32.dll",
    "SHELL32.dll",
    "ole32.dll",
    "SHLWAPI.dll",
    "WININET.dll",
    "iphlpapi.dll",
    "PSAPI.dll",
    "WS2_32.dll",
]

DROP_PATH = r"C:\Windows\temp\fx013_dropped.dll"
BAD_PE_PATH = r"C:\Windows\temp\fx013_bad.dll"
EMPTY_PATH = r"C:\Windows\temp\fx013_empty.dll"

DROPPED_EXPORT_ONE_RVA = 0x1030


def _bin(name: str) -> bytes:
    with lzma.open(BINS / name) as fh:
        return fh.read()


@pytest.fixture
def engine(config):
    """Speakeasy with the test EXE loaded as the primary (is_exe) module."""
    se = Speakeasy(config=config)
    try:
        se.load_module(data=_bin(PRIMARY_EXE))
        yield se
    finally:
        se.shutdown()


_NEXT_STRING_PAGE = [0x1E000000]


def _alloc_string(emu, text: str) -> int:
    # GetProcAddress treats pointers below 0x10000 as ordinals (Windows
    # MAKEINTRESOURCE semantics), so test strings must live above that range.
    base = _NEXT_STRING_PAGE[0]
    _NEXT_STRING_PAGE[0] += 0x1000
    addr = emu.mem_map(0x1000, base=base, tag="fx013.test")
    emu.mem_write(addr, text.encode("ascii") + b"\x00")
    return addr


def _kernel32(emu):
    return emu.api.load_api_handler("kernel32")


def _load_library(emu, name: str) -> int:
    name_ptr = _alloc_string(emu, name)
    return _kernel32(emu).LoadLibrary(emu, [name_ptr], {"func_name": "kernel32.LoadLibraryA"})


def _get_proc_address(emu, hmod: int, name: str) -> int:
    name_ptr = _alloc_string(emu, name)
    return _kernel32(emu).GetProcAddress(emu, [hmod, name_ptr], None)


def _log_text(caplog) -> str:
    return "\n".join(record.getMessage() for record in caplog.records)


def _primary_exe(emu):
    for mod in emu.modules:
        if mod.is_exe():
            return mod
    raise AssertionError("primary EXE module is not loaded")


def test_get_proc_address_null_hmod_returns_zero_and_records_parameters(engine, caplog):
    emu = engine.emu
    with caplog.at_level(logging.INFO):
        rv = _get_proc_address(emu, 0, "CreateFileA")

    assert rv == 0
    text = _log_text(caplog)
    assert "GetProcAddress" in text
    assert "hmod=0x0" in text
    assert "CreateFileA" in text
    # The readable trace should say which modules were considered, not just 0.
    assert "modules=" in text


def test_get_proc_address_missing_export_of_loaded_dll_returns_sentinel(engine, caplog):
    emu = engine.emu
    kernel32 = emu.get_mod_by_name("kernel32")
    assert kernel32 is not None and not kernel32.is_exe()

    with caplog.at_level(logging.INFO):
        rv = _get_proc_address(emu, kernel32.base, "Fx013NotAnExport")

    assert rv != 0
    assert wincommon.EMU_RESERVED <= rv < wincommon.EMU_RESERVED_END
    text = _log_text(caplog)
    assert "sentinel" in text.lower()
    assert "Fx013NotAnExport" in text


def test_get_proc_address_missing_export_of_primary_exe_returns_zero(engine, caplog):
    emu = engine.emu
    exe = _primary_exe(emu)

    with caplog.at_level(logging.INFO):
        rv = _get_proc_address(emu, exe.base, "Fx013NotAnExport")

    assert rv == 0
    assert "Fx013NotAnExport" in _log_text(caplog)


@pytest.mark.parametrize("dll_name", SYSTEM_DLLS)
def test_load_library_known_system_dll_returns_module(engine, dll_name):
    emu = engine.emu
    base_name = dll_name.lower()
    for suffix in (".dll", ".DLL"):
        if base_name.endswith(suffix):
            base_name = base_name[: -len(suffix)]
            break

    rv = _load_library(emu, dll_name)

    assert rv != 0
    mod = emu.get_mod_by_name(base_name)
    assert mod is not None
    assert mod.base == rv


def test_load_library_unknown_dll_returns_zero_and_records_name(engine, caplog):
    emu = engine.emu
    name = "fx013_definitely_not_a_system_dll"

    with caplog.at_level(logging.INFO):
        rv = _load_library(emu, name)

    assert rv == 0
    assert emu.get_mod_by_name(name) is None
    assert name in _log_text(caplog)
    assert _log_text(caplog).lower().count("loadlibrary") >= 1


def test_load_library_loads_guest_dropped_pe_file(engine, caplog):
    emu = engine.emu
    emu.fileman.add_existing_file(DROP_PATH, _bin(TEST_DLL))

    with caplog.at_level(logging.INFO):
        hmod = _load_library(emu, DROP_PATH)

    assert hmod != 0
    assert "not a loadable PE" not in _log_text(caplog)
    mod = emu.get_mod_by_name("fx013_dropped")
    assert mod is not None
    assert mod.base == hmod
    assert not mod.is_exe()


def test_get_proc_address_returns_real_export_address_for_pe_module(engine):
    emu = engine.emu
    emu.fileman.add_existing_file(DROP_PATH, _bin(TEST_DLL))
    hmod = _load_library(emu, DROP_PATH)
    assert hmod != 0

    rv = _get_proc_address(emu, hmod, "emu_test_one")

    assert rv == hmod + DROPPED_EXPORT_ONE_RVA
    # A real code address is outside the emulator's import-sentinel range.
    assert not (wincommon.EMU_RESERVED <= rv < wincommon.EMU_RESERVED_END)


def test_get_proc_address_missing_export_of_guest_dll_returns_sentinel(engine, caplog):
    emu = engine.emu
    emu.fileman.add_existing_file(DROP_PATH, _bin(TEST_DLL))
    hmod = _load_library(emu, DROP_PATH)
    assert hmod != 0

    with caplog.at_level(logging.INFO):
        rv = _get_proc_address(emu, hmod, "Fx013MissingFromDroppedDll")

    assert rv != 0
    assert wincommon.EMU_RESERVED <= rv < wincommon.EMU_RESERVED_END
    assert "sentinel" in _log_text(caplog).lower()


def test_load_library_guest_non_pe_file_returns_zero_and_records_reason(engine, caplog):
    emu = engine.emu
    emu.fileman.add_existing_file(BAD_PE_PATH, b"MZ" + b"\x00" * 0x40)

    with caplog.at_level(logging.INFO):
        rv = _load_library(emu, BAD_PE_PATH)

    assert rv == 0
    assert emu.get_mod_by_name("fx013_bad") is None
    text = _log_text(caplog)
    assert BAD_PE_PATH in text or "fx013_bad" in text
    assert "not a loadable PE" in text


def test_load_library_guest_empty_file_returns_zero(engine):
    emu = engine.emu
    emu.fileman.add_existing_file(EMPTY_PATH, b"")

    assert _load_library(emu, EMPTY_PATH) == 0
    assert emu.get_mod_by_name("fx013_empty") is None


def test_adjacent_loader_paths_unchanged(engine):
    emu = engine.emu
    kernel32 = emu.get_mod_by_name("kernel32")
    assert kernel32 is not None

    # Existing export of a handler-backed module still resolves to a sentinel.
    proc = _get_proc_address(emu, kernel32.base, "CreateFileA")
    assert proc != 0
    assert wincommon.EMU_RESERVED <= proc < wincommon.EMU_RESERVED_END

    # Re-loading an already loaded module returns its existing base.
    assert _load_library(emu, "kernel32.dll") == kernel32.base
