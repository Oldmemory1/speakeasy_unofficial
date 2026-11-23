"""FX-005 diagnostic contract tests: runtime API-name resolution / char width.

The work order (``Loader / getprocaddress``) asks for *evidence only*: which
runtime lookup matched an undecorated API name to a handler, what GetProcAddress
returned (a dispatch sentinel), and why the A/W character-width selection then
failed.

Expected behaviour (CSV): a runtime-resolved undecorated API name should follow
Windows semantics (lookup fails / returns NULL); it must not surface an
unhandled ``ApiEmuError`` that derails control flow into a RW data page.  This
FX is ``add_diagnostics`` only, so the semantic gap remains; these tests assert
the *evidence* that makes the gap explainable and assert the pre-existing
behaviour is unchanged.

These tests fail against the pre-FX-005 implementation (no
``api_name_resolution_diagnostic`` observation anywhere).

Observation contract
--------------------
* ``kind="api_name_resolution_diagnostic"``, ``schema_version=1``.
* Attached through the existing ``ctx["_api_observation"]`` channel, which the
  engine reports as ``ApiEvent.observation`` and merges into
  ``ErrorInfo.diagnostics["api_observation"]`` on the handler-error path.
* Read-only: no handler return value, page permission, exception dispatch or
  control-flow change; no sample/address/family special cases.
"""

from __future__ import annotations

import lzma
import struct
from pathlib import Path

import pytest

from speakeasy import Speakeasy
from speakeasy.errors import ApiEmuError
from speakeasy.winenv.api import sigdb

BINS = Path(__file__).resolve().parent / "bins"
PRIMARY_EXE = "seh_test_x86.exe.xz"

OBSERVATION_KIND = "api_name_resolution_diagnostic"
MERGE_KEY = "api_name_resolution_trace"

UNDECORATED = "undecorated_api_name"

_NEXT_STRING_PAGE = [0x1E800000]


def _bin(name: str) -> bytes:
    with lzma.open(BINS / name) as fh:
        return fh.read()


@pytest.fixture
def engine(config):
    """Speakeasy with the test EXE loaded as the primary module."""
    se = Speakeasy(config=config)
    try:
        se.load_module(data=_bin(PRIMARY_EXE))
        yield se
    finally:
        se.shutdown()


def _observation(ctx):
    observation = ctx.get("_api_observation")
    assert isinstance(observation, dict), "handler attached no diagnostic observation"
    assert observation["kind"] == OBSERVATION_KIND
    assert observation["schema_version"] == 1
    return observation


def _scratch(emu, tag) -> int:
    return emu.mem_map(0x1000, tag=tag)


def _alloc_string(emu, text: str) -> int:
    # GetProcAddress treats pointers below 0x10000 as ordinals.
    base = _NEXT_STRING_PAGE[0]
    _NEXT_STRING_PAGE[0] += 0x1000
    addr = emu.mem_map(0x1000, base=base, tag="fx005.test.string")
    emu.mem_write(addr, text.encode("ascii") + b"\x00")
    return addr


class _X86Asm:
    """Minimal x86 emitter: push imm32, mov eax, imm32, call eax, ret."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.patches: list[tuple[int, str]] = []

    def _imm32(self, key: str) -> None:
        offset = len(self.buf)
        self.buf += b"\x00\x00\x00\x00"
        self.patches.append((offset, key))

    def push_imm32(self, value: int) -> None:
        self.buf += b"\x68" + struct.pack("<I", value & 0xFFFFFFFF)

    def push_abs(self, key: str) -> None:
        self.buf += b"\x68"
        self._imm32(key)

    def mov_eax_abs(self, key: str) -> None:
        self.buf += b"\xb8"
        self._imm32(key)

    def call_eax(self) -> None:
        self.buf += b"\xff\xd0"

    def ret(self) -> None:
        self.buf += b"\xc3"


# ---------------------------------------------------------------------------
# Undecorated handler: evidence attached, original ApiEmuError unchanged
# ---------------------------------------------------------------------------


def test_undecorated_get_module_file_name_records_resolution_and_keeps_error(engine):
    emu = engine.emu
    kernel32 = emu.api.load_api_handler("kernel32")
    ctx = {"func_name": "kernel32.GetModuleFileName"}

    # Behaviour baseline: the engine still raises the same ApiEmuError.
    with pytest.raises(ApiEmuError) as excinfo:
        kernel32.GetModuleFileName(emu, [0, 0, 0], ctx)
    assert str(excinfo.value) == "Failed to get character width from function: kernel32.GetModuleFileName"

    observation = _observation(ctx)
    assert observation["api"] == "kernel32.GetModuleFileName"
    assert observation["module"] == "kernel32"
    assert observation["function"] == "GetModuleFileName"
    assert observation["failure"] == UNDECORATED
    assert observation["exception_type"] == "ApiEmuError"
    assert observation["char_width_selection"] == {
        "suffix": None,
        "width": None,
        "derived": False,
        "failure": UNDECORATED,
    }

    # The exact undecorated spelling is registered as a handler, which is why
    # the engine can match a name Windows would reject.
    resolution = observation["handler_resolution"]
    assert resolution["available"] is True
    assert resolution["resolution_path"] == "exact_handler"
    assert resolution["handler_registration"] == "undecorated"
    assert resolution["handler_impname"] == "GetModuleFileName"
    assert resolution["exact_registered"] is True
    assert resolution["aw_folded_registered"] is False

    # The synthetic module export table exposes the undecorated name plus the
    # real Windows A/W spellings; signature lookup only knows the A/W variants.
    membership = observation["module_export_membership"]
    assert membership["module_found"] is True
    assert membership["module_name"].lower().startswith("kernel32")
    assert membership["exact_present"] is True
    assert membership["aliases_present"] == ["GetModuleFileNameA", "GetModuleFileNameW"]
    signatures = observation["signature_resolution"]
    assert "exact" in signatures and "aliases" in signatures
    if signatures["available"]:
        assert signatures["exact"] is None
        assert signatures["aliases"]["GetModuleFileNameA"] is not None

    # Direct handler calls have no import-table sentinel behind them.
    dispatch = observation["dispatch_provenance"]
    assert dispatch["dispatch_kind"] == "direct_handler_call"
    assert dispatch["sentinel_target"] is None

    semantics = observation["windows_semantics"]
    assert semantics["undecorated_name_with_aw_aliases"] is True
    assert semantics["char_width_policy"] == "requires_A_or_W_suffix"
    if signatures["available"]:
        assert semantics["exact_signature_known"] is False
        assert semantics["decorated_signature_known"] is True
        assert semantics["expected_get_proc_address"] == "NULL"
    else:
        assert semantics["expected_get_proc_address"] == "unknown"


def test_undecorated_get_system_directory_records_error_without_role_change(engine):
    emu = engine.emu
    kernel32 = emu.api.load_api_handler("kernel32")
    ctx = {"func_name": "kernel32.GetSystemDirectory"}

    with pytest.raises(ApiEmuError):
        kernel32.GetSystemDirectory(emu, [0x2000, 0x100], ctx)

    observation = _observation(ctx)
    assert observation["function"] == "GetSystemDirectory"
    assert observation["failure"] == UNDECORATED
    assert observation["handler_resolution"]["resolution_path"] == "exact_handler"
    assert observation["module_export_membership"]["exact_present"] is True
    assert set(observation["module_export_membership"]["aliases_present"]) == {
        "GetSystemDirectoryA",
        "GetSystemDirectoryW",
    }


def test_undecorated_get_user_name_reports_advapi32_export_chain(engine):
    emu = engine.emu
    advapi32 = emu.api.load_api_handler("advapi32")
    ctx = {"func_name": "advapi32.GetUserName"}

    with pytest.raises(ApiEmuError) as excinfo:
        advapi32.GetUserName(emu, [0, 0], ctx)
    assert "Failed to get character width" in str(excinfo.value)

    observation = _observation(ctx)
    assert observation["module"] == "advapi32"
    assert observation["module_export_membership"]["exact_present"] is True
    assert observation["handler_resolution"]["handler_registration"] == "undecorated"
    assert observation["windows_semantics"]["undecorated_name_with_aw_aliases"] is True


# ---------------------------------------------------------------------------
# Counterexample: true A/W resolution keeps its width and existing behaviour
# ---------------------------------------------------------------------------


def test_decorated_get_system_directory_keeps_width_and_return(engine):
    emu = engine.emu
    kernel32 = emu.api.load_api_handler("kernel32")
    buf = _scratch(emu, "fx005.test.ansi")

    ctx = {"func_name": "kernel32.GetSystemDirectoryA"}
    rv = kernel32.GetSystemDirectory(emu, [buf, 0x100], ctx)
    assert rv == 20
    assert bytes(emu.mem_read(buf, 20)) == b"C:\\Windows\\system32\x00"
    observation = _observation(ctx)
    assert observation["char_width_selection"] == {
        "suffix": "A",
        "width": 1,
        "derived": True,
        "failure": None,
    }
    assert observation["handler_resolution"]["resolution_path"] == "aw_folded_handler"
    assert observation["handler_resolution"]["handler_registration"] == "undecorated"

    buf_w = _scratch(emu, "fx005.test.wide")
    ctx_w = {"func_name": "kernel32.GetSystemDirectoryW"}
    rv_w = kernel32.GetSystemDirectory(emu, [buf_w, 0x100], ctx_w)
    assert rv_w == 20
    wide = bytes(emu.mem_read(buf_w, 42)).decode("utf-16le")
    assert wide.split("\x00", 1)[0] == "C:\\Windows\\system32"
    observation_w = _observation(ctx_w)
    assert observation_w["char_width_selection"] == {
        "suffix": "W",
        "width": 2,
        "derived": True,
        "failure": None,
    }


def test_wvsprintf_width_is_unchanged_for_decorated_name(engine):
    emu = engine.emu
    user32 = emu.api.load_api_handler("user32")

    assert user32.get_char_width({"func_name": "user32.wvsprintfA"}) == 1
    with pytest.raises(ApiEmuError):
        user32.get_char_width({"func_name": "user32.wvsprintf"})


# ---------------------------------------------------------------------------
# Runtime chain: GetProcAddress sentinel -> handler -> width failure
# ---------------------------------------------------------------------------


def _api_events(report, api_name):
    events = report.entry_points[0].events or []
    return [
        event
        for event in events
        if getattr(event, "event", None) == "api" and getattr(event, "api_name", None) == api_name
    ]


def test_dynamic_get_proc_address_chain_records_sentinel_provenance(config):
    se = Speakeasy(config=config)
    try:
        asm = _X86Asm()
        asm.push_abs("name")
        asm.push_abs("kernel32")
        asm.mov_eax_abs("get_proc_address")
        asm.call_eax()
        # Call the FARPROC returned in EAX with GetModuleFileName(h=0, buf=0, n=0).
        asm.push_imm32(0)
        asm.push_imm32(0)
        asm.push_imm32(0)
        asm.call_eax()
        asm.push_imm32(0)
        asm.mov_eax_abs("exit_process")
        asm.call_eax()
        asm.ret()

        code = bytes(asm.buf)
        sc_addr = se.load_shellcode(data=code, arch="x86")
        emu = se.emu
        assert emu is not None
        name_addr = _alloc_string(emu, "GetModuleFileName")
        kernel32 = emu.get_mod_by_name("kernel32")
        assert kernel32 is not None
        values = {
            "name": name_addr,
            "kernel32": kernel32.base,
            "get_proc_address": emu.get_proc("kernel32", "GetProcAddress"),
            "exit_process": emu.get_proc("kernel32", "ExitProcess"),
        }
        assert all(values.values())
        for offset, key in asm.patches:
            emu.mem_write(sc_addr + offset, struct.pack("<I", values[key] & 0xFFFFFFFF))

        se.run_shellcode(sc_addr)
        report = se.get_report()
    finally:
        se.shutdown()

    entry = report.entry_points[0]
    error = entry.error
    assert error is not None
    assert "Failed to get character width" in str(error.type)

    # GetProcAddress returned a non-NULL dispatch sentinel (the semantic gap:
    # Windows would return NULL for this undecorated spelling).
    gpa_events = _api_events(report, "kernel32.GetProcAddress")
    assert gpa_events, "no GetProcAddress event recorded"
    gpa_event = gpa_events[-1]
    gpa_observation = gpa_event.observation
    assert isinstance(gpa_observation, dict)
    sentinel_hex = gpa_observation.get("return_value")
    assert sentinel_hex and int(sentinel_hex, 16) != 0

    # The handler-error path folds the width observation into the report.
    assert isinstance(error.diagnostics, dict)
    observation = error.diagnostics.get("api_observation")
    assert isinstance(observation, dict)
    assert observation["kind"] == OBSERVATION_KIND
    assert observation["api"] == "kernel32.GetModuleFileName"
    assert observation["failure"] == UNDECORATED

    dispatch = observation["dispatch_provenance"]
    assert dispatch["dispatch_kind"] == "import_table_sentinel"
    assert dispatch["sentinel"] == sentinel_hex
    assert dispatch["sentinel_target"] == {"module": "kernel32", "function": "GetModuleFileName"}

    assert observation["module_export_membership"]["exact_present"] is True
    assert observation["handler_resolution"]["resolution_path"] == "exact_handler"
    assert observation["handler_resolution"]["handler_registration"] == "undecorated"
    semantics = observation["windows_semantics"]
    assert semantics["undecorated_name_with_aw_aliases"] is True
    if observation["signature_resolution"]["available"]:
        assert semantics["expected_get_proc_address"] == "NULL"


# ---------------------------------------------------------------------------
# Counterexample: unrelated lookup paths keep original behaviour, no observation
# ---------------------------------------------------------------------------


def test_primary_image_export_miss_returns_null_without_char_width_observation(engine):
    emu = engine.emu
    primary = next(mod for mod in emu.modules if mod.is_exe())
    kernel32 = emu.api.load_api_handler("kernel32")
    name_addr = _alloc_string(emu, "NoSuchFx005Export")
    ctx = {"func_name": "kernel32.GetProcAddress"}

    rv = kernel32.GetProcAddress(emu, [primary.base, name_addr], ctx)
    assert rv == 0  # Windows semantics for a genuinely missing export.

    observation = ctx.get("_api_observation")
    assert isinstance(observation, dict), "FX-004 GetProcAddress provenance must stay attached"
    assert observation.get("kind") != OBSERVATION_KIND
    assert MERGE_KEY not in observation


# ---------------------------------------------------------------------------
# Diagnostic helper robustness / merge / signature variant lookup
# ---------------------------------------------------------------------------


def test_observe_char_width_is_defensive_without_engine():
    from speakeasy.windows import api_name_resolution_diagnostics as diagnostics

    ctx: dict = {}
    observation = diagnostics.observe_char_width(
        object(),
        ctx,
        "kernel32.GetModuleFileName",
        failure=UNDECORATED,
    )
    assert isinstance(observation, dict)
    assert observation["kind"] == OBSERVATION_KIND
    assert observation["handler_resolution"]["available"] is False
    assert observation["module_export_membership"]["module_found"] is False
    assert observation["signature_resolution"]["available"] is False
    assert observation["dispatch_provenance"]["dispatch_kind"] == "unknown"
    assert ctx["_api_observation"]["kind"] == OBSERVATION_KIND

    # No ctx: nothing is attached and nothing is raised.
    assert diagnostics.observe_char_width(object(), None, "kernel32.GetModuleFileName") is None


def test_observe_char_width_preserves_existing_observation():
    from speakeasy.windows import api_name_resolution_diagnostics as diagnostics

    existing = {"kind": "scatter_diagnostic", "marker": 1}
    ctx = {"func_name": "kernel32.GetModuleFileName", "_api_observation": existing}
    observation = diagnostics.observe_char_width(
        object(),
        ctx,
        "kernel32.GetModuleFileName",
        failure=UNDECORATED,
    )
    assert isinstance(observation, dict)
    assert ctx["_api_observation"] is existing
    assert existing["kind"] == "scatter_diagnostic"
    assert existing["marker"] == 1
    nested = existing[MERGE_KEY]
    assert nested["kind"] == OBSERVATION_KIND


def test_sigdb_name_variants_expose_only_decorated_spellings():
    database = sigdb.get_default_database()
    if not database.available:
        pytest.skip("bundled signature database is not provisioned")

    variants = sigdb.lookup_name_variants(database, "kernel32", "GetModuleFileName", "x86")
    assert set(variants) == {
        "GetModuleFileName",
        "GetModuleFileNameA",
        "GetModuleFileNameW",
    }
    assert variants["GetModuleFileName"] is None
    assert variants["GetModuleFileNameA"] is not None
    assert variants["GetModuleFileNameA"].name == "GetModuleFileNameA"
    # Variant lookup must not change the existing matching semantics.
    assert (
        database.lookup("kernel32", "GetModuleFileNameA", "x86")
        is variants["GetModuleFileNameA"]
    )

    decorated = sigdb.lookup_name_variants(database, "kernel32", "GetModuleFileNameW", "x86")
    assert set(decorated) == {"GetModuleFileNameW", "GetModuleFileName"}
    assert decorated["GetModuleFileNameW"] is not None
    assert decorated["GetModuleFileName"] is None
