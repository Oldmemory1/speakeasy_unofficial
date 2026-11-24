"""Contract tests for the selective fixO port.

The port adds six handlers to the user-mode API surface and fixes one:

* ``kernel32.TryAcquireSRWLockExclusive``;
* ``kernel32.WriteConsoleA`` / ``kernel32.WriteConsoleW``;
* ``kernel32.WritePrivateProfileStringA`` / ``kernel32.WritePrivateProfileStringW``;
* ``user32.SystemParametersInfoW``.

Each test calls the handler directly through ``tests.handler_harness`` and asserts
the guest-visible contract: return value, out-parameters, report display and
LastError. No environment switches, monkeypatching, address or sample
special-casing, ``skip`` or ``xfail`` are used.
"""

from __future__ import annotations

import struct
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from speakeasy import Speakeasy
from speakeasy.winenv.defs.windows import windows as windefs
from tests.handler_harness import alloc, call, load_emu, start_process

LAST_ERROR_SENTINEL = 0xDEAD
SPI_GETSCREENSAVEACTIVE = 0x0010
SPI_GETWORKAREA = 0x0030
SPI_GETSCREENSAVERRUNNING = 0x0072
UNKNOWN_SPI_ACTION = 0x9999


def _dword(se: Speakeasy, addr: int) -> int:
    return int.from_bytes(se.mem_read(addr, 4), "little")


@pytest.fixture(params=["dll_emu", "dll64_emu"])
def win_emu(request: pytest.FixtureRequest) -> Speakeasy:
    """Run the test against the x86 and x64 user-mode DLL emulators."""
    return request.getfixturevalue(request.param)


@pytest.fixture(params=["dll_test_x86.dll.xz", "dll_test_x64.dll.xz"])
def custom_ui_emu(
    request: pytest.FixtureRequest,
    config: dict[str, Any],
    load_test_bin: Callable[[str], bytes],
) -> Iterator[Speakeasy]:
    """Load an emulator whose UI profile reports a 1600x900 screen."""
    config["ui"] = {"profile": "custom", "screen_width": 1600, "screen_height": 900}
    yield from load_emu(config, load_test_bin(request.param))


def _ansi(se: Speakeasy, text: str) -> int:
    return alloc(se, text.encode("ascii") + b"\x00")


def _wide(se: Speakeasy, text: str) -> int:
    return alloc(se, text.encode("utf-16le") + b"\x00\x00")


def test_write_console_a_writes_the_character_count_and_displays_text(win_emu: Speakeasy) -> None:
    """WriteConsoleA delegates to WriteConsole with ANSI width (requirement 1)."""
    se = win_emu
    start_process(se)
    text = b"hello"
    written = alloc(se, b"\xcc" * 4)
    rv, displays = call(se, "kernel32", "WriteConsoleA", [1, alloc(se, text), len(text), written, 0])
    assert rv == 1
    assert _dword(se, written) == len(text)
    assert displays["lpBuffer"] == repr("hello")


def test_write_console_w_decodes_utf16_characters(win_emu: Speakeasy) -> None:
    """WriteConsoleW selects UTF-16 width, so the display shows the decoded text (requirement 2)."""
    se = win_emu
    start_process(se)
    text = "héllo"
    data = text.encode("utf-16le")
    written = alloc(se, b"\xcc" * 4)
    rv, displays = call(se, "kernel32", "WriteConsoleW", [1, alloc(se, data), len(text), written, 0])
    assert rv == 1
    assert _dword(se, written) == len(text)
    assert displays["lpBuffer"] == repr(text)


def test_try_acquire_srw_lock_exclusive_succeeds_without_touching_the_lock(win_emu: Speakeasy) -> None:
    """Every try succeeds, nothing is dereferenced, and LastError is untouched (requirement 3)."""
    se = win_emu
    start_process(se)
    lock = alloc(se, b"\x00" * 8)
    assert lock % 8 == 0
    # 0xDEADBEEF is deliberately unmapped: a handler that dereferenced it would fault.
    for argument in (lock, 0, 0xDEADBEEF):
        se.emu.set_last_error(LAST_ERROR_SENTINEL)
        rv, _ = call(se, "kernel32", "TryAcquireSRWLockExclusive", [argument])
        assert rv == 1
        assert se.emu.get_last_error() == LAST_ERROR_SENTINEL
    assert se.mem_read(lock, 8) == b"\x00" * 8


def test_write_private_profile_string_a_succeeds_and_rejects_a_null_file_name(win_emu: Speakeasy) -> None:
    """A valid ANSI call returns TRUE without touching LastError; NULL filename fails (requirement 4)."""
    se = win_emu
    start_process(se)
    argv = [
        _ansi(se, "Section"),
        _ansi(se, "Key"),
        _ansi(se, "Value"),
        _ansi(se, r"C:\test.ini"),
    ]
    se.emu.set_last_error(LAST_ERROR_SENTINEL)
    rv, _ = call(se, "kernel32", "WritePrivateProfileStringA", argv)
    assert rv == 1
    assert se.emu.get_last_error() == LAST_ERROR_SENTINEL

    se.emu.set_last_error(LAST_ERROR_SENTINEL)
    rv, _ = call(se, "kernel32", "WritePrivateProfileStringA", [*argv[:3], 0])
    assert rv == 0
    assert se.emu.get_last_error() == windefs.ERROR_INVALID_PARAMETER


def test_write_private_profile_string_w_succeeds_and_rejects_a_null_file_name(win_emu: Speakeasy) -> None:
    """A valid UTF-16 call returns TRUE without touching LastError; NULL filename fails (requirement 5)."""
    se = win_emu
    start_process(se)
    argv = [
        _wide(se, "Section"),
        _wide(se, "Key"),
        _wide(se, "Value"),
        _wide(se, r"C:\test.ini"),
    ]
    se.emu.set_last_error(LAST_ERROR_SENTINEL)
    rv, _ = call(se, "kernel32", "WritePrivateProfileStringW", argv)
    assert rv == 1
    assert se.emu.get_last_error() == LAST_ERROR_SENTINEL

    se.emu.set_last_error(LAST_ERROR_SENTINEL)
    rv, _ = call(se, "kernel32", "WritePrivateProfileStringW", [*argv[:3], 0])
    assert rv == 0
    assert se.emu.get_last_error() == windefs.ERROR_INVALID_PARAMETER


def test_system_parameters_info_get_work_area_uses_the_ui_profile(custom_ui_emu: Speakeasy) -> None:
    """SPI_GETWORKAREA fills the RECT from the configured screen size (requirement 6)."""
    se = custom_ui_emu
    start_process(se)
    rect = alloc(se, b"\xcc" * 20)
    se.emu.set_last_error(LAST_ERROR_SENTINEL)
    rv, _ = call(se, "user32", "SystemParametersInfoW", [SPI_GETWORKAREA, 0, rect, 0])
    assert rv == 1
    data = se.mem_read(rect, 20)
    assert struct.unpack("<iiii", data[:16]) == (0, 0, 1600, 900)
    assert data[16:] == b"\xcc" * 4
    assert se.emu.get_last_error() == LAST_ERROR_SENTINEL


@pytest.mark.parametrize("action", [SPI_GETSCREENSAVEACTIVE, SPI_GETSCREENSAVERRUNNING])
def test_system_parameters_info_screen_saver_queries_store_false(win_emu: Speakeasy, action: int) -> None:
    """Both screen-saver queries write a 32-bit FALSE and succeed (requirement 7)."""
    se = win_emu
    start_process(se)
    buf = alloc(se, b"\xcc" * 8)
    se.emu.set_last_error(LAST_ERROR_SENTINEL)
    rv, _ = call(se, "user32", "SystemParametersInfoW", [action, 0, buf, 0])
    assert rv == 1
    data = se.mem_read(buf, 8)
    assert data[:4] == b"\x00" * 4
    assert data[4:] == b"\xcc" * 4
    assert se.emu.get_last_error() == LAST_ERROR_SENTINEL


def test_system_parameters_info_unknown_action_fails_and_leaves_the_buffer(win_emu: Speakeasy) -> None:
    """An unmodeled action reports failure and writes nothing (requirement 8)."""
    se = win_emu
    start_process(se)
    buf = alloc(se, b"\xcc" * 16)
    se.emu.set_last_error(LAST_ERROR_SENTINEL)
    rv, _ = call(se, "user32", "SystemParametersInfoW", [UNKNOWN_SPI_ACTION, 0, buf, 0])
    assert rv == 0
    assert se.emu.get_last_error() == windefs.ERROR_INVALID_PARAMETER
    assert se.mem_read(buf, 16) == b"\xcc" * 16


def test_system_parameters_info_null_pv_param_fails(win_emu: Speakeasy) -> None:
    """A NULL pvParam fails with ERROR_INVALID_PARAMETER (requirement 9)."""
    se = win_emu
    start_process(se)
    se.emu.set_last_error(LAST_ERROR_SENTINEL)
    rv, _ = call(se, "user32", "SystemParametersInfoW", [SPI_GETWORKAREA, 0, 0, 0])
    assert rv == 0
    assert se.emu.get_last_error() == windefs.ERROR_INVALID_PARAMETER
