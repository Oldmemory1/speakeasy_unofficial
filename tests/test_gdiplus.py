from __future__ import annotations

from types import SimpleNamespace

import speakeasy.winenv.arch as e_arch
from speakeasy.winenv.api.usermode.gdiplus import (
    GDI_PLUS_INVALID_PARAMETER,
    GDI_PLUS_OK,
    Gdiplus,
)


def _handler() -> tuple[Gdiplus, SimpleNamespace]:
    memory: dict[int, bytes] = {}
    emu = SimpleNamespace(
        get_arch=lambda: e_arch.ARCH_X86,
        get_ptr_size=lambda: 8,
        mem_write=lambda address, data: memory.__setitem__(address, data),
    )
    return Gdiplus(emu), SimpleNamespace(memory=memory)


def test_startup_writes_stable_token_and_shutdown_is_idempotent() -> None:
    handler, state = _handler()
    token_address = 0x1000

    assert handler.GdiplusStartup(
        handler.emu,
        [token_address, 0x2000, 0],
    ) == GDI_PLUS_OK
    token = int.from_bytes(state.memory[token_address], "little")
    assert token != 0

    assert handler.GdiplusShutdown(handler.emu, [token]) is None
    assert handler.GdiplusShutdown(handler.emu, [token]) is None


def test_startup_rejects_null_token_or_input() -> None:
    handler, _state = _handler()

    assert handler.GdiplusStartup(handler.emu, [0, 0x2000, 0]) == (
        GDI_PLUS_INVALID_PARAMETER
    )
    assert handler.GdiplusStartup(handler.emu, [0x1000, 0, 0]) == (
        GDI_PLUS_INVALID_PARAMETER
    )
