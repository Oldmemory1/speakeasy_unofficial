from __future__ import annotations

from types import SimpleNamespace

import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.winenv.api.usermode.advapi32 import (
    TOKEN_INTEGRITY_LEVEL_INFORMATION_CLASS,
    TOKEN_USER_INFORMATION_CLASS,
    AdvApi32,
)


class _MemoryEmu:
    def __init__(self) -> None:
        self.memory: dict[int, int] = {}
        self.last_error: int | None = None
        self.config = SimpleNamespace(
            user=SimpleNamespace(
                sid="S-1-5-21-1111111111-2222222222-3333333333-1001",
                is_admin=True,
            )
        )

    def get_ptr_size(self) -> int:
        return 4

    def mem_write(self, address: int, data: bytes) -> None:
        for offset, value in enumerate(data):
            self.memory[address + offset] = value

    def set_last_error(self, value: int) -> None:
        self.last_error = value

    def get_address_map(self, _address: int):
        return None


def _handler(emu: _MemoryEmu) -> AdvApi32:
    handler = AdvApi32.__new__(AdvApi32)
    handler.emu = emu
    return handler


def _read_u32(emu: _MemoryEmu, address: int) -> int:
    return int.from_bytes(
        bytes(emu.memory[address + offset] for offset in range(4)),
        "little",
    )


def test_token_user_query_writes_inline_absolute_sid_pointer() -> None:
    emu = _MemoryEmu()
    handler = _handler(emu)
    info, ret_len = 0x2000, 0x3000

    assert handler.GetTokenInformation(
        emu,
        [0x220, TOKEN_USER_INFORMATION_CLASS, 0, 0, ret_len],
    ) == 0
    required = _read_u32(emu, ret_len)
    assert required > 8

    assert handler.GetTokenInformation(
        emu,
        [0x220, TOKEN_USER_INFORMATION_CLASS, info, required, ret_len],
    ) == 1
    sid = _read_u32(emu, info)
    assert sid == info + 8
    assert emu.memory[sid] == 1
    assert emu.memory[sid + 1] == 5


def test_token_integrity_level_uses_high_integrity_sid_for_admin() -> None:
    emu = _MemoryEmu()
    handler = _handler(emu)
    info, ret_len = 0x4000, 0x5000

    assert handler.GetTokenInformation(
        emu,
        [0x220, TOKEN_INTEGRITY_LEVEL_INFORMATION_CLASS, 0, 0, ret_len],
    ) == 0
    required = _read_u32(emu, ret_len)

    assert handler.GetTokenInformation(
        emu,
        [
            0x220,
            TOKEN_INTEGRITY_LEVEL_INFORMATION_CLASS,
            info,
            required,
            ret_len,
        ],
    ) == 1
    sid = _read_u32(emu, info)
    assert sid == info + 8
    assert _read_u32(emu, info + 4) == 0x20
    parsed = windefs.SID(4, 1)
    parsed.cast(bytes(emu.memory[sid + offset] for offset in range(parsed.sizeof())))
    assert parsed.SubAuthority[0] == 0x3000
