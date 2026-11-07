from __future__ import annotations

from speakeasy.winenv.api.usermode.kernel32 import Kernel32


class _Emu:
    def __init__(self) -> None:
        self.memory: dict[int, bytes] = {}
        self.last_error = None

    def mem_write(self, address: int, data: bytes) -> None:
        self.memory[address] = data

    def set_last_error(self, value: int) -> None:
        self.last_error = value


def _handler() -> Kernel32:
    handler = Kernel32.__new__(Kernel32)
    handler._process_user_mode_exception_policy = 0
    return handler


def test_exception_policy_round_trip() -> None:
    handler = _handler()
    emu = _Emu()
    flags_address = 0x401000

    assert handler.GetProcessUserModeExceptionPolicy(emu, [flags_address]) == 1
    assert int.from_bytes(emu.memory[flags_address], "little") == 0

    assert handler.SetProcessUserModeExceptionPolicy(emu, [1]) == 1
    assert handler.GetProcessUserModeExceptionPolicy(emu, [flags_address]) == 1
    assert int.from_bytes(emu.memory[flags_address], "little") == 1


def test_exception_policy_rejects_invalid_arguments() -> None:
    handler = _handler()
    emu = _Emu()

    assert handler.GetProcessUserModeExceptionPolicy(emu, [0]) == 0
    assert handler.SetProcessUserModeExceptionPolicy(emu, [2]) == 0
