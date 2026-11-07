from __future__ import annotations

from speakeasy.winenv.api.usermode.msvcrt import (
    SIG_DFL,
    SIG_ERR,
    SIG_GET,
    SIG_IGN,
    SIGINT,
    Msvcrt,
)


class _MemoryEmu:
    def __init__(self) -> None:
        self.memory: dict[int, int] = {}
        self.next_address = 0x1000

    def get_ptr_size(self) -> int:
        return 4

    def get_env(self) -> dict[str, str]:
        return {"SystemRoot": "C:\\Windows"}

    def mem_map(self, size: int, **_kwargs) -> int:
        address = self.next_address
        self.next_address += size + 0x100
        return address

    def mem_write(self, address: int, data: bytes) -> None:
        for offset, value in enumerate(data):
            self.memory[address + offset] = value

    def get_address_map(self, _address: int):
        return None


def _handler() -> Msvcrt:
    handler = Msvcrt.__new__(Msvcrt)
    handler.signal_handlers = {}
    return handler


def test_signal_returns_previous_handler_and_tracks_state() -> None:
    handler = _handler()

    assert handler.signal(None, [SIGINT, SIG_IGN]) == SIG_DFL
    assert handler.signal(None, [SIGINT, SIG_GET]) == SIG_IGN
    assert handler.signal(None, [SIGINT, 0x401000]) == SIG_IGN
    assert handler.signal(None, [SIGINT, SIG_GET]) == 0x401000


def test_signal_rejects_invalid_signal_and_err_action() -> None:
    handler = _handler()

    assert handler.signal(None, [9999, SIG_IGN]) == SIG_ERR
    assert handler.signal(None, [SIGINT, SIG_ERR]) == SIG_ERR
    assert handler.signal(None, [SIGINT, SIG_GET]) == SIG_DFL


def test_atexit_validates_callback_without_executing_it() -> None:
    handler = _handler()

    assert handler.atexit(None, [0x401000]) == 0
    assert handler.atexit(None, [0]) == 1


def test_p_environ_returns_stable_pointer_to_environment_array() -> None:
    emu = _MemoryEmu()
    handler = Msvcrt.__new__(Msvcrt)
    handler.emu = emu
    handler.ptr_size = 4
    handler._environ_pointer = None

    environ = handler._Msvcrt__p__environ
    environ_pointer = environ(emu, [])

    assert environ_pointer == environ(emu, [])
    environment = int.from_bytes(
        bytes(emu.memory[environ_pointer + offset] for offset in range(4)),
        "little",
    )
    first_string = int.from_bytes(
        bytes(emu.memory[environment + offset] for offset in range(4)),
        "little",
    )
    expected = b"SystemRoot=C:\\Windows\x00"
    value = bytes(
        emu.memory[first_string + offset]
        for offset in range(len(expected))
    )
    assert value == expected
