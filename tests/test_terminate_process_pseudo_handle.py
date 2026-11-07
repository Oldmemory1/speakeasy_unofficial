from __future__ import annotations

import pytest

import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.winenv.api.usermode.kernel32 import Kernel32
from speakeasy.winenv.api.usermode.pseudo_handles import (
    current_process_pseudo_handle,
    is_current_process_pseudo_handle,
)


class _FakeEmu:
    def __init__(self, pointer_size: int, process: object | None, handle_process: object | None = None):
        self.pointer_size = pointer_size
        self.process = process
        self.handle_process = handle_process
        self.killed: list[object] = []
        self.exit_count = 0
        self.last_error = None

    def get_ptr_size(self) -> int:
        return self.pointer_size

    def get_current_process(self) -> object | None:
        return self.process

    def get_object_from_handle(self, handle: int) -> object | None:
        return self.handle_process

    def kill_process(self, process: object) -> None:
        self.killed.append(process)

    def exit_process(self) -> None:
        self.exit_count += 1

    def set_last_error(self, value: int) -> None:
        self.last_error = value


def _handler(pointer_size: int) -> Kernel32:
    handler = Kernel32.__new__(Kernel32)
    handler.ptr_size = pointer_size
    return handler


@pytest.mark.parametrize(("pointer_size", "handle"), [(4, 0xFFFFFFFF), (8, 0xFFFFFFFFFFFFFFFF)])
def test_pseudo_handle_value_matches_process_bitness(pointer_size: int, handle: int) -> None:
    assert current_process_pseudo_handle(pointer_size) == handle
    assert is_current_process_pseudo_handle(handle, pointer_size)
    assert not is_current_process_pseudo_handle(0, pointer_size)


@pytest.mark.parametrize("pointer_size", [4, 8])
def test_terminate_current_process_by_pseudo_handle_terminates_run(pointer_size: int) -> None:
    process = object()
    emu = _FakeEmu(pointer_size, process)
    handle = current_process_pseudo_handle(pointer_size)

    assert Kernel32.TerminateProcess(_handler(pointer_size), emu, [handle, 0xC0000417]) is True
    assert emu.killed == [process]
    assert emu.exit_count == 1
    assert emu.last_error is None


def test_terminate_other_process_does_not_exit_current_run() -> None:
    current_process = object()
    target_process = object()
    emu = _FakeEmu(8, current_process, target_process)

    assert Kernel32.TerminateProcess(_handler(8), emu, [0x1234, 0]) is True
    assert emu.killed == [target_process]
    assert emu.exit_count == 0
    assert emu.last_error is None


def test_terminate_current_process_by_object_handle_terminates_run() -> None:
    current_process = object()
    emu = _FakeEmu(8, current_process, current_process)

    assert Kernel32.TerminateProcess(_handler(8), emu, [0x1234, 0]) is True
    assert emu.killed == [current_process]
    assert emu.exit_count == 1
    assert emu.last_error is None


@pytest.mark.parametrize("handle", [0, 0x1234])
def test_terminate_invalid_process_handle_fails(handle: int) -> None:
    emu = _FakeEmu(8, object(), None)

    assert Kernel32.TerminateProcess(_handler(8), emu, [handle, 0]) is False
    assert emu.killed == []
    assert emu.exit_count == 0
    assert emu.last_error == windefs.ERROR_INVALID_HANDLE


def test_pseudo_handle_rejects_unsupported_pointer_size() -> None:
    with pytest.raises(ValueError, match="unsupported pointer size"):
        current_process_pseudo_handle(16)
