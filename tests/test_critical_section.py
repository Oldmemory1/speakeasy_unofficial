"""Contract tests for kernel32 CRITICAL_SECTION and FormatMessage handlers.

The tests exercise the API handlers directly with a small in-memory emulator
double. They freeze the documented Windows behaviour that the PyInstaller
bootstrap path relies on:

* ``InitializeCriticalSection`` / ``...AndSpinCount`` / ``...Ex`` write the
  documented x86 and x64 ``RTL_CRITICAL_SECTION`` layout.
* ``EnterCriticalSection`` is recursive for the owning thread and records
  ownership.
* ``LeaveCriticalSection`` unwinds the recursion and releases the lock.
* ``TryEnterCriticalSection`` fails when another thread owns the lock.
* ``DeleteCriticalSection`` resets the structure.
* ``FormatMessageW``/``FormatMessageA`` return the system message for a known
  message id (notably id 0) instead of reporting failure, which is what
  prevents the PyInstaller error-printing recursion.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

import speakeasy.winenv.defs.windows.windows as windefs
from speakeasy.winenv.api.usermode.kernel32 import Kernel32

FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000
FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200
ERROR_MR_UNKNOWN = 317


class _MemoryEmu:
    """Minimal emulator double supporting the kernel32 handlers under test."""

    def __init__(self, *, ptr_size: int = 8, tid: int = 0x1111) -> None:
        self.ptr_size = ptr_size
        self.memory: dict[int, int] = {}
        self.ranges: list[tuple[int, int]] = []
        self.last_error: int | None = None
        self.current_thread = SimpleNamespace(tid=tid)

    def alloc(self, address: int, size: int) -> None:
        self.ranges.append((address, address + size))

    def _in_range(self, address: int, size: int) -> bool:
        return any(
            start <= address and address + size <= end
            for start, end in self.ranges
        )

    def get_ptr_size(self) -> int:
        return self.ptr_size

    def get_arch(self):
        return None

    def is_address_valid(self, address: int) -> bool:
        return self._in_range(address, 1)

    def mem_read(self, address: int, size: int) -> bytes:
        if not self._in_range(address, size):
            raise ValueError(f"invalid read at 0x{address:x}+{size}")
        return bytes(self.memory.get(address + offset, 0) for offset in range(size))

    def mem_write(self, address: int, data: bytes) -> None:
        if not self._in_range(address, len(data)):
            raise ValueError(f"invalid write at 0x{address:x}+{len(data)}")
        for offset, value in enumerate(data):
            self.memory[address + offset] = value

    def set_last_error(self, value: int) -> None:
        self.last_error = value

    def get_address_map(self, _address: int):
        return None

    def get_current_thread(self):
        return self.current_thread

    def get_current_process(self):
        return None

    def file_get(self, _handle: int):
        return None

    def pipe_get(self, _handle: int):
        return None


def _handler(emu: _MemoryEmu) -> Kernel32:
    handler = Kernel32.__new__(Kernel32)
    handler.emu = emu
    return handler


def _layout(ptr_size: int) -> dict[str, int]:
    if ptr_size == 4:
        return {
            "debug_info": 0x00,
            "lock_count": 0x04,
            "recursion_count": 0x08,
            "owning_thread": 0x0C,
            "lock_semaphore": 0x10,
            "spin_count": 0x14,
            "size": 0x18,
        }
    if ptr_size == 8:
        return {
            "debug_info": 0x00,
            "lock_count": 0x08,
            "recursion_count": 0x0C,
            "owning_thread": 0x10,
            "lock_semaphore": 0x18,
            "spin_count": 0x20,
            "size": 0x28,
        }
    raise AssertionError(f"unsupported ptr_size {ptr_size}")


def _read_cs(emu: _MemoryEmu, address: int) -> dict[str, int]:
    layout = _layout(emu.get_ptr_size())
    ptr = emu.get_ptr_size()
    return {
        "debug_info": int.from_bytes(
            emu.mem_read(address + layout["debug_info"], ptr), "little"
        ),
        "lock_count": int.from_bytes(
            emu.mem_read(address + layout["lock_count"], 4), "little", signed=True
        ),
        "recursion_count": int.from_bytes(
            emu.mem_read(address + layout["recursion_count"], 4),
            "little",
            signed=True,
        ),
        "owning_thread": int.from_bytes(
            emu.mem_read(address + layout["owning_thread"], ptr), "little"
        ),
        "lock_semaphore": int.from_bytes(
            emu.mem_read(address + layout["lock_semaphore"], ptr), "little"
        ),
        "spin_count": int.from_bytes(
            emu.mem_read(address + layout["spin_count"], ptr), "little"
        ),
    }


@pytest.mark.parametrize("ptr_size", [4, 8])
def test_initialize_critical_section_writes_documented_layout(ptr_size: int) -> None:
    emu = _MemoryEmu(ptr_size=ptr_size)
    address = 0x1000
    emu.alloc(address, _layout(ptr_size)["size"])
    # Poison the structure so a no-op handler cannot pass by accident.
    for offset in range(_layout(ptr_size)["size"]):
        emu.memory[address + offset] = 0xAA

    _handler(emu).InitializeCriticalSection(emu, [address])

    state = _read_cs(emu, address)
    assert state["debug_info"] == 0
    assert state["lock_count"] == -1
    assert state["recursion_count"] == 0
    assert state["owning_thread"] == 0
    assert state["lock_semaphore"] == 0
    assert state["spin_count"] == 0


@pytest.mark.parametrize("ptr_size", [4, 8])
def test_initialize_critical_section_and_spin_count_stores_spin(ptr_size: int) -> None:
    emu = _MemoryEmu(ptr_size=ptr_size)
    address = 0x2000
    emu.alloc(address, _layout(ptr_size)["size"])

    result = _handler(emu).InitializeCriticalSectionAndSpinCount(
        emu, [address, 0x1234]
    )

    assert result == 1
    state = _read_cs(emu, address)
    assert state["lock_count"] == -1
    assert state["recursion_count"] == 0
    assert state["spin_count"] == 0x1234


@pytest.mark.parametrize("ptr_size", [4, 8])
def test_initialize_critical_section_ex_stores_spin(ptr_size: int) -> None:
    emu = _MemoryEmu(ptr_size=ptr_size)
    address = 0x3000
    emu.alloc(address, _layout(ptr_size)["size"])

    result = _handler(emu).InitializeCriticalSectionEx(emu, [address, 0xFA0, 0])

    assert result is True
    state = _read_cs(emu, address)
    assert state["lock_count"] == -1
    assert state["recursion_count"] == 0
    assert state["spin_count"] == 0xFA0


@pytest.mark.parametrize("ptr_size", [4, 8])
def test_recursive_enter_increments_and_leave_releases(ptr_size: int) -> None:
    emu = _MemoryEmu(ptr_size=ptr_size, tid=0x1234)
    address = 0x4000
    emu.alloc(address, _layout(ptr_size)["size"])
    handler = _handler(emu)
    handler.InitializeCriticalSection(emu, [address])

    handler.EnterCriticalSection(emu, [address])
    state = _read_cs(emu, address)
    assert state["lock_count"] == 0
    assert state["recursion_count"] == 1
    assert state["owning_thread"] == 0x1234

    handler.EnterCriticalSection(emu, [address])
    state = _read_cs(emu, address)
    assert state["lock_count"] == 1
    assert state["recursion_count"] == 2
    assert state["owning_thread"] == 0x1234

    handler.LeaveCriticalSection(emu, [address])
    state = _read_cs(emu, address)
    assert state["lock_count"] == 0
    assert state["recursion_count"] == 1
    assert state["owning_thread"] == 0x1234

    handler.LeaveCriticalSection(emu, [address])
    state = _read_cs(emu, address)
    assert state["lock_count"] == -1
    assert state["recursion_count"] == 0
    assert state["owning_thread"] == 0


@pytest.mark.parametrize("ptr_size", [4, 8])
def test_try_enter_critical_section_contended(ptr_size: int) -> None:
    emu = _MemoryEmu(ptr_size=ptr_size, tid=0x1111)
    address = 0x5000
    emu.alloc(address, _layout(ptr_size)["size"])
    handler = _handler(emu)
    handler.InitializeCriticalSection(emu, [address])

    # Free lock: the calling thread acquires it.
    assert handler.TryEnterCriticalSection(emu, [address]) is True
    state = _read_cs(emu, address)
    assert state["owning_thread"] == 0x1111
    assert state["recursion_count"] == 1

    # Another thread must fail without changing the structure.
    emu.current_thread = SimpleNamespace(tid=0x2222)
    assert handler.TryEnterCriticalSection(emu, [address]) is False
    state = _read_cs(emu, address)
    assert state["owning_thread"] == 0x1111
    assert state["recursion_count"] == 1

    # The owner may re-enter recursively.
    emu.current_thread = SimpleNamespace(tid=0x1111)
    assert handler.TryEnterCriticalSection(emu, [address]) is True
    assert _read_cs(emu, address)["recursion_count"] == 2


@pytest.mark.parametrize("ptr_size", [4, 8])
def test_delete_critical_section_resets_structure(ptr_size: int) -> None:
    emu = _MemoryEmu(ptr_size=ptr_size, tid=0x3333)
    address = 0x6000
    emu.alloc(address, _layout(ptr_size)["size"])
    # Poison the structure so pre-fix no-op handlers cannot pass by default.
    for offset in range(_layout(ptr_size)["size"]):
        emu.memory[address + offset] = 0xAA
    handler = _handler(emu)
    handler.InitializeCriticalSection(emu, [address])
    handler.EnterCriticalSection(emu, [address])

    handler.DeleteCriticalSection(emu, [address])

    state = _read_cs(emu, address)
    assert state == {
        "debug_info": 0,
        "lock_count": 0,
        "recursion_count": 0,
        "owning_thread": 0,
        "lock_semaphore": 0,
        "spin_count": 0,
    }


@pytest.mark.parametrize("ptr_size", [4, 8])
def test_repeated_enter_leave_changes_state_every_call(ptr_size: int) -> None:
    """A balanced Enter/Leave stream must not be a silent no-op.

    ``cs_spin_loop_not_masked``: every ``EnterCriticalSection`` on an
    initialized structure updates ownership/recursion, and a never-released
    recursive enter keeps increasing ``RecursionCount`` instead of pretending
    the lock was acquired and released. A cross-thread attempt is reported as
    contention instead of silent success.
    """

    emu = _MemoryEmu(ptr_size=ptr_size, tid=0x4444)
    address = 0x7000
    emu.alloc(address, _layout(ptr_size)["size"])
    handler = _handler(emu)
    handler.InitializeCriticalSection(emu, [address])

    observed = set()
    for _ in range(2000):
        handler.EnterCriticalSection(emu, [address])
        state = _read_cs(emu, address)
        observed.add((state["lock_count"], state["recursion_count"]))
        handler.LeaveCriticalSection(emu, [address])
        state = _read_cs(emu, address)
        assert state["lock_count"] == -1
        assert state["recursion_count"] == 0

    assert observed

    # A never-released recursive lock is visible and monotonically deepens.
    for depth in range(1, 6):
        handler.EnterCriticalSection(emu, [address])
        assert _read_cs(emu, address)["recursion_count"] == depth

    # Another thread is told the truth: the lock is held.
    emu.current_thread = SimpleNamespace(tid=0x5555)
    assert handler.TryEnterCriticalSection(emu, [address]) is False


@pytest.mark.parametrize("ptr_size", [4, 8])
def test_format_message_w_returns_success_message_for_id_zero(ptr_size: int) -> None:
    emu = _MemoryEmu(ptr_size=ptr_size)
    buffer = 0x8000
    emu.alloc(buffer, 0x800)
    handler = _handler(emu)

    result = handler.FormatMessageW(
        emu, [FORMAT_MESSAGE_FROM_SYSTEM, 0, 0, 0x400, buffer, 0x400, 0]
    )

    assert result > 0
    expected = "The operation completed successfully.\r\n"
    raw = emu.mem_read(buffer, len(expected) * 2 + 2)
    text = raw.decode("utf-16le")
    assert text == expected + "\x00"
    assert emu.last_error == windefs.ERROR_SUCCESS


@pytest.mark.parametrize("ptr_size", [4, 8])
def test_format_message_a_returns_success_message_for_id_zero(ptr_size: int) -> None:
    emu = _MemoryEmu(ptr_size=ptr_size)
    buffer = 0x9000
    emu.alloc(buffer, 0x800)
    handler = _handler(emu)

    result = handler.FormatMessageA(
        emu, [FORMAT_MESSAGE_FROM_SYSTEM, 0, 0, 0x400, buffer, 0x400, 0]
    )

    assert result > 0
    expected = b"The operation completed successfully.\r\n"
    assert emu.mem_read(buffer, len(expected) + 1) == expected + b"\x00"


def test_format_message_w_unknown_message_id_fails() -> None:
    emu = _MemoryEmu(ptr_size=8)
    buffer = 0xA000
    emu.alloc(buffer, 0x100)
    handler = _handler(emu)

    result = handler.FormatMessageW(
        emu, [FORMAT_MESSAGE_FROM_SYSTEM, 0, 0xDEAD, 0, buffer, 0x100, 0]
    )

    assert result == 0
    assert emu.last_error == ERROR_MR_UNKNOWN


def test_format_message_w_rejects_missing_system_flag() -> None:
    emu = _MemoryEmu(ptr_size=8)
    buffer = 0xB000
    emu.alloc(buffer, 0x100)
    handler = _handler(emu)

    result = handler.FormatMessageW(emu, [0, 0, 0, 0, buffer, 0x100, 0])

    assert result == 0
    assert emu.last_error == windefs.ERROR_INVALID_PARAMETER


def test_format_message_w_truncates_to_buffer_size() -> None:
    emu = _MemoryEmu(ptr_size=8)
    buffer = 0xC000
    emu.alloc(buffer, 0x100)
    handler = _handler(emu)

    result = handler.FormatMessageW(
        emu,
        [FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, 0, 0, 0, buffer, 8, 0],
    )

    assert result == 7
    raw = emu.mem_read(buffer, 16)
    assert raw.decode("utf-16le") == "The ope\x00"


def test_format_message_w_rejects_null_buffer() -> None:
    emu = _MemoryEmu(ptr_size=8)
    handler = _handler(emu)

    result = handler.FormatMessageW(
        emu, [FORMAT_MESSAGE_FROM_SYSTEM, 0, 0, 0, 0, 0x100, 0]
    )

    assert result == 0
    assert emu.last_error == windefs.ERROR_INVALID_PARAMETER
