"""Contract tests for kernel32.SetFilePointer.

These tests pin the documented Windows semantics of ``SetFilePointer``:

* ``lDistanceToMove`` is a signed 32-bit ``LONG`` when ``lpDistanceToMoveHigh``
  is ``NULL``;
* when ``lpDistanceToMoveHigh`` is non-``NULL`` the two 32-bit halves form a
  signed 64-bit offset;
* the return value is the low 32 bits of the resulting file pointer and the
  high 32 bits are written back through ``lpDistanceToMoveHigh``;
* a negative resulting position fails with ``ERROR_NEGATIVE_SEEK`` and leaves
  the file pointer untouched;
* an invalid handle or move method fails with the matching Win32 error.

``lpDistanceToMoveHigh`` is a ``PLONG`` and therefore always addresses four
bytes, on both x86 and x64.
"""

from __future__ import annotations

import io

import pytest

from speakeasy.winenv.api.usermode.kernel32 import Kernel32

FILE_BEGIN = 0
FILE_CURRENT = 1
FILE_END = 2

INVALID_SET_FILE_POINTER = 0xFFFFFFFF
ERROR_SUCCESS = 0
ERROR_INVALID_HANDLE = 6
ERROR_INVALID_PARAMETER = 87
ERROR_NEGATIVE_SEEK = 131

NULL = 0
VALID_HANDLE = 1


class _FakeFile:
    """Minimal stand-in that mirrors speakeasy.windows.fileman.File."""

    def __init__(self, data: bytes):
        self.data = io.BytesIO(data)

    def seek(self, offset: int, whence: int) -> None:
        # File.seek silently ignores an unknown whence value.
        if whence not in (io.SEEK_SET, io.SEEK_CUR, io.SEEK_END):
            return
        self.data.seek(offset, whence)

    def tell(self) -> int:
        return self.data.tell()

    def get_size(self) -> int:
        return len(self.data.getvalue())


class _FakeEmu:
    def __init__(self, ptr_size: int = 4) -> None:
        self.ptr_size = ptr_size
        self.last_error = None
        self.memory = bytearray(0x10000)
        self.read_sizes: list[int] = []
        self.write_sizes: list[int] = []

    def get_ptr_size(self) -> int:
        return self.ptr_size

    def set_last_error(self, value: int) -> None:
        self.last_error = value

    def mem_read(self, addr: int, size: int) -> bytes:
        self.read_sizes.append(size)
        if addr < 0 or addr + size > len(self.memory):
            raise ValueError(f"out-of-range read at 0x{addr:x}")
        return bytes(self.memory[addr : addr + size])

    def mem_write(self, addr: int, data: bytes) -> None:
        self.write_sizes.append(len(data))
        if addr < 0 or addr + len(data) > len(self.memory):
            raise ValueError(f"out-of-range write at 0x{addr:x}")
        self.memory[addr : addr + len(data)] = data


def _make_handler(emu: _FakeEmu, file: _FakeFile | None) -> Kernel32:
    handler = Kernel32.__new__(Kernel32)
    handler.file_get = lambda handle: file if handle == VALID_HANDLE else None
    handler.mem_read = emu.mem_read
    handler.mem_write = emu.mem_write
    return handler


def _set_file_pointer(
    emu: _FakeEmu,
    file: _FakeFile | None,
    low: int,
    high_ptr: int,
    move_method: int,
):
    handler = _make_handler(emu, file)
    argv = [VALID_HANDLE, low, high_ptr, move_method]
    return handler.SetFilePointer(emu, argv)


@pytest.mark.parametrize("ptr_size", [4, 8])
def test_negative_low32_file_end(ptr_size: int) -> None:
    """0xFFFFFFFD with a NULL high pointer is -3, not +4294967293."""
    emu = _FakeEmu(ptr_size)
    file = _FakeFile(b"0123456789")  # 10 bytes

    result = _set_file_pointer(emu, file, 0xFFFFFFFD, NULL, FILE_END)

    assert result == 7
    assert file.tell() == 7
    assert emu.last_error == ERROR_SUCCESS


@pytest.mark.parametrize("ptr_size", [4, 8])
def test_negative_low32_current(ptr_size: int) -> None:
    """0xFFFFFFFF with a NULL high pointer is -1 from the current position."""
    emu = _FakeEmu(ptr_size)
    file = _FakeFile(b"0123456789")
    file.seek(5, io.SEEK_SET)

    result = _set_file_pointer(emu, file, 0xFFFFFFFF, NULL, FILE_CURRENT)

    assert result == 4
    assert file.tell() == 4
    assert emu.last_error == ERROR_SUCCESS


@pytest.mark.parametrize("ptr_size", [4, 8])
def test_positive_begin(ptr_size: int) -> None:
    """Positive distances keep their existing FILE_BEGIN meaning."""
    emu = _FakeEmu(ptr_size)
    file = _FakeFile(b"0123456789")

    result = _set_file_pointer(emu, file, 5, NULL, FILE_BEGIN)

    assert result == 5
    assert file.tell() == 5
    assert emu.last_error == ERROR_SUCCESS


@pytest.mark.parametrize("ptr_size", [4, 8])
def test_high_low_combination(ptr_size: int) -> None:
    """A non-NULL high pointer forms a 64-bit distance and receives the high half."""
    emu = _FakeEmu(ptr_size)
    file = _FakeFile(b"0123456789")
    high_ptr = 0x3000
    emu.memory[high_ptr : high_ptr + 4] = (1).to_bytes(4, "little")

    result = _set_file_pointer(emu, file, 0, high_ptr, FILE_BEGIN)

    assert result == 0  # low 32 bits of 2**32
    assert file.tell() == 1 << 32
    assert bytes(emu.memory[high_ptr : high_ptr + 4]) == (1).to_bytes(4, "little")
    assert emu.write_sizes == [4]
    assert emu.last_error == ERROR_SUCCESS


@pytest.mark.parametrize("ptr_size", [4, 8])
def test_negative_result_rejected(ptr_size: int) -> None:
    """A negative resulting position is an error and must not move the pointer."""
    emu = _FakeEmu(ptr_size)
    file = _FakeFile(b"0123456789")
    file.seek(3, io.SEEK_SET)

    result = _set_file_pointer(emu, file, 0xFFFFFFFB, NULL, FILE_CURRENT)  # -5

    assert result == INVALID_SET_FILE_POINTER
    assert emu.last_error == ERROR_NEGATIVE_SEEK
    assert file.tell() == 3


def test_invalid_handle() -> None:
    emu = _FakeEmu()
    handler = _make_handler(emu, None)

    result = handler.SetFilePointer(emu, [2, 0, NULL, FILE_BEGIN])

    assert result == INVALID_SET_FILE_POINTER
    assert emu.last_error == ERROR_INVALID_HANDLE


def test_invalid_whence() -> None:
    emu = _FakeEmu()
    file = _FakeFile(b"0123456789")
    file.seek(4, io.SEEK_SET)

    result = _set_file_pointer(emu, file, 5, NULL, 7)

    assert result == INVALID_SET_FILE_POINTER
    assert emu.last_error == ERROR_INVALID_PARAMETER
    assert file.tell() == 4


@pytest.mark.parametrize("ptr_size", [4, 8])
def test_pointer_size_boundaries(ptr_size: int) -> None:
    """lpDistanceToMoveHigh addresses four bytes regardless of pointer size."""
    emu = _FakeEmu(ptr_size)
    file = _FakeFile(b"0123456789")
    high_ptr = 0x3000
    emu.memory[high_ptr : high_ptr + 4] = (1).to_bytes(4, "little")

    _set_file_pointer(emu, file, 0, high_ptr, FILE_BEGIN)

    assert emu.read_sizes == [4]
    assert emu.write_sizes == [4]
    assert all(size == 4 for size in emu.read_sizes + emu.write_sizes)
    # Bytes after the LONG must not be touched (no accidental 8-byte access).
    assert bytes(emu.memory[high_ptr + 4 : high_ptr + 8]) == b"\x00\x00\x00\x00"


def test_set_file_pointer_ex_remains_unchanged() -> None:
    """The existing SetFilePointerEx behavior still handles lazy files."""

    class _LazyFile:
        def __init__(self) -> None:
            self.materialized = False

        def seek(self, offset: int, whence: int) -> None:
            return None

        def tell(self):
            return 0 if self.materialized else None

        def get_size(self) -> int:
            self.materialized = True
            return 0

    handler = Kernel32.__new__(Kernel32)
    handler.mem_write = lambda address, data: setattr(
        handler, "pointer_write", (address, data)
    )
    handler.file_get = lambda handle: _LazyFile()
    emu = _FakeEmu(ptr_size=8)

    assert Kernel32.SetFilePointerEx(handler, emu, [1, 0, 0x3000, 0]) is True
    assert handler.pointer_write == (0x3000, (0).to_bytes(8, "little"))
