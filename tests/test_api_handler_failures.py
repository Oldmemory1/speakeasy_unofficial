from __future__ import annotations

from types import SimpleNamespace

import speakeasy.winenv.defs.nt.ddk as ddk
import speakeasy.winenv.defs.windows.iphlpapi as iphlpapi_types
import speakeasy.winenv.defs.windows.windows as windefs
import speakeasy.winenv.defs.winsock.ws2_32 as ws2_types
from speakeasy.config import NetworkAdapterConfig
from speakeasy.winenv.api.api import ApiHandler
from speakeasy.winenv.api.kernelmode.ntoskrnl import Ntoskrnl
from speakeasy.winenv.api.usermode.iphlpapi import Iphlpapi
from speakeasy.winenv.api.usermode.kernel32 import Kernel32
from speakeasy.winenv.api.usermode.secur32 import Secur32
from speakeasy.winenv.api.usermode.shell32 import Shell32
from speakeasy.winenv.api.usermode.user32 import User32
from speakeasy.winenv.api.usermode.ws2_32 import WSAEFAULT, Ws2_32


class _FakeEmu:
    def __init__(self, *, ptr_size: int = 8) -> None:
        self.ptr_size = ptr_size
        self.last_error = None
        self.writes: list[tuple[int, bytes]] = []

    def get_ptr_size(self) -> int:
        return self.ptr_size

    def is_address_valid(self, address: int) -> bool:
        return bool(address)

    def set_last_error(self, value: int) -> None:
        self.last_error = value

    def mem_write(self, address: int, data: bytes) -> None:
        self.writes.append((address, data))


def test_wsprintf_null_string_argument_does_not_dereference_zero() -> None:
    handler = ApiHandler.__new__(ApiHandler)

    def read_string(address: int) -> str:
        if address == 0:
            raise AssertionError("NULL %s argument must not be dereferenced")
        return "name"

    handler.read_string = read_string
    handler.read_wide_string = lambda address: "wide"
    assert handler.do_str_format("%s %s %d", [0x1000, 0, 7]) == "name  7"


def test_dialog_box_resource_identifier_is_not_treated_as_pointer() -> None:
    handler = User32.__new__(User32)
    handler.get_handle = lambda: 0x1234
    handler.get_char_width = lambda ctx: 2
    handler.read_mem_string = lambda address, width: (_ for _ in ()).throw(
        AssertionError("resource identifier must not be read")
    )

    argv = [0, 101, 0, 0x401000, 0]
    assert User32.DialogBoxParam(handler, _FakeEmu(), argv) == 0x1234
    assert argv[1] == 101


def test_get_user_name_ex_null_buffer_reports_required_size() -> None:
    handler = Secur32.__new__(Secur32)
    handler.get_char_width = lambda ctx: 1
    handler.mem_read = lambda address, size: (12).to_bytes(4, "little")
    handler.mem_write = lambda address, data: setattr(handler, "size_write", (address, data))
    handler.write_mem_string = lambda *args: (_ for _ in ()).throw(
        AssertionError("NULL output buffer must not be written")
    )

    emu = _FakeEmu()
    emu.config = SimpleNamespace(user=SimpleNamespace(name="analyst"))
    argv = [2, 0, 0x2000]
    assert Secur32.GetUserNameEx(handler, emu, argv) == 0
    assert handler.size_write == (0x2000, (8).to_bytes(4, "little"))
    assert emu.last_error == 122


def test_wsa_startup_rejects_invalid_wsadata_pointer() -> None:
    handler = Ws2_32.__new__(Ws2_32)
    handler.wstypes = ws2_types

    emu = _FakeEmu()
    emu.is_address_valid = lambda address: False
    assert Ws2_32.WSAStartup(handler, emu, [0x202, 0]) == WSAEFAULT
    assert emu.last_error == WSAEFAULT


def test_map_view_of_file_missing_mapping_returns_zero() -> None:
    handler = Kernel32.__new__(Kernel32)
    emu = _FakeEmu()
    emu.get_file_manager = lambda: SimpleNamespace(get_mapping_from_handle=lambda handle: None)

    assert Kernel32.MapViewOfFile(handler, emu, [1, 0, 0, 0, 0]) == 0
    assert emu.last_error is not None


def test_load_library_null_name_returns_zero() -> None:
    handler = Kernel32.__new__(Kernel32)
    handler.get_char_width = lambda ctx: 2
    emu = _FakeEmu()

    assert Kernel32.LoadLibrary(handler, emu, [0], {"func_name": "kernel32.LoadLibraryW"}) == 0
    assert emu.last_error is not None


def test_set_file_pointer_ex_handles_unmaterialized_file() -> None:
    class _File:
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
    handler.mem_write = lambda address, data: setattr(handler, "pointer_write", (address, data))
    handler.file_get = lambda handle: _File()
    emu = _FakeEmu(ptr_size=8)

    assert Kernel32.SetFilePointerEx(handler, emu, [1, 0, 0x3000, 0]) is True
    assert handler.pointer_write == (0x3000, (0).to_bytes(8, "little"))


def test_get_adapters_info_accepts_pydantic_adapter_config() -> None:
    handler = Iphlpapi.__new__(Iphlpapi)
    handler.iphlpapi_types = iphlpapi_types
    handler.mem_alloc = lambda size, tag=None: 0x5000
    handler.get_bytes = ApiHandler.get_bytes.__get__(handler, Iphlpapi)
    handler.mem_write = lambda address, data: setattr(handler, "adapter_write", (address, data))

    adapter = NetworkAdapterConfig(
        name="Ethernet",
        description="Test adapter",
        mac_address="00-11-22-33-44-55",
        type="ethernet",
        ip_address="10.0.0.2",
        subnet_mask="255.255.255.0",
        dhcp_enabled=True,
    )
    emu = _FakeEmu()
    emu.config = SimpleNamespace(network=SimpleNamespace(adapters=[adapter]))

    assert Iphlpapi.GetAdaptersInfo(handler, emu, [0x1000, 0x2000]) == 0
    assert handler.adapter_write[0] == 0x1000
    assert len(handler.adapter_write[1]) > 0


def test_command_line_to_argv_null_input_returns_zero() -> None:
    handler = Shell32.__new__(Shell32)
    handler.get_char_width = lambda ctx: 2
    handler.read_mem_string = lambda *args: (_ for _ in ()).throw(
        AssertionError("NULL command line must not be dereferenced")
    )

    assert Shell32.CommandLineToArgv(handler, _FakeEmu(), [0, 0x2000]) == 0


def test_nt_query_system_information_returns_status_for_unknown_class() -> None:
    handler = Ntoskrnl.__new__(Ntoskrnl)
    handler.query_writes = []
    handler.mem_write = lambda address, data: handler.query_writes.append((address, data))
    emu = _FakeEmu()
    emu.get_processes = lambda: []

    assert (
        Ntoskrnl.ZwQuerySystemInformation(
            handler,
            emu,
            [ddk.SYSTEM_INFORMATION_CLASS.SystemBasicInformation, 0x4000, 0x100, 0x3000],
        )
        == ddk.STATUS_SUCCESS
    )
    assert handler.query_writes[0][0] == 0x4000

    assert Ntoskrnl.ZwQuerySystemInformation(handler, emu, [0x86, 0x4000, 0x100, 0x3000]) == (
        ddk.STATUS_INVALID_INFO_CLASS
    )


class _StdHandleEmu:
    """Emulator double for WriteFile std-handle semantics."""

    def __init__(self) -> None:
        self.ptr_size = 8
        self.last_error = None
        self.memory: dict[int, int] = {}
        self.ranges: list[tuple[int, int]] = []
        self.stdout = 0xF005
        self.stderr = 0xF006

    def alloc(self, address: int, size: int) -> None:
        self.ranges.append((address, address + size))

    def _in_range(self, address: int, size: int) -> bool:
        return any(start <= address and address + size <= end for start, end in self.ranges)

    def get_ptr_size(self) -> int:
        return self.ptr_size

    def is_address_valid(self, address: int) -> bool:
        return self._in_range(address, 1)

    def mem_read(self, address: int, size: int) -> bytes:
        if not self._in_range(address, size):
            raise ValueError("invalid read")
        return bytes(self.memory.get(address + i, 0) for i in range(size))

    def mem_write(self, address: int, data: bytes) -> None:
        if not self._in_range(address, len(data)):
            raise ValueError("invalid write")
        for offset, value in enumerate(data):
            self.memory[address + offset] = value

    def set_last_error(self, value: int) -> None:
        self.last_error = value

    def get_address_map(self, _address: int):
        return None

    def get_current_process(self):
        return SimpleNamespace(
            get_std_handle=lambda dev: {
                0xFFFFFFF5: self.stdout,
                0xFFFFFFF4: self.stderr,
            }.get(dev, 0)
        )

    def file_get(self, _handle: int):
        return None

    def pipe_get(self, _handle: int):
        return None


def test_write_file_stderr_writes_bytes_written_and_succeeds() -> None:
    handler = Kernel32.__new__(Kernel32)
    emu = _StdHandleEmu()
    handler.emu = emu
    emu.alloc(0x2000, 8)
    emu.alloc(0x3000, 4)
    for offset, value in enumerate(b"abc"):
        emu.memory[0x2000 + offset] = value

    result = Kernel32.WriteFile(handler, emu, [emu.stderr, 0x2000, 3, 0x3000, 0])

    assert result == 1
    assert int.from_bytes(emu.mem_read(0x3000, 4), "little") == 3
    assert emu.last_error == windefs.ERROR_SUCCESS


def test_write_file_invalid_handle_still_fails() -> None:
    handler = Kernel32.__new__(Kernel32)
    emu = _StdHandleEmu()
    handler.emu = emu
    emu.alloc(0x2000, 8)
    emu.alloc(0x3000, 4)
    emu.memory[0x2000] = 0x41

    result = Kernel32.WriteFile(handler, emu, [0xDEAD, 0x2000, 1, 0x3000, 0])

    assert result == 0
    assert int.from_bytes(emu.mem_read(0x3000, 4), "little") == 0
    assert emu.last_error == windefs.ERROR_INVALID_HANDLE
