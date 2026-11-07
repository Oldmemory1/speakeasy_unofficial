from __future__ import annotations

import speakeasy.common as common
import speakeasy.winenv.arch as _arch
from speakeasy.winenv.api.usermode.cygwin import Cygwin, Msys, Msys2, Msys2Short
from speakeasy.winenv.api.winapi import WindowsApi


class _FakeEmu:
    def __init__(self, arch: int = _arch.ARCH_AMD64) -> None:
        self.arch = arch
        self.argv = [Cygwin.CW_USER_DATA]
        self.maps: list[tuple[int, int, int, str]] = []
        self._next_base = 0x100000

    def get_arch(self) -> int:
        return self.arch

    def get_ptr_size(self) -> int:
        return 8 if self.arch == _arch.ARCH_AMD64 else 4

    def get_func_argv(self, conv: int, argc: int) -> list[int]:
        assert conv == _arch.CALL_CONV_CDECL
        return self.argv[:argc]

    def mem_map(self, size: int, base=None, perms: int = 0, tag=None, **kwargs) -> int:
        address = base or self._next_base
        self.maps.append((size, perms, address, tag))
        self._next_base += 0x1000
        return address


def test_both_module_names_load_the_cygwin_handler() -> None:
    emu = _FakeEmu()
    windows_api = WindowsApi(emu)

    assert isinstance(windows_api.load_api_handler("cygwin1"), Cygwin)
    assert isinstance(windows_api.load_api_handler("msys-1"), Msys)
    assert isinstance(windows_api.load_api_handler("msys-2"), Msys2Short)
    assert isinstance(windows_api.load_api_handler("msys-2.0"), Msys2)


def test_cw_user_data_is_stable_aligned_and_writable() -> None:
    for arch in (_arch.ARCH_X86, _arch.ARCH_AMD64):
        emu = _FakeEmu(arch)
        handler = Cygwin(emu)

        first = handler.Cygwin_internal(emu, [])
        second = handler.Cygwin_internal(emu, [])

        assert first != 0
        assert first == second
        assert first % emu.get_ptr_size() == 0
        assert emu.maps == [(Cygwin.USER_DATA_SIZE, common.PERM_MEM_RW, first, "emu.cygwin.user_data")]


def test_unknown_command_returns_cygwin_failure_sentinel() -> None:
    emu = _FakeEmu()
    emu.argv = [0x123456]
    handler = Cygwin(emu)

    assert handler.Cygwin_internal(emu, []) == handler.get_max_int()
    assert emu.maps == []


def test_pinfo_lock_commands_return_success() -> None:
    emu = _FakeEmu()
    handler = Cygwin(emu)

    for command in (Cygwin.CW_LOCK_PINFO, Cygwin.CW_UNLOCK_PINFO):
        emu.argv = [command]
        assert handler.Cygwin_internal(emu, []) == 1


def test_msys_uses_the_same_internal_contract() -> None:
    emu = _FakeEmu(_arch.ARCH_X86)
    handler = Msys(emu)

    address = handler.Cygwin_internal(emu, [])

    assert address == handler._get_user_data()
    assert emu.maps[0][1] == common.PERM_MEM_RW
