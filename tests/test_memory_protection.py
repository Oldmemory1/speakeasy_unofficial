from __future__ import annotations

import speakeasy.common as common
from speakeasy.memmgr import MemMap, MemoryManager
from speakeasy.winenv.api.usermode.kernel32 import Kernel32
from speakeasy.winenv.defs.windows import windows as windefs


def _kernel32() -> Kernel32:
    return Kernel32.__new__(Kernel32)


def test_emu_perms_to_win_perms_preserves_exact_access() -> None:
    kernel32 = _kernel32()

    cases = {
        common.PERM_MEM_NONE: windefs.PAGE_NOACCESS,
        common.PERM_MEM_READ: windefs.PAGE_READONLY,
        common.PERM_MEM_RW: windefs.PAGE_READWRITE,
        common.PERM_MEM_EXEC: windefs.PAGE_EXECUTE,
        common.PERM_MEM_RX: windefs.PAGE_EXECUTE_READ,
        common.PERM_MEM_RWX: windefs.PAGE_EXECUTE_READWRITE,
    }

    for emu_perms, win_perms in cases.items():
        assert kernel32.emu_perms_to_win_perms(emu_perms) == win_perms
        assert kernel32.win_perms_to_emu_perms(win_perms) == emu_perms

    assert kernel32.emu_perms_to_win_perms(common.PERM_MEM_WRITE) == windefs.PAGE_READWRITE


class _RecordingEngine:
    def __init__(self) -> None:
        self.calls: list[tuple[int, int, int]] = []

    def mem_protect(self, addr: int, size: int, perms: int) -> None:
        self.calls.append((addr, size, perms))


def test_page_protection_overrides_broad_image_map() -> None:
    manager = MemoryManager()
    manager.emu_eng = _RecordingEngine()
    manager.maps.append(
        MemMap(
            0x400000,
            0x14000,
            "emu.module.sample",
            common.PERM_MEM_RWX,
            0,
            0x400000,
            0x14000,
        )
    )

    manager.mem_protect(0x400000, 0x1000, common.PERM_MEM_READ)

    assert manager.get_address_perms(0x400000) == common.PERM_MEM_READ
    assert manager.get_address_perms(0x400100) == common.PERM_MEM_READ
    assert manager.get_address_perms(0x401000) == common.PERM_MEM_RWX
    assert manager.get_protection_region(0x400100) == (0x400000, 0x1000)
    assert manager.get_protection_region(0x401000) == (0x401000, 0x13000)

    manager.clear_page_protections(0x400000, 0x1000)
    assert manager.get_address_perms(0x400000) == common.PERM_MEM_RWX
    assert manager.get_protection_region(0x400100) == (0x400000, 0x14000)
