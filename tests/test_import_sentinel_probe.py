from speakeasy.windows.import_sentinel import (
    find_import_sentinel,
    import_probe_prefix,
)
from speakeasy.windows.winemu import WindowsEmulator
from speakeasy.winenv import arch


class _ImportSentinelHarness:
    def __init__(self, machine_arch: int = arch.ARCH_X86) -> None:
        self.import_table = {
            0xFEEDF00C: ("kernel32", "WriteFile"),
            0xFEEDF010: ("kernel32", "CloseHandle"),
        }
        self.machine_arch = machine_arch
        self.unset_hooks_calls = 0
        self.memory_writes: list[tuple[int, bytes]] = []

    def _unset_emu_hooks(self) -> None:
        self.unset_hooks_calls += 1

    def get_arch(self) -> int:
        return self.machine_arch

    def get_mod_from_addr(self, address: int):
        return None

    def get_ptr_size(self) -> int:
        return 4

    def mem_write(self, address: int, data: bytes) -> None:
        self.memory_writes.append((address, data))


def test_import_probe_prefix_matches_emulated_architecture() -> None:
    assert import_probe_prefix(arch.ARCH_X86) == b"\x8b\xff"
    assert import_probe_prefix(arch.ARCH_AMD64) == b"\x48\x8b\xc4"
    assert import_probe_prefix(0) == b""


def test_import_sentinel_lookup_accepts_exact_and_overlapping_reads() -> None:
    harness = _ImportSentinelHarness()

    assert find_import_sentinel(
        harness.import_table,
        0xFEEDF00C,
        1,
        4,
    ) == 0xFEEDF00C
    assert find_import_sentinel(
        harness.import_table,
        0xFEEDF00E,
        1,
        4,
    ) == 0xFEEDF00C
    assert find_import_sentinel(
        harness.import_table,
        0xFEEDF008,
        8,
        4,
    ) == 0xFEEDF00C
    assert find_import_sentinel(
        harness.import_table,
        0xFEEDF020,
        1,
        4,
    ) is None


def test_import_sentinel_read_installs_prologue_on_reserved_page() -> None:
    harness = _ImportSentinelHarness()

    handled = WindowsEmulator._handle_invalid_read(
        harness,
        None,
        0xFEEDF010,
        1,
        None,
    )

    assert handled is True
    assert harness.unset_hooks_calls == 1
    assert harness.memory_writes == [(0xFEEDF010, b"\x8b\xff")]


def test_other_reserved_reads_keep_zero_page_behavior() -> None:
    harness = _ImportSentinelHarness()

    handled = WindowsEmulator._handle_invalid_read(
        harness,
        None,
        0xFEEDF020,
        1,
        None,
    )

    assert handled is True
    assert harness.unset_hooks_calls == 1
    assert harness.memory_writes == []
