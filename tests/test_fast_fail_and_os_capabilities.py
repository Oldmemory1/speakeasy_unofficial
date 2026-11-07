from __future__ import annotations

from types import SimpleNamespace

from speakeasy import Speakeasy
from speakeasy.report import ErrorInfo
from speakeasy.windows.fast_fail import requires_kernel_bootstrap_recovery
from speakeasy.windows.os_capabilities import (
    PF_FASTFAIL_AVAILABLE,
    WindowsOsVersion,
    processor_feature_override,
)
from speakeasy.windows.winemu import WindowsEmulator
from speakeasy.winenv import arch
from speakeasy.winenv.api.usermode.kernel32 import Kernel32


class _FeatureEmu:
    def __init__(self, major: int | None, minor: int | None) -> None:
        self.config = SimpleNamespace(
            os_ver=SimpleNamespace(major=major, minor=minor),
        )


class _InterruptHarness:
    def __init__(self, *, bits: int, fast_fail_code: int, fast_fail_data: int) -> None:
        self.bits = bits
        self.fast_fail_code = fast_fail_code
        self.fast_fail_data = fast_fail_data
        self.config = SimpleNamespace(
            exceptions=SimpleNamespace(dispatch_handlers=True),
        )
        self.kernel_mode = False
        self.curr_run = SimpleNamespace(error=None)
        self.restart_curr_run = True
        self.run_complete = False
        self.run_complete_calls = 0
        self.stop_calls = 0

    def _get_exception_list(self) -> int:
        return 0x200000

    def get_arch(self) -> int:
        return self.bits

    def reg_read(self, register: int) -> int:
        if register in (arch.X86_REG_ECX, arch.AMD64_REG_RCX):
            return self.fast_fail_code
        if register in (arch.X86_REG_EDX, arch.AMD64_REG_RDX):
            return self.fast_fail_data
        raise AssertionError(f"unexpected register: {register}")

    def get_pc(self) -> int:
        return 0x401236

    def get_error_info(
        self,
        error_type: str,
        address: int,
        *,
        pc_override: int | None = None,
    ) -> ErrorInfo:
        return ErrorInfo(
            type=error_type,
            pc=pc_override if pc_override is not None else address,
        )

    def on_run_complete(self) -> None:
        self.run_complete_calls += 1

    def stop(self) -> None:
        self.stop_calls += 1
        self.run_complete = True


def test_fast_fail_feature_tracks_windows_version() -> None:
    assert processor_feature_override(
        PF_FASTFAIL_AVAILABLE,
        WindowsOsVersion(6, 1),
    ) == 0
    assert processor_feature_override(
        PF_FASTFAIL_AVAILABLE,
        WindowsOsVersion(6, 2),
    ) == 1
    assert processor_feature_override(
        PF_FASTFAIL_AVAILABLE,
        WindowsOsVersion(None, None),
    ) == 0
    assert processor_feature_override(2, WindowsOsVersion(6, 1)) is None


def test_processor_feature_api_uses_os_capability_without_blanket_result() -> None:
    handler = Kernel32.__new__(Kernel32)

    windows7_args = [PF_FASTFAIL_AVAILABLE]
    assert handler.IsProcessorFeaturePresent(
        _FeatureEmu(6, 1),
        windows7_args,
    ) == 0
    assert windows7_args[0] == "PF_FASTFAIL_AVAILABLE"

    windows8_args = [PF_FASTFAIL_AVAILABLE]
    assert handler.IsProcessorFeaturePresent(
        _FeatureEmu(6, 2),
        windows8_args,
    ) == 1

    assert handler.IsProcessorFeaturePresent(_FeatureEmu(6, 1), [2]) == 1
    assert handler.IsProcessorFeaturePresent(_FeatureEmu(6, 1), [0]) == 0
    assert handler.IsProcessorFeaturePresent(_FeatureEmu(6, 1), [999]) == 0


def test_fast_fail_interrupt_is_a_termination_not_unhandled_seh() -> None:
    harness = _InterruptHarness(
        bits=arch.ARCH_X86,
        fast_fail_code=2,
        fast_fail_data=0x41414141,
    )

    handled = WindowsEmulator._hook_interrupt(harness, None, 0x29)

    assert handled is True
    assert harness.run_complete is True
    assert harness.stop_calls == 1
    assert harness.run_complete_calls == 0
    assert harness.restart_curr_run is False
    error = harness.curr_run.error
    assert isinstance(error, ErrorInfo)
    assert error.type == "fast_fail"
    assert error.pc == 0x401234
    assert error.interrupt_num == 0x29
    assert error.termination_kind == "process_terminated"
    assert error.status_code == 0xC0000409
    assert error.fast_fail_code == 2
    assert error.fast_fail_data == 0x41414141
    serialized = error.model_dump(mode="json")
    assert serialized["termination_kind"] == "process_terminated"
    assert serialized["status_code"] == "0xc0000409"
    assert serialized["fast_fail_code"] == 2


def test_fast_fail_interrupt_reads_rcx_on_amd64() -> None:
    harness = _InterruptHarness(
        bits=arch.ARCH_AMD64,
        fast_fail_code=0x1_0000_0007,
        fast_fail_data=0x1234,
    )

    WindowsEmulator._hook_interrupt(harness, None, 0x29)

    assert harness.curr_run.error.fast_fail_code == 7
    assert harness.curr_run.error.fast_fail_data == 0x1234


def test_gs_cookie_init_fast_fail_also_terminates() -> None:
    harness = _InterruptHarness(
        bits=arch.ARCH_X86,
        fast_fail_code=6,
        fast_fail_data=0,
    )

    handled = WindowsEmulator._hook_interrupt(harness, None, 0x29)

    assert handled is True
    assert harness.stop_calls == 1
    assert harness.run_complete_calls == 0
    assert harness.restart_curr_run is False
    assert harness.curr_run.error.type == "fast_fail"
    assert harness.curr_run.error.termination_kind == "process_terminated"
    assert harness.curr_run.error.fast_fail_code == 6


def test_fast_fail_shellcode_terminates_with_structured_report(config) -> None:
    code = (
        b"\xb9\x02\x00\x00\x00"  # mov ecx, FAST_FAIL_STACK_COOKIE_CHECK_FAILURE
        b"\xba\x41\x41\x41\x41"  # mov edx, 0x41414141
        b"\xcd\x29"              # int 0x29
        b"\xcc"                  # int3, must never execute
        b"\xc3"
    )
    emulator = Speakeasy(config=config)
    try:
        address = emulator.load_shellcode(data=code, arch="x86")
        emulator.run_shellcode(address)
        report = emulator.get_report()
    finally:
        emulator.shutdown()

    assert len(report.entry_points) == 1
    error = report.entry_points[0].error
    assert error is not None
    assert error.type == "fast_fail"
    assert error.interrupt_num == 0x29
    assert error.termination_kind == "process_terminated"
    assert error.status_code == 0xC0000409
    assert error.fast_fail_code == 2
    assert error.fast_fail_data == 0x41414141
    assert error.pc == address + 10
    assert error.instr is not None and "int 0x29" in error.instr.lower()


def test_gs_cookie_bootstrap_recovery_is_kernel_only() -> None:
    assert requires_kernel_bootstrap_recovery(6, kernel_mode=True) is True
    assert requires_kernel_bootstrap_recovery(6, kernel_mode=False) is False
    assert requires_kernel_bootstrap_recovery(7, kernel_mode=True) is False


def test_other_unhandled_interrupt_keeps_existing_semantics() -> None:
    harness = _InterruptHarness(
        bits=arch.ARCH_X86,
        fast_fail_code=0,
        fast_fail_data=0,
    )
    harness.restart_curr_run = False

    handled = WindowsEmulator._hook_interrupt(harness, None, 0x2E)

    assert handled is False
    assert harness.run_complete_calls == 1
    assert harness.restart_curr_run is True
    assert harness.curr_run.error.type == "unhandled_interrupt"
    assert harness.curr_run.error.interrupt_num == 0x2E
    assert harness.curr_run.error.termination_kind is None
