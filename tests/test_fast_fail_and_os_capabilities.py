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
    def __init__(
        self,
        *,
        bits: int,
        fast_fail_code: int,
        fast_fail_data: int,
        exception_list: int = 0x200000,
        dispatch_handlers: bool = True,
        previous_opcode: bytes = b"\xCD\x04",
        eflags: int = 0x202,
    ) -> None:
        self.bits = bits
        self.fast_fail_code = fast_fail_code
        self.fast_fail_data = fast_fail_data
        self.previous_opcode = previous_opcode
        self.eflags = eflags
        self.exception_list = exception_list
        self.config = SimpleNamespace(
            exceptions=SimpleNamespace(dispatch_handlers=dispatch_handlers),
        )
        self.kernel_mode = False
        self.curr_run = SimpleNamespace(error=None)
        self.curr_exception_code = 0
        self.prev_pc: int | None = 0x401234
        self.restart_curr_run = True
        self.run_complete = False
        self.run_complete_calls = 0
        self.code_hook_enabled = 0
        self.stop_calls = 0

    def _get_exception_list(self) -> int:
        return self.exception_list

    def get_arch(self) -> int:
        return self.bits

    def reg_read(self, register: int) -> int:
        if register in (arch.X86_REG_ECX, arch.AMD64_REG_RCX):
            return self.fast_fail_code
        if register in (arch.X86_REG_EDX, arch.AMD64_REG_RDX):
            return self.fast_fail_data
        if register == arch.X86_REG_EFLAGS:
            return self.eflags
        raise AssertionError(f"unexpected register: {register}")

    def mem_read(self, address: int, size: int) -> bytes:
        assert address == self.prev_pc
        assert size == 2
        return self.previous_opcode

    def get_pc(self) -> int:
        return 0x401236

    def enable_code_hook(self) -> None:
        self.code_hook_enabled += 1

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


def test_int4_is_dispatched_as_integer_overflow() -> None:
    harness = _InterruptHarness(
        bits=arch.ARCH_X86,
        fast_fail_code=0,
        fast_fail_data=0,
    )

    handled = WindowsEmulator._hook_interrupt(harness, None, 4)

    assert handled is True
    assert harness.curr_exception_code == 0xC0000095
    assert harness.prev_pc == 0x401236
    assert harness.code_hook_enabled == 1
    assert harness.run_complete_calls == 0
    assert harness.curr_run.error is None


def test_into_without_overflow_continues_after_interrupt() -> None:
    harness = _InterruptHarness(
        bits=arch.ARCH_X86,
        fast_fail_code=0,
        fast_fail_data=0,
        previous_opcode=b"\xCE\x90",
        eflags=0x202,
    )

    handled = WindowsEmulator._hook_interrupt(harness, None, 4)

    assert handled is True
    assert harness.curr_exception_code == 0
    assert harness.code_hook_enabled == 0
    assert harness.curr_run.error is None


def test_into_with_overflow_dispatches_integer_overflow() -> None:
    harness = _InterruptHarness(
        bits=arch.ARCH_X86,
        fast_fail_code=0,
        fast_fail_data=0,
        previous_opcode=b"\xCE\x90",
        eflags=0xA02,
    )

    handled = WindowsEmulator._hook_interrupt(harness, None, 4)

    assert handled is True
    assert harness.curr_exception_code == 0xC0000095
    assert harness.code_hook_enabled == 1


def test_int4_without_seh_remains_diagnostic_failure() -> None:
    harness = _InterruptHarness(
        bits=arch.ARCH_X86,
        fast_fail_code=0,
        fast_fail_data=0,
        exception_list=0,
    )

    handled = WindowsEmulator._hook_interrupt(harness, None, 4)

    assert handled is False
    assert harness.curr_exception_code == 0
    assert harness.code_hook_enabled == 0
    assert harness.run_complete_calls == 1
    assert harness.curr_run.error.type == "unhandled_interrupt"
    assert harness.curr_run.error.interrupt_num == 4


def test_x64_int4_does_not_apply_x86_into_semantics() -> None:
    harness = _InterruptHarness(
        bits=arch.ARCH_AMD64,
        fast_fail_code=0,
        fast_fail_data=0,
        previous_opcode=b"\xCE\x90",
        eflags=0x202,
    )

    handled = WindowsEmulator._hook_interrupt(harness, None, 4)

    assert handled is True
    assert harness.curr_exception_code == 0xC0000095


def test_x86_into_of_zero_shellcode_continues() -> None:
    code = bytes.fromhex(
        "b801000000"  # mov eax, 1
        "83c001"      # add eax, 1 (OF=0)
        "ce"          # into
        "b834120000"  # mov eax, 0x1234
        "c3"
    )
    emulator = Speakeasy()
    try:
        address = emulator.load_shellcode(data=code, arch="x86")
        emulator.run_shellcode(address)
        report = emulator.get_report()
    finally:
        emulator.shutdown()

    assert report.entry_points[0].error is None


def test_x86_into_of_one_shellcode_still_reports_overflow() -> None:
    code = bytes.fromhex(
        "b8ffffff7f"  # mov eax, 0x7fffffff
        "83c001"      # add eax, 1 (OF=1)
        "ce"          # into
        "b834120000"  # mov eax, 0x1234
        "c3"
    )
    emulator = Speakeasy()
    try:
        address = emulator.load_shellcode(data=code, arch="x86")
        emulator.run_shellcode(address)
        report = emulator.get_report()
    finally:
        emulator.shutdown()

    error = report.entry_points[0].error
    assert error is not None
    assert error.type == "unhandled_interrupt"
    assert error.interrupt_num == 4
