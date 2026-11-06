from __future__ import annotations

import hashlib
import ntpath
import os
from types import SimpleNamespace

import pytest

import speakeasy.winenv.arch as _arch
from speakeasy.report import Report
from speakeasy.windows.child_execution import (
    ChildExecutionPolicy,
    ChildExecutionRegistry,
    ChildExecutionState,
    ChildTargetResolver,
)
from speakeasy.winenv.api.usermode.advapi32 import AdvApi32
from speakeasy.winenv.api.usermode.kernel32 import Kernel32
from speakeasy.winenv.api.usermode.shell32 import Shell32


class FakeProcess:
    id = 0x101
    pid = 0x101
    name = "fake-child"

    def __init__(self) -> None:
        self.threads = [SimpleNamespace(tid=0x201)]


class FakeFileManager:
    def __init__(self, files=None):
        self.files = files or []

    def get_file_from_path(self, path):
        for target in self.files:
            if target.path.lower() == path.lower():
                return target
        return None

    def get_dropped_files(self):
        return self.files


class DroppedFile:
    def __init__(self, path: str, data: bytes):
        self.path = path
        self.data = data
        self.bytes_written = len(data)

    def get_size(self):
        return len(self.data)

    def get_data(self, reset_pointer=False):
        return self.data


class FakeEmu:
    def __init__(self, root_data: bytes, *, root_name="deadbeef.exe"):
        self._root_pe_data = root_data
        self._root_emu_path = rf"C:\Windows\System32\{root_name}"
        self._root_sample_sha256 = "deadbeef"
        self.curr_process = SimpleNamespace(id=0x100)
        self.curr_thread = SimpleNamespace(tid=0x200)
        self.input = {"sha256": "deadbeef"}
        self.cd = r"C:\Windows\System32"
        self.env = {"systemroot": r"C:\Windows"}
        self.fileman = FakeFileManager()
        self.calls = []
        self.child_processes = []
        self.run_queue = []
        self._arch = _arch.ARCH_X86

    def get_arch(self):
        return self._arch

    def request_child_process(self, **kwargs):
        self.calls.append(kwargs)
        proc = FakeProcess()
        self.child_processes.append(proc)
        return proc, SimpleNamespace(launch_id="child-000001")

    def read_mem_string(self, addr, width=1, max_chars=0):
        return {0x10: r"C:\Windows\System32\cmd.exe", 0x20: "cmd.exe /c whoami"}[addr]

    def get_object_handle(self, obj):
        return 0x300 if getattr(obj, "threads", None) else 0x400

    def get_profiler(self):
        return None

    def get_ptr_size(self):
        return 4


def test_self_request_is_eligible_and_never_queues(
    base_config,
    load_test_bin,
):
    from speakeasy import Speakeasy

    data = load_test_bin("argv_test_x86.exe.xz")
    se = Speakeasy(config=base_config, argv=[])
    try:
        se.load_module(data=data)
        before = len(se.emu.run_queue)
        root_stem = os.path.splitext(ntpath.basename(se.emu._root_emu_path))[0]
        proc, request = se.emu.request_child_process(
            source_api="ShellExecute",
            path=rf"C:\Windows\System32\{root_stem}",
            cmdline="",
        )

        assert request.target_source == "self"
        assert request.target_resolved is True
        assert request.eligible is True
        assert request.state == ChildExecutionState.PROCESS_OBJECT_CREATED.value
        assert request.created_child_pid == proc.pid
        assert not hasattr(proc, "child_execution_launch_id")
        assert len(se.emu.run_queue) == before

        report = se.get_report()
        assert report.sha256 == hashlib.sha256(data).hexdigest()
        assert report.child_execution is not None
        assert report.child_execution.execution_enabled is False
        assert report.child_execution.policy["max_depth"] == 1
        assert report.child_execution.policy["max_children_per_root"] == 4
        assert report.child_execution.thread_queued_count == 0
        assert report.child_execution.entrypoint_reached_count == 0
        assert report.child_execution.requests[0].launch_id == request.launch_id
    finally:
        se.shutdown()


def test_unavailable_request_keeps_process_fact_separate(load_test_bin):
    data = load_test_bin("argv_test_x86.exe.xz")
    emu = FakeEmu(data)
    registry = ChildExecutionRegistry(emu)

    request = registry.create_request(
        source_api="WinExec",
        path=r"C:\Windows\System32\Hlklda32",
        command_line=r"C:\Windows\System32\Hlklda32",
    )

    assert request.state == ChildExecutionState.UNAVAILABLE.value
    assert request.target_resolved is False
    assert request.eligible is False
    assert request.rejection_reason == "target_unavailable"
    assert request.process_object_created is False
    assert request.created_child_pid is None

    request.mark_process_created(FakeProcess())
    assert request.state == ChildExecutionState.UNAVAILABLE.value
    assert request.process_object_created is True
    assert request.created_child_pid == FakeProcess.pid


def test_fixture_admission_rejects_non_pe(load_test_bin):
    data = load_test_bin("argv_test_x86.exe.xz")
    emu = FakeEmu(data)
    registry = ChildExecutionRegistry(emu)
    registry.register_fixture(r"C:\fixtures\not-a-pe.exe", b"not a pe")

    request = registry.create_request(
        source_api="CreateProcess",
        path=r"C:\fixtures\not-a-pe.exe",
        command_line="not-a-pe.exe",
    )

    assert request.target_source == "fixture"
    assert request.target_resolved is True
    assert request.eligible is False
    assert request.state == ChildExecutionState.REJECTED.value
    assert request.rejection_reason == "target_not_pe"


def test_complete_dropped_file_is_modeled_as_resolved(load_test_bin):
    data = load_test_bin("argv_test_x86.exe.xz")
    emu = FakeEmu(b"MZ")
    target_path = r"C:\Windows\Temp\dropped.exe"
    emu.fileman = FakeFileManager([DroppedFile(target_path, data)])
    registry = ChildExecutionRegistry(emu)

    request = registry.create_request(
        source_api="CreateProcess",
        path=target_path,
        command_line="dropped.exe /quiet",
    )

    assert request.target_source == "dropped_file"
    assert request.target_resolved is True
    assert request.eligible is True
    assert request.target_sha256 == hashlib.sha256(data).hexdigest()


def test_path_normalization_expands_environment_and_cwd():
    emu = FakeEmu(b"MZ")
    resolver = ChildTargetResolver(emu)

    assert resolver.normalize_path(r"%SystemRoot%\System32\child.exe") == (
        r"C:\Windows\System32\child.exe"
    )
    assert resolver.normalize_path("child.exe", cwd=r"C:\Temp") == (
        r"C:\Temp\child.exe"
    )


def test_duplicate_target_and_canonical_command_is_rejected(load_test_bin):
    data = load_test_bin("argv_test_x86.exe.xz")
    emu = FakeEmu(data)
    registry = ChildExecutionRegistry(emu)
    command = r'"C:\Program Files\Example\child.exe"   /quiet'

    first = registry.create_request(
        source_api="CreateProcess",
        path=r"C:\Windows\System32\deadbeef",
        command_line=command,
    )
    first.mark_process_created(FakeProcess())
    second = registry.create_request(
        source_api="ShellExecute",
        path=r"C:\Windows\System32\deadbeef",
        command_line=r'C:\Program Files\Example\child.exe /quiet',
    )

    assert first.eligible is True
    assert second.eligible is False
    assert second.state == ChildExecutionState.REJECTED.value
    assert second.rejection_reason == "duplicate_launch"


def test_oversized_target_is_rejected(load_test_bin):
    data = load_test_bin("argv_test_x86.exe.xz")
    emu = FakeEmu(data)
    registry = ChildExecutionRegistry(
        emu,
        policy=ChildExecutionPolicy(max_target_bytes=16),
    )

    request = registry.create_request(
        source_api="CreateProcess",
        path=emu._root_emu_path,
        command_line="deadbeef.exe",
    )

    assert request.target_resolved is True
    assert request.eligible is False
    assert request.rejection_reason == "target_too_large"


def test_child_count_limit_is_enforced(load_test_bin):
    data = load_test_bin("argv_test_x86.exe.xz")
    emu = FakeEmu(data)
    registry = ChildExecutionRegistry(
        emu,
        policy=ChildExecutionPolicy(max_children_per_root=1),
    )

    first = registry.create_request(
        source_api="CreateProcess",
        path=emu._root_emu_path,
        command_line="deadbeef.exe /first",
    )
    second = registry.create_request(
        source_api="CreateProcess",
        path=emu._root_emu_path,
        command_line="deadbeef.exe /second",
    )

    assert first.eligible is True
    assert second.eligible is False
    assert second.rejection_reason == "child_count_limit"


def test_depth_limit_is_enforced(load_test_bin):
    data = load_test_bin("argv_test_x86.exe.xz")
    emu = FakeEmu(data)
    registry = ChildExecutionRegistry(
        emu,
        policy=ChildExecutionPolicy(max_depth=1),
    )
    registry.active_depth = 1

    request = registry.create_request(
        source_api="CreateProcess",
        path=emu._root_emu_path,
        command_line="deadbeef.exe",
    )

    assert request.depth == 2
    assert request.eligible is False
    assert request.rejection_reason == "depth_limit"


def test_fixture_architecture_mismatch_is_rejected(load_test_bin):
    x64 = load_test_bin("argv_test_x64.exe.xz")
    emu = FakeEmu(x64, root_name="deadbeef.exe")
    emu._arch = _arch.ARCH_X86
    registry = ChildExecutionRegistry(emu)
    registry.register_fixture(r"C:\fixtures\child64.exe", x64)

    request = registry.create_request(
        source_api="CreateProcess",
        path=r"C:\fixtures\child64.exe",
        command_line="child64.exe",
    )

    assert request.target_arch == "x64"
    assert request.target_resolved is True
    assert request.eligible is False
    assert request.rejection_reason == "arch_mismatch"


def test_target_command_parser_preserves_quoted_path():
    command = r'"C:\Program Files\Internet Explorer\iexplore.exe" http://example.test/a'
    assert ChildTargetResolver.command_target(command) == (
        r"C:\Program Files\Internet Explorer\iexplore.exe"
    )


def test_process_api_handlers_route_requests():
    emu = FakeEmu(b"MZ", root_name="deadbeef.exe")

    shell = Shell32(emu)
    shell.record_process_event = lambda *args, **kwargs: None
    assert shell.ShellExecute(
        emu,
        [0, 0, 0x10, 0, 0, 0],
        {"func_name": "ShellExecuteA"},
    ) == 33
    assert emu.calls[-1]["source_api"] == "ShellExecute"
    shell.mem_cast = lambda obj, addr: SimpleNamespace(
        lpVerb=0,
        lpFile=0x10,
        lpParameters=0,
        lpDirectory=0,
    )
    assert shell.ShellExecuteEx(emu, [0x50], {"func_name": "ShellExecuteExA"}) is True
    assert emu.calls[-1]["source_api"] == "ShellExecuteEx"

    kernel = Kernel32(emu)
    kernel.record_process_event = lambda *args, **kwargs: None
    kernel.mem_cast = lambda obj, addr: obj
    kernel.get_bytes = lambda obj: b"\x00" * 16
    kernel.mem_write = lambda *args: None
    assert kernel.WinExec(emu, [0x20, 0], {}) == 32
    assert emu.calls[-1]["source_api"] == "WinExec"

    assert kernel.CreateProcess(
        emu,
        [0x10, 0x20, 0, 0, 0, 0, 0, 0, 0, 0x30],
        {"func_name": "CreateProcessA"},
    ) == 1
    assert emu.calls[-1]["source_api"] == "CreateProcess"
    assert kernel.CreateProcessInternal(
        emu,
        [0, 0x10, 0x20, 0, 0, 0, 0, 0, 0, 0, 0x30, 0],
        {"func_name": "CreateProcessInternalA"},
    ) == 1
    assert emu.calls[-1]["source_api"] == "CreateProcessInternal"

    advapi = AdvApi32(emu)
    advapi.record_process_event = lambda *args, **kwargs: None
    advapi.mem_cast = lambda obj, addr: obj
    advapi.mem_write = lambda *args: None
    assert advapi.CreateProcessAsUser(
        emu,
        [0, 0x10, 0x20, 0, 0, 0, 0, 0, 0, 0, 0x30],
        {"func_name": "CreateProcessAsUserA"},
    ) == 1
    assert emu.calls[-1]["source_api"] == "CreateProcessAsUser"


def test_stage_one_resume_thread_does_not_queue_child():
    emu = FakeEmu(b"MZ")
    proc = FakeProcess()
    thread = SimpleNamespace(
        suspend_count=1,
        process=proc,
        get_context=lambda: SimpleNamespace(Eip=0x401000, Eax=0),
    )
    emu.child_processes.append(proc)
    emu.get_object_from_handle = lambda handle: thread
    emu.resume_thread = lambda obj: False
    emu.child_execution = SimpleNamespace(allow_execution=False)
    emu.create_thread = lambda *args, **kwargs: pytest.fail("child thread was queued")

    kernel = Kernel32(emu)
    rv = kernel.ResumeThread(emu, [0x400], {})

    assert rv == 1
    assert proc in emu.child_processes


def test_stage_one_thread_injection_does_not_queue_child():
    emu = FakeEmu(b"MZ")
    proc = FakeProcess()
    proc.path = r"C:\Windows\Temp\child.exe"
    child_thread = SimpleNamespace(process=proc)
    emu.child_processes.append(proc)
    emu.child_execution = SimpleNamespace(allow_execution=False)
    emu.get_object_from_handle = lambda handle: proc if handle == 0x400 else child_thread
    emu.set_last_error = lambda error: None
    emu.create_thread = lambda *args, **kwargs: pytest.fail("child thread was queued")
    kernel = Kernel32(emu)

    assert kernel.CreateRemoteThread(
        emu,
        [0x400, 0, 0, 0x401000, 0, 0, 0],
        {},
    ) == 0
    assert kernel.QueueUserAPC(emu, [0x401000, 0x500, 0], {}) == 0


def test_child_execution_report_serializes_without_target_bytes(load_test_bin):
    data = load_test_bin("argv_test_x86.exe.xz")
    emu = FakeEmu(data)
    registry = ChildExecutionRegistry(emu)
    request = registry.create_request(
        source_api="ShellExecute",
        path=r"C:\Windows\System32\deadbeef",
        command_line="",
    )
    request.mark_process_created(FakeProcess())

    report = Report(
        emulation_total_runtime=0.1,
        timestamp=1,
        sha256="deadbeef",
        child_execution=registry.to_report_dict(),
    )
    payload = report.model_dump(mode="json")

    assert payload["sha256"] == "deadbeef"
    assert payload["child_execution"]["execution_enabled"] is False
    assert payload["child_execution"]["thread_queued_count"] == 0
    assert payload["child_execution"]["entrypoint_reached_count"] == 0
    assert payload["child_execution"]["requests"][0]["target_resolved"] is True
    assert "target_bytes" not in payload["child_execution"]["requests"][0]


@pytest.mark.parametrize("state", list(ChildExecutionState))
def test_contract_state_values_are_stable(state):
    assert state.value in {
        "requested",
        "target_resolved",
        "eligible",
        "skipped",
        "unavailable",
        "rejected",
        "process_object_created",
        "thread_queued",
        "entrypoint_reached",
        "completed",
        "partial",
        "failed",
    }
