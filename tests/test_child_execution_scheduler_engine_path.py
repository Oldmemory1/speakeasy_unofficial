from __future__ import annotations

from types import SimpleNamespace

from speakeasy import Speakeasy


class RecordingScheduler:
    """Record scheduler drains without loading or executing child code."""

    def __init__(self) -> None:
        self.drain_calls = []
        self.stop_reasons = []

    def drain(self, parent_result):
        """Record one parent-complete drain request."""

        self.drain_calls.append(parent_result)
        return ()

    def stop(self, reason):
        """Record one scheduler stop request."""

        self.stop_reasons.append(reason)


def test_run_module_uses_scheduler_as_only_child_drain_path(
    base_config,
    load_test_bin,
) -> None:
    """Legacy child_processes entries must not be loaded directly."""

    data = load_test_bin("argv_test_x86.exe.xz")
    se = Speakeasy(config=base_config, argv=[])
    scheduler = RecordingScheduler()
    sentinel = SimpleNamespace(pe_data=None, cmdline="")
    try:
        module = se.load_module(data=data)
        se.emu.set_child_scheduler(scheduler)
        se.emu.child_processes.append(sentinel)

        se.emu.run_module(module, emulate_children=True)

        assert len(scheduler.drain_calls) == 1
        assert scheduler.drain_calls[0].status == "ok"
        assert se.emu.child_processes == [sentinel]
    finally:
        se.shutdown()


def test_missing_scheduler_does_not_execute_legacy_child_queue(
    base_config,
    load_test_bin,
) -> None:
    """No scheduler means child execution remains disabled."""

    data = load_test_bin("argv_test_x86.exe.xz")
    se = Speakeasy(config=base_config, argv=[])
    sentinel = SimpleNamespace(pe_data=None, cmdline="")
    try:
        module = se.load_module(data=data)
        se.emu.set_child_scheduler(None)
        se.emu.child_processes.append(sentinel)

        se.emu.run_module(module, emulate_children=True)

        assert se.emu.child_processes == [sentinel]
    finally:
        se.shutdown()
