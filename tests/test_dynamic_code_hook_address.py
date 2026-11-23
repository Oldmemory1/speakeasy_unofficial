"""Regression test for dynamic-code hook trigger addresses."""

from types import SimpleNamespace

from speakeasy import common
from speakeasy.windows.winemu import WindowsEmulator


def test_dynamic_code_hook_exposes_exact_execution_address():
    observed = []
    mapping = SimpleNamespace(
        base=0x700000,
        size=0x4000,
        tag="api.VirtualAlloc.0x700000",
        prot=0x20,
    )

    # v2.1.0 hook ABI (``DynCodeHookCallback(emu, region)``): the hook object
    # carries ``enabled``/``emu`` and the double must provide the run lookup
    # that ``binemu._fire_dyn_code_hooks`` performs before firing the hooks.
    def record_dyn_code(emu, region):
        observed.append((
            region.execution_address,
            region.base,
            region.execution_caller_address,
        ))

    emulator = SimpleNamespace(
        hooks={
            common.HOOK_DYN_CODE: [
                SimpleNamespace(cb=record_dyn_code, enabled=True, emu="emu-double"),
            ],
        },
        get_profiler=lambda: None,
        get_current_run=lambda: SimpleNamespace(dynamic_code={}),
        get_address_map=lambda _address: mapping,
        _dyn_code_caller_pc=0x401234,
    )

    WindowsEmulator._fire_dyn_code_hooks(emulator, 0x701234)

    assert observed == [(0x701234, 0x700000, 0x401234)]
    # The trigger address and caller pc are transient attributes: they must not
    # leak onto the mapping that other code observes afterwards.
    assert not hasattr(mapping, "execution_address")
    assert not hasattr(mapping, "execution_caller_address")
